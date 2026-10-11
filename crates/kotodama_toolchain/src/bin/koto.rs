//! Unified Kotodama V1 developer command.
//!
//! Kotodama compiles to IVM bytecode (`.to`). `koto` checks, builds, tests, formats, documents and
//! explains Kotodama sources, and serves the language server.
#[path = "koto/doc_builtins.rs"]
mod doc_builtins;
#[path = "koto/explain.rs"]
mod explain;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use kotodama_lang::{
    compiler::CompilerOptions,
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase, Severity},
    driver::{
        BuildDriver, BuildError, BuildStatus, LinkedSourceBuildRequest, LoadedProjectGraph,
        LoadedSourceProject, ProjectSourceKey, PublishLayout, PublishMode, atomic_write_if_changed,
        discover_source_link_request, load_source_project, logical_source_name,
        project_root_for_source, read_source_file,
    },
    formatter::format_source,
    linker::SourceModuleUnit,
    lint::LintLevel,
    session::{CompilerSession, LintConfig},
    source::{FrontendBudget, SourceFile, SourceId},
};
#[cfg(test)]
use kotodama_lang::{
    diagnostic::{DiagnosticFix, DiagnosticLabel, SourcePosition, SourceSpan},
    session::{CompileOutput, CompileRequest},
    source::TextRange,
};
use kotodama_toolchain::diagnostics::{
    leveled_lint, remap_locked_project_diagnostic_sources, remap_project_diagnostic_sources,
    remap_rooted_diagnostic_sources,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    path::{Path, PathBuf},
};
/// Process exit statuses shared with `musubi` (see `crates/musubi/src/output.rs`).
///
/// Scripts can distinguish a misused command line from failing code: usage errors never reuse
/// the status reserved for diagnostics and failing tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitStatus {
    /// The command completed and every requested check passed.
    Success,
    /// The command line was malformed: unknown option, missing or conflicting arguments.
    Usage,
    /// Compiler diagnostics, formatting drift, or a `--verify` mismatch.
    Failed,
    /// The tests compiled and ran, and at least one failed.
    TestsFailed,
    /// A source, manifest, or output file could not be read or written.
    Io,
    /// The toolchain itself failed; report it with a minimal reproducer.
    Internal,
}
impl ExitStatus {
    /// Stable numeric process exit code.
    const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Usage => 2,
            Self::Failed => 8,
            Self::Io => 10,
            Self::TestsFailed => 11,
            Self::Internal => 70,
        }
    }
}
/// Exit-status table appended to `koto --help`.
const EXIT_STATUS_HELP: &str = "\
Exit status:
  0   success
  2   usage error (unknown option, missing or conflicting arguments)
  8   compiler diagnostics, formatting drift, or --verify mismatch
  10  a source, manifest, or output file could not be read or written
  11  the tests ran and at least one failed
  70  internal toolchain error";
/// Short version printed by `koto -V`.
const KOTO_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Long version printed by `koto --version`: compiler identity, bytecode target, and ABI hash.
fn koto_long_version() -> &'static str {
    static LONG_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LONG_VERSION.get_or_init(|| {
        let abi_hash = ivm_abi::syscalls::compute_abi_hash(ivm_abi::SyscallPolicy::AbiV1);
        format!(
            "{KOTO_VERSION}\ncompiler: kotodama_lang/{KOTO_VERSION}\ntarget: IVM 1.1 bytecode (.to), ABI v1\nabi_hash: {}",
            hex_lower(&abi_hash)
        )
    })
}
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
/// Kotodama V1 toolchain: check, build, test, format, document, and explain seiyaku compiled to
/// IVM bytecode.
#[derive(Parser, Debug)]
#[command(
    name = "koto",
    version = KOTO_VERSION,
    about = "Kotodama V1 toolchain: check, build, test, format, and document seiyaku compiled to IVM bytecode",
    after_help = EXIT_STATUS_HELP,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: KotoCommand,
}
#[derive(Subcommand, Debug)]
enum KotoCommand {
    /// Type-check sources and report diagnostics without writing artifacts.
    Check(CheckArgs),
    /// Compile seiyaku into IVM `.to` artifacts and their interface manifests.
    Build(BuildArgs),
    /// Discover and run `#[test]` functions against the seiyaku under test.
    Test(TestArgs),
    /// Format sources in place, or report unformatted files with --check.
    Fmt(FmtArgs),
    /// Render the public interface of a seiyaku as Markdown or JSON.
    Doc(DocArgs),
    /// Explain a diagnostic code, lint name, or branded keyword.
    Explain(ExplainArgs),
    /// Serve the Kotodama language server over stdio.
    Lsp(LspArgs),
}
/// Explicit source-graph selection shared by every compiling subcommand.
#[derive(Args, Debug, Default, Clone)]
struct SourceSelection {
    /// Directory that logical source names are relative to (default: the source's directory;
    /// for a `koto_test` module, the nearest directory containing both it and its target).
    #[arg(long, value_name = "DIR")]
    source_root: Option<PathBuf>,
}
/// Compiler capabilities shared by every compiling subcommand.
#[derive(Args, Debug, Clone, Copy)]
struct CompileCapabilities {
    /// Account-address chain discriminant (1..=65535) of the network the sources target:
    /// `AccountId` literals must be encoded for it, and `koto test` derives fixture actor
    /// accounts from it. Pass the target network's value when its literals use another prefix.
    #[arg(
        long,
        value_name = "N",
        value_parser = parse_chain_discriminant,
        default_value_t = iroha_data_model::account::address::chain_discriminant()
    )]
    chain_discriminant: u16,
    /// Enable ZK seiyaku compilation (`Secret<T>` and proof/commitment operations).
    #[arg(long)]
    zk: bool,
}
impl CompileCapabilities {
    fn chain_discriminant(self) -> u16 {
        self.chain_discriminant
    }
}
#[derive(Args, Debug)]
struct CheckArgs {
    /// Diagnostic output format.
    #[arg(long, value_enum, default_value_t)]
    format: DiagnosticFormat,
    #[command(flatten)]
    lints: LintArgs,
    #[command(flatten)]
    capabilities: CompileCapabilities,
    #[command(flatten)]
    selection: SourceSelection,
    /// One seiyaku source, reusable modules, or test modules. A `koto_test` module
    /// is checked in test mode against its target.
    #[arg(value_name = "SOURCE", required = true)]
    sources: Vec<PathBuf>,
}
/// Lint levels selected on the command line.
#[derive(Args, Debug, Default, Clone)]
struct LintArgs {
    /// Fail the check when any lint would warn (every `warn` lint becomes `deny`).
    #[arg(long)]
    deny_warnings: bool,
    /// Do not report the lint with this name, such as `unused-local` (repeatable).
    #[arg(long = "allow", value_name = "LINT")]
    allow: Vec<String>,
    /// Report the lint with this name as a warning (repeatable).
    #[arg(long = "warn", value_name = "LINT")]
    warn: Vec<String>,
    /// Report the lint with this name as an error that fails the check (repeatable).
    #[arg(long = "deny", value_name = "LINT")]
    deny: Vec<String>,
}
impl LintArgs {
    /// Validate the flags: every name must be a registered lint, and one lint gets one level.
    fn config(&self) -> Result<LintConfig, KotoError> {
        let mut config = LintConfig::new();
        let mut selected = BTreeMap::<&str, LintLevel>::new();
        for (names, level) in [
            (&self.allow, LintLevel::Allow),
            (&self.warn, LintLevel::Warn),
            (&self.deny, LintLevel::Deny),
        ] {
            for name in names {
                if let Some(previous) = selected.insert(name, level)
                    && previous != level
                {
                    return Err(KotoError::Usage(format!(
                        "lint `{name}` is given both `--{}` and `--{}`",
                        previous.as_str(),
                        level.as_str()
                    )));
                }
                config
                    .set_level(name, level)
                    .map_err(|unknown| KotoError::Usage(unknown.to_string()))?;
            }
        }
        config.set_deny_warnings(self.deny_warnings);
        Ok(config)
    }
}
#[derive(Args, Debug)]
struct BuildArgs {
    /// Diagnostic output format.
    #[arg(long, value_enum, default_value_t)]
    format: DiagnosticFormat,
    /// Build profile; selects the output directory `<target-dir>/<profile>`.
    #[arg(long, value_name = "NAME", default_value = "dev")]
    profile: String,
    /// Root directory for build outputs.
    #[arg(long, value_name = "DIR", default_value = "target/kotodama")]
    target_dir: PathBuf,
    /// Write the `.to` artifact to this exact path (one source only).
    #[arg(long, value_name = "FILE.to")]
    out: Option<PathBuf>,
    /// Write the manifest to this path, or `-` for stdout (one source only).
    #[arg(long, value_name = "FILE.json")]
    manifest_out: Option<PathBuf>,
    /// Cycle ceiling recorded in the artifact header; must not exceed node admission policy.
    #[arg(long, value_name = "COUNT", value_parser = clap::value_parser!(u64).range(1..))]
    max_cycles: Option<u64>,
    /// Check durable-state compatibility with the previous complete `.to` artifact before
    /// publishing one replacement. Runtime migration must still initialize newly added scalars.
    #[arg(long, value_name = "PREVIOUS.to")]
    upgrade_from: Option<PathBuf>,
    /// Verify that existing outputs match a fresh build without writing anything.
    #[arg(long)]
    verify: bool,
    #[command(flatten)]
    capabilities: CompileCapabilities,
    #[command(flatten)]
    selection: SourceSelection,
    /// Seiyaku sources to build. Each produces its own artifact.
    #[arg(value_name = "SOURCE", required = true)]
    sources: Vec<PathBuf>,
}
/// `koto test` with an optional action; a bare `koto test <SOURCE>` runs the suite.
#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct TestArgs {
    #[command(subcommand)]
    action: Option<TestAction>,
    #[command(flatten)]
    run: TestRunArgs,
}
#[derive(Subcommand, Debug)]
enum TestAction {
    /// Compile and run the selected tests (the default action).
    Run(TestRunArgs),
    /// List the discovered tests without compiling them.
    List(TestListArgs),
    /// Run the selected tests and report which seiyaku functions executed.
    Coverage(TestCoverageArgs),
    /// Run the selected tests and print a per-instruction execution trace.
    Trace(TestTraceArgs),
}
/// Suite discovery and selection shared by every `koto test` action.
#[derive(Args, Debug, Clone)]
struct TestSuiteArgs {
    /// Run only tests whose name contains this text (or equals it with --exact).
    #[arg(long, value_name = "TEXT")]
    filter: Option<String>,
    /// Require --filter to match the complete test name.
    #[arg(long, requires = "filter")]
    exact: bool,
    /// Deterministic ordering seed; 0 runs tests in name order.
    #[arg(long, value_name = "N", default_value_t = 0)]
    seed: u64,
    #[command(flatten)]
    capabilities: CompileCapabilities,
    #[command(flatten)]
    selection: SourceSelection,
    /// A seiyaku with inline tests, or a `*.test.ko` module declaring `koto_test { target: ... }`.
    #[arg(value_name = "SOURCE", required = true)]
    source: Option<PathBuf>,
}
#[derive(Args, Debug, Clone)]
struct TestRunArgs {
    /// Report format written to stdout.
    #[arg(long, value_enum, default_value_t)]
    format: TestRunFormat,
    /// Also write a JUnit XML report to this file.
    #[arg(long, value_name = "FILE.xml")]
    junit: Option<PathBuf>,
    /// Print a per-kotoage gas table (calls, min, mean, max) after the results.
    #[arg(long)]
    gas_report: bool,
    /// Number of tests executed in parallel.
    #[arg(long, short = 'j', value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=256))]
    jobs: u64,
    #[command(flatten)]
    suite: TestSuiteArgs,
}
#[derive(Args, Debug, Clone)]
struct TestListArgs {
    /// Listing format.
    #[arg(long, value_enum, default_value_t)]
    format: TestListFormat,
    #[command(flatten)]
    suite: TestSuiteArgs,
}
#[derive(Args, Debug, Clone)]
struct TestCoverageArgs {
    /// Number of tests executed in parallel.
    #[arg(long, short = 'j', value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=256))]
    jobs: u64,
    #[command(flatten)]
    suite: TestSuiteArgs,
}
#[derive(Args, Debug, Clone)]
struct TestTraceArgs {
    /// Trace format: readable steps, or one JSON object per executed instruction.
    #[arg(long, value_enum, default_value_t)]
    format: TestListFormat,
    #[command(flatten)]
    suite: TestSuiteArgs,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum TestRunFormat {
    #[default]
    Human,
    Json,
    Junit,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum TestListFormat {
    #[default]
    Human,
    Json,
}
#[derive(Args, Debug)]
struct FmtArgs {
    /// Report files that need formatting without rewriting them (exit status 8 if any).
    #[arg(long)]
    check: bool,
    /// Files or directories; directories are searched recursively for `*.ko` files, skipping
    /// hidden and `target` directories. Defaults to the current directory.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
}
#[derive(Args, Debug)]
struct DocArgs {
    /// Generate the complete source-visible builtin reference without compiling a source.
    #[arg(long, conflicts_with_all = ["source", "source_root", "zk", "chain_discriminant"])]
    builtins: bool,
    /// Documentation format.
    #[arg(long, value_enum, default_value_t)]
    format: DocFormat,
    #[command(flatten)]
    capabilities: CompileCapabilities,
    #[command(flatten)]
    selection: SourceSelection,
    /// Seiyaku source to document.
    #[arg(value_name = "SOURCE", required_unless_present = "builtins")]
    source: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum DocFormat {
    #[default]
    Markdown,
    Json,
}
#[derive(Args, Debug)]
struct ExplainArgs {
    /// Diagnostic code (`K2003`, `E_TEST_ONLY_PRODUCTION`), lint name (`unused-parameter`), or
    /// branded keyword in either spelling (`kotoage`, `言挙げ`).
    #[arg(value_name = "TOPIC", required_unless_present = "list")]
    topic: Option<String>,
    /// List every diagnostic code, lint name, and branded keyword.
    #[arg(long, conflicts_with = "topic")]
    list: bool,
    /// Output format; `markdown` renders a reference page with one anchor per code.
    #[arg(long, value_enum, default_value_t)]
    format: explain::ExplainFormat,
}
#[derive(Args, Debug)]
struct LspArgs {
    #[command(flatten)]
    capabilities: CompileCapabilities,
    #[command(flatten)]
    selection: SourceSelection,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum DiagnosticFormat {
    #[default]
    Human,
    Json,
    Sarif,
}
impl DiagnosticFormat {
    fn render(self, diagnostics: &DiagnosticBundle) -> String {
        match self {
            Self::Human => {
                let mut diagnostics = diagnostics.clone();
                if let Ok(cwd) = std::env::current_dir() {
                    diagnostics.relativize_sources(&cwd.canonicalize().unwrap_or(cwd));
                }
                diagnostics.render_human()
            }
            Self::Json => diagnostics
                .render_json()
                .unwrap_or_else(|error| format!("failed to render diagnostics: {error}")),
            Self::Sarif => diagnostics
                .render_sarif()
                .unwrap_or_else(|error| format!("failed to render diagnostics: {error}")),
        }
    }
}
/// A failed `koto` command and the exit status it selects.
#[derive(Debug)]
enum KotoError {
    /// Malformed command line detected after parsing (for example a conflicting combination).
    Usage(String),
    /// A file could not be read or written.
    Io(String),
    /// Code was rejected or tests failed; the details were already rendered or are in the text.
    Failed(String),
    /// Structured compiler diagnostics rendered in the requested format.
    Diagnostics {
        format: DiagnosticFormat,
        diagnostics: DiagnosticBundle,
    },
    /// The toolchain itself failed.
    Internal(String),
    /// Failing tests whose report was already printed.
    TestsFailed,
    /// A complete rendered failure report (for example compiler diagnostics), printed as is.
    Rendered(String),
}
impl KotoError {
    fn exit_status(&self) -> ExitStatus {
        match self {
            Self::Usage(_) => ExitStatus::Usage,
            Self::Io(_) => ExitStatus::Io,
            Self::Failed(_) | Self::Diagnostics { .. } | Self::Rendered(_) => ExitStatus::Failed,
            Self::TestsFailed => ExitStatus::TestsFailed,
            Self::Internal(_) => ExitStatus::Internal,
        }
    }
}
impl std::fmt::Display for KotoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message)
            | Self::Io(message)
            | Self::Failed(message)
            | Self::Internal(message) => formatter.write_str(message),
            Self::Diagnostics {
                format,
                diagnostics,
            } => formatter.write_str(&format.render(diagnostics)),
            Self::TestsFailed => Ok(()),
            Self::Rendered(report) => formatter.write_str(report),
        }
    }
}
fn build_error(format: DiagnosticFormat, error: BuildError) -> KotoError {
    match error {
        BuildError::Io { .. } => KotoError::Io(error.to_string()),
        BuildError::InvalidProfile(_)
        | BuildError::InvalidStem(_)
        | BuildError::InvalidPath { .. }
        | BuildError::OutputCollision { .. } => KotoError::Usage(error.to_string()),
        BuildError::Render(_) | BuildError::Internal(_) => KotoError::Internal(error.to_string()),
        error => match error.into_diagnostics() {
            Ok(diagnostics) => KotoError::Diagnostics {
                format,
                diagnostics,
            },
            Err(error) => KotoError::Failed(error.to_string()),
        },
    }
}
/// Attach physical project paths before rendering a build's canonical source diagnostics.
fn located_build_error(
    format: DiagnosticFormat,
    error: BuildError,
    source_paths: &BTreeMap<ProjectSourceKey, BTreeSet<PathBuf>>,
) -> KotoError {
    let mut error = build_error(format, error);
    if let KotoError::Diagnostics { diagnostics, .. } = &mut error {
        // Different roots in one batch may share a logical companion path. Keep ambiguous
        // identities logical rather than pointing at the wrong file.
        let unique_sources = source_paths
            .iter()
            .filter_map(|(key, paths)| {
                (paths.len() == 1)
                    .then(|| (key.clone(), paths.first().expect("one source").clone()))
            })
            .collect();
        for diagnostic in &mut diagnostics.diagnostics {
            remap_locked_project_diagnostic_sources(diagnostic, &unique_sources);
        }
    }
    error
}
/// Keep load-time parser diagnostics rooted in the same physical files as build diagnostics.
fn rooted_build_error(format: DiagnosticFormat, error: BuildError, root: &Path) -> KotoError {
    let mut error = build_error(format, error);
    if let KotoError::Diagnostics { diagnostics, .. } = &mut error {
        for diagnostic in &mut diagnostics.diagnostics {
            remap_rooted_diagnostic_sources(diagnostic, root);
        }
    }
    error
}
impl From<kotodama_toolchain::koto_test_driver::KotoTestCliError> for KotoError {
    fn from(error: kotodama_toolchain::koto_test_driver::KotoTestCliError) -> Self {
        use kotodama_toolchain::koto_test_driver::KotoTestCliErrorKind as Kind;
        match error.kind {
            Kind::Usage => Self::Usage(error.message),
            Kind::Io => Self::Io(error.message),
            Kind::Compile => Self::Rendered(error.message),
            Kind::TestsFailed => Self::TestsFailed,
            Kind::Internal => Self::Internal(error.message),
        }
    }
}
fn main() {
    std::process::exit(run_process(env::args_os()).code());
}
/// Parse a full process argument vector, run the command, and report its exit status.
fn run_process<I, T>(args: I) -> ExitStatus
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let command = Cli::command().long_version(koto_long_version());
    let cli = match command.try_get_matches_from(args) {
        Ok(matches) => match Cli::from_arg_matches(&matches) {
            Ok(cli) => cli,
            Err(error) => return report_clap_error(&error),
        },
        Err(error) => return report_clap_error(&error),
    };
    match run(cli) {
        Ok(()) => ExitStatus::Success,
        Err(error) => {
            let status = error.exit_status();
            match error {
                KotoError::Diagnostics {
                    format,
                    diagnostics,
                } => eprintln!("{}", format.render(&diagnostics)),
                // Failing tests already printed their report.
                KotoError::TestsFailed => {}
                KotoError::Rendered(report) => eprintln!("{report}"),
                other => eprintln!("error: {other}"),
            }
            status
        }
    }
}
fn report_clap_error(error: &clap::Error) -> ExitStatus {
    use clap::error::ErrorKind;
    let _ = error.print();
    match error.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            if error.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
                ExitStatus::Usage
            } else {
                ExitStatus::Success
            }
        }
        _ => ExitStatus::Usage,
    }
}
fn run(cli: Cli) -> Result<(), KotoError> {
    match cli.command {
        KotoCommand::Check(args) => check(args),
        KotoCommand::Build(args) => build(args),
        KotoCommand::Test(args) => run_tests(args),
        KotoCommand::Fmt(args) => format_sources(args),
        KotoCommand::Doc(args) => document(args),
        KotoCommand::Explain(args) => explain::run(&args.topic, args.list, args.format),
        KotoCommand::Lsp(args) => language_server(args),
    }
}
/// Translate the parsed `koto test` command line into the runner's option record.
fn test_cli_options(args: TestArgs) -> kotodama_toolchain::koto_test_driver::KotoTestCliOptions {
    use kotodama_toolchain::koto_test_driver::{
        KotoTestAction, KotoTestCliOptions, KotoTestReportFormat,
    };
    let suite_options = |action: KotoTestAction, suite: TestSuiteArgs| {
        let TestSuiteArgs {
            filter,
            exact,
            seed,
            capabilities,
            selection,
            source,
        } = suite;
        let mut options = KotoTestCliOptions::new(action, capabilities.chain_discriminant());
        options.source = source;
        options.source_root = selection.source_root;
        options.filter = filter;
        options.exact = exact;
        options.seed = seed;
        options.zk_enabled = capabilities.zk;
        options
    };
    let run_options = |args: TestRunArgs| {
        let mut options = suite_options(KotoTestAction::Run, args.suite);
        options.format = match args.format {
            TestRunFormat::Human => KotoTestReportFormat::Human,
            TestRunFormat::Json => KotoTestReportFormat::Json,
            TestRunFormat::Junit => KotoTestReportFormat::Junit,
        };
        options.junit = args.junit;
        options.gas_report = args.gas_report;
        options.jobs = usize::try_from(args.jobs).unwrap_or(1);
        options
    };
    let list_format = |format: TestListFormat| match format {
        TestListFormat::Human => KotoTestReportFormat::Human,
        TestListFormat::Json => KotoTestReportFormat::Json,
    };
    match args.action {
        None => run_options(args.run),
        Some(TestAction::Run(run)) => run_options(run),
        Some(TestAction::List(list)) => {
            let mut options = suite_options(KotoTestAction::List, list.suite);
            options.format = list_format(list.format);
            options
        }
        Some(TestAction::Coverage(coverage)) => {
            let mut options = suite_options(KotoTestAction::Coverage, coverage.suite);
            options.jobs = usize::try_from(coverage.jobs).unwrap_or(1);
            options
        }
        Some(TestAction::Trace(trace)) => {
            let mut options = suite_options(KotoTestAction::Trace, trace.suite);
            options.format = list_format(trace.format);
            options
        }
    }
}
fn run_tests(args: TestArgs) -> Result<(), KotoError> {
    kotodama_toolchain::koto_test_driver::run_cli(test_cli_options(args)).map_err(KotoError::from)
}
fn source_root_for_input(input: &Path, explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(root) = explicit {
        return root
            .canonicalize()
            .map_err(|error| format!("resolve source root `{}`: {error}", root.display()));
    }
    input
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("resolve source root: {error}"))
}
fn check(args: CheckArgs) -> Result<(), KotoError> {
    let CheckArgs {
        format,
        lints,
        capabilities,
        selection,
        sources,
    } = args;
    let lint_flags = lints.config()?;
    // A source that cannot be opened is an I/O failure (exit status 10), as in every other
    // subcommand, not a diagnostic about Kotodama code.
    if let Some((path, error)) = sources.iter().find_map(|path| {
        std::fs::File::open(path)
            .err()
            .map(|error| (path.as_path(), error))
    }) {
        return Err(KotoError::Io(format!(
            "cannot read `{}`: {error}",
            path.display()
        )));
    }
    let chain_discriminant = capabilities.chain_discriminant();
    let session = CompilerSession::new(CompilerOptions {
        force_zk: capabilities.zk,
        chain_discriminant,
        ..CompilerOptions::default()
    });
    let driver = BuildDriver::new(session, "koto-check");
    let (test_modules, sources): (Vec<_>, Vec<_>) = sources
        .into_iter()
        .partition(|path| is_test_module_path(path));
    let (mut checked, mut diagnostics) = if sources.is_empty() {
        (Vec::new(), DiagnosticBundle::new(Vec::new()))
    } else {
        check_project_paths_with_root(
            &driver,
            sources,
            selection.source_root.as_deref(),
            &lint_flags,
        )
    };
    let mut test_targets = Vec::new();
    for module in test_modules {
        match kotodama_toolchain::koto_test_driver::check_test_module_v1(
            &module,
            selection.source_root.as_deref(),
            chain_discriminant,
            capabilities.zk,
        ) {
            Ok(target) => {
                test_targets.push((module.clone(), target));
                checked.push(module);
            }
            Err(kotodama_toolchain::koto_test_driver::KotoTestCheckErrorV1::Diagnostics(
                bundle,
            )) => diagnostics.diagnostics.extend(bundle.diagnostics),
            Err(kotodama_toolchain::koto_test_driver::KotoTestCheckErrorV1::Other(error)) => {
                return Err(KotoError::from(error));
            }
        }
    }
    if format == DiagnosticFormat::Human {
        for path in &checked {
            match test_targets.iter().find(|(module, _)| module == path) {
                Some((_, target)) => println!(
                    "checked {} (test module for {}; run `koto test {}`)",
                    display_path(path),
                    display_path(target),
                    display_path(path)
                ),
                None => println!("checked {}", display_path(path)),
            }
        }
        if !diagnostics.diagnostics.is_empty() {
            eprintln!("{}", format.render(&diagnostics));
        }
    } else {
        // A batch is one machine-readable document, including the successful
        // empty result. Concatenated JSON arrays or SARIF logs are not valid
        // input for CI consumers.
        println!("{}", format.render(&diagnostics));
    }
    if diagnostics
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        Err(KotoError::Failed(
            "one or more sources failed validation".to_owned(),
        ))
    } else {
        Ok(())
    }
}
/// Display a path relative to the working directory when it lies inside it.
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
/// Whether `path` parses as a standalone test module (`module` with `koto_test { target: ... }`).
///
/// Unreadable or unparsable files are not test modules here; the ordinary check path reports
/// their diagnostics.
fn is_test_module_path(path: &Path) -> bool {
    read_source_file(path).is_ok_and(|source| {
        kotodama_lang::parser::parse(&source).is_ok_and(|program| program.test_target.is_some())
    })
}
fn check_loaded_project(
    driver: &BuildDriver,
    loaded: LoadedSourceProject,
    lint_flags: &LintConfig,
) -> (Vec<PathBuf>, DiagnosticBundle) {
    let lint_config = loaded.lints.merged_with(lint_flags);
    let source_paths = loaded.source_paths;
    let checked_graph = match loaded.graph {
        LoadedProjectGraph::Source(graph)
            if kotodama_lang::parser::parse(&graph.root.source).is_ok_and(|program| {
                program.unit.kind == kotodama_lang::ast::SourceUnitKind::Module
            }) && graph.imports.is_empty()
                && graph.packages.is_empty() =>
        {
            driver.check_module_sources(graph.root, graph.sources, graph.artifacts)
        }
        LoadedProjectGraph::Source(graph) => driver.check_project(graph),
        LoadedProjectGraph::Package(graph) => driver.check_package_project(graph),
    };
    match checked_graph {
        Ok(warnings) => {
            let checked = source_paths
                .values()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let diagnostics = warnings
                .into_iter()
                .filter_map(|warning| {
                    let lint = leveled_lint(&lint_config, warning.warning)?;
                    let key = ProjectSourceKey {
                        package_identity: warning.package_identity.clone(),
                        source_name: warning.source_name.clone(),
                    };
                    let path = source_paths
                        .get(&key)
                        .map_or_else(|| Path::new(&warning.source_name), PathBuf::as_path);
                    Some(lint.to_diagnostic(
                        &display_path(path),
                        warning.package_identity.as_deref(),
                        kotodama_lang::i18n::detect_language(),
                    ))
                })
                .collect();
            (checked, DiagnosticBundle::new(diagnostics))
        }
        Err(error) => {
            let mut bundle = error.into_diagnostics().unwrap_or_else(|error| {
                DiagnosticBundle::single(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    error.to_string(),
                    None,
                ))
            });
            for diagnostic in &mut bundle.diagnostics {
                remap_locked_project_diagnostic_sources(diagnostic, &source_paths);
            }
            (Vec::new(), bundle)
        }
    }
}
#[cfg(test)]
fn check_project_paths(
    driver: &BuildDriver,
    inputs: Vec<PathBuf>,
) -> (Vec<PathBuf>, DiagnosticBundle) {
    check_project_paths_with_root(driver, inputs, None, &LintConfig::default())
}
fn check_project_paths_with_root(
    driver: &BuildDriver,
    inputs: Vec<PathBuf>,
    explicit_root: Option<&Path>,
    lint_config: &LintConfig,
) -> (Vec<PathBuf>, DiagnosticBundle) {
    if let [input] = inputs.as_slice() {
        let root = source_root_for_input(input, explicit_root);
        let loaded = root
            .clone()
            .map_err(|error| BuildError::InvalidPath {
                path: input.clone(),
                message: error,
            })
            .and_then(|root| load_source_project(input, &root, &BTreeMap::new()));
        match loaded {
            Ok(loaded) => {
                return check_loaded_project(driver, loaded, lint_config);
            }
            Err(error) => {
                let mut diagnostics = error.into_diagnostics().unwrap_or_else(|error| {
                    DiagnosticBundle::single(Diagnostic::error(
                        "K0000",
                        DiagnosticPhase::Lex,
                        error.to_string(),
                        None,
                    ))
                });
                // Loading parses the source and its companions; name them by the same
                // working-directory-relative paths as semantic diagnostics.
                if let Ok(root) = root {
                    for diagnostic in &mut diagnostics.diagnostics {
                        remap_rooted_diagnostic_sources(diagnostic, &root);
                    }
                }
                return (Vec::new(), diagnostics);
            }
        }
    }
    let preferred_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut checked = Vec::new();
    let mut diagnostics = Vec::new();
    let mut sources = Vec::new();
    let mut source_paths = HashMap::<String, String>::new();
    let mut project_inputs = Vec::new();
    for path in inputs {
        let source = match read_source_file(&path) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    format!("failed to read source `{}`: {error}", path.display()),
                    None,
                ));
                continue;
            }
        };
        let project_root = match project_root_for_source(&path, &preferred_root) {
            Ok(root) => root,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    error.to_string(),
                    None,
                ));
                continue;
            }
        };
        let canonical_path = match path.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    format!(
                        "failed to canonicalize source `{}` after reading it: {error}",
                        path.display()
                    ),
                    None,
                ));
                continue;
            }
        };
        let source_name = match logical_source_name(&canonical_path, &project_root) {
            Ok(source_name) => source_name,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    error.to_string(),
                    None,
                ));
                continue;
            }
        };
        let display_path = path.display().to_string();
        if let Some(first) = source_paths.get(&source_name) {
            diagnostics.push(Diagnostic::error(
                "K0000",
                DiagnosticPhase::Lex,
                format!(
                    "explicit sources `{first}` and `{display_path}` have the same logical project path `{source_name}`"
                ),
                None,
            ));
            continue;
        }
        source_paths.insert(source_name.clone(), display_path);
        sources.push(SourceModuleUnit {
            source_name,
            source,
        });
        project_inputs.push(path);
    }
    if !sources.is_empty() {
        match driver.check_explicit_sources(sources) {
            Ok(warnings) => {
                checked.extend(project_inputs);
                diagnostics.extend(warnings.into_iter().filter_map(|warning| {
                    let lint = leveled_lint(lint_config, warning.warning)?;
                    let path = source_paths
                        .get(&warning.source_name)
                        .map(String::as_str)
                        .unwrap_or(warning.source_name.as_str());
                    Some(lint_diagnostic(lint, Path::new(path)))
                }));
            }
            Err(error) => match error.into_diagnostics() {
                Ok(mut bundle) => {
                    for diagnostic in &mut bundle.diagnostics {
                        remap_project_diagnostic_sources(diagnostic, &source_paths);
                    }
                    diagnostics.extend(bundle.diagnostics);
                }
                Err(error) => diagnostics.push(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    error.to_string(),
                    None,
                )),
            },
        }
    }
    (checked, DiagnosticBundle::new(diagnostics))
}
#[cfg(test)]
fn check_paths(
    session: &CompilerSession,
    inputs: Vec<PathBuf>,
) -> (Vec<PathBuf>, DiagnosticBundle) {
    let mut checked = Vec::new();
    let mut diagnostics = Vec::new();
    for path in inputs {
        match check_path(session, &path) {
            Ok(bundle) => {
                checked.push(path);
                diagnostics.extend(bundle.diagnostics);
            }
            Err(bundle) => diagnostics.extend(bundle.diagnostics),
        }
    }
    (checked, DiagnosticBundle::new(diagnostics))
}
fn build(args: BuildArgs) -> Result<(), KotoError> {
    let BuildArgs {
        format: diagnostic_format,
        profile,
        target_dir,
        out: explicit_output,
        manifest_out: explicit_manifest_output,
        max_cycles,
        upgrade_from,
        verify,
        capabilities,
        selection,
        sources: inputs,
    } = args;
    let publish_mode = if verify {
        PublishMode::Verify
    } else {
        PublishMode::Write
    };
    let source_root = selection.source_root;
    let build_count = inputs.len();
    if explicit_output.is_some() && build_count != 1 {
        return Err(KotoError::Usage(
            "--out can be used only when building one source".to_owned(),
        ));
    }
    if explicit_manifest_output.is_some() && build_count != 1 {
        return Err(KotoError::Usage(
            "--manifest-out can be used only when building one source".to_owned(),
        ));
    }
    if upgrade_from.is_some() && build_count != 1 {
        return Err(KotoError::Usage(
            "--upgrade-from can be used only when building one replacement source".to_owned(),
        ));
    }
    let previous_artifact = upgrade_from
        .as_ref()
        .map(|path| {
            let bytes = std::fs::read(path).map_err(|error| {
                KotoError::Io(format!(
                    "read previous artifact `{}`: {error}",
                    path.display()
                ))
            })?;
            ivm::verify_contract_artifact(&bytes).map_err(|error| {
                upgrade_diagnostic(
                    diagnostic_format,
                    "E_UPGRADE_BASE_INVALID",
                    format!(
                        "previous artifact `{}` failed canonical admission: {error}",
                        path.display()
                    ),
                )
            })
        })
        .transpose()?;
    let mut compiler_options = CompilerOptions::default();
    if let Some(max_cycles) = max_cycles {
        compiler_options.max_cycles = max_cycles;
    }
    compiler_options.chain_discriminant = capabilities.chain_discriminant();
    compiler_options.force_zk = capabilities.zk;
    let session = CompilerSession::new(compiler_options);
    let driver = BuildDriver::for_current_executable(session)
        .map_err(|error| build_error(diagnostic_format, error))?;
    let manifest_stdout = explicit_manifest_output.as_deref() == Some(Path::new("-"));
    let mut diagnostic_sources = BTreeMap::<ProjectSourceKey, BTreeSet<PathBuf>>::new();
    let mut remember_sources = |loaded: &LoadedSourceProject| {
        for (key, path) in &loaded.source_paths {
            diagnostic_sources
                .entry(key.clone())
                .or_default()
                .insert(path.clone());
        }
    };
    let projects = {
        let mut projects = Vec::with_capacity(inputs.len());
        for input in &inputs {
            let stem = input
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    KotoError::Usage(format!("{} has no UTF-8 file stem", input.display()))
                })?
                .to_owned();
            let project_root =
                source_root_for_input(input, source_root.as_deref()).map_err(KotoError::Io)?;
            let loaded = load_source_project(input, &project_root, &BTreeMap::new())
                .map_err(|error| rooted_build_error(diagnostic_format, error, &project_root))?;
            remember_sources(&loaded);
            let LoadedProjectGraph::Source(graph) = loaded.graph else {
                unreachable!("source loader returns a source graph")
            };
            let source_name = graph.root.source_name.clone();
            projects.push((stem, source_name, graph));
        }
        projects
    };
    let migration_obligations = if let Some(previous) = previous_artifact.as_ref() {
        let (_, source_name, graph) = &projects[0];
        let replacement = driver
            .compile_project(graph.clone(), source_name)
            .map_err(|error| located_build_error(diagnostic_format, error, &diagnostic_sources))?;
        let replacement =
            ivm::verify_contract_artifact(&replacement.artifact).map_err(|error| {
                KotoError::Internal(format!(
                    "fresh replacement artifact failed canonical admission: {error}"
                ))
            })?;
        let plan = ivm_abi::upgrade::validate_contract_upgrade(
            &previous.contract_interface,
            &replacement.contract_interface,
        )
        .map_err(|error| {
            upgrade_diagnostic(
                diagnostic_format,
                "E_UPGRADE_INCOMPATIBLE",
                error.to_string(),
            )
        })?;
        Some(
            plan.added_scalars
                .iter()
                .map(|state| state.name.clone())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let mut requests = Vec::with_capacity(projects.len());
    for (stem, source_name, graph) in projects {
        let mut layout = if let Some(output) = explicit_output.as_ref() {
            PublishLayout::for_artifact(output.clone(), None, None)
        } else {
            PublishLayout::standard(&target_dir, &profile, &stem, false)
        }
        .map_err(|error| build_error(diagnostic_format, error))?;
        if let Some(manifest) = explicit_manifest_output
            .as_ref()
            .filter(|path| path.as_path() != Path::new("-"))
        {
            layout.manifest = manifest.clone();
        }
        if manifest_stdout {
            layout = layout.with_sidecar_manifest();
        }
        requests.push(LinkedSourceBuildRequest {
            graph,
            source_name,
            profile: profile.clone(),
            layout,
            mode: publish_mode,
        });
    }
    let outcomes = driver
        .build_project_batch(requests)
        .map_err(|error| located_build_error(diagnostic_format, error, &diagnostic_sources))?;
    if let Some(scalars) = migration_obligations {
        eprintln!(
            "upgrade check: all existing durable state names and complete types are preserved"
        );
        if !scalars.is_empty() {
            eprintln!(
                "kaizen must initialize new scalar state: {}; the runtime validates these values during migration",
                scalars.join(", "),
            );
        }
    }
    for outcome in outcomes {
        let warnings = kotodama_toolchain::deployment_diagnostics::artifact_deployment_warnings(
            &outcome.artifact,
        )
        .map_err(|error| {
            KotoError::Internal(format!(
                "fresh artifact failed canonical admission: {error}"
            ))
        })?;
        if !warnings.diagnostics.is_empty() {
            eprintln!("{}", diagnostic_format.render(&warnings));
        }
        let notice = match outcome.status {
            BuildStatus::Fresh => "fresh",
            BuildStatus::Built => "built",
        };
        if manifest_stdout {
            eprintln!("{notice} {}", outcome.paths.artifact.display());
            println!(
                "{}",
                norito::json::to_json_pretty(&outcome.manifest).map_err(|error| {
                    KotoError::Internal(format!("render contract manifest: {error}"))
                })?
            );
        } else {
            println!("{notice} {}", outcome.paths.artifact.display());
        }
    }
    Ok(())
}
/// Render upgrade preflight failures through the compiler's human, JSON and SARIF channels.
fn upgrade_diagnostic(format: DiagnosticFormat, code: &str, message: String) -> KotoError {
    KotoError::Diagnostics {
        format,
        diagnostics: DiagnosticBundle::single(Diagnostic::error(
            code,
            DiagnosticPhase::Artifact,
            message,
            None,
        )),
    }
}
fn format_sources(args: FmtArgs) -> Result<(), KotoError> {
    let FmtArgs { check, paths } = args;
    let paths = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths
    };
    let inputs = collect_format_inputs(&paths)?;
    if inputs.is_empty() {
        return Err(KotoError::Usage(format!(
            "no `*.ko` sources found under {}",
            paths
                .iter()
                .map(|path| format!("`{}`", path.display()))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let mut changed = false;
    let mut invalid = false;
    for path in inputs {
        let source = read_source_file(&path).map_err(|error| KotoError::Io(error.to_string()))?;
        let formatted = match format_source_text(&source, path.to_str()) {
            Ok(formatted) => formatted,
            Err(diagnostics) => {
                // Keep formatting the remaining files; one invalid file must not hide drift in
                // the others.
                eprintln!("{diagnostics}");
                invalid = true;
                continue;
            }
        };
        if formatted != source {
            changed = true;
            if check {
                println!("would format {}", display_path(&path));
            } else {
                atomic_write_if_changed(&path, formatted.as_bytes())
                    .map_err(|error| KotoError::Io(error.to_string()))?;
                println!("formatted {}", display_path(&path));
            }
        }
    }
    if invalid {
        Err(KotoError::Failed(
            "one or more sources are not valid Kotodama and were left unchanged".to_owned(),
        ))
    } else if check && changed {
        Err(KotoError::Failed(
            "one or more sources require formatting; run `koto fmt` to rewrite them".to_owned(),
        ))
    } else {
        Ok(())
    }
}
/// Expand `koto fmt` operands: files are kept as given and directories are searched recursively
/// for `*.ko` sources in sorted order, skipping hidden directories, `target`, and symbolic links.
fn collect_format_inputs(paths: &[PathBuf]) -> Result<Vec<PathBuf>, KotoError> {
    let mut inputs = BTreeSet::new();
    for path in paths {
        let metadata = std::fs::metadata(path)
            .map_err(|error| KotoError::Io(format!("read `{}`: {error}", path.display())))?;
        if metadata.is_dir() {
            collect_ko_sources(path, &mut inputs)?;
        } else {
            inputs.insert(path.clone());
        }
    }
    Ok(inputs.into_iter().collect())
}
fn collect_ko_sources(directory: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), KotoError> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| KotoError::Io(format!("read `{}`: {error}", directory.display())))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| KotoError::Io(format!("read `{}`: {error}", directory.display())))?;
        let file_type = entry
            .file_type()
            .map_err(|error| KotoError::Io(format!("read `{}`: {error}", directory.display())))?;
        let path = entry.path();
        let hidden_or_output = entry
            .file_name()
            .to_str()
            .is_none_or(|name| name.starts_with('.') || name == "target");
        if file_type.is_dir() {
            if !hidden_or_output {
                collect_ko_sources(&path, out)?;
            }
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "ko")
        {
            out.insert(path);
        }
    }
    Ok(())
}
fn format_source_text(source: &str, source_name: Option<&str>) -> Result<String, String> {
    let file = SourceFile::new(SourceId(0), source_name.unwrap_or("<source>"), source);
    format_source(&file, FrontendBudget::v1())
        .map_err(|diagnostics| DiagnosticFormat::Human.render(&diagnostics))
}
fn document(args: DocArgs) -> Result<(), KotoError> {
    let DocArgs {
        builtins,
        format,
        capabilities,
        selection,
        source,
    } = args;
    if builtins {
        let rendered = match format {
            DocFormat::Markdown => doc_builtins::markdown(),
            DocFormat::Json => {
                norito::json::to_json_pretty(&doc_builtins::json().map_err(KotoError::Internal)?)
                    .map_err(|error| {
                        KotoError::Internal(format!("render builtin reference: {error}"))
                    })?
            }
        };
        println!("{rendered}");
        return Ok(());
    }
    let session = CompilerSession::new(CompilerOptions {
        force_zk: capabilities.zk,
        chain_discriminant: capabilities.chain_discriminant(),
        ..CompilerOptions::default()
    });
    let graph = {
        let path = source.ok_or_else(|| KotoError::Usage("doc expects a .ko source".to_owned()))?;
        let project_root = source_root_for_input(&path, selection.source_root.as_deref())
            .map_err(KotoError::Io)?;
        discover_source_link_request(&path, &project_root, Vec::new(), Vec::new())
            .map_err(|error| build_error(DiagnosticFormat::Human, error))?
    };
    let source_name = graph.root.source_name.clone();
    let root_source = graph.root.source.clone();
    let analysis = kotodama_lang::editor::EditorSnapshot::project(&graph, capabilities.zk);
    let source_id = analysis
        .sources()
        .find(|source| source.name() == source_name)
        .map(SourceFile::id)
        .ok_or_else(|| {
            KotoError::Internal(
                "documentation source is absent from the explicit project graph".to_owned(),
            )
        })?;
    let source_signatures = analysis.unit_declaration_signatures(source_id);
    let driver = BuildDriver::new(session, "koto-doc");
    let output = driver
        .compile_project(graph, &source_name)
        .map_err(|error| build_error(DiagnosticFormat::Human, error))?;
    let verified = ivm::verify_contract_artifact(&output.artifact).map_err(|error| {
        KotoError::Internal(format!("documentation artifact failed admission: {error}"))
    })?;
    let private_input_entrypoints = verified.private_input_entrypoints();
    let rendered = match format {
        DocFormat::Json => {
            let mut documentation =
                contract_documentation_json(&output.manifest, &source_signatures)
                    .map_err(KotoError::Internal)?;
            let requires_private_input_host = !private_input_entrypoints.is_empty();
            let private_input_names = private_input_entrypoints.to_vec();
            let requirements = norito::json!({
                "requires_private_input_host": requires_private_input_host,
                "private_input_entrypoints": private_input_names,
            });
            if let norito::json::Value::Object(fields) = &mut documentation {
                fields.insert("deployment_requirements".to_owned(), requirements);
            }
            norito::json::to_json_pretty(&documentation).map_err(|error| {
                KotoError::Internal(format!("render contract interface: {error}"))
            })?
        }
        DocFormat::Markdown => {
            let mut rendered = render_contract_documentation(
                &output.manifest,
                &DocumentationContext::new(&source_signatures, Some(&root_source)),
            );
            if !private_input_entrypoints.is_empty() {
                rendered.push_str(&format!(
                    "\n> Prover/test host required: {} reach raw private-input transport. Production consensus hosts do not provide private witnesses. Generate proofs off-chain and deploy a public-proof verifier.\n",
                    private_input_entrypoints.iter().map(|name| format!("`{}`", markdown_inline(name))).collect::<Vec<_>>().join(", ")
                ));
            }
            rendered
        }
    };
    println!("{rendered}");
    Ok(())
}
fn markdown_inline(text: &str) -> String {
    text.replace(['\n', '\r'], " ").replace('`', "\\`")
}
fn contract_documentation_json(
    manifest: &iroha_data_model::smart_contract::manifest::ContractManifest,
    signatures: &[kotodama_lang::editor::EditorSignature],
) -> Result<norito::json::Value, String> {
    use norito::json::{Value, object};
    let signatures = signatures
        .iter()
        .map(|signature| {
            let parameters = signature
                .parameters
                .iter()
                .map(|parameter| {
                    object([
                        ("name", Value::from(parameter.name.clone())),
                        ("type", Value::from(parameter.ty.clone())),
                        (
                            "call_mode",
                            Value::from(if parameter.named {
                                "named"
                            } else {
                                "positional"
                            }),
                        ),
                    ])
                })
                .collect::<Result<Vec<_>, _>>()?;
            object([
                ("name", Value::from(signature.name.clone())),
                ("parameters", Value::Array(parameters)),
                ("return_type", Value::from(signature.return_type.clone())),
                (
                    "documentation",
                    Value::from(signature.authored_documentation.clone()),
                ),
            ])
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    object([
        (
            "manifest",
            norito::json::to_value(manifest).map_err(|error| error.to_string())?,
        ),
        ("source_signatures", Value::Array(signatures)),
    ])
    .map_err(|error| error.to_string())
}
/// Inputs to `koto doc` beyond the manifest: the source-form signatures and the keyword spelling
/// written at each declaration.
struct DocumentationContext<'a> {
    signatures: &'a [kotodama_lang::editor::EditorSignature],
    spellings: BTreeMap<String, String>,
}
impl<'a> DocumentationContext<'a> {
    fn new(signatures: &'a [kotodama_lang::editor::EditorSignature], source: Option<&str>) -> Self {
        Self {
            signatures,
            spellings: source.map(declared_keyword_spellings).unwrap_or_default(),
        }
    }
}
/// Map each kotoage, hajimari and kaizen declaration to the keyword spelling written in source,
/// so generated documentation echoes `言挙げ` where the author wrote `言挙げ`.
fn declared_keyword_spellings(source: &str) -> BTreeMap<String, String> {
    use kotodama_lang::lexer::TokenKind;
    let Ok(tokens) = kotodama_lang::lexer::lex(source) else {
        return BTreeMap::new();
    };
    let spelling = |token: &kotodama_lang::lexer::Token| {
        source
            .get(token.range.start as usize..token.range.end as usize)
            .map(ToOwned::to_owned)
    };
    let mut spellings = BTreeMap::new();
    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Kotoage => {
                if let (Some(fn_token), Some(name_token)) =
                    (tokens.get(index + 1), tokens.get(index + 2))
                    && fn_token.kind == TokenKind::Fn
                    && let TokenKind::Ident(name) = &name_token.kind
                    && let Some(written) = spelling(token)
                {
                    spellings.insert(name.clone(), written);
                }
            }
            TokenKind::Hajimari | TokenKind::Kaizen => {
                let entry = if token.kind == TokenKind::Hajimari {
                    "hajimari"
                } else {
                    "kaizen"
                };
                if let Some(written) = spelling(token) {
                    spellings.insert(entry.to_owned(), written);
                }
            }
            _ => {}
        }
    }
    spellings
}
/// Canonical JSON example for one argument schema: the exact object `koto test`, Torii and the
/// CLIs accept for this entrypoint. Numbers that would lose precision in JSON (`int`, `decimal`,
/// `quantity`) are decimal strings.
fn argument_example(
    schema: &iroha_data_model::smart_contract::entrypoint::EntrypointArgumentSchemaV1,
) -> String {
    let fields = schema
        .fields
        .iter()
        .map(|field| {
            let mut index = 0;
            format!(
                "{}: {}",
                norito::json::to_string(&norito::json::Value::from(field.name.clone()))
                    .unwrap_or_else(|_| format!("\"{}\"", field.name)),
                value_example(&field.ty.nodes, &mut index)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{fields}}}")
}
fn value_example(
    nodes: &[iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1],
    index: &mut usize,
) -> String {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1 as Node,
    };
    let Some(node) = nodes.get(*index) else {
        return "null".to_owned();
    };
    *index += 1;
    match node {
        Node::Struct(structure) => {
            let fields = structure
                .fields
                .iter()
                .map(|field| format!("\"{field}\": {}", value_example(nodes, index)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{fields}}}")
        }
        Node::Tuple(arity) => {
            let items = (0..*arity)
                .map(|_| value_example(nodes, index))
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{items}]")
        }
        Node::Option => {
            skip_value(nodes, index);
            "{\"none\": true}".to_owned()
        }
        Node::Result => {
            let ok = value_example(nodes, index);
            skip_value(nodes, index);
            format!("{{\"ok\": {ok}}}")
        }
        Node::List(_) => {
            skip_value(nodes, index);
            "[]".to_owned()
        }
        Node::Unit => "null".to_owned(),
        Node::Error(error) => error.variants.first().map_or_else(
            || "null".to_owned(),
            |variant| format!("\"{}\"", variant.name),
        ),
        Node::Enum(error) => error.variants.first().map_or_else(
            || "null".to_owned(),
            |variant| format!("\"{}\"", variant.name),
        ),
        Node::StateCursor(_) => "\"0x…\"".to_owned(),
        Node::Leaf(kind) => match kind {
            Kind::Int | Kind::Quantity => "\"0\"",
            Kind::Decimal => "\"0.0\"",
            Kind::Bool => "false",
            Kind::String => "\"\"",
            Kind::Json => "{}",
            Kind::Name => "\"name\"",
            Kind::AccountId => "\"<account id>\"",
            Kind::AssetDefinitionId => "\"<asset definition id>\"",
            Kind::AssetId => "\"<asset id>\"",
            Kind::DomainId => "\"<domain>.<dataspace>\"",
            Kind::NftId => "\"<nft id>\"",
            Kind::DataSpaceId => "0",
            Kind::Blob => "\"0x\"",
        }
        .to_owned(),
    }
}
/// Encoding rules `koto doc` states for one argument schema, each only when a parameter uses it:
/// numbers that would lose precision in JSON are decimal strings, and options are tagged objects.
fn argument_encoding_notes(
    schema: &iroha_data_model::smart_contract::entrypoint::EntrypointArgumentSchemaV1,
) -> String {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1 as Node,
    };
    let nodes = || schema.fields.iter().flat_map(|field| &field.ty.nodes);
    let mut notes = String::new();
    if nodes().any(|node| matches!(node, Node::Leaf(Kind::Int | Kind::Decimal | Kind::Quantity))) {
        notes.push_str(" `int`, `decimal` and `quantity` values are canonical decimal strings.");
    }
    if nodes().any(|node| matches!(node, Node::Option)) {
        notes.push_str(" Options are `{\"some\": value}` or `{\"none\": true}`.");
    }
    if nodes().any(|node| matches!(node, Node::Enum(_))) {
        notes.push_str(
            " Ordinary enum values use the exact declared variant name as a JSON string.",
        );
    }
    notes
}
/// Advance `index` past one complete value subtree.
fn skip_value(
    nodes: &[iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1],
    index: &mut usize,
) {
    let _ = value_example(nodes, index);
}
/// Whether an error identity is owned by the compiler rather than declared by the seiyaku.
fn is_compiler_owned_error(identity: &str) -> bool {
    identity.starts_with("kotodama::")
}
fn render_contract_documentation(
    manifest: &iroha_data_model::smart_contract::manifest::ContractManifest,
    context: &DocumentationContext<'_>,
) -> String {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    use std::fmt::Write as _;
    let seiyaku_name = manifest.seiyaku_name.as_deref().unwrap_or("Seiyaku");
    let mut output = format!("# {}\n", markdown_inline(seiyaku_name));
    if let Some(code_hash) = manifest.code_hash.as_ref() {
        let _ = writeln!(output, "\nCanonical artifact: `{code_hash}`");
    }
    if let Some(abi_hash) = manifest.abi_hash.as_ref() {
        let _ = writeln!(output, "ABI V1: `{abi_hash}`");
    }
    if !manifest.permissions.is_empty() {
        use iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1;
        output.push_str("\n## Declared permissions\n\n| Name | Grant scope |\n| --- | --- |\n");
        for permission in &manifest.permissions {
            let scope = match &permission.scope {
                ContractPermissionScopeV1::Instance => "this deployed instance".to_owned(),
                ContractPermissionScopeV1::Chain { permission_name } => format!(
                    "explicit chain import `{}`",
                    markdown_inline(permission_name.as_ref())
                ),
            };
            let _ = writeln!(
                output,
                "| `{}` | {scope} |",
                markdown_inline(permission.name.as_ref())
            );
        }
    }
    let entrypoints = manifest.entrypoints.as_deref().unwrap_or_default();
    let keyword = |romaji: &str| {
        kotodama_lang::glossary::by_spelling(romaji).map_or_else(
            || format!("`{romaji}`"),
            |keyword| format!("`{}` / `{}`", keyword.romaji, keyword.kanji),
        )
    };
    let sections = [
        (
            EntryPointKind::Kotoage,
            format!("{} (authorized public mutations)", keyword("kotoage")),
        ),
        (EntryPointKind::View, "Views (read-only calls)".to_owned()),
        (
            EntryPointKind::Hajimari,
            format!("Lifecycle: {}", keyword("hajimari")),
        ),
        (
            EntryPointKind::Kaizen,
            format!("Lifecycle: {}", keyword("kaizen")),
        ),
    ];
    for (kind, title) in sections {
        let declared = entrypoints
            .iter()
            .filter(|entrypoint| entrypoint.kind == kind)
            .collect::<Vec<_>>();
        if declared.is_empty() {
            continue;
        }
        let _ = writeln!(output, "\n## {title}");
        for entrypoint in declared {
            render_entrypoint_documentation(&mut output, entrypoint, context);
        }
    }
    if let Some(states) = manifest.states.as_deref()
        && !states.is_empty()
    {
        output.push_str("\n## Durable state\n");
        for state in states {
            let _ = writeln!(
                output,
                "\n- `{}` `{}`",
                markdown_inline(&state.type_name),
                markdown_inline(&state.name)
            );
        }
    }
    if !manifest.enum_types.is_empty() {
        output.push_str("\n## Ordinary enums\n");
        for descriptor in &manifest.enum_types {
            let _ = writeln!(
                output,
                "\n- `{}`: {}",
                markdown_inline(&descriptor.identity),
                descriptor
                    .variants
                    .iter()
                    .map(|variant| format!(
                        "`{}` ({})",
                        markdown_inline(&variant.name),
                        variant.code
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if !manifest.events.is_empty() {
        output.push_str("\n## Events\n\nCommitted emissions carry the authenticated contract, artifact, entrypoint and caller alongside this payload.\n");
        for event in &manifest.events {
            let mut index = 0;
            let example = value_example(&event.payload_type.nodes, &mut index);
            let _ = writeln!(
                output,
                "\n### `{}`\n\n```json\n{}\n```",
                markdown_inline(event.name.as_ref()),
                example
            );
        }
    }
    let error_types = manifest.error_types.as_deref().unwrap_or_default();
    let render_errors = |output: &mut String| {
        for error in error_types
            .iter()
            .filter(|error| !is_compiler_owned_error(&error.identity))
        {
            for variant in &error.variants {
                let _ = writeln!(
                    output,
                    "\n- `{}::{}` = `{}`",
                    markdown_inline(&error.identity),
                    markdown_inline(&variant.name),
                    variant.code
                );
            }
        }
    };
    if error_types
        .iter()
        .any(|error| !is_compiler_owned_error(&error.identity))
    {
        output.push_str("\n## Seiyaku errors\n");
        render_errors(&mut output);
    }
    let compiler_owned = error_types
        .iter()
        .filter(|error| is_compiler_owned_error(&error.identity))
        .collect::<Vec<_>>();
    if !compiler_owned.is_empty() {
        output.push_str(
            "\n## Runtime errors\n\nCompiler-owned errors that checked list and numeric operations can raise in any seiyaku:\n",
        );
        for error in compiler_owned {
            let _ = writeln!(
                output,
                "\n- `{}`: {}",
                markdown_inline(&error.identity),
                error
                    .variants
                    .iter()
                    .map(|variant| format!(
                        "`{}` ({})",
                        markdown_inline(&variant.name),
                        variant.code
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    output
}
fn render_entrypoint_documentation(
    output: &mut String,
    entrypoint: &iroha_data_model::smart_contract::manifest::EntrypointDescriptor,
    context: &DocumentationContext<'_>,
) {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    use std::fmt::Write as _;
    let written = context.spellings.get(&entrypoint.name).map(String::as_str);
    let _ = writeln!(
        output,
        "\n### `{}`\n",
        markdown_inline(&entrypoint_declaration(entrypoint, context, written))
    );
    if let Some(signature) = context
        .signatures
        .iter()
        .find(|signature| signature.name == entrypoint.name)
        && !signature.authored_documentation.is_empty()
    {
        let _ = writeln!(output, "{}\n", signature.authored_documentation);
    }
    let declaration = match entrypoint.kind {
        EntryPointKind::Kotoage => format!(
            "Declared with `{}`: an authorized call that may change durable state and the ledger.",
            written.unwrap_or("kotoage")
        ),
        EntryPointKind::View => "Declared with `view`: a read-only call.".to_owned(),
        EntryPointKind::Hajimari => format!(
            "Declared with `{}`: the one-shot activation hook. Until it runs, every other call and view is rejected.",
            written.unwrap_or("hajimari")
        ),
        EntryPointKind::Kaizen => format!(
            "Declared with `{}`: the migration hook run once after this seiyaku's code is replaced in place.",
            written.unwrap_or("kaizen")
        ),
    };
    let _ = writeln!(output, "{declaration}");
    use iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1;
    match &entrypoint.authorization {
        EntrypointAuthorizationV1::Permission(permission) => {
            let _ = writeln!(
                output,
                "Authorization: declared permission `{}`",
                markdown_inline(permission.as_ref())
            );
        }
        EntrypointAuthorizationV1::RuntimeLifecycle => {
            output.push_str(
                "Authorization: the runtime `CanInvokeContractEntrypoint` lifecycle permission\n",
            );
        }
        EntrypointAuthorizationV1::Anyone => output.push_str("Authorization: anyone\n"),
    }
    match entrypoint.argument_schema.as_ref() {
        Some(schema) => {
            let _ = writeln!(
                output,
                "Arguments: a JSON object keyed by parameter name, for example `{}`.{}",
                markdown_inline(&argument_example(schema)),
                argument_encoding_notes(schema)
            );
        }
        None if !entrypoint.params.is_empty() => {
            output.push_str("Arguments: a JSON object keyed by parameter name; `int`, `decimal` and `quantity` values are canonical decimal strings.\n");
        }
        None => output.push_str("Arguments: none (send `{}`).\n"),
    }
    let complete = entrypoint.access_hints_complete == Some(true)
        && entrypoint.access_hints_skipped.is_empty();
    if complete {
        output.push_str("Access analysis: complete; the scheduler can run this call in parallel with calls that touch other keys.\n");
    } else {
        output.push_str("Access analysis: conservative; the compiler could not list every key this call touches, so the scheduler serializes it with other calls to this seiyaku. This affects throughput, not correctness.\n");
    }
    if !entrypoint.read_keys.is_empty() {
        let _ = writeln!(
            output,
            "Reads: {}",
            entrypoint
                .read_keys
                .iter()
                .map(|key| format!("`{}`", markdown_inline(key)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !entrypoint.write_keys.is_empty() {
        let _ = writeln!(
            output,
            "Writes: {}",
            entrypoint
                .write_keys
                .iter()
                .map(|key| format!("`{}`", markdown_inline(key)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for reason in &entrypoint.access_hints_skipped {
        let _ = writeln!(output, "Access note: {}", markdown_inline(reason));
    }
}
/// Source-syntax declaration header of an entrypoint, as `koto doc` headings show it.
///
/// Uses the editor snapshot's declaration (which keeps the keyword spelling written at the
/// declaration site) and otherwise renders the manifest descriptor through the shared
/// [`kotodama_lang::signature_render`] printer.
fn entrypoint_declaration(
    entrypoint: &iroha_data_model::smart_contract::manifest::EntrypointDescriptor,
    context: &DocumentationContext<'_>,
    written: Option<&str>,
) -> String {
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    use kotodama_lang::{
        ast::FunctionKind,
        signature_render::{RenderParameter, SourceDeclaration, source_declaration},
    };
    if let Some(declaration) = context
        .signatures
        .iter()
        .find(|signature| signature.name == entrypoint.name)
        .map(|signature| signature.declaration.as_str())
        .filter(|declaration| !declaration.is_empty())
    {
        return declaration.to_owned();
    }
    let parameters = entrypoint
        .params
        .iter()
        .map(|parameter| RenderParameter {
            name: &parameter.name,
            ty: &parameter.type_name,
            named: true,
        })
        .collect::<Vec<_>>();
    source_declaration(&SourceDeclaration {
        documentation: None,
        kind: match entrypoint.kind {
            EntryPointKind::Kotoage => FunctionKind::Kotoage,
            EntryPointKind::View => FunctionKind::View,
            EntryPointKind::Hajimari => FunctionKind::Hajimari,
            EntryPointKind::Kaizen => FunctionKind::Kaizen,
        },
        keyword: written,
        name: &entrypoint.name,
        parameters: &parameters,
        return_type: entrypoint.return_type.as_deref().unwrap_or("()"),
        authorization: match &entrypoint.authorization {
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone => Some("anyone"),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(name) => Some(name.as_ref()),
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::RuntimeLifecycle => None,
        },
        is_test: false,
        fixture: None,
    })
}
fn parse_chain_discriminant(raw: &str) -> Result<u16, String> {
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "invalid --chain-discriminant value `{raw}`: expected a decimal integer in 1..=65535"
        ));
    }
    let value = raw.parse::<u16>().map_err(|_| {
        format!(
            "invalid --chain-discriminant value `{raw}`: expected a decimal integer in 1..=65535"
        )
    })?;
    if value == 0 {
        return Err("--chain-discriminant must be in 1..=65535".to_owned());
    }
    Ok(value)
}
#[cfg(test)]
fn compile_path(session: &CompilerSession, path: &Path) -> Result<CompileOutput, DiagnosticBundle> {
    let source = read_source_file(path).map_err(|error| {
        DiagnosticBundle::single(Diagnostic::error(
            "K0000",
            DiagnosticPhase::Lex,
            format!("failed to read source `{}`: {error}", path.display()),
            None,
        ))
    })?;
    session.build(CompileRequest {
        source: &source,
        source_name: path.to_str(),
    })
}
#[cfg(test)]
fn check_path(
    session: &CompilerSession,
    path: &Path,
) -> Result<DiagnosticBundle, DiagnosticBundle> {
    let source = read_source_file(path).map_err(|error| {
        DiagnosticBundle::single(Diagnostic::error(
            "K0000",
            DiagnosticPhase::Lex,
            format!("failed to read source `{}`: {error}", path.display()),
            None,
        ))
    })?;
    let warnings = session.check_with_lints(CompileRequest {
        source: &source,
        source_name: path.to_str(),
    })?;
    Ok(DiagnosticBundle::new(
        warnings
            .into_iter()
            .map(|warning| lint_diagnostic(warning, path))
            .collect(),
    ))
}
fn lint_diagnostic(warning: kotodama_lang::lint::LintWarning, path: &Path) -> Diagnostic {
    warning.to_diagnostic(
        &path.display().to_string(),
        None,
        kotodama_lang::i18n::detect_language(),
    )
}
/// Serve standalone source files through the shared language-server engine.
fn language_server(args: LspArgs) -> Result<(), KotoError> {
    kotodama_toolchain::lsp::run_project_stdio(
        kotodama_toolchain::lsp::ServerOptions {
            source_root: args.selection.source_root,
            zk_enabled: args.capabilities.zk,
            chain_discriminant: args.capabilities.chain_discriminant,
        },
        None,
    )
    .map_err(KotoError::Io)
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Parse a complete `koto` argument vector the way `main` does.
    fn parse_cli(args: &[&str]) -> Result<Cli, clap::Error> {
        let command = Cli::command().long_version(koto_long_version());
        let matches =
            command.try_get_matches_from(std::iter::once("koto").chain(args.iter().copied()))?;
        Cli::from_arg_matches(&matches)
    }
    #[test]
    fn command_inventory_is_exact_and_retired_names_stay_rejected() {
        let inventory = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            inventory,
            ["check", "build", "test", "fmt", "doc", "explain", "lsp"]
        );
        for retired in ["compile", "lint", "koto_compile", "koto_lint", "koto_test"] {
            let error = parse_cli(&[retired, "x.ko"]).expect_err("retired command");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{retired}"
            );
        }
        Cli::command().debug_assert();
    }
    #[test]
    fn builtin_documentation_is_an_explicit_source_free_mode() {
        for format in ["markdown", "json"] {
            let Cli {
                command: KotoCommand::Doc(args),
            } = parse_cli(&["doc", "--builtins", "--format", format]).expect("builtin reference")
            else {
                panic!("expected doc command");
            };
            assert!(args.builtins);
            assert!(args.source.is_none());
        }
        let Cli {
            command: KotoCommand::Doc(args),
        } = parse_cli(&["doc", "--builtins"]).expect("default builtin format")
        else {
            panic!("expected doc command");
        };
        assert_eq!(args.format, DocFormat::Markdown);
        for arguments in [
            vec!["doc"],
            vec!["doc", "--source-root", "src"],
            vec!["doc", "--format", "json"],
        ] {
            assert_eq!(
                parse_cli(&arguments).unwrap_err().kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
        }
        for arguments in [
            vec!["doc", "--builtins", "counter.ko"],
            vec!["doc", "--builtins", "--source-root", "src"],
            vec!["doc", "--builtins", "--zk"],
            vec!["doc", "--builtins", "--chain-discriminant", "753"],
        ] {
            assert_eq!(
                parse_cli(&arguments).unwrap_err().kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        assert!(
            parse_cli(&[
                "doc",
                "--source-root",
                "src",
                "--zk",
                "--chain-discriminant",
                "753",
                "src/counter.ko"
            ])
            .is_ok()
        );
    }
    #[test]
    fn every_subcommand_has_help_and_the_binary_reports_its_version() {
        for command in ["check", "build", "test", "fmt", "doc", "explain", "lsp"] {
            for flag in ["--help", "-h"] {
                let error = parse_cli(&[command, flag]).expect_err("help is reported through clap");
                assert_eq!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp,
                    "{command} {flag}"
                );
                assert_eq!(report_status_for(&error), ExitStatus::Success);
            }
        }
        for flag in ["--version", "-V"] {
            let error = parse_cli(&[flag]).expect_err("version is reported through clap");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        }
        let long = koto_long_version();
        assert!(long.contains("kotodama_lang/"));
        assert!(long.contains("IVM 1.1 bytecode"));
        assert!(long.lines().any(|line| {
            line.strip_prefix("abi_hash: ")
                .is_some_and(|hash| hash.len() == 64)
        }));
        let help = Cli::command().render_long_help().to_string();
        for status in [
            "0   success",
            "2   usage error",
            "8   compiler diagnostics",
            "10  ",
            "11  the tests ran",
            "70  internal",
        ] {
            assert!(
                help.contains(status),
                "help omits exit status `{status}`:\n{help}"
            );
        }
    }
    /// Exit status `main` selects for a clap parse outcome, without printing.
    fn report_status_for(error: &clap::Error) -> ExitStatus {
        use clap::error::ErrorKind;
        match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitStatus::Success,
            _ => ExitStatus::Usage,
        }
    }
    #[test]
    fn unknown_options_report_the_subcommand_usage_with_the_usage_status() {
        let error = parse_cli(&["check", "--frobnicate", "a.ko"]).expect_err("unknown flag");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        assert_eq!(report_status_for(&error), ExitStatus::Usage);
        assert!(error.to_string().contains("koto check"), "{error}");
        let error = parse_cli(&["build"]).expect_err("missing source");
        assert_eq!(report_status_for(&error), ExitStatus::Usage);
        assert_eq!(ExitStatus::Usage.code(), 2);
        assert_eq!(ExitStatus::Failed.code(), 8);
        assert_eq!(ExitStatus::Io.code(), 10);
        assert_eq!(ExitStatus::TestsFailed.code(), 11);
        assert_eq!(ExitStatus::Internal.code(), 70);
        assert_eq!(KotoError::Io("x".to_owned()).exit_status(), ExitStatus::Io);
        assert_eq!(
            KotoError::TestsFailed.exit_status(),
            ExitStatus::TestsFailed
        );
        assert_eq!(
            KotoError::from(kotodama_toolchain::koto_test_driver::KotoTestCliError {
                kind: kotodama_toolchain::koto_test_driver::KotoTestCliErrorKind::TestsFailed,
                message: String::new(),
            })
            .exit_status(),
            ExitStatus::TestsFailed
        );
        assert_eq!(
            KotoError::Failed("drift".to_owned()).exit_status(),
            ExitStatus::Failed
        );
    }
    #[test]
    fn test_options_take_explicit_report_paths_and_default_to_run() {
        use kotodama_toolchain::koto_test_driver::{KotoTestAction, KotoTestReportFormat};
        let Cli {
            command: KotoCommand::Test(args),
        } = parse_cli(&["test", "--junit", "report.xml", "tests/vault.test.ko"]).expect("parse")
        else {
            panic!("expected test command");
        };
        let options = test_cli_options(args);
        assert_eq!(options.action, KotoTestAction::Run);
        assert_eq!(options.junit, Some(PathBuf::from("report.xml")));
        assert_eq!(options.source, Some(PathBuf::from("tests/vault.test.ko")));
        assert_eq!(options.format, KotoTestReportFormat::Human);
        let error = parse_cli(&["test", "--junit", "tests/vault.test.ko"])
            .expect_err("--junit consumes its value, so the source is missing");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        for (action, expected) in [
            ("run", KotoTestAction::Run),
            ("list", KotoTestAction::List),
            ("coverage", KotoTestAction::Coverage),
            ("trace", KotoTestAction::Trace),
        ] {
            let Cli {
                command: KotoCommand::Test(args),
            } = parse_cli(&["test", action, "--filter", "quote", "--exact", "x.test.ko"])
                .expect("parse action")
            else {
                panic!("expected test command");
            };
            let options = test_cli_options(args);
            assert_eq!(options.action, expected);
            assert_eq!(options.filter.as_deref(), Some("quote"));
            assert!(options.exact);
        }
        let error =
            parse_cli(&["test", "--exact", "x.test.ko"]).expect_err("--exact needs --filter");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let error = parse_cli(&["test", "run", "--format", "text", "x.test.ko"])
            .expect_err("retired format spelling");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        let error = parse_cli(&["test", "--json", "x.test.ko"]).expect_err("retired --json flag");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        let error =
            parse_cli(&["test", "profile", "x.test.ko"]).expect_err("`profile` is now `trace`");
        assert_ne!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }
    #[test]
    fn layout_normalization_is_idempotent() {
        let formatted =
            format_source_text("seiyaku Demo {   \n}\n\n", None).expect("format valid source");
        assert_eq!(formatted, "seiyaku Demo {}\n");
        assert_eq!(
            format_source_text(&formatted, None).expect("reformat valid source"),
            formatted
        );
    }
    #[test]
    fn contract_documentation_is_stable_markdown_from_the_manifest() {
        let source = r#"
                    seiyaku Vault { permission CanDeposit;
                        error enum VaultError { Empty = 7 }
                        state int balance;
                        始まり() { balance = 0; }
                        kaizen() {}
                        言挙げ fn deposit(int amount) authorize(CanDeposit) {
                            require(amount > 0, VaultError::Empty);
                            balance = balance + amount;
                        }
                        view fn read() authorize(anyone) -> int { return balance; }
                    }
                "#;
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("vault.ko"),
            })
            .expect("compile documentation fixture");
        let markdown = render_contract_documentation(
            &output.manifest,
            &DocumentationContext::new(&[], Some(source)),
        );
        for expected in [
            "# Vault",
            "## `kotoage` / `言挙げ` (authorized public mutations)",
            "### `言挙げ fn deposit(int amount) authorize(CanDeposit)`",
            "### `始まり()`",
            "### `kaizen()`",
            "### `view fn read() authorize(anyone) -> int`",
            "Declared with `言挙げ`: an authorized call",
            "## Views (read-only calls)",
            "Declared with `view`: a read-only call.",
            "Arguments: none (send `{}`).",
            "## Lifecycle: `hajimari` / `始まり`",
            "Declared with `始まり`: the one-shot activation hook",
            "Declared with `kaizen`: the migration hook",
            "Authorization: declared permission `CanDeposit`",
            "for example `{\"amount\": \"0\"}`",
            "`int`, `decimal` and `quantity` values are canonical decimal strings",
            "## Durable state",
            "`int` `balance`",
            "## Seiyaku errors",
            "`Vault::VaultError::Empty` = `7`",
        ] {
            assert!(
                markdown.contains(expected),
                "generated documentation omitted {expected:?}:\n{markdown}"
            );
        }
        for absent in [
            "deposit(amount: int)",
            "deposit(int amount) -> ()",
            "External arguments use a JSON record",
        ] {
            assert!(
                !markdown.contains(absent),
                "unexpected {absent:?}:\n{markdown}"
            );
        }
        let runtime = markdown
            .find("## Runtime errors")
            .expect("runtime error appendix");
        assert!(
            markdown
                .find("kotodama::")
                .is_some_and(|first| first > runtime),
            "compiler-owned errors stay in the appendix:\n{markdown}"
        );
    }
    #[test]
    fn documentation_states_only_the_encodings_a_record_uses() {
        let source = "seiyaku Notes { view fn greet(string who) authorize(anyone) -> string { return who; } view fn pick(Option<int> limit) authorize(anyone) -> int { return 1; } }";
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("notes.ko"),
            })
            .expect("compile encoding documentation fixture");
        let schema = |name: &str| {
            output
                .manifest
                .entrypoints
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|entrypoint| entrypoint.name == name)
                .and_then(|entrypoint| entrypoint.argument_schema.clone())
                .expect("argument schema")
        };
        assert_eq!(argument_encoding_notes(&schema("greet")), "");
        assert_eq!(
            argument_encoding_notes(&schema("pick")),
            " `int`, `decimal` and `quantity` values are canonical decimal strings. Options are `{\"some\": value}` or `{\"none\": true}`."
        );
        let markdown = render_contract_documentation(
            &output.manifest,
            &DocumentationContext::new(&[], Some(source)),
        );
        assert!(
            markdown.contains("for example `{\"who\": \"\"}`.\n"),
            "{markdown}"
        );
    }
    #[test]
    fn documentation_groups_compiler_owned_errors_separately() {
        let source = "seiyaku Rates { view fn ratio(decimal left, decimal right) authorize(anyone) -> decimal { return left / right; } }";
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("rates.ko"),
            })
            .expect("compile numeric documentation fixture");
        let markdown = render_contract_documentation(
            &output.manifest,
            &DocumentationContext::new(&[], Some(source)),
        );
        if markdown.contains("kotodama::") {
            let runtime = markdown
                .find("## Runtime errors")
                .expect("runtime error heading");
            let first = markdown.find("kotodama::").expect("compiler-owned error");
            assert!(first > runtime, "{markdown}");
        }
        assert!(!markdown.contains("## Seiyaku errors"), "{markdown}");
        assert!(
            !markdown.contains("## `kotoage`"),
            "no kotoage section without kotoage:\n{markdown}"
        );
        assert!(
            markdown.contains("for example `{\"left\": \"0.0\", \"right\": \"0.0\"}`"),
            "{markdown}"
        );
    }
    #[test]
    fn source_documentation_includes_ordinary_enums_events_and_exact_json_names() {
        use kotodama_lang::editor::EditorSnapshot;
        let source = "seiyaku Events { enum Status { Active = 1, Done = 7 } event Changed { Status status; } view fn echo(Status value) authorize(anyone) -> Status { value } kotoage fn notify() authorize(anyone) { emit Changed { status: Status::Done }; } }";
        let snapshot = EditorSnapshot::single("events.ko", source, false);
        let signatures = snapshot.declaration_signatures(SourceId(0));
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("events.ko"),
            })
            .expect("compile enum/event documentation fixture");
        let markdown = render_contract_documentation(
            &output.manifest,
            &DocumentationContext::new(&signatures, Some(source)),
        );
        assert!(markdown.contains("## Ordinary enums"), "{markdown}");
        assert!(markdown.contains("`Active` (1), `Done` (7)"), "{markdown}");
        assert!(markdown.contains("## Events"), "{markdown}");
        assert!(markdown.contains("### `Changed`"), "{markdown}");
        assert!(markdown.contains("\"status\": \"Active\""), "{markdown}");
        assert!(
            markdown.contains("exact declared variant name as a JSON string"),
            "{markdown}"
        );
        let json = contract_documentation_json(&output.manifest, &signatures).unwrap();
        assert_eq!(json["manifest"]["events"].as_array().unwrap().len(), 1);
        assert_eq!(json["manifest"]["enum_types"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn source_documentation_keeps_authored_markdown_in_both_formats() {
        use kotodama_lang::editor::EditorSnapshot;
        let source = "seiyaku Help {\n/// Returns the **current** amount.\n///\n/// No state is changed.\nview fn amount() authorize(anyone) -> int { 1 }\n}";
        let snapshot = EditorSnapshot::single("help.ko", source, false);
        let signatures = snapshot.declaration_signatures(SourceId(0));
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("help.ko"),
            })
            .unwrap();
        let markdown = render_contract_documentation(
            &output.manifest,
            &DocumentationContext::new(&signatures, Some(source)),
        );
        assert!(
            markdown.contains("Returns the **current** amount.\n\nNo state is changed."),
            "{markdown}"
        );
        let json = contract_documentation_json(&output.manifest, &signatures).unwrap();
        assert_eq!(
            json["source_signatures"][0]["documentation"],
            norito::json::Value::from("Returns the **current** amount.\n\nNo state is changed.")
        );
    }

    #[test]
    fn source_documentation_preserves_call_modes_and_named_external_records() {
        use kotodama_lang::editor::EditorSnapshot;
        for (declaration, mode) in [("int amount", "named"), ("int _ amount", "positional")] {
            let source = format!(
                "seiyaku Labels {{ view fn echo({declaration}) authorize(anyone) -> int {{ amount }} }}"
            );
            let snapshot = EditorSnapshot::single("labels.ko", &source, false);
            let signatures = snapshot.declaration_signatures(SourceId(0));
            let output = CompilerSession::default()
                .build(CompileRequest {
                    source: &source,
                    source_name: Some("labels.ko"),
                })
                .expect("compile source documentation fixture");
            let markdown = render_contract_documentation(
                &output.manifest,
                &DocumentationContext::new(&signatures, Some(&source)),
            );
            assert!(
                markdown.contains(&format!(
                    "### `view fn echo({declaration}) authorize(anyone) -> int`"
                )),
                "{markdown}"
            );
            assert!(markdown.contains("`{\"amount\": \"0\"}`"), "{markdown}");
            let json = contract_documentation_json(&output.manifest, &signatures).unwrap();
            let echo = json
                .get("source_signatures")
                .and_then(norito::json::Value::as_array)
                .unwrap()
                .iter()
                .find(|value| {
                    value.get("name").and_then(norito::json::Value::as_str) == Some("echo")
                })
                .unwrap();
            let parameter = &echo
                .get("parameters")
                .and_then(norito::json::Value::as_array)
                .unwrap()[0];
            assert_eq!(
                parameter
                    .get("call_mode")
                    .and_then(norito::json::Value::as_str),
                Some(mode)
            );
            assert_eq!(
                output.manifest.entrypoints.as_ref().unwrap()[0].params[0].name,
                "amount"
            );
        }
    }
    #[test]
    fn formatter_validation_uses_lossless_v1_syntax() {
        format_source_text(
            "seiyaku Demo { view fn value() authorize(anyone) -> int { return 1; } }",
            Some("valid.ko"),
        )
        .expect("valid syntax");
        let branded = format_source_text(
            "誓約 Demo { permission Run;  言挙げ fn run() authorize(Run) {} }",
            Some("branded.ko"),
        )
        .expect("branded Japanese keywords are valid V1 syntax");
        assert_eq!(
            branded, "誓約 Demo {\n    permission Run;\n    言挙げ fn run() authorize(Run) {}\n}\n",
            "formatting must preserve the selected branded script",
        );
        let error = format_source_text(
            "seiyaku Démo { view fn value() authorize(anyone) -> int { return ; } }",
            Some("invalid.ko"),
        )
        .expect_err("invalid source must not be formatted");
        assert!(error.contains("K0100"));
        assert!(error.contains("invalid.ko"));
    }
    #[test]
    fn check_options_select_zk_policy_without_source_metadata() {
        let Cli {
            command: KotoCommand::Check(options),
        } = parse_cli(&[
            "check",
            "--format",
            "sarif",
            "--chain-discriminant",
            "369",
            "--zk",
            "--source-root",
            "contracts",
            "contracts/app.ko",
        ])
        .expect("parse check options")
        else {
            panic!("expected check");
        };
        assert_eq!(options.format, DiagnosticFormat::Sarif);
        assert!(options.capabilities.zk);
        assert_eq!(options.capabilities.chain_discriminant(), 369);
        assert_eq!(
            options.selection.source_root,
            Some(PathBuf::from("contracts"))
        );
        assert_eq!(options.sources, vec![PathBuf::from("contracts/app.ko")]);
        let error = parse_cli(&["check", "--project", "p.json"])
            .expect_err("project configuration belongs to Musubi");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        let error = parse_cli(&["check", "--format", "text", "a.ko"]).expect_err("retired alias");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }
    #[test]
    fn chain_discriminant_option_is_strict_and_nonzero() {
        assert_eq!(parse_chain_discriminant("369").expect("Taira value"), 369);
        assert_eq!(
            parse_chain_discriminant("65535").expect("maximum u16 value"),
            u16::MAX
        );
        for invalid in ["", "0", "0369", "+369", "-1", "369x", "65536"] {
            assert!(
                parse_chain_discriminant(invalid).is_err(),
                "accepted invalid discriminant {invalid:?}"
            );
        }
        let duplicate = parse_cli(&[
            "check",
            "--chain-discriminant",
            "369",
            "--chain-discriminant",
            "753",
            "contract.ko",
        ])
        .expect_err("duplicate option must fail closed");
        assert_eq!(duplicate.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    #[test]
    fn unreadable_sources_emit_native_structured_diagnostics() {
        let missing = std::env::temp_dir().join(format!(
            "koto-missing-source-{}-{}.ko",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let session = CompilerSession::default();
        for diagnostics in [
            compile_path(&session, &missing).expect_err("missing build source"),
            check_path(&session, &missing).expect_err("missing check source"),
        ] {
            let diagnostic = diagnostics
                .diagnostics
                .first()
                .expect("one read diagnostic");
            assert_eq!(diagnostic.code, "K0000");
            assert_eq!(diagnostic.phase, DiagnosticPhase::Lex);
            assert!(diagnostic.primary_span.is_none());
            assert!(diagnostic.message.contains(&missing.display().to_string()));
            assert!(!diagnostic.message.starts_with("K0000:"));
        }
    }
    #[test]
    fn check_batch_has_one_equivalent_json_and_sarif_diagnostic_set() {
        let root = std::env::temp_dir().join(format!(
            "koto-check-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create check batch root");
        let first = root.join("first.ko");
        let second = root.join("second.ko");
        std::fs::write(&first, "seiyaku First { € }").expect("write first invalid source");
        std::fs::write(&second, "seiyaku Second { £ }").expect("write second invalid source");
        let (checked, diagnostics) = check_paths(
            &CompilerSession::default(),
            vec![first.clone(), second.clone()],
        );
        assert!(checked.is_empty());
        assert!(diagnostics.diagnostics.len() >= 2);
        let sources = diagnostics
            .diagnostics
            .iter()
            .filter_map(|diagnostic| {
                diagnostic
                    .primary_span
                    .as_ref()
                    .and_then(|span| span.source.as_deref())
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(sources.contains(first.to_str().expect("UTF-8 first path")));
        assert!(sources.contains(second.to_str().expect("UTF-8 second path")));
        let json: norito::json::Value =
            norito::json::from_str(&DiagnosticFormat::Json.render(&diagnostics))
                .expect("batch JSON is one document");
        let sarif: norito::json::Value =
            norito::json::from_str(&DiagnosticFormat::Sarif.render(&diagnostics))
                .expect("batch SARIF is one document");
        assert_eq!(
            json.as_array().map(Vec::len),
            sarif
                .pointer("/runs/0/results")
                .and_then(norito::json::Value::as_array)
                .map(Vec::len),
        );
        std::fs::remove_dir_all(root).expect("remove check batch root");
    }
    #[test]
    fn build_errors_preserve_identical_canonical_fields_in_every_renderer() {
        let primary = SourceSpan {
            package_identity: None,
            source: Some("modules/app.ko".to_owned()),
            start: SourcePosition { line: 3, column: 9 },
            end: SourcePosition {
                line: 3,
                column: 22,
            },
            byte_range: Some(TextRange::new(41, 54)),
        };
        let related = SourceSpan {
            package_identity: None,
            source: Some("modules/math.ko".to_owned()),
            start: SourcePosition {
                line: 1,
                column: 18,
            },
            end: SourcePosition {
                line: 1,
                column: 24,
            },
            byte_range: Some(TextRange::new(17, 23)),
        };
        let mut diagnostic = Diagnostic::error(
            "E_UNEXPORTED_SYMBOL",
            DiagnosticPhase::Resolve,
            "source `modules/app.ko` cannot call unexported symbol `math::hidden`",
            Some(primary.clone()),
        );
        diagnostic.labels.push(DiagnosticLabel {
            span: related,
            message: "the private declaration is here".to_owned(),
        });
        diagnostic
            .notes
            .push("imports are explicit in V1".to_owned());
        diagnostic.fix = Some(DiagnosticFix {
            span: primary,
            replacement: "math::visible".to_owned(),
        });
        let diagnostics = DiagnosticBundle::single(diagnostic.clone());
        let human = build_error(
            DiagnosticFormat::Human,
            BuildError::Compile(diagnostics.clone()),
        )
        .to_string();
        for expected in [
            "error[E_UNEXPORTED_SYMBOL] resolve",
            "--> modules/app.ko:3:9",
            "= label: modules/math.ko:1:18: the private declaration is here",
            "imports are explicit in V1",
            "= help:",
            "= fix:",
            "math::visible",
        ] {
            assert!(
                human.contains(expected),
                "human diagnostics omitted {expected:?}"
            );
        }
        let json: norito::json::Value = norito::json::from_str(
            &build_error(
                DiagnosticFormat::Json,
                BuildError::Compile(diagnostics.clone()),
            )
            .to_string(),
        )
        .expect("build JSON diagnostics");
        let sarif: norito::json::Value = norito::json::from_str(
            &build_error(DiagnosticFormat::Sarif, BuildError::Compile(diagnostics)).to_string(),
        )
        .expect("build SARIF diagnostics");
        let canonical = diagnostic.to_json_value();
        assert_eq!(
            json.as_array().and_then(|items| items.first()),
            Some(&canonical)
        );
        assert_eq!(
            sarif.pointer("/runs/0/results/0/properties/kotodama"),
            Some(&canonical),
        );
    }
    #[test]
    fn unified_check_surfaces_lints_as_non_fatal_structured_warnings() {
        let root = std::env::temp_dir().join(format!(
            "koto-check-lint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create lint check root");
        let source = root.join("lint.ko");
        std::fs::write(
            &source,
            "seiyaku Lint { fn helper(int unused) -> int { return 1; } view fn value() authorize(anyone) -> int { return helper(unused: 0); } }",
        )
        .expect("write lint source");
        let warnings = check_path(&CompilerSession::default(), &source)
            .expect("lint warning must not fail semantic checking");
        let warning = warnings
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K5003")
            .expect("unused parameter warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert!(warning.primary_span.is_some());
        assert!(
            kotodama_lang::diagnostic::diagnostic_explanation("K5003").is_some(),
            "every unified lint code must work with koto explain",
        );
        std::fs::remove_dir_all(root).expect("remove lint check root");
    }
    #[test]
    fn lint_flags_validate_names_and_select_one_level_per_lint() {
        let flags = LintArgs {
            deny_warnings: false,
            allow: vec!["unused-local".to_owned()],
            warn: Vec::new(),
            deny: vec!["dead-store".to_owned()],
        };
        let config = flags.config().expect("known lints");
        assert_eq!(config.level("unused-local"), LintLevel::Allow);
        assert_eq!(config.level("dead-store"), LintLevel::Deny);
        assert_eq!(config.level("unused-state"), LintLevel::Warn);
        let conflicting = LintArgs {
            deny: vec!["unused-local".to_owned()],
            ..flags.clone()
        };
        assert!(matches!(
            conflicting.config(),
            Err(KotoError::Usage(message)) if message.contains("both `--allow` and `--deny`")
        ));
        let unknown = LintArgs {
            allow: vec!["unused-locl".to_owned()],
            ..LintArgs::default()
        };
        assert!(matches!(
            unknown.config(),
            Err(KotoError::Usage(message)) if message.contains("did you mean `unused-local`?")
        ));
        let denying = LintArgs {
            deny_warnings: true,
            ..LintArgs::default()
        }
        .config()
        .expect("deny-warnings");
        let warnings = CompilerSession::default()
            .check_with_lints(CompileRequest {
                source: "seiyaku L { view fn one() authorize(anyone) -> int { let unused = 1; return 1; } }",
                source_name: Some("l.ko"),
            })
            .expect("lints do not fail the check");
        let unused = warnings
            .into_iter()
            .find(|warning| warning.code == "unused-local")
            .expect("unused local");
        let denied = leveled_lint(&denying, unused.clone()).expect("denied lints are reported");
        assert_eq!(denied.severity, kotodama_lang::lint::LintSeverity::Error);
        assert!(
            leveled_lint(&config, unused).is_none(),
            "allowed lints are dropped"
        );
    }
    #[test]
    fn rooted_diagnostics_name_existing_sources_relative_to_the_working_directory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let span = |source: &str| SourceSpan {
            package_identity: None,
            source: Some(source.to_owned()),
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition { line: 1, column: 2 },
            byte_range: None,
        };
        let mut diagnostic = Diagnostic::error(
            "K1001",
            DiagnosticPhase::Parse,
            "message",
            Some(span("lib.rs")),
        );
        diagnostic.alternative_fixes.push(DiagnosticFix {
            span: span("missing.ko"),
            replacement: String::new(),
        });
        remap_rooted_diagnostic_sources(&mut diagnostic, &root);
        assert_eq!(
            diagnostic
                .primary_span
                .and_then(|span| span.source)
                .as_deref(),
            Some(display_path(&root.join("lib.rs")).as_str())
        );
        assert_eq!(
            diagnostic.alternative_fixes[0].span.source.as_deref(),
            Some("missing.ko"),
            "names that are not files below the root stay logical"
        );
    }
    #[test]
    fn build_and_format_diagnostics_preserve_physical_source_locations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let diagnostic = Diagnostic::error(
            "K1001",
            DiagnosticPhase::Parse,
            "message",
            Some(SourceSpan {
                package_identity: None,
                source: Some("lib.rs".to_owned()),
                start: SourcePosition { line: 1, column: 1 },
                end: SourcePosition { line: 1, column: 2 },
                byte_range: None,
            }),
        );
        let bundle = DiagnosticBundle::single(diagnostic);
        let source_paths = BTreeMap::from([(
            ProjectSourceKey {
                package_identity: None,
                source_name: "lib.rs".to_owned(),
            },
            BTreeSet::from([root.join("lib.rs")]),
        )]);
        for error in [
            located_build_error(
                DiagnosticFormat::Human,
                BuildError::Compile(bundle.clone()),
                &source_paths,
            ),
            rooted_build_error(DiagnosticFormat::Human, BuildError::Compile(bundle), &root),
        ] {
            assert!(
                error
                    .to_string()
                    .contains(&format!("--> {}:1:1", display_path(&root.join("lib.rs")))),
                "{error}"
            );
        }
        let path = root.join("invalid.ko");
        let error =
            format_source_text("seiyaku Invalid {", path.to_str()).expect_err("missing delimiter");
        assert!(
            error.contains(&format!("--> {}:", display_path(&path))),
            "{error}"
        );
    }
    #[test]
    fn unified_check_links_only_the_explicit_locked_project_graph() {
        let root = std::env::temp_dir().join(format!(
            "koto-check-project-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create project check root");
        let app = root.join("app.ko");
        let module = root.join("math.ko");
        std::fs::write(
            &app,
            "seiyaku App { view fn run() authorize(anyone) -> int { return Math::value(unused: 1); } }",
        )
        .expect("write project root");
        std::fs::write(
            &module,
            "module Math { export fn value(int unused) -> int { return 7; } }",
        )
        .expect("write project module");
        let load_graph = || {
            use kotodama_lang::linker::{ImportBinding, SourceLinkRequest, SourcePackageUnit};
            let package = "example/math@1.0.0".to_owned();
            LoadedSourceProject {
                graph: LoadedProjectGraph::Source(SourceLinkRequest {
                    artifacts: Vec::new(),
                    root: SourceModuleUnit {
                        source_name: "app.ko".into(),
                        source: std::fs::read_to_string(&app).unwrap(),
                    },
                    sources: Vec::new(),
                    imports: vec![ImportBinding {
                        alias: "Math".into(),
                        package: package.clone(),
                    }],
                    packages: vec![SourcePackageUnit {
                        artifacts: Vec::new(),
                        identity: package.clone(),
                        modules: vec![SourceModuleUnit {
                            source_name: "math.ko".into(),
                            source: std::fs::read_to_string(&module).unwrap(),
                        }],
                        sources: Vec::new(),
                        exports: BTreeSet::from(["value".into()]),
                        imports: Vec::new(),
                    }],
                }),
                source_paths: BTreeMap::from([
                    (
                        ProjectSourceKey {
                            package_identity: None,
                            source_name: "app.ko".into(),
                        },
                        app.canonicalize().unwrap(),
                    ),
                    (
                        ProjectSourceKey {
                            package_identity: Some(package),
                            source_name: "math.ko".into(),
                        },
                        module.canonicalize().unwrap(),
                    ),
                ]),
                manifests: Vec::new(),
                lints: LintConfig::default(),
            }
        };
        let driver = BuildDriver::new(CompilerSession::default(), "koto-check-test");
        let (checked, diagnostics) =
            check_loaded_project(&driver, load_graph(), &LintConfig::default());
        let canonical_app = app.canonicalize().expect("canonical app path");
        let canonical_module = module.canonicalize().expect("canonical module path");
        assert_eq!(
            checked,
            vec![canonical_app.clone(), canonical_module.clone()]
        );
        assert!(
            diagnostics
                .diagnostics
                .iter()
                .all(|diagnostic| { diagnostic.severity != Severity::Error })
        );
        let warning = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K5003")
            .expect("module lint warning");
        assert_eq!(
            warning
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref()),
            canonical_module.to_str()
        );
        assert_eq!(
            warning
                .primary_span
                .as_ref()
                .and_then(|span| span.package_identity.as_deref()),
            Some("example/math@1.0.0")
        );
        let (checked, positional) = check_project_paths(&driver, vec![app.clone(), module.clone()]);
        assert!(checked.is_empty());
        assert!(
            positional
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E_PROJECT_MANIFEST_REQUIRED")
        );
        std::fs::write(
            &app,
            "seiyaku App { view fn run() authorize(anyone) -> int { return Missing::value(); } }",
        )
        .expect("write unknown module call");
        let (checked, diagnostics) =
            check_loaded_project(&driver, load_graph(), &LintConfig::default());
        assert!(checked.is_empty());
        let error = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_UNKNOWN_IMPORT_ALIAS")
            .expect("unknown module alias diagnostic");
        assert_eq!(
            error
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref()),
            canonical_app.to_str()
        );
        std::fs::remove_dir_all(root).expect("remove project check root");
    }
    #[test]
    fn unified_check_rejects_multiple_explicit_roots_with_physical_spans() {
        let root = std::env::temp_dir().join(format!(
            "koto-check-roots-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create multiple-root check directory");
        let first = root.join("a.ko");
        let second = root.join("b.ko");
        std::fs::write(
            &first,
            "seiyaku A { view fn value() authorize(anyone) -> int { return 1; } }",
        )
        .expect("write first root");
        std::fs::write(
            &second,
            "seiyaku B { view fn value() authorize(anyone) -> int { return 2; } }",
        )
        .expect("write second root");
        let driver = BuildDriver::new(CompilerSession::default(), "koto-check-test");
        let (checked, diagnostics) =
            check_project_paths(&driver, vec![second.clone(), first.clone()]);
        assert!(checked.is_empty());
        let diagnostic = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_MULTIPLE_SEIYAKU_ROOTS")
            .expect("multiple-root diagnostic");
        assert_eq!(
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref()),
            first.to_str()
        );
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(diagnostic.labels[0].span.source.as_deref(), second.to_str());
        std::fs::remove_dir_all(root).expect("remove multiple-root check directory");
    }
    #[test]
    fn formatter_options_fail_closed_and_allow_dash_paths_after_separator() {
        let error = parse_cli(&["fmt", "--write", "demo.ko"])
            .expect_err("unknown formatter flags must not become file paths");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        let error = parse_cli(&["fmt", "--check", "--check", "demo.ko"])
            .expect_err("duplicate formatter options must fail closed");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        let Cli {
            command: KotoCommand::Fmt(args),
        } = parse_cli(&["fmt", "--check", "--", "--literal-name.ko"])
            .expect("separator permits a leading-dash file name")
        else {
            panic!("expected fmt");
        };
        assert!(args.check);
        assert_eq!(args.paths, vec![PathBuf::from("--literal-name.ko")]);
    }
    #[test]
    fn formatter_directories_expand_recursively_to_sorted_sources() {
        let root = std::env::temp_dir().join(format!(
            "koto-fmt-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        for directory in ["contracts", "tests/nested", "target/kotodama", ".hidden"] {
            std::fs::create_dir_all(root.join(directory)).expect("create fmt tree");
        }
        for file in [
            "contracts/b.ko",
            "contracts/a.ko",
            "tests/nested/c.test.ko",
            "target/kotodama/generated.ko",
            ".hidden/skip.ko",
            "contracts/readme.md",
        ] {
            std::fs::write(root.join(file), "seiyaku Demo {}\n").expect("write fmt input");
        }
        let inputs = collect_format_inputs(std::slice::from_ref(&root)).expect("expand directory");
        let relative = inputs
            .iter()
            .map(|path| path.strip_prefix(&root).expect("inside root").to_path_buf())
            .collect::<Vec<_>>();
        assert_eq!(
            relative,
            [
                PathBuf::from("contracts/a.ko"),
                PathBuf::from("contracts/b.ko"),
                PathBuf::from("tests/nested/c.test.ko"),
            ]
        );
        let explicit = root.join("target/kotodama/generated.ko");
        assert_eq!(
            collect_format_inputs(std::slice::from_ref(&explicit)).expect("explicit file"),
            vec![explicit]
        );
        assert!(matches!(
            collect_format_inputs(&[root.join("missing")]),
            Err(KotoError::Io(_))
        ));
        std::fs::remove_dir_all(root).expect("remove fmt tree");
    }
    fn build_args(args: &[&str]) -> BuildArgs {
        let mut full = vec!["build"];
        full.extend_from_slice(args);
        match parse_cli(&full).expect("parse build arguments").command {
            KotoCommand::Build(args) => args,
            other => panic!("expected build, got {other:?}"),
        }
    }
    #[test]
    fn upgrade_build_checks_admitted_interfaces_before_publishing() {
        let root = std::env::temp_dir().join(format!(
            "koto-upgrade-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let previous = CompilerSession::default().build(CompileRequest {
            source: "seiyaku Counter { state int total; hajimari() { total = 0; } view fn read() authorize(anyone) -> int { total } }",
            source_name: Some("previous.ko"),
        }).unwrap();
        let previous_path = root.join("previous.to");
        std::fs::write(&previous_path, previous.artifact).unwrap();
        let source_path = root.join("replacement.ko");
        let output = root.join("replacement.to");
        let args = || {
            build_args(&[
                source_path.to_str().unwrap(),
                "--out",
                output.to_str().unwrap(),
                "--upgrade-from",
                previous_path.to_str().unwrap(),
                "--format",
                "json",
            ])
        };
        for source in [
            "seiyaku Counter { view fn read() authorize(anyone) -> int { 0 } }",
            "seiyaku Counter { state bool total; hajimari() { total = false; } kaizen() {} view fn read() authorize(anyone) -> bool { total } }",
            "seiyaku Counter { state int total; state int added; hajimari() { total = 0; added = 0; } view fn read() authorize(anyone) -> int { total } }",
        ] {
            std::fs::write(&source_path, source).unwrap();
            let error = build(args()).expect_err("incompatible upgrade");
            assert!(
                error.to_string().contains("E_UPGRADE_INCOMPATIBLE"),
                "{error}"
            );
            assert!(
                !output.exists(),
                "failed upgrade must not publish any artifact"
            );
        }
        std::fs::write(&source_path, "seiyaku Counter { state int total; state int added; hajimari() { total = 0; added = 0; } kaizen() { added = 1; } view fn read() authorize(anyone) -> int { total + added } }").unwrap();
        build(args()).expect("compatible upgrade with explicit migration obligation");
        let published = std::fs::read(&output).unwrap();
        ivm::verify_contract_artifact(&published).expect("complete replacement artifact");
        std::fs::write(&previous_path, b"not an artifact").unwrap();
        let error = build(args()).expect_err("base artifact must pass admission");
        assert!(
            error.to_string().contains("E_UPGRADE_BASE_INVALID"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(&output).unwrap(),
            published,
            "failed preflight preserves prior output"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn build_rejects_standalone_module_without_publishing_artifact() {
        let root = std::env::temp_dir().join(format!(
            "koto-module-build-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let source = root.join("math.ko");
        let target = root.join("target/kotodama");
        std::fs::create_dir_all(&root).expect("create module test root");
        std::fs::write(
            &source,
            "module Math { export fn add(int left, int right) -> int { return left + right; } }",
        )
        .expect("write module source");
        let error = build(build_args(&[
            "--target-dir",
            &target.display().to_string(),
            &source.display().to_string(),
        ]))
        .expect_err("standalone module build must fail");
        assert!(
            error.to_string().contains("E_ROOT_MUST_BE_SEIYAKU"),
            "unexpected error: {error}"
        );
        assert!(!target.join("dev/math.to").exists());
        let session = CompilerSession::default();
        check_path(&session, &source).expect("module remains valid for koto check");
        std::fs::remove_dir_all(root).expect("remove module test root");
    }
    #[test]
    fn lsp_options_select_standalone_source_root() {
        let Cli {
            command: KotoCommand::Lsp(args),
        } = parse_cli(&[
            "lsp",
            "--zk",
            "--source-root",
            "contracts",
            "--chain-discriminant",
            "42",
        ])
        .expect("standalone LSP options")
        else {
            panic!("expected lsp");
        };
        assert!(args.capabilities.zk);
        assert_eq!(args.capabilities.chain_discriminant, 42);
        assert_eq!(args.selection.source_root, Some(PathBuf::from("contracts")));
        assert_eq!(
            parse_cli(&["lsp", "--project", "p.json"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::UnknownArgument
        );
    }
}
