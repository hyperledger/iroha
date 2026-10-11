//! Reusable canonical compiler session API.
use crate::{
    ast::{FunctionKind, Item, Program, SourceUnitKind},
    compiler::{CompileReport, Compiler, CompilerMode, CompilerOptions},
    diagnostic::{
        Diagnostic, DiagnosticBundle, DiagnosticLabel, DiagnosticPhase, SourcePosition, SourceSpan,
        phase_for_semantic_failure,
    },
    lexer::{Token, TokenKind},
    semantic::TypedProgram,
    source::{FrontendBudget, MAX_SOURCE_BYTES, SourceFile, SourceId, TextRange},
};
use indexmap::IndexMap;
use iroha_data_model::{
    account::address::{ChainDiscriminantGuard, chain_discriminant},
    smart_contract::manifest::ContractManifest,
};
use ivm_abi::metadata::EmbeddedContractInterfaceV1;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::{Condvar, Mutex, OnceLock},
};

// Parsing, resolution, semantic analysis, and lowering all consume the same
// attacker-controlled structural depth budget. Keep the complete canonical
// pipeline on a stack twice the 32 MiB debug-build boundary corpus. Two worker
// permits cap compiler-stack reservation at 128 MiB; standalone parser workers
// have their own 64 MiB global ceiling.
const COMPILER_STACK_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_COMPILER_WORKERS: usize = 2;

thread_local! {
    static COMPILER_WORKER_ACTIVE: Cell<bool> = const { Cell::new(false) };
    #[cfg(test)]
    static COMPILER_WORKER_SPAWNS: Cell<usize> = const { Cell::new(0) };
}

struct CompilerWorkerGate {
    active: Mutex<usize>,
    ready: Condvar,
}

impl CompilerWorkerGate {
    fn acquire(&'static self) -> CompilerWorkerPermit {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while *active >= MAX_COMPILER_WORKERS {
            active = self
                .ready
                .wait(active)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        *active = active.saturating_add(1);
        CompilerWorkerPermit { gate: self }
    }
}

struct CompilerWorkerPermit {
    gate: &'static CompilerWorkerGate,
}

impl Drop for CompilerWorkerPermit {
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

struct CompilerWorkerMarker {
    previous: bool,
}

impl CompilerWorkerMarker {
    fn enter() -> Self {
        let previous = COMPILER_WORKER_ACTIVE.with(|active| active.replace(true));
        Self { previous }
    }
}

impl Drop for CompilerWorkerMarker {
    fn drop(&mut self) {
        COMPILER_WORKER_ACTIVE.with(|active| active.set(self.previous));
    }
}

static COMPILER_WORKER_GATE: OnceLock<CompilerWorkerGate> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompilerWorkerUnavailable;

pub(crate) fn compiler_worker_active() -> bool {
    COMPILER_WORKER_ACTIVE.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_compiler_worker_spawn_count() {
    COMPILER_WORKER_SPAWNS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn compiler_worker_spawn_count() -> usize {
    COMPILER_WORKER_SPAWNS.with(Cell::get)
}

pub(crate) fn run_with_compiler_stack<T, F>(operation: F) -> Result<T, CompilerWorkerUnavailable>
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    if compiler_worker_active() {
        return Ok(operation());
    }
    #[cfg(test)]
    COMPILER_WORKER_SPAWNS.with(|count| count.set(count.get().saturating_add(1)));
    let _permit = COMPILER_WORKER_GATE
        .get_or_init(|| CompilerWorkerGate {
            active: Mutex::new(0),
            ready: Condvar::new(),
        })
        .acquire();
    let inherited_chain_discriminant = chain_discriminant();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("kotodama-compiler".to_owned())
            .stack_size(COMPILER_STACK_BYTES)
            .spawn_scoped(scope, || {
                let _marker = CompilerWorkerMarker::enter();
                let _chain_discriminant =
                    ChainDiscriminantGuard::enter(inherited_chain_discriminant);
                operation()
            })
            .map_err(|_| CompilerWorkerUnavailable)?;
        match worker.join() {
            Ok(result) => Ok(result),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

pub(crate) fn compiler_worker_unavailable_diagnostic(
    source_name: Option<&str>,
) -> DiagnosticBundle {
    DiagnosticBundle::single(Diagnostic::error(
        "K0003",
        DiagnosticPhase::Parse,
        "compiler could not allocate the bounded stack required to validate source nesting",
        source_start_span(source_name),
    ))
}
/// One compilation request.
#[derive(Clone, Copy, Debug)]
pub struct CompileRequest<'source> {
    /// Kotodama source text.
    pub source: &'source str,
    /// Logical source path used in diagnostics and sidecars.
    pub source_name: Option<&'source str>,
}
/// Successful canonical compiler output.
#[derive(Clone, Debug)]
pub struct CompileOutput {
    /// Canonical compiled `.to` bytes.
    ///
    /// Production output is deployable; test-mode output is a local-only generic IVM harness.
    pub artifact: Vec<u8>,
    /// Exact compiler-owned contract interface for this artifact.
    ///
    /// Production artifacts embed the same descriptor in their `CNTR` section.
    /// Local test artifacts carry it beside the immutable generic IVM image so
    /// the runner validates exact entrypoint and durable-state metadata without
    /// reconstructing it from the lossy manifest or making the harness deployable.
    pub contract_interface: EmbeddedContractInterfaceV1,
    /// Manifest derived from the compiler-owned contract interface.
    pub manifest: ContractManifest,
    /// Source-map, budget, and access-hint sidecar data.
    pub report: CompileReport,
}
impl CompileOutput {
    /// Return the exact compiler-owned interface.
    ///
    /// Production artifacts embed the same descriptor in `CNTR`; generic test
    /// harnesses carry it only as this trusted local sidecar.
    #[must_use]
    pub fn contract_interface(&self) -> &EmbeddedContractInterfaceV1 {
        &self.contract_interface
    }
}
/// Paired artifacts produced for one explicitly selected local test suite.
#[derive(Clone, Debug)]
pub struct TestCompileOutput {
    /// Test-mode artifact containing the local test functions.
    pub suite: CompileOutput,
    /// Production-mode artifact derived after removing local-only test declarations.
    ///
    /// Pure unit-test targets with no public runtime entrypoint do not need a
    /// deployable projection and therefore return `None`.
    pub runtime: Option<CompileOutput>,
}
/// One source-identified input to the typed-HIR local test linker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestSourceUnit {
    /// Stable logical path retained in diagnostics and debug sidecars.
    pub source_name: String,
    /// Complete bounded Kotodama source text.
    pub source: String,
}
/// Per-project lint levels.
///
/// Every lint defaults to [`crate::lint::LintLevel::Warn`]. A level set for a
/// slug applies to that lint; `deny_warnings` promotes every lint still at
/// `warn` to `deny`, which makes the check fail. Front ends source these
/// settings from project configuration (a `[lints]` table) so CI and editors
/// agree on the result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LintConfig {
    levels: BTreeMap<&'static str, crate::lint::LintLevel>,
    deny_warnings: bool,
}
/// A lint configuration entry named no known lint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownLint {
    /// The unrecognized slug.
    pub slug: String,
    /// The closest known slug, when one is similar.
    pub suggestion: Option<&'static str>,
}
impl std::fmt::Display for UnknownLint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "unknown lint `{}`", self.slug)?;
        if let Some(suggestion) = self.suggestion {
            write!(formatter, "; did you mean `{suggestion}`?")?;
        }
        Ok(())
    }
}
impl std::error::Error for UnknownLint {}
impl LintConfig {
    /// Configuration where every lint warns.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the level of one lint by slug, such as `unused-local`.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownLint`] when the slug names no lint in
    /// [`crate::lint::LINT_REGISTRY`].
    pub fn set_level(
        &mut self,
        slug: &str,
        level: crate::lint::LintLevel,
    ) -> Result<&mut Self, UnknownLint> {
        let Some((known, _, _)) = crate::lint::lint_by_slug(slug) else {
            return Err(UnknownLint {
                slug: slug.to_owned(),
                suggestion: crate::diagnostic::suggest::closest(
                    slug,
                    crate::lint::LINT_REGISTRY.iter().map(|(slug, _, _)| *slug),
                ),
            });
        };
        self.levels.insert(known, level);
        Ok(self)
    }
    /// Layer `overrides` (for example command-line flags) over this configuration (for example a
    /// project manifest): a level set in `overrides` replaces this one for the same lint, and
    /// deny-warnings holds when either enables it.
    #[must_use]
    pub fn merged_with(&self, overrides: &Self) -> Self {
        let mut levels = self.levels.clone();
        levels.extend(overrides.levels.iter().map(|(slug, level)| (*slug, *level)));
        Self {
            levels,
            deny_warnings: self.deny_warnings || overrides.deny_warnings,
        }
    }
    /// Promote every lint that would warn to an error.
    pub fn set_deny_warnings(&mut self, deny: bool) -> &mut Self {
        self.deny_warnings = deny;
        self
    }
    /// Effective level of the lint with `slug`.
    #[must_use]
    pub fn level(&self, slug: &str) -> crate::lint::LintLevel {
        let level = self
            .levels
            .get(slug)
            .copied()
            .unwrap_or(crate::lint::LintLevel::Warn);
        if self.deny_warnings && level == crate::lint::LintLevel::Warn {
            crate::lint::LintLevel::Deny
        } else {
            level
        }
    }
    /// Drop allowed findings and mark denied ones as errors, preserving order.
    #[must_use]
    pub fn apply(&self, warnings: Vec<crate::lint::LintWarning>) -> Vec<crate::lint::LintWarning> {
        warnings
            .into_iter()
            .filter_map(|warning| match self.level(warning.code) {
                crate::lint::LintLevel::Allow => None,
                level => Some(warning.with_level(level)),
            })
            .collect()
    }
    /// Whether any finding in `warnings` is denied and must fail the check.
    #[must_use]
    pub fn denies_any(&self, warnings: &[crate::lint::LintWarning]) -> bool {
        warnings
            .iter()
            .any(|warning| self.level(warning.code) == crate::lint::LintLevel::Deny)
    }
}
/// Explicit reusable compiler context used by CLIs, SDK bindings, and language tools.
#[derive(Clone, Debug)]
pub struct CompilerSession {
    options: CompilerOptions,
}
struct IterativeResolvedGuard {
    program: Option<crate::resolved::ResolvedProgram>,
}
impl Clone for IterativeResolvedGuard {
    fn clone(&self) -> Self {
        // AST cloning uses its explicit work list; the other resolved fields are
        // flat records or shared immutable arenas. No worker stack is involved.
        Self::new(self.get().clone())
    }
}
impl IterativeResolvedGuard {
    fn new(program: crate::resolved::ResolvedProgram) -> Self {
        Self {
            program: Some(program),
        }
    }
    fn get(&self) -> &crate::resolved::ResolvedProgram {
        self.program.as_ref().expect("resolved guard is populated")
    }
}
impl Drop for IterativeResolvedGuard {
    fn drop(&mut self) {
        if let Some(program) = self.program.take() {
            crate::ast::drop_program_iterative(program.into_program());
        }
    }
}
struct IterativeSpannedGuard {
    program: Option<crate::spanned_ast::SpannedProgram>,
}
impl IterativeSpannedGuard {
    fn new(program: crate::spanned_ast::SpannedProgram) -> Self {
        Self {
            program: Some(program),
        }
    }
    fn take(mut self) -> crate::spanned_ast::SpannedProgram {
        self.program
            .take()
            .expect("spanned guard is populated exactly once")
    }
}
impl Clone for IterativeSpannedGuard {
    fn clone(&self) -> Self {
        Self::new(
            self.program
                .as_ref()
                .expect("spanned guard is populated")
                .clone(),
        )
    }
}
impl Drop for IterativeSpannedGuard {
    fn drop(&mut self) {
        if let Some(program) = self.program.take() {
            let crate::spanned_ast::SpannedProgram { program, facts } = program;
            drop(facts);
            crate::ast::drop_program_iterative(program);
        }
    }
}
/// Canonically parsed source retained between compiler phases.
///
/// The fields stay crate-private so instrumentation can time phase boundaries
/// without exposing forgeable frontend artifacts to compiler clients.
#[derive(Clone)]
pub(crate) struct ParsedCompilationUnit {
    source: SourceFile,
    program: IterativeSpannedGuard,
    source_name: Option<String>,
}
/// Canonically resolved HIR retained between compiler phases.
///
/// The iterative guard preserves the normal compiler's bounded-drop behavior
/// when a benchmark discards a cloned phase input.
#[derive(Clone)]
pub(crate) struct ResolvedCompilationUnit {
    source: SourceFile,
    program: IterativeResolvedGuard,
    source_name: Option<String>,
}
impl CompilerSession {
    /// Create a session with deterministic compiler options.
    pub fn new(options: CompilerOptions) -> Self {
        Self { options }
    }
    /// Enter the exact account-literal network selected by this session.
    ///
    /// Build drivers call this inside worker threads because thread-local
    /// network context is intentionally not inherited by spawned workers.
    pub(crate) fn enter_chain_discriminant(&self) -> ChainDiscriminantGuard {
        ChainDiscriminantGuard::enter(self.options.chain_discriminant)
    }
    /// Return a deterministic cache identity for every caller-controlled
    /// compiler policy that can change deployable output.
    pub fn policy_fingerprint(&self) -> iroha_crypto::Hash {
        let mode = match self.options.mode {
            crate::compiler::CompilerMode::Production => 0_u8,
            crate::compiler::CompilerMode::Test => 1_u8,
        };
        iroha_crypto::Hash::new_from_chunks(&[
            b"kotodama-compiler-policy-v2\0",
            &[u8::from(self.options.force_zk)],
            &self.options.max_cycles.to_le_bytes(),
            &self.options.chain_discriminant.to_le_bytes(),
            &[mode],
        ])
    }
    /// Derive typed-module linker capabilities from this compiler session.
    ///
    /// Keeping this mapping owned by the session prevents package frontends
    /// from linking with ZK or test capabilities that differ from the policy
    /// later used to generate the deployable artifact.
    pub(crate) fn linker_options(&self) -> crate::linker::LinkerOptions {
        let test_mode = self.options.mode == crate::compiler::CompilerMode::Test;
        crate::linker::LinkerOptions {
            zk_enabled: self.options.force_zk,
            test_builtins_enabled: test_mode,
            include_tests: test_mode,
        }
    }
    /// Validate a reusable package and its authenticated locked dependencies.
    ///
    /// Package frontends use this entry point so typed linking receives the exact production, ZK,
    /// and test capabilities owned by this compiler session. Validation does not synthesize a
    /// deployable seiyaku and does not emit bytecode.
    pub fn validate_package_graph(
        &self,
        graph: &crate::linker::ModuleBuildGraph,
        request: crate::linker::SourcePackageGraphRequest,
    ) -> Result<crate::linker::ValidatedSourcePackageGraph, crate::linker::SourceGraphError> {
        run_with_compiler_stack(move || self.validate_package_graph_inner(graph, request)).map_err(
            |_| crate::linker::SourceGraphError::Parse {
                source: "<project>".to_owned(),
                diagnostics: compiler_worker_unavailable_diagnostic(Some("<project>")),
            },
        )?
    }
    fn validate_package_graph_inner(
        &self,
        graph: &crate::linker::ModuleBuildGraph,
        request: crate::linker::SourcePackageGraphRequest,
    ) -> Result<crate::linker::ValidatedSourcePackageGraph, crate::linker::SourceGraphError> {
        let _chain_discriminant = self.enter_chain_discriminant();
        graph.validate_package(request, self.linker_options())
    }
    /// Parse and type/effect-check one seiyaku or reusable module without
    /// publishing deployable output.
    pub fn check(&self, request: CompileRequest<'_>) -> Result<(), DiagnosticBundle> {
        run_with_compiler_stack(move || self.check_inner(request))
            .map_err(|_| compiler_worker_unavailable_diagnostic(request.source_name))?
    }
    fn check_inner(&self, request: CompileRequest<'_>) -> Result<(), DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        let _program = self.checked_program(request)?;
        Ok(())
    }
    /// Run the canonical check pipeline and return non-fatal lint findings.
    ///
    /// Parsing and semantic analysis occur exactly once. Frontends use this method to replace the
    /// retired standalone linter without maintaining a second parser path.
    pub fn check_with_lints(
        &self,
        request: CompileRequest<'_>,
    ) -> Result<Vec<crate::lint::LintWarning>, DiagnosticBundle> {
        run_with_compiler_stack(move || self.check_with_lints_inner(request))
            .map_err(|_| compiler_worker_unavailable_diagnostic(request.source_name))?
    }
    /// Run the check pipeline and apply `config` to its lint findings.
    ///
    /// Allowed lints are dropped. When any remaining finding is denied, the
    /// whole result is an error bundle containing every finding (denied ones as
    /// errors, the rest as warnings) so callers can fail CI deterministically.
    pub fn check_with_lint_config(
        &self,
        request: CompileRequest<'_>,
        config: &LintConfig,
    ) -> Result<Vec<crate::lint::LintWarning>, DiagnosticBundle> {
        let warnings = config.apply(self.check_with_lints(request)?);
        if !warnings
            .iter()
            .any(|warning| warning.severity == crate::lint::LintSeverity::Error)
        {
            return Ok(warnings);
        }
        let source_name = request.source_name.unwrap_or("<source>");
        Err(DiagnosticBundle::new(
            warnings
                .iter()
                .map(|warning| {
                    warning.to_diagnostic(source_name, None, crate::i18n::Language::English)
                })
                .collect(),
        ))
    }
    fn check_with_lints_inner(
        &self,
        request: CompileRequest<'_>,
    ) -> Result<Vec<crate::lint::LintWarning>, DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        let unit = self.checked_program(request)?;
        let program = unit.program.get();
        Ok(crate::lint::lint_with_sources(
            program.program(),
            program.lint_facts(),
            &unit.source,
        ))
    }
    /// Parse one source through the canonical, budgeted lossless frontend.
    pub(crate) fn parse_compilation_unit(
        &self,
        request: CompileRequest<'_>,
    ) -> Result<ParsedCompilationUnit, DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        enforce_source_budget(request)?;
        let source = SourceFile::new(
            SourceId(0),
            request.source_name.unwrap_or("<source>"),
            request.source,
        );
        let (program, tokens) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())?;
        if let Some(directive) = program.program.directives.first() {
            let mut diagnostics = DiagnosticBundle::single(crate::diagnostic::Diagnostic::error(
                "E_SOURCE_NOT_FOUND",
                crate::diagnostic::DiagnosticPhase::Resolve,
                "source dependencies require an explicit source bundle; supply companion files to build_source_bundle",
                Some(crate::diagnostic::SourceSpan::from_range(
                    &source,
                    directive.source.range,
                )),
            ));
            diagnostics.capture_source(&source);
            return Err(diagnostics);
        }
        reject_production_test_surface(
            self.options.mode,
            &program.program,
            request.source_name,
            Some((&source, &tokens)),
        )?;
        Ok(ParsedCompilationUnit {
            source,
            program: IterativeSpannedGuard::new(program),
            source_name: request.source_name.map(ToOwned::to_owned),
        })
    }
    /// Resolve one canonical parsed source into fail-closed named HIR.
    pub(crate) fn resolve_compilation_unit(
        &self,
        parsed: ParsedCompilationUnit,
    ) -> Result<ResolvedCompilationUnit, DiagnosticBundle> {
        let ParsedCompilationUnit {
            source,
            program,
            source_name,
        } = parsed;
        let program = crate::resolved::resolve(program.take(), &source)?;
        Ok(ResolvedCompilationUnit {
            source,
            program: IterativeResolvedGuard::new(program),
            source_name,
        })
    }
    /// Type- and effect-check one resolved-HIR source with this session's policy.
    pub(crate) fn type_effect_compilation_unit(
        &self,
        resolved: ResolvedCompilationUnit,
    ) -> Result<TypedProgram, DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        self.type_effect_compilation_unit_ref(&resolved)
    }
    fn type_effect_compilation_unit_ref(
        &self,
        resolved: &ResolvedCompilationUnit,
    ) -> Result<TypedProgram, DiagnosticBundle> {
        let semantic = crate::semantic::SemanticContext::with_capabilities(
            self.options.force_zk,
            self.options.mode == crate::compiler::CompilerMode::Test,
        );
        let typed = semantic
            .analyze_resolved(resolved.program.get())
            .map_err(|failures| {
                crate::semantic_diagnostics::from_semantic_failures(
                    failures,
                    resolved.source_name.as_deref(),
                    Some(&resolved.source),
                    Some(resolved.program.get()),
                )
            })?;
        enforce_call_table_bounds(&typed, resolved.program.get())?;
        Ok(typed)
    }
    /// Report resolution failures together with type errors from functions
    /// that resolved cleanly.
    ///
    /// Failing function bodies are emptied in a reduced copy that is analyzed
    /// only to find independent errors; nothing from it is ever lowered.
    fn recovered_resolution_diagnostics(
        &self,
        source: &SourceFile,
        source_name: Option<&str>,
        recovered: crate::resolved::RecoveredResolution,
    ) -> DiagnosticBundle {
        let crate::resolved::RecoveredResolution {
            mut diagnostics,
            reduced,
            emptied,
        } = recovered;
        let Some(reduced) = reduced.map(IterativeResolvedGuard::new) else {
            return diagnostics;
        };
        let independent = reduced
            .get()
            .program()
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) if !emptied.contains(&function.name) => {
                    Some(function.location)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let semantic = crate::semantic::SemanticContext::with_capabilities(
            self.options.force_zk,
            self.options.mode == crate::compiler::CompilerMode::Test,
        );
        if let Err(mut failures) = semantic.analyze_resolved(reduced.get()) {
            failures.failures.retain(|failure| {
                failure.error.code != "K0004"
                    && failure
                        .location
                        .is_some_and(|location| independent.contains(&location))
            });
            if !failures.failures.is_empty() {
                diagnostics.diagnostics.extend(
                    crate::semantic_diagnostics::from_semantic_failures(
                        failures,
                        source_name,
                        Some(source),
                        Some(reduced.get()),
                    )
                    .diagnostics,
                );
            }
        }
        diagnostics
    }
    fn checked_program(
        &self,
        request: CompileRequest<'_>,
    ) -> Result<ResolvedCompilationUnit, DiagnosticBundle> {
        let ParsedCompilationUnit {
            source,
            program,
            source_name,
        } = self.parse_compilation_unit(request)?;
        let resolved = match crate::resolved::resolve_recovering(program.take(), &source) {
            Ok(program) => ResolvedCompilationUnit {
                source,
                program: IterativeResolvedGuard::new(program),
                source_name,
            },
            Err(recovered) => {
                return Err(self.recovered_resolution_diagnostics(
                    &source,
                    source_name.as_deref(),
                    *recovered,
                ));
            }
        };
        let typed = self.type_effect_compilation_unit_ref(&resolved)?;
        crate::semantic::validate_linked_program(&typed, self.options.force_zk).map_err(
            |error| {
                crate::semantic_diagnostics::from_semantic_failures(
                    error.into(),
                    request.source_name,
                    Some(&resolved.source),
                    Some(resolved.program.get()),
                )
            },
        )?;
        crate::policy::enforce_on_chain_profile(&typed).map_err(|errors| {
            DiagnosticBundle::new(
                errors
                    .into_iter()
                    .map(|error| {
                        Diagnostic::error(
                            "K2100",
                            DiagnosticPhase::Semantic,
                            error.message,
                            source_start_span(request.source_name),
                        )
                    })
                    .collect(),
            )
        })?;
        Ok(resolved)
    }
    /// Compile one named source unit into a deployable artifact and sidecar report.
    pub fn build(&self, request: CompileRequest<'_>) -> Result<CompileOutput, DiagnosticBundle> {
        run_with_compiler_stack(move || self.build_inner(request))
            .map_err(|_| compiler_worker_unavailable_diagnostic(request.source_name))?
    }
    /// Compile one complete, bounded source inventory without ambient file access.
    pub fn build_source_bundle(
        &self,
        request: crate::linker::SourceLinkRequest,
    ) -> Result<CompileOutput, DiagnosticBundle> {
        run_with_compiler_stack(move || {
            let _chain_discriminant = self.enter_chain_discriminant();
            let name = request.root.source_name.clone();
            let linked = crate::linker::ModuleBuildGraph::default()
                .link(request, self.linker_options())
                .map_err(crate::linker::SourceGraphError::into_diagnostics)?;
            self.build_typed_program(linked.program, Some(&name))
        })
        .map_err(|_| compiler_worker_unavailable_diagnostic(None))?
    }
    /// Resolve and type-check an explicit source inventory without emitting an artifact.
    pub fn check_source_bundle(
        &self,
        request: crate::linker::SourceLinkRequest,
    ) -> Result<(), DiagnosticBundle> {
        run_with_compiler_stack(move || {
            let _chain_discriminant = self.enter_chain_discriminant();
            crate::linker::ModuleBuildGraph::default()
                .link(request, self.linker_options())
                .map(|_| ())
                .map_err(crate::linker::SourceGraphError::into_diagnostics)
        })
        .map_err(|_| compiler_worker_unavailable_diagnostic(None))?
    }
    fn build_inner(&self, request: CompileRequest<'_>) -> Result<CompileOutput, DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        let parsed = self.parse_compilation_unit(request)?;
        let resolved = self.resolve_compilation_unit(parsed)?;
        let typed = self.type_effect_compilation_unit(resolved)?;
        self.build_typed_program(typed, request.source_name)
    }
    /// Compile a source-identified local test graph and its verified runtime projection.
    ///
    /// Every file is parsed and resolved independently with a stable `SourceId`.
    /// Standalone modules receive only the target's typed function/state
    /// interface; no AST items are flattened, reordered, or rewritten.
    pub fn build_test_sources(
        &self,
        target: &TestSourceUnit,
        test_modules: &[TestSourceUnit],
    ) -> Result<TestCompileOutput, DiagnosticBundle> {
        run_with_compiler_stack(move || self.build_test_sources_inner(target, test_modules))
            .map_err(|_| compiler_worker_unavailable_diagnostic(Some(&target.source_name)))?
    }
    fn build_test_sources_inner(
        &self,
        target: &TestSourceUnit,
        test_modules: &[TestSourceUnit],
    ) -> Result<TestCompileOutput, DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        if self.options.mode != CompilerMode::Test {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "E_TEST_ONLY_PRODUCTION",
                DiagnosticPhase::Semantic,
                "the local test compiler requires an explicit test-mode CompilerSession",
                source_start_span(Some(&target.source_name)),
            )));
        }
        let source_count = 1_usize.saturating_add(test_modules.len());
        let source_bytes = test_modules
            .iter()
            .fold(target.source.len(), |total, source| {
                total.saturating_add(source.source.len())
            });
        if source_count > crate::linker::MAX_MODULE_GRAPH_SOURCES
            || source_bytes > crate::linker::MAX_MODULE_GRAPH_SOURCE_BYTES
        {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "K1004",
                DiagnosticPhase::Parse,
                format!(
                    "Kotodama test graph contains {source_count} sources/{source_bytes} bytes; V1 permits at most {} sources/{} bytes",
                    crate::linker::MAX_MODULE_GRAPH_SOURCES,
                    crate::linker::MAX_MODULE_GRAPH_SOURCE_BYTES
                ),
                source_start_span(Some(&target.source_name)),
            )));
        }
        let mut ordered_tests = test_modules.iter().collect::<Vec<_>>();
        ordered_tests.sort_by(|left, right| {
            normalize_logical_path(Path::new(&left.source_name))
                .cmp(&normalize_logical_path(Path::new(&right.source_name)))
                .then_with(|| left.source_name.cmp(&right.source_name))
        });
        let mut names = BTreeSet::new();
        if !names.insert(normalize_logical_path(Path::new(&target.source_name)))
            || ordered_tests
                .iter()
                .any(|source| !names.insert(normalize_logical_path(Path::new(&source.source_name))))
        {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "E_DUPLICATE_SOURCE",
                DiagnosticPhase::Resolve,
                "the Kotodama test graph contains duplicate logical source paths",
                source_start_span(Some(&target.source_name)),
            )));
        }
        let units = std::iter::once(target)
            .chain(ordered_tests.iter().copied())
            .collect::<Vec<_>>();
        let keys = std::iter::once(format!(
            "target\0{}",
            normalize_logical_path(Path::new(&target.source_name)).display()
        ))
        .chain(ordered_tests.iter().map(|source| {
            format!(
                "test\0{}",
                normalize_logical_path(Path::new(&source.source_name)).display()
            )
        }))
        .collect::<Vec<_>>();
        let source_ids = crate::linker::stable_source_ids(&keys);
        let mut files = Vec::with_capacity(units.len());
        let mut parsed = Vec::with_capacity(units.len());
        for (unit, source_id) in units.iter().zip(source_ids) {
            enforce_source_budget(CompileRequest {
                source: &unit.source,
                source_name: Some(&unit.source_name),
            })?;
            let file = SourceFile::new(source_id, unit.source_name.clone(), &unit.source);
            let (program, _) = crate::parser::parse_source_spanned(&file, FrontendBudget::v1())?;
            files.push(file);
            parsed.push(program);
        }
        require_deployable_contract(&parsed[0].program, Some(&target.source_name))?;
        for (index, program) in parsed.iter().enumerate().skip(1) {
            validate_test_module_source(
                &program.program,
                Some(files[index].name()),
                &target.source_name,
            )?;
        }
        let target_resolved = crate::resolved::resolve(parsed.remove(0), &files[0])?;
        let target_semantic =
            crate::semantic::SemanticContext::with_capabilities(self.options.force_zk, true);
        let target_signatures = target_semantic
            .resolve_resolved_function_signatures(&target_resolved)
            .map_err(|error| semantic_error_diagnostic(error, Some(files[0].name())))?;
        let target_typed =
            target_semantic
                .analyze_resolved(&target_resolved)
                .map_err(|failures| {
                    crate::semantic_diagnostics::from_semantic_failures(
                        failures,
                        Some(files[0].name()),
                        Some(&files[0]),
                        Some(&target_resolved),
                    )
                })?;
        let external_states = target_typed
            .states
            .iter()
            .map(|state| (state.name.clone(), state.ty.clone()))
            .collect::<IndexMap<_, _>>();
        let target_environment =
            target_semantic.test_target_environment(target_signatures, external_states);
        let resolution_environment = crate::resolved::ExternalResolutionEnvironment {
            contracts: target_environment.contracts.clone(),
            permissions: BTreeSet::new(),
            functions: target_environment.functions.keys().cloned().collect(),
            states: target_environment.states.keys().cloned().collect(),
            structs: target_environment.structs.keys().cloned().collect(),
            consts: target_environment.consts.keys().cloned().collect(),
            variant_codes: target_environment
                .variant_codes
                .iter()
                .map(|(name, code)| (name.clone(), *code))
                .collect(),
        };
        let mut resolved_modules = Vec::with_capacity(parsed.len());
        for (index, program) in parsed.into_iter().enumerate() {
            let file = &files[index + 1];
            resolved_modules.push(crate::resolved::resolve_with_external_environment(
                program,
                file,
                &resolution_environment,
            )?);
        }
        reject_duplicate_test_graph_symbols(
            std::iter::once((&target_resolved, &files[0]))
                .chain(resolved_modules.iter().zip(files.iter().skip(1))),
        )?;
        let runtime_typed = crate::semantic::project_test_target_to_production(
            target_typed.clone(),
            self.options.force_zk,
        )
        .map_err(|error| semantic_error_diagnostic(error, Some(&target.source_name)))?;
        let mut suite_typed = target_typed;
        let mut error_types = suite_typed
            .error_types
            .iter()
            .map(|error| (error.identity.clone(), error.clone()))
            .collect::<BTreeMap<_, _>>();
        for (index, resolved) in resolved_modules.iter().enumerate() {
            let file = &files[index + 1];
            let semantic =
                crate::semantic::SemanticContext::with_capabilities(self.options.force_zk, true);
            let mut typed = semantic
                .analyze_resolved_with_test_target(resolved, &target_environment)
                .map_err(|failures| {
                    crate::semantic_diagnostics::from_semantic_failures(
                        failures,
                        Some(file.name()),
                        Some(file),
                        Some(resolved),
                    )
                })?;
            for error in &typed.error_types {
                if let Some(previous) = error_types.get(&error.identity) {
                    if previous != error {
                        return Err(DiagnosticBundle::single(
                            Diagnostic::error(
                                "E_CONFLICTING_ERROR_TYPE",
                                DiagnosticPhase::Resolve,
                                format!(
                                    "test graph assigns conflicting schemas to error type `{}`",
                                    error.identity
                                ),
                                source_start_span(Some(file.name())),
                            )
                            .with_source(file),
                        ));
                    }
                } else {
                    error_types.insert(error.identity.clone(), error.clone());
                }
            }
            merge_source_files(&mut suite_typed, &mut typed, file.name())?;
            suite_typed.items.append(&mut typed.items);
            suite_typed.error_messages.append(&mut typed.error_messages);
            suite_typed.error_types = error_types.values().cloned().collect();
            suite_typed
                .message_entries
                .append(&mut typed.message_entries);
        }
        suite_typed.error_messages.sort_by(|left, right| {
            (&left.error_type, left.code).cmp(&(&right.error_type, right.code))
        });
        suite_typed.error_messages.dedup();
        if !iroha_data_model::smart_contract::manifest::validate_contract_error_messages(
            &suite_typed.error_types,
            &suite_typed.error_messages,
        ) {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "E_ERROR_MESSAGE",
                DiagnosticPhase::Resolve,
                "standalone tests define conflicting error messages",
                None,
            )));
        }
        crate::semantic::validate_linked_program(&suite_typed, self.options.force_zk)
            .map_err(|error| semantic_error_diagnostic(error, Some(&target.source_name)))?;
        let suite = self.build_typed_program(suite_typed, Some(&target.source_name))?;
        let has_runtime_entrypoint = runtime_typed.items.iter().any(|item| {
            let crate::semantic::TypedItem::Function(function) = item;
            function.modifiers.kind != FunctionKind::Private
        });
        let runtime = if has_runtime_entrypoint {
            let mut runtime_options = self.options.clone();
            runtime_options.mode = CompilerMode::Production;
            Some(
                CompilerSession::new(runtime_options)
                    .build_typed_program(runtime_typed, Some(&target.source_name))?,
            )
        } else {
            None
        };
        Ok(TestCompileOutput { suite, runtime })
    }
    /// Compile a fully resolved and linked typed-HIR program inside the trusted driver.
    ///
    /// This is the only post-link code-generation entry point. It deliberately accepts no AST, so
    /// package managers cannot reintroduce source rewriting after module type/effect analysis.
    pub(crate) fn build_typed_program(
        &self,
        program: TypedProgram,
        source_name: Option<&str>,
    ) -> Result<CompileOutput, DiagnosticBundle> {
        run_with_compiler_stack(move || self.build_typed_program_inner(program, source_name))
            .map_err(|_| compiler_worker_unavailable_diagnostic(source_name))?
    }
    fn build_typed_program_inner(
        &self,
        program: TypedProgram,
        source_name: Option<&str>,
    ) -> Result<CompileOutput, DiagnosticBundle> {
        let _chain_discriminant = self.enter_chain_discriminant();
        if program.unit.kind != SourceUnitKind::Seiyaku {
            return Err(non_deployable_module_diagnostic(source_name));
        }
        let compiler = Compiler::new_with_options(self.options.clone());
        compiler.compile_typed_program_with_manifest_and_report_diagnostics(program, source_name)
    }
}
pub(crate) fn enforce_call_table_bounds(
    program: &TypedProgram,
    resolved: &crate::resolved::ResolvedProgram,
) -> Result<(), DiagnosticBundle> {
    let limit = crate::regalloc::MAX_ARGUMENT_VALUES;
    let mut diagnostics = Vec::new();
    for item in &program.items {
        let crate::semantic::TypedItem::Function(function) = item;
        let return_type = function
            .ret_ty
            .as_ref()
            .unwrap_or(&crate::semantic::Type::Unit);
        if crate::semantic::runtime_value_word_count_bounded(return_type, limit)
            .is_some_and(|words| words > limit)
        {
            diagnostics.push(Diagnostic::error(
                "K2007", DiagnosticPhase::Semantic,
                format!("function `{}` returns more than {limit} flattened words; V1 result tables are bounded to 64 KiB", function.name),
                function.name_source.and_then(|range| resolved.source_span(range)),
            ));
        }
        let counts = function
            .param_types
            .iter()
            .map(|parameter| {
                crate::semantic::runtime_value_word_count_bounded(&parameter.ty, limit).ok_or_else(
                    || {
                        let primary_span = resolved
                            .parameter_name_source(&function.name, &parameter.name)
                            .and_then(|range| resolved.source_span(range));
                        DiagnosticBundle::single(Diagnostic::error(
                            "K2098",
                            DiagnosticPhase::Semantic,
                            format!(
                                "parameter `{}` of function `{}` retained an unresolved ABI type",
                                parameter.name, function.name
                            ),
                            primary_span,
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let total_words = counts
            .iter()
            .try_fold(0_usize, |total, words| total.checked_add(*words))
            .unwrap_or(usize::MAX);
        if function.param_types.len() <= limit && total_words <= limit {
            continue;
        }
        let mut cumulative_words = 0_usize;
        let crossing_index = counts
            .iter()
            .enumerate()
            .find_map(|(index, words)| {
                cumulative_words = cumulative_words.saturating_add(*words);
                (index >= limit || cumulative_words > limit).then_some(index)
            })
            .unwrap_or_else(|| function.param_types.len().saturating_sub(1));
        let parameter = &function.param_types[crossing_index];
        let primary_span = resolved
            .parameter_name_source(&function.name, &parameter.name)
            .and_then(|range| resolved.source_span(range));
        let mut diagnostic = Diagnostic::error(
            "K2007",
            DiagnosticPhase::Semantic,
            format!(
                "function `{}` declares {} source parameter(s) requiring {total_words} flattened argument words; V1 permits at most {limit}",
                function.name,
                function.param_types.len(),
            ),
            primary_span,
        );
        if let Some(range) = function.name_source
            && let Some(span) = resolved.source_span(range)
        {
            diagnostic.labels.push(DiagnosticLabel {
                span,
                message: "function exceeds the V1 argument-table bound".to_owned(),
            });
        }
        diagnostics.push(diagnostic);
    }
    if diagnostics.is_empty() {
        Ok(())
    } else {
        let mut bundle = DiagnosticBundle::new(diagnostics);
        for source in resolved.source_files() {
            bundle.capture_source(source);
        }
        Err(bundle)
    }
}
fn semantic_error_diagnostic(
    error: crate::semantic::SemanticError,
    source_name: Option<&str>,
) -> DiagnosticBundle {
    DiagnosticBundle::single(Diagnostic::error(
        error.code,
        phase_for_semantic_failure(error.code),
        error.message,
        source_start_span(source_name),
    ))
}
pub(crate) fn validate_test_module_source(
    program: &Program,
    source_name: Option<&str>,
    target_source_name: &str,
) -> Result<(), DiagnosticBundle> {
    if program.unit.kind != SourceUnitKind::Module {
        return Err(DiagnosticBundle::single(Diagnostic::error(
            "E_TEST_MODULE_KIND",
            DiagnosticPhase::Semantic,
            "standalone Kotodama tests must declare a `module` source unit",
            source_start_span(source_name),
        )));
    }
    let Some(test_target) = program.test_target.as_ref() else {
        return Err(DiagnosticBundle::single(Diagnostic::error(
            "E_TEST_TARGET_REQUIRED",
            DiagnosticPhase::Semantic,
            "standalone Kotodama tests require a `koto_test { target: \"...\" }` declaration",
            source_start_span(source_name),
        )));
    };
    let test_source_name = source_name.unwrap_or("<test>");
    let declared_target = Path::new(test_source_name)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(&test_target.target);
    if normalize_logical_path(&declared_target)
        != normalize_logical_path(Path::new(target_source_name))
    {
        return Err(DiagnosticBundle::single(Diagnostic::error(
            "E_TEST_TARGET_MISMATCH",
            DiagnosticPhase::Resolve,
            format!(
                "standalone test target `{}` does not resolve to graph target `{target_source_name}`",
                test_target.target
            ),
            source_start_span(source_name),
        )));
    }
    for item in &program.items {
        let invalid = match item {
            Item::State(_) => Some("durable state declaration"),
            Item::Trigger(_) => Some("trigger declaration"),
            Item::Function(function)
                if function.modifiers.kind != crate::ast::FunctionKind::Private =>
            {
                Some("public or lifecycle function")
            }
            Item::Function(_)
            | Item::Struct(_)
            | Item::Event(_)
            | Item::Enum(_)
            | Item::Const(_) => None,
        };
        if let Some(invalid) = invalid {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "E_TEST_MODULE_ITEM",
                DiagnosticPhase::Semantic,
                format!("standalone Kotodama test module contains {invalid}"),
                source_start_span(source_name),
            )));
        }
    }
    Ok(())
}
fn normalize_logical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    normalized
}
pub(crate) fn reject_duplicate_test_graph_symbols<'program>(
    units: impl IntoIterator<
        Item = (
            &'program crate::resolved::ResolvedProgram,
            &'program SourceFile,
        ),
    >,
) -> Result<(), DiagnosticBundle> {
    let units = units.into_iter().collect::<Vec<_>>();
    let files = units
        .iter()
        .map(|(_, file)| (file.id(), *file))
        .collect::<BTreeMap<_, _>>();
    let mut declarations = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for (program, file) in units {
        for symbol in program.symbols() {
            if let Some(previous) = declarations.insert(symbol.name.clone(), symbol.source) {
                let mut diagnostic = Diagnostic::error(
                    "E_DUPLICATE_DECLARATION",
                    DiagnosticPhase::Resolve,
                    format!(
                        "declaration name `{}` is already used by another test-graph source",
                        symbol.name
                    ),
                    Some(SourceSpan::from_range(file, symbol.source.range)),
                );
                if let Some(previous_file) = files.get(&previous.source) {
                    diagnostic.labels.push(DiagnosticLabel {
                        span: SourceSpan::from_range(previous_file, previous.range),
                        message: "first graph declaration is here".to_owned(),
                    });
                }
                diagnostics.push(diagnostic);
            }
        }
    }
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(DiagnosticBundle::new(diagnostics))
    }
}
pub(crate) fn merge_source_files(
    target: &mut TypedProgram,
    source: &mut TypedProgram,
    source_name: &str,
) -> Result<(), DiagnosticBundle> {
    for (id, node) in std::mem::take(&mut source.hir_nodes) {
        if target.hir_nodes.insert(id, node).is_some() {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "E_DUPLICATE_HIR_ID",
                DiagnosticPhase::Resolve,
                format!(
                    "typed module graph reused HIR identity {}:{}",
                    id.source.0, id.local.0
                ),
                source_start_span(Some(source_name)),
            )));
        }
    }
    for (source_id, file) in std::mem::take(&mut source.source_files) {
        if let Some(previous) = target.source_files.insert(source_id, file.clone())
            && previous != file
        {
            return Err(DiagnosticBundle::single(Diagnostic::error(
                "E_DUPLICATE_SOURCE_ID",
                DiagnosticPhase::Resolve,
                format!(
                    "compiler assigned SourceId {} to both `{}` and `{}`",
                    source_id.0,
                    previous.name(),
                    file.name()
                ),
                source_start_span(Some(source_name)),
            )));
        }
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum ProductionTestSurface {
    TestTarget,
    Fixture,
    TestFunction,
}
impl ProductionTestSurface {
    fn message(self) -> &'static str {
        match self {
            Self::TestTarget => {
                "this file is a `koto_test` module; run it with `koto test`, which compiles it against its target in test mode (deployable builds never include test modules)"
            }
            Self::Fixture => {
                "fixture declarations belong in a `*.test.ko` module that declares `koto_test { target: \"...\" }`, not in a deployable seiyaku"
            }
            Self::TestFunction => {
                "`#[test]` functions belong in a `*.test.ko` module that declares `koto_test { target: \"...\" }`, not in a deployable seiyaku"
            }
        }
    }
}
fn reject_production_test_surface(
    mode: CompilerMode,
    program: &Program,
    source_name: Option<&str>,
    source_tokens: Option<(&SourceFile, &[Token])>,
) -> Result<(), DiagnosticBundle> {
    if mode == CompilerMode::Test {
        return Ok(());
    }
    let has_test_target = program.test_target.is_some();
    let has_fixture = !program.fixtures.is_empty();
    let first_test_function = program.items.iter().find_map(|item| match item {
        crate::ast::Item::Function(function)
            if function.modifiers.is_test || function.modifiers.test_fixture.is_some() =>
        {
            Some(function)
        }
        _ => None,
    });
    if !has_test_target && !has_fixture && first_test_function.is_none() {
        return Ok(());
    }
    let exact = source_tokens.and_then(|(source, tokens)| {
        first_test_surface_token(
            tokens,
            has_test_target,
            has_fixture,
            first_test_function.is_some(),
        )
        .map(|(surface, range)| (surface, Some(SourceSpan::from_range(source, range))))
    });
    let (surface, span) = exact.unwrap_or_else(|| {
        if has_test_target {
            (
                ProductionTestSurface::TestTarget,
                source_start_span(source_name),
            )
        } else if has_fixture {
            (
                ProductionTestSurface::Fixture,
                source_start_span(source_name),
            )
        } else {
            let function = first_test_function.expect("a test surface was found");
            (
                ProductionTestSurface::TestFunction,
                Some(SourceSpan {
                    package_identity: None,
                    source: source_name.map(ToOwned::to_owned),
                    start: SourcePosition {
                        line: function.location.line,
                        column: function.location.column,
                    },
                    end: SourcePosition {
                        line: function.location.line,
                        column: function.location.column.saturating_add(function.name.len()),
                    },
                    byte_range: None,
                }),
            )
        }
    });
    let mut diagnostic = Diagnostic::error(
        "E_TEST_ONLY_PRODUCTION",
        DiagnosticPhase::Semantic,
        surface.message(),
        span,
    );
    diagnostic.help = Some(
        "`koto check` and `koto build` reject test code instead of stripping it, so the artifact always matches the reviewed source. Move the tests into `<name>.test.ko` and run them with `koto test`."
            .to_owned(),
    );
    Err(DiagnosticBundle::single(diagnostic))
}
fn first_test_surface_token(
    tokens: &[Token],
    has_test_target: bool,
    has_fixture: bool,
    has_test_function: bool,
) -> Option<(ProductionTestSurface, TextRange)> {
    let mut brace_depth = 0_usize;
    for (index, token) in tokens.iter().enumerate() {
        if brace_depth == 1 {
            if has_test_function
                && matches!(token.kind, TokenKind::Hash)
                && matches!(
                    tokens.get(index + 1).map(|token| &token.kind),
                    Some(TokenKind::LBracket)
                )
                && matches!(
                    tokens.get(index + 2).map(|token| &token.kind),
                    Some(TokenKind::Ident(name)) if name == "test"
                )
            {
                let end = tokens[index + 2..]
                    .iter()
                    .find(|token| matches!(token.kind, TokenKind::RBracket))
                    .map_or(tokens[index + 2].range.end, |token| token.range.end);
                return Some((
                    ProductionTestSurface::TestFunction,
                    TextRange::new(token.range.start, end),
                ));
            }
            if has_test_target
                && matches!(&token.kind, TokenKind::Ident(name) if name == "koto_test")
                && matches!(
                    tokens.get(index + 1).map(|token| &token.kind),
                    Some(TokenKind::LBrace)
                )
            {
                return Some((ProductionTestSurface::TestTarget, token.range));
            }
            if has_fixture
                && matches!(&token.kind, TokenKind::Ident(name) if name == "fixture")
                && matches!(
                    tokens.get(index + 1).map(|token| &token.kind),
                    Some(TokenKind::Ident(_))
                )
                && matches!(
                    tokens.get(index + 2).map(|token| &token.kind),
                    Some(TokenKind::LBrace)
                )
            {
                return Some((ProductionTestSurface::Fixture, token.range));
            }
        }
        match token.kind {
            TokenKind::LBrace => brace_depth = brace_depth.saturating_add(1),
            TokenKind::RBrace => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}
fn require_deployable_contract(
    program: &Program,
    source_name: Option<&str>,
) -> Result<(), DiagnosticBundle> {
    if program.unit.kind == SourceUnitKind::Seiyaku {
        Ok(())
    } else {
        Err(non_deployable_module_diagnostic(source_name))
    }
}
fn non_deployable_module_diagnostic(source_name: Option<&str>) -> DiagnosticBundle {
    let mut diagnostic = Diagnostic::error(
        "K4003",
        DiagnosticPhase::Artifact,
        "a reusable module cannot be emitted as a deployable .to artifact",
        source_start_span(source_name),
    );
    diagnostic.help =
        Some("link the module into exactly one seiyaku root, then build that seiyaku".to_owned());
    DiagnosticBundle::single(diagnostic)
}
fn source_start_span(source_name: Option<&str>) -> Option<SourceSpan> {
    Some(SourceSpan {
        package_identity: None,
        source: source_name.map(ToOwned::to_owned),
        start: SourcePosition { line: 1, column: 1 },
        end: SourcePosition { line: 1, column: 2 },
        byte_range: None,
    })
}
fn enforce_source_budget(request: CompileRequest<'_>) -> Result<(), DiagnosticBundle> {
    if request.source.len() <= MAX_SOURCE_BYTES {
        return Ok(());
    }
    let mut diagnostic = Diagnostic::error(
        "K0001",
        DiagnosticPhase::Lex,
        format!(
            "source contains {} bytes and exceeds the {MAX_SOURCE_BYTES}-byte Kotodama V1 limit",
            request.source.len()
        ),
        source_start_span(request.source_name),
    );
    diagnostic.help = Some("split reusable code into typed modules and import it".to_owned());
    Err(DiagnosticBundle::single(diagnostic))
}
impl Default for CompilerSession {
    fn default() -> Self {
        Self::new(CompilerOptions::default())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_config_allows_denies_and_rejects_unknown_slugs() {
        let source = "seiyaku Cfg {\n    view fn f(int x) authorize(anyone) -> int {\n        let unused = 3;\n        return x;\n    }\n}";
        let request = CompileRequest {
            source,
            source_name: Some("cfg.ko"),
        };
        let session = CompilerSession::default();
        let warnings = session
            .check_with_lint_config(request, &LintConfig::new())
            .expect("warnings do not fail by default");
        assert!(
            warnings
                .iter()
                .any(|warning| warning.code == "unused-local")
        );

        let mut allow = LintConfig::new();
        allow
            .set_level("unused-local", crate::lint::LintLevel::Allow)
            .expect("known lint");
        assert!(
            session
                .check_with_lint_config(request, &allow)
                .expect("allowed")
                .iter()
                .all(|warning| warning.code != "unused-local")
        );

        let mut deny = LintConfig::new();
        deny.set_deny_warnings(true);
        let denied = session
            .check_with_lint_config(request, &deny)
            .expect_err("deny-warnings fails the check");
        assert!(denied.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "K5013" && diagnostic.severity == crate::diagnostic::Severity::Error
        }));
        let mut allow_over_deny = deny.clone();
        allow_over_deny
            .set_level("unused-local", crate::lint::LintLevel::Allow)
            .expect("known lint");
        assert_eq!(
            allow_over_deny.level("unused-local"),
            crate::lint::LintLevel::Allow
        );
        assert_eq!(
            allow_over_deny.level("dead-store"),
            crate::lint::LintLevel::Deny
        );

        let unknown = LintConfig::new()
            .set_level("unused-locals", crate::lint::LintLevel::Deny)
            .map(|_| ())
            .expect_err("unknown slug");
        assert_eq!(unknown.suggestion, Some("unused-local"));
        assert_eq!(
            unknown.to_string(),
            "unknown lint `unused-locals`; did you mean `unused-local`?"
        );
    }

    #[test]
    fn merged_lint_config_lets_overrides_win_per_lint() {
        use crate::lint::LintLevel;
        let mut manifest = LintConfig::new();
        manifest
            .set_level("unused-local", LintLevel::Deny)
            .and_then(|config| config.set_level("dead-store", LintLevel::Allow))
            .expect("known lints");
        let mut flags = LintConfig::new();
        flags
            .set_level("unused-local", LintLevel::Allow)
            .expect("known lint");
        let merged = manifest.merged_with(&flags);
        assert_eq!(merged.level("unused-local"), LintLevel::Allow);
        assert_eq!(merged.level("dead-store"), LintLevel::Allow);
        assert_eq!(merged.level("unused-state"), LintLevel::Warn);
        flags.set_deny_warnings(true);
        let merged = manifest.merged_with(&flags);
        assert_eq!(merged.level("unused-state"), LintLevel::Deny);
        assert_eq!(merged.level("dead-store"), LintLevel::Allow);
        assert_eq!(
            LintConfig::new().merged_with(&LintConfig::new()),
            LintConfig::new()
        );
    }

    fn source_fixture(source: &'static str) -> &'static str {
        source
            .strip_suffix('\n')
            .expect("source fixture must end with one storage newline")
    }

    fn list_expression(depth: usize, leaf: &str) -> String {
        format!("{}{leaf}{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn boundary_contract(leaf: &str) -> String {
        let expression = list_expression(crate::source::MAX_NESTING_DEPTH - 2, leaf);
        format!("seiyaku StackMargin {{ hajimari() {{ let value = {expression}; }} }}")
    }

    fn nested_call_expression(depth: usize) -> String {
        format!("{}0{}", "wrap(".repeat(depth), ")".repeat(depth))
    }

    fn mixed_scalar_expression(depth: usize) -> String {
        let mut expression = String::from("0");
        for index in 0..depth {
            expression = match index % 3 {
                0 => format!("({expression})"),
                1 => format!("wrap({expression})"),
                2 => format!("-{expression}"),
                _ => unreachable!("modulo constrains the wrapper kind"),
            };
        }
        expression
    }

    fn nested_if_expression(depth: usize) -> String {
        let mut expression = String::from("0");
        for _ in 0..depth {
            expression = format!("if true {{ {expression} }} else {{ 0 }}");
        }
        expression
    }

    fn nested_match_expression(depth: usize) -> String {
        let mut expression = String::from("0");
        for _ in 0..depth {
            expression = format!(
                "match candidate {{ Option::some(_) => {expression}, Option::none => 0, }}"
            );
        }
        expression
    }
    #[test]
    fn session_returns_structured_success_and_failure() {
        let session = CompilerSession::default();
        let output = session
            .build(CompileRequest {
                source: "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }",
                source_name: Some("demo.ko"),
            })
            .expect("compile canonical source");
        assert!(!output.artifact.is_empty());
        assert!(output.manifest.code_hash.is_some());
        assert!(
            output
                .report
                .source_map
                .iter()
                .all(|entry| entry.source.source_path.as_deref() == Some("demo.ko"))
        );
        let error = session
            .build(CompileRequest {
                source: "not a seiyaku",
                source_name: Some("broken.ko"),
            })
            .expect_err("invalid source must return diagnostics");
        assert_eq!(error.diagnostics.len(), 1);
    }
    #[test]
    fn compiler_worker_is_reentrant_and_inherits_chain_discriminant() {
        let caller = std::thread::current().id();
        let inherited = chain_discriminant().wrapping_add(1);
        let _chain_discriminant = ChainDiscriminantGuard::enter(inherited);
        let (outer, inner, observed) = run_with_compiler_stack(|| {
            assert!(compiler_worker_active());
            let outer = std::thread::current().id();
            let (inner, observed) =
                run_with_compiler_stack(|| (std::thread::current().id(), chain_discriminant()))
                    .expect("nested compiler work must run inline");
            (outer, inner, observed)
        })
        .expect("spawn compiler worker");
        assert_ne!(outer, caller);
        assert_eq!(inner, outer);
        assert_eq!(observed, inherited);
    }
    #[test]
    fn session_chain_discriminant_accepts_exact_taira_account_and_rejects_mismatch() {
        const TAIRA_RECIPIENT: &str =
            "testﾜヰ8ｽuimdh9FﾂｦUｸﾈbﾕﾆヱMUYｴGｷﾙｹﾐRヱbﾐｷwﾄ6ﾃdDLPQﾋW496uﾙﾜFpﾈtHd4Hﾙﾎ45M1L5";
        let source = format!(
            "seiyaku TairaLiteral {{ view fn recipient() authorize(anyone) -> AccountId {{ return AccountId::parse(\"{TAIRA_RECIPIENT}\"); }} }}"
        );
        let taira = CompilerSession::new(CompilerOptions {
            chain_discriminant: 369,
            ..CompilerOptions::default()
        });
        taira
            .build(CompileRequest {
                source: &source,
                source_name: Some("taira_literal.ko"),
            })
            .expect("the exact Taira I105 literal must compile under discriminant 369");
        let sora = CompilerSession::new(CompilerOptions {
            chain_discriminant: 753,
            ..CompilerOptions::default()
        });
        let diagnostics = sora
            .build(CompileRequest {
                source: &source,
                source_name: Some("taira_literal.ko"),
            })
            .expect_err("the Taira literal must fail under Sora discriminant 753");
        let mismatch = &diagnostics.diagnostics[0];
        assert_eq!(mismatch.code, "E_INVALID_ID_LITERAL");
        assert_eq!(
            mismatch.message,
            "AccountId literal is encoded for chain discriminant 369 but this build targets 753 (ERR_UNEXPECTED_NETWORK_PREFIX)"
        );
        let span = mismatch
            .primary_span
            .as_ref()
            .and_then(|span| span.byte_range)
            .expect("the mismatch is reported on the literal");
        assert_eq!(
            &source[span.start as usize..span.end as usize],
            format!("\"{TAIRA_RECIPIENT}\"")
        );
        assert_ne!(
            taira.policy_fingerprint(),
            sora.policy_fingerprint(),
            "network account-literal policy must be cache-keyed"
        );
    }
    #[test]
    fn contextual_retired_type_words_remain_valid_value_and_entrypoint_names() {
        let source = "seiyaku ValueNames { view fn amount(quantity money) authorize(anyone) -> quantity { let quantity number = money; return number; } }";
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("value-names.ko"),
            })
            .expect("contextual retired type words must remain ordinary value names");
        let entrypoints = output
            .manifest
            .entrypoints
            .as_deref()
            .expect("deployable seiyaku manifest entrypoints");
        assert_eq!(entrypoints.len(), 1);
        assert_eq!(entrypoints[0].name, "amount");
        let diagnostics = CompilerSession::default()
            .check(CompileRequest {
                source: "module RetiredType { struct Amount { int value; } }",
                source_name: Some("retired-type.ko"),
            })
            .expect_err("exact `Amount` must be forbidden in every identifier context");
        assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "E_FORBIDDEN_SOURCE_IDENTIFIER"
                && diagnostic.message.contains("identifier `Amount`")
        }));
    }
    #[test]
    fn retired_type_words_are_rejected_as_source_unit_identities() {
        let session = CompilerSession::default();
        let contract_diagnostics = session
            .build(CompileRequest {
                source: "seiyaku Amount { view fn run() authorize(anyone) {} }",
                source_name: Some("retired-contract.ko"),
            })
            .expect_err("a retired numeric type must not identify a deployable seiyaku");
        assert!(contract_diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "E_FORBIDDEN_SOURCE_IDENTIFIER"
                && diagnostic.message.contains("identifier `Amount`")
        }));
        let module_diagnostics = session
            .check(CompileRequest {
                source: "module i64 { fn run() {} }",
                source_name: Some("retired-module.ko"),
            })
            .expect_err("a retired numeric type must not identify a module");
        assert!(module_diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "E_RESERVED_DECLARATION"
                && diagnostic.message.contains("source unit `i64`")
        }));
    }
    #[test]
    fn check_drops_a_boundary_depth_program_iteratively() {
        let mut ty = String::from("int");
        for _ in 0..crate::source::MAX_NESTING_DEPTH - 2 {
            ty = format!("Option<{ty}>");
        }
        let source = format!("module Deep {{ struct Wrapper {{ {ty} value }} }}");
        let request = CompileRequest {
            source: &source,
            source_name: Some("deep.ko"),
        };
        let session = CompilerSession::default();
        session
            .check(request)
            .expect("the inclusive frontend nesting boundary must be stack-safe");
        session
            .check_with_lints(CompileRequest {
                source: &source,
                source_name: Some("deep.ko"),
            })
            .expect("lint cleanup at the nesting boundary must be stack-safe");
        let invalid = source.replace("int", "UnknownType");
        session
            .check(CompileRequest {
                source: &invalid,
                source_name: Some("deep-invalid.ko"),
            })
            .expect_err("semantic-error cleanup at the nesting boundary must be stack-safe");
    }
    #[test]
    fn whole_pipeline_fits_half_the_reserved_compiler_stack() {
        std::thread::Builder::new()
            .name("kotodama-direct-compiler-stack-margin".to_owned())
            .stack_size(COMPILER_STACK_BYTES / 2)
            .spawn(|| {
                let session = CompilerSession::default();
                let valid = boundary_contract("0");
                session
                    .check_inner(CompileRequest {
                        source: &valid,
                        source_name: Some("direct-margin-check.ko"),
                    })
                    .expect("boundary-depth check must fit half the compiler stack");
                let output = session
                    .build_inner(CompileRequest {
                        source: &valid,
                        source_name: Some("direct-margin-build.ko"),
                    })
                    .expect("boundary-depth code generation must fit half the compiler stack");
                assert!(!output.artifact.is_empty());

                let depth = crate::source::MAX_NESTING_DEPTH - 2;
                for (label, expression) in [
                    ("calls", nested_call_expression(depth)),
                    ("mixed", mixed_scalar_expression(depth)),
                    ("if", nested_if_expression(depth)),
                    // The arm payload parentheses occupy the one delimiter
                    // level that a scalar wrapper would otherwise use.
                    ("match", nested_match_expression(depth - 1)),
                ] {
                    let setup = if label == "match" {
                        "let candidate = Option::some(0);"
                    } else {
                        ""
                    };
                    let source = format!(
                        "seiyaku StackMargin {{ fn wrap(int _ value) -> int {{ return value; }} hajimari() {{ {setup} let value = {expression}; }} }}"
                    );
                    let output = session
                        .build_inner(CompileRequest {
                            source: &source,
                            source_name: Some("direct-margin-shape.ko"),
                        })
                        .unwrap_or_else(|diagnostics| {
                            panic!("{label} boundary pipeline failed: {diagnostics:?}")
                        });
                    assert!(!output.artifact.is_empty(), "{label}");
                }

                let deep_type = format!(
                    "{}int{}",
                    "Option<".repeat(depth),
                    ">".repeat(depth)
                );
                let typed_source =
                    format!("module StackMargin {{ fn value({deep_type} input) {{}} }}");
                session
                    .check_inner(CompileRequest {
                        source: &typed_source,
                        source_name: Some("direct-margin-type.ko"),
                    })
                    .expect("boundary-depth type checking must fit half the compiler stack");

                let unresolved = boundary_contract("missing");
                let resolve_error = session
                    .check_inner(CompileRequest {
                        source: &unresolved,
                        source_name: Some("direct-margin-resolve-error.ko"),
                    })
                    .expect_err("boundary-depth unresolved leaf must fail normally");
                assert!(
                    resolve_error
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.code == "K2002")
                );

                let invalid_expression =
                    list_expression(crate::source::MAX_NESTING_DEPTH - 3, "true + 1");
                let invalid = format!(
                    "seiyaku StackMargin {{ hajimari() {{ let value = {invalid_expression}; }} }}"
                );
                let semantic_error = session
                    .check_inner(CompileRequest {
                        source: &invalid,
                        source_name: Some("direct-margin-semantic-error.ko"),
                    })
                    .expect_err("boundary-depth invalid leaf must fail normally");
                assert!(
                    semantic_error.diagnostics.iter().any(|diagnostic| {
                        matches!(diagnostic.phase, DiagnosticPhase::Semantic)
                    })
                );
            })
            .expect("spawn direct compiler margin worker")
            .join()
            .expect("whole compiler pipeline must fit the verified 32 MiB stack margin");
    }
    #[test]
    fn public_compiler_pipeline_handoffs_from_a_small_caller() {
        let source = boundary_contract("0");
        std::thread::Builder::new()
            .name("kotodama-small-compiler-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let session = CompilerSession::default();
                session
                    .check(CompileRequest {
                        source: &source,
                        source_name: Some("small-caller-check.ko"),
                    })
                    .expect("boundary-depth check must leave the caller stack");
                session
                    .check_with_lints(CompileRequest {
                        source: &source,
                        source_name: Some("small-caller-lint.ko"),
                    })
                    .expect("boundary-depth linting must leave the caller stack");
                let output = session
                    .build(CompileRequest {
                        source: &source,
                        source_name: Some("small-caller-build.ko"),
                    })
                    .expect("boundary-depth build must leave the caller stack");
                assert!(!output.artifact.is_empty());

                let excessive_expression =
                    list_expression(crate::source::MAX_NESTING_DEPTH - 1, "0");
                let excessive = format!(
                    "seiyaku StackMargin {{ hajimari() {{ let value = {excessive_expression}; }} }}"
                );
                let diagnostics = session
                    .check(CompileRequest {
                        source: &excessive,
                        source_name: Some("small-caller-excessive.ko"),
                    })
                    .expect_err("one level above the boundary must fail closed");
                assert!(
                    diagnostics
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.code == "K0003")
                );
            })
            .expect("spawn small compiler caller")
            .join()
            .expect("bounded compiler worker must contain every recursive phase");
    }
    #[test]
    fn session_rejects_oversized_input_before_constructing_a_source_database() {
        let source = " ".repeat(MAX_SOURCE_BYTES + 1);
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source: &source,
                source_name: Some("oversized.ko"),
            })
            .expect_err("oversized source must fail before parsing");
        assert_eq!(diagnostics.diagnostics.len(), 1);
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "K0001");
        assert_eq!(diagnostic.phase, DiagnosticPhase::Lex);
        assert_eq!(
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref()),
            Some("oversized.ko")
        );
    }
    #[test]
    fn session_accepts_aggregate_arguments_beyond_the_retired_register_limit() {
        let session = CompilerSession::default();
        for source in [
            source_fixture(include_str!("session/fixtures/wide_call.ko")),
            source_fixture(include_str!("session/fixtures/nested_wide_call.ko")),
        ] {
            session
                .check(CompileRequest {
                    source,
                    source_name: Some("wide-call.ko"),
                })
                .expect("table ABI admits more than thirteen words");
            session
                .build(CompileRequest {
                    source,
                    source_name: Some("wide-call.ko"),
                })
                .expect("wide source check and build agree");
        }
    }
    #[test]
    fn modules_can_be_checked_but_never_emitted_directly() {
        let session = CompilerSession::default();
        let request = CompileRequest {
            source: "module Math { fn add(int left, int right) -> int { return left + right; } }",
            source_name: Some("math.ko"),
        };
        session.check(request).expect("standalone module check");
        let diagnostics = session
            .build(request)
            .expect_err("a module must not produce deployable bytecode");
        assert_eq!(diagnostics.diagnostics.len(), 1);
        assert_eq!(diagnostics.diagnostics[0].code, "K4003");
        assert_eq!(diagnostics.diagnostics[0].phase, DiagnosticPhase::Artifact);
    }
    #[test]
    fn check_and_build_return_identical_resolution_records_for_contracts_and_modules() {
        let session = CompilerSession::default();
        for source in [
            source_fixture(include_str!("session/fixtures/broken_contract.ko")),
            source_fixture(include_str!("session/fixtures/broken_module.ko")),
        ] {
            let request = CompileRequest {
                source,
                source_name: Some("broken.ko"),
            };
            let checked = session
                .check(request)
                .expect_err("check must reject source");
            let built = session
                .build(request)
                .expect_err("build must reject source");
            assert_eq!(checked, built);
            assert_eq!(checked.diagnostics.len(), 3, "{checked:?}");
            assert_eq!(
                checked
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.phase))
                    .collect::<Vec<_>>(),
                vec![
                    ("K2002", DiagnosticPhase::Resolve),
                    ("K2002", DiagnosticPhase::Resolve),
                    ("K2002", DiagnosticPhase::Resolve),
                ]
            );
            assert_eq!(
                checked
                    .diagnostics
                    .iter()
                    .map(|diagnostic| {
                        let range = diagnostic
                            .primary_span
                            .as_ref()
                            .and_then(|span| span.byte_range)
                            .expect("resolved diagnostic range");
                        &source[range.start as usize..range.end as usize]
                    })
                    .collect::<Vec<_>>(),
                vec!["Missing", "unknown", "missing_call"]
            );
            assert!(checked.diagnostics.iter().all(|diagnostic| {
                diagnostic
                    .primary_span
                    .as_ref()
                    .is_some_and(|span| span.byte_range.is_some())
            }));
        }
    }
    #[test]
    fn resolution_failures_are_collected_with_stable_source_spans() {
        let source = "seiyaku Broken {\nfn first() -> int { return missing_first; }\nfn second() -> int { return missing_second; }\n}";
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("multi-error.ko"),
            })
            .expect_err("both invalid function bodies must be diagnosed");
        assert_eq!(diagnostics.diagnostics.len(), 2);
        for ((diagnostic, expected_line), expected_name) in diagnostics
            .diagnostics
            .iter()
            .zip([2, 3])
            .zip(["missing_first", "missing_second"])
        {
            assert_eq!(diagnostic.phase, DiagnosticPhase::Resolve);
            assert_eq!(diagnostic.code, "K2002");
            let span = diagnostic.primary_span.as_ref().expect("function span");
            assert_eq!(span.source.as_deref(), Some("multi-error.ko"));
            assert_eq!(span.start.line, expected_line);
            let range = span.byte_range.expect("exact UTF-8 byte range");
            assert_eq!(
                &source[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()],
                expected_name
            );
        }
        let repeated = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("multi-error.ko"),
            })
            .expect_err("repeated invalid compilation must fail identically");
        assert_eq!(diagnostics, repeated);
    }
    #[test]
    fn compiler_session_preserves_explicit_semantic_code_and_plain_message() {
        let source = "seiyaku Broken { fn missing_context() { let values = []; } }";
        let diagnostics = CompilerSession::default()
            .check(CompileRequest {
                source,
                source_name: Some("explicit-semantic-code.ko"),
            })
            .expect_err("an empty List without a type context must fail");
        let [diagnostic] = diagnostics.diagnostics.as_slice() else {
            panic!("expected one semantic diagnostic: {diagnostics:?}");
        };
        assert_eq!(diagnostic.code, "E_LIST_EMPTY_CONTEXT");
        assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
        assert_eq!(
            diagnostic.message,
            "an empty list requires an exact `List<T, N>` type context"
        );
        assert!(!diagnostic.message.contains("E_LIST_EMPTY_CONTEXT"));
        let human = diagnostics.render_human();
        let json = diagnostics.render_json().expect("JSON diagnostics");
        let sarif = diagnostics.render_sarif().expect("SARIF diagnostics");
        for rendered in [&human, &json, &sarif] {
            assert!(rendered.contains("E_LIST_EMPTY_CONTEXT"));
            assert!(rendered.contains(&diagnostic.message));
        }
    }
    #[test]
    fn secret_signature_and_state_rejections_have_exact_type_spans() {
        let session = CompilerSession::new(CompilerOptions {
            force_zk: true,
            ..CompilerOptions::default()
        });
        for (source, code) in [
            (
                "seiyaku Privacy { state Secret<int> hidden; }",
                "E_SECRET_STATE_TYPE",
            ),
            (
                "seiyaku Privacy { permission Leak;  kotoage fn leak(Secret<int> value) authorize(Leak) {} }",
                "E_SECRET_PUBLIC_PARAMETER",
            ),
            (
                "seiyaku Privacy { permission Leak;  kotoage fn leak() authorize(Leak) -> Secret<int> { return crypto::private_input(0); } }",
                "E_SECRET_PUBLIC_RETURN",
            ),
        ] {
            let diagnostics = session
                .check(CompileRequest {
                    source,
                    source_name: Some("secret-span.ko"),
                })
                .expect_err("public or durable Secret<T> use must fail");
            let diagnostic = diagnostics
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .unwrap_or_else(|| panic!("missing {code}: {diagnostics:?}"));
            assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
            assert!(!diagnostic.message.contains(code));
            let range = diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .expect("security diagnostics retain an exact type span");
            assert_eq!(
                &source[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()],
                "Secret<int>"
            );
        }
    }
    #[test]
    fn v1_retired_and_unsafe_diagnostics_have_exact_ranges_and_safe_fixes() {
        fn reject(source: &str) -> DiagnosticBundle {
            CompilerSession::default()
                .check(CompileRequest {
                    source,
                    source_name: Some("v1-diagnostic.ko"),
                })
                .expect_err("fixture must be rejected")
        }
        fn diagnostic<'a>(bundle: &'a DiagnosticBundle, code: &str) -> &'a Diagnostic {
            bundle
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .unwrap_or_else(|| panic!("missing {code}: {bundle:#?}"))
        }
        fn primary_text<'a>(source: &'a str, diagnostic: &Diagnostic) -> &'a str {
            let range = diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .expect("exact primary byte range");
            &source[range.start as usize..range.end as usize]
        }
        fn fix_text<'source, 'diagnostic>(
            source: &'source str,
            diagnostic: &'diagnostic Diagnostic,
        ) -> (&'source str, &'diagnostic str) {
            let fix = diagnostic.fix.as_ref().expect("machine-applicable fix");
            let range = fix.span.byte_range.expect("exact fix byte range");
            (
                &source[range.start as usize..range.end as usize],
                &fix.replacement,
            )
        }
        let positional =
            "seiyaku C { struct Pair { int left, int right } fn f() { let pair = Pair(1, 2); } }";
        let positional_error = reject(positional);
        let positional_diagnostic = diagnostic(&positional_error, "E_POSITIONAL_STRUCT");
        assert_eq!(
            primary_text(positional, positional_diagnostic),
            "Pair(1, 2)"
        );
        assert_eq!(
            fix_text(positional, positional_diagnostic),
            ("Pair(1, 2)", "Pair { left: 1, right: 2, }")
        );
        let mixed =
            "seiyaku C { fn target(int first, int second) {} fn f() { target(1, first: 2); } }";
        let mixed_error = reject(mixed);
        let mixed_diagnostic = diagnostic(&mixed_error, "E_DUPLICATE_NAMED_ARGUMENT");
        assert!(mixed_diagnostic.primary_span.is_some());
        let reversed = "seiyaku C { fn f() { target(first: 1, 2); } }";
        let reversed_error = reject(reversed);
        let reversed_diagnostic = diagnostic(&reversed_error, "E_POSITIONAL_ARGUMENT_ORDER");
        assert_eq!(primary_text(reversed, reversed_diagnostic), "2");
        assert!(reversed_diagnostic.fix.is_none());
        let unsafe_read =
            "seiyaku C { fn read(List<int, 2> values) -> Option<int> { return values[0]; } }";
        let read_error = reject(unsafe_read);
        let read_diagnostic = diagnostic(&read_error, "E_LIST_UNSAFE_INDEX");
        assert_eq!(primary_text(unsafe_read, read_diagnostic), "values[0]");
        assert_eq!(
            fix_text(unsafe_read, read_diagnostic),
            ("values[0]", "values.get(0)")
        );
        let mistyped_read = "seiyaku C { fn read(List<int, 2> values) -> Option<int> { return values[\"zero\"]; } }";
        let mistyped_read_error = reject(mistyped_read);
        assert!(
            diagnostic(&mistyped_read_error, "E_LIST_UNSAFE_INDEX")
                .fix
                .is_none(),
            "a List.get recipe with a non-int index would not type-check"
        );
        let unsafe_write =
            "seiyaku C { fn write() { var List<int, 2> values = [1]; values[0] = 2; } }";
        let write_error = reject(unsafe_write);
        let write_diagnostic = diagnostic(&write_error, "E_LIST_UNSAFE_INDEX");
        assert_eq!(
            primary_text(unsafe_write, write_diagnostic),
            "values[0] = 2;"
        );
        assert_eq!(
            fix_text(unsafe_write, write_diagnostic),
            ("values[0] = 2;", "values.set(index: 0, value: 2);",)
        );
        for unsafe_without_recipe in [
            "seiyaku C { fn write() { let List<int, 2> values = [1]; values[0] = 2; } }",
            "seiyaku C { fn write() { var List<int, 2> values = [1]; values[\"zero\"] = 2; } }",
            "seiyaku C { fn write() { var List<int, 2> values = [1]; values[0] = \"two\"; } }",
            "seiyaku C { fn write() { var List<int, 2> values = [1]; values[0] += 2; } }",
            "seiyaku C { fn write() { var List<int, 2> values = [1]; values[0] /* keep */ = 2; } }",
        ] {
            let error = reject(unsafe_without_recipe);
            let diagnostic = diagnostic(&error, "E_LIST_UNSAFE_INDEX");
            assert!(
                diagnostic.fix.is_none(),
                "unsafe, non-compiling, compound, or trivia-moving rewrite must fail closed: {diagnostic:#?}"
            );
        }
        let legacy_sum = "seiyaku C { fn f() -> Option<int> { option::none(0) } }";
        let legacy_error = reject(legacy_sum);
        let legacy_diagnostic = diagnostic(&legacy_error, "E_LEGACY_SUM_CONSTRUCTOR");
        assert_eq!(
            primary_text(legacy_sum, legacy_diagnostic),
            "option::none(0)"
        );
        assert_eq!(
            fix_text(legacy_sum, legacy_diagnostic),
            ("option::none(0)", "Option::none")
        );
        let query_key = "seiyaku C { view fn account(bytes raw) authorize(anyone) { let account_view = ledger::query::account(raw); } }";
        let query_key_error = reject(query_key);
        let query_key_diagnostic = diagnostic(&query_key_error, "E_QUERY_KEY_TYPE");
        assert_eq!(
            primary_text(query_key, query_key_diagnostic),
            "ledger::query::account(raw)"
        );
        assert!(query_key_diagnostic.fix.is_none());
        let query_result = "seiyaku C { view fn account(AccountId id) authorize(anyone) { let bytes raw = ledger::query::account(id); } }";
        let query_result_error = reject(query_result);
        let query_result_diagnostic = diagnostic(&query_result_error, "E_QUERY_RESULT_TYPE");
        assert_eq!(primary_text(query_result, query_result_diagnostic), "bytes");
        assert_eq!(
            fix_text(query_result, query_result_diagnostic),
            ("bytes", "Option<AccountView>")
        );
        let comprehension = "seiyaku C { fn copy() { let List<int, 8> source = [1]; let List<int, 4> result = [item for item in source]; } }";
        let comprehension_error = reject(comprehension);
        let comprehension_diagnostic =
            diagnostic(&comprehension_error, "E_LIST_COMPREHENSION_CAPACITY");
        assert_eq!(
            primary_text(comprehension, comprehension_diagnostic),
            "List<int, 4>"
        );
        assert_eq!(
            fix_text(comprehension, comprehension_diagnostic),
            ("List<int, 4>", "List<int, 8>")
        );
        let retired_amount = "seiyaku C { fn quantity_value(Amount value) -> quantity { value } }";
        let retired_amount_error = reject(retired_amount);
        let retired_amount_diagnostic = diagnostic(&retired_amount_error, "E_RETIRED_NUMERIC_TYPE");
        assert_eq!(
            primary_text(retired_amount, retired_amount_diagnostic),
            "Amount"
        );
        assert_eq!(
            fix_text(retired_amount, retired_amount_diagnostic),
            ("Amount", "quantity")
        );
        let forbidden_identifier = "seiyaku C { fn quantity_value(int Amount) -> int { Amount } }";
        let forbidden_identifier_error = reject(forbidden_identifier);
        let forbidden_identifier_diagnostic =
            diagnostic(&forbidden_identifier_error, "E_FORBIDDEN_SOURCE_IDENTIFIER");
        assert_eq!(
            primary_text(forbidden_identifier, forbidden_identifier_diagnostic),
            "Amount"
        );
        assert!(forbidden_identifier_diagnostic.fix.is_none());
        for (retired_suffix, spelling, replacement) in [
            (
                "seiyaku C { fn quantity_value() -> quantity { 1.25amt } }",
                "1.25amt",
                "1.25",
            ),
            (
                "seiyaku C { fn quantity_value() -> quantity { 1.25qty } }",
                "1.25qty",
                "1.25",
            ),
        ] {
            let retired_error = reject(retired_suffix);
            let retired_diagnostic = diagnostic(&retired_error, "E_RETIRED_NUMERIC_SUFFIX");
            assert_eq!(primary_text(retired_suffix, retired_diagnostic), spelling);
            assert_eq!(
                fix_text(retired_suffix, retired_diagnostic),
                (spelling, replacement)
            );
        }
        let scale_29 = format!("0.{}1", "0".repeat(28));
        let invalid_quantity =
            format!("seiyaku C {{ fn quantity_value() -> quantity {{ return {scale_29}; }} }}");
        let quantity_error = reject(&invalid_quantity);
        let quantity_diagnostic = diagnostic(&quantity_error, "E_DECIMAL_SCALE_OVERFLOW");
        assert_eq!(
            primary_text(&invalid_quantity, quantity_diagnostic),
            scale_29
        );
        assert!(quantity_diagnostic.fix.is_none());
    }
    #[test]
    fn parser_recovers_independent_items_into_one_spanned_bundle() {
        let source = "seiyaku Broken {\nfn first() { let int value = ; }\nfn second() { let bool value = ; }\n}";
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("parse-errors.ko"),
            })
            .expect_err("both malformed function bodies must be diagnosed");
        assert_eq!(diagnostics.diagnostics.len(), 2);
        for (diagnostic, expected_line) in diagnostics.diagnostics.iter().zip([2, 3]) {
            assert_eq!(diagnostic.code, "K1001");
            assert_eq!(diagnostic.phase, DiagnosticPhase::Parse);
            let span = diagnostic.primary_span.as_ref().expect("parse error span");
            assert_eq!(span.source.as_deref(), Some("parse-errors.ko"));
            assert_eq!(span.start.line, expected_line);
        }
        let human = diagnostics.render_human();
        let json = diagnostics.render_json().expect("render JSON diagnostics");
        let sarif = diagnostics
            .render_sarif()
            .expect("render SARIF diagnostics");
        for field in ["K1001", "parse", "parse-errors.ko"] {
            assert!(human.contains(field), "human renderer omitted {field}");
            assert!(json.contains(field), "JSON renderer omitted {field}");
            assert!(sarif.contains(field), "SARIF renderer omitted {field}");
        }
        assert!(
            sarif.contains("\"kotodama\""),
            "SARIF must embed the canonical diagnostic record"
        );
    }
    #[test]
    fn parser_spans_cover_the_complete_unexpected_token() {
        let source = "seiyaku Broken {\nfn first() { let int value = ; }\nfn second() { let bool value = ; }\n}";
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("token-spans.ko"),
            })
            .expect_err("malformed expressions must fail");
        assert_eq!(diagnostics.diagnostics.len(), 2);
        for (diagnostic, line_number) in diagnostics.diagnostics.iter().zip([2, 3]) {
            let line = source.lines().nth(line_number - 1).expect("fixture line");
            let semicolon_column = line.find(';').expect("malformed semicolon") + 1;
            let span = diagnostic.primary_span.as_ref().expect("parse span");
            assert_eq!(span.source.as_deref(), Some("token-spans.ko"));
            assert_eq!((span.start.line, span.end.line), (line_number, line_number));
            assert_eq!(span.start.column, semicolon_column);
            assert_eq!(span.end.column, semicolon_column + 1);
        }
    }
    #[test]
    fn retired_english_declarations_and_unregistered_unicode_have_precise_spans() {
        for (retired, source) in [
            ("contract", "contract Demo {}"),
            (
                "entry",
                "seiyaku Demo { entry fn run() authorize(anyone) {} }",
            ),
            ("init", "seiyaku Demo { init() {} }"),
            ("upgrade", "seiyaku Demo { upgrade() {} }"),
        ] {
            let diagnostics = CompilerSession::default()
                .build(CompileRequest {
                    source,
                    source_name: Some("alias.ko"),
                })
                .expect_err("English declaration words are not V1 keywords");
            let diagnostic = diagnostics
                .diagnostics
                .first()
                .expect("retired declaration diagnostic");
            assert_eq!(diagnostic.phase, crate::diagnostic::DiagnosticPhase::Parse);
            let span = diagnostic.primary_span.as_ref().expect("declaration span");
            let start = source.find(retired).expect("declaration offset") + 1;
            assert_eq!(span.start.column, start, "{retired}");
            assert_eq!(span.end.column, start + retired.len(), "{retired}");
        }
        let unicode_source = "seiyaku Demo { fn 利用者() {} }";
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source: unicode_source,
                source_name: Some("unicode.ko"),
            })
            .expect_err("general Unicode identifiers are forbidden");
        assert!(
            diagnostics
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.phase == crate::diagnostic::DiagnosticPhase::Lex)
        );
        let first = diagnostics.diagnostics.first().expect("Unicode diagnostic");
        let span = first.primary_span.as_ref().expect("Unicode token span");
        assert_eq!(span.source.as_deref(), Some("unicode.ko"));
        let identifier = "利用者";
        let byte_start = unicode_source
            .find(identifier)
            .expect("Unicode identifier byte offset");
        assert_eq!(
            span.start.column,
            unicode_source[..byte_start].chars().count() + 1
        );
        assert_eq!(
            span.end.column,
            span.start.column + identifier.chars().count()
        );
        assert_eq!(
            span.byte_range,
            Some(TextRange::new(
                u32::try_from(byte_start).expect("test source offset fits u32"),
                u32::try_from(byte_start + identifier.len())
                    .expect("test source end offset fits u32"),
            ))
        );
    }
    #[test]
    fn invalid_escape_reports_the_full_literal_span() {
        let source = r#"module Escape { fn invalid() { let string value = "\q"; } }"#;
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("escape.ko"),
            })
            .expect_err("unknown escape must fail lexing");
        assert_eq!(diagnostics.diagnostics.len(), 1);
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "K0100");
        assert_eq!(diagnostic.phase, crate::diagnostic::DiagnosticPhase::Lex);
        let span = diagnostic.primary_span.as_ref().expect("literal span");
        let start = source.find(r#""\q""#).expect("literal offset") + 1;
        assert_eq!(span.start.column, start);
        assert_eq!(span.end.column, start + r#""\q""#.len());
    }
    #[test]
    fn state_initialization_diagnostics_retain_actionable_spans() {
        let session = CompilerSession::default();
        for (source, code, expected_primary) in [
            (
                "seiyaku Missing { state int value; view fn read() authorize(anyone) -> int { return value; } }",
                "E_STATE_HAJIMARI_REQUIRED",
                "state",
            ),
            (
                "seiyaku Partial { state int left; state int right; hajimari() { left = 0; } }",
                "E_STATE_HAJIMARI_INCOMPLETE",
                "hajimari",
            ),
        ] {
            let request = CompileRequest {
                source,
                source_name: Some("state.ko"),
            };
            let checked = session
                .check(request)
                .expect_err("incomplete scalar initialization must fail checking");
            let error = session
                .build(CompileRequest {
                    source,
                    source_name: Some("state.ko"),
                })
                .expect_err("incomplete scalar initialization must fail");
            assert_eq!(checked, error);
            let diagnostic = error
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .unwrap_or_else(|| panic!("missing {code}: {error:?}"));
            let span = diagnostic.primary_span.as_ref().expect("primary span");
            assert_eq!(span.source.as_deref(), Some("state.ko"));
            let range = span.byte_range.expect("byte range");
            assert_eq!(
                &source[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()],
                expected_primary
            );
        }
    }
    #[test]
    fn adversarial_error_fanout_is_bounded_and_reported() {
        let mut source = String::from("seiyaku ErrorFanout {\n");
        for index in 0..80 {
            use std::fmt::Write as _;
            writeln!(
                source,
                "fn failure_{index}() -> int {{ return missing_{index}; }}"
            )
            .expect("write source fixture");
        }
        source.push_str("}\n");
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source: &source,
                source_name: Some("fanout.ko"),
            })
            .expect_err("adversarial source must fail");
        assert_eq!(
            diagnostics.diagnostics.len(),
            crate::diagnostic::MAX_DIAGNOSTICS
        );
        let limit = diagnostics.diagnostics.last().expect("limit diagnostic");
        assert_eq!(limit.code, "K0004");
        assert_eq!(limit.phase, DiagnosticPhase::Resolve);
        assert!(limit.primary_span.is_none());
        assert!(
            limit.message.contains("17 additional"),
            "unexpected limit diagnostic: {}",
            limit.message
        );
        assert_eq!(
            diagnostics
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "K2002")
                .count(),
            crate::diagnostic::MAX_DIAGNOSTICS - 1
        );
    }
    #[test]
    fn production_rejects_every_local_test_declaration_with_exact_spans() {
        let production = CompilerSession::default();
        let test_mode = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        });
        for (source, expected_span) in [
            (
                "seiyaku Demo { view fn helper() authorize(anyone) {} #[test] fn smoke() {} }",
                "#[test]",
            ),
            (
                "seiyaku Demo { view fn helper() authorize(anyone) {} fixture seeded { caller(\"alice\"); } }",
                "fixture",
            ),
            (
                "seiyaku Demo { view fn helper() authorize(anyone) {} koto_test { target: \"demo.ko\" } }",
                "koto_test",
            ),
        ] {
            let request = CompileRequest {
                source,
                source_name: Some("local-test.ko"),
            };
            let diagnostics = production
                .build(request)
                .expect_err("production artifacts must reject local test syntax");
            assert_eq!(diagnostics.diagnostics.len(), 1, "{diagnostics:?}");
            let diagnostic = &diagnostics.diagnostics[0];
            assert_eq!(diagnostic.code, "E_TEST_ONLY_PRODUCTION");
            assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
            let span = diagnostic.primary_span.as_ref().expect("test syntax span");
            assert_eq!(span.source.as_deref(), Some("local-test.ko"));
            let range = span.byte_range.expect("exact test syntax range");
            assert_eq!(
                &source[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()],
                expected_span
            );
            test_mode
                .build(request)
                .expect("explicit test mode must retain local test syntax");
        }
    }
    #[test]
    fn production_rejects_test_only_helpers_and_test_capable_typed_hir() {
        let source = source_fixture(include_str!("session/fixtures/test_helper.ko"));
        let request = CompileRequest {
            source,
            source_name: Some("test-helper.ko"),
        };
        let production = CompilerSession::default();
        for diagnostics in [
            production
                .check(request)
                .expect_err("production checking must reject test-only helpers"),
            production
                .build(request)
                .expect_err("production building must reject test-only helpers"),
        ] {
            assert!(
                diagnostics
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "E_TEST_ONLY_PRODUCTION"),
                "{diagnostics:?}"
            );
        }
        let test_options = CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        };
        CompilerSession::new(test_options.clone())
            .build(request)
            .expect("explicit test mode enables test-only helpers");
        let program = crate::parser::parse(source).expect("parse helper program");
        let typed = crate::semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&program)
            .expect("analyze explicit test HIR");
        assert!(typed.test_support_enabled);
        let diagnostics = production
            .build_typed_program(typed, Some("test-helper.ko"))
            .expect_err("test-capable HIR must not cross into production codegen");
        assert_eq!(diagnostics.diagnostics[0].code, "E_TEST_ONLY_PRODUCTION");
    }
    #[test]
    fn typed_test_graph_is_restricted_to_test_mode_and_derives_a_clean_runtime() {
        let source = source_fixture(include_str!("session/fixtures/typed_test_graph.ko"));
        let target = TestSourceUnit {
            source_name: "suite.ko".to_owned(),
            source: source.to_owned(),
        };
        let diagnostics = CompilerSession::default()
            .build_test_sources(&target, &[])
            .expect_err("production sessions must not expose the local test build path");
        assert_eq!(diagnostics.diagnostics[0].code, "E_TEST_ONLY_PRODUCTION");
        let outputs = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        })
        .build_test_sources(&target, &[])
        .expect("explicit test-mode suite build");
        let parsed_suite = crate::metadata::ProgramMetadata::parse(&outputs.suite.artifact)
            .expect("parse generic local test harness");
        assert!(
            parsed_suite.contract_interface.is_none(),
            "local test images must keep the exact interface beside the generic artifact"
        );
        let smoke = outputs
            .suite
            .report
            .source_map
            .iter()
            .find(|function| function.function_name == "smoke")
            .expect("test function");
        let callable = outputs
            .suite
            .contract_interface
            .callables
            .iter()
            .find(|callable| callable.entry_pc == smoke.pc_start)
            .expect("authenticated test callable");
        assert!(callable.arguments.nodes.is_empty());
        assert_eq!(callable.results, ivm_abi::call::CallSchemaV1::unit());
        assert!(
            outputs
                .suite
                .report
                .source_map
                .iter()
                .any(|entry| entry.function_name == "smoke")
        );
        let runtime = outputs
            .runtime
            .as_ref()
            .expect("public view requires a runtime projection");
        let parsed_runtime = crate::metadata::ProgramMetadata::parse(&runtime.artifact)
            .expect("parse deployable runtime projection");
        assert_eq!(
            parsed_runtime.contract_interface.as_ref(),
            Some(&runtime.contract_interface),
            "production output must expose the exact interface embedded in CNTR"
        );
        assert!(
            runtime
                .report
                .source_map
                .iter()
                .all(|entry| entry.function_name != "smoke")
        );
    }
    #[test]
    fn typed_test_graph_projects_durable_state_map_intrinsics_into_runtime() {
        let target = TestSourceUnit {
            source_name: "state-map-runtime.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/state_map_runtime.ko"))
                .to_owned(),
        };
        let outputs = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        })
        .build_test_sources(&target, &[])
        .expect("valid compiler intrinsics must survive the production projection");
        let suite_metadata = crate::metadata::ProgramMetadata::parse(&outputs.suite.artifact)
            .expect("parse generic test harness");
        assert_eq!(suite_metadata.metadata.version_minor, 1);
        assert!(suite_metadata.contract_interface.is_none());
        assert!(matches!(
            outputs.suite.contract_interface().states.as_slice(),
            [crate::metadata::EmbeddedStateDescriptor {
                ty: crate::metadata::EmbeddedStateType::StateMap { .. },
                ..
            }]
        ));
        let runtime = outputs
            .runtime
            .expect("public view requires runtime output");
        let runtime_metadata = crate::metadata::ProgramMetadata::parse(&runtime.artifact)
            .expect("parse projected runtime contract");
        assert_eq!(runtime_metadata.metadata.version_minor, 1);
        assert_eq!(
            runtime_metadata
                .contract_interface
                .expect("production runtime embeds CNTR"),
            runtime.contract_interface().clone()
        );
        assert!(
            runtime
                .report
                .source_map
                .iter()
                .any(|entry| entry.function_name == "current")
        );
        assert!(
            runtime
                .report
                .source_map
                .iter()
                .all(|entry| entry.function_name != "absent_flag_is_zero")
        );
    }
    #[test]
    fn typed_test_graph_without_runtime_entrypoint_skips_runtime_artifact() {
        let target = TestSourceUnit {
            source_name: "pure-suite.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/pure_suite.ko")).to_owned(),
        };
        let outputs = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        })
        .build_test_sources(&target, &[])
        .expect("compile pure unit-test suite");
        assert!(outputs.runtime.is_none());
        assert!(
            outputs
                .suite
                .report
                .source_map
                .iter()
                .any(|entry| entry.function_name == "smoke")
        );
    }
    #[test]
    fn test_target_projection_retains_lowered_list_intrinsics() {
        let target = TestSourceUnit {
            source_name: "list-runtime.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/list_runtime.ko")).to_owned(),
        };
        let outputs = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        })
        .build_test_sources(&target, &[])
        .expect("lowered list intrinsics must survive runtime projection");
        assert!(
            outputs.runtime.is_some(),
            "public view requires runtime output"
        );
    }
    #[test]
    fn test_target_projection_retains_lowered_sum_type_intrinsics() {
        let target = TestSourceUnit {
            source_name: "sum-runtime.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/sum_runtime.ko")).to_owned(),
        };
        let outputs = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        })
        .build_test_sources(&target, &[])
        .expect("lowered sum-type intrinsics must survive runtime projection");
        assert!(
            outputs.runtime.is_some(),
            "public view requires runtime output"
        );
    }
    #[test]
    fn standalone_test_graph_keeps_stable_distinct_sources_and_typed_target_state() {
        let target = TestSourceUnit {
            source_name: "contracts/counter.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/counter_contract.ko")).to_owned(),
        };
        let first = TestSourceUnit {
            source_name: "tests/first.test.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/first_tests.ko")).to_owned(),
        };
        let second = TestSourceUnit {
            source_name: "tests/second.test.ko".to_owned(),
            source: source_fixture(include_str!("session/fixtures/second_tests.ko")).to_owned(),
        };
        let session = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        });
        let forward = session
            .build_test_sources(&target, &[first.clone(), second.clone()])
            .expect("link source-identified standalone tests");
        let reverse = session
            .build_test_sources(&target, &[second, first])
            .expect("test source order cannot affect linking");
        assert_eq!(forward.suite.artifact, reverse.suite.artifact);
        assert_eq!(
            forward
                .runtime
                .as_ref()
                .expect("target lifecycle requires runtime")
                .artifact,
            reverse
                .runtime
                .as_ref()
                .expect("target lifecycle requires runtime")
                .artifact
        );
        let paths = forward
            .suite
            .report
            .source_map
            .iter()
            .filter_map(|entry| {
                entry
                    .source
                    .source_path
                    .as_deref()
                    .map(|path| (path, entry.source.source_id))
            })
            .collect::<BTreeSet<_>>();
        assert!(
            paths
                .iter()
                .any(|(path, _)| *path == "contracts/counter.ko")
        );
        assert!(paths.iter().any(|(path, _)| *path == "tests/first.test.ko"));
        assert!(
            paths
                .iter()
                .any(|(path, _)| *path == "tests/second.test.ko")
        );
        assert_eq!(
            paths
                .iter()
                .map(|(_, source_id)| *source_id)
                .collect::<BTreeSet<_>>()
                .len(),
            3,
            "every logical source must retain a distinct stable SourceId"
        );
        assert!(forward.suite.report.source_map.iter().all(|entry| {
            entry.source.byte_start < entry.source.byte_end && entry.source.source_id != 0
        }));
        let source_texts = BTreeMap::from([
            ("contracts/counter.ko", target.source.as_str()),
            (
                "tests/first.test.ko",
                source_fixture(include_str!("session/fixtures/target_helper_tests.ko")),
            ),
            (
                "tests/second.test.ko",
                source_fixture(include_str!("session/fixtures/target_state_tests.ko")),
            ),
        ]);
        for entry in &forward.suite.report.source_map {
            let source_path = entry
                .source
                .source_path
                .as_deref()
                .expect("every source segment retains its logical path");
            let source = source_texts[source_path];
            let start = usize::try_from(entry.source.byte_start).expect("source offset fits usize");
            let end = usize::try_from(entry.source.byte_end).expect("source offset fits usize");
            assert!(start < end && end <= source.len());
            assert!(source.is_char_boundary(start) && source.is_char_boundary(end));
        }
    }
    #[test]
    fn standalone_test_graph_rejects_normalized_logical_path_aliases() {
        let target = TestSourceUnit {
            source_name: "contracts/demo.ko".to_owned(),
            source: "seiyaku Demo {}".to_owned(),
        };
        let source = source_fixture(include_str!("session/fixtures/normalized_alias_tests.ko"));
        let first = TestSourceUnit {
            source_name: "tests/./demo.test.ko".to_owned(),
            source: source.to_owned(),
        };
        let alias = TestSourceUnit {
            source_name: "tests/demo.test.ko".to_owned(),
            source: source.to_owned(),
        };
        let diagnostics = CompilerSession::new(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        })
        .build_test_sources(&target, &[first, alias])
        .expect_err("normalized aliases must not receive distinct SourceIds");
        assert_eq!(diagnostics.diagnostics[0].code, "E_DUPLICATE_SOURCE");
    }
    #[test]
    fn session_enforces_presence_aware_state_map_reads() {
        let session = CompilerSession::default();
        for (source, expected_code) in [
            (
                "seiyaku InvalidIndex { state StateMap<int, int> values; view fn read() authorize(anyone) -> int { return values[1]; } }",
                "E_STATE_MAP_OPTIONAL_READ",
            ),
            (
                "seiyaku InvalidFlatGet { state StateMap<int, int> values; view fn read() authorize(anyone) -> Option<int> { return get(values, 1); } }",
                "K2002",
            ),
        ] {
            let diagnostics = session
                .check(CompileRequest {
                    source,
                    source_name: Some("state-map-read.ko"),
                })
                .expect_err("presence-erasing StateMap read must fail");
            assert!(
                diagnostics
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code}: {diagnostics:?}"
            );
        }
        let source = concat!(
            include_str!("session/fixtures/presence_aware.ko"),
            "        "
        );
        let output = session
            .build(CompileRequest {
                source,
                source_name: Some("presence-aware.ko"),
            })
            .expect("canonical Option read, indexed write, and user get function must build");
        let interface = output
            .manifest
            .entrypoints
            .as_ref()
            .expect("entrypoint manifest")
            .iter()
            .find(|entrypoint| entrypoint.name == "read")
            .expect("read entrypoint manifest");
        assert_eq!(interface.return_type.as_deref(), Some("Option<int>"));
    }
    #[test]
    fn session_rejects_singleton_tuple_types_and_uninitialized_vars() {
        let session = CompilerSession::default();
        for (source, expected_span) in [
            ("seiyaku Invalid { fn run((int) value) {} }", "(int)"),
            ("seiyaku Invalid { fn run() { var int value; } }", ";"),
        ] {
            let diagnostics = session
                .check(CompileRequest {
                    source,
                    source_name: Some("invalid-unit.ko"),
                })
                .expect_err("singleton tuple types and uninitialized bindings must fail");
            let diagnostic = diagnostics.diagnostics.first().expect("parse diagnostic");
            assert_eq!(diagnostic.code, "K1001", "{diagnostics:?}");
            assert_eq!(diagnostic.phase, DiagnosticPhase::Parse);
            let span = diagnostic.primary_span.as_ref().expect("parse span");
            let range = span.byte_range.expect("exact parse range");
            assert_eq!(
                &source[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()],
                expected_span
            );
        }
    }
    #[test]
    fn session_builds_grouping_real_tuples_and_else_if_chains() {
        let source = concat!(include_str!("session/fixtures/branching.ko"), "        ");
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("branches.ko"),
            })
            .expect("documented else-if, grouping, and real tuples must build");
        assert_eq!(output.manifest.seiyaku_name.as_deref(), Some("Branches"));
    }
    #[test]
    fn concurrent_builds_do_not_share_semantic_declarations() {
        let session = CompilerSession::default();
        let sources = [
            (
                concat!(
                    include_str!("session/fixtures/integer_contract.ko"),
                    "                "
                ),
                "IntegerContract",
            ),
            (
                concat!(
                    include_str!("session/fixtures/boolean_contract.ko"),
                    "                "
                ),
                "BooleanContract",
            ),
        ];
        std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|worker| {
                    let session = &session;
                    let (source, expected_name) = sources[worker % sources.len()];
                    scope.spawn(move || {
                        for round in 0..4 {
                            let source_name = format!("worker-{worker}-round-{round}.ko");
                            let output = session
                                .build(CompileRequest {
                                    source,
                                    source_name: Some(&source_name),
                                })
                                .expect("parallel compilation must remain isolated");
                            assert_eq!(
                                output.manifest.seiyaku_name.as_deref(),
                                Some(expected_name)
                            );
                        }
                    })
                })
                .collect::<Vec<_>>();
            for handle in handles {
                handle.join().expect("compiler worker must not panic");
            }
        });
    }
}

#[cfg(test)]
#[path = "session/snapshot_clone_tests.rs"]
mod snapshot_clone_tests;
