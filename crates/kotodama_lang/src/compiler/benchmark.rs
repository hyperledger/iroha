//! Opaque, canonical compiler phase boundaries for performance measurement.
//!
//! The wrappers in this module intentionally expose no AST, HIR, MIR, or SSA
//! constructors. A caller can only advance source accepted by the production
//! [`CompilerSession`](crate::session::CompilerSession), so benchmarking an
//! individual phase cannot become a back door for forged typed programs.
use super::{Compiler, CompilerOptions, native_diagnostic_bundle};
use crate::{
    diagnostic::{DiagnosticBundle, DiagnosticPhase},
    session::{
        CompileOutput, CompileRequest, CompilerSession, ParsedCompilationUnit,
        ResolvedCompilationUnit, compiler_worker_unavailable_diagnostic, run_with_compiler_stack,
    },
};
use std::sync::Arc;

fn run_phase<T, F>(source_name: Option<&str>, operation: F) -> Result<T, DiagnosticBundle>
where
    T: Send,
    F: FnOnce() -> Result<T, DiagnosticBundle> + Send,
{
    run_with_compiler_stack(operation)
        .map_err(|_| compiler_worker_unavailable_diagnostic(source_name))?
}
/// Owned source input for the canonical compiler pipeline.
#[derive(Clone)]
pub struct SourcePhase {
    session: CompilerSession,
    compiler: Compiler,
    source: String,
    source_name: Option<String>,
}
impl SourcePhase {
    /// Create a benchmark input governed by the same options as an ordinary build.
    #[must_use]
    pub fn new(
        options: CompilerOptions,
        source: impl Into<String>,
        source_name: Option<String>,
    ) -> Self {
        Self {
            session: CompilerSession::new(options.clone()),
            compiler: Compiler::new_with_options(options),
            source: source.into(),
            source_name,
        }
    }
    /// Run source budgets, lossless lexing/CST construction, and spanned AST parsing.
    pub fn parse(self) -> Result<ParsedHirPhase, DiagnosticBundle> {
        let diagnostic_name = self.source_name.clone();
        run_phase(diagnostic_name.as_deref(), move || {
            let program = self.session.parse_compilation_unit(CompileRequest {
                source: &self.source,
                source_name: self.source_name.as_deref(),
            })?;
            Ok(ParsedHirPhase {
                session: self.session,
                compiler: self.compiler,
                program: Arc::new(program),
                source_name: self.source_name,
            })
        })
    }
}
/// Opaque spanned AST produced by the canonical lossless parser.
#[derive(Clone)]
pub struct ParsedHirPhase {
    session: CompilerSession,
    compiler: Compiler,
    program: Arc<ParsedCompilationUnit>,
    source_name: Option<String>,
}
impl ParsedHirPhase {
    /// Resolve declarations, types, values, and calls into fail-closed resolved HIR.
    pub fn resolve(self) -> Result<ResolvedHirPhase, DiagnosticBundle> {
        let diagnostic_name = self.source_name.clone();
        run_phase(diagnostic_name.as_deref(), move || {
            let parsed =
                Arc::try_unwrap(self.program).unwrap_or_else(|shared| shared.as_ref().clone());
            let program = self.session.resolve_compilation_unit(parsed)?;
            Ok(ResolvedHirPhase {
                session: self.session,
                compiler: self.compiler,
                program: Arc::new(program),
                source_name: self.source_name,
            })
        })
    }
}
/// Opaque resolved HIR with stable symbol and source identities.
#[derive(Clone)]
pub struct ResolvedHirPhase {
    session: CompilerSession,
    compiler: Compiler,
    program: Arc<ResolvedCompilationUnit>,
    source_name: Option<String>,
}
impl ResolvedHirPhase {
    /// Type-check the resolved program and derive its complete effect HIR.
    pub fn type_effect(self) -> Result<TypedEffectHirPhase, DiagnosticBundle> {
        let diagnostic_name = self.source_name.clone();
        run_phase(diagnostic_name.as_deref(), move || {
            let resolved =
                Arc::try_unwrap(self.program).unwrap_or_else(|shared| shared.as_ref().clone());
            let program = self.session.type_effect_compilation_unit(resolved)?;
            Ok(TypedEffectHirPhase {
                compiler: self.compiler,
                program: Arc::new(program),
                source_name: self.source_name,
            })
        })
    }
}
/// Opaque typed/effect HIR accepted by the canonical compiler session.
#[derive(Clone)]
pub struct TypedEffectHirPhase {
    compiler: Compiler,
    program: Arc<crate::semantic::TypedProgram>,
    source_name: Option<String>,
}
impl TypedEffectHirPhase {
    /// Validate deployability and lower typed/effect HIR into the mutable transport IR.
    pub fn lower_ir(self) -> Result<LoweredIrPhase, DiagnosticBundle> {
        let diagnostic_name = self.source_name.clone();
        run_phase(diagnostic_name.as_deref(), move || {
            let typed =
                Arc::try_unwrap(self.program).unwrap_or_else(|shared| shared.as_ref().clone());
            let program = self
                .compiler
                .lower_typed_program(typed, self.source_name.as_deref())?;
            Ok(LoweredIrPhase {
                compiler: self.compiler,
                program,
            })
        })
    }
}
/// Opaque lowering IR ready for strict SSA construction.
pub struct LoweredIrPhase {
    compiler: Compiler,
    program: super::LoweredCompilation,
}
impl LoweredIrPhase {
    /// Construct and verify strict SSA MIR without running optimization.
    pub fn construct_ssa(self) -> Result<SsaMirPhase, DiagnosticBundle> {
        run_phase(None, move || {
            let program = self.compiler.construct_ssa_program(self.program)?;
            Ok(SsaMirPhase {
                compiler: self.compiler,
                program,
            })
        })
    }
}
/// Opaque, verified strict SSA MIR before optimization.
pub struct SsaMirPhase {
    compiler: Compiler,
    program: super::SsaCompilation,
}
impl SsaMirPhase {
    /// Run the canonical SSA optimizer and whole-program reachability pass.
    pub fn optimize(self) -> Result<OptimizedSsaMirPhase, DiagnosticBundle> {
        run_phase(None, move || {
            let program = self.compiler.optimize_ssa_program(self.program)?;
            Ok(OptimizedSsaMirPhase {
                compiler: self.compiler,
                program,
            })
        })
    }
}
/// Opaque optimized SSA MIR ready for deterministic Phi destruction.
pub struct OptimizedSsaMirPhase {
    compiler: Compiler,
    program: super::PreparedCompilation,
}
impl OptimizedSsaMirPhase {
    /// Destroy SSA, split critical edges, and materialize deterministic Phi copies.
    pub fn destroy_ssa(self) -> Result<CodegenPhase, DiagnosticBundle> {
        run_phase(None, move || {
            let program = self.compiler.destroy_ssa_program(self.program)?;
            Ok(CodegenPhase {
                compiler: self.compiler,
                program,
            })
        })
    }
}
/// Opaque de-SSA program ready for final register allocation and artifact emission.
pub struct CodegenPhase {
    compiler: Compiler,
    program: super::CodegenCompilation,
}
impl CodegenPhase {
    /// Emit the canonical deployable artifact, manifest, and hash-bound sidecars.
    pub fn emit(self) -> Result<CompileOutput, DiagnosticBundle> {
        let source_name = self.program.source_name.clone();
        let diagnostic_name = source_name.clone();
        run_phase(diagnostic_name.as_deref(), move || {
            let artifacts = self
                .compiler
                .compile_codegen(self.program)
                .map_err(|message| {
                    native_diagnostic_bundle(
                        "K3099",
                        DiagnosticPhase::Lowering,
                        source_name.as_deref(),
                        None,
                        message,
                    )
                })?;
            self.compiler
                .manifest_from_artifacts(artifacts)
                .map_err(|message| {
                    native_diagnostic_bundle(
                        "K4002",
                        DiagnosticPhase::Artifact,
                        source_name.as_deref(),
                        None,
                        message,
                    )
                })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn build_through_phases(
        source: &str,
        source_name: &str,
    ) -> Result<CompileOutput, DiagnosticBundle> {
        SourcePhase::new(
            CompilerOptions::default(),
            source,
            Some(source_name.to_owned()),
        )
        .parse()?
        .resolve()?
        .type_effect()?
        .lower_ir()?
        .construct_ssa()?
        .optimize()?
        .destroy_ssa()?
        .emit()
    }
    #[test]
    fn phase_sequence_matches_ordinary_compilation() {
        let source = "seiyaku Bench { view fn add(int a, int b) authorize(anyone) -> int { return a + b; } }";
        let source_name = "bench/phase_agreement.ko";
        let ordinary = CompilerSession::new(CompilerOptions::default())
            .build(CompileRequest {
                source,
                source_name: Some(source_name),
            })
            .expect("ordinary compilation succeeds");
        let phased = build_through_phases(source, source_name)
            .expect("phase-separated compilation succeeds");
        assert_eq!(phased.artifact, ordinary.artifact);
        assert_eq!(phased.manifest, ordinary.manifest);
        assert_eq!(phased.report, ordinary.report);
    }
    #[test]
    fn phase_sequence_handoffs_from_a_small_caller_at_the_depth_boundary() {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let source =
            format!("seiyaku BenchMargin {{ hajimari() {{ let value = {expression}; }} }}");
        std::thread::Builder::new()
            .name("kotodama-small-benchmark-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let output = build_through_phases(&source, "bench/stack_margin.ko")
                    .expect("every public benchmark phase must use the compiler worker");
                assert!(!output.artifact.is_empty());
            })
            .expect("spawn small benchmark caller")
            .join()
            .expect("phase-separated compilation must not consume the caller stack");
    }
    #[test]
    fn opaque_phase_clone_and_drop_are_safe_on_a_small_caller() {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let source =
            format!("seiyaku BenchMargin {{ hajimari() {{ let value = {expression}; }} }}");
        std::thread::Builder::new()
            .name("kotodama-small-parsed-phase-owner".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let parsed = SourcePhase::new(
                    CompilerOptions::default(),
                    source,
                    Some("bench/parsed_owner_margin.ko".to_owned()),
                )
                .parse()
                .expect("boundary-depth benchmark source must parse");
                drop(parsed.clone());
                let resolved = parsed
                    .resolve()
                    .expect("boundary-depth benchmark source must resolve");
                drop(resolved.clone());
                let typed = resolved
                    .type_effect()
                    .expect("boundary-depth benchmark source must type-check");
                drop(typed.clone());
                drop(typed);
            })
            .expect("spawn small opaque-phase owner")
            .join()
            .expect("opaque phase clone and drop must not consume the caller stack");
    }
    #[test]
    fn resolution_failure_matches_ordinary_structured_diagnostics() {
        let source =
            "seiyaku Broken { view fn inspect() authorize(anyone) -> int { return missing; } }";
        let source_name = "bench/resolution_failure.ko";
        let ordinary = CompilerSession::new(CompilerOptions::default())
            .build(CompileRequest {
                source,
                source_name: Some(source_name),
            })
            .expect_err("unknown value must fail ordinary compilation");
        let parsed = SourcePhase::new(
            CompilerOptions::default(),
            source,
            Some(source_name.to_owned()),
        )
        .parse()
        .expect("source parses before resolution");
        let phased = match parsed.resolve() {
            Ok(_) => panic!("unknown value must fail resolved-HIR construction"),
            Err(diagnostics) => diagnostics,
        };
        assert_eq!(phased, ordinary);
        assert_eq!(phased.diagnostics[0].phase, DiagnosticPhase::Resolve);
    }
    #[test]
    fn semantic_failure_matches_ordinary_structured_diagnostics() {
        let source =
            "seiyaku Broken { view fn inspect() authorize(anyone) -> int { return true + 1; } }";
        let source_name = "bench/semantic_failure.ko";
        let ordinary = CompilerSession::new(CompilerOptions::default())
            .build(CompileRequest {
                source,
                source_name: Some(source_name),
            })
            .expect_err("invalid addition must fail ordinary compilation");
        let resolved = SourcePhase::new(
            CompilerOptions::default(),
            source,
            Some(source_name.to_owned()),
        )
        .parse()
        .expect("source parses")
        .resolve()
        .expect("source resolves before semantic typing");
        let phased = match resolved.type_effect() {
            Ok(_) => panic!("invalid addition must fail typed/effect HIR construction"),
            Err(diagnostics) => diagnostics,
        };
        assert_eq!(phased, ordinary);
        assert_eq!(phased.diagnostics[0].phase, DiagnosticPhase::Semantic);
    }
}
