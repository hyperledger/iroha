//! Explicit include/import closure and shared declaration resolution.
use super::*;
use crate::{
    ast::{SourceDirectiveKind, SourceUnit},
    resolved::{ExternalResolutionEnvironment, ResolvedProgram},
    source::SourceRange,
    spanned_ast::DeclarationKind,
};

#[derive(Clone)]
struct ParsedFile {
    file: SourceFile,
    parsed: SpannedProgram,
}
#[derive(Clone)]
struct ParsedUnit {
    path: String,
    files: Vec<ParsedFile>,
    order: Vec<(SourceId, usize)>,
    imports: BTreeMap<String, String>,
    contracts: BTreeMap<String, semantic::ImportedContractInterface>,
}
pub(super) struct ParsedTestUnit {
    unit: ParsedUnit,
    external: ExternalResolutionEnvironment,
}
impl ParsedTestUnit {
    pub(super) fn source_files(&self) -> impl Iterator<Item = &SourceFile> {
        self.unit.files.iter().map(|file| &file.file)
    }
    pub(super) fn resolve(
        mut self,
        target: &ExternalResolutionEnvironment,
    ) -> Result<ModuleUnit, DiagnosticBundle> {
        self.external
            .functions
            .extend(target.functions.iter().cloned());
        self.external.contracts.extend(target.contracts.clone());
        self.external.states.extend(target.states.iter().cloned());
        self.external.structs.extend(target.structs.iter().cloned());
        self.external.consts.extend(target.consts.iter().cloned());
        self.external.variant_codes.extend(
            target
                .variant_codes
                .iter()
                .map(|(name, code)| (name.clone(), *code)),
        );
        resolve_unit(&self.unit, &self.external, &mut None)
    }
}
/// Source spans whose function bodies resolved cleanly during a diagnostic-only
/// retry. A reduced graph may supply signatures and imported types, but it must
/// never become an emitted artifact or produce errors from emptied bodies.
#[derive(Default)]
struct ResolutionRecovery {
    independent: Vec<SourceSpan>,
}
impl ResolutionRecovery {
    fn collect_functions(&mut self, file: &ParsedFile, emptied: &BTreeSet<String>) {
        for declaration in &file.parsed.facts.declarations {
            if declaration.kind == DeclarationKind::Function
                && !emptied.contains(&declaration.name)
                && let Some(range) = file.parsed.facts.source_map.source_range(declaration.node)
            {
                self.independent
                    .push(SourceSpan::from_range(&file.file, range.range));
            }
        }
    }
    fn is_independent(&self, diagnostic: &Diagnostic) -> bool {
        diagnostic.primary_span.as_ref().is_some_and(|span| {
            self.independent.iter().any(|function| {
                function.source == span.source
                    && function.package_identity == span.package_identity
                    && function
                        .byte_range
                        .zip(span.byte_range)
                        .is_some_and(|(function, span)| function.contains(span))
            })
        })
    }
}
fn resolve_unit(
    unit: &ParsedUnit,
    external: &ExternalResolutionEnvironment,
    recovery: &mut Option<ResolutionRecovery>,
) -> Result<ModuleUnit, DiagnosticBundle> {
    let mut external = external.clone();
    external.contracts.extend(unit.contracts.clone());
    let directives = unit
        .files
        .iter()
        .flat_map(|file| file.parsed.program.directives.iter().cloned())
        .collect::<Vec<_>>();
    let types = semantic::contract_imports::namespace_types(&external.contracts, &directives)
        .map_err(|error| {
            DiagnosticBundle::single(Diagnostic::error(
                error.code,
                DiagnosticPhase::Resolve,
                error.message,
                None,
            ))
        })?;
    for (name, ty) in types {
        external.structs.insert(name.clone());
        match ty {
            Type::Enum(descriptor) => {
                for variant in &descriptor.variants {
                    external
                        .variant_codes
                        .insert(format!("{name}::{}", variant.name), variant.code);
                }
            }
            Type::ErrorEnum(descriptor) => {
                for variant in &descriptor.variants {
                    external
                        .variant_codes
                        .insert(format!("{name}::{}", variant.name), variant.code);
                }
            }
            _ => {}
        }
    }
    external.functions.extend(
        external
            .contracts
            .keys()
            .map(|alias| format!("{alias}::at")),
    );
    let external = &external;
    let mut files = Vec::<ResolvedProgram>::new();
    let mut failures = Vec::new();
    for file in &unit.files {
        if let Some(recovery) = recovery {
            match crate::resolved::resolve_with_imports_recovering(
                file.parsed.clone(),
                &file.file,
                external,
            ) {
                Ok(resolved) => {
                    recovery.collect_functions(file, &BTreeSet::new());
                    files.push(resolved);
                }
                Err(recovered) => {
                    if let Some(reduced) = recovered.reduced {
                        recovery.collect_functions(file, &recovered.emptied);
                        files.push(reduced);
                    } else {
                        failures.extend(recovered.diagnostics.diagnostics);
                    }
                }
            }
        } else {
            match crate::resolved::resolve_with_imports_and_external_environment(
                file.parsed.clone(),
                &file.file,
                external,
            ) {
                Ok(resolved) => files.push(resolved),
                Err(diagnostics) => failures.extend(diagnostics.diagnostics),
            }
        }
    }
    if !failures.is_empty() {
        let mut diagnostics = DiagnosticBundle::new(failures);
        for file in &unit.files {
            diagnostics.capture_source(&file.file);
        }
        return Err(diagnostics);
    }
    let root = files.remove(0);
    Ok(ModuleUnit {
        contracts: unit.contracts.clone(),
        source_name: unit.path.clone(),
        program: root.with_included_sources(files, &unit.order),
    })
}
fn graph_failures(mut errors: Vec<SourceGraphError>) -> SourceGraphError {
    if errors.len() == 1
        && !matches!(
            errors[0],
            SourceGraphError::Parse { .. } | SourceGraphError::Resolve { .. }
        )
    {
        return errors.remove(0);
    }
    let parse_only = errors
        .iter()
        .all(|error| matches!(error, SourceGraphError::Parse { .. }));
    let diagnostics = DiagnosticBundle::new(
        errors
            .into_iter()
            .flat_map(|error| error.into_diagnostics().diagnostics)
            .collect(),
    );
    if parse_only {
        SourceGraphError::Parse {
            source: "<project>".into(),
            diagnostics,
        }
    } else {
        SourceGraphError::Resolve {
            source: "<project>".into(),
            diagnostics,
        }
    }
}
struct Scope<'a> {
    graph: &'a ModuleBuildGraph,
    package: Option<&'a str>,
    inventory: BTreeMap<String, (&'a SourceModuleUnit, SourceId)>,
    artifacts: BTreeMap<String, &'a SourceContractArtifact>,
    admitted_artifacts: BTreeMap<String, semantic::ImportedContractInterface>,
    units: BTreeMap<String, ParsedUnit>,
    active_modules: Vec<String>,
    fragment_owners: BTreeMap<String, String>,
    package_constants: BTreeSet<String>,
}

pub(super) fn resolve_packages(
    graph: &ModuleBuildGraph,
    packages: &[SourcePackageUnit],
) -> Result<Vec<PackageUnit>, SourceGraphError> {
    resolve_packages_inner(graph, packages, &mut None)
}
fn resolve_packages_inner(
    graph: &ModuleBuildGraph,
    packages: &[SourcePackageUnit],
    recovery: &mut Option<ResolutionRecovery>,
) -> Result<Vec<PackageUnit>, SourceGraphError> {
    let keys = packages
        .iter()
        .flat_map(|package| {
            package
                .modules
                .iter()
                .chain(&package.sources)
                .map(|file| format!("package\0{}\0{}", package.identity, file.source_name))
        })
        .collect::<Vec<_>>();
    let mut ids = stable_source_ids(&keys).into_iter();
    let mut resolved = Vec::new();
    let mut failures = Vec::new();
    for package in packages {
        let inventory = package
            .modules
            .iter()
            .chain(&package.sources)
            .map(|source| {
                (
                    source.source_name.clone(),
                    (source, ids.next().expect("one id per inventory file")),
                )
            })
            .collect();
        let mut scope = Scope {
            graph,
            package: Some(&package.identity),
            artifacts: package
                .artifacts
                .iter()
                .map(|artifact| (artifact.source_name.clone(), artifact))
                .collect(),
            inventory,
            admitted_artifacts: BTreeMap::new(),
            units: BTreeMap::new(),
            active_modules: Vec::new(),
            fragment_owners: BTreeMap::new(),
            package_constants: imported_constants(&package.imports, packages),
        };
        let mut scope_failed = false;
        for module in &package.modules {
            if let Err(error) = scope.visit_unit(&module.source_name, SourceUnitKind::Module, None)
            {
                failures.push(error);
                scope_failed = true;
            }
        }
        if scope_failed {
            continue;
        }
        match scope.resolve_units(recovery) {
            Ok(modules) => resolved.push(PackageUnit {
                identity: package.identity.clone(),
                modules,
                exports: package.exports.clone(),
                imports: package.imports.clone(),
            }),
            Err(error) => failures.push(error),
        }
    }
    if failures.is_empty() {
        Ok(resolved)
    } else {
        Err(graph_failures(failures))
    }
}

pub(super) fn resolve(
    graph: &ModuleBuildGraph,
    request: &SourceLinkRequest,
) -> Result<LinkRequest, SourceGraphError> {
    resolve_with_tests(graph, request, &[]).map(|(request, _)| request)
}
pub(super) fn resolve_with_tests(
    graph: &ModuleBuildGraph,
    request: &SourceLinkRequest,
    test_sources: &[SourceModuleUnit],
) -> Result<(LinkRequest, Vec<ParsedTestUnit>), SourceGraphError> {
    resolve_with_tests_inner(graph, request, test_sources, &mut None)
}

/// Enrich strict resolution failures with type errors from independent functions.
/// The retry uses the original graph and session capabilities and only returns
/// diagnostics; successful lowering of a reduced graph is discarded.
pub(super) fn recover_project_diagnostics(
    graph: &ModuleBuildGraph,
    request: &SourceLinkRequest,
    test_sources: &[SourceModuleUnit],
    options: LinkerOptions,
    original: SourceGraphError,
) -> SourceGraphError {
    if !matches!(original, SourceGraphError::Resolve { .. }) {
        return original;
    }
    let mut recovery = Some(ResolutionRecovery::default());
    let Ok((resolved, tests)) =
        resolve_with_tests_inner(graph, request, test_sources, &mut recovery)
    else {
        return original;
    };
    let recovery = recovery.expect("diagnostic retry state");
    let mut diagnostics = original.into_diagnostics().diagnostics;
    if let Err(error) = TypedLinker::new(options).link_with_tests(resolved, tests) {
        diagnostics.extend(
            error
                .into_diagnostics()
                .diagnostics
                .into_iter()
                .filter(|diagnostic| recovery.is_independent(diagnostic)),
        );
    }
    SourceGraphError::Resolve {
        source: "<project>".into(),
        diagnostics: DiagnosticBundle::new(diagnostics),
    }
}
/// The package-validation counterpart of the deployable-project recovery pass.
pub(super) fn recover_package_diagnostics(
    graph: &ModuleBuildGraph,
    packages: &[SourcePackageUnit],
    local_identity: &str,
    options: LinkerOptions,
    original: SourceGraphError,
) -> SourceGraphError {
    if !matches!(original, SourceGraphError::Resolve { .. }) {
        return original;
    }
    let mut recovery = Some(ResolutionRecovery::default());
    let Ok(resolved) = resolve_packages_inner(graph, packages, &mut recovery) else {
        return original;
    };
    let recovery = recovery.expect("diagnostic retry state");
    let mut diagnostics = original.into_diagnostics().diagnostics;
    if let Err(error) = TypedLinker::new(options).validate_package_graph(resolved, local_identity) {
        diagnostics.extend(
            error
                .into_diagnostics()
                .diagnostics
                .into_iter()
                .filter(|diagnostic| recovery.is_independent(diagnostic)),
        );
    }
    SourceGraphError::Resolve {
        source: "<project>".into(),
        diagnostics: DiagnosticBundle::new(diagnostics),
    }
}
fn resolve_with_tests_inner(
    graph: &ModuleBuildGraph,
    request: &SourceLinkRequest,
    test_sources: &[SourceModuleUnit],
    recovery: &mut Option<ResolutionRecovery>,
) -> Result<(LinkRequest, Vec<ParsedTestUnit>), SourceGraphError> {
    let mut scopes = vec![(
        None,
        std::iter::once(&request.root)
            .chain(&request.sources)
            .chain(test_sources)
            .collect::<Vec<_>>(),
    )];
    scopes.extend(request.packages.iter().map(|package| {
        (
            Some(package.identity.as_str()),
            package.modules.iter().chain(&package.sources).collect(),
        )
    }));
    let keys = scopes
        .iter()
        .flat_map(|(package, files)| {
            files.iter().map(move |file| match package {
                Some(package) => format!("package\0{package}\0{}", file.source_name),
                None => format!("root\0{}", file.source_name),
            })
        })
        .collect::<Vec<_>>();
    let mut ids = stable_source_ids(&keys).into_iter();
    let mut resolved_scopes = Vec::new();
    let mut tests = Vec::new();
    let mut failures = Vec::new();
    for (index, (package, files)) in scopes.into_iter().enumerate() {
        let inventory = files
            .into_iter()
            .map(|source| {
                (
                    source.source_name.clone(),
                    (source, ids.next().expect("one id per inventory file")),
                )
            })
            .collect();
        let mut scope = Scope {
            graph,
            package,
            artifacts: (if index == 0 {
                &request.artifacts
            } else {
                &request.packages[index - 1].artifacts
            })
            .iter()
            .map(|artifact| (artifact.source_name.clone(), artifact))
            .collect(),
            inventory,
            admitted_artifacts: BTreeMap::new(),
            units: BTreeMap::new(),
            active_modules: Vec::new(),
            fragment_owners: BTreeMap::new(),
            package_constants: imported_constants(
                if index == 0 {
                    &request.imports
                } else {
                    &request.packages[index - 1].imports
                },
                &request.packages,
            ),
        };
        let entries = if index == 0 {
            std::iter::once((&request.root, SourceUnitKind::Seiyaku))
                .chain(
                    test_sources
                        .iter()
                        .map(|source| (source, SourceUnitKind::Module)),
                )
                .collect::<Vec<_>>()
        } else {
            request.packages[index - 1]
                .modules
                .iter()
                .map(|source| (source, SourceUnitKind::Module))
                .collect()
        };
        let mut scope_failed = false;
        for (source, kind) in entries {
            if let Err(error) = scope.visit_unit(&source.source_name, kind, None) {
                failures.push(error);
                scope_failed = true;
            }
        }
        if scope_failed {
            continue;
        }
        if index == 0 {
            // Capture test declaration environments before removing their units; resolution needs
            // the target's typed declarations and therefore follows production analysis.
            for source in test_sources {
                let unit = scope
                    .units
                    .get(&source.source_name)
                    .expect("test unit was visited");
                match scope.unit_environment(unit) {
                    Ok(external) => tests.push(ParsedTestUnit {
                        unit: unit.clone(),
                        external,
                    }),
                    Err(diagnostics) => failures.push(SourceGraphError::Resolve {
                        source: source.source_name.clone(),
                        diagnostics,
                    }),
                }
            }
            for source in test_sources {
                scope.units.remove(&source.source_name);
            }
        }
        match scope.resolve_units(recovery) {
            Ok(modules) => resolved_scopes.push(modules),
            Err(error) => failures.push(error),
        }
    }
    if !failures.is_empty() {
        return Err(graph_failures(failures));
    }
    let mut root_modules = resolved_scopes.remove(0);
    let root_index = root_modules
        .iter()
        .position(|module| module.source_name == request.root.source_name)
        .expect("root was resolved");
    let root = root_modules.remove(root_index);
    let packages = request
        .packages
        .iter()
        .zip(resolved_scopes)
        .map(|(package, modules)| PackageUnit {
            identity: package.identity.clone(),
            modules,
            exports: package.exports.clone(),
            imports: package.imports.clone(),
        })
        .collect();
    Ok((
        LinkRequest {
            root,
            local_modules: root_modules,
            imports: request.imports.clone(),
            packages,
        },
        tests,
    ))
}

impl Scope<'_> {
    fn error(
        &self,
        code: &str,
        message: impl Into<String>,
        source: Option<SourceRange>,
    ) -> SourceGraphError {
        let span = source.and_then(|range| {
            self.inventory
                .values()
                .find(|(_, id)| *id == range.source)
                .map(|(source, id)| {
                    SourceSpan::from_range(&self.source_file(source, *id), range.range)
                })
        });
        let mut diagnostics = DiagnosticBundle::single(Diagnostic::error(
            code,
            DiagnosticPhase::Resolve,
            message,
            span,
        ));
        for (source, id) in self.inventory.values() {
            diagnostics.capture_source(&self.source_file(source, *id));
        }
        SourceGraphError::Resolve {
            source: "<project>".into(),
            diagnostics,
        }
    }
    fn dependency_path(
        &self,
        referrer: &str,
        relative: &str,
        source: SourceRange,
    ) -> Result<String, SourceGraphError> {
        resolve_source_path(referrer, relative).map_err(|error| {
            let diagnostic = error.into_diagnostics().diagnostics.remove(0);
            self.error(&diagnostic.code, diagnostic.message, Some(source))
        })
    }
    fn source_file(&self, source: &SourceModuleUnit, id: SourceId) -> SourceFile {
        self.package.map_or_else(
            || SourceFile::new(id, source.source_name.as_str(), source.source.as_str()),
            |package| {
                SourceFile::new_in_package(
                    id,
                    package,
                    source.source_name.as_str(),
                    source.source.as_str(),
                )
            },
        )
    }
    fn parse(&self, path: &str, at: Option<SourceRange>) -> Result<ParsedFile, SourceGraphError> {
        let (source, id) = self.inventory.get(path).ok_or_else(|| {
            self.error(
                "E_SOURCE_NOT_FOUND",
                format!("source `{path}` is absent from the supplied source bundle"),
                at,
            )
        })?;
        let mut parsed = self.graph.parse_sources_with_ids_scoped(
            std::slice::from_ref(*source),
            &[*id],
            &[self.package.map(str::to_owned)],
        )?;
        Ok(ParsedFile {
            file: self.source_file(source, *id),
            parsed: parsed.remove(0),
        })
    }
    fn visit_unit(
        &mut self,
        path: &str,
        kind: SourceUnitKind,
        at: Option<SourceRange>,
    ) -> Result<(), SourceGraphError> {
        if let Some(start) = self.active_modules.iter().position(|active| active == path) {
            let mut cycle = self.active_modules[start..].to_vec();
            cycle.push(path.to_owned());
            return Err(self.error(
                "E_LOCAL_IMPORT_CYCLE",
                format!("local import cycle: {}", cycle.join(" -> ")),
                at,
            ));
        }
        if self.units.contains_key(path) {
            return Ok(());
        }
        let file = self.parse(path, at)?;
        if file.parsed.program.unit.kind != kind {
            if at.is_none() {
                return Err(if kind == SourceUnitKind::Seiyaku {
                    LinkError::RootMustBeSeiyaku {
                        source: path.into(),
                    }
                } else {
                    LinkError::DependencyMustBeModule {
                        source: path.into(),
                    }
                }
                .into());
            }
            return Err(self.error(
                "E_SOURCE_UNIT_KIND",
                format!(
                    "`{path}` must declare exactly one {}",
                    if kind == SourceUnitKind::Seiyaku {
                        "seiyaku"
                    } else {
                        "module"
                    }
                ),
                at,
            ));
        }
        self.active_modules.push(path.to_owned());
        let owner = file.parsed.program.unit.clone();
        let mut unit = ParsedUnit {
            path: path.to_owned(),
            files: Vec::new(),
            order: Vec::new(),
            imports: BTreeMap::new(),
            contracts: BTreeMap::new(),
        };
        let result = self.visit_file(file, &owner, &mut unit, &mut Vec::new());
        self.active_modules.pop();
        result?;
        self.units.insert(path.to_owned(), unit);
        Ok(())
    }
    fn visit_file(
        &mut self,
        mut file: ParsedFile,
        owner: &SourceUnit,
        unit: &mut ParsedUnit,
        active: &mut Vec<String>,
    ) -> Result<(), SourceGraphError> {
        let path = file.file.name().to_owned();
        if active.contains(&path) {
            let mut cycle = active.clone();
            cycle.push(path);
            return Err(self.error(
                "E_INCLUDE_CYCLE",
                format!("include cycle: {}", cycle.join(" -> ")),
                None,
            ));
        }
        if let Some(previous) = self.fragment_owners.get(&path) {
            if previous != &unit.path {
                return Err(self.error(
                    "E_SOURCE_OWNERSHIP",
                    format!(
                        "source `{path}` is included by both `{previous}` and `{}`",
                        unit.path
                    ),
                    None,
                ));
            }
            return Ok(());
        }
        if owner.kind == SourceUnitKind::Seiyaku
            && let Some(export) = file.parsed.program.exports.first()
        {
            return Err(self.error(
                "E_SOURCE_UNIT_KIND",
                "`export` is only permitted in module declarations",
                Some(export.source),
            ));
        }
        if file.parsed.program.unit.kind == SourceUnitKind::Fragment
            && file.parsed.program.test_target.is_some()
        {
            return Err(self.error(
                "E_SOURCE_UNIT_KIND",
                "a koto_test target must be declared in its owning module",
                None,
            ));
        }
        self.fragment_owners.insert(path.clone(), unit.path.clone());
        file.parsed.program.unit = owner.clone();
        let directives = file.parsed.program.directives.clone();
        let count = file.parsed.program.items.len();
        let id = file.file.id();
        unit.files.push(file);
        active.push(path.clone());
        for index in 0..=count {
            for directive in directives
                .iter()
                .filter(|directive| directive.item_index == index)
            {
                match &directive.kind {
                    SourceDirectiveKind::Include { path: target } => {
                        let target = self.dependency_path(&path, target, directive.source)?;
                        if active.contains(&target) {
                            let mut cycle = active.clone();
                            cycle.push(target);
                            return Err(self.error(
                                "E_INCLUDE_CYCLE",
                                format!("include cycle: {}", cycle.join(" -> ")),
                                Some(directive.source),
                            ));
                        }
                        if let Some(previous) = self.fragment_owners.get(&target) {
                            if previous == &unit.path {
                                continue;
                            }
                            return Err(self.error(
                                "E_SOURCE_OWNERSHIP",
                                format!(
                                    "source `{target}` is included by both `{previous}` and `{}`",
                                    unit.path
                                ),
                                Some(directive.source),
                            ));
                        }
                        let fragment = self.parse(&target, Some(directive.source))?;
                        if fragment.parsed.program.unit.kind != SourceUnitKind::Fragment {
                            return Err(self.error(
                                "E_SOURCE_UNIT_KIND",
                                format!(
                                    "included source `{target}` must contain bare declarations"
                                ),
                                Some(directive.source),
                            ));
                        }
                        self.visit_file(fragment, owner, unit, active)?;
                    }
                    SourceDirectiveKind::ContractTypeImport { .. } => {}
                    SourceDirectiveKind::ContractImport {
                        path: target,
                        alias,
                    } => {
                        let target =
                            resolve_contract_artifact_path(&path, target).map_err(|error| {
                                let diagnostic = error.into_diagnostics().diagnostics.remove(0);
                                self.error(
                                    &diagnostic.code,
                                    diagnostic.message,
                                    Some(directive.source),
                                )
                            })?;
                        if unit.imports.contains_key(alias) || unit.contracts.contains_key(alias) {
                            return Err(self.error(
                                "E_DUPLICATE_IMPORT",
                                format!(
                                    "unit `{}` imports alias `{alias}` more than once",
                                    owner.name
                                ),
                                Some(directive.source),
                            ));
                        }
                        let artifact = self.artifacts.get(&target).ok_or_else(|| self.error(
                            "E_CONTRACT_IMPORT_NOT_FOUND", format!("compiled contract `{target}` is absent from this source owner's artifact inventory"), Some(directive.source)))?;
                        let interface =
                            if let Some(interface) = self.admitted_artifacts.get(&target) {
                                interface.clone()
                            } else {
                                let admitted = ivm_artifact_admission::verify_contract_artifact(
                                    &artifact.artifact,
                                )
                                .map_err(|error| {
                                    self.error(
                                        "E_CONTRACT_IMPORT_INVALID",
                                        format!(
                                            "compiled contract `{target}` failed admission: {error}"
                                        ),
                                        Some(directive.source),
                                    )
                                })?;
                                let interface = semantic::ImportedContractInterface {
                                    code_hash: admitted.code_hash,
                                    interface: std::sync::Arc::new(admitted.contract_interface),
                                };
                                self.admitted_artifacts.insert(target, interface.clone());
                                interface
                            };
                        unit.contracts.insert(alias.clone(), interface);
                    }
                    SourceDirectiveKind::Import {
                        path: target,
                        alias,
                    } => {
                        let target = self.dependency_path(&path, target, directive.source)?;
                        if unit.contracts.contains_key(alias)
                            || unit.imports.insert(alias.clone(), target.clone()).is_some()
                        {
                            return Err(self.error(
                                "E_DUPLICATE_IMPORT",
                                format!(
                                    "unit `{}` imports alias `{alias}` more than once",
                                    owner.name
                                ),
                                Some(directive.source),
                            ));
                        }
                        self.visit_unit(&target, SourceUnitKind::Module, Some(directive.source))?;
                    }
                }
            }
            if index < count {
                unit.order.push((id, index));
            }
        }
        active.pop();
        Ok(())
    }
    fn unit_environment(
        &self,
        unit: &ParsedUnit,
    ) -> Result<ExternalResolutionEnvironment, DiagnosticBundle> {
        let mut failures = Vec::new();
        let mut external = ExternalResolutionEnvironment {
            consts: self.package_constants.clone(),
            contracts: unit.contracts.clone(),
            ..ExternalResolutionEnvironment::default()
        };
        let mut declarations = BTreeMap::new();
        for file in &unit.files {
            for symbol in &file.parsed.facts.declarations {
                if matches!(
                    symbol.kind,
                    crate::spanned_ast::DeclarationKind::Parameter
                        | crate::spanned_ast::DeclarationKind::SourceUnit
                ) {
                    continue;
                }
                let span = file
                    .parsed
                    .facts
                    .source_map
                    .source_span(&file.file, symbol.name_node);
                if let Some(previous) = declarations.insert(symbol.name.clone(), span.clone()) {
                    let mut diagnostic = Diagnostic::error(
                        "E_DUPLICATE_DECLARATION",
                        DiagnosticPhase::Resolve,
                        format!("duplicate declaration `{}` in shared unit", symbol.name),
                        span,
                    );
                    if let Some(previous) = previous {
                        diagnostic.labels.push(DiagnosticLabel {
                            span: previous,
                            message: "first declaration".into(),
                        });
                    }
                    failures.push(diagnostic);
                }
            }
            external.permissions.extend(
                file.parsed
                    .program
                    .permissions
                    .iter()
                    .map(|permission| permission.name.clone()),
            );
            for item in &file.parsed.program.items {
                match item {
                    Item::Function(function) => {
                        external.functions.insert(function.name.clone());
                    }
                    Item::Struct(definition) | Item::Event(definition) => {
                        external.structs.insert(definition.name.clone());
                    }
                    Item::Enum(definition) => {
                        external.structs.insert(definition.name.clone());
                        for variant in &definition.variants {
                            external.variant_codes.insert(
                                format!("{}::{}", definition.name, variant.name),
                                variant.code,
                            );
                        }
                    }
                    Item::State(state) => {
                        external.states.insert(state.name.clone());
                    }
                    Item::Const(constant) => {
                        external.consts.insert(constant.name.clone());
                    }
                    Item::Trigger(_) => {}
                }
            }
        }
        for (alias, path) in &unit.imports {
            for file in self
                .units
                .get(path)
                .into_iter()
                .flat_map(|unit| &unit.files)
            {
                for item in &file.parsed.program.items {
                    if let Item::Const(constant) = item {
                        external
                            .consts
                            .insert(format!("{alias}::{}", constant.name));
                    }
                }
            }
        }
        if failures.is_empty() {
            Ok(external)
        } else {
            let mut diagnostics = DiagnosticBundle::new(failures);
            for file in &unit.files {
                diagnostics.capture_source(&file.file);
            }
            Err(diagnostics)
        }
    }
    fn resolve_units(
        self,
        recovery: &mut Option<ResolutionRecovery>,
    ) -> Result<Vec<ModuleUnit>, SourceGraphError> {
        let mut units = Vec::new();
        let mut failures = Vec::new();
        for unit in self.units.values() {
            let result = self
                .unit_environment(unit)
                .and_then(|external| resolve_unit(unit, &external, recovery));
            match result {
                Ok(module) => units.push(module),
                Err(diagnostics) => failures.push(SourceGraphError::Resolve {
                    source: unit.path.clone(),
                    diagnostics,
                }),
            }
        }
        if failures.is_empty() {
            Ok(units)
        } else {
            Err(graph_failures(failures))
        }
    }
}

fn imported_constants(
    imports: &[ImportBinding],
    packages: &[SourcePackageUnit],
) -> BTreeSet<String> {
    imports
        .iter()
        .flat_map(|binding| {
            packages
                .iter()
                .find(|package| package.identity == binding.package)
                .into_iter()
                .flat_map(move |package| {
                    package
                        .exports
                        .iter()
                        .map(move |name| format!("{}::{name}", binding.alias))
                })
        })
        .collect()
}
