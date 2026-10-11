//! Definition-owned module interfaces and explicit local import environments.
use super::*;

#[derive(Clone, Default)]
pub(super) struct ModuleEnvironment {
    pub(super) typed: semantic::TestTargetEnvironment,
    pub(super) names: BTreeMap<String, String>,
    pub(super) aliases: BTreeSet<String>,
}
impl ModuleEnvironment {
    fn add_contracts(&mut self, module: &ModuleUnit) -> Result<(), LinkError> {
        for (alias, interface) in &module.contracts {
            validate_identifier("contract import alias", alias)?;
            if is_reserved_import_alias(alias) {
                return Err(LinkError::ReservedImport {
                    scope: module.source_name.clone(),
                    alias: alias.clone(),
                });
            }
            if !self.aliases.insert(alias.clone()) {
                return Err(LinkError::DuplicateImport {
                    scope: module.source_name.clone(),
                    alias: alias.clone(),
                });
            }
            self.typed
                .contracts
                .insert(alias.clone(), interface.clone());
        }
        let types = semantic::contract_imports::namespace_types(
            &module.contracts,
            &module.ast().directives,
        )
        .map_err(|error| {
            LinkError::Diagnostics(DiagnosticBundle::single(Diagnostic::error(
                error.code,
                DiagnosticPhase::Resolve,
                error.message,
                None,
            )))
        })?;
        self.typed.types.extend(types);
        for (alias, contract) in &module.contracts {
            self.typed.functions.insert(
                format!("{alias}::at"),
                semantic::contract_imports::constructor_signature(contract),
            );
        }
        Ok(())
    }
    pub(super) fn add_package(&mut self, alias: &str, package: &ResolvedPackage<'_>) {
        self.aliases.insert(alias.to_owned());
        for (name, export) in &package.exports {
            let name = format!("{alias}::{name}");
            self.typed
                .functions
                .insert(name.clone(), export.signature.clone());
            self.names.insert(name, export.linked_name.clone());
        }
        for (name, ty) in &package.type_exports {
            self.typed
                .types
                .insert(format!("{alias}::{name}"), ty.clone());
        }
        for (name, value) in &package.const_exports {
            self.typed
                .consts
                .insert(format!("{alias}::{name}"), value.clone());
        }
    }
    pub(super) fn add_module(
        &mut self,
        alias: &str,
        module: &ResolvedModule<'_>,
    ) -> Result<(), LinkError> {
        validate_identifier("import alias", alias)?;
        if is_reserved_import_alias(alias) {
            return Err(LinkError::ReservedImport {
                scope: "local module".into(),
                alias: alias.into(),
            });
        }
        if !self.aliases.insert(alias.to_owned()) {
            return Err(LinkError::DuplicateImport {
                scope: "source unit".into(),
                alias: alias.into(),
            });
        }
        for export in &module.source.ast().exports {
            let name = format!("{alias}::{}", export.name);
            if let Some(signature) = module.signatures.get(&export.name) {
                self.typed.functions.insert(name.clone(), signature.clone());
                self.names
                    .insert(name, module.linked_names[&export.name].clone());
            } else if let Some(ty) = module.types.get(&export.name) {
                self.typed.types.insert(name, ty.clone());
            } else if let Some(value) = module.constants.get(&export.name) {
                self.typed.consts.insert(name, value.clone());
            }
        }
        Ok(())
    }
    pub(super) fn with_local_imports(
        mut self,
        module: &ModuleUnit,
        modules: &[ResolvedModule<'_>],
    ) -> Result<Self, LinkError> {
        self.add_contracts(module)?;
        for (alias, path) in imports(module)? {
            let target = modules
                .iter()
                .find(|module| module.source.source_name == path)
                .ok_or_else(|| {
                    LinkError::Diagnostics(DiagnosticBundle::single(Diagnostic::error(
                        "E_SOURCE_NOT_FOUND",
                        DiagnosticPhase::Resolve,
                        format!("local import `{path}` is absent from the resolved module graph"),
                        None,
                    )))
                })?;
            self.add_module(&alias, target)?;
        }
        Ok(self)
    }
}

fn imports(module: &ModuleUnit) -> Result<BTreeMap<String, String>, LinkError> {
    let mut imports = BTreeMap::new();
    for directive in &module.ast().directives {
        let crate::ast::SourceDirectiveKind::Import { path, alias } = &directive.kind else {
            continue;
        };
        let source = module
            .program
            .source_files()
            .find(|source| source.id() == directive.source.source)
            .expect("source-backed directive retains its source file");
        let path = resolve_source_path(source.name(), path)
            .map_err(|error| LinkError::Diagnostics(error.into_diagnostics()))?;
        if imports.insert(alias.clone(), path).is_some() {
            return Err(LinkError::DuplicateImport {
                scope: module.source_name.clone(),
                alias: alias.clone(),
            });
        }
    }
    Ok(imports)
}

pub(super) fn resolve_module_group<'request>(
    options: LinkerOptions,
    modules: &'request [ModuleUnit],
    base: &ModuleEnvironment,
    package: Option<&str>,
    root_name: &str,
    group_index: usize,
) -> Result<Vec<ResolvedModule<'request>>, LinkError> {
    let edges = modules.iter().map(imports).collect::<Result<Vec<_>, _>>()?;
    let indexes = modules
        .iter()
        .enumerate()
        .map(|(index, module)| (module.source_name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut resolved: Vec<Option<ResolvedModule<'request>>> =
        (0..modules.len()).map(|_| None).collect();
    let mut pending = (0..modules.len()).collect::<BTreeSet<_>>();
    while !pending.is_empty() {
        let Some(index) = pending.iter().copied().find(|index| {
            edges[*index].values().all(|path| {
                indexes
                    .get(path.as_str())
                    .is_some_and(|index| resolved[*index].is_some())
            })
        }) else {
            return Err(LinkError::Diagnostics(DiagnosticBundle::single(
                Diagnostic::error(
                    "E_LOCAL_IMPORT_CYCLE",
                    DiagnosticPhase::Resolve,
                    "local module imports contain a cycle or an unavailable module",
                    None,
                ),
            )));
        };
        pending.remove(&index);
        let module = &modules[index];
        validate_program_symbols(module)?;
        validate_module_items(module)?;
        if module.ast().unit.kind != SourceUnitKind::Module {
            return Err(LinkError::DependencyMustBeModule {
                source: module.source_name.clone(),
            });
        }
        let mut environment = base.clone();
        environment.add_contracts(module)?;
        for (alias, path) in &edges[index] {
            environment.add_module(
                alias,
                resolved[indexes[path.as_str()]]
                    .as_ref()
                    .expect("ready dependency"),
            )?;
        }
        let nominal_owner = package.map(str::to_owned).unwrap_or_else(|| {
            let mut transcript = b"iroha:kotodama:local-module:v1\0".to_vec();
            for field in ["root", root_name, module.source_name.as_str()] {
                transcript.extend_from_slice(&(field.len() as u64).to_le_bytes());
                transcript.extend_from_slice(field.as_bytes());
            }
            format!("local::{}", hex::encode(Hash::new(transcript).as_ref()))
        });
        let semantic = semantic::SemanticContext::with_capabilities(
            options.zk_enabled,
            options.test_builtins_enabled,
        );
        semantic.set_package_identity(nominal_owner.clone());
        let signatures = semantic
            .resolve_resolved_function_signatures_with_environment(
                &module.program,
                &environment.typed,
            )
            .map_err(|failures| semantic_link_error(module, failures))?;
        let types = semantic
            .declared_nominal_types(module.ast())
            .map_err(|failure| {
                semantic_link_error(module, semantic::SemanticFailures::from(failure))
            })?;
        let constants = semantic
            .declared_constants(&module.program)
            .map_err(|failures| semantic_link_error(module, failures))?;
        let linked_names = signatures
            .keys()
            .enumerate()
            .map(|(function, name)| {
                (
                    name.clone(),
                    format!("{LINKED_SYMBOL_PREFIX}p{group_index}_m{index}_f{function}"),
                )
            })
            .collect();
        resolved[index] = Some(ResolvedModule {
            source: module,
            signatures,
            types,
            constants,
            linked_names,
            nominal_owner,
            environment,
        });
    }
    Ok(resolved
        .into_iter()
        .map(|module| module.expect("all modules resolved"))
        .collect())
}
