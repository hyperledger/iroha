//! Partial editor facts use the same locked type and callable imports as strict linking.
use super::*;
use crate::{
    resolved::BindingId,
    semantic::{SemanticContext, TypedHirNode},
};

/// Successfully resolved facts; no recovered program can reach code generation.
pub(crate) struct EditorModuleFacts {
    /// Call signatures resolved through the graph's explicit export tables.
    pub(crate) signatures: BTreeMap<String, FunctionSignature>,
    /// Inferred types keyed by the original resolver binding identities.
    pub(crate) bindings: BTreeMap<BindingId, Type>,
    /// Successfully typed source expressions, including those preceding a body error.
    pub(crate) nodes: Vec<TypedHirNode>,
}

impl ModuleBuildGraph {
    /// Apply the normal graph bounds and canonical source names before assigning editor identities.
    pub(crate) fn editor_request(
        request: &SourceLinkRequest,
    ) -> Result<SourceLinkRequest, SourceGraphError> {
        Self::canonical_source_bundle(request.clone())
    }
}

impl TypedLinker {
    /// Retain local facts after a body error while preserving locked import authority.
    pub(crate) fn analyze_editor_graph(
        &self,
        mut request: LinkRequest,
    ) -> Result<BTreeMap<SourceId, EditorModuleFacts>, LinkError> {
        validate_linker_options(self.options)?;
        if request.root.ast().unit.kind != SourceUnitKind::Seiyaku {
            return Err(LinkError::RootMustBeSeiyaku {
                source: request.root.source_name,
            });
        }
        validate_program_symbols(&request.root)?;
        let packages = resolve_packages(self.options, &mut request.packages)?;
        let indexes = packages
            .iter()
            .enumerate()
            .map(|(index, package)| (package.identity.clone(), index))
            .collect();
        let imports = resolve_imports("root", &request.imports, &indexes)?;
        let mut base = ModuleEnvironment::default();
        for (alias, index) in &imports {
            base.add_package(alias, &packages[*index]);
        }
        request
            .local_modules
            .sort_by(|left, right| left.source_name.cmp(&right.source_name));
        let local_modules = resolve_module_group(
            self.options,
            &request.local_modules,
            &base,
            None,
            &request.root.ast().unit.name,
            packages.len(),
        )?;
        let environment = base.with_local_imports(&request.root, &local_modules)?;
        let mut facts = BTreeMap::new();
        self.collect_editor_module_facts(&request.root, &environment, None, &mut facts);
        for module in packages
            .iter()
            .flat_map(|package| &package.modules)
            .chain(&local_modules)
        {
            self.collect_editor_module_facts(
                module.source,
                &module.environment,
                Some(&module.nominal_owner),
                &mut facts,
            );
        }
        Ok(facts)
    }
    /// Analyze a library graph with its original package ownership and locked imports.
    pub(crate) fn analyze_editor_package_graph(
        &self,
        mut packages: Vec<PackageUnit>,
    ) -> Result<BTreeMap<SourceId, EditorModuleFacts>, LinkError> {
        validate_linker_options(self.options)?;
        let packages = resolve_packages(self.options, &mut packages)?;
        let mut facts = BTreeMap::new();
        for module in packages.iter().flat_map(|package| &package.modules) {
            self.collect_editor_module_facts(
                module.source,
                &module.environment,
                Some(&module.nominal_owner),
                &mut facts,
            );
        }
        Ok(facts)
    }
    fn collect_editor_module_facts(
        &self,
        module: &ModuleUnit,
        environment: &ModuleEnvironment,
        owner: Option<&str>,
        facts: &mut BTreeMap<SourceId, EditorModuleFacts>,
    ) {
        let semantic = SemanticContext::with_capabilities(
            self.options.zk_enabled,
            self.options.test_builtins_enabled,
        );
        if let Some(owner) = owner {
            semantic.set_package_identity(owner.to_owned());
        }
        let signatures = semantic
            .resolve_resolved_function_signatures_with_environment(
                &module.program,
                &environment.typed,
            )
            .unwrap_or_default();
        let (_, bindings, nodes) =
            semantic.analyze_editor_with_environment(&module.program, &environment.typed);
        for native in module.program.source_programs() {
            let id = native.source_file().id();
            let mut local_bindings = if id == module.program.source_file().id() {
                bindings.clone()
            } else {
                BTreeMap::new()
            };
            let local_nodes = nodes
                .iter()
                .filter(|node| node.id.source == id)
                .cloned()
                .collect::<Vec<_>>();
            for node in &local_nodes {
                if let Some(crate::resolved::ResolvedTarget::Value(
                    crate::resolved::ResolvedValueTarget::Binding(binding),
                )) = node.target
                {
                    local_bindings.insert(binding, node.ty.clone());
                }
            }
            let names = native
                .symbols()
                .filter(|symbol| symbol.kind == crate::resolved::ResolvedSymbolKind::Function)
                .map(|symbol| symbol.name.as_str())
                .collect::<BTreeSet<_>>();
            facts.insert(
                id,
                EditorModuleFacts {
                    signatures: signatures
                        .iter()
                        .filter(|(name, _)| names.contains(name.as_str()))
                        .map(|(name, signature)| (name.clone(), signature.clone()))
                        .collect(),
                    bindings: local_bindings,
                    nodes: local_nodes,
                },
            );
        }
    }
}
