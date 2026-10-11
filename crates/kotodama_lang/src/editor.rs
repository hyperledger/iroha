//! Immutable compiler-owned editor analysis. Navigation uses resolved identities, never spelling scans.
//!
//! Recovery supplies completion candidates only. An incomplete buffer cannot produce a compilable
//! recovered AST, a rename edit, or a claimed cross-file reference. The explicit source and locked
//! import graph authorizes cross-file symbols; this module never reads the filesystem.
use crate::{
    ast::{FunctionKind, ParameterCallMode},
    lexer::{Token, TokenKind},
    linker::{
        ImportBinding, LinkerOptions, ModuleBuildGraph, ModuleUnit, SourceLinkRequest,
        SourcePackageGraphRequest, TypedLinker,
    },
    resolved::{
        BindingId, ResolvedCallTarget, ResolvedProgram, ResolvedSymbolKind, ResolvedTarget,
        ResolvedTypeTarget, ResolvedValueTarget, SymbolId,
    },
    semantic::{FunctionSignature, SemanticContext, Type, TypedHirNode, render_type_name},
    source::{FrontendBudget, SourceFile, SourceId, SourceRange, TextRange},
    spanned_ast::{AstFacts, DeclarationKind},
};
use kotodama_surface::builtins::{Builtin, BuiltinCallPolicy, BuiltinMode, BuiltinSurface};
use std::collections::{BTreeMap, BTreeSet};

mod context;
mod outline;
mod repair;
mod test_targets;

pub use outline::{
    EditorFold, EditorHighlight, EditorSemanticToken, EditorSymbol, EditorTestLens,
    SEMANTIC_TOKEN_MODIFIERS, SEMANTIC_TOKEN_TYPES,
};
pub use test_targets::declared_test_target;

/// Completion detail of a lexical binding whose type is unknown after a failed check.
const UNTYPED_BINDING_DETAIL: &str = "binding";
/// Stable source declaration or lexical binding in one snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EditorIdentity {
    /// A resolver-owned top-level declaration.
    Symbol(SourceId, SymbolId),
    /// A resolver-owned lexical binding.
    Binding(SourceId, BindingId),
}
/// One source parameter, including its explicit call mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorParameter {
    /// Source parameter name.
    pub name: String,
    /// Canonical source type.
    pub ty: String,
    /// Whether the argument requires its name.
    pub named: bool,
}
/// A source or builtin callable interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorSignature {
    /// Source-call spelling, including any explicitly imported alias.
    pub name: String,
    /// Ordered source parameters.
    pub parameters: Vec<EditorParameter>,
    /// Canonical source return type.
    pub return_type: String,
    /// Markdown prose: what the callable does, its effects, access and authorization.
    pub documentation: String,
    /// Authored Markdown only, without the generated function-role explanation.
    pub authored_documentation: String,
    /// Source-syntax declaration header, using the keyword spelling written at the
    /// declaration site (for example `言挙げ fn bump(int delta) authorize(CanBump) -> int`).
    pub declaration: String,
    /// Source declaration kind; `None` for builtins and compiler-provided members.
    pub function_kind: Option<crate::ast::FunctionKind>,
}
impl EditorSignature {
    /// Render the declaration using type-first parameter syntax.
    pub fn label(&self) -> String {
        format!(
            "{}({}) -> {}",
            self.name,
            self.parameters
                .iter()
                .map(|parameter| {
                    format!(
                        "{} {}{}",
                        parameter.ty,
                        if parameter.named { "" } else { "_ " },
                        parameter.name
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
            self.return_type
        )
    }
    /// Build an ordered LSP snippet with the declaration's required labels.
    pub fn snippet(&self) -> String {
        format!(
            "{}({})",
            self.name,
            self.parameters
                .iter()
                .enumerate()
                .map(|(index, parameter)| {
                    format!(
                        "{}${{{}:{}}}",
                        if parameter.named {
                            format!("{}: ", parameter.name)
                        } else {
                            String::new()
                        },
                        index + 1,
                        parameter.name
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}
/// One completion candidate selected for the current source and lexical context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorCompletion {
    /// Source spelling shown by the editor.
    pub label: String,
    /// LSP completion kind.
    pub kind: u64,
    /// Canonical type or full callable signature.
    pub detail: String,
    /// Snippet or plain spelling inserted by the editor.
    pub insert_text: String,
    /// Whether insert_text is an LSP snippet.
    pub snippet: bool,
    /// Markdown documentation.
    pub documentation: String,
    /// Text the client filters on when it differs from the label. Japanese keyword items
    /// also carry the romanized spelling, so typing either script finds them.
    pub filter_text: Option<String>,
    /// Sort key that keeps both spellings of a branded keyword adjacent.
    pub sort_text: Option<String>,
}
/// One declaration, shared by navigation, hover and completion.
#[derive(Clone, Debug)]
pub struct EditorDefinition {
    /// Resolver identity.
    pub identity: EditorIdentity,
    /// Exact declaration-name range.
    pub source: SourceRange,
    /// Source spelling.
    pub name: String,
    /// LSP completion kind.
    pub kind: u64,
    /// Canonical type or signature.
    pub detail: String,
    /// Callable interface, when applicable.
    pub signature: Option<EditorSignature>,
    /// Authored documentation attached to this declaration.
    pub documentation: String,
}
/// A package export that must change atomically with its resolved source declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorExportRename {
    /// Exact package identity; aliases and unrelated JSON strings are not export references.
    pub package: String,
    /// Existing exported declaration name.
    pub old_name: String,
    /// Replacement exported declaration name.
    pub new_name: String,
}
/// Semantically checked rename across source identities and explicit package metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorRename {
    /// Exact identifier ranges, including source call labels and imported references.
    pub sources: Vec<SourceRange>,
    /// Required metadata changes. A frontend must own these manifests before offering any edit.
    pub exports: Vec<EditorExportRename>,
}
#[derive(Clone, Debug)]
struct Occurrence {
    source: SourceRange,
    identity: EditorIdentity,
    declaration: bool,
    /// The use assigns to the declaration.
    write: bool,
}
struct EditorUnit {
    file: SourceFile,
    owner: SourceId,
    local_imports: BTreeMap<String, SourceId>,
    error_messages: BTreeMap<(String, String), String>,
    tokens: Vec<Token>,
    facts: AstFacts,
    resolved: Option<ResolvedProgram>,
    imports: Vec<ImportBinding>,
    package: Option<String>,
    exports: BTreeSet<String>,
    manifest_exports: BTreeSet<String>,
    binding_types: BTreeMap<BindingId, Type>,
    typed_nodes: Vec<TypedHirNode>,
    signatures: BTreeMap<String, FunctionSignature>,
    contract_types: BTreeMap<String, Type>,
}
fn source_error_messages(program: &crate::ast::Program) -> BTreeMap<(String, String), String> {
    program
        .items
        .iter()
        .filter_map(|item| {
            if let crate::ast::Item::Enum(error) = item {
                Some(error)
            } else {
                None
            }
        })
        .flat_map(|error| {
            error.variants.iter().filter_map(|variant| {
                variant
                    .message
                    .as_ref()
                    .map(|message| ((error.name.clone(), variant.name.clone()), message.clone()))
            })
        })
        .collect()
}
fn source_path_at(unit: &EditorUnit, range: SourceRange) -> Option<(String, SourceRange)> {
    let mut tokens = unit
        .tokens
        .iter()
        .skip_while(|token| token.range.start < range.range.start);
    let first = tokens.next()?;
    let TokenKind::Ident(name) = &first.kind else {
        return None;
    };
    let mut path = name.clone();
    let mut terminal = first.range;
    loop {
        let Some(separator) = tokens.next() else {
            break;
        };
        if !matches!(separator.kind, TokenKind::ColonColon) {
            break;
        }
        let Some(next) = tokens.next() else { break };
        let TokenKind::Ident(name) = &next.kind else {
            break;
        };
        path.push_str("::");
        path.push_str(name);
        terminal = next.range;
    }
    Some((path, SourceRange::new(unit.file.id(), terminal)))
}
/// A bounded, immutable source-graph snapshot used by every semantic editor operation.
#[derive(Default)]
pub struct EditorSnapshot {
    units: BTreeMap<SourceId, EditorUnit>,
    definitions: BTreeMap<EditorIdentity, EditorDefinition>,
    occurrences: Vec<Occurrence>,
    complete: bool,
    /// First diagnostic that made the graph incomplete: its code and location, and message.
    blocking: Option<(String, String)>,
    project_request: Option<SourceLinkRequest>,
    package_request: Option<SourcePackageGraphRequest>,
    zk_enabled: bool,
    /// Standalone test modules attached for selector navigation, in attachment order.
    test_modules: Vec<(SourceId, crate::linker::SourceModuleUnit)>,
    /// Owner whose public entrypoints the attached test selectors name.
    test_target_owner: Option<SourceId>,
}
impl EditorSnapshot {
    /// Analyze a loose document without any ambient import authority.
    pub fn single(name: &str, text: &str, zk_enabled: bool) -> Self {
        Self::single_with_tests(name, text, &[], zk_enabled)
    }
    /// Analyze a loose document together with standalone test modules that target it.
    ///
    /// Test selector strings such as `kotoage: "quote"` resolve to the document's public
    /// entrypoints. Attached tests never make the document's own graph incomplete.
    pub fn single_with_tests(
        name: &str,
        text: &str,
        tests: &[crate::linker::SourceModuleUnit],
        zk_enabled: bool,
    ) -> Self {
        crate::session::run_with_compiler_stack(|| {
            let mut snapshot = Self {
                complete: true,
                zk_enabled,
                ..Self::default()
            };
            snapshot.add_unit(
                SourceFile::new(SourceId(0), name, text),
                vec![],
                None,
                BTreeSet::new(),
                zk_enabled,
            );
            snapshot.test_target_owner = Some(SourceId(0));
            snapshot.attach_test_modules(tests, zk_enabled);
            snapshot.index();
            snapshot.index_test_selectors();
            snapshot
        })
        .unwrap_or_default()
    }
    /// Analyze the exact locked project graph supplied by a frontend, including its source overlays.
    pub fn project(request: &SourceLinkRequest, zk_enabled: bool) -> Self {
        Self::project_with_tests(request, &[], zk_enabled)
    }
    /// Analyze a locked project graph together with standalone test modules targeting its root.
    pub fn project_with_tests(
        request: &SourceLinkRequest,
        tests: &[crate::linker::SourceModuleUnit],
        zk_enabled: bool,
    ) -> Self {
        crate::session::run_with_compiler_stack(|| {
            let Ok(request) = ModuleBuildGraph::editor_request(request) else {
                return Self::default();
            };
            let mut snapshot = Self {
                complete: true,
                zk_enabled,
                project_request: Some(request.clone()),
                ..Self::default()
            };
            let graph = ModuleBuildGraph::default();
            let resolved_request = graph.resolve_sources(request.clone());
            if let Ok(resolved) = &resolved_request {
                let roots = std::iter::once(&resolved.root)
                    .chain(&resolved.local_modules)
                    .collect::<Vec<_>>();
                for module in &roots {
                    snapshot.add_resolved_unit(
                        module,
                        &roots,
                        &request.imports,
                        None,
                        &BTreeSet::new(),
                    );
                }
                for package in &resolved.packages {
                    let modules = package.modules.iter().collect::<Vec<_>>();
                    for module in &modules {
                        snapshot.add_resolved_unit(
                            module,
                            &modules,
                            &package.imports,
                            Some(&package.identity),
                            &package.exports,
                        );
                    }
                }
            } else {
                let files =
                    std::iter::once((None, &request.root, &request.imports, BTreeSet::new()))
                        .chain(
                            request
                                .sources
                                .iter()
                                .map(|file| (None, file, &request.imports, BTreeSet::new())),
                        )
                        .chain(request.packages.iter().flat_map(|package| {
                            package
                                .modules
                                .iter()
                                .chain(&package.sources)
                                .map(move |file| {
                                    (
                                        Some(package.identity.as_str()),
                                        file,
                                        &package.imports,
                                        package.exports.clone(),
                                    )
                                })
                        }))
                        .collect::<Vec<_>>();
                let keys = files
                    .iter()
                    .map(|(package, file, _, _)| match package {
                        Some(package) => format!("package\0{package}\0{}", file.source_name),
                        None => format!("root\0{}", file.source_name),
                    })
                    .collect::<Vec<_>>();
                for ((package, file, imports, exports), id) in files
                    .into_iter()
                    .zip(crate::linker::stable_source_ids(&keys))
                {
                    let source = if let Some(package) = package {
                        SourceFile::new_in_package(
                            id,
                            package,
                            file.source_name.as_str(),
                            file.source.as_str(),
                        )
                    } else {
                        SourceFile::new(id, file.source_name.as_str(), file.source.as_str())
                    };
                    snapshot.add_unit(
                        source,
                        imports.clone(),
                        package.map(str::to_owned),
                        exports,
                        zk_enabled,
                    );
                }
                snapshot.complete = false;
            }
            // Successful linking supplies graph-authenticated receiver types, preserving original HIR ids.
            match graph.link(
                request.clone(),
                LinkerOptions {
                    zk_enabled,
                    ..LinkerOptions::default()
                },
            ) {
                Ok(linked) => {
                    snapshot.complete = snapshot.units.values().all(|unit| unit.resolved.is_some());
                    for crate::semantic::TypedItem::Function(function) in &linked.program.items {
                        if let Some(name_source) = function.name_source
                            && let Some(unit) = snapshot.units.get_mut(&name_source.source)
                            && let Some(resolved) = &unit.resolved
                            && let Some(symbol) = resolved
                                .symbols()
                                .find(|symbol| symbol.source == name_source)
                        {
                            unit.signatures.insert(
                                symbol.name.clone(),
                                FunctionSignature {
                                    params: function.param_types.clone(),
                                    return_type: function.ret_ty.clone().unwrap_or(Type::Unit),
                                    modifiers: function.modifiers.clone(),
                                },
                            );
                        }
                    }
                    for (_, node) in linked.program.hir_nodes {
                        if let Some(unit) = snapshot.units.get_mut(&node.id.source) {
                            if let Some(ResolvedTarget::Value(ResolvedValueTarget::Binding(id))) =
                                node.target
                            {
                                unit.binding_types.insert(id, node.ty.clone());
                            }
                            unit.typed_nodes.push(node);
                        }
                    }
                }
                Err(error) => {
                    snapshot.complete = false;
                    snapshot
                        .blocking
                        .get_or_insert_with(|| blocking_summary(&error.into_diagnostics()));
                    // A body error must not discard receiver types from locked dependencies.
                    // The editor projection exposes facts only; strict linking still failed.
                    if let Ok(request) = resolved_request
                        && let Ok(facts) = TypedLinker::new(LinkerOptions {
                            zk_enabled,
                            ..LinkerOptions::default()
                        })
                        .analyze_editor_graph(request)
                    {
                        for (source, facts) in facts {
                            if let Some(unit) = snapshot.units.get_mut(&source) {
                                unit.signatures = facts.signatures;
                                unit.binding_types = facts.bindings;
                                unit.typed_nodes = facts.nodes;
                            }
                        }
                    }
                }
            }
            snapshot.test_target_owner = snapshot
                .units
                .values()
                .find(|unit| unit.package.is_none() && unit.file.name() == request.root.source_name)
                .map(|unit| unit.owner);
            snapshot.attach_test_modules(tests, zk_enabled);
            snapshot.index();
            snapshot.index_test_selectors();
            snapshot
        })
        .unwrap_or_default()
    }
    /// Analyze a reusable package and its exact locked dependencies without a deployable root.
    ///
    /// Source ownership, nominal types, dependency aliases, and manifest exports retain their
    /// package identities. Only a successfully validated package graph permits rename operations.
    pub fn package(request: &SourcePackageGraphRequest, zk_enabled: bool) -> Self {
        crate::session::run_with_compiler_stack(|| {
            let Ok(request) = ModuleBuildGraph::canonical_source_package_bundle(request.clone())
            else {
                return Self::default();
            };
            let mut snapshot = Self {
                complete: true,
                zk_enabled,
                package_request: Some(request.clone()),
                ..Self::default()
            };
            let graph = ModuleBuildGraph::default();
            let resolved = graph.resolve_package_sources(request.clone());
            match &resolved {
                Ok(packages) => {
                    for package in packages {
                        let modules = package.modules.iter().collect::<Vec<_>>();
                        for module in &modules {
                            snapshot.add_resolved_unit(
                                module,
                                &modules,
                                &package.imports,
                                Some(&package.identity),
                                &package.exports,
                            );
                        }
                    }
                }
                Err(_) => {
                    let files = std::iter::once(&request.package)
                        .chain(&request.dependencies)
                        .flat_map(|package| {
                            package
                                .modules
                                .iter()
                                .chain(&package.sources)
                                .map(move |file| (package, file))
                        })
                        .collect::<Vec<_>>();
                    let keys = files
                        .iter()
                        .map(|(package, file)| {
                            format!("package\0{}\0{}", package.identity, file.source_name)
                        })
                        .collect::<Vec<_>>();
                    for ((package, file), id) in files
                        .into_iter()
                        .zip(crate::linker::stable_source_ids(&keys))
                    {
                        snapshot.add_unit(
                            SourceFile::new_in_package(
                                id,
                                package.identity.as_str(),
                                file.source_name.as_str(),
                                &file.source,
                            ),
                            package.imports.clone(),
                            Some(package.identity.clone()),
                            package.exports.clone(),
                            zk_enabled,
                        );
                    }
                    snapshot.complete = false;
                }
            }
            let options = LinkerOptions {
                zk_enabled,
                ..LinkerOptions::default()
            };
            match graph.validate_package(request, options) {
                Ok(_) => {
                    snapshot.complete = snapshot.units.values().all(|unit| unit.resolved.is_some())
                }
                Err(error) => {
                    snapshot.complete = false;
                    snapshot.blocking = Some(blocking_summary(&error.into_diagnostics()));
                }
            }
            // Editor facts also survive body errors, while strict validation remains authoritative.
            if let Ok(packages) = resolved
                && let Ok(facts) = TypedLinker::new(options).analyze_editor_package_graph(packages)
            {
                for (source, facts) in facts {
                    if let Some(unit) = snapshot.units.get_mut(&source) {
                        unit.signatures = facts.signatures;
                        unit.binding_types = facts.bindings;
                        unit.typed_nodes = facts.nodes;
                    }
                }
            }
            snapshot.index();
            snapshot
        })
        .unwrap_or_default()
    }
    /// Re-analyze this snapshot with one source replaced, keeping its graph and attached tests.
    /// Used only for completion recovery; the result never reaches a build API.
    fn with_replaced_source(&self, unit: &EditorUnit, text: String) -> Self {
        let id = unit.file.id();
        let tests = self
            .test_modules
            .iter()
            .map(|(test, module)| crate::linker::SourceModuleUnit {
                source_name: module.source_name.clone(),
                source: if *test == id {
                    text.clone()
                } else {
                    module.source.clone()
                },
            })
            .collect::<Vec<_>>();
        let is_test = self.test_modules.iter().any(|(test, _)| *test == id);
        if let Some(request) = &self.project_request {
            let mut request = request.clone();
            if is_test {
                // Test modules are attached separately and never edit the target graph.
            } else if let Some(package) = &unit.package {
                if let Some(module) = request
                    .packages
                    .iter_mut()
                    .filter(|candidate| &candidate.identity == package)
                    .flat_map(|package| package.modules.iter_mut().chain(&mut package.sources))
                    .find(|module| module.source_name == unit.file.name())
                {
                    module.source = text;
                }
            } else if request.root.source_name == unit.file.name() {
                request.root.source = text;
            } else if let Some(file) = request
                .sources
                .iter_mut()
                .find(|file| file.source_name == unit.file.name())
            {
                file.source = text;
            }
            Self::project_with_tests(&request, &tests, self.zk_enabled)
        } else if let Some(request) = &self.package_request {
            let mut request = request.clone();
            for package in std::iter::once(&mut request.package).chain(&mut request.dependencies) {
                if Some(&package.identity) == unit.package.as_ref()
                    && let Some(file) = package
                        .modules
                        .iter_mut()
                        .chain(&mut package.sources)
                        .find(|file| file.source_name == unit.file.name())
                {
                    file.source.clone_from(&text);
                }
            }
            Self::package(&request, self.zk_enabled)
        } else {
            let Some(root) = self.units.get(&SourceId(0)) else {
                return Self::default();
            };
            let root_text = if is_test {
                root.file.text().to_owned()
            } else {
                text
            };
            Self::single_with_tests(root.file.name(), &root_text, &tests, self.zk_enabled)
        }
    }
    fn add_resolved_unit(
        &mut self,
        module: &ModuleUnit,
        modules: &[&ModuleUnit],
        imports: &[ImportBinding],
        package: Option<&str>,
        package_exports: &BTreeSet<String>,
    ) {
        let owner = module.program.source_file().id();
        let exports = module
            .program
            .program()
            .exports
            .iter()
            .map(|export| export.name.clone())
            .collect::<BTreeSet<_>>();
        let local_imports = module
            .program
            .program()
            .directives
            .iter()
            .filter_map(|directive| {
                let crate::ast::SourceDirectiveKind::Import { path, alias } = &directive.kind
                else {
                    return None;
                };
                let file = module
                    .program
                    .source_files()
                    .find(|file| file.id() == directive.source.source)?;
                let path = crate::linker::resolve_source_path(file.name(), path).ok()?;
                let target = modules.iter().find(|module| module.source_name == path)?;
                Some((alias.clone(), target.program.source_file().id()))
            })
            .collect::<BTreeMap<_, _>>();
        for file in module.program.source_files() {
            let native = module
                .program
                .source_program(file.id())
                .expect("native source program");
            let file = native.source_file().clone();
            let budget = FrontendBudget::v1();
            let (tokens, _) = crate::lexer::lower_lexed_recovering(
                &file,
                budget,
                crate::syntax::lex(&file, budget),
            );
            self.units.insert(
                file.id(),
                EditorUnit {
                    owner,
                    local_imports: local_imports.clone(),
                    error_messages: source_error_messages(native.program()),
                    file,
                    tokens,
                    facts: native.lint_facts().clone(),
                    resolved: Some(native.clone()),
                    imports: imports.to_vec(),
                    package: package.map(str::to_owned),
                    exports: exports.clone(),
                    manifest_exports: package_exports.clone(),
                    binding_types: BTreeMap::new(),
                    typed_nodes: Vec::new(),
                    signatures: BTreeMap::new(),
                    contract_types: crate::semantic::contract_imports::namespace_types(
                        &module.contracts,
                        &module.program.program().directives,
                    )
                    .unwrap_or_default(),
                },
            );
        }
    }
    fn add_unit(
        &mut self,
        file: SourceFile,
        imports: Vec<ImportBinding>,
        package: Option<String>,
        exports: BTreeSet<String>,
        zk_enabled: bool,
    ) {
        let budget = FrontendBudget::v1();
        let (tokens, _) =
            crate::lexer::lower_lexed_recovering(&file, budget, crate::syntax::lex(&file, budget));
        let parsed = match crate::syntax::parser::parse_spanned_source_or_fragment(&file, budget) {
            Ok((parsed, _)) => Some(parsed),
            Err(bundle) => {
                self.blocking
                    .get_or_insert_with(|| blocking_summary(&bundle));
                None
            }
        };
        let facts = parsed
            .as_ref()
            .map(|parsed| parsed.facts.clone())
            .unwrap_or_else(|| crate::parser::editor_source_facts(&file, &tokens));
        let aliases = imports
            .iter()
            .map(|import| (import.alias.clone(), ()))
            .collect();
        let resolved = parsed.and_then(|parsed| {
            crate::resolved::resolve_with_imports(parsed, &file, &aliases)
                .map_err(|bundle| {
                    self.blocking
                        .get_or_insert_with(|| blocking_summary(&bundle));
                })
                .ok()
        });
        let signatures = resolved
            .as_ref()
            .and_then(|resolved| {
                SemanticContext::with_capabilities(zk_enabled, true)
                    .resolve_resolved_function_signatures(resolved)
                    .ok()
            })
            .unwrap_or_default();
        let mut binding_types = BTreeMap::new();
        let mut typed_nodes = Vec::new();
        if let Some(resolved) = &resolved {
            if !resolved.program().directives.is_empty() {
                self.complete = false;
                self.blocking.get_or_insert_with(|| {
                    (
                        "an `include`/`import` directive".to_owned(),
                        "a loose document has no project graph; start the server with `musubi lsp --manifest-path <Musubi.toml>`".to_owned(),
                    )
                });
            }
            let (typed, bindings, nodes) = SemanticContext::with_capabilities(zk_enabled, true)
                .analyze_editor(resolved, BTreeMap::new(), BTreeMap::new());
            binding_types = bindings;
            typed_nodes = nodes;
            if let Err(failures) = typed {
                self.complete = false;
                if let Some(failure) = failures.failures.first() {
                    self.blocking.get_or_insert_with(|| {
                        let line = failure.location.as_ref().map_or(String::new(), |location| {
                            format!(" at line {}", location.line)
                        });
                        (
                            format!("{}{line}", failure.error.code),
                            failure.error.message.clone(),
                        )
                    });
                }
            }
        } else {
            self.complete = false;
        }
        self.units.insert(
            file.id(),
            EditorUnit {
                owner: file.id(),
                local_imports: BTreeMap::new(),
                error_messages: resolved
                    .as_ref()
                    .map(|resolved| source_error_messages(resolved.program()))
                    .unwrap_or_default(),
                file,
                tokens,
                facts,
                resolved,
                imports,
                package,
                manifest_exports: exports.clone(),
                exports,
                binding_types,
                typed_nodes,
                signatures,
                contract_types: BTreeMap::new(),
            },
        );
    }
    fn index(&mut self) {
        for (source, unit) in &self.units {
            let Some(resolved) = &unit.resolved else {
                continue;
            };
            let signatures = &unit.signatures;
            for symbol in resolved.symbols() {
                let identity = EditorIdentity::Symbol(*source, symbol.id);
                let signature = signatures
                    .get(&symbol.name)
                    .filter(|_| symbol.kind == ResolvedSymbolKind::Function)
                    .map(|signature| {
                        source_signature(
                            &symbol.name,
                            signature,
                            declaration_keyword(unit, symbol.source.range).as_deref(),
                            authored_documentation(unit, symbol.source.range),
                        )
                    });
                let detail = signature
                    .as_ref()
                    .map(|signature| signature.declaration.clone())
                    .or_else(|| declaration_header(unit, symbol.source.range))
                    .unwrap_or_else(|| symbol.name.clone());
                let kind = match symbol.kind {
                    ResolvedSymbolKind::Function => 3,
                    ResolvedSymbolKind::Struct => 22,
                    ResolvedSymbolKind::Event => 23,
                    ResolvedSymbolKind::Enum => 13,
                    ResolvedSymbolKind::State => 6,
                    ResolvedSymbolKind::Const => 21,
                    ResolvedSymbolKind::Permission => 14,
                    _ => 9,
                };
                self.definitions.insert(
                    identity,
                    EditorDefinition {
                        identity,
                        source: symbol.source,
                        name: symbol.name.clone(),
                        documentation: authored_documentation(unit, symbol.source.range).to_owned(),
                        kind,
                        detail,
                        signature,
                    },
                );
                self.occurrences.push(Occurrence {
                    source: symbol.source,
                    identity,
                    declaration: true,
                    write: false,
                });
            }
            for binding in resolved.bindings() {
                let Some(range) = binding.source else {
                    continue;
                };
                let identity = EditorIdentity::Binding(*source, binding.id);
                let detail = unit
                    .binding_types
                    .get(&binding.id)
                    .map(render_type_name)
                    .unwrap_or_else(|| UNTYPED_BINDING_DETAIL.to_owned());
                self.definitions.insert(
                    identity,
                    EditorDefinition {
                        documentation: String::new(),
                        identity,
                        source: range,
                        name: binding.name.clone(),
                        kind: 6,
                        detail,
                        signature: None,
                    },
                );
                self.occurrences.push(Occurrence {
                    source: range,
                    identity,
                    declaration: true,
                    write: false,
                });
            }
            for node in resolved.arena().nodes() {
                if let (Some(range), Some(identity)) = (
                    node.source,
                    node.target.and_then(|target| local_target(*source, target)),
                ) {
                    // Calls carry full expression ranges in HIR; their exact names are indexed below.
                    if !matches!(node.target, Some(ResolvedTarget::Call(_))) {
                        let name = self
                            .definitions
                            .get(&identity)
                            .map(|definition| definition.name.as_str());
                        if let Some(index) = unit
                            .tokens
                            .iter()
                            .position(|token| token.range.start == range.range.start)
                            && let token = &unit.tokens[index]
                            && matches!(&token.kind, TokenKind::Ident(value) if Some(value.as_str()) == name)
                        {
                            self.occurrences.push(Occurrence {
                                source: SourceRange::new(*source, token.range),
                                identity,
                                declaration: false,
                                write: matches!(node.target, Some(ResolvedTarget::Assignment(_)))
                                    || is_assignment_place(&unit.tokens, index),
                            });
                        }
                    }
                }
            }
        }
        for (source, unit) in &self.units {
            let Some(resolved) = &unit.resolved else {
                continue;
            };
            // Permission references are authenticated parser/resolver facts. Chain-token
            // strings never enter the rename set.
            let arena = resolved.arena();
            let permission_references = unit
                .facts
                .authorizations
                .iter()
                .filter_map(|authorization| {
                    unit.facts
                        .source_map
                        .source_range(authorization.name_node)
                        .map(|range| (authorization.name.as_str(), range))
                })
                .chain(arena.nodes().filter_map(|node| {
                    if node.target != Some(ResolvedTarget::Value(ResolvedValueTarget::Intrinsic)) {
                        return None;
                    }
                    let range = node.source?;
                    Some((unit.file.slice(range.range)?, range))
                }));
            for (name, range) in permission_references {
                if let Some(identity) = self.shared_identity(unit, name)
                    && self
                        .definitions
                        .get(&identity)
                        .is_some_and(|definition| definition.kind == 14)
                {
                    self.occurrences.push(Occurrence {
                        source: range,
                        identity,
                        declaration: false,
                        write: false,
                    });
                }
            }
            for node in resolved.arena().nodes() {
                if let Some(ResolvedTarget::Value(
                    target @ (ResolvedValueTarget::VariantCode(_)
                    | ResolvedValueTarget::ImportedVariant),
                )) = node.target
                    && let Some(source) = node.source
                    && let Some((namespace, range)) = enum_namespace_source(unit, source)
                {
                    let identity = match target {
                        ResolvedValueTarget::VariantCode(_) => {
                            self.shared_identity(unit, &namespace)
                        }
                        ResolvedValueTarget::ImportedVariant => {
                            self.imported_identity(unit, &namespace)
                        }
                        _ => None,
                    };
                    if let Some(identity) = identity {
                        self.occurrences.push(Occurrence {
                            source: range,
                            identity,
                            declaration: false,
                            write: false,
                        });
                    }
                }
            }
            for node in resolved.arena().nodes() {
                if matches!(
                    node.target,
                    Some(
                        ResolvedTarget::Value(
                            ResolvedValueTarget::ExternalState | ResolvedValueTarget::ExternalConst
                        ) | ResolvedTarget::Assignment(
                            ResolvedValueTarget::ExternalState | ResolvedValueTarget::ExternalConst
                        ) | ResolvedTarget::ExternalStructLiteral
                    )
                ) && let Some(range) = node.source
                    && let Some((path, name_source)) = source_path_at(unit, range)
                    && let Some(identity) = self.imported_identity(unit, &path)
                {
                    self.occurrences.push(Occurrence {
                        source: name_source,
                        identity,
                        declaration: false,
                        write: matches!(node.target, Some(ResolvedTarget::Assignment(_))),
                    });
                }
            }
            for call in resolved.calls() {
                let identity = match call.target {
                    ResolvedCallTarget::Function(id) | ResolvedCallTarget::Struct(id) => {
                        Some(EditorIdentity::Symbol(*source, id))
                    }
                    ResolvedCallTarget::External => self.imported_identity(unit, &call.name),
                    _ => None,
                };
                if let Some(identity) = identity {
                    let range = terminal_name_range(&unit.file, call.name_source);
                    self.occurrences.push(Occurrence {
                        source: range,
                        identity,
                        declaration: false,
                        write: false,
                    });
                    if let Some(definition) = self.definitions.get(&identity)
                        && let Some(signature) = &definition.signature
                        && let Some(target_unit) = self.units.get(&definition.source.source)
                        && let Some(target) = &target_unit.resolved
                    {
                        for label in call.argument_name_sources.iter().flatten() {
                            let Some(name) = unit.file.slice(label.range) else {
                                continue;
                            };
                            if !signature
                                .parameters
                                .iter()
                                .any(|parameter| parameter.name == name && parameter.named)
                            {
                                continue;
                            }
                            if let Some(range) =
                                target.parameter_name_source(&definition.name, name)
                                && let Some(binding) = target
                                    .bindings()
                                    .find(|binding| binding.source == Some(range))
                            {
                                self.occurrences.push(Occurrence {
                                    source: *label,
                                    identity: EditorIdentity::Binding(
                                        definition.source.source,
                                        binding.id,
                                    ),
                                    declaration: false,
                                    write: false,
                                });
                            }
                        }
                    }
                }
            }
            for ty in resolved.types() {
                let identity = match ty.target {
                    ResolvedTypeTarget::ExternalType | ResolvedTypeTarget::ExternalStruct => {
                        self.imported_identity(unit, &ty.name)
                    }
                    ResolvedTypeTarget::Struct(id) | ResolvedTypeTarget::Enum(id) => {
                        Some(EditorIdentity::Symbol(*source, id))
                    }
                    _ => None,
                };
                if let Some(identity) = identity {
                    self.occurrences.push(Occurrence {
                        source: terminal_name_range(&unit.file, ty.source),
                        identity,
                        declaration: false,
                        write: false,
                    });
                }
            }
        }
        self.occurrences
            .sort_by_key(|occurrence| (occurrence.source, occurrence.identity));
        merge_duplicate_occurrences(&mut self.occurrences);
    }
    fn shared_identity(&self, unit: &EditorUnit, name: &str) -> Option<EditorIdentity> {
        self.units
            .values()
            .filter(|candidate| candidate.owner == unit.owner)
            .find_map(|candidate| {
                candidate
                    .resolved
                    .as_ref()?
                    .symbols()
                    .find(|symbol| symbol.name == name)
                    .map(|symbol| EditorIdentity::Symbol(candidate.file.id(), symbol.id))
            })
    }
    fn imported_identity(&self, unit: &EditorUnit, path: &str) -> Option<EditorIdentity> {
        let Some((alias, name)) = path.split_once("::") else {
            return self.shared_identity(unit, path);
        };
        if name.contains("::") {
            return None;
        }
        let owner = unit.local_imports.get(alias);
        let package = unit
            .imports
            .iter()
            .find(|import| import.alias == alias)
            .map(|import| import.package.as_str());
        let mut found = self
            .units
            .values()
            .filter(|candidate| {
                (owner.is_some_and(|owner| candidate.owner == *owner)
                    || package.is_some_and(|package| {
                        candidate.package.as_deref() == Some(package)
                            && candidate.manifest_exports.contains(name)
                    }))
                    && candidate.exports.contains(name)
            })
            .filter_map(|candidate| {
                candidate
                    .resolved
                    .as_ref()?
                    .symbols()
                    .find(|symbol| symbol.name == name)
                    .map(|symbol| EditorIdentity::Symbol(candidate.file.id(), symbol.id))
            });
        let identity = found.next()?;
        found.next().is_none().then_some(identity)
    }
    fn error_message(&self, unit: &EditorUnit, path: &str) -> Option<String> {
        let (namespace, variant) = path.rsplit_once("::")?;
        let identity = self.imported_identity(unit, namespace)?;
        let definition = self.definitions.get(&identity)?;
        self.units
            .get(&definition.source.source)?
            .error_messages
            .get(&(definition.name.clone(), variant.to_owned()))
            .cloned()
    }
    /// All immutable source files in this snapshot.
    pub fn sources(&self) -> impl Iterator<Item = &SourceFile> {
        self.units.values().map(|unit| &unit.file)
    }
    /// Exact file by source identity.
    pub fn source(&self, id: SourceId) -> Option<&SourceFile> {
        self.units.get(&id).map(|unit| &unit.file)
    }
    /// Return declaration-site callable signatures for source documentation.
    /// Modes come from resolved compiler interfaces, including locked imports;
    /// public JSON record schemas intentionally do not encode those modes.
    pub fn declaration_signatures(&self, source: SourceId) -> Vec<EditorSignature> {
        let mut signatures = self
            .units
            .get(&source)
            .map(|unit| {
                unit.signatures
                    .iter()
                    .map(|(name, signature)| unit_source_signature(unit, name, signature))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        signatures.sort_by(|left, right| left.name.cmp(&right.name));
        signatures
    }
    /// Callable declarations of the enclosing contract or module, including its fragments.
    /// Imported modules retain separate owners and do not contribute declarations here.
    pub fn unit_declaration_signatures(&self, source: SourceId) -> Vec<EditorSignature> {
        let Some(unit) = self.units.get(&source) else {
            return Vec::new();
        };
        let mut signatures = self
            .units
            .values()
            .filter(|candidate| candidate.owner == unit.owner)
            .flat_map(|candidate| {
                candidate
                    .signatures
                    .iter()
                    .map(|(name, signature)| unit_source_signature(candidate, name, signature))
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.name.cmp(&right.name));
        signatures
    }
    /// Whether every source has complete, successful semantic analysis.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    /// Resolve the smallest exact identifier under a cursor.
    pub fn definition(&self, source: SourceId, offset: u32) -> Option<&EditorDefinition> {
        let occurrence = self
            .occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.source.source == source && contains(occurrence.source.range, offset)
            })
            .min_by_key(|occurrence| occurrence.source.range.end - occurrence.source.range.start)?;
        self.definitions.get(&occurrence.identity)
    }
    /// Canonical hover text from a resolved declaration, call, or typed expression.
    pub fn hover(&self, source: SourceId, offset: u32) -> Option<(String, String)> {
        let unit = self.units.get(&source)?;
        if let Some(resolved) = &unit.resolved {
            for node in resolved.arena().nodes() {
                if matches!(
                    node.target,
                    Some(ResolvedTarget::Value(
                        ResolvedValueTarget::VariantCode(_) | ResolvedValueTarget::ImportedVariant
                    ))
                ) && let Some(range) = node.source
                    && contains(range.range, offset)
                    && let Some((path, _)) = source_path_at(unit, range)
                    && let Some(message) = self.error_message(unit, &path)
                {
                    return Some((path, message));
                }
            }
        }
        if let Some(definition) = self.definition(source, offset) {
            if let Some(signature) = &definition.signature {
                return Some((
                    signature.declaration.clone(),
                    signature.documentation.clone(),
                ));
            }
            if let EditorIdentity::Binding(..) = definition.identity {
                let ty = unit
                    .typed_nodes
                    .iter()
                    .filter(|node| {
                        node.source
                            .is_some_and(|source| contains(source.range, offset))
                    })
                    .min_by_key(|node| {
                        node.source
                            .map_or(u32::MAX, |source| source.range.end - source.range.start)
                    })
                    .map(|node| render_type_name(&node.ty))
                    .or_else(|| {
                        (definition.detail != UNTYPED_BINDING_DETAIL)
                            .then(|| definition.detail.clone())
                    })
                    .or_else(|| {
                        self.units
                            .get(&definition.source.source)
                            .and_then(|owner| declared_binding_type(owner, definition.source.range))
                    });
                return Some((
                    ty.map_or_else(
                        || definition.name.clone(),
                        |ty| format!("{ty} {}", definition.name),
                    ),
                    String::new(),
                ));
            }
            return Some((
                definition.detail.clone(),
                [
                    definition.documentation.clone(),
                    symbol_documentation(&definition.detail),
                ]
                .into_iter()
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("\n\n"),
            ));
        }
        if let Some(token) = unit
            .tokens
            .iter()
            .find(|token| contains(token.range, offset))
            && context::is_keyword(&token.kind)
            && let Some(spelling) = unit.file.slice(token.range)
            && let Some(documentation) = context::keyword_documentation(spelling)
        {
            return Some((spelling.to_owned(), documentation));
        }
        if let Some(resolved) = &unit.resolved
            && let Some(call) = resolved
                .calls()
                .find(|call| contains(call.name_source.range, offset))
            && let Some(signature) =
                self.signature_for_name(unit, &call.name, call.name_source.range.end)
        {
            return Some((signature.declaration, signature.documentation));
        }
        unit.typed_nodes
            .iter()
            .filter(|node| {
                node.source
                    .is_some_and(|source| contains(source.range, offset))
            })
            .min_by_key(|node| {
                node.source
                    .map_or(u32::MAX, |source| source.range.end - source.range.start)
            })
            .map(|node| (render_type_name(&node.ty), String::new()))
    }
    /// Return every identity-bound source use, optionally including its declaration.
    pub fn references(
        &self,
        source: SourceId,
        offset: u32,
        declarations: bool,
    ) -> Vec<SourceRange> {
        let Some(definition) = self.definition(source, offset) else {
            return vec![];
        };
        self.occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.identity == definition.identity
                    && (declarations || !occurrence.declaration)
            })
            .map(|occurrence| occurrence.source)
            .collect()
    }
    /// Plan an atomic source/export rename for a complete graph and collision-free identifier.
    /// Frontends must authorize and bind every export edit to its exact owned manifest snapshot.
    pub fn rename(
        &self,
        source: SourceId,
        offset: u32,
        name: &str,
    ) -> Result<EditorRename, String> {
        if !self.complete {
            return Err(match &self.blocking {
                Some((label, message)) => {
                    format!("Rename is unavailable until {label} is fixed: {message}")
                }
                None => "Rename requires a complete, successfully checked source graph.".into(),
            });
        }
        let definition = self
            .definition(source, offset)
            .ok_or("No resolved declaration at this position.")?;
        if definition.kind == 9 {
            return Err("Source-unit names are part of package and contract identity; rename their manifest explicitly.".into());
        }
        if let Some(hook) =
            definition
                .signature
                .as_ref()
                .and_then(|signature| match signature.function_kind {
                    Some(crate::ast::FunctionKind::Hajimari) => {
                        crate::glossary::by_spelling("hajimari")
                    }
                    Some(crate::ast::FunctionKind::Kaizen) => {
                        crate::glossary::by_spelling("kaizen")
                    }
                    _ => None,
                })
        {
            return Err(format!(
                "Lifecycle hooks are named by their keyword (`{}`/`{}`) and cannot be renamed.",
                hook.romaji, hook.kanji
            ));
        }
        validate_rename_name(name)?;
        let exports = self
            .units
            .get(&definition.source.source)
            .filter(|unit| {
                matches!(definition.identity, EditorIdentity::Symbol(..))
                    && unit.manifest_exports.contains(&definition.name)
            })
            .and_then(|unit| unit.package.as_ref())
            .map(|package| EditorExportRename {
                package: package.clone(),
                old_name: definition.name.clone(),
                new_name: name.into(),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let ranges = self.references(source, offset, true);
        let mut rewritten = BTreeMap::new();
        for (id, unit) in &self.units {
            let mut text = unit.file.text().to_owned();
            let mut edits = ranges
                .iter()
                .filter(|range| range.source == *id)
                .collect::<Vec<_>>();
            edits.sort_by_key(|range| std::cmp::Reverse(range.range.start));
            for range in edits {
                text.replace_range(range.range.start as usize..range.range.end as usize, name);
            }
            rewritten.insert(*id, text);
        }
        let rewritten_tests = self
            .test_modules
            .iter()
            .map(|(id, module)| crate::linker::SourceModuleUnit {
                source_name: module.source_name.clone(),
                source: rewritten
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| module.source.clone()),
            })
            .collect::<Vec<_>>();
        let checked = if let Some(request) = &self.project_request {
            let mut request = request.clone();
            for export in &exports {
                let package = request
                    .packages
                    .iter_mut()
                    .find(|package| package.identity == export.package)
                    .ok_or("Rename export package is unavailable.")?;
                if export.old_name != export.new_name && package.exports.contains(&export.new_name)
                {
                    return Err(format!(
                        "`{name}` is already exported by `{}`.",
                        export.package
                    ));
                }
                if !package.exports.remove(&export.old_name) {
                    return Err("Rename export no longer matches its checked graph.".into());
                }
                package.exports.insert(export.new_name.clone());
            }
            for (id, unit) in &self.units {
                let replacement = rewritten.get(id).expect("rewritten source");
                if self.test_modules.iter().any(|(test, _)| test == id) {
                    continue;
                }
                if let Some(package) = &unit.package {
                    for module in request
                        .packages
                        .iter_mut()
                        .filter(|candidate| &candidate.identity == package)
                        .flat_map(|package| package.modules.iter_mut().chain(&mut package.sources))
                    {
                        if module.source_name == unit.file.name() {
                            module.source.clone_from(replacement);
                        }
                    }
                } else if request.root.source_name == unit.file.name() {
                    request.root.source.clone_from(replacement);
                } else if let Some(file) = request
                    .sources
                    .iter_mut()
                    .find(|file| file.source_name == unit.file.name())
                {
                    file.source.clone_from(replacement);
                }
            }
            Self::project_with_tests(&request, &rewritten_tests, self.zk_enabled)
        } else if let Some(request) = &self.package_request {
            let mut request = request.clone();
            for export in &exports {
                let package = std::iter::once(&mut request.package)
                    .chain(&mut request.dependencies)
                    .find(|package| package.identity == export.package)
                    .ok_or("Rename export package is unavailable.")?;
                if export.old_name != export.new_name && package.exports.contains(&export.new_name)
                {
                    return Err(format!(
                        "`{name}` is already exported by `{}`.",
                        export.package
                    ));
                }
                if !package.exports.remove(&export.old_name) {
                    return Err("Rename export no longer matches its checked graph.".into());
                }
                package.exports.insert(export.new_name.clone());
            }
            for package in std::iter::once(&mut request.package).chain(&mut request.dependencies) {
                for (id, unit) in self
                    .units
                    .iter()
                    .filter(|(_, unit)| unit.package.as_ref() == Some(&package.identity))
                {
                    if let Some(file) = package
                        .modules
                        .iter_mut()
                        .chain(&mut package.sources)
                        .find(|file| file.source_name == unit.file.name())
                    {
                        file.source
                            .clone_from(rewritten.get(id).expect("rewritten source"));
                    }
                }
            }
            Self::package(&request, self.zk_enabled)
        } else {
            let (id, unit) = self
                .units
                .first_key_value()
                .ok_or("Rename source is unavailable.")?;
            Self::single_with_tests(
                unit.file.name(),
                &rewritten[id],
                &rewritten_tests,
                self.zk_enabled,
            )
        };
        if !checked.is_complete() {
            return Err(match &checked.blocking {
                Some((label, message)) => format!(
                    "Renaming to `{name}` would not check: {label}: {message}"
                ),
                None => "The proposed source rename does not pass semantic checks; update the associated syntax or metadata explicitly.".into(),
            });
        }
        // A graph can still type-check after accidental capture or shadowing. Preserve every
        // resolver identity after translating offsets through exactly the proposed edits.
        // This permits unrelated declarations in disjoint scopes without accepting rebinding.
        let mut deltas = BTreeMap::<SourceId, Vec<(u32, i64)>>::new();
        for range in &ranges {
            deltas.entry(range.source).or_default().push((
                range.range.end,
                name.len() as i64 - i64::from(range.range.end - range.range.start),
            ));
        }
        for edits in deltas.values_mut() {
            edits.sort_unstable_by_key(|(end, _)| *end);
            let mut cumulative = 0_i64;
            for (_, delta) in edits {
                cumulative = cumulative
                    .checked_add(*delta)
                    .ok_or("Rename offset overflow.")?;
                *delta = cumulative;
            }
        }
        let checked_occurrences = checked
            .occurrences
            .iter()
            .map(|occurrence| {
                (
                    occurrence.source.source,
                    occurrence.source.range.start,
                    occurrence.source.range.end,
                    occurrence.identity,
                    occurrence.declaration,
                )
            })
            .collect::<BTreeSet<_>>();
        for occurrence in &self.occurrences {
            let shift = |offset: u32| -> Option<u32> {
                let delta = deltas.get(&occurrence.source.source).map_or(0, |edits| {
                    let count = edits.partition_point(|(end, _)| *end <= offset);
                    count.checked_sub(1).map_or(0, |index| edits[index].1)
                });
                u32::try_from(i64::from(offset).checked_add(delta)?).ok()
            };
            let start = shift(occurrence.source.range.start).ok_or("Rename offset overflow.")?;
            let end = shift(occurrence.source.range.end).ok_or("Rename offset overflow.")?;
            if !checked_occurrences.contains(&(
                occurrence.source.source,
                start,
                end,
                occurrence.identity,
                occurrence.declaration,
            )) {
                return Err(
                    "Rename would capture, shadow, or redirect a resolved reference.".into(),
                );
            }
        }
        Ok(EditorRename {
            sources: ranges,
            exports,
        })
    }
    /// Determine the enclosing callable and active source-order argument.
    pub fn signature_help(
        &self,
        source: SourceId,
        offset: u32,
    ) -> Option<(EditorSignature, usize)> {
        let unit = self.units.get(&source)?;
        let (name, opening, active) = call_context(&unit.tokens, offset)?;
        let signature = self.signature_for_name(unit, &name, opening)?;
        let (_, label, _) = argument_context(&unit.tokens, opening, offset);
        let active = label
            .and_then(|label| {
                signature
                    .parameters
                    .iter()
                    .position(|parameter| parameter.name == label)
            })
            .unwrap_or(active);
        Some((signature, active))
    }
    fn signature_for_name(
        &self,
        unit: &EditorUnit,
        name: &str,
        offset: u32,
    ) -> Option<EditorSignature> {
        if let Some((alias, "at")) = name.split_once("::")
            && let Some(Type::ContractRef(contract)) = unit.contract_types.get(alias)
        {
            return Some(editor_signature(
                name,
                vec![("address", "bytes".into(), true)],
                alias.to_owned(),
                &format!(
                    "Bind the authenticated {} interface to a contract address.",
                    contract.interface.seiyaku_name
                ),
            ));
        }
        if let Some(receiver) = receiver_before(&unit.tokens, offset)
            && let Some(ty) = self.type_at(unit, receiver)
        {
            return self
                .receiver_signatures(unit, ty)
                .into_iter()
                .find(|signature| signature.name == name);
        }
        if let Some(signature) = intrinsic_signatures()
            .into_iter()
            .find(|signature| signature.name == name)
        {
            return Some(signature);
        }
        if let Some(builtin) = Builtin::from_source_name(name) {
            return Some(builtin_signature(builtin, false));
        }
        if let Some(identity) = self.imported_identity(unit, name) {
            let mut signature = self.definitions.get(&identity)?.signature.clone()?;
            signature.name = name.to_owned();
            return Some(signature);
        }
        self.definitions
            .values()
            .find(|definition| {
                definition.source.source == unit.file.id()
                    && definition.name == name
                    && definition.signature.is_some()
            })
            .and_then(|definition| definition.signature.clone())
            .or_else(|| {
                let receiver = receiver_before(&unit.tokens, offset)?;
                let ty = self.type_at(unit, receiver)?;
                member_signatures(ty)
                    .into_iter()
                    .find(|signature| signature.name == name)
            })
    }
    fn receiver_signatures(&self, unit: &EditorUnit, ty: &Type) -> Vec<EditorSignature> {
        let mut signatures = member_signatures(ty)
            .into_iter()
            .map(|signature| (signature.name.clone(), signature))
            .collect::<BTreeMap<_, _>>();
        // Contract members always come from the authenticated imported interface.
        if !matches!(ty, Type::ContractRef(_)) {
            for owner in self
                .units
                .values()
                .filter(|candidate| candidate.owner == unit.owner)
            {
                for (name, signature) in &owner.signatures {
                    if signature.modifiers.kind == FunctionKind::Private
                        && let Some(receiver) = signature.params.first()
                        && crate::semantic::user_receiver_accepts(&receiver.ty, ty)
                    {
                        let mut method = signature.clone();
                        method.params.remove(0);
                        signatures
                            .insert(name.clone(), unit_source_signature(owner, name, &method));
                    }
                }
            }
        }
        signatures.into_values().collect()
    }
    fn type_at<'a>(&'a self, unit: &'a EditorUnit, range: TextRange) -> Option<&'a Type> {
        unit.typed_nodes
            .iter()
            // The token before `.` may end a call, parenthesized expression, or
            // field access. Select the innermost complete typed receiver ending
            // there, rather than treating only an identifier as a receiver.
            .filter(|node| {
                node.source.is_some_and(|source| {
                    source.range.end == range.end && source.range.start <= range.start
                })
            })
            .max_by_key(|node| node.source.map(|source| source.range.start))
            .map(|node| &node.ty)
            .or_else(|| {
                let definition = self.definition(unit.file.id(), range.start)?;
                let EditorIdentity::Binding(_, binding) = definition.identity else {
                    return None;
                };
                unit.binding_types.get(&binding)
            })
    }
    /// Contextual completion using lexical bindings, locked exports, receiver types, and call labels.
    pub fn completions(&self, source: SourceId, offset: u32) -> Vec<EditorCompletion> {
        self.completions_inner(source, offset, true)
    }
    fn completions_inner(
        &self,
        source: SourceId,
        offset: u32,
        recover: bool,
    ) -> Vec<EditorCompletion> {
        let Some(unit) = self.units.get(&source) else {
            return vec![];
        };
        if let Some(candidates) = self.selector_completions(unit, offset) {
            return candidates;
        }
        // `.` triggers completion, so a sentence in a comment or a string must not open a list.
        if inside_comment_or_literal(&unit.file, offset) {
            return Vec::new();
        }
        if recover && unit.resolved.is_none() {
            for repaired in repair::completion_repairs(&unit.file, &unit.tokens, offset) {
                let recovery = self.with_replaced_source(unit, repaired);
                if recovery
                    .units
                    .get(&source)
                    .is_none_or(|candidate| candidate.resolved.is_none())
                {
                    continue;
                }
                let candidates = recovery.completions_inner(source, offset, false);
                if !candidates.is_empty() {
                    return candidates;
                }
            }
        }
        if let Some(receiver) = receiver_before(&unit.tokens, offset) {
            return self
                .type_at(unit, receiver)
                .map(|ty| {
                    let mut candidates = self
                        .receiver_signatures(unit, ty)
                        .into_iter()
                        .map(signature_completion)
                        .collect::<Vec<_>>();
                    if let Type::Struct { fields, .. } = ty {
                        candidates.extend(
                            fields
                                .iter()
                                .map(|(name, ty)| plain_completion(name, 5, &render_type_name(ty))),
                        );
                    }
                    candidates
                })
                .unwrap_or_default();
        }
        // Only members follow `.`; a literal or keyword before it has none to offer.
        if after_member_dot(&unit.tokens, offset) {
            return Vec::new();
        }
        let prefix = path_prefix(&unit.tokens, offset);
        if let Some((namespace, _)) = prefix.rsplit_once("::") {
            let alias = namespace.split("::").next().unwrap_or(namespace);
            let mut candidates = Vec::new();
            if unit.contract_types.contains_key(alias) {
                if let Some(ty) = unit.contract_types.get(namespace) {
                    let variants = match ty {
                        Type::Enum(descriptor) => descriptor
                            .variants
                            .iter()
                            .map(|variant| (&variant.name, variant.code))
                            .collect::<Vec<_>>(),
                        Type::ErrorEnum(descriptor) => descriptor
                            .variants
                            .iter()
                            .map(|variant| (&variant.name, variant.code))
                            .collect::<Vec<_>>(),
                        Type::ContractRef(_) => {
                            let mut signature = self
                                .signature_for_name(unit, &format!("{alias}::at"), offset)
                                .expect("contract namespace constructor");
                            signature.name = "at".into();
                            candidates.push(signature_completion(signature));
                            Vec::new()
                        }
                        _ => Vec::new(),
                    };
                    candidates.extend(variants.into_iter().map(|(name, code)| {
                        plain_completion(name, 20, &format!("{namespace}::{name} = {code}"))
                    }));
                }
                let prefix = format!("{namespace}::");
                let mut seen = BTreeSet::new();
                for (path, ty) in &unit.contract_types {
                    if let Some(suffix) = path.strip_prefix(&prefix) {
                        let label = suffix
                            .split("::")
                            .next()
                            .expect("nonempty imported type suffix");
                        if seen.insert(label) {
                            candidates.push(plain_completion(
                                label,
                                if suffix.contains("::") { 9 } else { 22 },
                                &render_type_name(ty),
                            ));
                        }
                    }
                }
                return candidates;
            }
            if unit.local_imports.contains_key(alias)
                || unit.imports.iter().any(|import| import.alias == alias)
            {
                if namespace != alias {
                    if let Some(identity) = self.imported_identity(unit, namespace)
                        && let Some(definition) = self.definitions.get(&identity)
                        && definition.kind == 13
                        && let Some(descriptor) = self
                            .units
                            .get(&definition.source.source)
                            .and_then(|owner| owner.resolved.as_ref())
                            .and_then(|resolved| {
                                resolved.program().items.iter().find_map(|item| {
                                    if let crate::ast::Item::Enum(error) = item {
                                        (error.name == definition.name).then_some(error)
                                    } else {
                                        None
                                    }
                                })
                            })
                    {
                        for variant in &descriptor.variants {
                            let mut completion = plain_completion(
                                &variant.name,
                                20,
                                &format!("{namespace}::{} = {}", variant.name, variant.code),
                            );
                            completion.documentation = self
                                .error_message(unit, &format!("{namespace}::{}", variant.name))
                                .unwrap_or_default();
                            candidates.push(completion);
                        }
                    }
                    return candidates;
                }
                for definition in self.definitions.values().filter(|definition| {
                    self.units
                        .get(&definition.source.source)
                        .is_some_and(|candidate| {
                            (unit
                                .local_imports
                                .get(alias)
                                .is_some_and(|owner| candidate.owner == *owner)
                                || unit.imports.iter().any(|import| {
                                    import.alias == alias
                                        && candidate.package.as_deref()
                                            == Some(import.package.as_str())
                                        && candidate.manifest_exports.contains(&definition.name)
                                }))
                                && candidate.exports.contains(&definition.name)
                        })
                }) {
                    candidates.push(definition_completion(definition));
                }
                return candidates;
            }
            for path in kotodama_surface::source_policy::V1_SUM_PATHS
                .iter()
                .chain(kotodama_surface::source_policy::V1_ROUNDING_PATHS)
            {
                if let Some(suffix) = path.strip_prefix(&format!("{namespace}::")) {
                    candidates.push(plain_completion(suffix, 20, path));
                }
            }
            for descriptor in [
                ivm_abi::error_types::list_error_type(),
                ivm_abi::error_types::numeric_error_type(),
            ] {
                if descriptor.identity.rsplit("::").next() == Some(namespace) {
                    for variant in descriptor.variants {
                        candidates.push(plain_completion(
                            &variant.name,
                            20,
                            &format!("{namespace}::{} = {}", variant.name, variant.code),
                        ));
                    }
                }
            }
            for owner in self
                .units
                .values()
                .filter(|candidate| candidate.owner == unit.owner)
            {
                for declaration in owner.facts.declarations.iter().filter(|declaration| {
                    declaration.kind == DeclarationKind::Enum && declaration.name == namespace
                }) {
                    if let Some(node) = owner.facts.source_map.node(declaration.node)
                        && let Some(source) = owner.file.slice(node.range)
                        && let Ok(program) =
                            crate::parser::parse(&format!("module Editor {{ {source} }}"))
                    {
                        for item in program.items {
                            if let crate::ast::Item::Enum(error) = item {
                                for variant in error.variants {
                                    let mut completion = plain_completion(
                                        &variant.name,
                                        20,
                                        &format!(
                                            "{namespace}::{} = {}",
                                            variant.name, variant.code
                                        ),
                                    );
                                    completion.documentation = variant.message.unwrap_or_default();
                                    candidates.push(completion);
                                }
                            }
                        }
                    }
                }
            }
            for mut signature in intrinsic_signatures() {
                if let Some(suffix) = signature.name.strip_prefix(&format!("{namespace}::")) {
                    signature.name = suffix.to_owned();
                    candidates.push(signature_completion(signature));
                }
            }
            for (builtin, spec) in Builtin::registry() {
                if builtin_visible(unit, builtin, offset, self.zk_enabled)
                    && spec.surface != BuiltinSurface::CompilerInternal
                    && spec.name.starts_with(&format!("{namespace}::"))
                {
                    let mut signature = builtin_signature(builtin, false);
                    signature.name = spec.name[namespace.len() + 2..].to_owned();
                    candidates.push(signature_completion(signature));
                }
            }
            return candidates;
        }
        if let Some((signature, _)) = self.signature_help(source, offset)
            && let Some((_, opening, _)) = call_context(&unit.tokens, offset)
            && argument_context(&unit.tokens, opening, offset).1.is_none()
        {
            let (_, opening, _) = call_context(&unit.tokens, offset).expect("signature context");
            let (_, _, existing) = argument_context(&unit.tokens, opening, offset);
            let labels = signature
                .parameters
                .iter()
                .filter(|parameter| parameter.named && !existing.contains(parameter.name.as_str()))
                .map(|parameter| EditorCompletion {
                    label: format!("{}:", parameter.name),
                    kind: 5,
                    detail: parameter.ty.clone(),
                    insert_text: format!("{}: ${{1:{}}}", parameter.name, parameter.name),
                    snippet: true,
                    documentation: String::new(),
                    filter_text: None,
                    sort_text: None,
                })
                .collect::<Vec<_>>();
            if !labels.is_empty() {
                return labels;
            }
        }
        let site = context::completion_site(&unit.tokens, offset);
        match site {
            context::CompletionSite::TopLevel {
                fragment,
                unit_start,
            } => {
                // A source-unit header must be the first significant token of its file.
                let mut items = if unit_start {
                    context::source_unit_items()
                } else {
                    Vec::new()
                };
                if fragment {
                    items.extend(context::item_start_items(context::UnitKind::Fragment));
                }
                return items;
            }
            context::CompletionSite::ItemStart(kind) => return context::item_start_items(kind),
            context::CompletionSite::Type => return self.type_completions(unit),
            context::CompletionSite::Event => {
                return self
                    .units
                    .values()
                    .filter(|candidate| candidate.owner == unit.owner)
                    .flat_map(|candidate| candidate.facts.declarations.iter())
                    .filter(|declaration| declaration.kind == DeclarationKind::Event)
                    .map(|declaration| {
                        plain_completion(&declaration.name, 23, "Declared native event")
                    })
                    .collect();
            }
            context::CompletionSite::Authorization => {
                let mut items = vec![plain_completion(
                    "anyone",
                    14,
                    "Explicitly allow every caller",
                )];
                for candidate in self
                    .units
                    .values()
                    .filter(|candidate| candidate.owner == unit.owner)
                {
                    for declaration in candidate
                        .facts
                        .declarations
                        .iter()
                        .filter(|declaration| declaration.kind == DeclarationKind::Permission)
                    {
                        items.push(plain_completion(
                            &declaration.name,
                            14,
                            "Declared caller permission",
                        ));
                    }
                }
                return items;
            }
            context::CompletionSite::Nothing => return Vec::new(),
            context::CompletionSite::Statement | context::CompletionSite::Expression => {}
            _ => return context::modifier_items(site),
        }
        let mut candidates = BTreeMap::new();
        for definition in self
            .definitions
            .values()
            .filter(|definition| match definition.identity {
                EditorIdentity::Symbol(..) => self
                    .units
                    .get(&definition.source.source)
                    .is_some_and(|candidate| candidate.owner == unit.owner),
                EditorIdentity::Binding(..) => definition.source.source == source,
            })
        {
            // Source units and triggers are not values, and runtime functions (kotoage, view
            // and lifecycle hooks) cannot be called from source.
            let callable = definition.signature.as_ref().is_none_or(|signature| {
                signature.function_kind == Some(crate::ast::FunctionKind::Private)
            });
            let visible = match definition.identity {
                EditorIdentity::Symbol(..) => {
                    definition.kind != 9
                        && definition.kind != 14
                        && definition.kind != 23
                        && callable
                }
                EditorIdentity::Binding(_, binding) => visible_binding(unit, binding, offset),
            };
            if visible {
                candidates.insert(
                    (definition.name.clone(), definition.kind),
                    definition_completion(definition),
                );
            }
        }
        // Only parser-owned declarations are available after syntax failure. They are candidates,
        // never promoted into resolved identities or used by rename/navigation.
        if unit.resolved.is_none() {
            for declaration in &unit.facts.declarations {
                let kind = match declaration.kind {
                    DeclarationKind::Function => 3,
                    DeclarationKind::Struct => 22,
                    DeclarationKind::Event => continue,
                    DeclarationKind::Enum => 13,
                    DeclarationKind::SourceUnit
                    | DeclarationKind::Trigger
                    | DeclarationKind::Permission => continue,
                    _ => 6,
                };
                if crate::glossary::by_spelling(&declaration.name).is_some()
                    || candidates.keys().any(|(name, _)| name == &declaration.name)
                {
                    continue;
                }
                if declaration.kind != DeclarationKind::Parameter
                    || declaration.owner.is_some_and(|owner| {
                        unit.facts
                            .source_map
                            .node(owner)
                            .is_some_and(|node| contains_open(node.range, offset))
                    })
                {
                    candidates.insert(
                        (declaration.name.clone(), kind),
                        plain_completion(
                            &declaration.name,
                            kind,
                            "declaration (incomplete source)",
                        ),
                    );
                }
            }
        }
        let mut items = candidates.into_values().collect::<Vec<_>>();
        let keywords = if site == context::CompletionSite::Statement {
            context::STATEMENT_KEYWORDS
                .iter()
                .chain(context::EXPRESSION_KEYWORDS)
                .collect::<BTreeSet<_>>()
        } else {
            context::EXPRESSION_KEYWORDS.iter().collect()
        };
        items.extend(
            keywords
                .into_iter()
                .map(|keyword| context::plain_keyword(keyword)),
        );
        items.extend(
            kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES
                .iter()
                .map(|name| plain_completion(name, 7, "Kotodama type")),
        );
        items.extend(intrinsic_signatures().into_iter().map(signature_completion));
        for (builtin, spec) in Builtin::registry() {
            if builtin_visible(unit, builtin, offset, self.zk_enabled)
                && matches!(
                    spec.surface,
                    BuiltinSurface::Function | BuiltinSurface::FunctionOrMethod
                )
            {
                items.push(signature_completion(builtin_signature(builtin, false)));
            }
        }
        items
    }
    /// Types valid at a type position: canonical source types and the unit's own nominal types.
    fn type_completions(&self, unit: &EditorUnit) -> Vec<EditorCompletion> {
        let mut items = kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES
            .iter()
            .map(|name| plain_completion(name, 7, "Kotodama type"))
            .collect::<Vec<_>>();
        items.extend(
            self.definitions
                .values()
                .filter(|definition| {
                    matches!(definition.identity, EditorIdentity::Symbol(..))
                        && matches!(definition.kind, 13 | 22)
                        && self
                            .units
                            .get(&definition.source.source)
                            .is_some_and(|candidate| candidate.owner == unit.owner)
                })
                .map(definition_completion),
        );
        items
    }
}
/// Whether the identifier at `index` starts the place of an assignment statement
/// (`value = ...`, `record.field += ...`, `Balances[key] = ...`).
fn is_assignment_place(tokens: &[Token], index: usize) -> bool {
    if index
        .checked_sub(1)
        .and_then(|previous| tokens.get(previous))
        .is_some_and(|token| {
            !matches!(
                token.kind,
                TokenKind::Semicolon | TokenKind::LBrace | TokenKind::RBrace
            )
        })
    {
        return false;
    }
    let mut cursor = index + 1;
    let mut depth = 0_usize;
    while let Some(token) = tokens.get(cursor) {
        match token.kind {
            TokenKind::LBracket => depth += 1,
            TokenKind::RBracket => depth = depth.saturating_sub(1),
            TokenKind::Equal
            | TokenKind::PlusEqual
            | TokenKind::MinusEqual
            | TokenKind::StarEqual
            | TokenKind::SlashEqual
            | TokenKind::PercentEqual
                if depth == 0 =>
            {
                return true;
            }
            TokenKind::Dot | TokenKind::Ident(_) | TokenKind::Number(_) => {}
            _ if depth > 0 => {}
            _ => return false,
        }
        cursor += 1;
    }
    false
}
/// Merge occurrences of one identity at one range; a use that is also written stays a write.
/// Callers sort by `(source, identity)` first.
fn merge_duplicate_occurrences(occurrences: &mut Vec<Occurrence>) {
    occurrences.dedup_by(|later, earlier| {
        if (later.source, later.identity) == (earlier.source, earlier.identity) {
            earlier.write |= later.write;
            earlier.declaration |= later.declaration;
            true
        } else {
            false
        }
    });
}
/// Explain why `name` cannot be a rename target, naming the keyword (in both spellings for a
/// branded keyword), the ASCII identifier rule or the reserved source surface.
fn validate_rename_name(name: &str) -> Result<(), String> {
    if let Some(keyword) = crate::glossary::by_spelling(name) {
        return Err(format!(
            "`{name}` is the Kotodama keyword `{}`/`{}` and cannot name a declaration.",
            keyword.romaji, keyword.kanji
        ));
    }
    if crate::lexer::V1_KEYWORDS.contains(&name) {
        return Err(format!(
            "`{name}` is a Kotodama keyword and cannot name a declaration."
        ));
    }
    if !name.is_ascii() {
        return Err(format!(
            "`{name}` is not a valid name: Kotodama V1 identifiers are ASCII letters, digits and `_`."
        ));
    }
    let tokens = crate::lexer::lex(name)
        .map_err(|_| format!("`{name}` is not a single Kotodama identifier."))?;
    if !matches!(tokens.as_slice(), [Token { kind: TokenKind::Ident(value), .. }, Token { kind: TokenKind::EOF, .. }] if value == name)
    {
        return Err(format!("`{name}` is not a single Kotodama identifier."));
    }
    if kotodama_surface::source_policy::is_reserved_source_declaration(name, false) {
        return Err(format!(
            "`{name}` is reserved by the Kotodama V1 source surface; choose another name."
        ));
    }
    Ok(())
}
/// Code, location and message of the first diagnostic in a bundle.
fn blocking_summary(bundle: &crate::diagnostic::DiagnosticBundle) -> (String, String) {
    bundle.diagnostics.first().map_or_else(
        || ("an earlier diagnostic".to_owned(), String::new()),
        |diagnostic| {
            let location =
                diagnostic
                    .primary_span
                    .as_ref()
                    .map_or(String::new(), |span| match span.source.as_deref() {
                        Some(source) => format!(" at {source}:{}", span.start.line),
                        None => format!(" at line {}", span.start.line),
                    });
            (
                format!("{}{location}", diagnostic.code),
                diagnostic.message.clone(),
            )
        },
    )
}
/// Documentation for a declaration header, from its leading keyword. A branded keyword uses
/// the glossary wording in the spelling written at the declaration (`誓約 Counter` documents
/// 誓約 first); other declarations (`state`, `const`, `struct`, `error enum`, `trigger`,
/// `module`) use the keyword's own documentation.
fn symbol_documentation(header: &str) -> String {
    let Some(written) = header.split_whitespace().next() else {
        return String::new();
    };
    match crate::glossary::by_spelling(written) {
        Some(entry) => {
            let other = if written == entry.kanji {
                entry.romaji
            } else {
                entry.kanji
            };
            format!("**{written}** ({other}) \u{2014} {}.", entry.role)
        }
        None if matches!(
            written,
            "state" | "const" | "struct" | "enum" | "error" | "trigger" | "module"
        ) =>
        {
            context::keyword_documentation(written).unwrap_or_default()
        }
        None => String::new(),
    }
}
fn local_target(source: SourceId, target: ResolvedTarget) -> Option<EditorIdentity> {
    Some(match target {
        ResolvedTarget::Value(ResolvedValueTarget::Binding(id))
        | ResolvedTarget::Assignment(ResolvedValueTarget::Binding(id)) => {
            EditorIdentity::Binding(source, id)
        }
        ResolvedTarget::Value(ResolvedValueTarget::State(id) | ResolvedValueTarget::Const(id))
        | ResolvedTarget::Assignment(
            ResolvedValueTarget::State(id) | ResolvedValueTarget::Const(id),
        )
        | ResolvedTarget::Type(ResolvedTypeTarget::Struct(id) | ResolvedTypeTarget::Enum(id))
        | ResolvedTarget::StructLiteral(id) => EditorIdentity::Symbol(source, id),
        _ => return None,
    })
}
// The resolver authenticated this value as a nominal variant. Read only its exact
// source-backed path tokens; numeric codes alone cannot identify the declaring enum.
fn enum_namespace_source(unit: &EditorUnit, source: SourceRange) -> Option<(String, SourceRange)> {
    let start = unit
        .tokens
        .partition_point(|token| token.range.start < source.range.start);
    let end = unit
        .tokens
        .partition_point(|token| token.range.end <= source.range.end);
    let mut tokens = unit.tokens.get(start..end)?;
    while matches!(tokens.first()?.kind, TokenKind::LParen)
        && matches!(tokens.last()?.kind, TokenKind::RParen)
    {
        tokens = &tokens[1..tokens.len() - 1];
    }
    let (namespace, name) = match tokens {
        [first, separator, variant]
            if matches!(separator.kind, TokenKind::ColonColon)
                && matches!(variant.kind, TokenKind::Ident(_)) =>
        {
            let TokenKind::Ident(namespace) = &first.kind else {
                return None;
            };
            (namespace.clone(), first)
        }
        [alias, first_separator, name, second_separator, variant]
            if matches!(first_separator.kind, TokenKind::ColonColon)
                && matches!(second_separator.kind, TokenKind::ColonColon)
                && matches!(variant.kind, TokenKind::Ident(_)) =>
        {
            let (TokenKind::Ident(alias), TokenKind::Ident(namespace)) = (&alias.kind, &name.kind)
            else {
                return None;
            };
            (format!("{alias}::{namespace}"), name)
        }
        _ => return None,
    };
    Some((namespace, SourceRange::new(source.source, name.range)))
}
fn contains(range: TextRange, offset: u32) -> bool {
    range.start <= offset && offset < range.end
}
fn contains_open(range: TextRange, offset: u32) -> bool {
    range.start <= offset && (offset <= range.end || range.is_empty())
}
fn terminal_name_range(file: &SourceFile, source: SourceRange) -> SourceRange {
    let offset = file
        .slice(source.range)
        .and_then(|text| text.rfind("::"))
        .map_or(0, |offset| offset + 2);
    SourceRange::new(
        source.source,
        TextRange::new(source.range.start + offset as u32, source.range.end),
    )
}
fn visible_binding(unit: &EditorUnit, id: BindingId, offset: u32) -> bool {
    let Some(resolved) = &unit.resolved else {
        return false;
    };
    let arena = resolved.arena();
    let Some(binding) = arena.binding(id) else {
        return false;
    };
    if binding
        .source
        .is_some_and(|source| source.range.start > offset)
    {
        return false;
    }
    if let Some(owner) = binding
        .source_node
        .and_then(|node| unit.facts.source_map.node(node))
        .and_then(|node| node.owner)
        && unit
            .facts
            .source_map
            .node(owner)
            .is_some_and(|node| !contains_open(node.range, offset))
    {
        return false;
    }
    let scope_range = binding
        .source
        .and_then(|source| enclosing_brace(&unit.tokens, source.range.start));
    if let Some(range) = scope_range
        && !contains_open(range, offset)
    {
        return false;
    }
    let node = arena
        .nodes()
        .filter(|node| {
            node.source
                .is_some_and(|source| contains_open(source.range, offset))
        })
        .min_by_key(|node| {
            node.source
                .map_or(u32::MAX, |source| source.range.end - source.range.start)
        });
    if let Some(node) = node {
        return arena.binding_visible_at(id, node.id);
    }
    // Whitespace has no expression node. Bindings are still restricted to their parser-token
    // block and declaring function; exact-name use resolution remains solely the resolver's job.
    scope_range.is_some()
}
fn enclosing_brace(tokens: &[Token], offset: u32) -> Option<TextRange> {
    let mut stack = Vec::new();
    let mut ranges = Vec::new();
    for token in tokens {
        match token.kind {
            TokenKind::LBrace => stack.push(token.range.start),
            TokenKind::RBrace => {
                if let Some(start) = stack.pop() {
                    ranges.push(TextRange::new(start, token.range.end));
                }
            }
            _ => {}
        }
    }
    let end = tokens.last().map_or(offset, |token| token.range.end);
    ranges.extend(stack.into_iter().map(|start| TextRange::new(start, end)));
    ranges
        .into_iter()
        .filter(|range| contains_open(*range, offset))
        .min_by_key(|range| range.end - range.start)
}
fn source_signature(
    name: &str,
    signature: &FunctionSignature,
    keyword: Option<&str>,
    authored: &str,
) -> EditorSignature {
    let parameters = signature
        .params
        .iter()
        .map(|parameter| EditorParameter {
            name: parameter.name.clone(),
            ty: render_type_name(&parameter.ty),
            named: parameter.call_mode == ParameterCallMode::Named,
        })
        .collect::<Vec<_>>();
    let return_type = render_type_name(&signature.return_type);
    let rendered = parameters
        .iter()
        .map(|parameter| crate::signature_render::RenderParameter {
            name: &parameter.name,
            ty: &parameter.ty,
            named: parameter.named,
        })
        .collect::<Vec<_>>();
    let declaration = crate::signature_render::SourceDeclaration {
        kind: signature.modifiers.kind,
        documentation: Some(authored),
        keyword,
        name,
        parameters: &rendered,
        return_type: &return_type,
        authorization: signature.modifiers.authorization.as_deref(),
        is_test: signature.modifiers.is_test,
        fixture: signature.modifiers.test_fixture.as_deref(),
    };
    let documentation = crate::signature_render::source_documentation(&declaration);
    let declaration = crate::signature_render::source_declaration(&declaration);
    EditorSignature {
        name: name.into(),
        parameters,
        return_type,
        documentation,
        authored_documentation: authored.to_owned(),
        declaration,
        function_kind: Some(signature.modifiers.kind),
    }
}
fn authored_documentation(unit: &EditorUnit, name: TextRange) -> &str {
    unit.facts
        .declarations
        .iter()
        .find(|declaration| {
            unit.facts
                .source_map
                .node(declaration.name_node)
                .is_some_and(|node| node.range == name)
        })
        .map(|declaration| declaration.documentation.as_str())
        .unwrap_or_default()
}
fn unit_source_signature(
    unit: &EditorUnit,
    name: &str,
    signature: &FunctionSignature,
) -> EditorSignature {
    let keyword = unit
        .resolved
        .as_ref()
        .and_then(|resolved| {
            resolved
                .symbols()
                .find(|symbol| symbol.name == name && symbol.kind == ResolvedSymbolKind::Function)
        })
        .and_then(|symbol| declaration_keyword(unit, symbol.source.range));
    let authored = unit
        .resolved
        .as_ref()
        .and_then(|resolved| {
            resolved
                .symbols()
                .find(|symbol| symbol.name == name && symbol.kind == ResolvedSymbolKind::Function)
        })
        .map(|symbol| authored_documentation(unit, symbol.source.range))
        .unwrap_or_default();
    source_signature(name, signature, keyword.as_deref(), authored)
}
/// Keyword spelling written at a function or lifecycle declaration whose name occupies
/// `name`: `言挙げ`/`kotoage`/`view` before `fn`, or the lifecycle keyword itself.
fn declaration_keyword(unit: &EditorUnit, name: TextRange) -> Option<String> {
    let index = unit
        .tokens
        .iter()
        .position(|token| token.range.start == name.start)?;
    let token = &unit.tokens[index];
    if matches!(token.kind, TokenKind::Hajimari | TokenKind::Kaizen) {
        return unit.file.slice(token.range).map(str::to_owned);
    }
    let fn_token = unit.tokens.get(index.checked_sub(1)?)?;
    let modifier = unit.tokens.get(index.checked_sub(2)?)?;
    (fn_token.kind == TokenKind::Fn
        && matches!(modifier.kind, TokenKind::Kotoage | TokenKind::View))
    .then(|| unit.file.slice(modifier.range).map(str::to_owned))
    .flatten()
}
/// Type written before a binding's declared name (`int _ value`, `let StateMap<int, int> m`),
/// used when a failed check left the binding untyped. Untyped bindings (`let x = ...`,
/// destructuring, loop variables) have none.
fn declared_binding_type(unit: &EditorUnit, name: TextRange) -> Option<String> {
    let index = unit.tokens.iter().position(|token| token.range == name)?;
    let mut end = index.checked_sub(1)?;
    // A positional parameter marker sits between the type and the name.
    if matches!(&unit.tokens[end].kind, TokenKind::Ident(marker) if marker == "_") {
        end = end.checked_sub(1)?;
    }
    // Walk back over `Head<Argument, ...>` (and `::` path segments) to the type's head name.
    let mut start = end;
    let mut depth = 0_usize;
    loop {
        match &unit.tokens[start].kind {
            TokenKind::Greater => depth += 1,
            TokenKind::Less if depth > 0 => depth -= 1,
            TokenKind::Ident(_) if depth == 0 => {
                let path = start
                    .checked_sub(1)
                    .is_some_and(|previous| unit.tokens[previous].kind == TokenKind::ColonColon);
                if !path {
                    return render_token_range(unit, start, end);
                }
            }
            TokenKind::Ident(_) | TokenKind::ColonColon => {}
            TokenKind::Number(_) | TokenKind::Comma | TokenKind::LParen | TokenKind::RParen
                if depth > 0 => {}
            _ => return None,
        }
        start = start.checked_sub(1)?;
    }
}
/// Source text of tokens `first..=last` with runs of whitespace collapsed.
fn render_token_range(unit: &EditorUnit, first: usize, last: usize) -> Option<String> {
    let text = unit.file.slice(TextRange::new(
        unit.tokens.get(first)?.range.start,
        unit.tokens.get(last)?.range.end,
    ))?;
    Some(text.split_whitespace().collect::<Vec<_>>().join(" "))
}
/// Declaration header exactly as written, from the item start up to its body or terminator,
/// with runs of whitespace collapsed: `state StateMap<int, int> Values`, `誓約 Counter`.
fn declaration_header(unit: &EditorUnit, name: TextRange) -> Option<String> {
    let index = unit
        .tokens
        .iter()
        .position(|token| token.range.start == name.start)?;
    let mut start = index;
    while start > 0
        && !matches!(
            unit.tokens[start - 1].kind,
            TokenKind::Semicolon | TokenKind::LBrace | TokenKind::RBrace | TokenKind::RBracket
        )
    {
        start -= 1;
    }
    let mut end = index;
    let mut depth = 0_usize;
    while let Some(token) = unit.tokens.get(end + 1) {
        match token.kind {
            TokenKind::LParen | TokenKind::LBracket => depth += 1,
            TokenKind::RParen | TokenKind::RBracket => depth = depth.saturating_sub(1),
            TokenKind::LBrace | TokenKind::Semicolon | TokenKind::EOF if depth == 0 => break,
            _ => {}
        }
        end += 1;
    }
    let text = unit.file.slice(TextRange::new(
        unit.tokens[start].range.start,
        unit.tokens[end].range.end,
    ))?;
    Some(text.split_whitespace().collect::<Vec<_>>().join(" "))
}
fn builtin_signature(builtin: Builtin, receiver: bool) -> EditorSignature {
    let signature = builtin.signature();
    let positional = match builtin.call_policy() {
        BuiltinCallPolicy::Named => 0,
        BuiltinCallPolicy::PositionalPrefix(count) => count,
    };
    let mut rendered = EditorSignature {
        authored_documentation: String::new(),
        name: if receiver {
            builtin.name()
        } else {
            builtin.source_name()
        }
        .into(),
        parameters: signature
            .parameter_names
            .iter()
            .zip(signature.parameters)
            .enumerate()
            .skip(usize::from(receiver))
            .map(|(index, (name, ty))| EditorParameter {
                name: (*name).into(),
                ty: (*ty).into(),
                named: index >= positional,
            })
            .collect(),
        return_type: signature.return_type.into(),
        documentation: crate::signature_render::builtin_documentation(builtin),
        declaration: String::new(),
        function_kind: None,
    };
    rendered.declaration = rendered.label();
    rendered
}
fn builtin_visible(unit: &EditorUnit, builtin: Builtin, offset: u32, zk: bool) -> bool {
    match builtin.mode() {
        BuiltinMode::Any => true,
        BuiltinMode::ZkOnly => zk,
        BuiltinMode::CompilerInternal => false,
        BuiltinMode::TestOnly | BuiltinMode::TestFunctionOnly => {
            unit.facts.declarations.iter().any(|declaration| {
                declaration.kind == DeclarationKind::Function
                    && unit
                        .signatures
                        .get(&declaration.name)
                        .is_some_and(|signature| signature.modifiers.is_test)
                    && unit
                        .facts
                        .source_map
                        .node(declaration.node)
                        .is_some_and(|node| contains_open(node.range, offset))
            })
        }
    }
}
fn editor_signature(
    name: &str,
    parameters: Vec<(&str, String, bool)>,
    return_type: String,
    documentation: &str,
) -> EditorSignature {
    let mut signature = EditorSignature {
        authored_documentation: String::new(),
        name: name.into(),
        parameters: parameters
            .into_iter()
            .map(|(name, ty, named)| EditorParameter {
                name: name.into(),
                ty,
                named,
            })
            .collect(),
        return_type,
        documentation: documentation.into(),
        declaration: String::new(),
        function_kind: None,
    };
    signature.declaration = signature.label();
    signature
}
fn intrinsic_signatures() -> Vec<EditorSignature> {
    let mut signatures = [
        ("decimal::from_int", "int", "decimal"),
        ("decimal::from_quantity", "quantity", "decimal"),
        ("decimal::to_int_exact", "decimal", "int"),
        ("decimal::to_int_trunc", "decimal", "int"),
        (
            "quantity::try_from_int",
            "int",
            "Result<quantity, NumericError>",
        ),
        (
            "quantity::try_from_decimal",
            "decimal",
            "Result<quantity, NumericError>",
        ),
    ]
    .into_iter()
    .map(|(name, input, output)| {
        editor_signature(
            name,
            vec![("value", input.into(), false)],
            output.into(),
            "Canonical numeric conversion; recoverable conversion returns NumericError.",
        )
    })
    .collect::<Vec<_>>();
    signatures.push(editor_signature(
        "decimal::to_int_round",
        vec![
            ("value", "decimal".into(), false),
            ("mode", "Rounding".into(), true),
        ],
        "int".into(),
        "Round once using the explicit Rounding mode.",
    ));
    signatures
}
fn member_signatures(ty: &Type) -> Vec<EditorSignature> {
    if let Type::ContractRef(contract) = ty {
        use iroha_data_model::smart_contract::manifest::EntryPointKind;
        return contract.interface.entrypoints.iter().filter_map(|entry| {
            let kind = match entry.kind {
                EntryPointKind::View => crate::ast::FunctionKind::View,
                EntryPointKind::Kotoage => crate::ast::FunctionKind::Kotoage,
                _ => return None,
            };
            let parameters = entry.argument_schema.as_ref()?.fields.iter().map(|field| {
                crate::semantic::contract_imports::schema_type(&field.ty).ok().map(|ty| {
                    (field.name.as_str(), render_type_name(&ty), true)
                })
            }).collect::<Option<Vec<_>>>()?;
            let result = crate::semantic::contract_imports::schema_type(entry.return_schema.as_ref()?).ok()?;
            let mut signature = editor_signature(&entry.name, parameters, render_type_name(&result),
                "Public method from the authenticated imported artifact. Argument names and nominal types must match its signed interface.");
            signature.function_kind = Some(kind);
            Some(signature)
        }).collect();
    }
    if let Type::Option(value) | Type::Result(value, _) = ty {
        let value = render_type_name(value);
        let option = matches!(ty, Type::Option(_));
        let mut signatures = vec![
            editor_signature(
                if option { "is_some" } else { "is_ok" },
                vec![],
                "bool".into(),
                if option {
                    "Test whether the optional value is present without extracting it."
                } else {
                    "Test whether the result contains a successful value without extracting it."
                },
            ),
            editor_signature(
                if option { "is_none" } else { "is_err" },
                vec![],
                "bool".into(),
                if option {
                    "Test whether the optional value is absent."
                } else {
                    "Test whether the result contains an error without extracting it."
                },
            ),
            editor_signature(
                "unwrap_or",
                vec![("default", value.clone(), false)],
                value.clone(),
                "Extract the value, or use the fallback. The fallback is evaluated eagerly.",
            ),
        ];
        if let Type::Result(_, error) = ty {
            let error = render_type_name(error);
            signatures.push(editor_signature(
                "unwrap_err_or",
                vec![("default", error.clone(), false)],
                error,
                "Extract the error, or use the fallback. The fallback is evaluated eagerly.",
            ));
        }
        signatures.push(editor_signature(
            "expect",
            vec![("error", "error enum".into(), false)],
            value.clone(),
            "Extract the value or reject with the supplied nominal error, such as Error::Missing. The receiver is evaluated once; the error is evaluated only on none or err.",
        ));
        signatures.push(editor_signature(
            if option { "ok_or" } else { "or_err" },
            vec![("error", "E (error enum)".into(), false)],
            format!("Result<{value}, E>"),
            if option {
                "Turn some into ok, or none into err with the supplied nominal error. The receiver is evaluated once; the error is evaluated only on none."
            } else {
                "Keep the successful payload, or replace the original error with the supplied nominal error. The receiver is evaluated once; the replacement error is evaluated only on err."
            },
        ));
        return signatures;
    }
    if let Type::List(element, _) = ty {
        let element = render_type_name(element);
        return [
            ("len", vec![], "int".into()),
            ("pop", vec![], format!("Option<{element}>")),
            (
                "contains",
                vec![("value", element.clone(), false)],
                "bool".into(),
            ),
            (
                "take",
                vec![("limit", "int".into(), false)],
                render_type_name(ty),
            ),
            (
                "enumerate",
                vec![],
                format!(
                    "List<(int, {element}), {}>",
                    if let Type::List(_, capacity) = ty {
                        *capacity
                    } else {
                        0
                    }
                ),
            ),
            (
                "get",
                vec![("index", "int".into(), false)],
                format!("Option<{element}>"),
            ),
            (
                "set",
                vec![
                    ("index", "int".into(), true),
                    ("value", element.clone(), true),
                ],
                "()".into(),
            ),
            (
                "try_set",
                vec![
                    ("index", "int".into(), true),
                    ("value", element.clone(), true),
                ],
                "Result<(), ListError>".into(),
            ),
            ("push", vec![("value", element.clone(), false)], "()".into()),
            (
                "try_push",
                vec![("value", element, false)],
                "Result<(), ListError>".into(),
            ),
        ]
        .into_iter()
        .map(|(name, parameters, return_type)| {
            editor_signature(
                name,
                parameters,
                return_type,
                "Bounded List operation; checked mutation rejects with ListError.",
            )
        })
        .collect();
    }
    let name = render_type_name(ty);
    let mut signatures = Vec::new();
    if matches!(ty, Type::Decimal | Type::Quantity) {
        let rounding = "Round once at the requested scale with an explicit Rounding mode.";
        signatures.push(editor_signature(
            "div_round",
            vec![
                ("divisor", "decimal".into(), true),
                ("scale", "int".into(), true),
                ("mode", "Rounding".into(), true),
            ],
            name.clone(),
            rounding,
        ));
        signatures.push(editor_signature(
            "mul_div_round",
            vec![
                ("multiplier", "decimal".into(), true),
                ("divisor", "decimal".into(), true),
                ("scale", "int".into(), true),
                ("mode", "Rounding".into(), true),
            ],
            name.clone(),
            "Fused multiply/divide with one final rounding step; intermediate arithmetic is exact.",
        ));
        if matches!(ty, Type::Quantity) {
            signatures.push(editor_signature(
                "ratio_round",
                vec![
                    ("divisor", "quantity".into(), true),
                    ("scale", "int".into(), true),
                    ("mode", "Rounding".into(), true),
                ],
                "decimal".into(),
                rounding,
            ));
        }
    }
    if let Type::StateMap(key, value) = ty {
        let (key, value) = (render_type_name(key), render_type_name(value));
        signatures.push(editor_signature(
            "get",
            vec![("key", key.clone(), false)],
            format!("Option<{value}>"),
            "Read one durable key; absence is Option::none.",
        ));
        signatures.push(editor_signature("page", vec![("after", format!("Option<StateCursor<{key}>>"), true), ("limit", "int".into(), true)], format!("StatePage<{key}, {value}, N>"), "Live keyset page; limit is a compile-time int constant expression N in 1..=64. At most 64 candidate positions are examined, including tombstones, and at most N values are returned. Read items and next; a final empty page is possible."));
        signatures.push(editor_signature("take", vec![("limit", "int".into(), false)], format!("List<({key}, {value}), N>"), "Return the first page's items; limit is a compile-time int constant expression N in 1..=64."));
    }
    signatures.extend(Builtin::registry().filter_map(|(builtin, spec)| {
        let first = spec.signature.parameters.first()?;
        (matches!(
            spec.surface,
            BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
        ) && (*first == name
            || (*first == "StateMap<K,V>" && matches!(ty, Type::StateMap(..)))
            || (*first == "decimal|quantity" && matches!(ty, Type::Decimal | Type::Quantity))))
        .then(|| {
            let mut signature = builtin_signature(builtin, true);
            if let Type::StateMap(key, value) = ty {
                for parameter in &mut signature.parameters {
                    parameter.ty = parameter
                        .ty
                        .replace('K', &render_type_name(key))
                        .replace('V', &render_type_name(value));
                }
                signature.return_type = signature
                    .return_type
                    .replace('K', &render_type_name(key))
                    .replace('V', &render_type_name(value));
                signature.declaration = signature.label();
            }
            signature
        })
    }));
    signatures
}
fn plain_completion(name: &str, kind: u64, detail: &str) -> EditorCompletion {
    EditorCompletion {
        label: name.into(),
        kind,
        detail: detail.into(),
        insert_text: name.into(),
        snippet: false,
        documentation: String::new(),
        filter_text: None,
        sort_text: None,
    }
}
fn signature_completion(signature: EditorSignature) -> EditorCompletion {
    EditorCompletion {
        label: signature.name.clone(),
        kind: 3,
        detail: signature.declaration.clone(),
        insert_text: signature.snippet(),
        snippet: true,
        documentation: signature.documentation,
        filter_text: None,
        sort_text: None,
    }
}
fn definition_completion(definition: &EditorDefinition) -> EditorCompletion {
    definition
        .signature
        .clone()
        .map(signature_completion)
        .unwrap_or_else(|| {
            let mut completion =
                plain_completion(&definition.name, definition.kind, &definition.detail);
            completion
                .documentation
                .clone_from(&definition.documentation);
            completion
        })
}
fn path_prefix(tokens: &[Token], offset: u32) -> String {
    let mut pieces = Vec::new();
    for token in tokens
        .iter()
        .rev()
        .filter(|token| token.range.start < offset && token.kind != TokenKind::EOF)
    {
        match &token.kind {
            TokenKind::Ident(name) => pieces.push(name.clone()),
            TokenKind::ColonColon => pieces.push("::".into()),
            _ => break,
        }
    }
    pieces.reverse();
    pieces.concat()
}
/// Whether `offset` lies in a comment or literal where no Kotodama word applies.
/// Numeric tokens include a partially written decimal such as `1.`; that dot
/// belongs to the number and must not trigger member or global completions.
fn inside_comment_or_literal(file: &SourceFile, offset: u32) -> bool {
    use crate::syntax::SyntaxKind;
    crate::syntax::lex(file, FrontendBudget::v1())
        .tokens
        .iter()
        .any(|token| {
            let strictly_inside = token.range.start < offset && offset < token.range.end;
            // A line comment, and an unterminated literal, still covers the end of its line.
            let through_end = token.range.start < offset && offset <= token.range.end;
            match token.kind {
                SyntaxKind::LineComment | SyntaxKind::DocComment => {
                    // The lossless token includes its newline. Completion at the
                    // next line belongs to code, even though it is the token end.
                    file.slice(token.range).is_some_and(|text| {
                        let end =
                            token.range.start + text.trim_end_matches(['\r', '\n']).len() as u32;
                        token.range.start < offset && offset <= end
                    })
                }
                SyntaxKind::Number | SyntaxKind::Decimal => through_end,
                SyntaxKind::BlockComment | SyntaxKind::String | SyntaxKind::Bytes => {
                    strictly_inside
                }
                SyntaxKind::ErrorToken => {
                    through_end
                        && file.slice(token.range).is_some_and(|text| {
                            text.as_bytes().first().is_some_and(u8::is_ascii_digit)
                                || ["\"", "b\"", "r\"", "r#", "br", "rb", "/*"]
                                    .iter()
                                    .any(|opening| text.starts_with(opening))
                        })
                }
                _ => false,
            }
        })
}
/// Whether the cursor follows `.`, possibly with a partially typed member name.
fn after_member_dot(tokens: &[Token], offset: u32) -> bool {
    let mut before = tokens
        .iter()
        .filter(|token| token.kind != TokenKind::EOF && token.range.end <= offset)
        .rev();
    let mut last = before.next();
    if last
        .is_some_and(|token| token.range.end == offset && matches!(token.kind, TokenKind::Ident(_)))
    {
        last = before.next();
    }
    last.is_some_and(|token| token.kind == TokenKind::Dot)
}
fn receiver_before(tokens: &[Token], offset: u32) -> Option<TextRange> {
    let before = tokens
        .iter()
        .take_while(|token| token.range.start < offset)
        .collect::<Vec<_>>();
    let dot = before
        .iter()
        .rposition(|token| token.kind == TokenKind::Dot)?;
    if before[dot + 1..]
        .iter()
        .any(|token| !matches!(token.kind, TokenKind::Ident(_) | TokenKind::LParen))
    {
        return None;
    }
    let receiver = before.get(dot.checked_sub(1)?)?;
    matches!(
        receiver.kind,
        TokenKind::Ident(_) | TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace
    )
    .then_some(receiver.range)
}
fn call_context(tokens: &[Token], offset: u32) -> Option<(String, u32, usize)> {
    let mut stack: Vec<(TokenKind, usize)> = Vec::new();
    for (index, token) in tokens
        .iter()
        .enumerate()
        .take_while(|(_, token)| token.range.start < offset)
    {
        match token.kind {
            TokenKind::LParen | TokenKind::LBracket | TokenKind::LBrace => {
                stack.push((token.kind.clone(), index))
            }
            TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace => {
                stack.pop();
            }
            _ => {}
        }
    }
    let (_, index) = stack
        .iter()
        .rev()
        .find(|(kind, _)| *kind == TokenKind::LParen)?;
    let opening = tokens[*index].range.start;
    let name = path_prefix(&tokens[..*index], opening);
    let (active, _, _) = argument_context(tokens, opening, offset);
    (!name.is_empty()).then_some((name, opening, active))
}
fn argument_context(
    tokens: &[Token],
    opening: u32,
    offset: u32,
) -> (usize, Option<String>, BTreeSet<String>) {
    let mut depth = 0_usize;
    let mut active = 0;
    let mut label = None;
    let mut labels = BTreeSet::new();
    let mut previous: Option<&TokenKind> = None;
    for token in tokens
        .iter()
        .filter(|token| token.range.start > opening && token.range.start < offset)
    {
        match token.kind {
            TokenKind::LParen | TokenKind::LBracket | TokenKind::LBrace => depth += 1,
            TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace => {
                depth = depth.saturating_sub(1)
            }
            TokenKind::Comma if depth == 0 => {
                active += 1;
                label = None;
            }
            TokenKind::Colon if depth == 0 => {
                if let Some(TokenKind::Ident(name)) = previous {
                    label = Some(name.clone());
                    labels.insert(name.clone());
                }
            }
            _ => {}
        }
        previous = Some(&token.kind);
    }
    (active, label, labels)
}
#[cfg(test)]
mod locked_recovery_tests;
#[cfg(test)]
mod nominal_references_tests;
#[cfg(test)]
mod tests {
    use super::*;
    fn cursor(source: &str, fragment: &str) -> u32 {
        source.find(fragment).expect("cursor fragment") as u32
    }
    fn labels(snapshot: &EditorSnapshot, offset: u32) -> BTreeSet<String> {
        snapshot
            .completions(SourceId(0), offset)
            .into_iter()
            .map(|candidate| candidate.label)
            .collect()
    }
    #[test]
    fn permission_identifiers_navigate_rename_and_complete_without_chain_token_edits() {
        let source = r#"seiyaku Policies { permission Admin; import permission "CanSetParameters" as ChainAdmin;
            kotoage fn grant(AccountId account) authorize(Admin) {
                ledger::seiyaku::grant_permission(account: account, permission: Admin);
            }
            view fn inspect() authorize(ChainAdmin) -> int { 1 }
        }"#;
        let snapshot = EditorSnapshot::single("permissions.ko", source, false);
        assert!(snapshot.is_complete(), "{:?}", snapshot.blocking);
        let position = source.find("authorize(Admin)").unwrap() + "authorize(".len();
        let definition = snapshot
            .definition(SourceId(0), position as u32)
            .expect("permission declaration navigation");
        assert_eq!(definition.name, "Admin");
        let rename = snapshot
            .rename(SourceId(0), position as u32, "Manager")
            .expect("permission rename");
        assert_eq!(
            rename.sources.len(),
            3,
            "declaration, guard and grant operand"
        );
        let position = source.find("authorize(ChainAdmin)").unwrap() + "authorize(".len();
        let rename = snapshot
            .rename(SourceId(0), position as u32, "ChainManager")
            .unwrap();
        assert_eq!(rename.sources.len(), 2, "alias declaration and guard only");
        for range in rename.sources {
            assert_eq!(
                &source[range.range.start as usize..range.range.end as usize],
                "ChainAdmin"
            );
        }
        let incomplete = "seiyaku Policies { permission Admin; view fn inspect() authorize(";
        let snapshot = EditorSnapshot::single("permissions.ko", incomplete, false);
        let completions = snapshot.completions(SourceId(0), incomplete.len() as u32);
        let labels = completions
            .iter()
            .map(|item| item.label.as_str())
            .collect::<Vec<_>>();
        assert!(
            labels.contains(&"Admin") && labels.contains(&"anyone"),
            "{labels:?}"
        );
        assert!(!labels.contains(&"int"));
    }
    #[test]
    fn comments_strings_and_non_member_dots_offer_no_completions() {
        let body = |statement: &str| {
            format!(
                "seiyaku A {{\n    state StateMap<int, int> Scores;\n    view fn f(int who) authorize(anyone) -> int {{\n        {statement}\n        return 0;\n    }}\n}}\n"
            )
        };
        for (statement, needle, delta) in [
            ("// read Scores.", "Scores.", 7),
            ("// read Sco", "read Sco", 8),
            ("/* Scores. */", "Scores.", 7),
            ("debug::info(\"Scores.\");", "Scores.\"", 7),
            ("debug::info(\"Scores.", "Scores.", 7),
            ("let x = 1.", "1.", 2),
            ("let x = 1.25", "1.25", 4),
            ("let x = 0x", "0x", 2),
            ("let x = true.", "true.", 5),
        ] {
            let source = body(statement);
            let snapshot = EditorSnapshot::single("quiet.ko", &source, false);
            let offset = cursor(&source, needle) + delta;
            assert!(
                labels(&snapshot, offset).is_empty(),
                "`{statement}` offered {:?}",
                labels(&snapshot, offset)
            );
        }
        // Ordinary positions, and members after a value receiver, still complete.
        let source = body("let x = Scores.");
        let snapshot = EditorSnapshot::single("members.ko", &source, false);
        assert!(labels(&snapshot, cursor(&source, "Scores.\n") + 7).contains("contains"));
        let source = body("// note\n        ");
        let snapshot = EditorSnapshot::single("statement.ko", &source, false);
        assert!(labels(&snapshot, cursor(&source, "note\n") + 13).contains("let"));
        let file = SourceFile::new(SourceId(0), "edge.ko", "// end\nlet s = \"ab\"; /* c */");
        assert!(inside_comment_or_literal(&file, 6), "end of a line comment");
        assert!(!inside_comment_or_literal(&file, 7), "next line");
        let crlf = SourceFile::new(SourceId(0), "crlf.ko", "// end\r\nlet x = 0;");
        assert!(inside_comment_or_literal(&crlf, 6), "before CRLF");
        assert!(!inside_comment_or_literal(&crlf, 8), "after CRLF");
        assert!(inside_comment_or_literal(&file, 17), "inside a string");
        assert!(
            !inside_comment_or_literal(&file, 19),
            "after the closing quote"
        );
        assert!(!inside_comment_or_literal(&file, 28), "after `*/`");
    }
    #[test]
    fn authored_docs_follow_declaration_identity_and_preserve_markdown() {
        let source = r#"module Guide {
            /// A **named** record.
            export struct Payload { int value; }
            /// Read the value.
            ///
            /// Keeps the caller's data unchanged.
            export fn inspect(Payload payload) -> int { payload.value }
            /// This block is detached.

            export fn plain() -> int { 0 }
            /// This block is interrupted.
            // Ordinary comment.
            export fn other() -> int { 0 }
        }"#;
        let snapshot = EditorSnapshot::single("guide.ko", source, false);
        assert!(snapshot.is_complete());
        let (_, prose) = snapshot
            .hover(SourceId(0), cursor(source, "inspect"))
            .unwrap();
        assert!(
            prose.starts_with("Read the value.\n\nKeeps the caller's data unchanged."),
            "{prose}"
        );
        let (_, prose) = snapshot
            .hover(SourceId(0), cursor(source, "Payload"))
            .unwrap();
        assert!(prose.contains("A **named** record."), "{prose}");
        for name in ["plain", "other"] {
            let (_, prose) = snapshot.hover(SourceId(0), cursor(source, name)).unwrap();
            assert!(!prose.contains("This block"), "{prose}");
        }
    }

    #[test]
    fn declaration_hovers_document_their_leading_keyword_in_the_written_spelling() {
        assert!(symbol_documentation("誓約 Counter").starts_with("**誓約** (seiyaku)"));
        assert!(symbol_documentation("seiyaku Counter").starts_with("**seiyaku** (誓約)"));
        assert!(symbol_documentation("trigger wake -> reset").contains("trigger name -> callback"));
        assert!(symbol_documentation("state int value").contains("durable seiyaku state"));
        assert!(symbol_documentation("struct Pair").contains("record type"));
        assert_eq!(symbol_documentation("Pair"), "");
        assert_eq!(symbol_documentation(""), "");
        let source = "seiyaku Timer { permission CanTick; \n    state int ticks;\n    hajimari() {\n        ticks = 0;\n    }\n    trigger wake -> tick {\n        on time pre_commit;\n    }\n    kotoage fn tick() authorize(CanTick) {\n        ticks = ticks + 1;\n    }\n}\n";
        let snapshot = EditorSnapshot::single("timer.ko", source, false);
        let (detail, documentation) = snapshot
            .hover(SourceId(0), cursor(source, "wake"))
            .expect("trigger hover");
        assert_eq!(detail, "trigger wake -> tick");
        assert!(
            documentation.contains("recorded in the manifest"),
            "{documentation}"
        );
    }
    #[test]
    fn rename_tracks_binding_identity_and_named_argument_labels() {
        let source = "module Names { fn target(int _ first, int second) -> int { first + second } fn caller() -> int { target(1, second: 2) } }";
        let snapshot = EditorSnapshot::single("names.ko", source, false);
        assert!(snapshot.is_complete());
        let ranges = snapshot
            .rename(SourceId(0), cursor(source, "second)"), "amount")
            .expect("rename named parameter");
        assert!(ranges.exports.is_empty());
        assert_eq!(ranges.sources.len(), 3);
        for range in ranges.sources {
            assert_eq!(
                &source[range.range.start as usize..range.range.end as usize],
                "second"
            );
        }
        let call = cursor(source, "second: 2") + 9;
        let (signature, active) = snapshot
            .signature_help(SourceId(0), call)
            .expect("signature");
        assert_eq!(active, 1);
        assert_eq!(signature.label(), "target(int _ first, int second) -> int");
        assert_eq!(
            signature.snippet(),
            "target(${1:first}, second: ${2:second})"
        );
        assert!(
            snapshot
                .rename(SourceId(0), cursor(source, "second)"), "first")
                .is_err()
        );
    }
    #[test]
    fn rename_allows_disjoint_scopes_and_rejects_reference_capture() {
        let source = "module Scopes { fn first(int _ value) -> int { value } fn second(int _ amount) -> int { amount } }";
        let snapshot = EditorSnapshot::single("scopes.ko", source, false);
        let rename = snapshot
            .rename(SourceId(0), cursor(source, "value)"), "amount")
            .expect("independent function scopes may use the same parameter name");
        assert_eq!(rename.sources.len(), 2);
        let captured = "module Capture { fn run(int _ value) -> int { if true { let amount = 1; value + amount } else { value } } }";
        let snapshot = EditorSnapshot::single("capture.ko", captured, false);
        assert!(snapshot.is_complete());
        assert!(
            snapshot
                .rename(SourceId(0), cursor(captured, "value)"), "amount")
                .is_err(),
            "a type-correct rename must not capture an outer parameter inside a nested scope"
        );
    }
    #[test]
    fn rename_refusals_name_keywords_hooks_and_the_failing_check() {
        let source = "seiyaku Counter {\n    state int value;\n    始まり() {\n        value = 0;\n    }\n    fn helper(int _ input) -> int { input }\n    view fn read() authorize(anyone) -> int { helper(value) }\n}\n";
        let snapshot = EditorSnapshot::single("counter.ko", source, false);
        assert!(snapshot.is_complete());
        let helper = cursor(source, "helper(int");
        for (name, expected) in [
            ("言挙げ", "keyword `kotoage`/`言挙げ`"),
            ("kotoage", "keyword `kotoage`/`言挙げ`"),
            ("state", "is a Kotodama keyword"),
            ("助ける", "identifiers are ASCII"),
            ("two words", "not a single Kotodama identifier"),
        ] {
            let error = snapshot
                .rename(SourceId(0), helper, name)
                .expect_err("invalid rename target");
            assert!(error.contains(expected), "{name}: {error}");
        }
        // Renaming onto an existing declaration fails the post-rename check, which is named.
        let error = snapshot
            .rename(SourceId(0), helper, "read")
            .expect_err("collision");
        assert!(
            error.starts_with("Renaming to `read` would not check: "),
            "{error}"
        );
        // Lifecycle hooks are named by their keyword in either spelling.
        let error = snapshot
            .rename(SourceId(0), cursor(source, "始まり"), "start")
            .expect_err("hooks cannot be renamed");
        assert!(error.contains("`hajimari`/`始まり`"), "{error}");
        assert!(validate_rename_name("assist").is_ok());
    }
    #[test]
    fn binding_hovers_fall_back_to_the_declared_type() {
        // `require` without its error argument fails the check, so binding types are unknown.
        let source = "module Hover {\n    fn run(Option<int> _ maybe, int who, Option<AccountId> owner) -> int {\n        let count = 1;\n        require(maybe.is_some());\n        return count + who;\n    }\n}\n";
        let snapshot = EditorSnapshot::single("hover.ko", source, false);
        assert!(!snapshot.is_complete());
        let hover = |needle: &str| {
            snapshot
                .hover(SourceId(0), cursor(source, needle) + 1)
                .map(|(detail, _)| detail)
        };
        assert_eq!(hover("who;").as_deref(), Some("int who"));
        assert_eq!(hover("maybe.").as_deref(), Some("Option<int> maybe"));
        let unit = snapshot.units.get(&SourceId(0)).expect("unit");
        let range = |needle: &str| {
            let start = cursor(source, needle);
            unit.tokens
                .iter()
                .find(|token| token.range.start == start)
                .expect("token")
                .range
        };
        assert_eq!(
            declared_binding_type(unit, range("owner)")).as_deref(),
            Some("Option<AccountId>")
        );
        assert_eq!(declared_binding_type(unit, range("count =")), None);
    }
    #[test]
    fn scopes_do_not_leak_sibling_parameters_or_finished_block_locals() {
        let source = "module Scope { fn first(int _ input) -> int { if true { let hidden = input; } input } fn second(int _ other) -> int { other } }";
        let snapshot = EditorSnapshot::single("scope.ko", source, false);
        assert!(snapshot.is_complete());
        let visible = labels(&snapshot, cursor(source, "} input }") + 3);
        assert!(visible.contains("input"));
        assert!(!visible.contains("hidden"));
        assert!(!visible.contains("other"));
        let visible = labels(&snapshot, cursor(source, "{ other }") + 3);
        assert!(visible.contains("other"));
        assert!(!visible.contains("input"));
    }
    #[test]
    fn receivers_offer_only_their_actual_members_including_incomplete_buffers() {
        let source =
            "module Lists { fn read(List<int, 4> values) -> Option<int> { values.get(0) } }";
        let snapshot = EditorSnapshot::single("lists.ko", source, false);
        let members = labels(&snapshot, cursor(source, ".get") + 1);
        assert_eq!(
            members,
            kotodama_surface::source_policy::V1_LIST_MEMBER_NAMES
                .iter()
                .copied()
                .chain(["read"])
                .map(str::to_owned)
                .collect()
        );
        assert!(!members.contains("ledger::asset::mint"));
        let incomplete = "module Lists { fn read(List<int, 4> values) { values. } }";
        let snapshot = EditorSnapshot::single("lists.ko", incomplete, false);
        assert!(!snapshot.is_complete());
        assert!(labels(&snapshot, cursor(incomplete, ". }") + 1).contains("try_set"));
        assert!(
            snapshot
                .rename(SourceId(0), cursor(incomplete, "values)"), "items")
                .is_err()
        );
        assert!(
            crate::parser::parse(incomplete).is_err(),
            "editor recovery must never broaden parser acceptance"
        );
    }
    #[test]
    fn optional_and_result_receivers_offer_concise_typed_extraction() {
        for (ty, expression, expected, absent) in [
            (
                "Option<int>",
                "value.expect(Failure::Missing)",
                vec!["expect", "is_none", "is_some", "ok_or", "read", "unwrap_or"],
                "unwrap_err_or",
            ),
            (
                "Result<int, Failure>",
                "value.unwrap_or(0)",
                vec![
                    "expect",
                    "is_err",
                    "is_ok",
                    "or_err",
                    "read",
                    "unwrap_err_or",
                    "unwrap_or",
                ],
                "ok_or",
            ),
        ] {
            let source = format!(
                "module Values {{ error enum Failure {{ Missing = 1 }} \
                 fn read({ty} value) -> int {{ {expression} }} }}"
            );
            let snapshot = EditorSnapshot::single("values.ko", &source, false);
            assert!(snapshot.is_complete());
            let members = labels(&snapshot, cursor(&source, "value.") + 6);
            assert_eq!(members, expected.into_iter().map(str::to_owned).collect());
            assert!(!members.contains(absent));
            let (signature, active) = snapshot
                .signature_help(
                    SourceId(0),
                    cursor(&source, expression)
                        + u32::try_from(expression.len()).expect("short expression")
                        - 1,
                )
                .expect("typed extraction signature");
            assert_eq!(signature.return_type, "int");
            assert_eq!(active, 0);
            assert!(!signature.parameters[0].named);
        }
    }
    #[test]
    fn chained_state_reads_offer_expect_with_the_record_return_type() {
        let source = "seiyaku Notes { error enum Failure { Missing = 1 } struct Note { int amount } state StateMap<int, Note> Values; view fn read() authorize(anyone) -> Note { Values.get(1).expect(Failure::Missing) } }";
        let snapshot = EditorSnapshot::single("notes.ko", source, false);
        assert!(snapshot.is_complete());
        let candidates = snapshot.completions(SourceId(0), cursor(source, ".expect") + 1);
        let expect = candidates
            .iter()
            .find(|candidate| candidate.label == "expect")
            .expect("chained Option receiver offers expect");
        assert_eq!(expect.insert_text, "expect(${1:error})");
        assert!(expect.documentation.contains("nominal error"));
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.label == "amount")
        );
        let (signature, _) = snapshot
            .signature_help(SourceId(0), cursor(source, "Failure::Missing)"))
            .expect("chained extraction signature");
        assert_eq!(signature.return_type, "Notes::Note");
    }
    #[test]
    fn extraction_completion_handles_nested_fields_and_incomplete_chains() {
        let source = "module Fields { struct Record { Option<int> value } \
            fn read(Record record) -> bool { record.value.is_some() } }";
        let snapshot = EditorSnapshot::single("fields.ko", source, false);
        assert!(snapshot.is_complete());
        assert!(labels(&snapshot, cursor(source, ".is_some") + 1).contains("expect"));
        let incomplete = "seiyaku Notes { state StateMap<int, int> Values; view fn read() authorize(anyone) { Values.get(1). } }";
        let snapshot = EditorSnapshot::single("notes.ko", incomplete, false);
        assert!(!snapshot.is_complete());
        assert!(labels(&snapshot, cursor(incomplete, ". }") + 1).contains("expect"));
        assert!(crate::parser::parse(incomplete).is_err());
    }
    #[test]
    fn canonical_builtin_hover_and_nested_argument_context_share_signatures() {
        let source = "module Calls { fn target(Json payload, int count) -> int { count } fn run() -> int { target(payload: json { nested: [1, 2], other: 3 }, count: 4) } }";
        let snapshot = EditorSnapshot::single("calls.ko", source, false);
        let offset = cursor(source, "count: 4") + 8;
        let (_, active) = snapshot
            .signature_help(SourceId(0), offset)
            .expect("nested signature");
        assert_eq!(active, 1);
        let source = "module Builtins { fn check() { let x = Json::parse(\"{}\"); } }";
        let snapshot = EditorSnapshot::single("builtins.ko", source, false);
        let (hover, _) = snapshot
            .hover(SourceId(0), cursor(source, "Json::parse") + 7)
            .expect("builtin hover");
        assert!(hover.contains("Json::parse"));
        assert!(hover.contains("string _"));
    }
    fn library_editor_request(body: &str) -> SourcePackageGraphRequest {
        use crate::linker::{SourceModuleUnit, SourcePackageUnit};
        SourcePackageGraphRequest {
            package: SourcePackageUnit { artifacts: Vec::new(),
                identity: "local/editor@1".into(),
                modules: vec![SourceModuleUnit {
                    source_name: "src/lib.ko".into(),
                    source: format!(r#"module Library {{ import "./detail.ko" as helper; export fn value(rows::Row row) -> int {{ {body} }} }}"#),
                }],
                sources: vec![SourceModuleUnit {
                    source_name: "src/detail.ko".into(),
                    source: "module Detail { export const int SEED = 1; }".into(),
                }],
                imports: vec![ImportBinding { alias: "rows".into(), package: "locked/rows@1".into() }],
                exports: BTreeSet::from(["value".into()]),
            },
            dependencies: vec![SourcePackageUnit { artifacts: Vec::new(),
                identity: "locked/rows@1".into(),
                modules: vec![SourceModuleUnit {
                    source_name: "src/lib.ko".into(),
                    source: "module Rows { export struct Row { int amount; string memo; } struct Hidden { int secret; } }".into(),
                }],
                sources: vec![], imports: vec![], exports: BTreeSet::from(["Row".into()]),
            }],
        }
    }
    #[test]
    fn native_event_editor_resolves_emission_and_offers_only_declared_events() {
        let source = "seiyaku Events { event Note { int value; } kotoage fn run() authorize(anyone) { emit Note { value: 1 }; } }";
        let snapshot = EditorSnapshot::single("events.ko", source, false);
        assert!(snapshot.is_complete(), "{:?}", snapshot.blocking);
        let file = snapshot.sources().next().unwrap();
        let offset = cursor(source, "Note { value");
        let definition = snapshot
            .definition(file.id(), offset)
            .expect("event reference");
        assert_eq!(definition.name, "Note");
        assert!(
            definition.detail.starts_with("event Note"),
            "{}",
            definition.detail
        );
        assert!(snapshot.rename(file.id(), offset, "Changed").is_ok());
        let candidates = snapshot.completions(file.id(), offset);
        assert!(candidates.iter().any(|item| item.label == "Note"));
        assert!(!candidates.iter().any(|item| item.label == "run"));
        let empty = "seiyaku Events {  }";
        let snapshot = EditorSnapshot::single("empty.ko", empty, false);
        let file = snapshot.sources().next().unwrap();
        assert!(
            snapshot
                .completions(file.id(), 17)
                .iter()
                .any(|item| item.label == "event")
        );
    }
    #[test]
    fn ordinary_enum_editor_supports_variant_completion_navigation_and_rename() {
        let source = "module Data { enum Status { Active = 1, Paused = 2 } export fn echo(Status value) -> Status { if value == Status::Active { value } else { Status::Paused } } }";
        let snapshot = EditorSnapshot::single("data.ko", source, false);
        assert!(snapshot.is_complete(), "{:?}", snapshot.blocking);
        let file = snapshot.sources().next().unwrap();
        let offset = cursor(source, "Status::Active") + u32::try_from("Status::".len()).unwrap();
        let completions = snapshot.completions(file.id(), offset);
        assert!(completions.iter().any(|item| item.label == "Active"));
        assert!(completions.iter().any(|item| item.label == "Paused"));
        let definition = snapshot
            .definition(file.id(), cursor(source, "Status value"))
            .unwrap();
        assert_eq!(definition.name, "Status");
        assert!(definition.detail.starts_with("enum Status"));
        let rename = snapshot
            .rename(file.id(), cursor(source, "Status value"), "Mode")
            .unwrap();
        assert_eq!(
            rename.sources.len(),
            5,
            "rename updates declaration, parameter, return, and both qualified variants"
        );
        let suggestions = EditorSnapshot::single("empty.ko", "module Data {  }", false);
        let file = suggestions.sources().next().unwrap();
        assert!(
            suggestions
                .completions(file.id(), 14)
                .iter()
                .any(|item| item.label == "enum")
        );
    }
    #[test]
    fn package_editor_preserves_nominal_source_imports_and_manifest_rename() {
        let request = library_editor_request("row.amount + helper::SEED");
        let snapshot = EditorSnapshot::package(&request, false);
        assert!(snapshot.is_complete(), "{:?}", snapshot.blocking);
        assert_eq!(snapshot.sources().count(), 3);
        assert!(
            snapshot
                .sources()
                .all(|file| file.package_identity().is_some())
        );
        let local = snapshot
            .sources()
            .find(|file| {
                file.package_identity() == Some("local/editor@1") && file.name() == "src/lib.ko"
            })
            .unwrap();
        let dependency = snapshot
            .sources()
            .find(|file| file.package_identity() == Some("locked/rows@1"))
            .unwrap();
        assert_ne!(local.id(), dependency.id());
        let row = snapshot
            .definition(local.id(), cursor(local.text(), "Row row"))
            .unwrap();
        assert_eq!(row.source.source, dependency.id());
        let seed = snapshot
            .definition(local.id(), cursor(local.text(), "SEED"))
            .unwrap();
        assert_eq!(
            snapshot.source(seed.source.source).unwrap().name(),
            "src/detail.ko"
        );
        let rename = snapshot
            .rename(local.id(), cursor(local.text(), "value("), "quote")
            .unwrap();
        assert_eq!(
            rename.exports,
            vec![EditorExportRename {
                package: "local/editor@1".into(),
                old_name: "value".into(),
                new_name: "quote".into()
            }]
        );
        let dependency_rename = snapshot
            .rename(local.id(), cursor(local.text(), "Row row"), "Receipt")
            .unwrap();
        assert_eq!(dependency_rename.sources.len(), 2);
        assert_eq!(
            dependency_rename.exports,
            vec![EditorExportRename {
                package: "locked/rows@1".into(),
                old_name: "Row".into(),
                new_name: "Receipt".into()
            }]
        );
    }
    #[test]
    fn package_editor_recovery_preserves_locked_receiver_types_and_export_authority() {
        for body in ["row.", "row.am", "row.amount + true"] {
            let request = library_editor_request(body);
            let snapshot = EditorSnapshot::package(&request, false);
            assert!(!snapshot.is_complete());
            let source = snapshot
                .sources()
                .find(|file| {
                    file.package_identity() == Some("local/editor@1") && file.name() == "src/lib.ko"
                })
                .unwrap();
            let offset = cursor(source.text(), "row.") + if body == "row.am" { 6 } else { 4 };
            let candidates = snapshot.completions(source.id(), offset);
            assert_eq!(
                candidates
                    .iter()
                    .map(|item| item.label.as_str())
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from(["amount", "memo", "value"]),
                "{body}: {candidates:?}"
            );
            assert!(
                snapshot
                    .rename(source.id(), cursor(source.text(), "value("), "quote")
                    .is_err()
            );
        }
        let mut request = library_editor_request("row.amount");
        request.package.imports.clear();
        let snapshot = EditorSnapshot::package(&request, false);
        assert!(!snapshot.is_complete());
        let source = snapshot
            .sources()
            .find(|file| {
                file.package_identity() == Some("local/editor@1") && file.name() == "src/lib.ko"
            })
            .unwrap();
        assert!(
            snapshot
                .definition(source.id(), cursor(source.text(), "Row row"))
                .is_none()
        );
        assert!(
            snapshot
                .completions(source.id(), cursor(source.text(), "rows::") + 6)
                .is_empty()
        );
    }
    #[test]
    fn package_editor_rejects_nominal_type_substitution_and_preserves_body_facts() {
        let mut request = library_editor_request("accept(row: row)");
        request.package.modules[0].source = request.package.modules[0].source.replace("export fn value", "struct Row { int amount; string memo; } fn accept(Row row) -> int { row.amount } export fn value");
        let snapshot = EditorSnapshot::package(&request, false);
        assert!(
            !snapshot.is_complete(),
            "local and locked structs must stay nominally distinct"
        );
        assert!(
            ModuleBuildGraph::default()
                .validate_package(request, LinkerOptions::default())
                .is_err()
        );
    }
    #[test]
    fn locked_import_references_keep_source_and_package_identity() {
        use crate::linker::{SourceModuleUnit, SourcePackageUnit};
        let request = SourceLinkRequest {
            artifacts: Vec::new(),
            sources: Vec::new(),
            root: SourceModuleUnit {
                source_name: "app.ko".into(),
                source:
                    "seiyaku App { view fn run() authorize(anyone) -> int { arithmetic::value() } }"
                        .into(),
            },
            imports: vec![ImportBinding {
                alias: "arithmetic".into(),
                package: "std/math@1.0.0".into(),
            }],
            packages: vec![SourcePackageUnit {
                artifacts: Vec::new(),
                sources: Vec::new(),
                identity: "std/math@1.0.0".into(),
                modules: vec![SourceModuleUnit {
                    source_name: "math.ko".into(),
                    source:
                        "module Math { export fn value() -> int { 7 } fn hidden() -> int { 9 } }"
                            .into(),
                }],
                exports: BTreeSet::from(["value".into()]),
                imports: vec![],
            }],
        };
        let snapshot = EditorSnapshot::project(&request, false);
        assert!(
            snapshot.is_complete(),
            "{:#?}",
            ModuleBuildGraph::default().link(request.clone(), LinkerOptions::default())
        );
        let root = snapshot
            .sources()
            .find(|source| source.name() == "app.ko")
            .expect("root");
        let call = cursor(root.text(), "value()");
        let definition = snapshot
            .definition(root.id(), call)
            .expect("import definition");
        assert_eq!(
            snapshot
                .source(definition.source.source)
                .expect("definition source")
                .package_identity(),
            Some("std/math@1.0.0")
        );
        assert_eq!(snapshot.references(root.id(), call, true).len(), 2);
        let candidates = snapshot.completions(root.id(), cursor(root.text(), "arithmetic::") + 12);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.label.as_str())
                .collect::<Vec<_>>(),
            vec!["value"]
        );
        let rename = snapshot
            .rename(root.id(), call, "next")
            .expect("checked source and export plan");
        assert_eq!(rename.sources.len(), 2);
        assert_eq!(
            rename.exports,
            vec![EditorExportRename {
                package: "std/math@1.0.0".into(),
                old_name: "value".into(),
                new_name: "next".into(),
            }]
        );
        assert!(snapshot.rename(root.id(), call, "hidden").is_err());
    }
    #[test]
    fn imported_error_namespace_completion_uses_the_exported_nominal_type() {
        use crate::linker::{SourceModuleUnit, SourcePackageUnit};
        let request = SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
            root: SourceModuleUnit {
                source_name: "app.ko".into(),
                source: "seiyaku App { view fn run() authorize(anyone) -> errors::Failure { errors::Failure::Missing } }".into(),
            },
            imports: vec![ImportBinding { alias: "errors".into(), package: "local/errors@1".into() }],
            packages: vec![SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
                identity: "local/errors@1".into(),
                modules: vec![SourceModuleUnit {
                    source_name: "errors.ko".into(),
                    source: "module Errors { export error enum Failure { Missing = 1, Invalid = 2 } export fn value() -> int { 7 } }".into(),
                }],
                exports: BTreeSet::from(["Failure".into(), "value".into()]), imports: vec![],
            }],
        };
        let snapshot = EditorSnapshot::project(&request, false);
        assert!(snapshot.is_complete());
        let root = snapshot
            .sources()
            .find(|file| file.name() == "app.ko")
            .unwrap();
        let offset =
            cursor(root.text(), "errors::Failure::Missing") + "errors::Failure::".len() as u32;
        let candidates = snapshot.completions(root.id(), offset);
        assert_eq!(
            candidates
                .iter()
                .map(|item| item.label.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["Missing", "Invalid"])
        );
        assert!(
            candidates
                .iter()
                .all(|item| item.detail.starts_with("errors::Failure::"))
        );
    }
    #[test]
    fn namespace_completion_preserves_nested_prefixes_and_nominal_errors() {
        let source = "module Partial { fn run() { ledger::asset:: } }";
        let snapshot = EditorSnapshot::single("partial.ko", source, false);
        let candidates = snapshot.completions(SourceId(0), cursor(source, "ledger::asset::") + 15);
        assert!(candidates.iter().any(|candidate| candidate.label == "mint"));
        assert!(
            candidates
                .iter()
                .all(|candidate| !candidate.insert_text.starts_with("asset::"))
        );
        let source = "module Partial { fn run() { ListError:: } }";
        let snapshot = EditorSnapshot::single("partial.ko", source, false);
        let candidates = snapshot.completions(SourceId(0), cursor(source, "ListError::") + 11);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.label == "IndexOutOfBounds")
        );
    }
    #[test]
    fn admitted_contract_members_offer_exact_named_signatures_without_lifecycle_hooks() {
        use crate::linker::{SourceContractArtifact, SourceModuleUnit};
        let artifact = crate::compiler::Compiler::new().compile_source(
            "seiyaku Pool { struct Payload { int amount; } hajimari() {} view fn quote(Payload payload) authorize(anyone) -> Payload { payload } kotoage fn update(int amount) authorize(anyone) {} }"
        ).expect("compile imported interface");
        let source = r#"seiyaku App { import seiyaku "pool.to" as Pool; view fn relay(bytes address, Pool::Payload payload) authorize(anyone) -> Pool::Payload { let pool = Pool::at(address: address); pool.quote(payload: payload) } }"#;
        let request = SourceLinkRequest {
            root: SourceModuleUnit {
                source_name: "app.ko".into(),
                source: source.into(),
            },
            artifacts: vec![SourceContractArtifact {
                source_name: "pool.to".into(),
                artifact,
            }],
            sources: vec![],
            imports: vec![],
            packages: vec![],
        };
        let snapshot = EditorSnapshot::project(&request, false);
        assert!(
            snapshot.is_complete(),
            "{:?}",
            ModuleBuildGraph::default().link(request.clone(), LinkerOptions::default())
        );
        let root = snapshot
            .sources()
            .find(|file| file.name() == "app.ko")
            .unwrap();
        let members = snapshot.completions(root.id(), cursor(source, "pool.quote") + 5);
        assert_eq!(
            members
                .iter()
                .map(|member| member.label.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["quote", "update"])
        );
        let (signature, _) = snapshot
            .signature_help(root.id(), cursor(source, "payload: payload") + 12)
            .expect("typed method signature");
        assert_eq!(
            signature.label(),
            "quote(Pool::Payload payload) -> Pool::Payload"
        );
        assert_eq!(signature.snippet(), "quote(payload: ${1:payload})");
        assert_eq!(
            signature.function_kind,
            Some(crate::ast::FunctionKind::View)
        );
    }
    #[test]
    fn matching_private_receiver_helpers_supply_method_signatures_and_completions() {
        let source = "module Helpers { error enum Failure { Missing = 1 } fn expect(int value, int extra) -> int { value + extra } fn read(int value) -> int { value.expect(extra: 2) } fn native(Option<int> option) -> int { option.expect(Failure::Missing) } }";
        let snapshot = EditorSnapshot::single("helpers.ko", source, false);
        assert!(snapshot.is_complete());
        let (signature, active) = snapshot
            .signature_help(SourceId(0), cursor(source, "extra: 2") + 8)
            .unwrap();
        assert_eq!(signature.label(), "expect(int extra) -> int");
        assert_eq!(active, 0);
        let completions = snapshot.completions(SourceId(0), cursor(source, "value.expect") + 6);
        assert_eq!(
            completions
                .iter()
                .filter(|candidate| candidate.label == "expect")
                .count(),
            1
        );
        assert_eq!(
            completions
                .iter()
                .find(|candidate| candidate.label == "expect")
                .unwrap()
                .insert_text,
            "expect(extra: ${1:extra})"
        );
        let (native, _) = snapshot
            .signature_help(SourceId(0), cursor(source, "Failure::Missing)"))
            .unwrap();
        assert_eq!(native.parameters[0].name, "error");
    }
    #[test]
    fn numeric_and_cursor_signatures_offer_exact_labels_and_types() {
        let numeric = member_signatures(&Type::Quantity);
        let fused = numeric
            .iter()
            .find(|signature| signature.name == "mul_div_round")
            .unwrap();
        assert_eq!(fused.return_type, "quantity");
        assert_eq!(
            fused.snippet(),
            "mul_div_round(multiplier: ${1:multiplier}, divisor: ${2:divisor}, scale: ${3:scale}, mode: ${4:mode})"
        );
        let map = member_signatures(&Type::StateMap(Box::new(Type::Int), Box::new(Type::Bool)));
        let page = map
            .iter()
            .find(|signature| signature.name == "page")
            .unwrap();
        assert_eq!(page.parameters[0].ty, "Option<StateCursor<int>>");
        assert_eq!(page.return_type, "StatePage<int, bool, N>");
        assert!(map.iter().all(|signature| signature.name != "range"));
        assert_eq!(
            map.iter()
                .find(|signature| signature.name == "take")
                .unwrap()
                .snippet(),
            "take(${1:limit})"
        );
        assert!(
            intrinsic_signatures()
                .iter()
                .any(|signature| signature.name == "quantity::try_from_int"
                    && signature.return_type == "Result<quantity, NumericError>"
                    && !signature.parameters[0].named)
        );
    }
    #[test]
    fn completion_filters_test_and_zk_modes_by_source_context() {
        let source = "module Modes { fn ordinary() {} #[test] fn test_case() {} }";
        let snapshot = EditorSnapshot::single("modes.ko", source, false);
        let ordinary = snapshot.completions(SourceId(0), cursor(source, "ordinary() {") + 12);
        assert!(
            ordinary
                .iter()
                .all(|candidate| !candidate.label.starts_with("test::"))
        );
        let test = snapshot.completions(SourceId(0), cursor(source, "test_case() {") + 13);
        assert!(
            test.iter()
                .any(|candidate| candidate.label == "test::expect_reject_as")
        );
    }
    #[test]
    fn multifile_editor_tracks_includes_imports_messages_and_rename() {
        use crate::linker::SourceModuleUnit;
        let request = SourceLinkRequest { artifacts: Vec::new(),
            root: SourceModuleUnit { source_name: "app.ko".into(), source: r#"seiyaku App { include "./parts.ko"; import "./math.ko" as arithmetic; view fn run() authorize(anyone) -> int { helper(arithmetic::SCALE) } fn fail() -> Fault { Fault::Denied } }"#.into() },
            sources: vec![
                SourceModuleUnit { source_name: "parts.ko".into(), source: r#"const int BASE = 1; fn helper(int _ value) -> int { value + BASE } error enum Fault { #[message("Permission required")] Denied = 3; }"#.into() },
                SourceModuleUnit { source_name: "math.ko".into(), source: "module Math { export const int SCALE = 7; fn hidden() -> int { 2 } }".into() },
            ], imports: vec![], packages: vec![],
        };
        let snapshot = EditorSnapshot::project(&request, false);
        assert!(
            snapshot.is_complete(),
            "{:?}",
            ModuleBuildGraph::default().link(request.clone(), LinkerOptions::default())
        );
        assert_eq!(snapshot.sources().count(), 3);
        let root = snapshot
            .sources()
            .find(|file| file.name() == "app.ko")
            .unwrap();
        assert_eq!(
            snapshot
                .unit_declaration_signatures(root.id())
                .iter()
                .map(|signature| signature.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fail", "helper", "run"]
        );
        let helper = cursor(root.text(), "helper(");
        let definition = snapshot
            .definition(root.id(), helper)
            .expect("included helper definition");
        assert_eq!(
            snapshot.source(definition.source.source).unwrap().name(),
            "parts.ko"
        );
        assert_eq!(snapshot.references(root.id(), helper, true).len(), 2);
        let rename = snapshot
            .rename(root.id(), helper, "calculate")
            .expect("rename across native files");
        assert_eq!(rename.sources.len(), 2);
        let constant = snapshot
            .definition(root.id(), cursor(root.text(), "SCALE"))
            .expect("local exported constant");
        assert_eq!(
            snapshot.source(constant.source.source).unwrap().name(),
            "math.ko"
        );
        let completions = snapshot.completions(root.id(), cursor(root.text(), "arithmetic::") + 12);
        assert!(completions.iter().any(|item| item.label == "SCALE"));
        assert!(completions.iter().all(|item| item.label != "hidden"));
        assert_eq!(
            snapshot
                .hover(root.id(), cursor(root.text(), "Denied"))
                .unwrap()
                .1,
            "Permission required"
        );
        let variants = snapshot.completions(root.id(), cursor(root.text(), "Fault::") + 7);
        assert_eq!(
            variants
                .iter()
                .find(|item| item.label == "Denied")
                .unwrap()
                .documentation,
            "Permission required"
        );
    }
    #[test]
    fn multifile_editor_retains_shared_receiver_facts_after_body_error() {
        use crate::linker::SourceModuleUnit;
        let request = SourceLinkRequest { artifacts: Vec::new(),
            root: SourceModuleUnit { source_name: "app.ko".into(), source: r#"seiyaku App { include "./types.ko"; view fn run(Receipt receipt) authorize(anyone) -> int { receipt.amount + true } }"#.into() },
            sources: vec![SourceModuleUnit { source_name: "types.ko".into(), source: "struct Receipt { int amount; }".into() }],
            imports: vec![], packages: vec![],
        };
        let snapshot = EditorSnapshot::project(&request, false);
        assert!(!snapshot.is_complete());
        let root = snapshot
            .sources()
            .find(|file| file.name() == "app.ko")
            .unwrap();
        let completions =
            snapshot.completions(root.id(), cursor(root.text(), "receipt.amount") + 8);
        assert!(
            completions
                .iter()
                .any(|item| item.label == "amount" && item.detail == "int")
        );
        let definition = snapshot
            .definition(root.id(), cursor(root.text(), "Receipt receipt"))
            .unwrap();
        assert_eq!(
            snapshot.source(definition.source.source).unwrap().name(),
            "types.ko"
        );
    }
    #[test]
    fn multifile_editor_package_paths_preserve_source_and_manifest_exports() {
        use crate::linker::{SourceModuleUnit, SourcePackageUnit};
        let request = SourceLinkRequest { artifacts: Vec::new(),
            root: SourceModuleUnit { source_name: "app.ko".into(), source: "seiyaku App { view fn run() authorize(anyone) -> int { library::value() } }".into() },
            sources: vec![], imports: vec![ImportBinding { alias: "library".into(), package: "local/tools@1".into() }],
            packages: vec![SourcePackageUnit { artifacts: Vec::new(),
                identity: "local/tools@1".into(),
                modules: vec![SourceModuleUnit { source_name: "lib.ko".into(), source: r#"module Tools { import "./detail.ko" as helper; export fn value() -> int { helper::SEED } }"#.into() }],
                sources: vec![SourceModuleUnit { source_name: "detail.ko".into(), source: "module Detail { export const int SEED = 7; fn hidden() -> int { 2 } }".into() }],
                imports: vec![], exports: BTreeSet::from(["value".into()]),
            }],
        };
        let snapshot = EditorSnapshot::project(&request, false);
        assert!(
            snapshot.is_complete(),
            "{:?}",
            ModuleBuildGraph::default().link(request.clone(), LinkerOptions::default())
        );
        let module = snapshot
            .sources()
            .find(|file| file.name() == "lib.ko")
            .unwrap();
        let constant = snapshot
            .definition(module.id(), cursor(module.text(), "SEED"))
            .expect("source export through a local path");
        assert_eq!(
            snapshot.source(constant.source.source).unwrap().name(),
            "detail.ko"
        );
        let completion = snapshot.completions(module.id(), cursor(module.text(), "helper::") + 8);
        assert_eq!(
            completion
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            vec!["SEED"]
        );
        let rename = snapshot
            .rename(module.id(), cursor(module.text(), "SEED"), "START")
            .expect("private package export rename");
        assert_eq!(rename.sources.len(), 2);
        assert!(rename.exports.is_empty());
        let root = snapshot
            .sources()
            .find(|file| file.name() == "app.ko")
            .unwrap();
        let completion = snapshot.completions(root.id(), cursor(root.text(), "library::") + 9);
        assert_eq!(
            completion
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            vec!["value"]
        );
    }
    #[test]
    fn multifile_loose_document_requires_dependency_authority_before_rename() {
        let source = r#"seiyaku App { include "./missing.ko"; view fn answer() authorize(anyone) -> int { 1 } }"#;
        let snapshot = EditorSnapshot::single("app.ko", source, false);
        assert!(!snapshot.is_complete());
        assert!(
            snapshot
                .rename(SourceId(0), cursor(source, "answer"), "value")
                .is_err()
        );
    }
}
