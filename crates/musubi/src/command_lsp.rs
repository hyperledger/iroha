//! Canonical Musubi workspace provider for the shared language-server engine.
use super::*;
use kotodama_toolchain::lsp::{ProjectProvider, ProjectSnapshot, ServerOptions};

#[derive(Args, Debug)]
pub(super) struct LspArgs {
    #[command(flatten)]
    build: BuildArgs,
    /// Select one semantic target when a source belongs to several contracts. Diagnostics still
    /// cover all selected targets. Use a unique target name or `namespace/package::target`.
    #[arg(long)]
    contract: Option<String>,
}

struct WorkspaceProvider<'a> {
    manifest: PathBuf,
    selection: &'a SelectionArgs,
    contract: Option<&'a str>,
    cache: Option<MusubiCache>,
    network_id: Option<iroha_data_model::NetworkId>,
    chain_discriminant: u16,
    explicit_network: Option<String>,
    config_path: Option<PathBuf>,
}
impl ProjectProvider for WorkspaceProvider<'_> {
    fn reload(&mut self, overlays: &BTreeMap<PathBuf, String>) -> Result<ProjectSnapshot, String> {
        let workspace = crate::workspace::load_workspace_with_overlays(&self.manifest, overlays)
            .map_err(|error| error.to_string())?;
        let selected = select_members(&workspace, self.selection)
            .map_err(|error| error.render_human())?
            .into_iter()
            .map(|member| member.package.selector.clone())
            .collect::<Vec<_>>();
        let lock = read_optional_workspace_lock(&workspace)
            .map_err(|error| error.render_human())?
            .ok_or("Musubi.lock is absent; save the manifest and run `musubi check` to resolve the project")?;
        if matches!(lock.context, LockContextV1::Registry { .. }) {
            let root = platform_cache_root_v1().map_err(|error| error.to_string())?;
            let cache = ResolverIndexCacheV1::open(&root).map_err(|error| error.to_string())?;
            resolve_workspace_offline_cached(
                &cache,
                &workspace,
                &selected,
                Some(lock.clone()),
                None,
                OfflineGraphOptionsV1 {
                    mode: ResolveModeV1::Locked,
                    purpose: GraphPurposeV1::Workspace,
                    expected_binding: self.network_id.map(|id| (id, self.chain_discriminant)),
                },
            )
            .map_err(|error| {
                format!(
                    "{error}; save dependency changes and run `musubi check` to update the lock"
                )
            })?;
        }
        let mut targets = crate::compiler::load_editor_projects(
            self.cache.as_ref(),
            &workspace,
            &selected,
            &lock,
            overlays,
        )
        .map_err(|error| error.to_string())?;
        for target in &mut targets {
            if let Some(context) = &mut target.test_context {
                context.network.clone_from(&self.explicit_network);
                context.config_path.clone_from(&self.config_path);
            }
        }
        let selected_target = self
            .contract
            .map(|selector| {
                let matches = targets
                    .iter()
                    .filter(|target| {
                        target.project.graph.as_source().is_some()
                            && (target.name == selector
                                || target
                                    .name
                                    .rsplit_once("::")
                                    .is_some_and(|(_, name)| name == selector))
                    })
                    .collect::<Vec<_>>();
                match matches.as_slice() {
                    [target] => Ok(target.name.clone()),
                    [] => Err(format!(
                        "Contract `{selector}` is absent from the selected workspace targets"
                    )),
                    _ => Err(format!(
                        "Contract `{selector}` is ambiguous; select one of: {}",
                        matches
                            .iter()
                            .map(|target| target.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                }
            })
            .transpose()?;
        Ok(ProjectSnapshot {
            targets,
            selected_target,
        })
    }
}

pub(super) fn run_lsp(manifest: Option<&Path>, args: &LspArgs) -> CommandResult {
    let prepared = build::prepare_project(
        manifest,
        &args.build,
        network::NetworkPurpose::LocalCompilation,
    )?;
    let chain_discriminant = prepared.graph.account_chain_discriminant()?;
    let mut provider = WorkspaceProvider {
        manifest: prepared.workspace.root_manifest_path().to_path_buf(),
        selection: &args.build.selection,
        contract: args.contract.as_deref(),
        cache: prepared.cache,
        network_id: prepared.network.network_id,
        chain_discriminant,
        explicit_network: args.build.network.clone(),
        config_path: args
            .build
            .registry
            .config
            .as_ref()
            .map(|path| {
                path.canonicalize().map_err(|error| {
                    Diagnostic::new(
                        ErrorCode::Io,
                        format!("read LSP configuration path: {error}"),
                    )
                })
            })
            .transpose()?,
    };
    kotodama_toolchain::lsp::run_project_stdio(
        ServerOptions {
            source_root: None,
            zk_enabled: args.build.zk,
            chain_discriminant,
        },
        Some(&mut provider),
    )
    .map_err(|error| Diagnostic::new(ErrorCode::Compiler, error))?;
    // The language-server protocol owns stdout; successful shutdown has no command trailer.
    Ok(Success {
        message: String::new(),
        data: Value::Null,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use kotodama_lang::{driver::ProjectSourceKey, lint::LintLevel};
    const MANIFEST: &str = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "editor"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "lib"
exports = ["v\u0061lue"]
[[contract]]
name = "a"
path = "contracts/a.ko"
[[contract]]
name = "b"
path = "contracts/b.ko"
[lints]
unused-parameter = "allow"
"#;
    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        for (name, text) in [
            ("Musubi.toml", MANIFEST),
            (
                "lib/values.ko",
                "module Values { export fn value() -> int { 7 } }",
            ),
            ("common.ko", "fn common() -> int { 1 }"),
            (
                "contracts/a.ko",
                "seiyaku A { include \"../common.ko\"; view fn get() authorize(anyone) -> int { common() } }",
            ),
            (
                "contracts/b.ko",
                "seiyaku B { include \"../common.ko\"; view fn get() authorize(anyone) -> int { common() } }",
            ),
        ] {
            let path = temp.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        temp
    }
    fn args() -> LspArgs {
        let Cli {
            command: Command::Lsp(args),
            ..
        } = Cli::try_parse_from(["musubi", "lsp"]).unwrap()
        else {
            panic!("lsp")
        };
        args
    }
    #[test]
    fn project_provider_keeps_all_targets_exact_toml_tokens_and_unsaved_closures() {
        let temp = fixture();
        let args = args();
        let prepared = build::prepare_project(
            Some(&temp.path().join("Musubi.toml")),
            &args.build,
            network::NetworkPurpose::LocalCompilation,
        )
        .unwrap();
        let mut provider = WorkspaceProvider {
            manifest: prepared.workspace.root_manifest_path().to_path_buf(),
            selection: &args.build.selection,
            contract: None,
            cache: None,
            network_id: None,
            chain_discriminant: 753,
            explicit_network: None,
            config_path: None,
        };
        let initial = provider.reload(&BTreeMap::new()).unwrap();
        assert_eq!(initial.targets.len(), 3);
        let manifest = initial.targets[0]
            .project
            .manifests
            .iter()
            .find(|manifest| manifest.path() == provider.manifest)
            .unwrap();
        let identity = &initial.targets[0]
            .project
            .graph
            .as_source()
            .unwrap()
            .packages[0]
            .identity;
        let range = manifest.export_range(identity, "value").unwrap();
        assert_eq!(
            &manifest.text()[range.start as usize..range.end as usize],
            "\"v\\u0061lue\""
        );
        let overlay = MANIFEST.replace(
            "unused-parameter = \"allow\"",
            "unused-parameter = \"deny\"",
        );
        let common = temp.path().join("common.ko").canonicalize().unwrap();
        let unsaved = temp.path().canonicalize().unwrap().join("new.ko");
        let source = "include \"./new.ko\"; fn common() -> int { added() }";
        let overlays = BTreeMap::from([
            (provider.manifest.clone(), overlay.clone()),
            (common.clone(), source.to_owned()),
            (unsaved.clone(), "fn added() -> int { 9 }".to_owned()),
        ]);
        let snapshot = provider.reload(&overlays).unwrap();
        for target in snapshot
            .targets
            .iter()
            .filter(|target| target.project.graph.as_source().is_some())
        {
            assert_eq!(target.project.manifests[0].text(), overlay);
            assert!(
                target
                    .project
                    .graph
                    .as_source()
                    .unwrap()
                    .sources
                    .iter()
                    .any(|unit| unit.source_name == "new.ko")
            );
            assert_eq!(
                target.project.source_paths[&ProjectSourceKey {
                    package_identity: None,
                    source_name: "common.ko".into()
                }],
                common
            );
            assert_eq!(
                target.project.lints.level("unused-parameter"),
                LintLevel::Deny
            );
            assert_eq!(
                target.test_context.as_ref().unwrap().manifest_path,
                provider.manifest
            );
        }
        assert_eq!(
            std::fs::read_to_string(&provider.manifest).unwrap(),
            MANIFEST,
            "editor overlay must not write a manifest"
        );
        assert!(!unsaved.exists());
        let bad = BTreeMap::from([(
            provider.manifest.clone(),
            MANIFEST.replace("unused-parameter", "unuesd-parameter"),
        )]);
        assert!(
            provider
                .reload(&bad)
                .unwrap_err()
                .contains("unuesd-parameter")
        );
        provider.contract = Some("b");
        assert!(
            provider
                .reload(&BTreeMap::new())
                .unwrap()
                .selected_target
                .unwrap()
                .ends_with("::b")
        );
        provider.contract = Some("absent");
        assert!(provider.reload(&BTreeMap::new()).is_err());
    }
    #[test]
    fn library_only_project_keeps_locked_dependencies_and_owned_overlays() {
        use kotodama_lang::{
            driver::{BuildDriver, LoadedProjectGraph},
            editor::EditorSnapshot,
            session::CompilerSession,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let manifest = |name: &str, exports: &str| {
            format!(
                "manifest-version = 1\n[package]\nnamespace = \"apps.sora\"\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nsource-dir = \"src\"\nexports = [{exports}]\n"
            )
        };
        for (path, text) in [
            ("Musubi.toml", "manifest-version = 1\n[workspace]\nmembers = [\"app\", \"math\"]\ndefault-members = [\"app\"]\n".into()),
            (
                "app/Musubi.toml",
                format!(
                    "{}[dependencies]\narithmetic = {{ path = \"../math\" }}\n[lints]\nunused-parameter = \"deny\"\n",
                    manifest("app", "\"value\"")
                ),
            ),
            ("math/Musubi.toml", manifest("math", "\"base\"")),
            (
                "app/src/value.ko",
                "module App { export fn value() -> int { arithmetic::base() } }".into(),
            ),
            (
                "math/src/base.ko",
                "module Math { export fn base() -> int { 7 } }".into(),
            ),
        ] {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let args = args();
        let prepared = build::prepare_project(
            Some(&root.join("app/Musubi.toml")),
            &args.build,
            network::NetworkPurpose::LocalCompilation,
        )
        .unwrap();
        let mut provider = WorkspaceProvider {
            manifest: prepared.workspace.root_manifest_path().to_path_buf(),
            selection: &args.build.selection,
            contract: None,
            cache: None,
            network_id: None,
            chain_discriminant: 753,
            explicit_network: None,
            config_path: None,
        };
        let initial = provider.reload(&BTreeMap::new()).unwrap();
        assert_eq!(initial.targets.len(), 1);
        let target = &initial.targets[0];
        assert!(target.test_context.is_none());
        let LoadedProjectGraph::Package(graph) = &target.project.graph else {
            panic!("library graph")
        };
        assert_eq!(graph.dependencies.len(), 1);
        BuildDriver::new(CompilerSession::default(), "library-lsp")
            .check_package_project(graph.clone())
            .expect("library dependency graph must pass the canonical package checker");
        assert!(EditorSnapshot::package(graph, false).is_complete());
        for package in std::iter::once(&graph.package).chain(&graph.dependencies) {
            assert!(
                target
                    .project
                    .source_paths
                    .keys()
                    .any(|key| key.package_identity.as_deref() == Some(package.identity.as_str()))
            );
        }
        let overlay = BTreeMap::from([(
            root.join("app/src/value.ko"),
            "module App { export fn value(int ignored) -> int { arithmetic::base() } }".into(),
        )]);
        let changed = provider.reload(&overlay).unwrap();
        let LoadedProjectGraph::Package(graph) = &changed.targets[0].project.graph else {
            panic!("library graph")
        };
        let warnings = BuildDriver::new(CompilerSession::default(), "library-lsp")
            .check_package_project(graph.clone())
            .unwrap();
        assert!(
            warnings
                .iter()
                .any(|warning| warning.package_identity.as_deref()
                    == Some(graph.package.identity.as_str()))
        );
        assert_eq!(
            changed.targets[0].project.lints.level("unused-parameter"),
            LintLevel::Deny
        );
        assert!(
            !std::fs::read_to_string(root.join("app/src/value.ko"))
                .unwrap()
                .contains("ignored")
        );
        let invalid_dependency = BTreeMap::from([(
            root.join("math/src/base.ko"),
            "module Math { export fn base() -> int { true } }".into(),
        )]);
        let changed = provider.reload(&invalid_dependency).unwrap();
        let LoadedProjectGraph::Package(graph) = &changed.targets[0].project.graph else {
            panic!("library graph")
        };
        let diagnostics = BuildDriver::new(CompilerSession::default(), "library-lsp")
            .check_package_project(graph.clone())
            .unwrap_err()
            .into_diagnostics()
            .unwrap();
        assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.primary_span.as_ref().is_some_and(|span| {
                span.package_identity.as_deref() == Some(graph.dependencies[0].identity.as_str())
            })
        }));
        std::fs::write(
            root.join("app/src/value.ko"),
            "module App { export fn value(int ignored) -> int { arithmetic::base() } }",
        )
        .unwrap();
        let error = build::run_build(Some(&root.join("app/Musubi.toml")), "check", &args.build)
            .err()
            .expect("denied library lint");
        assert!(
            error.render_human().contains("unused"),
            "{}",
            error.render_human()
        );
    }
    #[test]
    fn lsp_and_test_options_preserve_canonical_project_context() {
        let Cli {
            command: Command::Test(test),
            ..
        } = Cli::try_parse_from([
            "musubi",
            "test",
            "--package",
            "apps.sora/editor",
            "--contract",
            "a",
            "--filter",
            "works",
            "--exact",
        ])
        .unwrap()
        else {
            panic!("test")
        };
        assert_eq!(test.contract.as_deref(), Some("a"));
        assert_eq!(test.filter.as_deref(), Some("works"));
        assert!(test.exact);
        assert!(Cli::try_parse_from(["musubi", "check", "--filter", "works"]).is_err());
        assert!(Cli::try_parse_from(["musubi", "lsp", "--project", "old.json"]).is_err());
    }
    #[test]
    fn lsp_source_closure_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let temp = fixture();
        let args = args();
        let prepared = build::prepare_project(
            Some(&temp.path().join("Musubi.toml")),
            &args.build,
            network::NetworkPurpose::LocalCompilation,
        )
        .unwrap();
        let mut provider = WorkspaceProvider {
            manifest: prepared.workspace.root_manifest_path().to_path_buf(),
            selection: &args.build.selection,
            contract: None,
            cache: None,
            network_id: None,
            chain_discriminant: 753,
            explicit_network: None,
            config_path: None,
        };
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("common.ko"), "fn common() -> int { 9 }").unwrap();
        std::fs::remove_file(temp.path().join("common.ko")).unwrap();
        symlink(
            outside.path().join("common.ko"),
            temp.path().join("common.ko"),
        )
        .unwrap();
        assert!(provider.reload(&BTreeMap::new()).is_err());
    }
}
