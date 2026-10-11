//! Package build and test presentation with explicit network context and complete diagnostics.
use super::*;
use crate::{
    compiler::{CompilerArtifactV1, CompilerExecutionV1},
    test_runner::WorkspaceTestReportV1,
};

pub(super) fn run_build(
    explicit_manifest: Option<&Path>,
    command: &'static str,
    args: &BuildArgs,
) -> CommandResult {
    run_build_with_warnings(explicit_manifest, command, args, None).map(|(success, _)| success)
}

/// Run `check`, `build` or `test`, also returning canonical lint warnings for SARIF output.
pub(super) fn run_build_with_warnings(
    explicit_manifest: Option<&Path>,
    command: &'static str,
    args: &BuildArgs,
    test: Option<&TestArgs>,
) -> Result<(Success, kotodama_lang::diagnostic::DiagnosticBundle), Diagnostic> {
    let PreparedBuild {
        workspace,
        selected_names,
        network,
        graph,
        cache,
        archives,
        execution,
    } = prepare_build(
        explicit_manifest,
        args,
        if command == "build" {
            CompilerActionV1::Build
        } else {
            CompilerActionV1::Check
        },
        network::NetworkPurpose::LocalCompilation,
    )?;
    let chain_discriminant = graph.account_chain_discriminant()?;
    let warnings = leveled_warnings(execution.warnings.clone(), args.deny_warnings)
        .map_err(compiler_bundle_diagnostic)?;
    let mut data = Map::from_iter([
        ("network".to_owned(), network.json()),
        (
            "validated_packages".to_owned(),
            Value::from(execution.validated_packages as u64),
        ),
        (
            "contract_targets".to_owned(),
            Value::from(execution.contract_targets as u64),
        ),
        (
            "warnings".to_owned(),
            Value::from(execution.warnings.len() as u64),
        ),
        (
            "diagnostics".to_owned(),
            Value::Array(
                warnings
                    .diagnostics
                    .iter()
                    .map(kotodama_lang::diagnostic::Diagnostic::to_json_value)
                    .collect(),
            ),
        ),
        ("zk".to_owned(), Value::Bool(args.zk)),
        ("archives".to_owned(), Value::Array(archives)),
        ("lock".to_owned(), lockfile_json(&graph.lock)),
    ]);
    let mut human = network_header(&network, chain_discriminant);
    if !warnings.diagnostics.is_empty() {
        human.push_str(&warnings.render_human());
        human.push('\n');
    }
    if command == "test" {
        let mut options = WorkspaceTestOptionsV1::new(chain_discriminant);
        options.zk_enabled = args.zk;
        if let Some(test) = test {
            options.filter.clone_from(&test.filter);
            options.exact = test.exact;
            options.contract.clone_from(&test.contract);
        }
        let report = execute_workspace_tests_v1(
            cache.as_ref(),
            &workspace,
            &selected_names,
            &graph.lock,
            &options,
        )
        .map_err(|error| graph_mode_test_diagnostic(&error, args.mode))?;
        let (summary, tests) = render_test_report(&report);
        human.push_str(&summary);
        data.extend(tests);
        if !report.is_success() {
            let failed = report.failed();
            return Err(Diagnostic::new(
                ErrorCode::TestFailed,
                format!(
                    "Kotodama tests failed: {failed} of {} failed",
                    report.passed() + failed
                ),
            )
            .with_report(human, &Value::Object(data)));
        }
    } else {
        append_build_completion(
            &mut human,
            &mut data,
            command,
            &execution,
            workspace.root_manifest_path(),
            &network,
        );
    }
    Ok((
        Success {
            message: human,
            data: Value::Object(data),
        },
        warnings,
    ))
}

/// Apply `--deny-warnings` to the lint findings of a check. Findings denied by `[lints]` or by
/// the flag are errors and fail the command with the complete set of findings.
fn leveled_warnings(
    mut warnings: Vec<kotodama_lang::diagnostic::Diagnostic>,
    deny_warnings: bool,
) -> Result<kotodama_lang::diagnostic::DiagnosticBundle, kotodama_lang::diagnostic::DiagnosticBundle>
{
    use kotodama_lang::diagnostic::{DiagnosticBundle, Severity};
    if deny_warnings {
        for warning in &mut warnings {
            warning.severity = Severity::Error;
        }
    }
    let bundle = DiagnosticBundle::new(warnings);
    if bundle
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        Err(bundle)
    } else {
        Ok(bundle)
    }
}

/// Describe which address profile the selected sources were compiled for.
fn network_header(network: &network::SelectedNetwork, chain_discriminant: u16) -> String {
    match network.network_id {
        Some(id) => format!(
            "Network: {} (address profile {chain_discriminant})\nNetwork identity: {id}\n",
            network.name
        ),
        None if network.name == network::LOCAL_NETWORK_NAME => format!(
            "Local compilation for address profile {chain_discriminant}; no deployment network is selected.\n"
        ),
        None => format!(
            "Network: {} (address profile {chain_discriminant})\nLocal compilation; the deployment network is not configured.\n",
            network.name
        ),
    }
}

/// Append the build/check completion summary, artifacts and package interfaces.
fn append_build_completion(
    human: &mut String,
    data: &mut Map,
    command: &'static str,
    execution: &CompilerExecutionV1,
    manifest: &Path,
    network: &network::SelectedNetwork,
) {
    let _ = writeln!(
        human,
        "{command} completed: {} package(s), {} contract target(s), {} warning(s)",
        execution.validated_packages,
        execution.contract_targets,
        execution.warnings.len()
    );
    for artifact in &execution.artifacts {
        human.push_str(&render_artifact(artifact));
    }
    if let [artifact] = execution.artifacts.as_slice() {
        human.push_str(&deployment_next_step(manifest, network, artifact));
    }
    data.insert(
        "artifacts".to_owned(),
        Value::Array(execution.artifacts.iter().map(artifact_json).collect()),
    );
    data.insert(
        "interfaces".to_owned(),
        Value::Array(
            execution
                .package_interfaces
                .iter()
                .map(|interface| {
                    object([
                        ("package", Value::from(interface.package.to_string())),
                        (
                            "digest",
                            Value::from(hex::encode(interface.digest.as_bytes())),
                        ),
                    ])
                })
                .collect(),
        ),
    );
}

fn deployment_next_step(
    manifest: &Path,
    network: &network::SelectedNetwork,
    artifact: &CompilerArtifactV1,
) -> String {
    let key = network::contract_key(&artifact.package, &artifact.target);
    let invocation = format!(
        "musubi --manifest-path {}",
        quote_cli_argument(&manifest.display().to_string())
    );
    let client = network.config.as_ref().map(|path| {
        format!(
            " --config {}",
            quote_cli_argument(&path.display().to_string())
        )
    });
    if network.network_id.is_some()
        && network.fee_payment.is_some()
        && network.contracts.contains_key(&key)
    {
        format!(
            "Next: {invocation} deploy --network {}{} --package {} --contract {}\n",
            network.name,
            client.unwrap_or_default(),
            quote_cli_argument(&artifact.package.to_string()),
            quote_cli_argument(&artifact.target)
        )
    } else {
        let target = if network.network_id.is_none() && network.name == network::LOCAL_NETWORK_NAME
        {
            "taira"
        } else {
            network.name.as_str()
        };
        let (setup, client) = match client {
            Some(client) => (
                "Bind an alias in a domain owned by the selected account; the existing fee policy is retained.\n".to_owned(),
                client,
            ),
            None if target == "taira" => (
                "For a new Taira account, run `musubi wallet create`, `musubi wallet fund`, and `musubi wallet namespace <your-domain>`.\n".to_owned(),
                " --wallet default".to_owned(),
            ),
            None => (
                format!("Select a funded wallet for {} and acquire a domain for that account.\n", network.name),
                " --wallet <wallet-for-network>".to_owned(),
            ),
        };
        format!(
            "{setup}Next: {invocation} network configure {target}{client} --package {} --contract {} --alias <name::your-domain>\n",
            quote_cli_argument(&artifact.package.to_string()),
            quote_cli_argument(&artifact.target)
        )
    }
}

pub(super) struct PreparedBuild {
    pub(super) workspace: Workspace,
    pub(super) selected_names: Vec<MusubiPackageSelectorV1>,
    pub(super) network: network::SelectedNetwork,
    pub(super) graph: ResolvedWorkspaceGraphV1,
    pub(super) cache: Option<MusubiCache>,
    pub(super) archives: Vec<Value>,
    pub(super) execution: crate::compiler::CompilerExecutionV1,
}

pub(super) struct PreparedProject {
    pub(super) workspace: Workspace,
    pub(super) selected_names: Vec<MusubiPackageSelectorV1>,
    pub(super) network: network::SelectedNetwork,
    pub(super) graph: ResolvedWorkspaceGraphV1,
    pub(super) cache: Option<MusubiCache>,
    pub(super) archives: Vec<Value>,
}
pub(super) fn prepare_project(
    explicit_manifest: Option<&Path>,
    args: &BuildArgs,
    purpose: network::NetworkPurpose,
) -> Result<PreparedProject, Diagnostic> {
    let (workspace, selected_names) = load_selected_workspace(explicit_manifest, &args.selection)?;
    let network = network::select_network(
        workspace.root(),
        args.network.as_deref(),
        args.registry.config.as_deref(),
        args.chain_discriminant,
        purpose,
    )?;
    let previous = read_optional_workspace_lock(&workspace)?;
    let graph = resolve_and_persist_graph(
        &workspace,
        &selected_names,
        previous,
        None,
        WorkspaceResolutionOptionsV1 {
            cache_root: None,
            archive_transport: None,
            config_image: network.config_image.clone(),
            expected_network_id: network.network_id,
            mode: args.mode,
            config: network.config.as_deref(),
            fresh_only: false,
            purpose: GraphPurposeV1::Workspace,
            requested_chain_discriminant: Some(network.chain_discriminant),
        },
    )?;
    let cache = if graph.lock.nodes.is_empty() {
        None
    } else {
        Some(open_user_cache()?)
    };
    let archives = match &cache {
        Some(cache) => ensure_graph_archives(cache, &graph, args.mode)?,
        None => Vec::new(),
    };
    Ok(PreparedProject {
        workspace,
        selected_names,
        network,
        graph,
        cache,
        archives,
    })
}
pub(super) fn prepare_build(
    explicit_manifest: Option<&Path>,
    args: &BuildArgs,
    action: CompilerActionV1,
    purpose: network::NetworkPurpose,
) -> Result<PreparedBuild, Diagnostic> {
    let PreparedProject {
        workspace,
        selected_names,
        network,
        graph,
        cache,
        archives,
    } = prepare_project(explicit_manifest, args, purpose)?;
    let chain_discriminant = graph.account_chain_discriminant()?;
    let execution = execute_compiler_graph(
        cache.as_ref(),
        &workspace,
        &selected_names,
        &graph.lock,
        action,
        CompilerSettingsV1 {
            chain_discriminant,
            zk_enabled: args.zk,
            profile: &args.profile,
        },
    )
    .map_err(|error| graph_mode_compiler_diagnostic(&error, args.mode))?;
    Ok(PreparedBuild {
        workspace,
        selected_names,
        network,
        graph,
        cache,
        archives,
        execution,
    })
}

/// Exact local package and contract selection retained across a runtime build.
#[derive(Clone, Copy)]
pub struct RuntimePackageSelection<'a> {
    /// Selected manifest handle whose identity the caller retains and revalidates.
    pub manifest: &'a iroha_fs::SelectedRegularFile,
    /// Explicit package selector, if the workspace does not select it implicitly.
    pub package: Option<&'a str>,
    /// Explicit contract target, if the package has more than one.
    pub contract: Option<&'a str>,
    /// Require the existing lock graph without resolving a replacement.
    pub locked: bool,
}

pub(super) fn build_runtime_package(
    config: &iroha::config::Config,
    cache_root: &Path,
    registry_config: Option<&iroha::config::Config>,
    registry_resolver: Option<&crate::deployment_runtime::BuildRegistryResolver>,
    selection: &RuntimePackageSelection<'_>,
    mut archive_transport: Option<PreparedProductionSorafsArchiveTransportV1>,
) -> Result<crate::deployment_runtime::BuiltArtifact, Diagnostic> {
    let RuntimePackageSelection {
        manifest,
        package,
        contract,
        locked,
    } = *selection;
    let mut selection = SelectionArgs {
        packages: package
            .map(str::parse)
            .transpose()
            .map_err(|_| Diagnostic::new(ErrorCode::Usage, "invalid package selector"))?
            .into_iter()
            .collect(),
        ..SelectionArgs::default()
    };
    let manifest_path = project_manifest_path(Some(manifest.path()))?;
    if manifest_path != manifest.path() {
        return Err(Diagnostic::new(
            ErrorCode::Usage,
            "selected manifest path changed during workspace admission",
        ));
    }
    let workspace =
        crate::workspace::load_workspace_from_selected(manifest).map_err(workspace_diagnostic)?;
    if manifest.path() != workspace.root_manifest_path() {
        let member = workspace
            .members()
            .values()
            .find(|member| member.manifest_path == manifest.path())
            .ok_or_else(|| {
                Diagnostic::new(
                    ErrorCode::Usage,
                    "selected manifest has no owning workspace member",
                )
            })?;
        if selection
            .packages
            .iter()
            .any(|package| package != &member.package.selector)
        {
            return Err(Diagnostic::new(
                ErrorCode::Usage,
                "selected member manifest cannot select another package",
            ));
        }
        if selection.packages.is_empty() {
            selection.packages.push(member.package.selector.clone());
        }
    }
    let selected = select_members(&workspace, &selection)?
        .into_iter()
        .map(|member| member.package.selector.clone())
        .collect::<Vec<_>>();
    let previous = read_optional_workspace_lock(&workspace)?;
    let mode = GraphModeArgs {
        locked,
        ..GraphModeArgs::default()
    };
    let resolve_mode = if locked {
        ResolveModeV1::Locked
    } else {
        ResolveModeV1::UpdateLock
    };
    // Local packages must not consult any network file, environment, wallet or registry.
    let local = resolve_workspace_local(&workspace, &selected, previous.clone(), resolve_mode)
        .map_err(graph_diagnostic)?;
    let (outcome, registry, cached_source) = if let Some(outcome) = local {
        (outcome, None, None)
    } else {
        let resolved_registry = registry_resolver
            .map(|resolve| {
                resolve().map_err(|error| {
                    Diagnostic::new(
                        ErrorCode::Registry,
                        format!("cannot resolve authenticated build registry: {error:#}"),
                    )
                })
            })
            .transpose()?
            .flatten();
        let registry_config = resolved_registry
            .as_ref()
            .map(|(config, _)| config)
            .or(registry_config)
            .ok_or_else(|| {
                Diagnostic::new(
                    ErrorCode::Registry,
                    "the selected environment has no authenticated build registry",
                )
            })?;
        if let Some((_, transport)) = &resolved_registry {
            if transport.network_id() != registry_config.network_id {
                return Err(Diagnostic::new(
                    ErrorCode::Registry,
                    "build registry transport belongs to another network",
                ));
            }
            archive_transport = Some(transport.clone());
        }
        let resolver_cache = ResolverIndexCacheV1::open(cache_root)
            .map_err(|error| Diagnostic::new(ErrorCode::CacheCorrupt, error.to_string()))?;
        let cached = if previous.is_some() {
            match resolve_workspace_offline_cached(
                &resolver_cache,
                &workspace,
                &selected,
                previous.clone(),
                None,
                OfflineGraphOptionsV1 {
                    mode: resolve_mode,
                    purpose: GraphPurposeV1::Workspace,
                    expected_binding: Some((
                        registry_config.network_id,
                        registry_config.account_chain_discriminant,
                    )),
                },
            ) {
                Ok(cached) => Some(cached),
                Err(GraphErrorV1::OfflineMiss(_)) => None,
                Err(error) => return Err(graph_diagnostic(error)),
            }
        } else {
            None
        };
        let warm = if let Some(cached) = cached {
            let cache = open_cache_at(cache_root)?;
            if !cached.outcome.changed
                && cached
                    .outcome
                    .lockfile
                    .nodes
                    .iter()
                    .all(|node| cache.load_compiler_package(node).is_ok())
            {
                Some(cached)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(cached) = warm {
            (cached.outcome, None, Some(cached.source))
        } else {
            let client = iroha::client::Client::builder(registry_config.clone())
                .build()
                .map_err(|error| Diagnostic::new(ErrorCode::Network, format!("{error:#}")))?;
            let registry = RegistryReadClientV1::new(
                &client,
                registry_config
                    .torii_request_timeout
                    .min(std::time::Duration::from_secs(60)),
                registry_config.account_chain_discriminant,
            )
            .map_err(|error| registry_diagnostic(error, ErrorCode::Registry))?;
            ensure_network_identity(registry_config.network_id, registry.network_id())?;
            let mut snapshot_mismatches = 0_u8;
            let outcome = loop {
                match resolve_workspace_online_cached(
                    &registry,
                    &resolver_cache,
                    &workspace,
                    &selected,
                    previous.clone(),
                    None,
                    resolve_mode,
                    GraphPurposeV1::Workspace,
                ) {
                    Err(GraphErrorV1::SnapshotChanged) if snapshot_mismatches < 2 => {
                        snapshot_mismatches += 1;
                    }
                    result => break result.map_err(graph_diagnostic)?,
                }
            };
            (outcome, Some(registry), None)
        }
    };
    if outcome.changed {
        write_resolved_lock(&workspace, GraphPurposeV1::Workspace, &outcome.lockfile)?;
    }
    let graph = ResolvedWorkspaceGraphV1 {
        lock: outcome.lockfile,
        registry,
        cached_source,
        prepared_archive_fetch: archive_transport.map(Ok),
        platform_config_provenance: None,
        account_chain_discriminant: Some(config.account_chain_discriminant),
    };
    let cache = if graph.lock.nodes.is_empty() {
        None
    } else {
        Some(open_cache_at(cache_root)?)
    };
    if let Some(cache) = &cache {
        ensure_graph_archives(cache, &graph, mode)?;
    }
    let execution = execute_compiler_graph(
        cache.as_ref(),
        &workspace,
        &selected,
        &graph.lock,
        CompilerActionV1::Build,
        CompilerSettingsV1 {
            chain_discriminant: config.account_chain_discriminant,
            zk_enabled: false,
            profile: "production",
        },
    )
    .map_err(|error| graph_mode_compiler_diagnostic(&error, mode))?;
    let artifact = deploy::select_artifact(&execution.artifacts, contract)?;
    crate::deployment_runtime::BuiltArtifact::from_bytes(deploy::read_selected_artifact(artifact)?)
        .map_err(|error| Diagnostic::new(ErrorCode::PackageInvalid, format!("{error:#}")))
}

fn artifact_json(artifact: &CompilerArtifactV1) -> Value {
    object([
        ("package", Value::from(artifact.package.to_string())),
        ("target", Value::from(artifact.target.clone())),
        ("source", Value::from(artifact.source.clone())),
        (
            "artifact",
            Value::from(artifact.artifact.display().to_string()),
        ),
        (
            "manifest",
            Value::from(artifact.manifest.display().to_string()),
        ),
        (
            "interface",
            Value::from(artifact.interface.display().to_string()),
        ),
        ("code_hash", Value::from(artifact.artifact_hash.clone())),
        ("abi_hash", Value::from(artifact.abi_hash.clone())),
        (
            "entrypoints",
            Value::Array(
                artifact
                    .entrypoints
                    .iter()
                    .cloned()
                    .map(Value::from)
                    .collect(),
            ),
        ),
        ("fresh", Value::from(artifact.fresh)),
    ])
}

fn render_artifact(artifact: &CompilerArtifactV1) -> String {
    format!(
        "{} {}::{}\n  bytecode: {}\n  manifest: {}\n  interface: {}\n  code hash: {}\n  ABI hash: {}\n  entrypoints: {}\n",
        if artifact.fresh { "Fresh" } else { "Built" },
        artifact.package,
        artifact.target,
        artifact.artifact.display(),
        artifact.manifest.display(),
        artifact.interface.display(),
        artifact.artifact_hash,
        artifact.abi_hash,
        artifact.entrypoints.join(", ")
    )
}

fn render_test_report(report: &WorkspaceTestReportV1) -> (String, Map) {
    let mut human = String::new();
    let targets = report
        .targets
        .iter()
        .map(|target| {
            let _ = writeln!(
                human,
                "{}::{} ({})",
                target.package, target.target, target.source
            );
            let cases = target
                .report
                .cases
                .iter()
                .map(|case| {
                    let _ = writeln!(
                        human,
                        "  {} {} (line {})",
                        if case.passed { "PASS" } else { "FAIL" },
                        case.name,
                        case.line
                    );
                    if let Some(failure) = &case.failure {
                        for line in failure.lines() {
                            let _ = writeln!(human, "    {line}");
                        }
                    }
                    object([
                        ("name", Value::from(case.name.clone())),
                        ("line", Value::from(u64::from(case.line))),
                        ("passed", Value::from(case.passed)),
                        ("fault", norito::json!(case.fault)),
                        (
                            "failure",
                            case.failure
                                .as_ref()
                                .map_or(Value::Null, |failure| Value::from(failure.clone())),
                        ),
                    ])
                })
                .collect();
            object([
                ("package", Value::from(target.package.to_string())),
                ("target", Value::from(target.target.clone())),
                ("source", Value::from(target.source.clone())),
                ("cases", Value::Array(cases)),
            ])
        })
        .collect();
    let _ = writeln!(
        human,
        "test completed: {} passed; {} failed",
        report.passed(),
        report.failed()
    );
    (
        human,
        Map::from_iter([
            ("passed".to_owned(), Value::from(report.passed() as u64)),
            ("failed".to_owned(), Value::from(report.failed() as u64)),
            ("targets".to_owned(), Value::Array(targets)),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_warnings_turns_every_lint_finding_into_a_failure() {
        use kotodama_lang::diagnostic::{Diagnostic, DiagnosticPhase, Severity};
        let warning = Diagnostic::warning("K5013", DiagnosticPhase::Semantic, "unused", None);
        let kept = leveled_warnings(vec![warning.clone()], false).expect("warnings do not fail");
        assert_eq!(kept.diagnostics[0].severity, Severity::Warning);
        let denied = leveled_warnings(vec![warning.clone()], true).expect_err("denied");
        assert_eq!(denied.diagnostics[0].severity, Severity::Error);
        let mut by_manifest = warning;
        by_manifest.severity = Severity::Error;
        assert!(leveled_warnings(vec![by_manifest], false).is_err());
        assert!(
            leveled_warnings(Vec::new(), true)
                .expect("nothing to deny")
                .diagnostics
                .is_empty()
        );
    }

    #[test]
    fn copyable_commands_quote_shell_syntax_in_package_paths_and_target_names() {
        for (input, expected) in [
            ("demo/coffee::target", "demo/coffee::target"),
            ("a b", "'a b'"),
            ("quote'one", "'quote'\"'\"'one'"),
            ("quote;echo", "'quote;echo'"),
            ("$(echo)", "'$(echo)'"),
            ("", "''"),
        ] {
            assert_eq!(quote_cli_argument(input), expected);
        }
    }
    use crate::test_runner::WorkspaceTestTargetReportV1;
    use kotodama_toolchain::koto_test_driver::{KotoTestCaseOutcomeV1, KotoTestRunReportV1};

    #[test]
    fn all_named_test_failures_retain_source_line_and_vm_reason() {
        let report = WorkspaceTestReportV1 {
            targets: vec![WorkspaceTestTargetReportV1 {
                package: "demo/coffee-club".parse().expect("package"),
                target: "quote".to_owned(),
                source: "tests/quote.test.ko".to_owned(),
                report: KotoTestRunReportV1 {
                    target: PathBuf::from("tests/quote.test.ko"),
                    seed: 0,
                    cases: vec![
                        KotoTestCaseOutcomeV1 {
                            name: "first".to_owned(),
                            line: 3,
                            passed: false,
                            fault: None,
                            failure: Some("actual 29; expected 30".to_owned()),
                        },
                        KotoTestCaseOutcomeV1 {
                            name: "second".to_owned(),
                            line: 8,
                            passed: false,
                            fault: None,
                            failure: Some("VM gas exhausted".to_owned()),
                        },
                        KotoTestCaseOutcomeV1 {
                            name: "third".to_owned(),
                            line: 13,
                            passed: true,
                            fault: None,
                            failure: None,
                        },
                    ],
                },
            }],
        };
        let (human, json) = render_test_report(&report);
        for detail in [
            "FAIL first (line 3)",
            "actual 29; expected 30",
            "FAIL second (line 8)",
            "VM gas exhausted",
            "PASS third",
            "1 passed; 2 failed",
            "tests/quote.test.ko",
        ] {
            assert!(human.contains(detail), "missing {detail}");
        }
        let json = Value::Object(json);
        assert_eq!(
            json.pointer("/targets/0/cases/1/failure")
                .and_then(Value::as_str),
            Some("VM gas exhausted")
        );
        assert_eq!(
            json.pointer("/targets/0/cases/2/failure"),
            Some(&Value::Null)
        );
    }

    #[test]
    fn artifact_output_exposes_verified_deployment_inputs_and_freshness() {
        let artifact = CompilerArtifactV1 {
            package: "demo/coffee-club".parse().expect("package"),
            target: "coffee-club".to_owned(),
            source: "contracts/coffee-club.ko".to_owned(),
            artifact: PathBuf::from("target/coffee-club.to"),
            manifest: PathBuf::from("target/coffee-club.manifest.json"),
            interface: PathBuf::from("target/coffee-club.interface.json"),
            artifact_hash: "code-digest".to_owned(),
            abi_hash: "abi-digest".to_owned(),
            entrypoints: vec!["quote".to_owned()],
            fresh: true,
        };
        let human = render_artifact(&artifact);
        for detail in [
            "Fresh",
            "coffee-club.to",
            "coffee-club.manifest.json",
            "coffee-club.interface.json",
            "code-digest",
            "abi-digest",
            "quote",
        ] {
            assert!(human.contains(detail));
        }
        let json = artifact_json(&artifact);
        assert_eq!(
            json.get("code_hash").and_then(Value::as_str),
            Some("code-digest")
        );
        assert_eq!(
            json.pointer("/entrypoints/0").and_then(Value::as_str),
            Some("quote")
        );
        let dir = tempfile::tempdir().expect("workspace");
        let mut network = network::select_network(
            dir.path(),
            None,
            None,
            None,
            network::NetworkPurpose::LocalCompilation,
        )
        .expect("network");
        assert_eq!(network.name, network::LOCAL_NETWORK_NAME);
        assert!(
            network_header(&network, network.chain_discriminant)
                .starts_with("Local compilation for address profile 753;")
        );
        let manifest = dir.path().join("Musubi.toml");
        let unbound = deployment_next_step(&manifest, &network, &artifact);
        for expected in [
            "musubi wallet create",
            "musubi wallet fund",
            "musubi wallet namespace <your-domain>",
            "network configure taira --wallet default",
            "--alias <name::your-domain>",
        ] {
            assert!(unbound.contains(expected), "missing {expected}: {unbound}");
        }
        assert!(!unbound.contains("<client.toml>"));
        assert!(!unbound.contains("--fee-payer"));
        network.name = "custom".to_owned();
        let custom = deployment_next_step(&manifest, &network, &artifact);
        assert!(custom.contains("--wallet <wallet-for-network>"));
        assert!(!custom.contains("musubi wallet fund"));
        network.name = "taira".to_owned();
        network.network_id = Some(iroha_data_model::NetworkId::from_genesis_hash(
            iroha::crypto::HashOf::from_untyped_unchecked(iroha::crypto::Hash::new(
                b"test genesis",
            )),
        ));
        network.fee_payment = Some(iroha_data_model::transaction::FeePaymentIntent::authority(
            Vec::new(),
            None,
        ));
        network.config = Some(PathBuf::from("/runtime/selected wallet/client.toml"));
        let missing_alias = deployment_next_step(&manifest, &network, &artifact);
        assert!(missing_alias.contains("--config '/runtime/selected wallet/client.toml'"));
        assert!(missing_alias.contains("existing fee policy is retained"));
        assert!(!missing_alias.contains("--wallet default"));
        assert!(!missing_alias.contains("--fee-payer"));
        network.contracts.insert(
            network::contract_key(&artifact.package, &artifact.target),
            "coffee-club::universal".parse().expect("alias"),
        );
        assert_eq!(
            deployment_next_step(&manifest, &network, &artifact),
            format!(
                "Next: musubi --manifest-path {} deploy --network taira --config '/runtime/selected wallet/client.toml' --package demo/coffee-club --contract coffee-club\n",
                quote_cli_argument(&manifest.display().to_string())
            )
        );
    }

    #[test]
    fn build_completion_reports_counts_artifacts_interfaces_and_single_target_next_step() {
        let artifact = CompilerArtifactV1 {
            package: "demo/coffee-club".parse().expect("package"),
            target: "coffee-club".to_owned(),
            source: "contracts/coffee-club.ko".to_owned(),
            artifact: PathBuf::from("target/coffee-club.to"),
            manifest: PathBuf::from("target/coffee-club.manifest.json"),
            interface: PathBuf::from("target/coffee-club.interface.json"),
            artifact_hash: "code-digest".to_owned(),
            abi_hash: "abi-digest".to_owned(),
            entrypoints: vec!["quote".to_owned()],
            fresh: false,
        };
        let mut execution = CompilerExecutionV1 {
            validated_packages: 2,
            contract_targets: 1,
            warnings: vec![
                kotodama_lang::diagnostic::Diagnostic::warning(
                    "K5001",
                    kotodama_lang::diagnostic::DiagnosticPhase::Semantic,
                    "unused binding",
                    None,
                );
                3
            ],
            artifacts: vec![artifact.clone()],
            package_interfaces: vec![crate::compiler::CompilerPackageInterfaceV1 {
                package: "demo/library".parse().expect("library package"),
                digest: MusubiContentDigestV1::new([7; 32]),
            }],
        };
        let dir = tempfile::tempdir().expect("workspace");
        let network = network::select_network(
            dir.path(),
            None,
            None,
            None,
            network::NetworkPurpose::LocalCompilation,
        )
        .expect("network");
        let manifest = dir.path().join("Musubi.toml");
        let mut human = String::new();
        let mut data = Map::new();
        append_build_completion(
            &mut human, &mut data, "build", &execution, &manifest, &network,
        );
        assert_eq!(
            human,
            format!(
                "build completed: 2 package(s), 1 contract target(s), 3 warning(s)\n{}{}",
                render_artifact(&artifact),
                deployment_next_step(&manifest, &network, &artifact)
            )
        );
        let data = Value::Object(data);
        assert_eq!(
            data.pointer("/artifacts/0"),
            Some(&artifact_json(&artifact))
        );
        assert_eq!(
            data.pointer("/interfaces/0/package")
                .and_then(Value::as_str),
            Some("demo/library")
        );
        assert_eq!(
            data.pointer("/interfaces/0/digest").and_then(Value::as_str),
            Some(hex::encode([7; 32]).as_str())
        );
        execution.artifacts.push(CompilerArtifactV1 {
            target: "second".to_owned(),
            ..artifact
        });
        let mut human = String::new();
        let mut data = Map::new();
        append_build_completion(
            &mut human, &mut data, "check", &execution, &manifest, &network,
        );
        assert!(human.starts_with("check completed: 2 package(s), 1 contract target(s)"));
        assert!(
            !human.contains("Next:"),
            "several artifacts have no single deployment step: {human}"
        );
        assert_eq!(
            Value::Object(data)
                .pointer("/artifacts")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
    }
}
