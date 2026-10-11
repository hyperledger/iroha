//! Immutable, confined source-set discovery for authenticated Kotodama test callers.
use super::{
    DiscoveredSuite, DiscoveredTestModule, KotoTestModuleGraphV1, KotoTestRunErrorV1,
    KotoTestRunPhaseV1, KotoTestRunReportV1, KotoTestRunRequestV1, MAX_LOGICAL_SOURCE_PATH_BYTES,
    MAX_MODULE_GRAPH_SOURCE_BYTES, Path, PathBuf, Program, SourceModuleUnit, SourceUnitKind,
    SuiteError, finalize_suite_with_sources, parser, run_discovered_suite_structured,
    validate_standalone_test_items, validate_structured_request, validate_structured_source,
    validate_structured_source_request,
};
/// Run an authenticated test source with its explicitly supplied contract target, if indirect.
///
/// Both immutable source units retain their logical identities. No path is opened, no sibling
/// source is discovered, and target/package/test sources share the same bounded typed graph.
///
/// # Errors
///
/// Returns a stage-tagged error for an invalid source binding, undeclared/mismatched target,
/// parsing, exact linking, compilation, or execution failure.
pub fn run_tests_structured_source_set_with_modules_v1(
    request: &KotoTestRunRequestV1,
    root: &SourceModuleUnit,
    target: Option<&SourceModuleUnit>,
    modules: &KotoTestModuleGraphV1,
) -> Result<KotoTestRunReportV1, KotoTestRunErrorV1> {
    validate_structured_request(request)?;
    validate_structured_source_request(request, root)?;
    let suite =
        discover_declared_suite_from_source_set(root, target, &modules.sources, &modules.artifacts)
            .map_err(|error| {
                KotoTestRunErrorV1::from_suite(KotoTestRunPhaseV1::Discovery, error)
            })?;
    run_discovered_suite_structured(request, suite, Some(modules))
}
/// Resolve a supplied test source's optional target to a confined portable logical path.
///
/// Resolution is lexical and never consults the filesystem. Callers must separately authenticate
/// the returned path against their explicit manifest before loading its immutable source.
///
/// # Errors
///
/// Returns an error for malformed source, nonportable targets, or paths that escape the source root.
pub fn declared_test_target_source_v1(
    root: &SourceModuleUnit,
) -> Result<Option<String>, KotoTestRunErrorV1> {
    let program = parse_source_unit(root)
        .map_err(|error| KotoTestRunErrorV1::from_suite(KotoTestRunPhaseV1::Discovery, error))?;
    declared_test_target(&root.source_name, &program)
        .map_err(|error| KotoTestRunErrorV1::new(KotoTestRunPhaseV1::Discovery, error))
}
fn parse_source_unit(root: &SourceModuleUnit) -> Result<Program, SuiteError> {
    validate_structured_source(root)?;
    let file = kotodama_lang::source::SourceFile::new(
        kotodama_lang::source::SourceId(0),
        root.source_name.as_str(),
        root.source.as_str(),
    );
    parser::parse_source(&file, kotodama_lang::source::FrontendBudget::v1())
        .map_err(SuiteError::Diagnostics)
}
fn declared_test_target(source_name: &str, program: &Program) -> Result<Option<String>, String> {
    let Some(target) = &program.test_target else {
        return Ok(None);
    };
    let raw = &target.target;
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.contains('\\')
        || raw.contains(':')
        || raw.chars().any(char::is_control)
    {
        return Err(format!("{source_name} has a nonportable koto_test target"));
    }
    let mut components = source_name.split('/').collect::<Vec<_>>();
    components.pop();
    for component in raw.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(format!(
                        "{source_name} koto_test target escapes its source root"
                    ));
                }
            }
            component => components.push(component),
        }
    }
    let name = components.join("/");
    if name.is_empty()
        || name.len() > MAX_LOGICAL_SOURCE_PATH_BYTES
        || name
            .split('/')
            .any(|component| component.chars().all(|character| character == '.'))
    {
        return Err(format!(
            "{source_name} has an invalid bounded koto_test target"
        ));
    }
    Ok(Some(name))
}
/// Discover tests from an explicit immutable test/target source set without ambient files.
///
/// # Errors
///
/// Returns an error for a missing or mismatched target, malformed source, or an empty suite.
pub fn discover_declared_test_names_source_set_v1(
    root: &SourceModuleUnit,
    target: Option<&SourceModuleUnit>,
) -> Result<Vec<String>, String> {
    let suite = discover_declared_suite_from_source_set(root, target, &[], &[])?;
    Ok(suite.tests.into_iter().map(|test| test.name).collect())
}
/// Discover tests using the same explicit companion inventory supplied for compilation.
///
/// # Errors
///
/// Returns an error for an invalid or mismatched target, malformed or missing companion
/// source, an exceeded source-set bound, or a source set that declares no tests.
pub fn discover_declared_test_names_source_set_with_sources_v1(
    root: &SourceModuleUnit,
    target: Option<&SourceModuleUnit>,
    sources: &[SourceModuleUnit],
) -> Result<Vec<String>, String> {
    let suite = discover_declared_suite_from_source_set(root, target, sources, &[])?;
    Ok(suite.tests.into_iter().map(|test| test.name).collect())
}
pub(super) fn discover_declared_suite_from_source_set(
    root: &SourceModuleUnit,
    target: Option<&SourceModuleUnit>,
    sources: &[SourceModuleUnit],
    artifacts: &[kotodama_lang::linker::SourceContractArtifact],
) -> Result<DiscoveredSuite, SuiteError> {
    if root
        .source
        .len()
        .saturating_add(target.map_or(0, |target| target.source.len()))
        > MAX_MODULE_GRAPH_SOURCE_BYTES
    {
        return Err(SuiteError::Invalid(format!(
            "supplied Kotodama test source set exceeds {MAX_MODULE_GRAPH_SOURCE_BYTES} UTF-8 bytes"
        )));
    }
    let program = parse_source_unit(root)?;
    let declared_target = declared_test_target(&root.source_name, &program)?;
    let Some(expected) = declared_target else {
        if target.is_some() {
            return Err(SuiteError::Invalid(format!(
                "{} is direct and must not receive a separate target",
                root.source_name
            )));
        }
        return finalize_suite_with_sources(
            PathBuf::from(&root.source_name),
            root.source.clone(),
            program,
            Vec::new(),
            sources.to_vec(),
            artifacts.to_vec(),
            None,
        );
    };
    let target = target.ok_or_else(|| format!("{} is an indirect koto_test module and requires its explicitly supplied target `{expected}`", root.source_name))?;
    validate_structured_source(target)?;
    if target.source_name != expected {
        return Err(SuiteError::Invalid(format!(
            "{} targets `{expected}`, not supplied source `{}`",
            root.source_name, target.source_name
        )));
    }
    validate_standalone_test_items(Path::new(&root.source_name), &program)?;
    let target_program = parse_source_unit(target)?;
    if target_program.unit.kind != SourceUnitKind::Seiyaku || target_program.test_target.is_some() {
        return Err(SuiteError::Invalid(format!(
            "{} is not a direct deployable contract target",
            target.source_name
        )));
    }
    finalize_suite_with_sources(
        PathBuf::from(&target.source_name),
        target.source.clone(),
        target_program,
        vec![DiscoveredTestModule {
            path: PathBuf::from(&root.source_name),
            source: root.source.clone(),
            program,
        }],
        sources.to_vec(),
        artifacts.to_vec(),
        None,
    )
}
