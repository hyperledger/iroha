// Test body included from command.rs to keep the production source budget bounded.
use super::*;
#[cfg(unix)]
use crate::package::PackageCar;
use crate::{
    lockfile::LockedRootV1,
    output::{OUTPUT_SCHEMA, OUTPUT_VERSION},
    publish::{PublicationAmxSubmissionV1, PublicationFinalCheckpointV1},
};
use clap::CommandFactory as _;
use iroha::crypto::{Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::{AccountId, address::ChainDiscriminantGuard},
    block::BlockHeader,
    musubi::{
        ArchiveId, MusubiAbiBindingV1, MusubiDescriptionV1, MusubiInvitationStateV1,
        MusubiKeywordV1, MusubiMaintainerInvitationV1, MusubiNamespaceBindingV1,
        MusubiOrderedPackageEntryV1, MusubiOrderedPackagePageV1, MusubiOrderedPrefixQueryV1,
        MusubiOrderedPrefixV1, MusubiPackageIdV1, MusubiPackageMemberV1, MusubiPackageScopeV1,
        MusubiRegistrySnapshotV1, MusubiReleaseDigestV1, MusubiSearchHitV1, MusubiSearchPageV1,
        MusubiSearchSnapshotV1, MusubiVerificationNodeV1,
    },
};
#[cfg(unix)]
use iroha_data_model::{
    musubi::{MUSUBI_REGISTRY_VERSION_V1, MusubiPublicationV1, MusubiVerificationLockV1},
    sorafs::capacity::ProviderId,
};
use iroha_model_base::topology::DataSpaceId;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::{io::Write as _, net::TcpListener, thread, time::Duration};
use tempfile::TempDir;
fn test_network_id(byte: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        [byte; Hash::LENGTH],
    )))
}
fn authenticated_registry_config(torii_url: &str, chain_discriminant: u16) -> String {
    authenticated_registry_config_for_network(torii_url, chain_discriminant, test_network_id(0x31))
}
fn authenticated_registry_config_for_network(
    torii_url: &str,
    chain_discriminant: u16,
    network_id: NetworkId,
) -> String {
    let signer =
        KeyPair::try_from_seed(vec![0x5B; 32], Algorithm::Ed25519).expect("registry signer");
    format!(
        r#"
chain = "musubi-command-test"
network_id = "{}"
torii_url = "{torii_url}"
torii_request_timeout_ms = 2000

[account]
chain_discriminant = {chain_discriminant}
public_key = "{}"
private_key = "{}"
"#,
        network_id,
        signer.public_key(),
        ExposedPrivateKey(signer.private_key().clone()),
    )
}
/// Create a retention reader bound to the fixture network before receiving a batch.
fn retention_registry_reader(torii_url: &str) -> RegistryReadClientV1 {
    let config = authenticated_registry_config_for_network(torii_url, 753, test_network_id(0x81));
    RegistryReadClientV1::load_from_config_bytes(
        Path::new("command-retention-reader-test.toml"),
        config.as_bytes(),
    )
    .expect("authenticated registry client on the retention fixture network")
}
#[test]
fn resolver_search_limit_has_a_resource_corridor_diagnostic() {
    let diagnostic = graph_diagnostic(GraphErrorV1::Resolver(ResolverError::SearchLimitExceeded {
        limit: 16_384,
    }));
    assert_eq!(diagnostic.code(), ErrorCode::ResolutionConflict);
    assert_eq!(
        diagnostic
            .context()
            .get("candidate_branch_attempt_limit")
            .map(String::as_str),
        Some("16384")
    );
}
fn command_names(command: &clap::Command) -> BTreeSet<String> {
    command
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .collect()
}
fn command_aliases(command: &clap::Command) -> BTreeSet<String> {
    let mut aliases = command
        .get_all_aliases()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for subcommand in command.get_subcommands() {
        aliases.extend(command_aliases(subcommand));
    }
    aliases
}
fn command_long_options(command: &clap::Command) -> BTreeSet<String> {
    let mut options = command
        .get_arguments()
        .filter_map(|argument| argument.get_long().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for subcommand in command.get_subcommands() {
        options.extend(command_long_options(subcommand));
    }
    options
}
fn create_test_package(temp: &TempDir) -> (PathBuf, PathBuf) {
    let root = temp.path().join("demo");
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("new"),
        root.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("library"),
        OsString::from("--namespace"),
        OsString::from("apps.sora"),
        OsString::from("--export"),
        OsString::from("run"),
    ]);
    assert_eq!(invocation.output.exit_code(), 0);
    let manifest = root.join(MANIFEST_FILE_NAME);
    (root, manifest)
}

fn assert_scaffold_compiler_workflows(root: &Path, cache_root: &Path) {
    write_test_lock(root);
    let workspace = load_workspace(root).expect("scaffold workspace");
    let selector = "apps.sora/demo".parse().expect("scaffold selector");
    let lock = LockfileV1::read(&root.join(LOCK_FILE_NAME)).expect("scaffold lock");
    let cache = MusubiCache::open(cache_root).expect("empty private compiler cache");
    let mut interfaces = None;
    for action in [CompilerActionV1::Check, CompilerActionV1::Build] {
        let execution = execute_compiler_graph(
            Some(&cache),
            &workspace,
            std::slice::from_ref(&selector),
            &lock,
            action,
            CompilerSettingsV1 {
                chain_discriminant: 753,
                zk_enabled: false,
                profile: "dev",
            },
        )
        .expect("canonical scaffold compiler workflow");
        assert_eq!(execution.validated_packages, 1);
        assert_eq!(execution.contract_targets, 0);
        assert!(execution.warnings.is_empty());
        assert!(
            execution.artifacts.is_empty(),
            "a library is not a contract"
        );
        assert_eq!(execution.package_interfaces.len(), 1);
        assert_eq!(execution.package_interfaces[0].package, selector);
        assert!(!execution.package_interfaces[0].digest.is_zero());
        if let Some(expected) = &interfaces {
            assert_eq!(&execution.package_interfaces, expected);
        }
        interfaces = Some(execution.package_interfaces);
    }
}

#[test]
fn new_and_init_scaffolds_check_and_build_with_exact_exports() {
    for command in ["new", "init"] {
        for exports in [vec![], vec!["route", "quote", "route"]] {
            let temp = TempDir::new().expect("scaffold directory");
            let root = temp.path().join("demo");
            if command == "init" {
                fs::create_dir(&root).expect("existing init directory");
            }
            let mut arguments = vec![
                OsString::from("musubi"),
                OsString::from(command),
                root.as_os_str().to_owned(),
                OsString::from("--template"),
                OsString::from("library"),
                OsString::from("--namespace"),
                OsString::from("apps.sora"),
            ];
            for name in &exports {
                arguments.extend([OsString::from("--export"), OsString::from(name)]);
            }
            assert_eq!(invoke(arguments).output.exit_code(), 0);
            let source = fs::read_to_string(root.join("src/lib.ko")).expect("scaffold source");
            assert!(source.contains("module Library {"));
            assert!(source.contains("TODO: Define the library interface"));
            let program = kotodama_lang::parser::parse(&source).expect("canonical module grammar");
            let expected = exports.into_iter().collect::<BTreeSet<_>>();
            let functions = program
                .items
                .iter()
                .map(|item| match item {
                    kotodama_lang::ast::Item::Function(function) => function.name.as_str(),
                    _ => panic!("scaffold must contain only placeholder functions"),
                })
                .collect::<Vec<_>>();
            assert_eq!(functions, expected.iter().copied().collect::<Vec<_>>());
            assert_eq!(
                program
                    .exports
                    .iter()
                    .map(|export| export.name.as_str())
                    .collect::<Vec<_>>(),
                functions,
                "the generated source must explicitly expose its manifest exports",
            );
            let manifest = parse_manifest(
                &fs::read_to_string(root.join(MANIFEST_FILE_NAME)).expect("scaffold manifest"),
            )
            .expect("canonical scaffold manifest");
            assert_eq!(
                manifest
                    .library
                    .expect("library manifest")
                    .exports
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<_>>(),
                functions,
            );
            assert_scaffold_compiler_workflows(&root, &temp.path().join("compiler-cache"));
        }
    }
}

#[test]
fn scaffold_rejects_noncanonical_and_reserved_exports_before_writing() {
    for name in [
        "bad-name",
        "café",
        "fn",
        "int",
        "__kotodama_link_user",
        "run(){}//",
        "run/*x*/",
    ] {
        let temp = TempDir::new().expect("invalid scaffold directory");
        let new_root = temp.path().join("new-package");
        let new = invoke([
            OsString::from("musubi"),
            OsString::from("new"),
            new_root.as_os_str().to_owned(),
            OsString::from("--template"),
            OsString::from("library"),
            OsString::from("--namespace"),
            OsString::from("apps.sora"),
            OsString::from("--export"),
            OsString::from(name),
        ]);
        assert_eq!(
            new.output.exit_code(),
            ErrorCode::Usage.exit_code(),
            "{name}"
        );
        assert!(
            !new_root.exists(),
            "invalid export must not create a package"
        );
        let (root, manifest_path) = create_test_package(&temp);
        let manifest = fs::read(&manifest_path).expect("original manifest");
        let library = fs::read(root.join("src/lib.ko")).expect("original source");
        let init = invoke([
            OsString::from("musubi"),
            OsString::from("init"),
            root.as_os_str().to_owned(),
            OsString::from("--force"),
            OsString::from("--template"),
            OsString::from("library"),
            OsString::from("--namespace"),
            OsString::from("apps.sora"),
            OsString::from("--export"),
            OsString::from(name),
        ]);
        assert_eq!(
            init.output.exit_code(),
            ErrorCode::Usage.exit_code(),
            "{name}"
        );
        assert_eq!(
            fs::read(&manifest_path).expect("unchanged manifest"),
            manifest
        );
        assert_eq!(
            fs::read(root.join("src/lib.ko")).expect("unchanged source"),
            library
        );
    }
}

#[test]
fn init_preserves_existing_type_exports_and_custom_source_directory() {
    let temp = TempDir::new().expect("existing library directory");
    let root = temp.path().join("demo");
    fs::create_dir_all(root.join("library")).expect("custom source directory");
    let source = "module Existing { export struct Receipt { int value; } export struct require { int value; } }\n";
    assert!(kotodama_surface::source_policy::is_reserved_source_declaration("require", true));
    assert!(!kotodama_surface::source_policy::is_reserved_source_type_declaration("require"));
    let library = root.join("library/lib.ko");
    fs::write(&library, source).expect("existing type export");
    for force in [false, true] {
        let mut arguments = vec![
            OsString::from("musubi"),
            OsString::from("init"),
            root.as_os_str().to_owned(),
            OsString::from("--template"),
            OsString::from("library"),
            OsString::from("--namespace"),
            OsString::from("apps.sora"),
            OsString::from("--source-dir"),
            OsString::from("library"),
            OsString::from("--export"),
            OsString::from("Receipt"),
            OsString::from("--export"),
            OsString::from("require"),
        ];
        if force {
            arguments.push(OsString::from("--force"));
        }
        assert_eq!(invoke(arguments).output.exit_code(), 0);
        assert_eq!(
            fs::read_to_string(&library).expect("preserved source"),
            source
        );
        assert!(!root.join("src").exists());
    }
    assert_scaffold_compiler_workflows(&root, &temp.path().join("compiler-cache"));
}

#[test]
fn new_source_rejects_function_only_reserved_exports_before_writing() {
    for command in ["new", "init"] {
        let temp = TempDir::new().expect("scaffold directory");
        let root = temp.path().join("demo");
        if command == "init" {
            fs::create_dir(&root).expect("existing empty package directory");
        }
        let invocation = invoke([
            OsString::from("musubi"),
            OsString::from(command),
            root.as_os_str().to_owned(),
            OsString::from("--template"),
            OsString::from("library"),
            OsString::from("--namespace"),
            OsString::from("apps.sora"),
            OsString::from("--export"),
            OsString::from("require"),
        ]);
        assert_eq!(invocation.output.exit_code(), ErrorCode::Usage.exit_code());
        if command == "new" {
            assert!(!root.exists());
        } else {
            assert_eq!(
                fs::read_dir(&root).expect("unchanged empty root").count(),
                0
            );
        }
    }
}

#[test]
fn preserved_source_disappearance_or_substitution_never_creates_a_scaffold() {
    for replacement in ["missing", "directory", "symlink"] {
        let temp = TempDir::new().expect("preserved source directory");
        let root = temp.path().join("demo");
        fs::create_dir_all(root.join("src")).expect("library source directory");
        let source_dir = PortablePath::new("src").expect("source directory");
        let library = root.join("src/lib.ko");
        fs::write(&library, "module Existing { struct assert { int value; } }")
            .expect("existing type export");
        let choice = prepare_existing_package_library(
            &root,
            &source_dir,
            &["assert".parse().expect("export name")],
        )
        .expect("preserve valid type export");
        assert!(matches!(choice, PackageLibrarySource::Existing));
        fs::remove_file(&library).expect("remove selected existing source");
        let other = temp.path().join("other.ko");
        fs::write(&other, "untouched").expect("unrelated source");
        match replacement {
            "directory" => fs::create_dir(&library).expect("substitute directory"),
            "symlink" => std::os::unix::fs::symlink(&other, &library).expect("substitute link"),
            _ => {}
        }
        let error = initialize_package_files(&root, &source_dir, "unused manifest", &choice)
            .expect_err("changed source must not fall back to scaffold generation");
        assert_eq!(error.code(), ErrorCode::Io);
        assert!(!root.join(MANIFEST_FILE_NAME).exists());
        assert_eq!(
            fs::read_to_string(&other).expect("unrelated source"),
            "untouched"
        );
        if replacement == "missing" {
            assert!(!library.exists());
        }
    }
}

#[test]
fn prepared_scaffold_never_overwrites_a_concurrently_created_library() {
    let temp = TempDir::new().expect("scaffold directory");
    let root = temp.path().join("demo");
    fs::create_dir(&root).expect("empty package directory");
    let source_dir = PortablePath::new("src").expect("source directory");
    let choice = prepare_existing_package_library(
        &root,
        &source_dir,
        &["run".parse().expect("export name")],
    )
    .expect("prepare scaffold before writes");
    assert!(matches!(choice, PackageLibrarySource::Scaffold(_)));
    fs::create_dir(root.join("src")).expect("concurrent source directory");
    let library = root.join("src/lib.ko");
    let existing = "module UserLibrary { fn run() {} }\n";
    fs::write(&library, existing).expect("concurrent user source");
    let error = initialize_package_files(&root, &source_dir, "unused manifest", &choice)
        .expect_err("concurrent user source must not be overwritten");
    assert_eq!(error.code(), ErrorCode::Io);
    assert_eq!(
        fs::read_to_string(&library).expect("preserved source"),
        existing
    );
    assert!(!root.join(MANIFEST_FILE_NAME).exists());
}

fn test_account(seed: u8) -> AccountId {
    let keypair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("derive test account");
    AccountId::new(keypair.public_key().clone())
}
#[cfg(unix)]
struct RecoveryPackageFixture {
    publication: MusubiPublicationV1,
    archive_commitment: iroha_data_model::musubi::MusubiArchiveCommitmentV1,
    car: PackageCar,
}
#[cfg(unix)]
fn recovery_snapshot() -> MusubiRegistrySnapshotV1 {
    MusubiRegistrySnapshotV1 {
        finalized_height: 7,
        finalized_block_hash: [0x42; 32],
        index_revision: 3,
    }
}
#[cfg(unix)]
fn fixture_release(manifest_path: &Path, home_dataspace: u64, domain: &str) -> MusubiReleaseIdV1 {
    let workspace = load_workspace(manifest_path).expect("load fixture workspace");
    let mut members = workspace.members().values();
    let member = members.next().expect("one fixture member");
    assert!(members.next().is_none(), "fixture must have one package");
    MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            DataSpaceId::new(home_dataspace),
            MusubiPackageScopeV1::Domain(domain.parse().expect("fixture package domain")),
            member.package.selector.name.clone(),
        ),
        member.package.version.clone(),
    )
}
#[cfg(unix)]
fn fixture_verification_lock(
    release: MusubiReleaseIdV1,
    root_dependencies: Vec<MusubiExactDependencyEdgeV1>,
    nodes: Vec<MusubiVerificationNodeV1>,
) -> MusubiVerificationLockV1 {
    let mut lock = MusubiVerificationLockV1 {
        schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
        version: MUSUBI_REGISTRY_VERSION_V1,
        root: release,
        root_dependencies,
        nodes,
    };
    lock.canonicalize();
    lock.validate().expect("valid fixture verification lock");
    lock
}
#[cfg(unix)]
fn build_recovery_package(
    manifest_path: &Path,
    cache: &MusubiCache,
    verification_lock: MusubiVerificationLockV1,
) -> RecoveryPackageFixture {
    let workspace = load_workspace(manifest_path).expect("load package fixture workspace");
    let mut members = workspace.members().values();
    let member = members.next().expect("one package fixture member");
    assert!(members.next().is_none(), "fixture must have one package");
    let manifest = publication_manifest_toml(member).expect("canonical package manifest");
    let layout = package_layout_for_member(workspace.root(), member);
    let plan = plan_package(&layout, &manifest, &verification_lock).expect("package plan");
    let interface_digest = validate_packaged_plan(cache, &plan, &verification_lock, 753)
        .expect("clean package validation");
    let semantic = semantic_release_manifest(
        member,
        verification_lock.root.clone(),
        &verification_lock,
        interface_digest,
    )
    .expect("semantic release");
    let car = plan
        .into_car(&semantic, &verification_lock)
        .expect("canonical package CAR");
    let archive_commitment = car.archive_commitment().expect("archive commitment");
    let publication = publication_claim(
        &semantic,
        &archive_commitment,
        recovery_snapshot(),
        verification_lock,
    )
    .expect("publication claim");
    RecoveryPackageFixture {
        publication,
        archive_commitment,
        car,
    }
}
#[cfg(unix)]
fn recovery_request(namespace: &str, package: &RecoveryPackageFixture) -> PublicationRequestV1 {
    let request = PublicationRequestV1 {
        network_id: test_network_id(0x31),
        publisher: test_account(20),
        ingress_broker: test_account(21),
        seed_provider: ProviderId::new([0x32; 32]),
        namespace: namespace.parse().expect("fixture namespace"),
        publication: package.publication.clone(),
        archive_commitment: package.archive_commitment.clone(),
        namespace_delegation: None,
        expected_policy_revision: 1,
        expected_governance_revision: None,
        nonce: [0x33; 32],
    };
    request.validate().expect("valid recovery request");
    request
}
#[cfg(unix)]
fn persist_recovery_request(
    state_root: &Path,
    request: &PublicationRequestV1,
) -> PublicationOperationIdV1 {
    let store = PublicationJournalStore::open(state_root).expect("open recovery journal store");
    let journal = store
        .create(request.clone())
        .expect("persist pristine recovery journal");
    assert_eq!(journal.revision, 1);
    assert_eq!(
        journal.phase,
        crate::publish::PublicationPhaseV1::Validation
    );
    journal.operation_id
}
#[cfg(unix)]
fn create_private_fixture_directory(path: &Path) {
    fs::create_dir(path).expect("create private fixture directory");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("secure private fixture directory");
}
#[cfg(unix)]
fn recovery_publish_args(
    operation_id: PublicationOperationIdV1,
    config: &Path,
    locked: bool,
    offline: bool,
) -> PublishArgs {
    PublishArgs {
        selection: SelectionArgs::default(),
        mode: GraphModeArgs {
            locked,
            offline,
            frozen: false,
        },
        network: NetworkArgs {
            config: Some(config.to_path_buf()),
            ..NetworkArgs::default()
        },
        detach: false,
        resume: None,
        recover: Some(operation_id),
    }
}
#[cfg(unix)]
fn write_poisoned_recovery_config(root: &Path) -> PathBuf {
    let config = root.join("client.toml");
    fs::write(
        &config,
        r#"torii_url = "http://127.0.0.1:9/"
torii_request_timeout_ms = 1

[account]
chain_discriminant = 753
public_key = "deliberately-not-a-key"
private_key = "deliberately-not-a-key"

[musubi.fetch]
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
client_id = "recovery-test"
request_timeout_ms = 1

[[musubi.fetch.provider_gateways]]
provider_id = "1111111111111111111111111111111111111111111111111111111111111111"
url = "https://provider.invalid/"
operator_public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
operator_private_key_file = "missing-provider.key"
"#,
    )
    .expect("write poisoned recovery config");
    config
}
#[cfg(unix)]
fn assert_archive_transport_is_poisoned(config: &Path) {
    let bytes = fs::read(config).expect("read poisoned recovery config");
    let prepared = prepare_production_archive_transport_v1(config, &bytes)
        .expect("parse secret-free fetch configuration");
    assert!(
        build_production_archive_transport_v1(&prepared).is_err(),
        "the absent operator key must make runtime transport construction fail"
    );
}
#[cfg(unix)]
fn assert_no_recovery_sidecars(
    state_root: &Path,
    operation_id: PublicationOperationIdV1,
    expected_size: u64,
) {
    let source = PublicationStagedCarSourceV1::new(state_root, operation_id, expected_size);
    assert!(!source.path().exists(), "recovery CAR must remain absent");
    assert!(
        !source.plan_path().exists(),
        "recovery plan must remain absent"
    );
}
#[cfg(unix)]
fn build_and_install_dependency_fixture(
    root: &Path,
    cache: &MusubiCache,
) -> (MusubiExactDependencyEdgeV1, MusubiVerificationNodeV1) {
    let dependency_root = root.join("dependency");
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("new"),
        dependency_root.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from("library"),
        OsString::from("--namespace"),
        OsString::from("deps.sora"),
        OsString::from("--name"),
        OsString::from("dependency"),
        OsString::from("--version"),
        OsString::from("1.0.0"),
        OsString::from("--export"),
        OsString::from("run"),
    ]);
    assert_eq!(invocation.output.exit_code(), 0);
    let manifest_path = dependency_root.join(MANIFEST_FILE_NAME);
    let release = fixture_release(&manifest_path, 8, "deps");
    let package = build_recovery_package(
        &manifest_path,
        cache,
        fixture_verification_lock(release.clone(), Vec::new(), Vec::new()),
    );
    cache
        .install(
            &package.archive_commitment,
            package.car.plan(),
            std::io::Cursor::new(package.car.bytes()),
        )
        .expect("install dependency fixture in immutable cache");
    let manifest = &package.publication.manifest;
    let node = MusubiVerificationNodeV1 {
        release: release.clone(),
        release_digest: manifest.release_digest(),
        archive_id: package.archive_commitment.archive_id(),
        source_digest: package.archive_commitment.source_tree_digest,
        interface_digest: manifest.interface_digest,
        abi: manifest.abi,
        dependencies: Vec::new(),
    };
    node.validate().expect("valid dependency fixture node");
    let edge = MusubiExactDependencyEdgeV1 {
        alias: "dependency".parse().expect("dependency alias"),
        kind: MusubiDependencyKindV1::Normal,
        package: release.package.clone(),
        requirement: "^1.0.0".parse().expect("dependency requirement"),
        selected: release,
    };
    edge.validate().expect("valid dependency fixture edge");
    (edge, node)
}
fn add_dependency_to_fixture_manifest(manifest_path: &Path) {
    let mut document = fs::read_to_string(manifest_path).expect("read fixture manifest");
    document.push_str(
        "\n[dependencies]\ndependency = { package = \"deps.sora/dependency\", version = \"^1.0.0\" }\n",
    );
    fs::write(manifest_path, document).expect("add fixture dependency");
}
#[cfg(unix)]
fn build_root_recovery_request(
    manifest_path: &Path,
    cache: &MusubiCache,
    dependencies: Vec<MusubiExactDependencyEdgeV1>,
    nodes: Vec<MusubiVerificationNodeV1>,
) -> PublicationRequestV1 {
    let release = fixture_release(manifest_path, 7, "apps");
    let package = build_recovery_package(
        manifest_path,
        cache,
        fixture_verification_lock(release, dependencies, nodes),
    );
    recovery_request("apps.sora", &package)
}
#[cfg(unix)]
fn retarget_recovery_request(
    mut request: PublicationRequestV1,
    name: Option<&str>,
    version: Option<&str>,
) -> PublicationRequestV1 {
    if let Some(name) = name {
        request.publication.resolution.lock.root.package.name =
            name.parse().expect("replacement package name");
    }
    if let Some(version) = version {
        request.publication.resolution.lock.root.version =
            version.parse().expect("replacement package version");
    }
    request.publication.manifest.release = request.publication.resolution.lock.root.clone();
    request.publication.manifest.verification_lock_digest =
        request.publication.resolution.lock.digest();
    request
        .validate()
        .expect("retargeted recovery request remains internally valid");
    request
}
#[cfg(unix)]
fn add_unreachable_recovery_node_unchecked(
    mut request: PublicationRequestV1,
) -> PublicationRequestV1 {
    let release = MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            DataSpaceId::new(99),
            MusubiPackageScopeV1::DataspaceRoot,
            "unreachable".parse().expect("unreachable package name"),
        ),
        "1.0.0".parse().expect("unreachable package version"),
    );
    request
        .publication
        .resolution
        .lock
        .nodes
        .push(MusubiVerificationNodeV1 {
            release,
            release_digest: MusubiReleaseDigestV1::new([0x51; 32]),
            archive_id: ArchiveId::new([0x52; 32]),
            source_digest: MusubiContentDigestV1::new([0x53; 32]),
            interface_digest: MusubiContentDigestV1::new([0x54; 32]),
            abi: MusubiAbiBindingV1::new([0x55; 32]).expect("unreachable node ABI"),
            dependencies: Vec::new(),
        });
    request.publication.resolution.lock.canonicalize();
    request.publication.manifest.verification_lock_digest =
        request.publication.resolution.lock.digest();
    request
}
fn publication_receipt_fixture() -> (MusubiNamespaceV1, PublicationResultV1) {
    let namespace = "apps.sora".parse().expect("fixture namespace");
    let release = MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::Domain("apps".parse().expect("fixture structural domain")),
            "demo".parse().expect("fixture package name"),
        ),
        "1.2.3".parse().expect("fixture release version"),
    );
    let operation_id = "0101010101010101010101010101010101010101010101010101010101010101"
        .parse()
        .expect("fixture operation id");
    let submission = PublicationAmxSubmissionV1 {
        operation_id,
        instruction_digest: [0x18; 32],
        transaction_hash: [0x19; 32],
        applied_height: u64::MAX,
    };
    let final_checkpoint = PublicationFinalCheckpointV1 {
        operation_id,
        network_id: test_network_id(0x11),
        snapshot: MusubiRegistrySnapshotV1 {
            finalized_height: u64::MAX,
            finalized_block_hash: [0x12; 32],
            index_revision: u64::MAX,
        },
        release,
        release_digest: iroha_data_model::musubi::MusubiReleaseDigestV1::new([0x13; 32]),
        archive_id: iroha_data_model::musubi::ArchiveId::new([0x14; 32]),
        home_release_digest: [0x15; 32],
        universal_release_digest: [0x16; 32],
        checkpoint_digest: [0x17; 32],
    };
    (
        namespace,
        PublicationResultV1 {
            operation_id,
            submission,
            final_checkpoint,
        },
    )
}
fn serve_json_sequence(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback registry listener");
    let address = listener.local_addr().expect("loopback registry address");
    let server = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("registry query connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("registry read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2_048];
            let (body_start, content_length) = loop {
                let read = stream.read(&mut buffer).expect("read registry query");
                assert_ne!(read, 0, "registry request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers =
                    std::str::from_utf8(&request[..header_end]).expect("HTTP request headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                break (header_end + 4, content_length);
            };
            while request.len() < body_start + content_length {
                let read = stream.read(&mut buffer).expect("read registry query body");
                assert_ne!(read, 0, "registry request ended before its body");
                request.extend_from_slice(&buffer[..read]);
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .expect("write registry response headers");
            stream
                .write_all(&response)
                .expect("write registry response body");
        }
    });
    (format!("http://{address}/"), server)
}
fn retention_snapshot() -> MusubiRegistrySnapshotV1 {
    MusubiRegistrySnapshotV1 {
        finalized_height: 17,
        finalized_block_hash: [0x71; 32],
        index_revision: 19,
    }
}
fn retention_page(
    network_byte: u8,
    archive_ids: &[iroha_data_model::musubi::ArchiveId],
    prunable: &BTreeSet<iroha_data_model::musubi::ArchiveId>,
) -> iroha_data_model::musubi::MusubiArchiveRetentionPageV1 {
    let snapshot = retention_snapshot();
    iroha_data_model::musubi::MusubiArchiveRetentionPageV1 {
        network_id: test_network_id(network_byte),
        items: archive_ids
            .iter()
            .map(|archive_id| {
                if prunable.contains(archive_id) {
                    iroha_data_model::musubi::MusubiArchiveRetentionDecisionV1 {
                        archive_id: *archive_id,
                        disposition: MusubiArchiveRetentionDispositionV1::PruneUnreferenced,
                        active_releases: 0,
                        yanked_releases: 0,
                        taken_down_releases: 0,
                        storage: Some(iroha_data_model::musubi::MusubiArchiveAvailabilityV1 {
                            archive_id: *archive_id,
                            availability: MusubiStorageAvailabilityV1::Unavailable,
                            healthy_replicas: 0,
                            active_locations: 0,
                            finalized_height: snapshot.finalized_height,
                            finalized_block_hash: snapshot.finalized_block_hash,
                            index_revision: snapshot.index_revision,
                        }),
                    }
                } else {
                    iroha_data_model::musubi::MusubiArchiveRetentionDecisionV1 {
                        archive_id: *archive_id,
                        disposition: MusubiArchiveRetentionDispositionV1::RetainUnknown,
                        active_releases: 0,
                        yanked_releases: 0,
                        taken_down_releases: 0,
                        storage: None,
                    }
                }
            })
            .collect(),
        snapshot,
        finalized_time_ms: 1_700_000_000_000,
    }
}
#[cfg(unix)]
fn create_cache_archive_directory(
    cache: &MusubiCache,
    archive_id: iroha_data_model::musubi::ArchiveId,
) -> PathBuf {
    let path = cache
        .source_path(&archive_id)
        .parent()
        .expect("source path has archive parent")
        .to_path_buf();
    fs::create_dir(&path).expect("create archive cache directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("secure archive cache directory");
    path
}
#[cfg(unix)]
#[test]
fn cache_prune_dry_run_reports_without_mutating() {
    let temporary = TempDir::new().expect("temporary cache root");
    let cache = MusubiCache::open(temporary.path().join("cache")).expect("private cache");
    let archive_id = iroha_data_model::musubi::ArchiveId::new([0x21; 32]);
    let archive_path = create_cache_archive_directory(&cache, archive_id);
    let prunable = BTreeSet::from([archive_id]);
    let page = retention_page(0x81, &[archive_id], &prunable);
    let (torii_url, server) = serve_json_sequence(vec![
        norito::json::to_vec(&page).expect("retention response JSON"),
    ]);
    let registry = retention_registry_reader(&torii_url);
    let result = prune_cache_targets(&cache, &[archive_id], &registry, true)
        .expect("dry-run retention proof");
    assert_eq!(result.message, "would prune 1 cached archive(s)");
    assert!(archive_path.exists(), "dry-run must not rename or delete");
    assert_eq!(
        result
            .data
            .get("removed")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        result
            .data
            .get("candidates")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    server.join().expect("registry server");
}
#[cfg(unix)]
#[test]
fn cache_prune_live_fails_closed_without_touching_any_candidate() {
    let temporary = TempDir::new().expect("temporary cache root");
    let cache = MusubiCache::open(temporary.path().join("cache")).expect("private cache");
    let pruned_id = iroha_data_model::musubi::ArchiveId::new([0x31; 32]);
    let retained_id = iroha_data_model::musubi::ArchiveId::new([0x32; 32]);
    let pruned_path = create_cache_archive_directory(&cache, pruned_id);
    let retained_path = create_cache_archive_directory(&cache, retained_id);
    let pruned_sentinel = pruned_path.join("sentinel");
    let retained_sentinel = retained_path.join("sentinel");
    fs::write(&pruned_sentinel, b"prunable sentinel").expect("write prunable sentinel");
    fs::write(&retained_sentinel, b"retained sentinel").expect("write retained sentinel");
    let pruned_before = fs::symlink_metadata(&pruned_path).expect("prunable identity");
    let retained_before = fs::symlink_metadata(&retained_path).expect("retained identity");
    let archive_ids = [pruned_id, retained_id];
    let prunable = BTreeSet::from([pruned_id]);
    let page = retention_page(0x81, &archive_ids, &prunable);
    let (torii_url, server) = serve_json_sequence(vec![
        norito::json::to_vec(&page).expect("retention response JSON"),
    ]);
    let registry = retention_registry_reader(&torii_url);
    let error = match prune_cache_targets(&cache, &archive_ids, &registry, false) {
        Err(error) => error,
        Ok(_) => panic!("non-empty live prune must fail closed"),
    };
    assert_eq!(error.code(), ErrorCode::Io);
    assert!(
        error
            .context()
            .get("reason")
            .is_some_and(|reason| reason.contains("atomic compare-and-delete"))
    );
    let pruned_after = fs::symlink_metadata(&pruned_path).expect("prunable remains");
    let retained_after = fs::symlink_metadata(&retained_path).expect("retained remains");
    assert_eq!(
        (pruned_before.dev(), pruned_before.ino()),
        (pruned_after.dev(), pruned_after.ino())
    );
    assert_eq!(
        (retained_before.dev(), retained_before.ino()),
        (retained_after.dev(), retained_after.ino())
    );
    assert_eq!(
        fs::read(&pruned_sentinel).expect("read prunable sentinel"),
        b"prunable sentinel"
    );
    assert_eq!(
        fs::read(&retained_sentinel).expect("read retained sentinel"),
        b"retained sentinel"
    );
    assert!(
        fs::read_dir(cache.root().join("registry-v1"))
            .expect("read cache registry")
            .all(|entry| !entry
                .expect("read cache entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".prune."))
    );
    server.join().expect("registry server");
}
#[cfg(unix)]
#[test]
fn cache_prune_rejects_cross_batch_deployment_drift_before_mutation() {
    let temporary = TempDir::new().expect("temporary cache root");
    let cache = MusubiCache::open(temporary.path().join("cache")).expect("private cache");
    let archive_ids = (1_u8..=101)
        .map(|seed| iroha_data_model::musubi::ArchiveId::new([seed; 32]))
        .collect::<Vec<_>>();
    let candidate = archive_ids[0];
    let archive_path = create_cache_archive_directory(&cache, candidate);
    let prunable = BTreeSet::from([candidate]);
    let first = retention_page(
        0x81,
        &archive_ids[..MUSUBI_MAX_ARCHIVE_RETENTION_BATCH_V1],
        &prunable,
    );
    let second = retention_page(
        0x83,
        &archive_ids[MUSUBI_MAX_ARCHIVE_RETENTION_BATCH_V1..],
        &BTreeSet::new(),
    );
    let responses = vec![
        norito::json::to_vec(&first).expect("first retention batch JSON"),
        norito::json::to_vec(&second).expect("second retention batch JSON"),
    ];
    let (torii_url, server) = serve_json_sequence(responses);
    let registry = retention_registry_reader(&torii_url);
    let error = match prune_cache_targets(&cache, &archive_ids, &registry, false) {
        Err(error) => error,
        Ok(_) => panic!("deployment drift must fail closed"),
    };
    assert_eq!(error.code(), ErrorCode::Registry);
    assert!(
        archive_path.exists(),
        "no batch may mutate before full proof"
    );
    server.join().expect("registry server");
}
fn write_test_lock(root: &Path) {
    write_test_lock_graph(root, Vec::new(), Vec::new());
}
fn write_test_lock_with_registry_node(root: &Path) {
    let dependency_package = MusubiPackageIdV1::new(
        DataSpaceId::new(8),
        MusubiPackageScopeV1::DataspaceRoot,
        "dependency".parse().expect("dependency package name"),
    );
    let dependency_release = MusubiReleaseIdV1::new(
        dependency_package.clone(),
        "1.0.0".parse().expect("dependency version"),
    );
    write_test_lock_graph(
        root,
        vec![MusubiExactDependencyEdgeV1 {
            alias: "dependency".parse().expect("dependency alias"),
            kind: MusubiDependencyKindV1::Normal,
            package: dependency_package,
            requirement: "^1.0.0".parse().expect("dependency requirement"),
            selected: dependency_release.clone(),
        }],
        vec![MusubiVerificationNodeV1 {
            release: dependency_release,
            release_digest: MusubiReleaseDigestV1::new([3; 32]),
            archive_id: ArchiveId::new([4; 32]),
            source_digest: MusubiContentDigestV1::new([5; 32]),
            interface_digest: MusubiContentDigestV1::new([6; 32]),
            abi: MusubiAbiBindingV1::new([7; 32]).expect("dependency ABI"),
            dependencies: Vec::new(),
        }],
    );
}
fn write_test_lock_graph(
    root: &Path,
    root_dependencies: Vec<MusubiExactDependencyEdgeV1>,
    nodes: Vec<MusubiVerificationNodeV1>,
) {
    let lock = LockfileV1::new(
        LockContextV1::Registry {
            network_id: test_network_id(1),
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 7,
                finalized_block_hash: [2; 32],
                index_revision: 3,
            },
        },
        vec![LockedRootV1 {
            package: "apps.sora/demo".parse().expect("root package selector"),
            dependencies: root_dependencies,
        }],
        nodes,
    )
    .expect("valid test lock");
    let bytes = lock.render().expect("render lock").into_bytes();
    LockfileV1::parse(std::str::from_utf8(&bytes).expect("UTF-8 lock"))
        .expect("rendered lock parses");
    let lock_path = root.join(LOCK_FILE_NAME);
    fs::write(&lock_path, &bytes).expect("write lock");
    LockfileV1::read(&lock_path).expect("written lock parses");
}
#[test]
fn top_level_and_nested_command_inventory_is_exact() {
    let command = Cli::command();
    assert_eq!(
        command_aliases(&command),
        BTreeSet::new(),
        "Musubi V1 must not retain hidden or visible command aliases"
    );
    assert_eq!(
        command_names(&command),
        BTreeSet::from_iter(
            [
                "add", "alias", "bindgen", "build", "cache", "call", "check", "deploy", "fetch",
                "info", "init", "lsp", "metadata", "network", "new", "owner", "package", "publish",
                "remove", "search", "test", "tree", "unyank", "update", "versions", "view",
                "wallet", "yank",
            ]
            .map(str::to_owned)
        )
    );
    let wallet = command
        .get_subcommands()
        .find(|command| command.get_name() == "wallet")
        .expect("wallet command");
    assert_eq!(
        command_names(wallet),
        BTreeSet::from_iter(
            [
                "balance",
                "create",
                "fund",
                "import",
                "list",
                "namespace",
                "send",
                "show"
            ]
            .map(str::to_owned)
        )
    );
    let network = command
        .get_subcommands()
        .find(|command| command.get_name() == "network")
        .expect("network command");
    assert_eq!(
        command_names(network),
        BTreeSet::from_iter(["configure", "list"].map(str::to_owned))
    );
    let owner = command
        .get_subcommands()
        .find(|command| command.get_name() == "owner")
        .expect("owner command");
    assert_eq!(
        command_names(owner),
        BTreeSet::from_iter(["accept", "invite", "list", "remove", "set-role"].map(str::to_owned))
    );
    let alias = command
        .get_subcommands()
        .find(|command| command.get_name() == "alias")
        .expect("alias command");
    assert_eq!(
        command_names(alias),
        BTreeSet::from_iter(["history", "info", "register", "resolve"].map(str::to_owned))
    );
    let cache = command
        .get_subcommands()
        .find(|command| command.get_name() == "cache")
        .expect("cache command");
    assert_eq!(
        command_names(cache),
        BTreeSet::from_iter(["prune", "repair", "verify"].map(str::to_owned))
    );
}
#[test]
fn retired_commands_and_subcommands_are_rejected() {
    for argv in [
        vec!["musubi", "install"],
        vec!["musubi", "pack"],
        vec!["musubi", "alias", "set"],
        vec!["musubi", "cache", "list"],
        vec!["musubi", "cache", "import"],
        vec!["musubi", "cache", "fetch"],
        vec!["musubi", "publish", "--wait"],
    ] {
        let invocation = invoke(argv);
        assert_eq!(invocation.output.exit_code(), ErrorCode::Usage.exit_code());
    }
}
#[test]
fn argv_has_no_secret_or_arbitrary_cache_source_controls() {
    let options = command_long_options(&Cli::command());
    assert!(options.contains("private-key-file"));
    assert!(
        Cli::try_parse_from([
            "musubi",
            "wallet",
            "import",
            "--private-key",
            "inline-secret"
        ])
        .is_err(),
        "wallet import accepts only a private file path, never an inline signing key"
    );
    for secret_fragment in [
        "authorization",
        "credential",
        "password",
        "private-key",
        "provider-url",
        "secret",
        "source-plan",
        "token",
    ] {
        assert!(
            options
                .iter()
                // This exact option names a held owner-private file; it cannot carry key bytes.
                .filter(|option| option.as_str() != "private-key-file")
                .all(|option| !option.contains(secret_fragment)),
            "secret-bearing --*{secret_fragment}* option is reachable"
        );
    }
    for forbidden in ["cache-dir", "cache-path", "cache-root"] {
        assert!(
            !options.contains(forbidden),
            "arbitrary cache control --{forbidden} is reachable"
        );
    }
}
#[test]
fn frozen_combines_locked_and_offline_at_typed_boundary() {
    let cli = Cli::try_parse_from(["musubi", "fetch", "--frozen"]).expect("parse frozen fetch");
    let Command::Fetch(args) = cli.command else {
        panic!("expected fetch");
    };
    assert!(args.mode.effective_locked());
    assert!(args.mode.effective_offline());
}
#[test]
fn graph_commands_accept_an_explicit_authenticated_registry_config() {
    let cli = Cli::try_parse_from(["musubi", "build", "--config", "/platform/client.toml"])
        .expect("parse registry config");
    let Command::Build(args) = cli.command else {
        panic!("expected build");
    };
    assert_eq!(
        args.registry.config.as_deref(),
        Some(Path::new("/platform/client.toml"))
    );
}
#[test]
fn search_uses_the_authenticated_finalized_projection_route() {
    let selector: MusubiPackageSelectorV1 = "apps.sora/proofs".parse().expect("selector");
    let page = MusubiSearchPageV1 {
        query: MusubiSearchQueryV1 {
            query: "proof systems".to_owned(),
            page: MusubiSearchPageRequestV1 {
                limit: 1,
                cursor: None,
            },
        },
        items: vec![MusubiSearchHitV1 {
            package: MusubiPackageIdV1::new(
                DataSpaceId::new(7),
                MusubiPackageScopeV1::Domain("apps".parse().expect("domain")),
                selector.name,
            ),
            claimed_namespace: selector.namespace,
            description: Some(
                MusubiDescriptionV1::new("Proof systems for Kotodama").expect("description"),
            ),
            keywords: vec![MusubiKeywordV1::from_str("proof-systems").expect("keyword")],
            metadata_revision: 3,
        }],
        next_cursor: None,
        snapshot: MusubiSearchSnapshotV1 {
            finalized_height: 9,
            finalized_block_hash: [4; 32],
            projection_revision: 5,
        },
    };
    page.validate().expect("valid search page");
    let response = {
        let _chain_discriminant = ChainDiscriminantGuard::enter(753);
        norito::json::to_vec(&page).expect("search page JSON")
    };
    let (torii_url, server) = serve_json_sequence(vec![response]);
    let temporary = TempDir::new().expect("temporary config directory");
    let config = temporary.path().join("client.toml");
    fs::write(&config, authenticated_registry_config(&torii_url, 753))
        .expect("write authenticated config");
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("search"),
        OsString::from("proof systems"),
        OsString::from("--limit"),
        OsString::from("1"),
        OsString::from("--config"),
        config.into_os_string(),
    ]);
    assert_eq!(invocation.output.exit_code(), 0);
    let rendered = invocation
        .output
        .render(invocation.format)
        .expect("search JSON output");
    assert!(rendered.stderr().is_empty());
    let document: Value = norito::json::from_str(rendered.stdout()).expect("JSON document");
    assert_eq!(
        document
            .pointer("/data/items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    server.join().expect("registry server");
}
#[test]
fn owner_roles_require_explicit_nonempty_maintainer_permissions() {
    assert_eq!(
        owner_role(RoleArg::Owner, MaintainerPermissionArgs::default()).expect("plain owner role"),
        MusubiPackageRoleV1::Owner
    );
    assert!(
        owner_role(
            RoleArg::Owner,
            MaintainerPermissionArgs {
                publish: true,
                ..MaintainerPermissionArgs::default()
            },
        )
        .is_err()
    );
    assert!(
        owner_role(RoleArg::Maintainer, MaintainerPermissionArgs::default()).is_err(),
        "a maintainer role must not silently receive implicit permissions"
    );
    assert_eq!(
        owner_role(
            RoleArg::Maintainer,
            MaintainerPermissionArgs {
                publish: true,
                metadata: true,
                ..MaintainerPermissionArgs::default()
            },
        )
        .expect("explicit maintainer permissions"),
        MusubiPackageRoleV1::Maintainer(MusubiMaintainerPermissionsV1 {
            publish: true,
            yank: false,
            metadata: true,
            archive_locations: false,
        })
    );
}
#[test]
fn workspace_test_failures_keep_their_stable_boundary_codes() {
    assert_eq!(
        test_runner_diagnostic(&WorkspaceTestErrorV1::UnsupportedPlatform).code(),
        ErrorCode::Io
    );
    assert_eq!(
        test_runner_diagnostic(&WorkspaceTestErrorV1::Workspace("invalid".to_owned())).code(),
        ErrorCode::WorkspaceInvalid
    );
    assert_eq!(
        test_runner_diagnostic(&WorkspaceTestErrorV1::Lock("invalid".to_owned())).code(),
        ErrorCode::LockfileInvalid
    );
    assert_eq!(
        test_runner_diagnostic(&WorkspaceTestErrorV1::Cache("invalid".to_owned())).code(),
        ErrorCode::CacheCorrupt
    );
    assert_eq!(
        test_runner_diagnostic(&WorkspaceTestErrorV1::Runner("failed".to_owned())).code(),
        ErrorCode::Compiler
    );
    assert_eq!(
        test_runner_diagnostic(&WorkspaceTestErrorV1::Execution("fixture".to_owned())).code(),
        ErrorCode::TestFailed
    );
    let bundle = kotodama_lang::diagnostic::DiagnosticBundle::single(
        kotodama_lang::diagnostic::Diagnostic::error(
            "K2003",
            kotodama_lang::diagnostic::DiagnosticPhase::Semantic,
            "operator `+` is not defined for `bool` and `int`",
            Some(kotodama_lang::diagnostic::SourceSpan {
                package_identity: None,
                source: Some("tests/app.test.ko".to_owned()),
                start: kotodama_lang::diagnostic::SourcePosition { line: 3, column: 9 },
                end: kotodama_lang::diagnostic::SourcePosition {
                    line: 3,
                    column: 10,
                },
                byte_range: None,
            }),
        ),
    );
    let rendered = bundle.render_human();
    let compilation = test_runner_diagnostic(&WorkspaceTestErrorV1::Compilation(bundle));
    assert_eq!(compilation.code(), ErrorCode::Compiler);
    assert_eq!(
        compilation.render_human(),
        format!(
            "{rendered}\nerror[MUSUBI_E_COMPILER]: Kotodama rejected the selected test sources\n"
        )
    );
    let output = CommandOutput::failure("test", compilation);
    let json = output.render(OutputFormat::Json).expect("json failure");
    let json: Value = norito::json::from_str(json.stdout()).expect("json document");
    assert_eq!(
        json.pointer("/error/message").and_then(Value::as_str),
        Some("Kotodama rejected the selected test sources")
    );
    assert_eq!(
        json.pointer("/error/diagnostics/0/code")
            .and_then(Value::as_str),
        Some("K2003")
    );
    assert!(json.pointer("/error/details/compiler_output").is_none());
    let sarif = output.render(OutputFormat::Sarif).expect("sarif failure");
    let sarif: Value = norito::json::from_str(sarif.stdout()).expect("sarif document");
    assert_eq!(
        sarif
            .pointer("/runs/0/results/0/ruleId")
            .and_then(Value::as_str),
        Some("K2003")
    );
    assert_eq!(
        package_diagnostic(&PackageError::UnsupportedPlatform).code(),
        ErrorCode::Io
    );
    assert_eq!(
        cache_maintenance_diagnostic(&CacheError::UnsupportedPlatform).code(),
        ErrorCode::Io
    );
}
#[test]
fn invitation_ids_and_compare_and_set_revisions_are_canonical() {
    let invitation = format!("{}1", "0".repeat(63));
    assert_eq!(
        hex::encode(
            parse_invite_id(&invitation)
                .expect("canonical invitation")
                .as_bytes()
        ),
        invitation
    );
    for invalid in [
        "0".repeat(64),
        "A".repeat(64),
        "1".repeat(63),
        format!("{}g", "0".repeat(63)),
    ] {
        assert!(parse_invite_id(&invalid).is_err(), "accepted {invalid}");
    }
    require_nonzero_revision(1, "revision").expect("non-zero revision");
    assert!(require_nonzero_revision(0, "revision").is_err());
}
#[test]
fn owner_invite_parser_requires_explicit_identity_expiry_and_permissions() {
    let invitation = format!("{}1", "0".repeat(63));
    let parsed = Cli::try_parse_from([
        "musubi",
        "owner",
        "invite",
        "apps.sora/demo",
        "ed0120deadbeef",
        "--role",
        "maintainer",
        "--invitation",
        &invitation,
        "--expires-at-height",
        "42",
        "--publish",
        "--expected-revision",
        "7",
    ])
    .expect("complete invite command");
    let Command::Owner(OwnerArgs {
        command:
            OwnerCommand::Invite {
                expires_at_height,
                expected_revision,
                permissions,
                ..
            },
    }) = parsed.command
    else {
        panic!("owner invite command expected");
    };
    assert_eq!(expires_at_height, 42);
    assert_eq!(expected_revision, 7);
    assert!(permissions.publish);
    assert!(
        Cli::try_parse_from([
            "musubi",
            "owner",
            "invite",
            "apps.sora/demo",
            "ed0120deadbeef",
            "--role",
            "maintainer",
            "--expires-at-height",
            "42",
            "--publish",
            "--expected-revision",
            "7",
        ])
        .is_err(),
        "invitation ids must never be synthesized by the CLI"
    );
}
#[test]
fn owner_remove_selects_exactly_one_member_or_pending_invitation() {
    let invitation = format!("{}1", "0".repeat(63));
    let accepted = Cli::try_parse_from([
        "musubi",
        "owner",
        "remove",
        "apps.sora/demo",
        "ed0120deadbeef",
        "--expected-revision",
        "7",
    ])
    .expect("accepted-member removal");
    let Command::Owner(OwnerArgs {
        command:
            OwnerCommand::Remove {
                account,
                invitation: pending,
                ..
            },
    }) = accepted.command
    else {
        panic!("owner remove command expected");
    };
    assert_eq!(account.as_deref(), Some("ed0120deadbeef"));
    assert!(pending.is_none());
    let pending = Cli::try_parse_from([
        "musubi",
        "owner",
        "remove",
        "apps.sora/demo",
        "--invitation",
        &invitation,
        "--expected-revision",
        "7",
    ])
    .expect("pending-invitation revocation");
    let Command::Owner(OwnerArgs {
        command:
            OwnerCommand::Remove {
                account,
                invitation: pending,
                ..
            },
    }) = pending.command
    else {
        panic!("owner remove command expected");
    };
    assert!(account.is_none());
    assert_eq!(pending.as_deref(), Some(invitation.as_str()));
    assert!(
        Cli::try_parse_from([
            "musubi",
            "owner",
            "remove",
            "apps.sora/demo",
            "--expected-revision",
            "7",
        ])
        .is_err(),
        "a removal target is required"
    );
    assert!(
        Cli::try_parse_from([
            "musubi",
            "owner",
            "remove",
            "apps.sora/demo",
            "ed0120deadbeef",
            "--invitation",
            &invitation,
            "--expected-revision",
            "7",
        ])
        .is_err(),
        "accepted and pending targets are mutually exclusive"
    );
}
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture verifies the complete authenticated owner-list response"
)]
fn owner_list_is_authenticated_and_includes_pending_invitations() {
    let selector: MusubiPackageSelectorV1 = "apps.sora/demo".parse().expect("selector");
    let binding = MusubiNamespaceBindingV1 {
        namespace: selector.namespace.clone(),
        home_dataspace: DataSpaceId::new(7),
        scope: MusubiPackageScopeV1::Domain("apps".parse().expect("domain")),
        generation: 1,
    };
    let package = MusubiPackageIdV1::new(
        binding.home_dataspace,
        binding.scope.clone(),
        selector.name.clone(),
    );
    let snapshot = MusubiRegistrySnapshotV1 {
        finalized_height: 10,
        finalized_block_hash: [9; 32],
        index_revision: 11,
    };
    let directory = MusubiOrderedPackagePageV1 {
        query: MusubiOrderedPrefixQueryV1 {
            prefix: MusubiOrderedPrefixV1::new(&selector.to_string())
                .expect("exact selector prefix"),
            page: MusubiPageRequestV1 {
                limit: 2,
                cursor: None,
            },
        },
        network_id: test_network_id(9),
        namespace_binding: binding,
        items: vec![MusubiOrderedPackageEntryV1 {
            selector: selector.clone(),
            package: package.clone(),
            latest_selectable: Some("1.0.0".parse().expect("version")),
            metadata_revision: 2,
            index_revision: snapshot.index_revision,
        }],
        next_cursor: None,
        snapshot,
    };
    let owner = test_account(31);
    let invited = test_account(32);
    let mut entries = vec![
        MusubiMaintainerDirectoryEntryV1::Accepted(MusubiPackageMemberV1 {
            package: package.clone(),
            account: owner.clone(),
            role: MusubiPackageRoleV1::Owner,
            accepted_at_height: 3,
            governance_revision: 4,
        }),
        MusubiMaintainerDirectoryEntryV1::PendingInvitation(MusubiMaintainerInvitationV1 {
            invite_id: MusubiInviteIdV1::new([5; 32]),
            package: package.clone(),
            invited_by: owner,
            invited_account: invited,
            role: MusubiPackageRoleV1::Maintainer(MusubiMaintainerPermissionsV1 {
                publish: true,
                yank: false,
                metadata: false,
                archive_locations: false,
            }),
            expected_governance_revision: 4,
            expires_at_height: 50,
            state: MusubiInvitationStateV1::Pending,
        }),
    ];
    entries.sort_by_key(MusubiMaintainerDirectoryEntryV1::key);
    let maintainers = iroha_data_model::musubi::MusubiMaintainerPageV1 {
        query: MusubiPackagePageQueryV1 {
            package,
            page: MusubiPageRequestV1 {
                limit: u32::try_from(MUSUBI_MAX_PAGE_SIZE_V1).expect("canonical page bound"),
                cursor: None,
            },
        },
        items: entries,
        next_cursor: None,
        snapshot,
    };
    directory
        .validate_for(&directory.query)
        .expect("canonical exact-selector directory fixture");
    maintainers
        .validate_for(&maintainers.query)
        .expect("canonical complete maintainer-page fixture");
    let responses = {
        let _chain_discriminant = ChainDiscriminantGuard::enter(753);
        vec![
            norito::json::to_vec(&directory).expect("directory JSON"),
            norito::json::to_vec(&maintainers).expect("maintainer JSON"),
        ]
    };
    let (torii_url, server) = serve_json_sequence(responses);
    let temporary = TempDir::new().expect("temporary config directory");
    let config = temporary.path().join("client.toml");
    fs::write(
        &config,
        authenticated_registry_config_for_network(&torii_url, 753, test_network_id(9)),
    )
    .expect("write authenticated config");
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("owner"),
        OsString::from("list"),
        OsString::from(selector.to_string()),
        OsString::from("--config"),
        config.into_os_string(),
    ]);
    assert_eq!(invocation.output.exit_code(), 0);
    let rendered = invocation
        .output
        .render(invocation.format)
        .expect("owner-list JSON output");
    assert!(rendered.stderr().is_empty());
    let document: Value = norito::json::from_str(rendered.stdout()).expect("JSON document");
    assert_eq!(
        document.pointer("/data/accepted").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        document.pointer("/data/pending").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        document
            .pointer("/data/entries")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    server.join().expect("registry server");
}
#[test]
fn targeted_update_parser_requires_structural_package_and_exact_version() {
    let target = "std/math@1.2.3"
        .parse::<UpdateTarget>()
        .expect("valid targeted update");
    assert_eq!(target.package.to_string(), "std/math");
    assert_eq!(
        target.locked_version.as_ref().map(ToString::to_string),
        Some("1.2.3".to_owned())
    );
    assert!("math@1.2.3".parse::<UpdateTarget>().is_err());
    assert!("std/math@1.2.3+local".parse::<UpdateTarget>().is_err());
}
#[test]
fn json_parse_failure_is_one_stdout_document() {
    let invocation = invoke(["musubi", "--format", "json", "install"]);
    let rendered = invocation
        .output
        .render(invocation.format)
        .expect("render JSON failure");
    assert_eq!(rendered.exit_code(), ErrorCode::Usage.exit_code());
    assert!(rendered.stderr().is_empty());
    assert_eq!(rendered.stdout().matches('\n').count(), 1);
    let value: Value = norito::json::from_str(rendered.stdout()).expect("JSON document");
    assert_eq!(value.get("ok").and_then(Value::as_bool), Some(false));
}
#[test]
fn local_new_add_metadata_tree_remove_roundtrip() {
    let temp = TempDir::new().expect("temporary directory");
    let (_root, manifest_path) = create_test_package(&temp);
    let manifest = fs::read_to_string(&manifest_path).expect("new manifest");
    parse_manifest(&manifest).expect("strict generated manifest");
    let add = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("std/math"),
        OsString::from("--version"),
        OsString::from("^1.0.0"),
        OsString::from("--rename"),
        OsString::from("math"),
    ]);
    assert_eq!(add.output.exit_code(), 0);
    let add_local_dev = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("local-test-support"),
        OsString::from("--path"),
        OsString::from("."),
        OsString::from("--dev"),
    ]);
    assert_eq!(add_local_dev.output.exit_code(), 0);
    let metadata = invoke([
        OsString::from("musubi"),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("metadata"),
    ]);
    assert_eq!(
        metadata.output.exit_code(),
        0,
        "{}",
        metadata
            .output
            .render(OutputFormat::Human)
            .expect("metadata diagnostic")
            .stderr()
    );
    let rendered = metadata
        .output
        .render(metadata.format)
        .expect("metadata JSON");
    let document: Value = norito::json::from_str(rendered.stdout()).expect("metadata document");
    assert_eq!(
        document
            .pointer("/data/packages/0/package")
            .and_then(Value::as_str),
        Some("apps.sora/demo")
    );
    let tree = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("tree"),
    ]);
    assert_eq!(tree.output.exit_code(), 0);
    let tree = tree.output.render(tree.format).expect("tree output");
    assert!(tree.stdout().contains("math -> std/math ^1.0.0"));
    assert!(tree.stdout().contains("[dev] local-test-support ->"));
    let remove = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("remove"),
        OsString::from("math"),
    ]);
    assert_eq!(remove.output.exit_code(), 0);
    let manifest = fs::read_to_string(&manifest_path).expect("edited manifest");
    assert!(
        !parse_manifest(&manifest)
            .expect("manifest after remove")
            .dependencies
            .contains_key("math")
    );
}
#[test]
fn add_rejects_a_hardlinked_manifest_without_mutation() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, manifest_path) = create_test_package(&temp);
    let alias = root.join("Musubi.manifest-alias.toml");
    let before = fs::read(&manifest_path).expect("read original manifest");
    fs::hard_link(&manifest_path, &alias).expect("create manifest hard link");
    let add = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("std/math"),
        OsString::from("--version"),
        OsString::from("^1.0.0"),
    ]);
    assert_ne!(add.output.exit_code(), 0);
    assert_eq!(
        fs::read(&manifest_path).expect("reread rejected manifest"),
        before
    );
}
#[test]
fn metadata_and_tree_include_only_the_validated_exact_lock_graph() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, manifest_path) = create_test_package(&temp);
    write_test_lock(&root);
    let metadata = invoke([
        OsString::from("musubi"),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("metadata"),
    ]);
    assert_eq!(metadata.output.exit_code(), 0);
    let rendered = metadata
        .output
        .render(metadata.format)
        .expect("metadata JSON");
    let document: Value = norito::json::from_str(rendered.stdout()).expect("JSON document");
    assert_eq!(
        document
            .pointer("/data/lock/schema")
            .and_then(Value::as_str),
        Some("musubi-lock")
    );
    assert_eq!(
        document
            .pointer("/data/lock/context/finalized_height")
            .and_then(Value::as_u64),
        Some(7)
    );
    for forbidden in ["cache_path", "provider_url", "credential", "bearer"] {
        assert!(!rendered.stdout().contains(forbidden));
    }
    let tree = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("tree"),
    ]);
    assert_eq!(tree.output.exit_code(), 0);
    let rendered = tree.output.render(tree.format).expect("tree output");
    assert!(
        rendered
            .stdout()
            .contains("apps.sora/demo exact lock graph")
    );
}
#[test]
fn locked_fetch_rejects_legacy_lock_without_rewriting_it() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, manifest_path) = create_test_package(&temp);
    let lock_path = root.join(LOCK_FILE_NAME);
    let legacy = b"schema = \"musubi-lock\"\nversion = 2\n";
    fs::write(&lock_path, legacy).expect("write legacy lock");
    let fetch = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("fetch"),
        OsString::from("--locked"),
    ]);
    assert_eq!(
        fetch.output.exit_code(),
        ErrorCode::LockfileLegacy.exit_code()
    );
    assert_eq!(fs::read(lock_path).expect("read lock"), legacy);
    let rendered = fetch
        .output
        .render(OutputFormat::Human)
        .expect("legacy diagnostic");
    assert!(
        rendered.stderr().contains("MUSUBI_E_LOCKFILE_LEGACY"),
        "{}",
        rendered.stderr()
    );
    assert!(rendered.stderr().contains("never rewrites retired formats"));
}
#[test]
fn consumer_lock_is_not_used_as_package_or_cache_authentication() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, manifest_path) = create_test_package(&temp);
    write_test_lock_with_registry_node(&root);
    let consumer_lock = fs::read(root.join(LOCK_FILE_NAME)).expect("consumer lock evidence");
    let package = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("package"),
        OsString::from("--offline"),
    ]);
    assert_eq!(
        package.output.exit_code(),
        ErrorCode::OfflineMiss.exit_code()
    );
    let rendered = package
        .output
        .render(OutputFormat::Human)
        .expect("package diagnostic");
    assert!(rendered.stderr().contains("cached Musubi resolver index"));
    assert!(rendered.stderr().contains("resolver cache"));
    assert_eq!(
        fs::read(root.join(LOCK_FILE_NAME)).expect("unchanged consumer lock"),
        consumer_lock
    );
    let verify = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("cache"),
        OsString::from("verify"),
        OsString::from("--config"),
        manifest_path.as_os_str().to_owned(),
    ]);
    assert_eq!(verify.output.exit_code(), ErrorCode::Registry.exit_code());
    let rendered = verify
        .output
        .render(OutputFormat::Human)
        .expect("cache diagnostic");
    assert!(
        rendered
            .stderr()
            .contains("MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID")
    );
    assert!(!rendered.stderr().contains("healthy"));
}
#[cfg(unix)]
#[test]
fn empty_cache_maintenance_is_signer_and_network_free() {
    let temp = TempDir::new().expect("temporary directory");
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private cache");
    let targets = BTreeSet::new();
    let verified = verify_cache_targets(&cache, &targets, None).expect("empty verification");
    assert_eq!(verified.message, "verified 0 cached archive(s)");
    let repaired = repair_cache_targets(&cache, &targets, None, true).expect("empty repair");
    assert_eq!(repaired.message, "repaired 0 cached archive(s)");
    let graph = ResolvedWorkspaceGraphV1 {
        lock: LockfileV1::new(
            LockContextV1::Registry {
                network_id: test_network_id(1),
                snapshot: MusubiRegistrySnapshotV1 {
                    finalized_height: 1,
                    finalized_block_hash: [2; 32],
                    index_revision: 1,
                },
            },
            vec![LockedRootV1 {
                package: "apps.sora/demo".parse().expect("root package"),
                dependencies: Vec::new(),
            }],
            Vec::new(),
        )
        .expect("empty external graph"),
        registry: None,
        cached_source: None,
        prepared_archive_fetch: None,
        platform_config_provenance: None,
        account_chain_discriminant: Some(753),
    };
    assert!(
        ensure_graph_archives(&cache, &graph, GraphModeArgs::default())
            .expect("empty graph fetch")
            .is_empty()
    );
}

#[test]
fn cold_online_dependency_reports_missing_environment_capability_before_registry_or_storage_io() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, _) = create_test_package(&temp);
    write_test_lock_with_registry_node(&root);
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private cache");
    let graph = ResolvedWorkspaceGraphV1 {
        lock: LockfileV1::read(&root.join(LOCK_FILE_NAME)).expect("exact locked dependency"),
        registry: None,
        cached_source: None,
        prepared_archive_fetch: None,
        platform_config_provenance: None,
        account_chain_discriminant: Some(753),
    };
    let error = ensure_graph_archives(&cache, &graph, GraphModeArgs::default())
        .expect_err("cold online dependency requires an admitted download capability");
    assert_eq!(error.code(), ErrorCode::Registry);
    let rendered = CommandOutput::failure("deploy", error)
        .render(OutputFormat::Human)
        .expect("cold capability diagnostic");
    assert!(rendered.stderr().contains("selected environment"));
    assert!(rendered.stderr().contains("uncached dependency"));
    assert!(!rendered.stderr().contains("offline"));
    let offline = ensure_graph_archives(
        &cache,
        &graph,
        GraphModeArgs {
            offline: true,
            ..GraphModeArgs::default()
        },
    )
    .expect_err("offline misses remain distinct");
    assert_eq!(offline.code(), ErrorCode::OfflineMiss);
}
#[test]
fn package_output_writer_creates_confined_target_directory() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, _manifest_path) = create_test_package(&temp);
    let workspace = load_workspace(&root).expect("workspace");
    let writer = package_output_writer(&workspace).expect("package writer");
    writer
        .replace(Path::new("target/package/demo.car"), b"canonical-car")
        .expect("confined package write");
    assert_eq!(
        fs::read(root.join("target/package/demo.car")).expect("package bytes"),
        b"canonical-car"
    );
}
#[test]
fn offline_fetch_with_a_valid_lock_requires_authenticated_cache_inputs() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, manifest_path) = create_test_package(&temp);
    write_test_lock(&root);
    add_dependency_to_fixture_manifest(&manifest_path);
    let fetch = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("fetch"),
        OsString::from("--offline"),
    ]);
    assert_eq!(fetch.output.exit_code(), ErrorCode::OfflineMiss.exit_code());
    let rendered = fetch
        .output
        .render(OutputFormat::Human)
        .expect("offline diagnostic");
    assert!(rendered.stderr().contains("cached Musubi resolver index"));
    assert!(rendered.stderr().contains("resolver cache"));
}
#[test]
fn compiler_command_requires_an_authenticated_v1_graph_offline() {
    let temp = TempDir::new().expect("temporary directory");
    let (root, manifest_path) = create_test_package(&temp);
    write_test_lock(&root);
    add_dependency_to_fixture_manifest(&manifest_path);
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("check"),
        OsString::from("--offline"),
    ]);
    assert_eq!(
        invocation.output.exit_code(),
        ErrorCode::OfflineMiss.exit_code()
    );
    let rendered = invocation
        .output
        .render(OutputFormat::Human)
        .expect("authenticated graph diagnostic");
    assert!(rendered.stderr().contains("resolver cache"));
    assert!(!rendered.stderr().contains("install"));
}
#[test]
fn publish_resume_and_recover_accept_only_canonical_detached_operations() {
    let operation = "0101010101010101010101010101010101010101010101010101010101010101";
    let parsed = Cli::try_parse_from(["musubi", "publish", "--resume", operation])
        .expect("canonical resume command");
    let Command::Publish(arguments) = parsed.command else {
        panic!("publish command expected");
    };
    assert_eq!(arguments.resume.expect("operation").to_string(), operation);
    assert!(!arguments.detach);
    assert!(arguments.recover.is_none());
    let parsed = Cli::try_parse_from(["musubi", "publish", "--recover", operation])
        .expect("canonical recovery command");
    let Command::Publish(arguments) = parsed.command else {
        panic!("publish command expected");
    };
    assert_eq!(arguments.recover.expect("operation").to_string(), operation);
    assert!(!arguments.detach);
    assert!(arguments.resume.is_none());
    assert!(
        Cli::try_parse_from(["musubi", "publish", "--resume", operation, "--detach"]).is_err(),
        "detach and resume are mutually exclusive"
    );
    assert!(
        Cli::try_parse_from(["musubi", "publish", "--recover", operation, "--detach"]).is_err(),
        "detach and recover are mutually exclusive"
    );
    assert!(
        Cli::try_parse_from([
            "musubi",
            "publish",
            "--recover",
            operation,
            "--resume",
            operation,
        ])
        .is_err(),
        "resume and recover are mutually exclusive"
    );
    assert!(
        Cli::try_parse_from([
            "musubi",
            "publish",
            "--resume",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ])
        .is_err(),
        "operation id uses canonical lowercase hex"
    );
}
#[test]
fn publish_recovery_rejects_explicit_workspace_selection() {
    let operation = "0101010101010101010101010101010101010101010101010101010101010101";
    let invocation = invoke([
        "musubi",
        "publish",
        "--recover",
        operation,
        "-p",
        "apps.sora/demo",
    ]);
    assert_eq!(invocation.output.exit_code(), ErrorCode::Usage.exit_code());
    let rendered = invocation
        .output
        .render(OutputFormat::Human)
        .expect("recovery selection diagnostic");
    assert!(
        rendered
            .stderr()
            .contains("derives its exact package selection")
    );
}
#[cfg(unix)]
#[test]
fn publish_recovery_is_signer_free_and_ignores_the_locked_consumer_graph() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (root, manifest_path) = create_test_package(&temp);
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private fixture cache");
    let request = build_root_recovery_request(&manifest_path, &cache, Vec::new(), Vec::new());
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let operation_id = persist_recovery_request(&state_root, &request);
    let config = write_poisoned_recovery_config(temp.path());
    assert_eq!(
        RegistrySigningClientV1::load(Some(&config))
            .expect_err("poisoned signing identity must be rejected")
            .code(),
        "MUSUBI_REGISTRY_SIGNING_CONFIG_INVALID"
    );
    assert_archive_transport_is_poisoned(&config);
    let lock_path = root.join(LOCK_FILE_NAME);
    let lock_bytes = b"retired lock bytes that recovery must never parse or replace\n";
    fs::write(&lock_path, lock_bytes).expect("write deliberately invalid consumer lock");
    let mut permissions = fs::metadata(&lock_path)
        .expect("consumer lock metadata")
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&lock_path, permissions).expect("make consumer lock read-only");
    let before = fs::metadata(&lock_path).expect("consumer lock metadata before recovery");
    let before_modified = before.modified().expect("consumer lock modification time");
    #[cfg(unix)]
    let before_identity = (
        before.dev(),
        before.ino(),
        before.mode(),
        before.mtime(),
        before.mtime_nsec(),
    );
    let args = recovery_publish_args(operation_id, &config, true, true);
    let success = recover_publication_sidecars_at(
        Some(&manifest_path),
        &args,
        operation_id,
        &state_root,
        Some(&cache),
        None,
    )
    .expect("locked offline recovery must use only its journal graph");
    assert_eq!(
        success.message,
        format!("recovered publication sidecars {operation_id}")
    );
    let source = PublicationStagedCarSourceV1::new(
        &state_root,
        operation_id,
        request.archive_commitment.car_size,
    );
    assert!(source.path().is_file());
    assert!(source.plan_path().is_file());
    let store = PublicationJournalStore::open(&state_root).expect("reopen journal store");
    let journal = store
        .load(operation_id)
        .expect("unchanged recovery journal");
    assert_eq!(journal.request, request);
    assert_eq!(journal.revision, 1);
    assert_eq!(
        journal.phase,
        crate::publish::PublicationPhaseV1::Validation
    );
    let after = fs::metadata(&lock_path).expect("consumer lock metadata after recovery");
    assert_eq!(
        fs::read(&lock_path).expect("consumer lock bytes"),
        lock_bytes
    );
    assert_eq!(after.len(), before.len());
    assert_eq!(
        after.permissions().readonly(),
        before.permissions().readonly()
    );
    assert_eq!(
        after.modified().expect("consumer lock modification time"),
        before_modified
    );
    #[cfg(unix)]
    assert_eq!(
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.mtime(),
            after.mtime_nsec(),
        ),
        before_identity
    );
}
#[cfg(unix)]
#[test]
fn offline_publish_recovery_uses_cached_nodes_without_transport() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (_root, manifest_path) = create_test_package(&temp);
    add_dependency_to_fixture_manifest(&manifest_path);
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private fixture cache");
    let (edge, node) = build_and_install_dependency_fixture(temp.path(), &cache);
    let request = build_root_recovery_request(&manifest_path, &cache, vec![edge], vec![node]);
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let operation_id = persist_recovery_request(&state_root, &request);
    let config = write_poisoned_recovery_config(temp.path());
    assert_archive_transport_is_poisoned(&config);
    let args = recovery_publish_args(operation_id, &config, false, true);
    recover_publication_sidecars_at(
        Some(&manifest_path),
        &args,
        operation_id,
        &state_root,
        Some(&cache),
        None,
    )
    .expect("offline recovery must accept an authenticated cache hit");
    let source = PublicationStagedCarSourceV1::new(
        &state_root,
        operation_id,
        request.archive_commitment.car_size,
    );
    assert!(source.path().is_file());
    assert!(source.plan_path().is_file());
    let journal = PublicationJournalStore::open(&state_root)
        .expect("reopen journal store")
        .load(operation_id)
        .expect("unchanged recovery journal");
    assert_eq!(journal.request, request);
    assert_eq!(journal.revision, 1);
}
#[cfg(unix)]
#[test]
fn offline_publish_recovery_reports_cache_miss_before_transport() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (_root, manifest_path) = create_test_package(&temp);
    add_dependency_to_fixture_manifest(&manifest_path);
    let builder_cache =
        MusubiCache::open(temp.path().join("builder-cache")).expect("private builder cache");
    let (edge, node) = build_and_install_dependency_fixture(temp.path(), &builder_cache);
    let request =
        build_root_recovery_request(&manifest_path, &builder_cache, vec![edge], vec![node]);
    let empty_cache =
        MusubiCache::open(temp.path().join("empty-cache")).expect("private empty cache");
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let operation_id = persist_recovery_request(&state_root, &request);
    let store = PublicationJournalStore::open(&state_root).expect("reopen journal store");
    let journal_before = store.load(operation_id).expect("pristine recovery journal");
    let config = write_poisoned_recovery_config(temp.path());
    assert_archive_transport_is_poisoned(&config);
    let args = recovery_publish_args(operation_id, &config, false, true);
    let error = match recover_publication_sidecars_at(
        Some(&manifest_path),
        &args,
        operation_id,
        &state_root,
        Some(&empty_cache),
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("offline recovery must reject a missing exact archive"),
    };
    assert_eq!(error.code(), ErrorCode::OfflineMiss);
    assert_eq!(
        store
            .load(operation_id)
            .expect("unchanged recovery journal"),
        journal_before
    );
    assert_no_recovery_sidecars(
        &state_root,
        operation_id,
        request.archive_commitment.car_size,
    );
}
#[cfg(unix)]
#[test]
fn online_publish_recovery_uses_cached_nodes_without_loading_credentials() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (_root, manifest_path) = create_test_package(&temp);
    add_dependency_to_fixture_manifest(&manifest_path);
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private fixture cache");
    let (edge, node) = build_and_install_dependency_fixture(temp.path(), &cache);
    let request = build_root_recovery_request(&manifest_path, &cache, vec![edge], vec![node]);
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let operation_id = persist_recovery_request(&state_root, &request);
    let config = write_poisoned_recovery_config(temp.path());
    assert_archive_transport_is_poisoned(&config);
    let args = recovery_publish_args(operation_id, &config, false, false);
    recover_publication_sidecars_at(
        Some(&manifest_path),
        &args,
        operation_id,
        &state_root,
        Some(&cache),
        None,
    )
    .expect("an online cache hit must not load unusable signing or provider credentials");
    let source = PublicationStagedCarSourceV1::new(
        &state_root,
        operation_id,
        request.archive_commitment.car_size,
    );
    assert!(source.path().is_file());
    assert!(source.plan_path().is_file());
    let journal = PublicationJournalStore::open(&state_root)
        .expect("reopen journal store")
        .load(operation_id)
        .expect("unchanged recovery journal");
    assert_eq!(journal.request, request);
    assert_eq!(journal.revision, 1);
}
#[cfg(unix)]
#[test]
fn online_publish_recovery_requires_credentials_only_after_a_cache_miss() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (_root, manifest_path) = create_test_package(&temp);
    add_dependency_to_fixture_manifest(&manifest_path);
    let builder_cache =
        MusubiCache::open(temp.path().join("builder-cache")).expect("private builder cache");
    let (edge, node) = build_and_install_dependency_fixture(temp.path(), &builder_cache);
    let request =
        build_root_recovery_request(&manifest_path, &builder_cache, vec![edge], vec![node]);
    let empty_cache =
        MusubiCache::open(temp.path().join("empty-cache")).expect("private empty cache");
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let operation_id = persist_recovery_request(&state_root, &request);
    let store = PublicationJournalStore::open(&state_root).expect("reopen journal store");
    let before = store.load(operation_id).expect("pristine journal");
    let config = write_poisoned_recovery_config(temp.path());
    let args = recovery_publish_args(operation_id, &config, false, false);
    let error = match recover_publication_sidecars_at(
        Some(&manifest_path),
        &args,
        operation_id,
        &state_root,
        Some(&empty_cache),
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("an online cache miss requires valid registry credentials"),
    };
    assert_eq!(error.code(), ErrorCode::Publish);
    assert_eq!(
        error.context().get("registry_code").map(String::as_str),
        Some("MUSUBI_REGISTRY_PUBLIC_CONFIG_INVALID"),
    );
    assert_eq!(store.load(operation_id).expect("unchanged journal"), before);
    assert_no_recovery_sidecars(
        &state_root,
        operation_id,
        request.archive_commitment.car_size,
    );
}
#[cfg(unix)]
#[test]
fn publish_recovery_rejects_identity_mismatches_before_sidecars() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (_root, manifest_path) = create_test_package(&temp);
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private fixture cache");
    let base = build_root_recovery_request(&manifest_path, &cache, Vec::new(), Vec::new());
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let missing_config = temp.path().join("must-not-be-opened.toml");
    let cases = [
        (
            retarget_recovery_request(base.clone(), Some("other"), None),
            ErrorCode::WorkspaceInvalid,
            "not a member of the selected workspace",
        ),
        (
            retarget_recovery_request(base.clone(), None, Some("9.9.9")),
            ErrorCode::WorkspaceInvalid,
            "version differs from the immutable recovery journal",
        ),
    ];
    for (request, expected_code, expected_message) in cases {
        let operation_id = persist_recovery_request(&state_root, &request);
        let store = PublicationJournalStore::open(&state_root).expect("reopen journal store");
        let journal_before = store.load(operation_id).expect("pristine recovery journal");
        let args = recovery_publish_args(operation_id, &missing_config, false, false);
        let error = match recover_publication_sidecars_at(
            Some(&manifest_path),
            &args,
            operation_id,
            &state_root,
            Some(&cache),
            None,
        ) {
            Err(error) => error,
            Ok(_) => panic!("mismatched recovery request must fail"),
        };
        assert_eq!(error.code(), expected_code);
        let rendered = CommandOutput::failure("publish", error)
            .render(OutputFormat::Human)
            .expect("render recovery mismatch diagnostic");
        assert!(
            rendered.stderr().contains(expected_message),
            "{}",
            rendered.stderr()
        );
        assert_eq!(
            store
                .load(operation_id)
                .expect("unchanged recovery journal"),
            journal_before
        );
        assert_no_recovery_sidecars(
            &state_root,
            operation_id,
            request.archive_commitment.car_size,
        );
    }
    assert!(
        !missing_config.exists(),
        "early mismatch checks must not create or require platform config"
    );
}
#[cfg(unix)]
#[test]
fn publish_rejects_unreachable_verification_nodes_before_journal_or_sidecars() {
    let temp = TempDir::new().expect("temporary recovery fixture");
    let (_root, manifest_path) = create_test_package(&temp);
    let cache = MusubiCache::open(temp.path().join("cache")).expect("private fixture cache");
    let request = add_unreachable_recovery_node_unchecked(build_root_recovery_request(
        &manifest_path,
        &cache,
        Vec::new(),
        Vec::new(),
    ));
    let operation_id = request.operation_id();
    let expected_size = request.archive_commitment.car_size;
    let validation_error = request
        .validate()
        .expect_err("an unreachable exact node must invalidate the publication request");
    assert!(
        validation_error
            .to_string()
            .contains("unreachable exact nodes")
    );
    let state_root = temp.path().join("state");
    create_private_fixture_directory(&state_root);
    let store = PublicationJournalStore::open(&state_root).expect("open recovery journal store");
    let create_error = store
        .create(request)
        .expect_err("invalid proof graphs must be rejected before journal creation");
    assert!(create_error.to_string().contains("unreachable exact nodes"));
    assert!(matches!(
        store.load(operation_id),
        Err(crate::publish::PublicationError::NotFound(found)) if found == operation_id
    ));
    assert_no_recovery_sidecars(&state_root, operation_id, expected_size);
}
#[test]
fn recovered_publication_json_is_one_secret_free_resume_instruction() {
    let (namespace, result) = publication_receipt_fixture();
    let operation_id = result.operation_id;
    let success =
        recovered_publication_result(&namespace, &result.final_checkpoint.release, operation_id);
    let rendered = CommandOutput::success("publish", success.message, success.data)
        .render(OutputFormat::Json)
        .expect("recovery JSON");
    assert_eq!(rendered.exit_code(), 0);
    assert!(rendered.stderr().is_empty());
    assert_eq!(rendered.stdout().matches('\n').count(), 1);
    let document: Value =
        norito::json::from_str(rendered.stdout()).expect("one recovery JSON document");
    let data = document
        .get("data")
        .and_then(Value::as_object)
        .expect("recovery data");
    assert_eq!(
        data.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "next",
            "operation_id",
            "phase",
            "release",
            "status",
            "structural_release",
        ])
    );
    assert_eq!(
        data.get("status").and_then(Value::as_str),
        Some("recovered")
    );
    assert_eq!(
        data.get("phase").and_then(Value::as_str),
        Some("validation")
    );
    let expected_next = format!("musubi publish --resume {operation_id}");
    assert_eq!(
        data.get("next").and_then(Value::as_str),
        Some(expected_next.as_str())
    );
}
#[test]
fn fresh_publish_selects_one_explicit_workspace_package() {
    let parsed = Cli::try_parse_from([
        "musubi",
        "publish",
        "-p",
        "apps.sora/demo",
        "--config",
        "/platform/client.toml",
        "--detach",
    ])
    .expect("fresh publication command");
    let Command::Publish(arguments) = parsed.command else {
        panic!("publish command expected");
    };
    assert_eq!(
        arguments.selection.packages,
        vec![
            "apps.sora/demo"
                .parse::<MusubiPackageSelectorV1>()
                .expect("package selector")
        ]
    );
    assert_eq!(
        arguments.network.config.as_deref(),
        Some(Path::new("/platform/client.toml"))
    );
    assert!(arguments.detach);
    assert!(arguments.resume.is_none());
    assert!(arguments.recover.is_none());
}
#[test]
#[allow(clippy::too_many_lines)]
fn completed_publication_json_is_one_origin_independent_exact_receipt() {
    let (namespace, result) = publication_receipt_fixture();
    let operation_id = result.operation_id.to_string();
    let structural_release = result.final_checkpoint.release.to_string();
    // Fresh publication and completed resume both converge on this formatter with the
    // immutable request namespace and the same final result. Render two independent calls so
    // neither origin can acquire a distinct success envelope.
    let fresh_success = publication_result(&namespace, result.clone());
    let resumed_success = publication_result(&namespace, result);
    assert_eq!(fresh_success.message, "published apps.sora/demo@1.2.3");
    assert_eq!(resumed_success.message, fresh_success.message);
    let first = CommandOutput::success("publish", fresh_success.message, fresh_success.data)
        .render(OutputFormat::Json)
        .expect("first publication JSON");
    let second = CommandOutput::success("publish", resumed_success.message, resumed_success.data)
        .render(OutputFormat::Json)
        .expect("second publication JSON");
    assert_eq!(first, second);
    assert_eq!(first.exit_code(), 0);
    assert!(first.stderr().is_empty());
    assert_eq!(first.stdout().matches('\n').count(), 1);
    let document: Value =
        norito::json::from_str(first.stdout()).expect("one publication JSON document");
    assert_eq!(
        document
            .as_object()
            .expect("output envelope")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["command", "data", "message", "ok", "schema", "version"])
    );
    assert_eq!(
        document.get("schema").and_then(Value::as_str),
        Some(OUTPUT_SCHEMA)
    );
    assert_eq!(
        document.get("version").and_then(Value::as_u64),
        Some(OUTPUT_VERSION)
    );
    assert_eq!(
        document.get("command").and_then(Value::as_str),
        Some("publish")
    );
    assert_eq!(document.get("ok").and_then(Value::as_bool), Some(true));
    let data = document
        .get("data")
        .and_then(Value::as_object)
        .expect("publication receipt data");
    assert_eq!(
        data.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "amx_submission",
            "archive_id",
            "checkpoint_digest",
            "home_release_digest",
            "network_id",
            "operation_id",
            "release",
            "release_digest",
            "snapshot",
            "status",
            "structural_release",
            "universal_release_digest",
        ])
    );
    assert_eq!(data.get("status").and_then(Value::as_str), Some("complete"));
    assert_eq!(
        data.get("operation_id").and_then(Value::as_str),
        Some(operation_id.as_str())
    );
    assert_eq!(
        data.get("release").and_then(Value::as_str),
        Some("apps.sora/demo@1.2.3")
    );
    assert_eq!(
        data.get("structural_release").and_then(Value::as_str),
        Some(structural_release.as_str())
    );
    assert_eq!(
        data.get("network_id").and_then(Value::as_str),
        Some(test_network_id(0x11).to_string().as_str())
    );
    assert_eq!(
        data.get("release_digest").and_then(Value::as_str),
        Some(hex::encode([0x13; 32]).as_str())
    );
    assert_eq!(
        data.get("archive_id").and_then(Value::as_str),
        Some(hex::encode([0x14; 32]).as_str())
    );
    assert_eq!(
        data.get("home_release_digest").and_then(Value::as_str),
        Some(hex::encode([0x15; 32]).as_str())
    );
    assert_eq!(
        data.get("universal_release_digest").and_then(Value::as_str),
        Some(hex::encode([0x16; 32]).as_str())
    );
    assert_eq!(
        data.get("checkpoint_digest").and_then(Value::as_str),
        Some(hex::encode([0x17; 32]).as_str())
    );
    let snapshot = data
        .get("snapshot")
        .and_then(Value::as_object)
        .expect("receipt snapshot");
    assert_eq!(
        snapshot.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["finalized_block_hash", "finalized_height", "index_revision"])
    );
    assert_eq!(
        snapshot.get("finalized_height").and_then(Value::as_u64),
        Some(u64::MAX)
    );
    assert_eq!(
        snapshot.get("index_revision").and_then(Value::as_u64),
        Some(u64::MAX)
    );
    assert_eq!(
        snapshot.get("finalized_block_hash").and_then(Value::as_str),
        Some(hex::encode([0x12; 32]).as_str())
    );
    let submission = data
        .get("amx_submission")
        .and_then(Value::as_object)
        .expect("AMX submission binding");
    assert_eq!(
        submission
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["applied_height", "instruction_digest", "transaction_hash"])
    );
    assert_eq!(
        submission.get("applied_height").and_then(Value::as_u64),
        Some(u64::MAX)
    );
    assert_eq!(
        submission.get("instruction_digest").and_then(Value::as_str),
        Some(hex::encode([0x18; 32]).as_str())
    );
    assert_eq!(
        submission.get("transaction_hash").and_then(Value::as_str),
        Some(hex::encode([0x19; 32]).as_str())
    );
}
#[test]
fn detached_publication_json_is_namespaced_and_discriminated() {
    let (namespace, result) = publication_receipt_fixture();
    let release = &result.final_checkpoint.release;
    let success = detached_publication_result(&namespace, release, result.operation_id);
    let output = CommandOutput::success("publish", success.message, success.data)
        .render(OutputFormat::Json)
        .expect("detached publication JSON");
    let document: Value = norito::json::from_str(output.stdout()).expect("detached document");
    let data = document
        .get("data")
        .and_then(Value::as_object)
        .expect("detached receipt data");
    assert_eq!(
        data.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "operation_id",
            "phase",
            "release",
            "status",
            "structural_release",
        ])
    );
    assert_eq!(data.get("status").and_then(Value::as_str), Some("detached"));
    assert_eq!(
        data.get("phase").and_then(Value::as_str),
        Some("seed-ingress")
    );
    assert_eq!(
        data.get("release").and_then(Value::as_str),
        Some("apps.sora/demo@1.2.3")
    );
    assert_eq!(
        data.get("structural_release").and_then(Value::as_str),
        Some(release.to_string().as_str())
    );
}
#[test]
fn publication_release_labels_stay_namespaced_for_both_structural_scopes() {
    let (namespace, result) = publication_receipt_fixture();
    let domain_release = result.final_checkpoint.release;
    assert_eq!(
        namespaced_release(&namespace, &domain_release),
        "apps.sora/demo@1.2.3"
    );
    assert_ne!(domain_release.to_string(), "apps.sora/demo@1.2.3");
    let root_namespace = "sora".parse().expect("fixture root namespace");
    let mut root_release = domain_release;
    root_release.package.scope = MusubiPackageScopeV1::DataspaceRoot;
    assert_eq!(
        namespaced_release(&root_namespace, &root_release),
        "sora/demo@1.2.3"
    );
    assert_ne!(root_release.to_string(), "sora/demo@1.2.3");
}
#[test]
fn publication_receipts_and_diagnostics_do_not_expose_secret_controls() {
    let (namespace, result) = publication_receipt_fixture();
    let success = publication_result(&namespace, result);
    let rendered = CommandOutput::success("publish", success.message, success.data)
        .render(OutputFormat::Json)
        .expect("publication receipt JSON");
    for forbidden in [
        "authorization",
        "bearer",
        "car_path",
        "config_path",
        "credential",
        "journal_path",
        "private_key",
        "provider_url",
        "runtime_endpoint",
        "seed_provider",
        "stream_token",
        "torii_url",
    ] {
        assert!(
            !rendered.stdout().contains(forbidden),
            "publication receipt exposed {forbidden}"
        );
    }
    for (error, secret, expected_code) in [
        (
            PublicationError::CarSource(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar-secret",
            )),
            "sidecar-secret",
            "PUBLICATION_SIDECAR_UNAVAILABLE",
        ),
        (
            PublicationError::InvalidJournal(
                "private_key=journal-secret Authorization: Bearer journal-bearer".to_owned(),
            ),
            "journal-secret",
            "PUBLICATION_JOURNAL_INVALID",
        ),
        (
            PublicationError::Backend(PublicationBackendError::permanent(
                "authorization=Bearer backend-secret",
            )),
            "backend-secret",
            "MUSUBI_BACKEND_FAILURE",
        ),
    ] {
        let rendered = CommandOutput::failure("publish", publication_diagnostic(&error))
            .render(OutputFormat::Json)
            .expect("redacted publication diagnostic");
        assert!(!rendered.stdout().contains(secret));
        let document: Value =
            norito::json::from_str(rendered.stdout()).expect("diagnostic document");
        assert_eq!(
            document
                .pointer("/error/context/publication_code")
                .and_then(Value::as_str),
            Some(expected_code)
        );
        assert_eq!(
            document.pointer("/error/message").and_then(Value::as_str),
            Some("publication operation failed")
        );
    }
    #[cfg(unix)]
    {
        let temporary = TempDir::new().expect("temporary publication state");
        let writer = AtomicWriteRoot::new(temporary.path()).expect("bind state root");
        writer
            .install_immutable(Path::new("sidecar"), b"expected")
            .expect("install immutable sidecar");
        let conflict = writer
            .install_immutable(Path::new("sidecar"), b"substituted")
            .expect_err("differing immutable sidecar must conflict");
        let rendered = CommandOutput::failure(
            "publish",
            publication_diagnostic(&PublicationError::JournalWrite(conflict)),
        )
        .render(OutputFormat::Json)
        .expect("redacted sidecar-conflict diagnostic");
        let document: Value =
            norito::json::from_str(rendered.stdout()).expect("diagnostic document");
        assert_eq!(
            document
                .pointer("/error/context/publication_code")
                .and_then(Value::as_str),
            Some("PUBLICATION_STATE_INTEGRITY_INVALID")
        );
    }
}
#[test]
fn prepared_car_validation_stream_is_bounded_and_exact() {
    let bytes = b"canonical-publication-car";
    let size = u64::try_from(bytes.len()).expect("fixture length fits u64");
    let digest = MusubiContentDigestV1::new(*blake3::hash(bytes).as_bytes());
    validate_prepared_car_stream(&mut bytes.as_slice(), size, digest)
        .expect("exact stream validates");
    let length_error = validate_prepared_car_stream(
        &mut bytes.as_slice(),
        size.checked_sub(1).expect("non-empty fixture"),
        digest,
    )
    .expect_err("oversized stream must fail before accepting trailing bytes");
    assert_eq!(length_error.code(), "PACKAGE_VALIDATION_LENGTH_INVALID");
    let digest_error = validate_prepared_car_stream(
        &mut bytes.as_slice(),
        size,
        MusubiContentDigestV1::new([0x55; 32]),
    )
    .expect_err("substituted digest must fail");
    assert_eq!(digest_error.code(), "PACKAGE_VALIDATION_CAR_MISMATCH");
}
#[test]
fn publication_compiler_evidence_and_nonce_are_domain_bound() {
    let interface = MusubiContentDigestV1::new([1; 32]);
    let release = iroha_data_model::musubi::MusubiReleaseDigestV1::new([2; 32]);
    let lock = iroha_data_model::musubi::MusubiVerificationLockDigestV1::new([3; 32]);
    let digest = publication_compiler_output_digest(interface, release, lock);
    assert!(!digest.is_zero());
    assert_ne!(
        digest,
        publication_compiler_output_digest(MusubiContentDigestV1::new([4; 32]), release, lock,)
    );
    let first = unpredictable_publication_nonce();
    let second = unpredictable_publication_nonce();
    assert!(first.iter().any(|byte| *byte != 0));
    assert!(second.iter().any(|byte| *byte != 0));
    assert_ne!(first, second);
}

mod local_workflows {
    include!("command_local_tests.rs");
}

#[test]
fn generated_publication_cache_uses_the_explicit_private_root() {
    let temporary = TempDir::new().expect("private explicit cache fixture");
    // The cache reports its canonical root; temporary roots may sit behind a symlink.
    let selected = fs::canonicalize(temporary.path())
        .expect("canonical temporary root")
        .join("generated-cache");
    let cache = open_cache_at(&selected).expect("existing canonical cache owner");
    assert_eq!(cache.root(), selected);
    assert!(selected.join("registry-v1").is_dir());
    assert!(selected.is_dir());
    assert!(!temporary.path().join("publication-state").exists());
    assert!(!temporary.path().join("namespace-parent").exists());
}

fn serve_runtime_cache_responses(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("runtime registry listener");
    let address = listener.local_addr().expect("runtime registry address");
    listener
        .set_nonblocking(true)
        .expect("bounded runtime listener");
    let server = thread::spawn(move || {
        let mut completed = 0;
        for response in responses {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "registry request was not sent"
                        );
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("runtime registry accept failed: {error}"),
                }
            };
            // Keep accept bounded while the accepted request uses the existing finite timeout.
            stream
                .set_nonblocking(false)
                .expect("blocking registry stream");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("bounded registry read");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("bounded registry write");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2_048];
            let (body_start, content_length) = loop {
                let read = stream.read(&mut buffer).expect("registry query headers");
                assert_ne!(read, 0, "registry query ended early");
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() <= 64 * 1024, "bounded fixture query");
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..header_end]).expect("query headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("query content length"))
                    })
                    .expect("signed registry query has a request body");
                assert!(content_length <= 32 * 1024, "bounded fixture body");
                break (header_end + 4, content_length);
            };
            while request.len() < body_start + content_length {
                let read = stream.read(&mut buffer).expect("registry query body");
                assert_ne!(read, 0, "registry query body ended early");
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() <= 64 * 1024, "bounded complete fixture query");
            }
            write!(stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            ).expect("runtime registry response headers");
            stream
                .write_all(&response)
                .expect("runtime registry response body");
            completed += 1;
        }
        completed
    });
    (format!("http://{address}/"), server)
}

fn runtime_cache_contract_fixture(temp: &TempDir) -> (PathBuf, PathBuf) {
    let (root, manifest) = create_test_package(temp);
    add_dependency_to_fixture_manifest(&manifest);
    fs::write(
        root.join("contract.ko"),
        "seiyaku CachedCoffee { view fn quote(int cups) authorize(anyone) -> int { return cups * 10; } }",
    )
    .expect("real runtime contract source");
    let mut document = fs::read_to_string(&manifest).expect("runtime fixture manifest");
    document.push_str("\n[[contract]]\nname = \"coffee\"\npath = \"contract.ko\"\n");
    fs::write(&manifest, document).expect("runtime fixture contract target");
    (root, manifest)
}

fn runtime_cache_registry_config(torii_url: &str) -> iroha::config::Config {
    iroha::config::Config::load_bytes_with_musubi_publication(
        Path::new("explicit-runtime-cache-client.toml"),
        authenticated_registry_config(torii_url, 753).as_bytes(),
    )
    .expect("explicit registry client fixture")
    .0
}

// These are HTTP query/cache fixtures. Their artifact commitments come from the actual package
// compiler and CAR owner; the synthetic registry snapshot makes no native-finality claim.
#[cfg(unix)]
fn runtime_cache_registry_responses(
    edge: &MusubiExactDependencyEdgeV1,
    node: &MusubiVerificationNodeV1,
) -> Vec<Vec<u8>> {
    use iroha_data_model::musubi::{
        MUSUBI_MIN_HEALTHY_REPLICAS_V1, MusubiArchiveAvailabilityV1,
        MusubiArtifactGovernanceStateV1, MusubiReleaseSelectionStateV1, MusubiReleaseYankV1,
        MusubiResolverIndexPageV1, MusubiResolverIndexQueryV1, MusubiResolverReleaseRowV1,
    };

    let snapshot = recovery_snapshot();
    let selector: MusubiPackageSelectorV1 = "deps.sora/dependency".parse().expect("selector");
    assert_eq!(edge.selected, node.release);
    let directory = MusubiOrderedPackagePageV1 {
        query: MusubiOrderedPrefixQueryV1 {
            prefix: MusubiOrderedPrefixV1::new(&selector.to_string()).expect("exact prefix"),
            page: MusubiPageRequestV1 {
                limit: 2,
                cursor: None,
            },
        },
        network_id: test_network_id(0x31),
        namespace_binding: MusubiNamespaceBindingV1 {
            namespace: selector.namespace.clone(),
            home_dataspace: node.release.package.home_dataspace,
            scope: node.release.package.scope.clone(),
            generation: 1,
        },
        items: vec![MusubiOrderedPackageEntryV1 {
            selector,
            package: node.release.package.clone(),
            latest_selectable: Some(node.release.version.clone()),
            metadata_revision: 1,
            index_revision: snapshot.index_revision,
        }],
        next_cursor: None,
        snapshot,
    };
    let resolver = MusubiResolverIndexPageV1 {
        query: MusubiResolverIndexQueryV1 {
            package: node.release.package.clone(),
            requirement: Some(edge.requirement.clone()),
            page: MusubiPageRequestV1 {
                limit: u32::try_from(MUSUBI_MAX_PAGE_SIZE_V1).expect("page bound"),
                cursor: None,
            },
        },
        network_id: directory.network_id,
        items: vec![MusubiResolverReleaseRowV1 {
            release: node.release.clone(),
            release_digest: node.release_digest,
            archive_id: node.archive_id,
            source_digest: node.source_digest,
            interface_digest: node.interface_digest,
            abi: node.abi,
            dependencies: Vec::new(),
            selection: MusubiReleaseSelectionStateV1 {
                yank: MusubiReleaseYankV1 {
                    release: node.release.clone(),
                    yanked: false,
                    reason: "fixture".parse().expect("fixture reason"),
                    changed_by: test_account(0x5B),
                    changed_at_height: snapshot.finalized_height,
                    revision: 1,
                },
                storage: MusubiArchiveAvailabilityV1 {
                    archive_id: node.archive_id,
                    availability: MusubiStorageAvailabilityV1::Selectable,
                    healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                    active_locations: 1,
                    finalized_height: snapshot.finalized_height,
                    finalized_block_hash: snapshot.finalized_block_hash,
                    index_revision: snapshot.index_revision,
                },
                governance: MusubiArtifactGovernanceStateV1::Available,
            },
            index_revision: snapshot.index_revision,
        }],
        next_cursor: None,
        snapshot,
    };
    directory
        .validate_for(&directory.query)
        .expect("directory fixture");
    resolver
        .validate_for(&resolver.query)
        .expect("resolver fixture");
    let _chain_discriminant = ChainDiscriminantGuard::enter(753);
    vec![
        norito::json::to_vec(&directory).expect("canonical directory response"),
        norito::json::to_vec(&resolver).expect("canonical resolver response"),
    ]
}

#[test]
fn runtime_package_cold_registry_failure_uses_only_selected_cache_root() {
    let temp = TempDir::new().expect("explicit cache fixture");
    let (root, manifest) = runtime_cache_contract_fixture(&temp);
    let selected_cache = temp.path().join("selected-cache");
    let unrelated_cache = temp.path().join("unrelated-cache");
    assert!(!selected_cache.exists());
    let (torii_url, server) = serve_runtime_cache_responses(vec![b"{}".to_vec()]);
    let config = runtime_cache_registry_config(&torii_url);
    let result = build_runtime_package(
        &config,
        &selected_cache,
        Some(&config),
        None,
        &RuntimePackageSelection {
            manifest: &iroha_fs::SelectedRegularFile::capture(&manifest).unwrap(),
            package: None,
            contract: None,
            locked: false,
        },
        None,
    );
    assert_eq!(
        server.join().expect("one actual failed registry response"),
        1
    );
    let error = result.err().expect("malformed registry data refuses build");
    assert!(error.to_string().contains("MUSUBI_E_REGISTRY"));
    assert!(selected_cache.join("registry-v1").is_dir());
    assert!(
        !selected_cache
            .join("registry-v1/resolver-index-v1.norito")
            .exists()
    );
    assert!(!unrelated_cache.exists());
    assert!(!root.join(LOCK_FILE_NAME).exists());
    assert!(!root.join("target").exists());
    assert!(!temp.path().join("journals").exists());
}

#[cfg(unix)]
#[test]
fn runtime_package_recorded_resolver_and_real_archive_reuse_exact_cache_root() {
    let temp = TempDir::new().expect("runtime cache fixture");
    let (root, manifest) = runtime_cache_contract_fixture(&temp);
    let selected_cache = temp.path().join("selected-cache");
    let cache = MusubiCache::open(&selected_cache).expect("explicit immutable cache");
    let (edge, node) = build_and_install_dependency_fixture(temp.path(), &cache);
    cache
        .load_compiler_package(&node)
        .expect("actual compiled CAR is cached");
    let resolver_image = selected_cache.join("registry-v1/resolver-index-v1.norito");
    assert!(!resolver_image.exists(), "the resolver starts cold");
    let (torii_url, server) =
        serve_runtime_cache_responses(runtime_cache_registry_responses(&edge, &node));
    let config = runtime_cache_registry_config(&torii_url);
    let result = build_runtime_package(
        &config,
        &selected_cache,
        Some(&config),
        None,
        &RuntimePackageSelection {
            manifest: &iroha_fs::SelectedRegularFile::capture(&manifest).unwrap(),
            package: None,
            contract: None,
            locked: false,
        },
        None,
    );
    assert_eq!(
        server
            .join()
            .expect("directory and resolver requests completed"),
        2
    );
    let online = result.expect("online resolver reuses actual immutable archive");
    assert_eq!(online.name(), "CachedCoffee");
    let lock_path = root.join(LOCK_FILE_NAME);
    let lock_before = fs::read(&lock_path).expect("resolved lock bytes");
    let lock = LockfileV1::read(&lock_path).expect("authenticated registry lock");
    assert_eq!(lock.nodes, vec![node.clone()]);
    assert_eq!(
        lock.registry_context().expect("registry identity").0,
        config.network_id
    );
    let resolver_before = fs::read(&resolver_image).expect("sole recorder wrote resolver cache");

    // A live, unserved listener makes any attempted registry HTTP observable. The only usable
    // pages and archive are the immutable inputs retained below the explicitly selected root.
    let observer = TcpListener::bind("127.0.0.1:0").expect("no-HTTP observer");
    observer
        .set_nonblocking(true)
        .expect("nonblocking observer");
    let offline_config = runtime_cache_registry_config(&format!(
        "http://{}/",
        observer.local_addr().expect("observer address")
    ));
    let offline = build_runtime_package(
        &offline_config,
        &selected_cache,
        Some(&offline_config),
        None,
        &RuntimePackageSelection {
            manifest: &iroha_fs::SelectedRegularFile::capture(&manifest).unwrap(),
            package: None,
            contract: None,
            locked: true,
        },
        None,
    )
    .expect("locked cache reuse without registry or provider HTTP");
    assert_eq!(offline.bytes(), online.bytes());
    assert!(matches!(observer.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert_eq!(fs::read(&lock_path).expect("retained lock"), lock_before);
    assert_eq!(
        fs::read(&resolver_image).expect("retained resolver"),
        resolver_before
    );
    cache
        .load_compiler_package(&node)
        .expect("original archive remains valid");

    let other_cache = temp.path().join("other-cache");
    assert!(!other_cache.exists());
    let (refusing_url, server) = serve_runtime_cache_responses(vec![b"{}".to_vec()]);
    let refusing_config = runtime_cache_registry_config(&refusing_url);
    let result = build_runtime_package(
        &refusing_config,
        &other_cache,
        Some(&refusing_config),
        None,
        &RuntimePackageSelection {
            manifest: &iroha_fs::SelectedRegularFile::capture(&manifest).unwrap(),
            package: None,
            contract: None,
            locked: true,
        },
        None,
    );
    assert_eq!(
        server
            .join()
            .expect("new cache requires its own registry read"),
        1
    );
    let error = result
        .err()
        .expect("another root cannot reuse the first cache");
    assert!(error.to_string().contains("MUSUBI_E_REGISTRY"));
    assert!(other_cache.join("registry-v1").is_dir());
    assert!(
        !other_cache
            .join("registry-v1/resolver-index-v1.norito")
            .exists()
    );
    assert!(
        MusubiCache::open(&other_cache)
            .expect("other cache")
            .load_compiler_package(&node)
            .is_err()
    );
    assert_eq!(fs::read(&lock_path).expect("unchanged lock"), lock_before);
    assert_eq!(
        fs::read(&resolver_image).expect("unchanged first cache"),
        resolver_before
    );
    assert!(!temp.path().join("journals").exists());
}

#[cfg(unix)]
fn contract_package(temp: &TempDir) -> PathBuf {
    let root = temp.path().join("hello");
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("new"),
        root.as_os_str().to_owned(),
    ]);
    assert_eq!(invocation.output.exit_code(), 0);
    root.join(MANIFEST_FILE_NAME)
}

#[cfg(unix)]
fn run_with_manifest(manifest: &Path, arguments: &[&str]) -> Invocation {
    let mut argv = vec![
        OsString::from("musubi"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
    ];
    argv.extend(arguments.iter().map(OsString::from));
    invoke(argv)
}

#[cfg(unix)]
#[test]
fn unbound_local_commands_use_the_data_model_default_address_profile() {
    let temp = TempDir::new().expect("package directory");
    let manifest = contract_package(&temp);
    let check = run_with_manifest(&manifest, &["--format", "json", "check"]);
    let rendered = check.output.render(check.format).expect("json");
    assert_eq!(rendered.exit_code(), 0, "{}", rendered.stdout());
    let document: Value = norito::json::from_str(rendered.stdout()).expect("document");
    assert_eq!(
        document
            .pointer("/data/network/chain_discriminant")
            .and_then(Value::as_u64),
        Some(u64::from(
            iroha_data_model::account::address::chain_discriminant()
        ))
    );
    assert_eq!(
        document
            .pointer("/data/network/name")
            .and_then(Value::as_str),
        Some("local")
    );
    let human = run_with_manifest(&manifest, &["check"])
        .output
        .render(OutputFormat::Human)
        .expect("human");
    assert!(
        human
            .stdout()
            .starts_with("Local compilation for address profile 753;"),
        "{}",
        human.stdout()
    );
    let taira = run_with_manifest(
        &manifest,
        &["--format", "json", "check", "--network", "taira"],
    );
    let taira = taira.output.render(taira.format).expect("taira json");
    let taira: Value = norito::json::from_str(taira.stdout()).expect("taira document");
    assert_eq!(
        taira
            .pointer("/data/network/chain_discriminant")
            .and_then(Value::as_u64),
        Some(369)
    );
}

#[cfg(unix)]
#[test]
fn compiler_failures_reach_json_and_sarif_as_canonical_diagnostics() {
    let temp = TempDir::new().expect("package directory");
    let manifest = contract_package(&temp);
    let contract = manifest
        .parent()
        .expect("package root")
        .join("contracts/hello.ko");
    let source = fs::read_to_string(&contract).expect("contract");
    fs::write(&contract, source.replace("return count;", "return true;"))
        .expect("introduce a type error");
    let human = run_with_manifest(&manifest, &["check"]);
    let error = match &human.output.render(OutputFormat::Human) {
        Ok(rendered) => {
            assert_eq!(rendered.exit_code(), ErrorCode::Compiler.exit_code());
            rendered.stderr().to_owned()
        }
        Err(error) => panic!("render: {error}"),
    };
    assert_eq!(
        error.matches("error[MUSUBI_E_COMPILER]").count(),
        1,
        "{error}"
    );
    assert!(!error.contains("compiler failed: error["), "{error}");
    assert!(error.contains("--> contracts/hello.ko:"), "{error}");
    let json = run_with_manifest(&manifest, &["--format", "json", "check"]);
    let rendered = json.output.render(json.format).expect("json");
    let document: Value = norito::json::from_str(rendered.stdout()).expect("document");
    let diagnostic = document
        .pointer("/error/diagnostics/0")
        .expect("canonical diagnostic record");
    assert!(diagnostic.get("code").and_then(Value::as_str).is_some());
    assert_eq!(
        diagnostic
            .pointer("/primary_span/source")
            .and_then(Value::as_str),
        Some("contracts/hello.ko")
    );
    assert!(
        !document
            .pointer("/error/message")
            .and_then(Value::as_str)
            .expect("summary")
            .contains("error[")
    );
    let sarif = run_with_manifest(&manifest, &["--format", "sarif", "build"]);
    assert_eq!(sarif.format, OutputFormat::Sarif);
    let rendered = sarif.output.render(sarif.format).expect("sarif");
    assert_eq!(rendered.exit_code(), ErrorCode::Compiler.exit_code());
    let document: Value = norito::json::from_str(rendered.stdout()).expect("sarif document");
    assert!(
        document
            .pointer("/runs/0/results/0/ruleId")
            .and_then(Value::as_str)
            .is_some()
    );
    let other = run_with_manifest(&manifest, &["--format", "sarif", "metadata"]);
    let rendered = other.output.render(other.format).expect("sarif usage");
    assert_eq!(rendered.exit_code(), ErrorCode::Usage.exit_code());
    assert!(rendered.stdout().contains("MUSUBI_E_USAGE"));
}

#[cfg(unix)]
#[test]
fn test_source_parse_and_semantic_failures_reach_json_and_sarif() {
    let temp = TempDir::new().expect("package directory");
    let manifest = contract_package(&temp);
    let test_path = manifest
        .parent()
        .expect("package root")
        .join("tests/hello.test.ko");
    for body in ["let int value = 1", "test::assert(missing());"] {
        fs::write(
            &test_path,
            format!(
                r#"module Tests {{
            koto_test {{ target: "../contracts/hello.ko" }}
            #[test] fn broken() {{ {body} }}
        }}"#
            ),
        )
        .expect("invalid test source");
        let invocation = run_with_manifest(&manifest, &["--format", "json", "test"]);
        let rendered = invocation.output.render(invocation.format).expect("json");
        assert_eq!(
            rendered.exit_code(),
            ErrorCode::Compiler.exit_code(),
            "{}",
            rendered.stdout()
        );
        let json: Value = norito::json::from_str(rendered.stdout()).expect("json document");
        assert_eq!(
            json.pointer("/error/diagnostics/0/primary_span/source")
                .and_then(Value::as_str),
            Some("tests/hello.test.ko")
        );
        let invocation = run_with_manifest(&manifest, &["--format", "sarif", "test"]);
        let rendered = invocation.output.render(invocation.format).expect("sarif");
        assert_eq!(rendered.exit_code(), ErrorCode::Compiler.exit_code());
        let sarif: Value = norito::json::from_str(rendered.stdout()).expect("sarif document");
        let rule = sarif
            .pointer("/runs/0/results/0/ruleId")
            .and_then(Value::as_str)
            .expect("canonical compiler code");
        assert!(!rule.starts_with("MUSUBI_"), "{rule}");
        assert_eq!(
            sarif
                .pointer("/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri")
                .and_then(Value::as_str),
            Some("tests/hello.test.ko")
        );
    }
}

#[test]
fn usage_errors_have_one_prefix_and_zk_reaches_the_build_options() {
    let rendered = invoke(["musubi", "new"])
        .output
        .render(OutputFormat::Human)
        .expect("usage failure");
    assert!(
        rendered
            .stderr()
            .starts_with("error[MUSUBI_E_USAGE]: the following required"),
        "{}",
        rendered.stderr()
    );
    assert!(!rendered.stderr().contains("error[MUSUBI_E_USAGE]: error:"));
    for command in ["check", "build", "test"] {
        let parsed = Cli::try_parse_from(["musubi", command, "--zk"]).expect("zk flag");
        let args = match parsed.command {
            Command::Check(args) | Command::Build(args) => args,
            Command::Test(args) => args.build,
            _ => panic!("expected compiler command"),
        };
        assert!(args.zk);
    }
    let sarif = invoke(["musubi", "--format", "sarif", "bogus"]);
    assert_eq!(sarif.format, OutputFormat::Sarif);
}

#[test]
fn escaping_path_dependencies_explain_the_shared_workspace() {
    let help = shared_workspace_help(Path::new("/projects/app"), Path::new("/projects/feemath"));
    assert!(help.contains("/projects/Musubi.toml"), "{help}");
    assert!(help.contains(r#"members = ["app", "feemath"]"#), "{help}");
    assert!(help.contains("--create-workspace"), "{help}");
}

#[cfg(unix)]
fn new_package(parent: &Path, name: &str, template: &str) -> PathBuf {
    let root = parent.join(name);
    let invocation = invoke([
        OsString::from("musubi"),
        OsString::from("new"),
        root.as_os_str().to_owned(),
        OsString::from("--template"),
        OsString::from(template),
    ]);
    let rendered = invocation
        .output
        .render(OutputFormat::Human)
        .expect("scaffold output");
    assert_eq!(rendered.exit_code(), 0, "{}", rendered.stderr());
    root.join(MANIFEST_FILE_NAME)
}

#[cfg(unix)]
#[test]
fn sibling_path_dependencies_can_create_their_shared_workspace() {
    let temp = TempDir::new().expect("project directory");
    let projects = fs::canonicalize(temp.path()).expect("canonical project directory");
    let app = new_package(&projects, "app", "contract");
    let _feemath = new_package(&projects, "feemath", "library");
    let shared = projects.join(MANIFEST_FILE_NAME);
    let standalone = run_with_manifest(&app, &["check"]);
    assert_eq!(standalone.output.exit_code(), 0);
    assert!(projects.join("app").join(LOCK_FILE_NAME).is_file());
    let refused = run_with_manifest(&app, &["add", "feemath", "--path", "../feemath"]);
    let rendered = refused.output.render(OutputFormat::Human).expect("refusal");
    assert_eq!(
        rendered.exit_code(),
        ErrorCode::WorkspaceInvalid.exit_code(),
        "{}",
        rendered.stderr()
    );
    assert!(
        rendered.stderr().contains("--create-workspace"),
        "{}",
        rendered.stderr()
    );
    assert!(!shared.exists());
    let added = run_with_manifest(
        &app,
        &[
            "add",
            "feemath",
            "--path",
            "../feemath",
            "--create-workspace",
        ],
    );
    let rendered = added.output.render(OutputFormat::Human).expect("added");
    assert_eq!(rendered.exit_code(), 0, "{}", rendered.stderr());
    assert!(
        rendered.stdout().contains("created workspace"),
        "{}",
        rendered.stdout()
    );
    assert_eq!(
        fs::read_to_string(&shared).expect("created workspace"),
        "manifest-version = 1\n\n[workspace]\nmembers = [\"app\", \"feemath\"]\n"
    );
    let workspace = load_workspace(&app).expect("shared workspace");
    assert_eq!(workspace.root(), projects);
    assert_eq!(workspace.members().len(), 2);
    assert!(
        fs::read_to_string(&app)
            .expect("app manifest")
            .contains("feemath = { path = \"../feemath\" }")
    );
    // The app was checked as a standalone package before; its old lock is reported, not deleted.
    let stale = projects.join("app").join(LOCK_FILE_NAME);
    assert!(
        rendered
            .stdout()
            .contains(&format!("{} is no longer read; delete it", stale.display())),
        "{}",
        rendered.stdout()
    );
    assert!(stale.is_file());
    let checked = run_with_manifest(&app, &["check"]);
    let rendered = checked.output.render(OutputFormat::Human).expect("check");
    assert_eq!(rendered.exit_code(), 0, "{}", rendered.stderr());
    assert!(projects.join(LOCK_FILE_NAME).is_file());
    let again = run_with_manifest(
        &app,
        &["add", "other", "--path", "../feemath", "--create-workspace"],
    );
    assert_eq!(again.output.exit_code(), ErrorCode::Usage.exit_code());
}

#[cfg(unix)]
#[test]
fn publishing_refuses_the_scaffold_placeholder_namespace() {
    let temp = TempDir::new().expect("project directory");
    let projects = fs::canonicalize(temp.path()).expect("canonical project directory");
    let app = new_package(&projects, "app", "contract");
    let refused = run_with_manifest(&app, &["publish"]);
    let rendered = refused.output.render(OutputFormat::Human).expect("refusal");
    assert_eq!(
        rendered.exit_code(),
        ErrorCode::Usage.exit_code(),
        "{}",
        rendered.stderr()
    );
    assert!(
        rendered.stderr().contains("placeholder namespace `local`"),
        "{}",
        rendered.stderr()
    );
    assert!(!projects.join("app").join(PUBLICATION_LOCK_PATH).exists());
    assert!(reject_placeholder_namespace(&"local/app".parse().expect("selector")).is_err());
    assert!(reject_placeholder_namespace(&"demo/app".parse().expect("selector")).is_ok());
}

#[cfg(unix)]
#[test]
fn creating_a_shared_workspace_refuses_root_scoped_state_and_writes_nothing() {
    let temp = TempDir::new().expect("project directory");
    let projects = fs::canonicalize(temp.path()).expect("canonical project directory");
    let app = new_package(&projects, "app", "contract");
    let _feemath = new_package(&projects, "feemath", "library");
    fs::write(projects.join("app/Musubi.networks.toml"), "version = 1\n")
        .expect("network bindings");
    let refused = run_with_manifest(
        &app,
        &[
            "add",
            "feemath",
            "--path",
            "../feemath",
            "--create-workspace",
        ],
    );
    let rendered = refused.output.render(OutputFormat::Human).expect("refusal");
    assert_eq!(
        rendered.exit_code(),
        ErrorCode::WorkspaceInvalid.exit_code(),
        "{}",
        rendered.stderr()
    );
    assert!(
        rendered.stderr().contains("Musubi.networks.toml"),
        "{}",
        rendered.stderr()
    );
    assert!(!projects.join(MANIFEST_FILE_NAME).exists());
    assert!(
        !fs::read_to_string(&app)
            .expect("app manifest")
            .contains("feemath")
    );
    assert!(
        Cli::try_parse_from(["musubi", "add", "feemath", "--create-workspace"]).is_err(),
        "--create-workspace requires --path"
    );
}

#[cfg(unix)]
#[test]
fn workspace_diagnostics_name_member_sources_from_the_workspace_root() {
    let temp = TempDir::new().expect("project directory");
    let projects = fs::canonicalize(temp.path()).expect("canonical project directory");
    let app = new_package(&projects, "app", "contract");
    let _feemath = new_package(&projects, "feemath", "library");
    let added = run_with_manifest(
        &app,
        &[
            "add",
            "feemath",
            "--path",
            "../feemath",
            "--create-workspace",
        ],
    );
    assert_eq!(added.output.exit_code(), 0);
    let shared = projects.join(MANIFEST_FILE_NAME);
    let library = projects.join("feemath/src/lib.ko");
    let library_source = fs::read_to_string(&library).expect("library source");
    fs::write(
        &library,
        "module Feemath {\n    export fn double(int x) -> int {\n        return true;\n    }\n}\n",
    )
    .expect("introduce a library type error");
    let located = |format: &str| {
        let invocation = run_with_manifest(&shared, &["--format", format, "check", "--workspace"]);
        let rendered = invocation.output.render(invocation.format).expect("render");
        assert_eq!(rendered.exit_code(), ErrorCode::Compiler.exit_code());
        rendered
    };
    let json: Value = norito::json::from_str(located("json").stdout()).expect("json document");
    let span = json
        .pointer("/error/diagnostics/0/primary_span")
        .expect("library diagnostic span");
    assert_eq!(
        span.get("source").and_then(Value::as_str),
        Some("feemath/src/lib.ko")
    );
    assert_eq!(span.get("package_identity"), Some(&Value::Null));
    let human = located("human");
    assert!(
        human.stderr().contains("--> feemath/src/lib.ko:3:9"),
        "{}",
        human.stderr()
    );
    assert!(
        !human.stderr().contains("musubi/local/"),
        "{}",
        human.stderr()
    );
    fs::write(&library, library_source).expect("restore library");
    let contract = projects.join("app/contracts/app.ko");
    let contract_source = fs::read_to_string(&contract).expect("contract source");
    fs::write(
        &contract,
        contract_source.replace("return count;", "return true;"),
    )
    .expect("introduce a contract type error");
    let sarif: Value = norito::json::from_str(located("sarif").stdout()).expect("sarif document");
    assert_eq!(
        sarif
            .pointer("/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri")
            .and_then(Value::as_str),
        Some("app/contracts/app.ko")
    );
    let standalone = run_with_manifest(&app, &["--format", "json", "check"]);
    let rendered = standalone
        .output
        .render(standalone.format)
        .expect("member json");
    let document: Value = norito::json::from_str(rendered.stdout()).expect("member document");
    assert_eq!(
        document
            .pointer("/error/diagnostics/0/primary_span/source")
            .and_then(Value::as_str),
        Some("app/contracts/app.ko"),
        "member commands report paths from the shared workspace root"
    );
}
