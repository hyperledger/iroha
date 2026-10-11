"""Source guards for aggregated Cargo integration-test targets."""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class TargetContract:
    package: str
    target: str
    root: str
    modules: tuple[tuple[str, str], ...]
    tests: tuple[str, ...]


@dataclass(frozen=True)
class WaveTwoTarget:
    package: str
    target: str
    root: str
    modules: tuple[tuple[str, str], ...]
    required_features: tuple[str, ...] = ()
    dead_code_modules: tuple[str, ...] = ()
    serial: bool = False


XTASK_MODULES = tuple(
    (name, f"{name}.rs")
    for name in (
        "address_vectors",
        "android_dashboard_parity_cli",
        "codec_rans_tables",
        "da_proof_bench",
        "iso_bridge_lint",
        "ministry_agenda",
        "mochi_bundle",
        "sm_wycheproof_sync",
        "soradns_cli",
        "sorafs_fetch_fixture",
        "soranet_bug_bounty",
        "soranet_chaos",
        "soranet_gateway_billing",
        "soranet_gateway_m0",
        "soranet_gateway_m1",
        "soranet_gateway_m2",
        "soranet_gateway_ops_m0",
        "soranet_pop_template",
        "streaming_bundle_check",
        "streaming_entropy_bench",
    )
)


XTASK_TESTS = tuple(
    line.strip()
    for line in """
address_vectors::address_vectors_verify_defaults
address_vectors::address_vectors_write_custom_path
android_dashboard_parity_cli::dashboard_parity_cli_respects_cli_overrides
codec_rans_tables::rans_tables_generation_is_deterministic
codec_rans_tables::verify_tables_detects_tampering
codec_rans_tables::bundled_tables_enable_roundtrip
da_proof_bench::da_proof_bench_emits_reports
iso_bridge_lint::iso_bridge_lint_defaults_pass
iso_bridge_lint::iso_bridge_lint_rejects_unknown_instrument_fixture
ministry_agenda::ministry_agenda_validate_example_passes
ministry_agenda::ministry_agenda_duplicate_conflict_is_reported
mochi_bundle::mochi_bundle_command_generates_manifest
mochi_bundle::mochi_bundle_matrix_and_smoke
mochi_bundle::mochi_bundle_stage_directory_copies_bundle
sm_wycheproof_sync::sm_wycheproof_sync_from_file
sm_wycheproof_sync::sm_wycheproof_sync_from_url
soradns_cli::soradns_hosts_reports_expected_derivations
soradns_cli::soradns_hosts_supports_taira_mon_pretty_suffix
soradns_cli::soradns_binding_template_writes_payload_and_headers
soradns_cli::soradns_gar_template_renders_payload
soradns_cli::soradns_gar_template_derives_manifest_metadata
soradns_cli::soradns_cache_plan_renders_targets
soradns_cli::soradns_acme_plan_covers_canonical_and_pretty_hosts
soradns_cli::soradns_acme_plan_supports_taira_mon_pretty_suffix
sorafs_fetch_fixture::sorafs_fetch_fixture_copies_and_verifies_local_files
soranet_bug_bounty::bug_bounty_pack_is_emitted
soranet_chaos::soranet_chaos_kit_and_report_round_trip
soranet_gateway_billing::soranet_gateway_billing_runs_end_to_end
soranet_gateway_m0::soranet_gateway_m0_pack_is_deterministic
soranet_gateway_m1::soranet_gateway_m1_bundle_is_emitted
soranet_gateway_m2::soranet_gateway_m2_pipeline_emits_beta_and_ga
soranet_gateway_ops_m0::soranet_gateway_ops_m0_pack_is_deterministic
soranet_pop_template::soranet_pop_template_renders_fixture
soranet_pop_template::soranet_pop_template_writes_resolver_config
soranet_pop_template::soranet_pop_validate_reports_metadata
soranet_pop_template::soranet_pop_policy_report_emits_monitoring_pack
soranet_pop_template::soranet_pop_bundle_embeds_route_health_probe
soranet_pop_template::soranet_pop_bundle_writes_manifest_and_assets
soranet_pop_template::soranet_popctl_aliases_pop_bundle
streaming_bundle_check::streaming_bundle_check_reports_bundled_requirements
streaming_entropy_bench::streaming_entropy_bench_emits_metrics
streaming_entropy_bench::streaming_entropy_bench_roundtrips_chroma_and_yuv_psnr
streaming_entropy_bench::streaming_entropy_bench_respects_quantizer_override
streaming_entropy_bench::streaming_entropy_bench_supports_quantizer_ladder_and_tiny_preset
""".splitlines()
    if line.strip()
)


SCHEMA = TargetContract(
    package="crates/iroha_schema",
    target="schema",
    root="schema.rs",
    modules=(
        ("architecture_dependent", "architecture-dependent.rs"),
        ("enum_with_default_discriminants", "enum_with_default_discriminants.rs"),
        ("enum_with_various_discriminants", "enum_with_various_discriminants.rs"),
        ("fieldless_enum", "fieldless_enum.rs"),
        ("floats", "floats.rs"),
        ("non_zero", "non_zero.rs"),
        ("numbers_compact_and_fixed", "numbers_compact_and_fixed.rs"),
        ("schema_json", "schema_json.rs"),
        ("struct_with_generic_bounds", "struct_with_generic_bounds.rs"),
        ("struct_with_named_fields", "struct_with_named_fields.rs"),
        ("struct_with_unnamed_fields", "struct_with_unnamed_fields.rs"),
        ("transparent_types", "transparent_types.rs"),
    ),
    tests=tuple(
        line.strip()
        for line in """
architecture_dependent::usize_isize_not_into_schema
enum_with_default_discriminants::default_discriminants
enum_with_various_discriminants::discriminant
enum_with_various_discriminants::schema_discriminants_match_encoded_u32_tags
fieldless_enum::discriminant
floats::float_primitives_have_explicit_schema_metadata
non_zero::non_zero_integers_schema
non_zero::arch_dependent_non_zero_are_excluded
numbers_compact_and_fixed::compact
schema_json::test_struct
schema_json::test_struct_codec_attr
schema_json::test_transparent
schema_json::test_enum
schema_json::test_enum_with_norito_rename_all
schema_json::test_enum_codec_attr
struct_with_generic_bounds::check_generic
struct_with_named_fields::named_fields
struct_with_unnamed_fields::unnamed
transparent_types::transparent_types
""".splitlines()
        if line.strip()
    ),
)


XTASK = TargetContract(
    package="xtask",
    target="integration",
    root="integration.rs",
    modules=XTASK_MODULES,
    tests=XTASK_TESTS,
)


WAVE_TWO_TARGETS = (
    WaveTwoTarget(
        package="crates/iroha_derive",
        target="container_enum_from_variant",
        root="container_enum_from_variant.rs",
        modules=(("enum_from_variant_attrs", "enum_from_variant_attrs.rs"),),
        dead_code_modules=("enum_from_variant_attrs",),
    ),
    WaveTwoTarget(
        package="crates/iroha_derive",
        target="ui",
        root="ui.rs",
        modules=(("config_base_ui", "config_base_ui.rs"),),
        required_features=("trybuild-tests",),
        serial=True,
    ),
    WaveTwoTarget(
        package="crates/iroha_monitor",
        target="smoke",
        root="smoke.rs",
        modules=(
            ("attach_render", "attach_render.rs"),
            ("http_limits", "http_limits.rs"),
            ("invalid_credentials", "invalid_credentials.rs"),
        ),
        serial=True,
    ),
    WaveTwoTarget(
        package="crates/iroha_primitives",
        target="addr_parsing",
        root="addr_parsing.rs",
        modules=(("numeric_inspect", "numeric_inspect.rs"),),
    ),
    WaveTwoTarget(
        package="crates/iroha_primitives",
        target="ui",
        root="ui.rs",
        modules=(),
        required_features=("trybuild-tests",),
    ),
    # Its global allocator census must run in its own registered test process.
    WaveTwoTarget(
        package="crates/iroha_primitives",
        target="numeric_abi_encoding_allocations",
        root="numeric_abi_encoding_allocations.rs",
        modules=(),
    ),
    WaveTwoTarget(
        package="crates/iroha_zkp_halo2",
        target="vega_engine_reachability",
        root="vega_engine_reachability.rs",
        modules=(
            (
                "vega_microsoft_cross_conformance",
                "vega_microsoft_cross_conformance.rs",
            ),
        ),
        required_features=("full",),
    ),
    WaveTwoTarget(
        package="crates/iroha_zkp_halo2",
        target="ipa_minimum_dimension",
        root="ipa_minimum_dimension.rs",
        modules=(),
        required_features=("full",),
    ),
    WaveTwoTarget(
        package="crates/soranet_pq",
        target="kat_vectors",
        root="kat_vectors.rs",
        modules=(("pq_kat", "pq_kat.rs"),),
    ),
    WaveTwoTarget(
        package="mochi/mochi-core",
        target="composer_drafts",
        root="composer_drafts.rs",
        modules=(("torii_streams", "torii_streams.rs"),),
    ),
    WaveTwoTarget(
        package="mochi/mochi-integration",
        target="readiness_smoke",
        root="readiness_smoke.rs",
        modules=(),
    ),
    WaveTwoTarget(
        package="crates/sorafs_node",
        target="pin_workflows",
        root="pin_workflows.rs",
        modules=(("cli", "cli.rs"), ("publication_roundtrip", "publication_roundtrip.rs")),
    ),
    WaveTwoTarget(
        package="tools/soranet-handshake-harness",
        target="fixtures_verify",
        root="fixtures_verify.rs",
        modules=(
            ("interop_parity", "interop_parity.rs"),
            ("perf_gate", "perf_gate.rs"),
            ("simulate_cli", "simulate_cli.rs"),
        ),
        serial=True,
    ),
)


WAVE_TWO_SOURCE_PATHS = (
    'crates/iroha_zkp_halo2/tests/ipa_minimum_dimension.rs',
    'crates/sorafs_node/tests/publication_roundtrip.rs',
    'crates/iroha_derive/tests/config_base_ui.rs',
    'crates/iroha_derive/tests/container_enum_from_variant.rs',
    'crates/iroha_derive/tests/enum_from_variant_attrs.rs',
    'crates/iroha_derive/tests/ui.rs',
    'crates/iroha_monitor/tests/attach_render.rs',
    'crates/iroha_monitor/tests/http_limits.rs',
    'crates/iroha_monitor/tests/invalid_credentials.rs',
    'crates/iroha_monitor/tests/smoke.rs',
    'crates/iroha_primitives/tests/addr_parsing.rs',
    'crates/iroha_primitives/tests/numeric_inspect.rs',
    'crates/iroha_primitives/tests/numeric_abi_encoding_allocations.rs',
    'crates/iroha_primitives/tests/ui.rs',
    'crates/iroha_zkp_halo2/tests/vega_engine_reachability.rs',
    'crates/iroha_zkp_halo2/tests/vega_microsoft_cross_conformance.rs',
    'crates/soranet_pq/tests/kat_vectors.rs',
    'crates/soranet_pq/tests/pq_kat.rs',
    'crates/sorafs_node/tests/cli.rs',
    'crates/sorafs_node/tests/pin_workflows.rs',
    'mochi/mochi-core/tests/composer_drafts.rs',
    'mochi/mochi-core/tests/torii_streams.rs',
    'mochi/mochi-integration/tests/readiness_smoke.rs',
    'tools/soranet-handshake-harness/tests/fixtures_verify.rs',
    'tools/soranet-handshake-harness/tests/interop_parity.rs',
    'tools/soranet-handshake-harness/tests/perf_gate.rs',
    'tools/soranet-handshake-harness/tests/simulate_cli.rs',
)


SERIAL_GUARD_SOURCE = """fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
"""
SERIAL_CALL = "    let _serial = crate::serial_guard();\n"


def _test_tables(manifest: str) -> list[str]:
    return [
        table.strip()
        for table in re.findall(r"(?ms)^\[\[test\]\]\n(.*?)(?=^\[|\Z)", manifest)
    ]


def _module_rows(source: str) -> tuple[tuple[str, str], ...]:
    return tuple(
        (module, path)
        for path, module in re.findall(
            r'#\[path = "([^"]+)"\]\nmod ([a-z0-9_]+);', source
        )
    )


def _test_names(module: str, source: str) -> tuple[str, ...]:
    attrs = re.findall(
        r"(?m)^\s*#\[([^]]*test[^]]*)\]\s*\n\s*fn\s+([A-Za-z0-9_]+)", source
    )
    if any(attr != "test" for attr, _ in attrs):
        raise AssertionError(f"{module}: non-plain test attribute found: {attrs!r}")
    return tuple(f"{module}::{name}" for _, name in attrs)


def validate(contract: TargetContract) -> None:
    package = ROOT / contract.package
    manifest = (package / "Cargo.toml").read_text(encoding="utf-8")
    package_table = manifest.split("\n[", 1)[0]
    if not re.search(r"(?m)^autotests = false$", package_table):
        raise AssertionError(f"{contract.package}: autotests must be disabled")
    tables = _test_tables(manifest)
    expected_table = f'name = "{contract.target}"\npath = "tests/{contract.root}"'
    if tables != [expected_table]:
        raise AssertionError(f"{contract.package}: unexpected test target tables: {tables!r}")

    tests_dir = package / "tests"
    aggregate = (tests_dir / contract.root).read_text(encoding="utf-8")
    if _module_rows(aggregate) != contract.modules:
        raise AssertionError(f"{contract.package}: aggregate module inventory drifted")

    actual_tests: list[str] = []
    for module, path in contract.modules:
        source = (tests_dir / path).read_text(encoding="utf-8")
        actual_tests.extend(_test_names(module, source))
    if tuple(actual_tests) != contract.tests:
        raise AssertionError(f"{contract.package}: historical test inventory drifted")


def _wave_two_packages() -> tuple[str, ...]:
    return tuple(dict.fromkeys(target.package for target in WAVE_TWO_TARGETS))


def _wave_two_table(target: WaveTwoTarget) -> str:
    lines = [f'name = "{target.target}"', f'path = "tests/{target.root}"']
    if target.required_features:
        features = ", ".join(f'"{feature}"' for feature in target.required_features)
        lines.append(f"required-features = [{features}]")
    return "\n".join(lines)


def _wave_two_module_declaration(
    target: WaveTwoTarget, module: str, path: str
) -> str:
    allow = "#[allow(dead_code)]\n" if module in target.dead_code_modules else ""
    return f'{allow}#[path = "{path}"]\nmod {module};\n'


def _wave_two_expected_paths() -> set[str]:
    paths = {f"{package}/Cargo.toml" for package in _wave_two_packages()}
    paths.update(WAVE_TWO_SOURCE_PATHS)
    return paths


def _read_wave_two_sources() -> dict[str, str]:
    paths = {f"{package}/Cargo.toml" for package in _wave_two_packages()}
    for package in _wave_two_packages():
        tests_dir = ROOT / package / "tests"
        paths.update(
            path.relative_to(ROOT).as_posix() for path in tests_dir.glob("*.rs")
        )
    return {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in sorted(paths)
    }


def _test_items(source: str) -> tuple[tuple[str, str], ...]:
    return tuple(
        re.findall(
            r"(?m)^\s*#\[((?:tokio::)?test(?:\([^]\n]*\))?)\]\s*\n"
            r"\s*(?:async\s+)?fn\s+([A-Za-z0-9_]+)",
            source,
        )
    )




def _serial_members() -> set[str]:
    members: set[str] = set()
    for target in WAVE_TWO_TARGETS:
        if not target.serial:
            continue
        members.add(f"{target.package}/tests/{target.root}")
        members.update(f"{target.package}/tests/{path}" for _, path in target.modules)
    return members


def _normalized_wave_two_source(path: str, source: str) -> str:
    for target in WAVE_TWO_TARGETS:
        root = f"{target.package}/tests/{target.root}"
        if path != root:
            continue
        for module, module_path in target.modules:
            declaration = _wave_two_module_declaration(target, module, module_path)
            if source.count(declaration) != 1:
                raise AssertionError(f"{path}: module declaration is not unique")
            source = source.replace(declaration, "", 1)
        if target.serial:
            if source.count(SERIAL_GUARD_SOURCE) != 1:
                raise AssertionError(f"{path}: serial guard is not unique")
            source = source.replace(SERIAL_GUARD_SOURCE, "", 1)

    if path in _serial_members():
        expected_calls = len(_test_items(source))
        if source.count(SERIAL_CALL) != expected_calls:
            raise AssertionError(f"{path}: serial call count drifted")
        source = source.replace(SERIAL_CALL, "")
    elif SERIAL_CALL in source:
        raise AssertionError(f"{path}: unexpected serial call")
    return source


def validate_wave_two(sources: dict[str, str] | None = None) -> None:
    if sources is None:
        sources = _read_wave_two_sources()
    expected_paths = _wave_two_expected_paths()
    if set(sources) != expected_paths:
        raise AssertionError("wave-two source path inventory drifted")

    target_rows: list[str] = []
    module_rows: list[str] = []
    for package in _wave_two_packages():
        manifest_path = f"{package}/Cargo.toml"
        manifest = sources[manifest_path]
        package_table = manifest.split("\n[", 1)[0]
        if package_table.count("autotests = false") != 1:
            raise AssertionError(f"{package}: autotests must be disabled exactly once")
        targets = tuple(
            target for target in WAVE_TWO_TARGETS if target.package == package
        )
        expected_tables = [_wave_two_table(target) for target in targets]
        if _test_tables(manifest) != expected_tables:
            raise AssertionError(f"{package}: explicit target inventory drifted")

        for target in targets:
            features = ",".join(target.required_features)
            target_rows.append(f"{package}\0{target.target}\0{features}\n")
            root_path = f"{package}/tests/{target.root}"
            root = sources[root_path]
            if _module_rows(root) != target.modules:
                raise AssertionError(f"{root_path}: child module inventory drifted")
            for module, module_path in target.modules:
                marker = "dead_code" if module in target.dead_code_modules else ""
                module_rows.append(
                    f"{package}\0{target.root}\0{module}\0{module_path}\0{marker}\n"
                )
                declaration = _wave_two_module_declaration(
                    target, module, module_path
                )
                if root.count(declaration) != 1:
                    raise AssertionError(
                        f"{root_path}: child module declaration drifted"
                    )

    serial_members = _serial_members()
    serial_test_count = 0
    for path in serial_members:
        source = sources[path]
        for _, name in _test_items(source):
            serial_test_count += 1
            first_statement = f"fn {name}() {{\n{SERIAL_CALL}"
            if source.count(first_statement) != 1:
                raise AssertionError(f"{path}: {name} is not directly serialized")
    if serial_test_count != 14:
        raise AssertionError("serialized test count drifted")

    for path in sorted(WAVE_TWO_SOURCE_PATHS):
        source = sources[path]
        normalized = _normalized_wave_two_source(path, source)
        if "type Callback = fn" in normalized:
            raise AssertionError(f"{path}: callback test body indirection returned")
        names = [name for _, name in _test_items(source)]
        if len(names) != len(set(names)):
            raise AssertionError(f"{path}: duplicate test identities")


def _replace_once(
    sources: dict[str, str], path: str, before: str, after: str
) -> dict[str, str]:
    mutated = dict(sources)
    if mutated[path].count(before) != 1:
        raise AssertionError(f"{path}: mutation anchor is not unique")
    mutated[path] = mutated[path].replace(before, after, 1)
    return mutated


class IntegrationTargetConsolidationTest(unittest.TestCase):
    def test_xtask_target_is_aggregated(self) -> None:
        validate(XTASK)

    def test_iroha_schema_target_is_aggregated(self) -> None:
        validate(SCHEMA)

    def test_wave_two_targets_are_aggregated(self) -> None:
        validate_wave_two()

    def test_wave_two_guard_rejects_mutations(self) -> None:
        sources = _read_wave_two_sources()
        validate_wave_two(sources)
        mutations = (
            _replace_once(
                sources,
                "crates/iroha_monitor/Cargo.toml",
                "autotests = false",
                "autotests = true",
            ),
            _replace_once(
                sources,
                "crates/iroha_monitor/tests/smoke.rs",
                '#[path = "attach_render.rs"]',
                '#[path = "invalid_credentials.rs"]',
            ),
            _replace_once(
                sources,
                "crates/iroha_derive/Cargo.toml",
                'required-features = ["trybuild-tests"]',
                "required-features = []",
            ),
            _replace_once(
                sources,
                "crates/iroha_derive/tests/config_base_ui.rs",
                SERIAL_CALL,
                "",
            ),
            _replace_once(
                sources,
                "crates/iroha_derive/tests/ui.rs",
                "        .unwrap_or_else(std::sync::PoisonError::into_inner)",
                "        .unwrap()",
            ),
            _replace_once(
                sources,
                "crates/iroha_monitor/tests/smoke.rs",
                f"fn status_stub_retains_listener_until_its_owner_drops() {{\n{SERIAL_CALL}",
                "fn status_stub_retains_listener_until_its_owner_drops() {\n",
            ),
        )
        body_mutation = dict(sources)
        body_mutation[
            "crates/iroha_primitives/tests/numeric_inspect.rs"
        ] += "\ntype Callback = fn();\n"
        extra_source = dict(sources)
        extra_source["crates/iroha_monitor/tests/unexpected.rs"] = (
            "#[test]\nfn unexpected() {}\n"
        )
        for mutation in (*mutations, body_mutation, extra_source):
            with self.subTest():
                with self.assertRaises(AssertionError):
                    validate_wave_two(mutation)


@dataclass(frozen=True)
class WaveThreeAggregate:
    package: str
    target: str
    root: str
    modules: tuple[tuple[str, str, str | None], ...]


WAVE_THREE_TARGETS = (
    ("crates/iroha", "tx_ttl", "tx_ttl.rs"),
    ("crates/iroha_p2p", "mod", "mod.rs"),
    ("crates/norito_derive", "strict_json", "strict_json.rs"),
    ("crates/norito_derive", "ui", "ui.rs"),
    ("crates/sorafs_chunker", "vectors", "vectors.rs"),
    ("crates/sorafs_chunker", "one_gib", "one_gib.rs"),
    (
        "crates/sorafs_orchestrator",
        "orchestrator_parity",
        "orchestrator_parity.rs",
    ),
    ("crates/sorafs_orchestrator", "sorafs_cli", "sorafs_cli.rs"),
)

WAVE_THREE_AGGREGATES = (
    WaveThreeAggregate(
        package="crates/iroha",
        target="tx_ttl",
        root="tx_ttl.rs",
        modules=(("sm_signing", "sm_signing.rs", None),),
    ),
    WaveThreeAggregate(
        package="crates/iroha_p2p",
        target="mod",
        root="mod.rs",
        modules=(("production_source_reachability", "production_source_reachability.rs", None),
                 ("retired_relay_surface", "retired_relay_surface.rs", None)),
    ),
    WaveThreeAggregate(
        package="crates/sorafs_chunker",
        target="vectors",
        root="vectors.rs",
        modules=(("backpressure", "backpressure.rs", None),),
    ),
    WaveThreeAggregate(
        package="crates/sorafs_orchestrator",
        target="orchestrator_parity",
        root="orchestrator_parity.rs",
        modules=(("multi_peer_fetch", "multi_peer_fetch.rs", None),),
    ),
)

WAVE_THREE_TOP_LEVEL_RS = {
    "crates/iroha": (
        "sm_signing.rs",
        "tx_ttl.rs",
    ),
    "crates/iroha_p2p": ("mod.rs", "production_source_reachability.rs", "retired_relay_surface.rs"),
    "crates/norito_derive": ("strict_json.rs", "ui.rs"),
    "crates/sorafs_chunker": ("backpressure.rs", "one_gib.rs", "vectors.rs"),
    "crates/sorafs_orchestrator": (
        "multi_peer_fetch.rs",
        "orchestrator_parity.rs",
        "sorafs_cli.rs",
    ),
}


WAVE_THREE_SOURCE_PATHS = (
    'crates/iroha_p2p/tests/production_source_reachability.rs',
    'crates/iroha/tests/sm_signing.rs',
    'crates/iroha/tests/tx_ttl.rs',
    'crates/iroha_p2p/tests/mod.rs',
    'crates/iroha_p2p/tests/retired_relay_surface.rs',
    'crates/norito_derive/tests/strict_json.rs',
    'crates/norito_derive/tests/ui.rs',
    'crates/sorafs_chunker/tests/backpressure.rs',
    'crates/sorafs_chunker/tests/one_gib.rs',
    'crates/sorafs_chunker/tests/vectors.rs',
    'crates/sorafs_orchestrator/tests/multi_peer_fetch.rs',
    'crates/sorafs_orchestrator/tests/orchestrator_parity.rs',
)

WAVE_THREE_DOC_PATH = "specs/sorafs/chunker_profile_authoring.md"
WAVE_THREE_OLD_DOC_COMMAND = (
    "cargo test --locked -p sorafs_chunker --test backpressure"
)
WAVE_THREE_NEW_DOC_COMMAND = (
    "cargo test --locked -p sorafs_chunker --test vectors backpressure"
)


def _wave_three_packages() -> tuple[str, ...]:
    return tuple(dict.fromkeys(package for package, _, _ in WAVE_THREE_TARGETS))


def _wave_three_table(target: str, root: str) -> str:
    table = f'name = "{target}"\npath = "tests/{root}"'
    if root == "ui.rs":
        table += '\nrequired-features = ["trybuild-tests"]'
    if root == "sorafs_cli.rs":
        table += '\nrequired-features = ["cli-orchestrator", "moderation-grpc"]'
    if root == "one_gib.rs":
        table += '\nrequired-features = ["dev-tools"]'
    return table


def _wave_three_module_declaration(
    module: str, path: str, required_feature: str | None
) -> str:
    cfg = (
        f'#[cfg(feature = "{required_feature}")]\n'
        if required_feature is not None
        else ""
    )
    return f'\n{cfg}#[path = "{path}"]\nmod {module};\n'


def _wave_three_expected_paths() -> set[str]:
    paths = {f"{package}/Cargo.toml" for package in _wave_three_packages()}
    paths.update(WAVE_THREE_SOURCE_PATHS)
    paths.add(WAVE_THREE_DOC_PATH)
    return paths


def _read_wave_three_sources() -> dict[str, str]:
    return {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in sorted(_wave_three_expected_paths())
    }


def _wave_three_top_level_inventory() -> dict[str, tuple[str, ...]]:
    return {
        package: tuple(
            sorted(path.name for path in (ROOT / package / "tests").glob("*.rs"))
        )
        for package in _wave_three_packages()
    }


def _wave_three_test_items(source: str) -> tuple[tuple[str, str], ...]:
    items: list[tuple[str, str]] = []
    for block, name in re.findall(
        r"(?m)((?:^[ \t]*#\[[^\n]+\]\n)+)"
        r"^[ \t]*(?:async[ \t]+)?fn[ \t]+([A-Za-z0-9_]+)[ \t]*\(",
        source,
    ):
        attributes = tuple(line.strip() for line in block.splitlines())
        if "#[test]" not in attributes and not any(
            attribute.startswith("#[tokio::test") for attribute in attributes
        ):
            continue
        items.append(("\n".join(attributes), name))
    return tuple(items)


def _normalized_wave_three_source(path: str, source: str) -> str:
    for aggregate in WAVE_THREE_AGGREGATES:
        root = f"{aggregate.package}/tests/{aggregate.root}"
        if path != root:
            continue
        for module, module_path, required_feature in aggregate.modules:
            declaration = _wave_three_module_declaration(
                module, module_path, required_feature
            )
            if source.count(declaration) != 1:
                raise AssertionError(f"{path}: module declaration is not unique")
            source = source.replace(declaration, "", 1)
    return source


def validate_wave_three(
    sources: dict[str, str] | None = None,
    inventories: dict[str, tuple[str, ...]] | None = None,
) -> None:
    if sources is None:
        sources = _read_wave_three_sources()
    if set(sources) != _wave_three_expected_paths():
        raise AssertionError("wave-three source path inventory drifted")
    if inventories is None:
        inventories = _wave_three_top_level_inventory()
    if inventories != WAVE_THREE_TOP_LEVEL_RS:
        raise AssertionError("wave-three top-level Rust source inventory drifted")

    target_rows: list[str] = []
    for package in _wave_three_packages():
        manifest = sources[f"{package}/Cargo.toml"]
        package_table = manifest.split("\n[", 1)[0]
        if package_table.count("autotests = false") != 1:
            raise AssertionError(f"{package}: autotests must be disabled exactly once")
        targets = tuple(
            (target, root)
            for target_package, target, root in WAVE_THREE_TARGETS
            if target_package == package
        )
        expected_tables = [_wave_three_table(target, root) for target, root in targets]
        if _test_tables(manifest) != expected_tables:
            raise AssertionError(f"{package}: explicit target inventory drifted")
        target_rows.extend(
            f"{package}\0{target}\0{root}\n" for target, root in targets
        )

    module_rows: list[str] = []
    for aggregate in WAVE_THREE_AGGREGATES:
        root_path = f"{aggregate.package}/tests/{aggregate.root}"
        root = sources[root_path]
        expected_modules = tuple(
            (module, path) for module, path, _ in aggregate.modules
        )
        if _module_rows(root) != expected_modules:
            raise AssertionError(f"{root_path}: child module inventory drifted")
        for module, module_path, required_feature in aggregate.modules:
            declaration = _wave_three_module_declaration(
                module, module_path, required_feature
            )
            if root.count(declaration) != 1:
                raise AssertionError(f"{root_path}: child declaration drifted")
            feature = required_feature or ""
            module_rows.append(
                f"{aggregate.package}\0{aggregate.root}\0{module}\0"
                f"{module_path}\0{feature}\n"
            )

    for path in sorted(WAVE_THREE_SOURCE_PATHS):
        source = sources[path]
        normalized = _normalized_wave_three_source(path, source)
        if "type Callback = fn" in normalized:
            raise AssertionError(f"{path}: callback test body indirection returned")
        names = [name for _, name in _wave_three_test_items(source)]
        if len(names) != len(set(names)):
            raise AssertionError(f"{path}: duplicate test identities")
    docs = sources[WAVE_THREE_DOC_PATH]
    if docs.count(WAVE_THREE_OLD_DOC_COMMAND) != 0:
        raise AssertionError("retired backpressure target command remains documented")
    if docs.count(WAVE_THREE_NEW_DOC_COMMAND) != 1:
        raise AssertionError("aggregated backpressure command drifted")


class WaveThreeIntegrationTargetConsolidationTest(unittest.TestCase):
    def test_wave_three_targets_are_aggregated(self) -> None:
        validate_wave_three()

    def test_wave_three_guard_rejects_mutations(self) -> None:
        sources = _read_wave_three_sources()
        inventories = _wave_three_top_level_inventory()
        validate_wave_three(sources, inventories)
        mutations = (
            _replace_once(
                sources,
                "crates/iroha/Cargo.toml",
                "autotests = false",
                "autotests = true",
            ),
            _replace_once(
                sources,
                "crates/iroha/Cargo.toml",
                'name = "tx_ttl"',
                'name = "sm_signing"',
            ),
            _replace_once(
                sources,
                "crates/sorafs_chunker/tests/vectors.rs",
                '#[path = "backpressure.rs"]',
                '#[path = "one_gib.rs"]',
            ),
            _replace_once(
                sources,
                "crates/norito_derive/Cargo.toml",
                'required-features = ["trybuild-tests"]',
                'required-features = ["other"]',
            ),
            _replace_once(
                sources,
                "crates/sorafs_chunker/Cargo.toml",
                'name = "one_gib"\npath = "tests/one_gib.rs"\nrequired-features = ["dev-tools"]',
                'name = "one_gib"\npath = "tests/one_gib.rs"\nrequired-features = []',
            ),
            _replace_once(
                sources,
                WAVE_THREE_DOC_PATH,
                WAVE_THREE_NEW_DOC_COMMAND,
                WAVE_THREE_OLD_DOC_COMMAND,
            ),
        )
        body_mutation = dict(sources)
        body_mutation["crates/iroha/tests/sm_signing.rs"] += "\ntype Callback = fn();\n"
        inventory_mutation = dict(inventories)
        inventory_mutation["crates/sorafs_chunker"] = tuple(
            sorted((*inventory_mutation["crates/sorafs_chunker"], "unexpected.rs"))
        )
        for mutation in (*mutations, body_mutation):
            with self.subTest():
                with self.assertRaises(AssertionError):
                    validate_wave_three(mutation, inventories)
        with self.assertRaises(AssertionError):
            validate_wave_three(sources, inventory_mutation)
