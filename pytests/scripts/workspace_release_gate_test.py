"""Static guards for the exact-SHA release build and optional diagnostics."""

from __future__ import annotations

import functools
import importlib.util
import json
import os
import re
import subprocess
import textwrap
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "workspace_release.yml"
PR_WORKFLOW = ROOT / ".github" / "workflows" / "pr.yml"
PINNED_RUST = "1.93.1"
SETUP_RUST_TOOLCHAIN_COMMIT = "166cdcfd11aee3cb47222f9ddb555ce30ddb9659"
RUST_CACHE_COMMIT = "e18b497796c12c097a38f9edb9d0641fb99eee32"
COMPILE_UNIT_BASELINE = ROOT / "ci" / "compile_unit_baselines.json"
COMPILE_UNIT_GUARD_COMMAND = (
    "python3 scripts/check_compile_unit_budget.py --locked --lib "
    "-p iroha_data_model --artifact-scope workspace "
    "--baseline ci/compile_unit_baselines.json "
    "--baseline-key iroha_data_model_lib "
    "--budget-percent 2 --budget-min-growth 3 "
    "--json-out target/ci/iroha-data-model-compile-units.json"
)
COMPILE_UNIT_REPORT = "target/ci/iroha-data-model-compile-units.json"
COMPILE_UNIT_ARTIFACT_IDENTITY = "cargo-package-target-features-profile-v2"
BUILD_EFFICIENCY_PROVENANCE_COMMAND = (
    "python3 -I -S scripts/check_build_efficiency_provenance.py"
)
BUILD_EFFICIENCY_PROVENANCE_TEST = (
    "scripts/tests/check_build_efficiency_provenance_test.py"
)
RESULT_CONSUMERS = (
    "BINARY_FREE", "NETWORK", "BUILD", "CONSISTENCY", "KOTODAMA", "PYTESTS",
    "PARLIAMENT",
)
REQUIRED_NUMERIC_TEST_COMMANDS = (
    "cargo test --locked -p ivm --test ivm_group_06 numeric_",
    "cargo test --locked -p ivm --test ivm_group_01 abi_hash_versions::",
    "cargo test --locked -p ivm --test ivm_group_03 gas_schedule_hash",
    "cargo test --locked -p ivm --test ivm_group_05 "
    "kotodama_checked_arithmetic::",
    "cargo test --locked -p iroha_primitives "
    "randomized_decimal_arithmetic_matches_independent_rational_reference",
)


NEXTEST_CONFIG = ROOT / ".config" / "nextest.toml"
NEXTEST_INSTALL_ACTION = (
    "uses: taiki-e/install-action@10ddf82bb4948219b68187f154decde56c89ee88"
)
RELEASE_GATE_FETCH = "cargo fetch --locked"
RELEASE_GATE_COMMAND = (
    "cargo nextest run --profile release-gate --locked --offline --no-tests=fail"
)
RELEASE_GATE_BUILD = "cargo build --locked --offline --workspace"
RELEASE_GATE_BUILD_STEP = "- name: Build the full workspace"
DIAGNOSTIC_CONDITION = (
    "    if: ${{ github.event_name == 'schedule' || inputs.run_diagnostics }}"
)
DIAGNOSTIC_JOBS = (
    "format", "release-diagnostics", "doc", "test", "coverage", "clippy", "adversarial",
)
RETIRED_CENSUS_MARKERS = (
    "taira_release",
    "taira-native-checks",
    "python3",
    "setup-python",
)


def _release_gate_packages(diagnostic_job: str) -> list[str]:
    """Return the `-p` package list of the optional nextest command."""

    normalized = _normalized(diagnostic_job)
    start = normalized.find("cargo nextest run ")
    if start < 0:
        return []
    end = normalized.find(RELEASE_GATE_BUILD_STEP, start)
    command = normalized[start:] if end < 0 else normalized[start:end]
    return re.findall(r"(?:^|\s)-p\s+([A-Za-z0-9_-]+)", command)


def _filter_packages(default_filter: str) -> list[str]:
    """Return the package names that a nextest filterset selects."""

    return re.findall(r"\bpackage\(([A-Za-z0-9_-]+)\)", default_filter)


@functools.cache
def _workspace_packages() -> dict[str, Path]:
    """Return the workspace member packages by name: root `members` globs minus `exclude`."""

    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    excluded = {(ROOT / path).resolve() for path in workspace.get("exclude", [])}
    packages = {}
    for pattern in workspace.get("members", []):
        for directory in sorted(ROOT.glob(pattern)):
            manifest = directory / "Cargo.toml"
            if directory.resolve() in excluded or not manifest.is_file():
                continue
            package = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package", {})
            if isinstance(package.get("name"), str):
                packages[package["name"]] = directory
    return packages


def _workspace_package_names() -> set[str]:
    """Return every workspace member package name."""

    return set(_workspace_packages())


# No leading `\b`: a literal prefix keeps this fast over large crates, and
# `_module_names` checks the word boundary itself.
MODULE_DECLARATION = re.compile(r"mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*[;{]")


@functools.cache
def _module_names(directory: Path) -> frozenset[str]:
    """Return every module name a package's `src/` and `tests/` sources declare.

    Names come from `mod` declarations (inline, file or `#[path]`) and module file
    names. Nesting and target kind are not resolved: the release-gate check only
    needs to see that each module it names still exists in the package.
    """

    names = set()
    for sources in (directory / "src", directory / "tests"):
        for source in sorted(sources.rglob("*.rs")):
            names.add(source.parent.name if source.stem == "mod" else source.stem)
            text = source.read_text(encoding="utf-8", errors="replace")
            for match in MODULE_DECLARATION.finditer(text):
                before = text[match.start() - 1:match.start()]
                if not (before.isalnum() or before == "_"):
                    names.add(match.group(1))
    return frozenset(names)


FILTER_TOKEN = re.compile(
    r"(?P<op>[()|&!])|(?P<not>not)\b|(?P<matcher>package|kind|test)"
    r"\((?P<argument>/(?:[^/\\]|\\.)*/|[A-Za-z0-9_-]+)\)"
)


def _parse_filter(text: str) -> tuple:
    """Parse the nextest filterset subset the release gate may use.

    `expr := term ("|" term)*`, `term := factor ("&" factor)*` and
    `factor := ("not" | "!") factor | "(" expr ")" | package(name) | kind(name)
    | test(/regex/)`. Anything else raises `ValueError`.
    """

    tokens = []
    position = 0
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        match = FILTER_TOKEN.match(text, position)
        if match is None:
            raise ValueError(f"unexpected text at {text[position:position + 24]!r}")
        tokens.append(match)
        position = match.end()
    index = 0

    def peek(op: str) -> bool:
        return index < len(tokens) and tokens[index].group("op") == op

    def expression() -> tuple:
        nonlocal index
        node = term()
        while peek("|"):
            index += 1
            node = ("or", node, term())
        return node

    def term() -> tuple:
        nonlocal index
        node = factor()
        while peek("&"):
            index += 1
            node = ("and", node, factor())
        return node

    def factor() -> tuple:
        nonlocal index
        if index == len(tokens):
            raise ValueError("unexpected end of filter")
        token = tokens[index]
        index += 1
        if token.group("not") or token.group("op") == "!":
            return ("not", factor())
        if token.group("op") == "(":
            node = expression()
            if not peek(")"):
                raise ValueError("unclosed `(`")
            index += 1
            return node
        if token.group("matcher"):
            argument = token.group("argument")
            if token.group("matcher") == "test" and not argument.startswith("/"):
                raise ValueError(f"test() needs a /regex/: {argument}")
            if token.group("matcher") != "test" and argument.startswith("/"):
                raise ValueError(f"{token.group('matcher')}() needs a name: {argument}")
            return (token.group("matcher"), argument)
        raise ValueError(f"unexpected `{token.group(0)}`")

    tree = expression()
    if index != len(tokens):
        raise ValueError(f"unexpected `{tokens[index].group(0)}`")
    return tree


def _filter_matches(tree: tuple, package: str, kind: str, name: str) -> bool:
    """Evaluate a parsed filter for one test, as nextest does."""

    operator = tree[0]
    if operator == "or":
        return any(_filter_matches(side, package, kind, name) for side in tree[1:])
    if operator == "and":
        return all(_filter_matches(side, package, kind, name) for side in tree[1:])
    if operator == "not":
        return not _filter_matches(tree[1], package, kind, name)
    if operator == "package":
        return tree[1] == package
    if operator == "kind":
        return tree[1] == kind
    return re.search(tree[1][1:-1], name) is not None


def _flatten(tree: tuple, operator: str) -> list[tuple]:
    """Return the operands of a chain of one binary operator."""

    if tree[0] != operator:
        return [tree]
    return [operand for side in tree[1:] for operand in _flatten(side, operator)]


def _filter_groups(tree: tuple) -> list[tuple[list[str], list[str]]]:
    """Return each union term's packages and positive (not negated) test regexes."""

    groups = []
    for term in _flatten(tree, "or"):
        factors = _flatten(term, "and")
        packages = [factor[1] for factor in factors if factor[0] == "package"]
        tests = [factor[1] for factor in factors if factor[0] == "test"]
        groups.append((packages, tests))
    return groups


def _split_alternation(text: str) -> list[str]:
    """Split a regex at its top-level `|`."""

    parts, current, depth, in_class = [], "", 0, False
    for char in text:
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += char
    parts.append(current)
    return parts


def _expand_alternatives(text: str) -> list[str]:
    """Expand every parenthesized alternation: `a::(b|c)` gives `a::b` and `a::c`."""

    depth, start, in_class = 0, -1, False
    for index, char in enumerate(text):
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            if depth == 0:
                start = index
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                inner = text[start + 1:index].removeprefix("?:")
                return [
                    expanded
                    for choice in _split_alternation(inner)
                    for expanded in _expand_alternatives(text[:start] + choice + text[index + 1:])
                ]
    return [text]


def _module_path_alternatives(pattern: str) -> list[str]:
    """Return the module paths a `/^path::/` release-gate pattern selects."""

    body = pattern[1:-1].removeprefix("^").removesuffix("::")
    return _expand_alternatives(body)


def _job_block(workflow: str, name: str) -> str:
    """Return one top-level job block from a GitHub Actions workflow."""

    try:
        jobs = workflow.split("\njobs:\n", 1)[1]
    except IndexError:
        return ""
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        jobs,
    )
    return "" if match is None else match.group(0)


def _normalized(text: str) -> str:
    """Collapse YAML presentation whitespace for command assertions."""

    return " ".join(text.split())


def _replace_once(text: str, old: str, new: str) -> str:
    """Apply one deliberate mutation and fail if the fixture drifted."""

    assert text.count(old) >= 1, f"mutation source is absent: {old!r}"
    return text.replace(old, new, 1)


def _replace_once_in_job(
    workflow: str, job_name: str, old: str, new: str
) -> str:
    """Apply one deliberate mutation inside exactly one named workflow job."""

    job = _job_block(workflow, job_name)
    assert job, f"workflow job is absent: {job_name!r}"
    mutated_job = _replace_once(job, old, new)
    assert workflow.count(job) == 1, f"workflow job block is not unique: {job_name!r}"
    return workflow.replace(job, mutated_job, 1)


def _aggregate_results(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Execute the actual required-job shell against synthetic GitHub results."""

    job = _job_block(PR_WORKFLOW.read_text(encoding="utf-8"), "rust_required")
    script = textwrap.dedent(job.split("        run: |\n", 1)[1])
    return subprocess.run(
        ["bash", "-c", script], env={**os.environ, **environment},
        capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize("selected", (False, True))
def test_required_aggregate_accepts_only_explicit_success_or_skip(selected: bool) -> None:
    """A fully selected run and an explicitly empty run both aggregate correctly."""

    environment = {"CLASSIFIER_RESULT": "success"}
    for name in RESULT_CONSUMERS:
        environment[f"{name}_SELECTED"] = str(selected).lower()
        environment[f"{name}_RESULT"] = "success" if selected else "skipped"
    assert _aggregate_results(environment).returncode == 0


@pytest.mark.parametrize("name", RESULT_CONSUMERS)
@pytest.mark.parametrize("result", ("failure", "cancelled", "skipped"))
def test_required_aggregate_rejects_every_selected_consumer_failure(name: str, result: str) -> None:
    """A missing, cancelled, or failed selected consumer cannot produce green CI."""

    environment = {"CLASSIFIER_RESULT": "success"}
    for consumer in RESULT_CONSUMERS:
        environment[f"{consumer}_SELECTED"] = "false"
        environment[f"{consumer}_RESULT"] = "skipped"
    environment[f"{name}_SELECTED"] = "true"
    environment[f"{name}_RESULT"] = result
    assert _aggregate_results(environment).returncode != 0


def test_required_aggregate_rejects_classifier_failure_and_absent_decisions() -> None:
    """Empty classifier outputs cannot masquerade as an intentional skipped run."""

    assert _aggregate_results({"CLASSIFIER_RESULT": "failure"}).returncode != 0
    environment = {"CLASSIFIER_RESULT": "success"}
    for name in RESULT_CONSUMERS:
        environment[f"{name}_SELECTED"] = ""
        environment[f"{name}_RESULT"] = "skipped"
    assert _aggregate_results(environment).returncode != 0


@pytest.mark.parametrize("name", RESULT_CONSUMERS)
@pytest.mark.parametrize("result", ("success", "failure", "cancelled"))
def test_required_aggregate_rejects_unselected_jobs_that_ran(name: str, result: str) -> None:
    """A routed-off job must be skipped; execution is a classification mismatch."""

    environment = {"CLASSIFIER_RESULT": "success"}
    for consumer in RESULT_CONSUMERS:
        environment[f"{consumer}_SELECTED"] = "false"
        environment[f"{consumer}_RESULT"] = "skipped"
    environment[f"{name}_RESULT"] = result
    assert _aggregate_results(environment).returncode != 0


def _validate_release_gate_profile(config: str) -> list[str]:
    """Return errors when the nextest release gate is missing or name-based."""

    try:
        profiles = tomllib.loads(config).get("profile", {})
    except tomllib.TOMLDecodeError as error:
        return [f"nextest config must parse: {error}"]
    gate = profiles.get("release-gate")
    if not isinstance(gate, dict):
        return ["nextest config must define profile.release-gate"]
    default_filter = gate.get("default-filter")
    if not isinstance(default_filter, str) or not default_filter.strip():
        return ["release-gate must select tests with a default-filter"]

    errors: list[str] = []
    ci = profiles.get("ci", {})
    if gate.get("fail-fast") is not False:
        errors.append("release-gate must report every failure (fail-fast = false)")
    for key in ("failure-output", "slow-timeout"):
        if key not in ci or gate.get(key) != ci.get(key):
            errors.append(f"release-gate {key} must match profile.ci")
    if re.search(r"\bbinary(_id)?\(", default_filter):
        errors.append("release-gate must not name test binaries")
    matchers = re.findall(r"(\bnot\s+|[!-]\s*)?\btest\(([^/][^)]*|/.*?/)\)", default_filter)
    for negated, pattern in matchers:
        if not pattern.startswith("/"):
            errors.append(f"release-gate test matchers must be regex groups: {pattern}")
        elif not negated and not re.fullmatch(r"/\^[A-Za-z0-9_:|()\[\]+*-]+::/", pattern):
            # A module path ends at `::`, so a test name cannot pose as one.
            errors.append(f"release-gate must select tests by module path: {pattern}")
    unknown = sorted(set(_filter_packages(default_filter)) - _workspace_package_names())
    if unknown:
        errors.append(f"release-gate names unknown packages: {', '.join(unknown)}")
        return errors
    try:
        tree = _parse_filter(default_filter)
    except ValueError as error:
        return [*errors, f"release-gate default-filter must parse: {error}"]
    packages = _workspace_packages()
    for group_packages, tests in _filter_groups(tree):
        if len(group_packages) != 1:
            errors.append(
                f"each release-gate group must name exactly one package: {group_packages}"
            )
            continue
        # Nextest accepts a module path that selects nothing; require each named
        # module to exist so a rename cannot silently drop a group from the gate.
        names = _module_names(packages[group_packages[0]])
        for pattern in tests:
            if pattern.startswith("/^") and pattern.endswith("::/"):
                for path in _module_path_alternatives(pattern):
                    if not all(
                        any(re.fullmatch(component, name) for name in names)
                        for component in path.split("::")
                    ):
                        errors.append(
                            f"release-gate module path matches no module in "
                            f"{group_packages[0]}: {path}"
                        )
    return errors


def _validate_release_gate_job(job: str, config: str) -> list[str]:
    """Require exact-source nextest selection only in the optional diagnostic job."""

    errors: list[str] = []
    for marker in RETIRED_CENSUS_MARKERS:
        if marker in job:
            errors.append(f"release-diagnostics must not run the retired Python release census: {marker}")
    normalized = _normalized(job)
    positions = [
        normalized.find(marker)
        for marker in (
            NEXTEST_INSTALL_ACTION, RELEASE_GATE_FETCH, RELEASE_GATE_COMMAND,
        )
    ]
    if not all(position >= 0 for position in positions) or positions != sorted(positions):
        errors.append(
            "release-diagnostics must install nextest, fetch, then run offline"
        )
    packages = _release_gate_packages(job)
    try:
        default_filter = tomllib.loads(config)["profile"]["release-gate"]["default-filter"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError):
        default_filter = ""
    expected = _filter_packages(default_filter)
    if len(packages) != len(set(packages)) or set(packages) != set(expected):
        errors.append(
            "release-diagnostics packages must equal the release-gate default-filter packages"
        )
    return errors


def _validate_release_workflow(workflow: str, nextest_config: str | None = None) -> list[str]:
    """Return deterministic errors for weakened release-workflow semantics."""

    if nextest_config is None:
        nextest_config = NEXTEST_CONFIG.read_text(encoding="utf-8")
    errors: list[str] = []
    global_requirements = (
        (
            '  schedule:\n    - cron: "17 2 * * *"',
            "release workflow must run nightly",
        ),
        (
            '  push:\n    branches: [main]\n    tags: ["v*"]',
            "release workflow must run on main and v* pushes",
        ),
        ("  workflow_dispatch:\n", "release workflow must support manual runs"),
        ("  workflow_call:\n", "release workflow must support reusable calls"),
        ("permissions:\n  contents: read", "release workflow must be read-only"),
        (
            "group: workspace-release-${{ github.sha }}",
            "release concurrency must be scoped to the exact SHA",
        ),
        (
            "cancel-in-progress: false",
            "release evidence must not be cancelled by ref movement",
        ),
        (
            f"RUSTUP_TOOLCHAIN: {PINNED_RUST}",
            "release workflow must advertise the pinned Rust toolchain",
        ),
    )
    for marker, message in global_requirements:
        if marker not in workflow:
            errors.append(message)

    for event in ("workflow_dispatch", "workflow_call"):
        match = re.search(
            rf"(?ms)^  {event}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:|^permissions:|\Z)",
            workflow,
        )
        body = "" if match is None else match.group("body")
        if not re.search(
            r"(?m)^      run_diagnostics:\n"
            r"        description: [^\n]+\n"
            r"        required: false\n"
            r"        type: boolean\n"
            r"        default: false$",
            body,
        ):
            errors.append(f"{event} diagnostics must be an optional boolean defaulting to false")

    for job_name in DIAGNOSTIC_JOBS:
        job = _job_block(workflow, job_name)
        if DIAGNOSTIC_CONDITION not in job:
            errors.append(f"{job_name} must run only for nightly or explicitly requested diagnostics")
        if "    continue-on-error: true\n" not in job:
            errors.append(f"{job_name} diagnostics must not block the release workflow")

    build_job = _job_block(workflow, "build")
    if re.search(r"(?m)^    (?:if|needs|continue-on-error):", build_job):
        errors.append("release build must be independent of diagnostic jobs")
    for marker in ("cargo nextest", "cargo test", "cargo clippy", "cargo fmt", *RETIRED_CENSUS_MARKERS):
        if marker in build_job:
            errors.append(f"release build must not run diagnostics: {marker}")
    if _normalized(build_job).find(RELEASE_GATE_FETCH) > _normalized(build_job).find(RELEASE_GATE_BUILD):
        errors.append("release build must fetch locked dependencies before building offline")

    if re.search(r"(?m)^  pull_request:", workflow):
        errors.append("release workflow must not substitute PR state for release evidence")

    expected_runners = {
        "format": "runs-on: ubuntu-latest",
        "build": "runs-on: [self-hosted, Linux, iroha2]",
        "release-diagnostics": "runs-on: [self-hosted, Linux, iroha2]",
        "doc": "runs-on: [self-hosted, Linux, iroha2]",
        "test": "runs-on: [self-hosted, Linux, iroha2]",
        "coverage": "runs-on: [self-hosted, Linux, iroha2]",
        "clippy": "runs-on: [self-hosted, Linux, iroha2]",
    }
    commands = {
        "format": (
            "python3 -m pytest -q pytests/scripts/workspace_release_gate_test.py",
            "cargo metadata --locked --no-deps --format-version 1 > /dev/null",
            "cargo fmt --all -- --check",
        ),
        "build": (
            f"shared-key: workspace-release-build-{PINNED_RUST}",
            RELEASE_GATE_FETCH,
            RELEASE_GATE_BUILD,
        ),
        "release-diagnostics": (
            f"shared-key: workspace-release-diagnostics-{PINNED_RUST}",
            NEXTEST_INSTALL_ACTION,
            RELEASE_GATE_FETCH,
            RELEASE_GATE_COMMAND,
        ),
        "doc": ("cargo doc --locked --workspace --no-deps --all-features",),
        "test": (
            COMPILE_UNIT_GUARD_COMMAND,
            "name: workspace-release-compile-units",
            f"path: {COMPILE_UNIT_REPORT}",
            "if-no-files-found: error",
            "cargo test --locked --workspace --no-fail-fast",
        ),
        "coverage": (
            "mold --run cargo llvm-cov nextest --workspace --locked --branch --no-report",
            "mold --run cargo llvm-cov --doc --branch --no-report",
            "cargo llvm-cov report --doctests --ignore-filename-regex "
            "'iroha_cli|iroha_torii' --lcov --output-path lcov.info",
            "uses: coverallsapp/github-action@648a8eb78e6d50909eff900e4ec85cab4524a45b",
        ),
        "clippy": (
            "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
        ),
    }
    exact_source_markers = (
        "persist-credentials: false",
        "ref: ${{ github.sha }}",
        "EXPECTED_SHA: ${{ github.sha }}",
        "WORKFLOW_SHA: ${{ github.workflow_sha }}",
        'source_sha="$(git rev-parse "${EXPECTED_SHA}^{commit}")"',
        'test "$(git rev-parse HEAD)" = "$source_sha"',
        'test "$WORKFLOW_SHA" = "$source_sha"',
    )

    for job_name, runner in expected_runners.items():
        job = _job_block(workflow, job_name)
        if not job:
            errors.append(f"release workflow is missing the {job_name} job")
            continue
        if runner not in job:
            errors.append(f"{job_name} must use its production CI runner class")
        for marker in exact_source_markers:
            if marker not in job:
                errors.append(f"{job_name} must verify the exact workflow SHA: {marker}")
        if (
            "uses: actions-rust-lang/setup-rust-toolchain@"
            f"{SETUP_RUST_TOOLCHAIN_COMMIT}"
        ) not in job:
            errors.append(
                f"{job_name} must install the managed Rust toolchain from the reviewed commit"
            )
        if f"toolchain: {PINNED_RUST}" not in job:
            errors.append(f"{job_name} must pin Rust {PINNED_RUST}")

        if job_name == "release-diagnostics":
            errors.extend(_validate_release_gate_job(job, nextest_config))

        normalized_job = _normalized(job)
        for command in commands[job_name]:
            if command not in normalized_job:
                errors.append(f"{job_name} is missing required command: {command}")

    return errors


def _validate_pr_parity(workflow: str) -> list[str]:
    """Return errors when affected PR routing can silently weaken validation."""

    errors: list[str] = []
    if "paths-ignore:" in workflow or "paths_ignore:" in workflow:
        errors.append("PR workflow must classify every change before selectively skipping jobs")
    docs_job = _job_block(workflow, "kotodama_docs")
    if (
        "python3 -m pytest -q pytests/scripts/workspace_release_gate_test.py"
        not in _normalized(docs_job)
    ):
        errors.append("PR workflow must execute the workspace release semantics guard")

    classifier_job = _job_block(workflow, "rust_changes")
    if not classifier_job:
        errors.append("PR workflow is missing the Rust lane classifier")
    else:
        normalized_classifier = _normalized(classifier_job)
        classifier_requirements = (
            "fetch-depth: 0",
            "python3 scripts/rust_ci.py validate",
            "python3 -m pytest -q pytests/scripts/rust_ci_test.py",
            "pytests/scripts/check_cargo_feature_hygiene_test.py",
            "pytests/scripts/check_workspace_target_inventory_test.py",
            BUILD_EFFICIENCY_PROVENANCE_TEST,
            "scripts/tests/sdk_operation_inventory_test.py",
            "scripts/tests/check_compile_unit_budget_test.py",
            "scripts/tests/check_generated_artifacts_test.py",
            "python3 scripts/check_cargo_feature_hygiene.py",
            "python3 scripts/check_workspace_target_inventory.py",
            BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "python3 scripts/check_dependency_budget.py --check-boundaries",
            "python3 scripts/sdk_operation_inventory.py",
            "python3 scripts/check_generated_artifacts.py",
            'FULL_REQUESTED: ${{ contains(github.event.pull_request.labels.*.name, '
            "'ci/full') }}",
            'scope_args=(--base "$BASE_SHA")',
            "scope_args=(--all)",
            'python3 scripts/rust_ci.py classify \\ "${scope_args[@]}" \\ '
            "--json-out target/ci/rust-classification.json \\ "
            '--github-output "$GITHUB_OUTPUT"',
        )
        for requirement in classifier_requirements:
            if requirement not in normalized_classifier:
                errors.append(
                    f"PR Rust classifier is missing required behavior: {requirement}"
                )
        provenance_position = normalized_classifier.find(
            BUILD_EFFICIENCY_PROVENANCE_COMMAND
        )
        provenance_followers = (
            "python3 scripts/rust_ci.py validate",
            "python3 -m pytest -q pytests/scripts/rust_ci_test.py",
            "python3 scripts/check_cargo_feature_hygiene.py",
            "python3 scripts/check_workspace_target_inventory.py",
            "python3 scripts/check_compile_time_table_assets.py",
            "python3 scripts/check_dependency_budget.py",
            "python3 scripts/check_dependency_budget.py --check-boundaries",
        )
        if provenance_position >= 0 and any(
            normalized_classifier.find(command) < provenance_position
            for command in provenance_followers
            if normalized_classifier.find(command) >= 0
        ):
            errors.append(
                "PR build-efficiency provenance guard must run before dependency "
                "and Cargo-facing checks"
            )

    affected_job = _job_block(workflow, "rust_affected")
    if not affected_job:
        errors.append("PR workflow is missing affected Rust validation")
    else:
        normalized_affected = _normalized(affected_job)
        affected_requirements = (
            "matrix: ${{ fromJSON(needs.rust_changes.outputs.binary_free_matrix) }}",
            "if: needs.rust_changes.outputs.has_binary_free_rust == 'true'",
            "needs: rust_changes",
            "uses: actions-rust-lang/setup-rust-toolchain@"
            f"{SETUP_RUST_TOOLCHAIN_COMMIT}",
            'cache: "false"',
            f"toolchain: {PINNED_RUST}",
            f"shared-key: rust-lane-{PINNED_RUST}-${{{{ matrix.lane }}}}",
            "if: matrix.lane == 'execution'",
            COMPILE_UNIT_GUARD_COMMAND,
            "if: always() && matrix.lane == 'execution'",
            "name: compile-units-${{ matrix.lane }}",
            f"path: {COMPILE_UNIT_REPORT}",
            "if-no-files-found: error",
            'python3 scripts/rust_ci.py run --packages "${{ matrix.packages }}" '
            "--checks clippy,build,test,doc",
        )
        for requirement in affected_requirements:
            if requirement not in normalized_affected:
                errors.append(
                    f"PR affected Rust job is missing required behavior: {requirement}"
                )
        if "pre_build" in affected_job or "TEST_NETWORK_BIN_" in affected_job:
            errors.append("PR binary-free Rust job must not depend on prebuilt network binaries")

    for job_name, requirements in {
        "pre_build": (
            "needs: rust_changes",
            "if: needs.rust_changes.outputs.has_binaries == 'true'",
            "REQUIRED_BINARIES: ${{ needs.rust_changes.outputs.binaries }}",
            'python3 scripts/rust_ci.py build-binaries \\ --binaries "$REQUIRED_BINARIES"',
        ),
        "rust_network": (
            "needs: [rust_changes, pre_build]",
            "if: needs.rust_changes.outputs.has_binary_rust == 'true'",
            "matrix: ${{ fromJSON(needs.rust_changes.outputs.binary_matrix) }}",
            "TEST_NETWORK_BIN_IROHAD: bins/iroha3d",
            "TEST_NETWORK_BIN_IROHA: bins/iroha",
            "TEST_NETWORK_BIN_IROHAD_PRIVATE_SETTLEMENT_ROUTES: bins/iroha3d_private_settlement_routes",
            'IROHA_TEST_REQUIRE_NETWORK: "1"',
            'python3 scripts/rust_ci.py run --packages "${{ matrix.packages }}" --checks clippy,build,test,doc',
        ),
        **{
            name: (
                "needs: [rust_changes, pre_build]",
                f"if: needs.rust_changes.outputs.run_{name} == 'true'",
            ) for name in ("consistency", "kotodama_docs", "pytests")
        },
    }.items():
        normalized_job = _normalized(_job_block(workflow, job_name))
        for requirement in requirements:
            if requirement not in normalized_job:
                errors.append(f"PR {job_name} is missing selected-binary behavior: {requirement}")

    for name in ("sora_parliament_lifecycle",):
        job = _job_block(workflow, name)
        normalized_job = _normalized(job)
        for requirement in (
            "needs: rust_changes",
            f"if: needs.rust_changes.outputs.run_{name} == 'true'",
            f"run: bash ci/check_{name}.sh",
            f"run_{name}: ${{{{ steps.classify.outputs.run_{name} }}}}",
        ):
            owner = _normalized(_job_block(workflow, "rust_changes")) if requirement.startswith("run_") else normalized_job
            if requirement not in owner:
                errors.append(f"PR {name} is missing qualified-owner routing: {requirement}")
        if "pre_build" in job or "actions/download-artifact@" in job:
            errors.append(f"PR {name} must retain its owned qualified binary protocol")

    required_job = _job_block(workflow, "rust_required")
    if not required_job:
        errors.append("PR workflow is missing the single Rust result aggregator")
    else:
        normalized_required = _normalized(required_job)
        for requirement in (
            "if: always()",
            "needs: [rust_changes, rust_affected, rust_network, pre_build, consistency, kotodama_docs, pytests, sora_parliament_lifecycle]",
            'test "$CLASSIFIER_RESULT" = success',
            "true:success|false:skipped) return 0",
            *(
                f'check_result "${name}_SELECTED" "${name}_RESULT"'
                for name in RESULT_CONSUMERS
            ),
        ):
            if requirement not in normalized_required:
                errors.append(
                    f"PR Rust result aggregator is missing required behavior: {requirement}"
                )

    numeric_job = _job_block(workflow, "numeric_v1_architecture_parity")
    if not numeric_job:
        errors.append("PR workflow is missing Numeric V1 architecture parity")
        return errors
    if (
        "uses: actions-rust-lang/setup-rust-toolchain@"
        f"{SETUP_RUST_TOOLCHAIN_COMMIT}"
    ) not in numeric_job:
        errors.append(
            "PR numeric parity must install the managed Rust toolchain from the reviewed commit"
        )
    if f"toolchain: {PINNED_RUST}" not in numeric_job:
        errors.append(f"PR numeric parity must pin Rust {PINNED_RUST}")

    numeric_commands = [
        line.strip()
        for line in numeric_job.splitlines()
        if line.strip().startswith("cargo test ")
    ]
    for required_command in REQUIRED_NUMERIC_TEST_COMMANDS:
        if required_command not in numeric_commands:
            errors.append(
                "PR numeric parity is missing required command: "
                f"{required_command}"
            )
    for command in numeric_commands:
        if not command.startswith("cargo test --locked "):
            errors.append(f"PR numeric parity command is not locked: {command}")
    return errors


def test_workspace_release_workflow_is_exact_sha_and_complete() -> None:
    """The release build is independent and optional diagnostics retain exact source."""

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert _validate_release_workflow(workflow) == []


def test_release_workflow_diagnostics_are_optional_and_nonblocking() -> None:
    """Diagnostics cannot become default prerequisites or mask a release build failure."""

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    for event in ("workflow_dispatch", "workflow_call"):
        start = workflow.index(f"  {event}:\n")
        prefix, remaining = workflow[:start], workflow[start:]
        changed = prefix + _replace_once(remaining, "        default: false", "        default: true")
        assert f"{event} diagnostics must be an optional boolean defaulting to false" in _validate_release_workflow(changed)
    for job_name in DIAGNOSTIC_JOBS:
        changed = _replace_once_in_job(workflow, job_name, DIAGNOSTIC_CONDITION, "    if: true")
        assert f"{job_name} must run only for nightly or explicitly requested diagnostics" in _validate_release_workflow(changed)
        changed = _replace_once_in_job(workflow, job_name, "    continue-on-error: true", "    continue-on-error: false")
        assert f"{job_name} diagnostics must not block the release workflow" in _validate_release_workflow(changed)
    for field in ("needs: test", "continue-on-error: true", "if: inputs.run_diagnostics"):
        changed = _replace_once_in_job(workflow, "build", "  build:\n", f"  build:\n    {field}\n")
        assert "release build must be independent of diagnostic jobs" in _validate_release_workflow(changed)


@pytest.mark.parametrize(("old", "new", "expected_error"), (
    (
        "--profile release-gate --locked --offline",
        "--profile ci --locked --offline",
        f"release-diagnostics is missing required command: {RELEASE_GATE_COMMAND}",
    ),
    (
        "--profile release-gate --locked --offline",
        "--profile release-gate --offline",
        f"release-diagnostics is missing required command: {RELEASE_GATE_COMMAND}",
    ),
    (
        "--no-tests=fail",
        "--no-tests=pass",
        f"release-diagnostics is missing required command: {RELEASE_GATE_COMMAND}",
    ),
    (
        RELEASE_GATE_BUILD,
        "cargo build --locked --workspace",
        f"build is missing required command: {RELEASE_GATE_BUILD}",
    ),
    (
        RELEASE_GATE_BUILD,
        "cargo build --locked --offline -p iroha_cli",
        f"build is missing required command: {RELEASE_GATE_BUILD}",
    ),
    (
        "run: cargo fetch --locked",
        "run: cargo fetch",
        f"build is missing required command: {RELEASE_GATE_FETCH}",
    ),
    (
        NEXTEST_INSTALL_ACTION,
        "uses: taiki-e/install-action@nextest",
        f"release-diagnostics is missing required command: {NEXTEST_INSTALL_ACTION}",
    ),
    (
        "-p fastpq_prover -p iroha_core",
        "-p fastpq_prover",
        "release-diagnostics packages must equal the release-gate default-filter packages",
    ),
    (
        "-p iroha_test_network",
        "-p iroha_test_network -p integration_tests",
        "release-diagnostics packages must equal the release-gate default-filter packages",
    ),
    (
        "-p iroha_test_network",
        "-p iroha_test_network -p mv",
        "release-diagnostics packages must equal the release-gate default-filter packages",
    ),
    (
        "run: cargo fetch --locked",
        "run: cargo fetch --locked && python3 scripts/taira_release_check.py",
        "release build must not run diagnostics: taira_release",
    ),
))
def test_release_workflow_guard_rejects_release_gate_drift(
    old: str, new: str, expected_error: str
) -> None:
    """The optional nextest job retains its locks and selected diagnostic packages."""

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    job_name = "release-diagnostics" if expected_error.startswith("release-diagnostics") else "build"
    changed = _replace_once_in_job(workflow, job_name, old, new)
    assert expected_error in _validate_release_workflow(changed)


def test_release_workflow_guard_rejects_reordered_release_gate() -> None:
    """Offline diagnostics must follow their own locked fetch."""

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    job = _job_block(workflow, "release-diagnostics")
    fetch = re.search(r"(?ms)^      - name: Fetch locked dependencies\n.*?(?=^      - )", job)
    assert fetch is not None
    changed = job[:fetch.start()] + job[fetch.end():] + fetch.group(0)
    errors = _validate_release_workflow(workflow.replace(job, changed))
    assert "release-diagnostics must install nextest, fetch, then run offline" in errors


def test_release_workflow_build_job_imports_no_taira_release_tooling() -> None:
    """The release build runs locked Cargo without tests or the retired census."""

    job = _job_block(RELEASE_WORKFLOW.read_text(encoding="utf-8"), "build")
    assert job
    for marker in RETIRED_CENSUS_MARKERS:
        assert marker not in job
    assert not _release_gate_packages(job)
    assert RELEASE_GATE_BUILD in job


def test_release_gate_profile_parses_and_matches_the_workflow() -> None:
    """The nextest profile exists, parses, and names only workspace packages."""

    config = NEXTEST_CONFIG.read_text(encoding="utf-8")
    assert _validate_release_gate_profile(config) == []
    gate = tomllib.loads(config)["profile"]["release-gate"]
    packages = _filter_packages(gate["default-filter"])
    job = _job_block(RELEASE_WORKFLOW.read_text(encoding="utf-8"), "release-diagnostics")
    assert sorted(_release_gate_packages(job)) == sorted(set(packages))


GATE_SETTINGS = (
    "'''\nfail-fast = false\nfailure-output = \"immediate-final\"\n"
    "slow-timeout = { period = \"30s\", terminate-after = 4 }"
)


@pytest.mark.parametrize(("old", "new", "expected_error"), (
    (
        "    package(mv)\n",
        "    package(mv)\n    | binary(taira_app_contracts)\n",
        "release-gate must not name test binaries",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(iroha_core) & test(=state::tests::exact_name))\n",
        "release-gate test matchers must be regex groups: =state::tests::exact_name",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(iroha_core) & test(/^state::tests::exact_name$/))\n",
        "release-gate must select tests by module path: /^state::tests::exact_name$/",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(iroha_core) & test(/exact_name/))\n",
        "release-gate must select tests by module path: /exact_name/",
    ),
    (
        "package(iroha_wallet)",
        "package(iroha_wallet_renamed)",
        "release-gate names unknown packages: iroha_wallet_renamed",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | package(halo2-axiom)\n",
        "release-gate names unknown packages: halo2-axiom",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | package(iroha_sumeragi_core)\n",
        "release-gate names unknown packages: iroha_sumeragi_core",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | | package(iroha_deploy)\n",
        "release-gate default-filter must parse",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(mv) & kind(lib)\n",
        "release-gate default-filter must parse",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    - package(iroha_deploy)\n",
        "release-gate default-filter must parse",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(iroha_core) & test(/^state::tests::some_exact_test_name/))\n",
        "release-gate must select tests by module path: /^state::tests::some_exact_test_name/",
    ),
    (
        "test(/^(axt_binding|backend::compact_quantity_producer|proof)::tests::/)",
        "test(/^(axt_binding|backend::compact_quantity_producer|proof)::tests::.*(limit|resource_profile)/)",
        "release-gate must select tests by module path",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(iroha_core) & test(/^state::tests::some_exact_test_name::/))\n",
        "release-gate module path matches no module in iroha_core: "
        "state::tests::some_exact_test_name",
    ),
    (
        "|nexus_lifecycle_endpoint)",
        "|nexus_lifecycle_endpoints)",
        "release-gate module path matches no module in iroha_torii: nexus_lifecycle_endpoints",
    ),
    (
        "smartcontracts::isi::(domain|",
        "smartcontracts::isi::(unreviewed_domain|",
        "release-gate module path matches no module in iroha_core: smartcontracts::isi::unreviewed_domain",
    ),
    (
        "    package(mv)\n",
        "    package(mv)\n    | (package(iroha_core) | package(iroha_p2p)) & test(/^state::/)\n",
        "each release-gate group must name exactly one package",
    ),
    (
        "[profile.release-gate]\n",
        "[profile.release-gate]\n[profile.release-gate]\n",
        "nextest config must parse",
    ),
    (
        GATE_SETTINGS,
        GATE_SETTINGS.replace("fail-fast = false", "fail-fast = true"),
        "release-gate must report every failure (fail-fast = false)",
    ),
    (
        GATE_SETTINGS,
        GATE_SETTINGS.replace('period = "30s"', 'period = "300s"'),
        "release-gate slow-timeout must match profile.ci",
    ),
    (
        GATE_SETTINGS,
        GATE_SETTINGS.replace('"immediate-final"', '"never"'),
        "release-gate failure-output must match profile.ci",
    ),
    (
        "[profile.release-gate]",
        "[profile.release-gate-disabled]",
        "nextest config must define profile.release-gate",
    ),
))
def test_release_gate_profile_guard_rejects_name_lists_and_drift(
    old: str, new: str, expected_error: str
) -> None:
    """The gate cannot regress to exact names, binary names, or weaker runner settings."""

    config = NEXTEST_CONFIG.read_text(encoding="utf-8")
    errors = _validate_release_gate_profile(_replace_once(config, old, new))
    assert any(error.startswith(expected_error) for error in errors), errors


def test_release_gate_filter_parser_and_evaluator_follow_nextest_semantics() -> None:
    """`&` binds tighter than `|`, `not` negates one factor, and regexes search."""

    tree = _parse_filter(
        "package(a) | (package(b) & kind(lib) & test(/^m::/)) & not test(/slow/)"
    )
    assert _filter_matches(tree, "a", "test", "anything")
    assert _filter_matches(tree, "b", "lib", "m::fast")
    assert not _filter_matches(tree, "b", "lib", "m::slow")
    assert not _filter_matches(tree, "b", "test", "m::fast")
    assert not _filter_matches(tree, "b", "lib", "other::m::fast")
    assert _filter_groups(tree) == [(["a"], []), (["b"], ["/^m::/"])]
    for broken in ("", "package(a) |", "(package(a)", "package(a) package(b)",
                   "test(=exact)", "package(/a/)", "binary(a)", "package(a) + package(b)"):
        with pytest.raises(ValueError):
            _parse_filter(broken)


def test_release_gate_module_paths_expand_every_alternative() -> None:
    assert _module_path_alternatives("/^(a|b::(c|d)|e_[a-z]+)::/") == [
        "a", "b::c", "b::d", "e_[a-z]+",
    ]
    assert _module_path_alternatives("/^proof::tests::/") == ["proof::tests"]
    assert _split_alternation("a|(b|c)|[|]") == ["a", "(b|c)", "[|]"]
    packages = _workspace_packages()
    assert "iroha_core" in packages and "concread" in packages
    assert "iroha_sumeragi_core" not in packages
    assert "halo2-axiom" not in packages
    assert {"sumeragi", "tests", "world"} <= _module_names(packages["iroha_core"])


def _load_census():
    """Load the frozen Python census without running it."""

    spec = importlib.util.spec_from_file_location(
        "_release_gate_census", ROOT / "scripts" / "taira_release_check.py"
    )
    assert spec and spec.loader
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    return census


# TODO(P8): delete with `scripts/taira_release_check.py`.
def test_release_gate_selects_every_basic_census_test_except_the_four_peer_fixture() -> None:
    """The nextest gate replaces the census without dropping its basic-scope tests."""

    census = _load_census()
    config = tomllib.loads(NEXTEST_CONFIG.read_text(encoding="utf-8"))
    tree = _parse_filter(config["profile"]["release-gate"]["default-filter"])
    missing = set()
    total = 0
    for harness, stages in census.qualification_stages("basic").items():
        _, _, kind, selection = census.HARNESS_TARGETS[harness]
        package = selection[selection.index("-p") + 1]
        for _, names in stages:
            for name in names:
                total += 1
                if not _filter_matches(tree, package, kind, name):
                    missing.add((package, name))
    assert total > 1000
    # The live four-peer fixture moves to the engine self-test (TODO(P4)).
    assert missing == {("iroha_test_network", census.BEACON_NETWORK_TEST)}


def test_pr_workflow_retains_locked_workspace_and_numeric_parity() -> None:
    """PR routing fails closed while retaining pinned numeric tests."""

    workflow = PR_WORKFLOW.read_text(encoding="utf-8")
    assert _validate_pr_parity(workflow) == []


def test_compile_unit_baseline_pins_the_cross_platform_measurement_scope() -> None:
    """The checked-in ratchet describes exactly the graph enforced in CI."""

    payload = json.loads(COMPILE_UNIT_BASELINE.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    baseline = payload["iroha_data_model_lib"]
    assert baseline["compile_units"] > 0
    assert baseline["artifact_identity"] == COMPILE_UNIT_ARTIFACT_IDENTITY
    assert baseline["manifest_path"] == "Cargo.toml"
    assert baseline["packages"] == ["iroha_data_model"]
    assert baseline["target"] == "lib"
    assert baseline["artifact_scope"] == "workspace"
    assert baseline["cargo_locked"] is True
    assert baseline["toolchain"] == PINNED_RUST
    assert baseline["workspace"] is False
    assert baseline["budget_percent"] == 2
    assert baseline["budget_min_growth"] == 3


ReleaseMutation = Callable[[str], str]


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        (
            lambda workflow: _replace_once(
                workflow,
                '  schedule:\n    - cron: "17 2 * * *"',
                "",
            ),
            "release workflow must run nightly",
        ),
        (
            lambda workflow: _replace_once(
                workflow, '    tags: ["v*"]', '    tags: ["release-*"]'
            ),
            "release workflow must run on main and v* pushes",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "group: workspace-release-${{ github.sha }}",
                "group: workspace-release-${{ github.ref }}",
            ),
            "release concurrency must be scoped to the exact SHA",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "cancel-in-progress: false",
                "cancel-in-progress: true",
            ),
            "release evidence must not be cancelled by ref movement",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "WORKFLOW_SHA: ${{ github.workflow_sha }}",
                "WORKFLOW_SHA: ${{ github.sha }}",
            ),
            "format must verify the exact workflow SHA: WORKFLOW_SHA: ${{ github.workflow_sha }}",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "toolchain: 1.93.1",
                "toolchain: stable",
            ),
            "format must pin Rust 1.93.1",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                f"actions-rust-lang/setup-rust-toolchain@{SETUP_RUST_TOOLCHAIN_COMMIT}",
                "actions-rust-lang/setup-rust-toolchain@v1",
            ),
            "format must install the managed Rust toolchain from the reviewed commit",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "python3 -m pytest -q pytests/scripts/workspace_release_gate_test.py",
                "python3 -m pytest -q pytests/scripts/check_kotodama_docs_test.py",
            ),
            "format is missing required command: python3 -m pytest -q pytests/scripts/workspace_release_gate_test.py",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "cargo doc --locked --workspace --no-deps --all-features",
                "cargo doc --locked --workspace --no-deps",
            ),
            "doc is missing required command: cargo doc --locked --workspace --no-deps --all-features",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "cargo test --locked --workspace --no-fail-fast",
                "cargo test --workspace --no-fail-fast",
            ),
            "test is missing required command: cargo test --locked --workspace --no-fail-fast",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "test",
                "python3 scripts/check_compile_unit_budget.py",
                "true # compile-unit guard removed",
            ),
            f"test is missing required command: {COMPILE_UNIT_GUARD_COMMAND}",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "test",
                "--budget-percent 2",
                "--budget-percent 20",
            ),
            f"test is missing required command: {COMPILE_UNIT_GUARD_COMMAND}",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "coverallsapp/github-action@648a8eb78e6d50909eff900e4ec85cab4524a45b",
                "coverallsapp/github-action@main",
            ),
            "coverage is missing required command: uses: coverallsapp/github-action@648a8eb78e6d50909eff900e4ec85cab4524a45b",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "cargo clippy --locked --workspace --all-targets --all-features",
                "cargo clippy --locked --workspace --all-targets",
            ),
            "clippy is missing required command: cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
        ),
    ),
)
def test_release_workflow_guard_rejects_weakening(
    mutation: ReleaseMutation, expected_error: str
) -> None:
    """Representative trigger, source, toolchain, and command drift fails closed."""

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert expected_error in _validate_release_workflow(mutation(workflow))


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        (
            lambda workflow: _replace_once(
                workflow,
                "python3 -m pytest -q pytests/scripts/workspace_release_gate_test.py",
                "python3 -m pytest -q pytests/scripts/check_kotodama_docs_test.py",
            ),
            "PR workflow must execute the workspace release semantics guard",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "    branches: [main]\n",
                "    branches: [main]\n    paths-ignore: ['**/*.md']\n",
            ),
            "PR workflow must classify every change before selectively skipping jobs",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                '          scope_args=(--base "$BASE_SHA")\n',
                "          scope_args=(--paths specs/index.md)\n",
            ),
            "PR Rust classifier is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_changes",
                "python3 scripts/check_cargo_feature_hygiene.py",
                "true # Cargo feature guard removed",
            ),
            "PR Rust classifier is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_changes",
                "python3 scripts/check_workspace_target_inventory.py",
                "true # Cargo target guard removed",
            ),
            "PR Rust classifier is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_changes",
                BUILD_EFFICIENCY_PROVENANCE_TEST,
                "scripts/tests/check_compile_unit_budget_test.py",
            ),
            "PR Rust classifier is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_changes",
                BUILD_EFFICIENCY_PROVENANCE_COMMAND,
                "true # build-efficiency provenance removed",
            ),
            "PR Rust classifier is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_changes",
                f"{BUILD_EFFICIENCY_PROVENANCE_COMMAND}\n"
                "          python3 scripts/rust_ci.py validate",
                "python3 scripts/rust_ci.py validate\n"
                f"          {BUILD_EFFICIENCY_PROVENANCE_COMMAND}",
            ),
            "PR build-efficiency provenance guard must run before",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_affected",
                "--checks clippy,build,test,doc",
                "--checks build",
            ),
            "PR affected Rust job is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_affected",
                "--artifact-scope workspace",
                "--artifact-scope all",
            ),
            "PR affected Rust job is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_affected",
                f"toolchain: {PINNED_RUST}",
                "toolchain: stable",
            ),
            "PR affected Rust job is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_affected",
                "if: matrix.lane == 'execution'",
                "if: false",
            ),
            "PR affected Rust job is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "rust_required",
                '          test "$CLASSIFIER_RESULT" = success\n',
                "          true\n",
            ),
            "PR Rust result aggregator is missing required behavior",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "numeric_v1_architecture_parity",
                "          toolchain: 1.93.1\n"
                f"      - uses: Swatinem/rust-cache@{RUST_CACHE_COMMIT}",
                "          toolchain: stable\n"
                f"      - uses: Swatinem/rust-cache@{RUST_CACHE_COMMIT}",
            ),
            "PR numeric parity must pin Rust 1.93.1",
        ),
        (
            lambda workflow: _replace_once_in_job(
                workflow,
                "numeric_v1_architecture_parity",
                f"actions-rust-lang/setup-rust-toolchain@{SETUP_RUST_TOOLCHAIN_COMMIT}",
                "actions-rust-lang/setup-rust-toolchain@v1",
            ),
            "PR numeric parity must install the managed Rust toolchain from the reviewed commit",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "cargo test --locked -p ivm --test ivm_group_06 numeric_",
                "cargo test -p ivm --test ivm_group_06 numeric_",
            ),
            "PR numeric parity command is not locked",
        ),
        (
            lambda workflow: _replace_once(
                workflow,
                "cargo test --locked -p ivm --test ivm_group_03 gas_schedule_hash",
                "true # numeric gas schedule coverage removed",
            ),
            "PR numeric parity is missing required command",
        ),
    ),
)
def test_pr_workflow_guard_rejects_parity_weakening(
    mutation: ReleaseMutation, expected_error: str
) -> None:
    """PR workspace selection, toolchain pinning, and locking fail closed."""

    workflow = PR_WORKFLOW.read_text(encoding="utf-8")
    assert any(
        expected_error in error for error in _validate_pr_parity(mutation(workflow))
    )
