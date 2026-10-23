#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SORAFS_PIN_REGISTER_SDK_GUARD_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MODE="${1:-}"

python3 - "${ROOT_DIR}" "${MODE}" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
mode = sys.argv[2]
text_overrides = {}

workflow_path = ".github/workflows/pr_sorafs_pin_register_sdk.yml"
main_job = "sorafs-pin-register-sdk-guard"
swift_job = "sorafs_pin_register_swift_sdk_check"
jvm_job = "sorafs_pin_register_jvm_sdk_tests"
csharp_job = "sorafs_pin_register_csharp_sdk_tests"
js_job = "sorafs_pin_register_javascript_sdk_tests"
python_job = "sorafs_pin_register_python_sdk_tests"

main_command = "bash ci/check_sorafs_pin_register_sdk_guard.sh"
bytecode_command = "bash ci/check_no_tracked_python_bytecode.sh"
swift_command = "bash ci/check_sorafs_pin_register_swift_sdk.sh"
jvm_command = "bash ci/check_sorafs_pin_register_jvm_sdk.sh"
csharp_command = "bash ci/check_sorafs_pin_register_csharp_sdk.sh"
js_install_command = "npm ci --prefix javascript/iroha_js"
js_command = "bash ci/check_sorafs_pin_register_js_sdk.sh"
python_command = "bash ci/check_sorafs_pin_register_python_sdk.sh"
main_job_needs_line = (
    "    needs: [sorafs_pin_register_swift_sdk_check, "
    "sorafs_pin_register_jvm_sdk_tests, sorafs_pin_register_csharp_sdk_tests, "
    "sorafs_pin_register_javascript_sdk_tests, sorafs_pin_register_python_sdk_tests]"
)

required_paths = (
    workflow_path,
    "ci/check_sorafs_pin_register_csharp_sdk.sh",
    "ci/check_no_tracked_python_bytecode.sh",
    "ci/check_sorafs_pin_register_js_sdk.sh",
    "ci/check_sorafs_pin_register_jvm_sdk.sh",
    "ci/check_sorafs_pin_register_python_sdk.sh",
    "ci/check_sorafs_pin_register_sdk_guard.sh",
    "ci/check_sorafs_pin_register_swift_sdk.sh",
    "IrohaSwift/Sources/IrohaSwift/ToriiClient.swift",
    "IrohaSwift/Tests/IrohaSwiftTests/ToriiClientTests.swift",
    "csharp/src/Hyperledger.Iroha.Sdk/Torii/ToriiClient.cs",
    "csharp/src/Hyperledger.Iroha.Sdk/Torii/ToriiModels.cs",
    "csharp/src/Hyperledger.Iroha.Sdk/Torii/ToriiJsonSerializerContext.cs",
    "csharp/tests/Hyperledger.Iroha.Sdk.Tests/ToriiClientTests.cs",
    "csharp/tests/Hyperledger.Iroha.Sdk.Tests/Hyperledger.Iroha.Sdk.Tests.csproj",
    "artifacts/openapi/torii.json",
    "artifacts/openapi/versions/current/torii.json",
    "crates/iroha/src/client.rs",
    "crates/iroha_torii/assets/openapi/torii.json",
    "crates/iroha_torii/src/openapi.rs",
    "crates/iroha_torii/src/openapi/tests/sorafs_contracts.rs",
    "crates/iroha_torii/src/routing.rs",
    "crates/iroha_torii/tests/sorafs_discovery.rs",
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/ApprovePinManifestInstruction.java",
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/BindManifestAliasInstruction.java",
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/RegisterPinManifestInstruction.java",
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/RetirePinManifestInstruction.java",
    "java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsManifestInstructionBuilderTests.java",
    "java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java",
    "java/iroha_android/src/test/java/org/hyperledger/iroha/android/testing/SimpleJson.java",
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/ApprovePinManifestInstruction.kt",
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstruction.kt",
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/RetirePinManifestInstruction.kt",
    "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/PinManifestLifecycleInstructionTest.kt",
    "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt",
    "javascript/iroha_js/package.json",
    "javascript/iroha_js/package-lock.json",
    "javascript/iroha_js/src/transaction.js",
    "javascript/iroha_js/src/toriiClient.js",
    "javascript/iroha_js/index.d.ts",
    "javascript/iroha_js/test/toriiClient.test.js",
    "javascript/iroha_js/test/sorafsPinRegisterSdkGuard.test.js",
    "javascript/iroha_js/test/transactionBuilder.test.js",
    "python/iroha_python/src/iroha_python/__init__.py",
    "python/iroha_python/src/iroha_python/client.py",
    "python/iroha_python/tests/client_sorafs_pin_register_test.py",
    "roadmap.md",
    "status.md",
)

negative_control_commands = (
    ("workflow path negative control", f"{main_command} --negative-control-workflow-path"),
    ("workflow command negative control", f"{main_command} --negative-control-workflow-command"),
    (
        "negative-control workflow negative control",
        f"{main_command} --negative-control-negative-controls-workflow",
    ),
    (
        "commented negative-control workflow negative control",
        f"{main_command} --negative-control-negative-controls-comment-workflow",
    ),
    (
        "negative-control ordering workflow negative control",
        f"{main_command} --negative-control-negative-controls-order-workflow",
    ),
    (
        "tracked Python bytecode workflow negative control",
        f"{main_command} --negative-control-bytecode-workflow",
    ),
    (
        "OpenAPI split-test include negative control",
        f"{main_command} --negative-control-openapi-test-include",
    ),
    (
        "OpenAPI split-test body negative control",
        f"{main_command} --negative-control-openapi-test-function",
    ),
    ("Swift SDK job workflow negative control", f"{main_command} --negative-control-swift-sdk-job-workflow"),
    ("Swift SDK runner workflow negative control", f"{main_command} --negative-control-swift-sdk-runner-workflow"),
    ("Swift SDK script workflow negative control", f"{main_command} --negative-control-swift-sdk-script-workflow"),
    ("Swift SDK version script negative control", f"{main_command} --negative-control-swift-sdk-version-script"),
    ("Swift SDK compiler override script negative control", f"{main_command} --negative-control-swift-sdk-override-script"),
    ("Swift SDK dependency workflow negative control", f"{main_command} --negative-control-swift-sdk-needs-workflow"),
    ("JVM SDK job workflow negative control", f"{main_command} --negative-control-jvm-sdk-job-workflow"),
    ("JVM SDK setup workflow negative control", f"{main_command} --negative-control-jvm-sdk-setup-workflow"),
    ("JVM SDK Java distribution workflow negative control", f"{main_command} --negative-control-jvm-sdk-distribution-workflow"),
    ("JVM SDK Java version workflow negative control", f"{main_command} --negative-control-jvm-sdk-java-version-workflow"),
    ("JVM SDK Java setup ordering workflow negative control", f"{main_command} --negative-control-jvm-sdk-setup-order-workflow"),
    ("JVM SDK script workflow negative control", f"{main_command} --negative-control-jvm-sdk-script-workflow"),
    ("JVM SDK JDK 21 script negative control", f"{main_command} --negative-control-jvm-sdk-jdk21-script"),
    ("JVM SDK Java home override script negative control", f"{main_command} --negative-control-jvm-sdk-java-home-override-script"),
    ("JVM SDK inherited Java home rejection script negative control", f"{main_command} --negative-control-jvm-sdk-java-home-reject-script"),
    ("JVM SDK dependency workflow negative control", f"{main_command} --negative-control-jvm-sdk-needs-workflow"),
    ("C# SDK job workflow negative control", f"{main_command} --negative-control-csharp-sdk-job-workflow"),
    ("C# SDK setup workflow negative control", f"{main_command} --negative-control-csharp-sdk-setup-workflow"),
    ("C# SDK dotnet version workflow negative control", f"{main_command} --negative-control-csharp-sdk-dotnet-version-workflow"),
    ("C# SDK setup ordering workflow negative control", f"{main_command} --negative-control-csharp-sdk-setup-order-workflow"),
    ("C# SDK dotnet version script negative control", f"{main_command} --negative-control-csharp-sdk-dotnet-version-script"),
    ("C# SDK dotnet override script negative control", f"{main_command} --negative-control-csharp-sdk-dotnet-override-script"),
    ("C# SDK dotnet major script negative control", f"{main_command} --negative-control-csharp-sdk-dotnet-major-script"),
    ("C# SDK script workflow negative control", f"{main_command} --negative-control-csharp-sdk-script-workflow"),
    ("C# SDK dependency workflow negative control", f"{main_command} --negative-control-csharp-sdk-needs-workflow"),
    ("JavaScript SDK job workflow negative control", f"{main_command} --negative-control-js-sdk-job-workflow"),
    ("JavaScript SDK runner workflow negative control", f"{main_command} --negative-control-js-sdk-runner-workflow"),
    ("JavaScript SDK Node setup workflow negative control", f"{main_command} --negative-control-js-sdk-node-setup-workflow"),
    ("JavaScript SDK Node version workflow negative control", f"{main_command} --negative-control-js-sdk-node-version-workflow"),
    ("JavaScript SDK Node version script negative control", f"{main_command} --negative-control-js-sdk-node-version-script"),
    ("JavaScript SDK Node override script negative control", f"{main_command} --negative-control-js-sdk-node-override-script"),
    ("JavaScript SDK Node resolver script negative control", f"{main_command} --negative-control-js-sdk-node-resolver-script"),
    ("JavaScript SDK Node major script negative control", f"{main_command} --negative-control-js-sdk-node-major-script"),
    ("JavaScript SDK Node cache workflow negative control", f"{main_command} --negative-control-js-sdk-node-cache-workflow"),
    ("JavaScript SDK Node setup ordering workflow negative control", f"{main_command} --negative-control-js-sdk-node-setup-order-workflow"),
    ("JavaScript SDK install workflow negative control", f"{main_command} --negative-control-js-sdk-install-workflow"),
    ("JavaScript SDK script workflow negative control", f"{main_command} --negative-control-js-sdk-script-workflow"),
    ("JavaScript SDK install ordering workflow negative control", f"{main_command} --negative-control-js-sdk-install-order-workflow"),
    ("JavaScript SDK test ordering workflow negative control", f"{main_command} --negative-control-js-sdk-test-order-workflow"),
    ("JavaScript SDK dependency workflow negative control", f"{main_command} --negative-control-js-sdk-needs-workflow"),
    ("Python SDK job workflow negative control", f"{main_command} --negative-control-python-sdk-job-workflow"),
    ("Python SDK setup workflow negative control", f"{main_command} --negative-control-python-sdk-setup-workflow"),
    ("Python SDK version workflow negative control", f"{main_command} --negative-control-python-sdk-version-workflow"),
    ("Python SDK setup ordering workflow negative control", f"{main_command} --negative-control-python-sdk-setup-order-workflow"),
    ("Python SDK version script negative control", f"{main_command} --negative-control-python-sdk-version-script"),
    ("Python SDK override script negative control", f"{main_command} --negative-control-python-sdk-override-script"),
    ("Python SDK resolver script negative control", f"{main_command} --negative-control-python-sdk-resolver-script"),
    ("Python SDK major script negative control", f"{main_command} --negative-control-python-sdk-major-script"),
    ("Python SDK stale venv rebuild script negative control", f"{main_command} --negative-control-python-sdk-venv-rebuild-script"),
    ("Python SDK bytecode script negative control", f"{main_command} --negative-control-python-sdk-bytecode-script"),
    ("Python SDK dependency lock script negative control", f"{main_command} --negative-control-python-sdk-lock-script"),
    ("Python SDK script workflow negative control", f"{main_command} --negative-control-python-sdk-script-workflow"),
    ("Python SDK dependency workflow negative control", f"{main_command} --negative-control-python-sdk-needs-workflow"),
    ("JavaScript source negative control", f"{main_command} --negative-control-js-source-endpoint"),
    ("JavaScript adversarial test negative control", f"{main_command} --negative-control-js-adversarial-test"),
    ("Python adversarial test negative control", f"{main_command} --negative-control-python-adversarial-test"),
    (
        "Rust client sole-manifest-source negative control",
        f"{main_command} --negative-control-rust-client-dual-manifest-source",
    ),
    (
        "Rust client retired submitted-epoch negative control",
        f"{main_command} --negative-control-rust-client-submitted-epoch",
    ),
    (
        "Rust client canonical wire-key negative control",
        f"{main_command} --negative-control-rust-client-manifest-b64-wire",
    ),
    (
        "Rust client manifest bound negative control",
        f"{main_command} --negative-control-rust-client-manifest-bound",
    ),
    (
        "Rust client canonical decode negative control",
        f"{main_command} --negative-control-rust-client-canonical-decode",
    ),
    (
        "Rust client retired helper negative control",
        f"{main_command} --negative-control-rust-client-retired-helper",
    ),
    (
        "Torii retired manifest_b64 negative control",
        f"{main_command} --negative-control-torii-retired-manifest-b64",
    ),
    (
        "Torii retired summary-field negative control",
        f"{main_command} --negative-control-torii-retired-summary-field",
    ),
    (
        "Torii manifest bound negative control",
        f"{main_command} --negative-control-torii-manifest-bound",
    ),
    (
        "Torii canonical decode negative control",
        f"{main_command} --negative-control-torii-canonical-decode",
    ),
    (
        "Torii retired helper negative control",
        f"{main_command} --negative-control-torii-retired-helper",
    ),
    (
        "Python retired fee_payment negative control",
        f"{main_command} --negative-control-python-fee-payment-field",
    ),
    ("Swift contract test negative control", f"{main_command} --negative-control-swift-contract-test"),
    ("Swift retired request field negative control", f"{main_command} --negative-control-swift-retired-request-field"),
    ("C# malformed response test negative control", f"{main_command} --negative-control-csharp-malformed-response-test"),
    ("Kotlin builder test negative control", f"{main_command} --negative-control-kotlin-builder-test"),
    ("Kotlin successor digest test negative control", f"{main_command} --negative-control-kotlin-successor-digest-test"),
    ("Java builder test negative control", f"{main_command} --negative-control-java-builder-test"),
    ("Java successor digest test negative control", f"{main_command} --negative-control-java-successor-digest-test"),
    (
        "JavaScript retired submitted-epoch type negative control",
        f"{main_command} --negative-control-js-submitted-epoch-type",
    ),
    (
        "Kotlin retired submitted-epoch model negative control",
        f"{main_command} --negative-control-kotlin-submitted-epoch-model",
    ),
    (
        "Java retired submitted-epoch model negative control",
        f"{main_command} --negative-control-java-submitted-epoch-model",
    ),
)


class GuardError(Exception):
    pass


def read_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def read_text_no_follow(full_path: Path, label: str) -> str:
    if full_path.is_symlink():
        raise GuardError(f"{label} must not be a symlink: {full_path}")
    for parent in (full_path.parent, *full_path.parent.parents):
        if parent.is_symlink():
            raise GuardError(f"{label} parent must not be a symlink: {parent}")
        if parent.exists() and not parent.is_dir():
            raise GuardError(f"{label} parent must be a directory: {parent}")
    try:
        path_stat = full_path.lstat()
    except FileNotFoundError as exc:
        raise GuardError(f"required file is missing: {label}") from exc
    if not stat.S_ISREG(path_stat.st_mode):
        raise GuardError(f"{label} must be a regular file: {full_path}")
    fd = os.open(full_path, read_open_flags())
    try:
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise GuardError(f"{label} must be a regular file: {full_path}")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    except OSError as exc:
        raise GuardError(f"failed to read required file {label}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def read(path):
    if path in text_overrides:
        return text_overrides[path]
    full_path = root / path
    return read_text_no_follow(full_path, path)


def require(condition, message):
    if not condition:
        raise GuardError(message)


def require_contains(path, needle, label):
    require(needle in read(path), f"{path} missing {label}: {needle}")


def require_min_count(path, needle, minimum, label):
    actual = read(path).count(needle)
    require(
        actual >= minimum,
        f"{path} missing {label}: expected at least {minimum}, got {actual}: {needle}",
    )


def require_regex_slice(path, pattern, label):
    match = re.search(pattern, read(path), flags=re.MULTILINE | re.DOTALL)
    require(match is not None, f"{path} missing structured {label} slice")
    return match.group(0)


def rust_public_field_names(item_text):
    return re.findall(r"(?m)^\s+pub\s+([a-z][a-z0-9_]*)\s*:", item_text)


def rust_named_field_names(item_text):
    return re.findall(
        r"(?m)^\s+(?:pub(?:\([^)]*\))?\s+)?([a-z][a-z0-9_]*)\s*:",
        item_text,
    )


def require_exact_fields(actual, expected, label):
    require(
        actual == expected,
        f"{label} fields must be exactly {expected}; got {actual}",
    )


def compact_source(text):
    return re.sub(r"\s+", "", text)


def require_ordered_fragments(text, fragments, label):
    compact = compact_source(text)
    cursor = -1
    for fragment, fragment_label in fragments:
        compact_fragment = compact_source(fragment)
        position = compact.find(compact_fragment)
        require(
            position >= 0,
            f"{label} missing {fragment_label}: {fragment}",
        )
        require(
            position > cursor,
            f"{label} must perform {fragment_label} in fail-closed order",
        )
        cursor = position


def rust_function_is_declared(source, name):
    return (
        re.search(
            rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{re.escape(name)}\s*\(",
            source,
        )
        is not None
    )


def workflow_job(workflow, job):
    marker = f"  {job}:\n"
    start = workflow.find(marker)
    require(start >= 0, f"workflow missing job: {job}")
    next_match = re.search(r"\n  [A-Za-z0-9_-]+:\n", workflow[start + len(marker) :])
    if next_match is None:
        return workflow[start:]
    return workflow[start : start + len(marker) + next_match.start()]


def require_workflow_path(workflow, path):
    require(f'      - "{path}"' in workflow, f"workflow pull_request paths must include {path}")


def require_run(job_text, command, label):
    require(f"        run: {command}\n" in job_text, f"{label} must run `{command}`")


def require_negative_controls(workflow):
    for label, command in negative_control_commands:
        require(
            f"          {command}\n" in workflow,
            f"workflow must execute {label}: {command}",
        )
    first_negative = workflow.index(f"          {negative_control_commands[0][1]}\n")
    guard_command = workflow.index(f"        run: {main_command}")
    require(first_negative < guard_command, "negative controls must run before the main guard")


def check_workflow():
    workflow = read(workflow_path)
    require("name: SoraFS Pin Register SDK Guard" in workflow, "workflow has unexpected name")
    require("cancel-in-progress: false" in workflow, "workflow must not cancel in-progress checks")
    for path in required_paths:
        require_workflow_path(workflow, path)

    swift = workflow_job(workflow, swift_job)
    require("    runs-on: macos-latest" in swift, "Swift SDK check must run on macOS")
    require_run(swift, swift_command, "Swift SDK check")

    jvm = workflow_job(workflow, jvm_job)
    require("    runs-on: ubuntu-latest" in jvm, "JVM SDK tests must run on Ubuntu")
    java_setup_match = re.search(
        r"(?m)^\s+- uses:\s+actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961\s*$",
        jvm,
    )
    java_command_match = re.search(rf"(?m)^\s+run:\s+{re.escape(jvm_command)}\s*$", jvm)
    require(java_setup_match is not None, "JVM SDK tests must set up Java")
    require(re.search(r'(?m)^\s+distribution:\s+"temurin"\s*$', jvm) is not None, "JVM SDK tests must pin Temurin Java")
    require(re.search(r'(?m)^\s+java-version:\s+"21"\s*$', jvm) is not None, "JVM SDK tests must pin Java 21")
    require_run(jvm, jvm_command, "JVM SDK tests")
    if java_setup_match is not None and java_command_match is not None:
        require(
            java_setup_match.start() < java_command_match.start(),
            "JVM SDK tests must set up Java before running tests",
        )

    csharp = workflow_job(workflow, csharp_job)
    require("    runs-on: ubuntu-latest" in csharp, "C# SDK tests must run on Ubuntu")
    dotnet_setup_match = re.search(
        r"(?m)^\s+- uses:\s+actions/setup-dotnet@26b0ec14cb23fa6904739307f278c14f94c95bf1\s*$",
        csharp,
    )
    dotnet_command_match = re.search(rf"(?m)^\s+run:\s+{re.escape(csharp_command)}\s*$", csharp)
    require(dotnet_setup_match is not None, "C# SDK tests must set up .NET")
    require(re.search(r"(?m)^\s+dotnet-version:\s+8\.0\.x\s*$", csharp) is not None, "C# SDK tests must pin .NET 8")
    require_run(csharp, csharp_command, "C# SDK tests")
    if dotnet_setup_match is not None and dotnet_command_match is not None:
        require(
            dotnet_setup_match.start() < dotnet_command_match.start(),
            "C# SDK tests must set up .NET before running tests",
        )

    js = workflow_job(workflow, js_job)
    require("    runs-on: ubuntu-latest" in js, "JavaScript SDK tests must run on Ubuntu")
    node_setup_match = re.search(
        r"(?m)^\s+- uses:\s+actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38\s*$",
        js,
    )
    node_install_match = re.search(rf"(?m)^\s+run:\s+{re.escape(js_install_command)}\s*$", js)
    require(node_setup_match is not None, "JavaScript SDK tests must set up Node")
    require(re.search(r'(?m)^\s+node-version:\s+"24"\s*$', js) is not None, "JavaScript SDK tests must pin Node 24")
    require(
        re.search(
            r"(?m)^\s+cache-dependency-path:\s+javascript/iroha_js/package-lock\.json\s*$",
            js,
        )
        is not None,
        "JavaScript SDK tests must cache dependencies by package-lock",
    )
    require(f"        run: {js_install_command}" in js, "JavaScript SDK tests must install dependencies")
    require_run(js, js_command, "JavaScript SDK tests")
    if node_setup_match is not None and node_install_match is not None:
        require(
            node_setup_match.start() < node_install_match.start(),
            "JavaScript SDK tests must set up Node before installing dependencies",
        )
    require(
        js.index(f"        run: {js_install_command}") < js.index(f"        run: {js_command}"),
        "JavaScript SDK dependency install must run before tests",
    )

    python = workflow_job(workflow, python_job)
    require("    runs-on: ubuntu-latest" in python, "Python SDK tests must run on Ubuntu")
    python_setup_match = re.search(
        r"(?m)^\s+- uses:\s+actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\s*$",
        python,
    )
    python_command_match = re.search(rf"(?m)^\s+run:\s+{re.escape(python_command)}\s*$", python)
    require(python_setup_match is not None, "Python SDK tests must set up Python")
    require(re.search(r'(?m)^\s+python-version:\s+"3\.12"\s*$', python) is not None, "Python SDK tests must pin Python 3.12")
    require_run(python, python_command, "Python SDK tests")
    if python_setup_match is not None and python_command_match is not None:
        require(
            python_setup_match.start() < python_command_match.start(),
            "Python SDK tests must set up Python before running tests",
        )

    main = workflow_job(workflow, main_job)
    require(main_job_needs_line in main, "main SoraFS guard must depend on every SDK lane")
    require_run(main, bytecode_command, "tracked Python bytecode guard")
    require_run(main, main_command, "main SoraFS SDK guard")
    require(
        main.index(f"        run: {bytecode_command}\n") < main.index(f"        run: {main_command}\n"),
        "tracked Python bytecode guard must run before the main SoraFS SDK guard",
    )
    require_negative_controls(workflow)


def check_scripts():
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", "buildRegisterPinManifestInstruction", "focused JS instruction-builder test pattern")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", "rejects a retired submitted epoch", "focused JS retired-time test pattern")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", "test/transactionBuilder.test.js", "JavaScript instruction-builder test file")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", 'NODE_OVERRIDE="${SORAFS_PIN_REGISTER_JS_SDK_NODE_BIN:-}"', "JavaScript SDK Node override variable")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", "resolve_node_24_bin()", "JavaScript SDK Node 24 resolver")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", "is_node_24_bin()", "JavaScript SDK Node 24 version predicate")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", 'NODE_BIN="$(resolve_node_24_bin)"', "JavaScript SDK selected Node resolver")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", 'NODE_VERSION="$("${NODE_BIN}" --version)"', "JavaScript SDK selected Node capture")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", 'printf \'%s\\n\' "${NODE_VERSION}"', "JavaScript SDK Node version evidence")
    require_contains("ci/check_sorafs_pin_register_js_sdk.sh", "v24.*) ;;", "JavaScript SDK Node 24 matcher")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "client_sorafs_pin_register_test.py", "Python paid-pin test suite")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", 'PYTHON_OVERRIDE="${SORAFS_PIN_REGISTER_PYTHON_BIN:-}"', "Python SDK override variable")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "resolve_python_312_bin()", "Python SDK 3.12 resolver")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "python3.12", "Python SDK 3.12 resolver candidate")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", 'PYTHON_BIN="$(resolve_python_312_bin)"', "Python SDK selected resolver")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", 'PYTHON_VERSION="$("${PYTHON_BIN}" -c', "Python SDK selected version capture")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", '"${PYTHON_BIN}" --version', "Python SDK selected version evidence")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", 'VENV_PYTHON_VERSION="$("${VENV_DIR}/bin/python" -c', "Python SDK venv version capture")
    require_min_count(
        "ci/check_sorafs_pin_register_python_sdk.sh",
        '"${VENV_DIR}/bin/python" --version',
        2,
        "Python SDK initial and rebuilt venv version evidence",
    )
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "3.12) ;;", "Python SDK 3.12 matcher")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "recreating SoraFS pin-register Python SDK venv", "Python SDK stale venv rebuild evidence")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", 'rm -rf "${VENV_DIR}"', "Python SDK stale venv removal")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "export PYTHONDONTWRITEBYTECODE=1", "Python SDK bytecode-cache guard")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "--require-hashes", "Python SDK hashed dependency lock")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", "--only-binary=:all:", "Python SDK binary-only dependency lock")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", '"${ROOT_DIR}/python/iroha_python/requirements-ci.lock"', "Python SDK exact dependency lock")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", '"${ROOT_DIR}/python/norito_py"', "Python SDK local Norito package install")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", '"${ROOT_DIR}/python/iroha_torii_client"', "Python SDK local Torii package install")
    require_contains("ci/check_sorafs_pin_register_python_sdk.sh", 'PYTHONPATH="${ROOT_DIR}/python/iroha_python/src:${ROOT_DIR}/python/norito_py/src:${ROOT_DIR}/python"', "Python SDK local source path")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "RegisterPinManifestInstructionTest", "Kotlin paid-pin builder test")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "PinManifestLifecycleInstructionTest", "Kotlin pin lifecycle hard-cut test")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "SorafsRegisterPinManifestBuilderTests", "Java Android paid-pin builder harness")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "SorafsManifestInstructionBuilderTests", "Java Android pin lifecycle hard-cut harness")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", 'JAVA_HOME_OVERRIDE="${SORAFS_PIN_REGISTER_JVM_SDK_JAVA_HOME:-}"', "JVM SDK Java home override variable")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "SORAFS_PIN_REGISTER_JVM_SDK_JAVA_HOME must point to a JDK 21 home.", "JVM SDK explicit Java home override rejection")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "JAVA_HOME must point to a JDK 21 home for SoraFS pin-register JVM SDK tests.", "JVM SDK inherited Java home rejection")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "is_java_21_home()", "JVM SDK JDK 21 resolver")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", 'version[[:space:]]+\\"21(\\.|\\")', "JVM SDK JDK 21 version matcher")
    require_contains("ci/check_sorafs_pin_register_jvm_sdk.sh", "java -version", "JVM SDK Java version evidence")
    require_contains("ci/check_sorafs_pin_register_swift_sdk.sh", "testRegisterSoraFsPinManifestPostsOnlySignedNoritoAndReturnsAdmission", "Swift signed-transport test contract")
    require_contains("ci/check_sorafs_pin_register_swift_sdk.sh", 'SWIFTC_BIN="${SORAFS_PIN_REGISTER_SWIFTC_BIN:-swiftc}"', "Swift SDK swiftc override variable")
    require_contains("ci/check_sorafs_pin_register_swift_sdk.sh", '"${SWIFTC_BIN}" --version', "Swift SDK swiftc version evidence")
    require_contains("ci/check_sorafs_pin_register_csharp_sdk.sh", "RegisterSoraFsPinManifestAsync", "C# paid-pin test filter")
    require_contains("ci/check_sorafs_pin_register_csharp_sdk.sh", '--filter-method "*RegisterSoraFsPinManifestAsync*"', "C# Microsoft Testing Platform method filter")
    require_contains("ci/check_sorafs_pin_register_csharp_sdk.sh", 'DOTNET_BIN="${SORAFS_PIN_REGISTER_DOTNET_BIN:-dotnet}"', "C# SDK dotnet override variable")
    require_contains("ci/check_sorafs_pin_register_csharp_sdk.sh", 'DOTNET_VERSION="$("${DOTNET_BIN}" --version)"', "C# SDK selected dotnet capture")
    require_contains("ci/check_sorafs_pin_register_csharp_sdk.sh", 'printf \'%s\\n\' "${DOTNET_VERSION}"', "C# SDK dotnet version evidence")
    require_contains("ci/check_sorafs_pin_register_csharp_sdk.sh", "8.0.*) ;;", "C# SDK dotnet 8 matcher")


def check_rust_wire_contract():
    client_path = "crates/iroha/src/client.rs"
    client_source = read(client_path)
    client_args = require_regex_slice(
        client_path,
        r"^pub struct SorafsPinRegisterArgs<'a>\s*\{.*?^\}",
        "Rust client SorafsPinRegisterArgs",
    )
    require_exact_fields(
        rust_named_field_names(client_args),
        ["manifest_payload", "alias", "successor_of"],
        "Rust client SorafsPinRegisterArgs",
    )
    require(
        "authority" not in client_args
        and "private_key" not in client_args
        and "submitted_epoch" not in client_args,
        "Rust pin-register arguments must not transport signing material or caller time",
    )
    pin_register_start = client_source.find("    pub async fn post_sorafs_pin_register(")
    require(pin_register_start >= 0, "Rust client missing canonical account pin-register operation")
    pin_register_end = client_source.find(
        "\n    /// Submit a prebuilt transaction", pin_register_start
    )
    require(pin_register_end >= 0, "Rust client pin-register operation is not structurally bounded")
    pin_register_source = client_source[pin_register_start:pin_register_end]
    for needle, label in (
        (
            ".quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })",
            "typed account fee quote",
        ),
        (
            "apply_fee_quote_intent(&mut payload, quote.intent)",
            "fee-quote binding validation",
        ),
        ("self.sign_transaction(payload)?", "local account signing"),
        ('.header("Content-Type", APPLICATION_NORITO)', "Norito content type"),
        (".body(transaction.encode_versioned())", "versioned signed body"),
        ("Client::decode_json_response(", "canonical response decoding"),
        ("StatusCode::ACCEPTED", "HTTP 202 admission"),
        ("InstructionBox::from(instruction)", "typed instruction assembly"),
    ):
        require(needle in pin_register_source, f"Rust pin-register client missing {label}")

    torii_path = "crates/iroha_torii/src/routing.rs"
    torii_source = read(torii_path)
    require(
        "pub struct RegisterPinManifestDto" not in torii_source,
        "Torii must not retain the secret-bearing pin request DTO",
    )
    response = require_regex_slice(
        torii_path,
        r"^pub struct RegisterPinManifestResponseDto\s*\{.*?^\}",
        "Torii pin-register admission response",
    )
    require_exact_fields(
        rust_named_field_names(response),
        ["status", "tx_hash_hex", "manifest_digest_hex"],
        "Torii pin-register admission response",
    )
    handler = require_regex_slice(
        torii_path,
        r"^pub async fn handle_post_sorafs_register_manifest\b.*?^\}",
        "Torii signed pin-register handler",
    )
    for needle, label in (
        ("transaction: SignedTransaction", "signed transaction input"),
        ("validate_sorafs_pin_register_transaction", "signed transaction validation"),
        ("handle_transaction_with_metrics(", "original queue submission"),
        ('status: "submitted".to_owned()', "submitted status"),
        ("StatusCode::ACCEPTED", "HTTP 202 response"),
    ):
        require(needle in handler, f"Torii pin-register handler missing {label}")
    validator = require_regex_slice(
        torii_path,
        r"^fn validate_sorafs_pin_register_transaction\b.*?^\}",
        "Torii pin-register transaction validator",
    )
    require(
        "validate_single_signed_instruction::<iroha_data_model::isi::sorafs::RegisterPinManifest>"
        in compact_source(validator),
        "Torii must accept exactly one typed RegisterPinManifest",
    )
    shared = require_regex_slice(
        torii_path,
        r"^fn validate_single_signed_instruction\b.*?^\}",
        "Torii signed instruction validator",
    )
    for needle, label in (
        ("transaction.network_id() != Some(network_id)", "network validation"),
        ("transaction.verify_signature()", "signature validation"),
        ("let [instruction] = instructions.as_ref()", "exact instruction count"),
        ("downcast_ref::<T>()", "exact instruction type"),
    ):
        require(needle in shared, f"Torii signed instruction validator missing {label}")

    route_tests = read("crates/iroha_torii/tests/sorafs_discovery.rs")
    for needle, label in (
        ("sorafs_pin_register_route_accepts_caller_signed_transaction", "signed JSON test"),
        ("sorafs_pin_register_route_accepts_versioned_norito_transaction", "signed Norito test"),
        ("sorafs_pin_register_rejects_secret_bearing_legacy_body", "secret rejection"),
        ("sorafs_pin_register_rejects_wrong_shape_network_and_signature", "validation rejection"),
        ("admission response must not claim a fee, custody result, or finalized pin status", "admission claim guard"),
    ):
        require(needle in route_tests, f"Torii route tests missing {label}")

    openapi_source = read("crates/iroha_torii/src/openapi.rs")
    openapi = read("crates/iroha_torii/assets/openapi/torii.json")
    canonical_openapi = read("artifacts/openapi/torii.json")
    current_openapi = read("artifacts/openapi/versions/current/torii.json")
    require(
        canonical_openapi == current_openapi == openapi,
        "Torii latest/current/package OpenAPI authorities must be byte-identical",
    )
    for needle, label in (
        ("#/components/schemas/VersionedSignedTransactionJson", "signed request schema"),
        ("#/components/schemas/SorafsPinRegisterResponseV1", "admission response schema"),
        ("Submitted never means committed or finalized", "admission semantics"),
    ):
        require(needle in openapi, f"Torii pin-register OpenAPI missing {label}")
    openapi_document = json.loads(openapi)
    status_schema = openapi_document["components"]["schemas"][
        "SorafsPinRegisterResponseV1"
    ]["properties"]["status"]
    require(
        status_schema.get("enum") == ["submitted"],
        "Torii pin-register OpenAPI missing submitted-only status",
    )
    require(
        'include!("openapi/tests/sorafs_contracts.rs");' in openapi_source,
        "Torii pin-register OpenAPI missing its identity-preserving contract-test include",
    )
    openapi_contract_tests = read(
        "crates/iroha_torii/src/openapi/tests/sorafs_contracts.rs"
    )
    require(
        "fn sorafs_pin_register_openapi_is_caller_signed_transaction_transport()"
        in openapi_contract_tests,
        "Torii pin-register OpenAPI missing OpenAPI guard",
    )
    require(
        '"SorafsPinRegisterRequestV1"' not in openapi,
        "OpenAPI must not retain the secret-bearing request schema",
    )


def check_javascript_contract():
    for path in ("javascript/iroha_js/src/toriiClient.js",):
        source = read(path)
        match = re.search(
            r"async registerSorafsPinManifest\(signedTransaction, options = \{\}\).*?(?=\n  /\*\*)",
            source,
            flags=re.DOTALL,
        )
        require(match is not None, f"{path} signed register API is missing")
        method = match.group(0)
        for needle, label in (
            ("toVersionedTransactionPayload", "versioned transaction wrapping"),
            ('"Content-Type": APPLICATION_NORITO', "Norito content type"),
            ("Accept: APPLICATION_JSON", "JSON response negotiation"),
            ("_expectStatus(response, [202])", "HTTP 202 admission"),
        ):
            require(needle in method, f"{path} pin-register method missing {label}")
        require(
            "private_key" not in method and "manifest_payload" not in method,
            f"{path} pin-register method must transport only signed bytes",
        )
        require(
            "function buildSorafsPinRegisterPayload" not in source,
            f"{path} retains the secret-bearing request builder",
        )

    for path in ("javascript/iroha_js/src/transaction.js",):
        require_contains(path, "buildRegisterPinManifestInstruction", "local typed instruction builder")
        require_contains(path, "buildRegisterPinManifestTransaction", "local quote-and-sign builder")
        require_contains(path, "instructions: [instruction]", "exactly-one instruction assembly")
        require_contains(path, "quoteAndSignTransaction", "local signing")
        require_contains(path, "no longer accepts a submitted epoch", "retired caller-time rejection")

    dts = read("javascript/iroha_js/index.d.ts")
    require("interface SorafsPinRegisterRequest" not in dts, "TypeScript secret request DTO remains")
    instruction_input = require_regex_slice(
        "javascript/iroha_js/index.d.ts",
        r"^export interface RegisterPinManifestInstructionInput\s*\{.*?^\}",
        "TypeScript register-pin instruction input",
    )
    input_fields = re.findall(r"(?m)^\s+([A-Za-z][A-Za-z0-9_]*)(?:\?)?:", instruction_input)
    require_exact_fields(
        input_fields,
        ["manifestPayload", "alias", "successorOf"],
        "TypeScript RegisterPinManifestInstructionInput",
    )
    for needle, label in (
        ("registerSorafsPinManifest(", "signed register declaration"),
        ("signedTransaction: Buffer | ArrayBuffer | ArrayBufferView", "signed input"),
        ("buildRegisterPinManifestInstruction", "typed instruction declaration"),
        ("buildRegisterPinManifestTransaction", "local signed builder declaration"),
        ('status: "submitted";', "submitted admission response"),
    ):
        require(needle in dts, f"TypeScript declarations missing {label}")

    tests = read("javascript/iroha_js/test/toriiClient.test.js")
    for needle, label in (
        ("posts only a versioned signed transaction", "signed transport test"),
        ("rejects legacy secret-bearing request objects", "secret rejection test"),
        ("rejects pre-finality fee or custody claims", "admission response guard"),
    ):
        require(needle in tests, f"JavaScript tests missing {label}")
    transaction_tests = read("javascript/iroha_js/test/transactionBuilder.test.js")
    for needle, label in (
        ("buildRegisterPinManifestInstruction binds the canonical pin fields", "canonical instruction test"),
        ("buildRegisterPinManifestTransaction rejects a retired submitted epoch", "retired transaction epoch test"),
        ('["submittedEpoch", "submitted_epoch"]', "camel- and snake-case retired epoch rejection"),
    ):
        require(needle in transaction_tests, f"JavaScript transaction tests missing {label}")


def check_python_contract():
    client_path = "python/iroha_python/src/iroha_python/client.py"
    source = read(client_path)
    method = require_regex_slice(
        client_path,
        r"^    def register_sorafs_pin_manifest\b.*?(?=^    def )",
        "Python signed pin-register method",
    )
    for needle, label in (
        ('transaction: "SignedTransactionEnvelope"', "signed envelope input"),
        ("transaction.signed_transaction_versioned", "versioned signed bytes"),
        ('"Content-Type": "application/x-norito"', "Norito content type"),
        ('"Accept": "application/json"', "JSON response negotiation"),
        ("self._expect_status(response, (202,))", "HTTP 202 admission"),
    ):
        require(needle in method, f"Python pin-register method missing {label}")
    require(
        "private_key" not in method
        and "manifest_payload" not in method
        and "submitted_epoch" not in method
        and "fee_payment" not in method,
        "Python pin-register method must transport only signed bytes without retired request fields",
    )
    require(
        "_normalize_sorafs_pin_register_request" not in source,
        "Python secret-bearing request normalizer remains",
    )
    require_contains(
        "python/iroha_python/src/iroha_python/__init__.py",
        "SorafsPinRegisterResponse",
        "Python admission response export",
    )
    tests = read("python/iroha_python/tests/client_sorafs_pin_register_test.py")
    require("test_pin_register_posts_only_versioned_signed_transaction" in tests, "Python signed transport test missing")
    require("test_pin_register_rejects_pre_finality_fee_claim" in tests, "Python admission response guard missing")


def check_swift_contract():
    path = "IrohaSwift/Sources/IrohaSwift/ToriiClient.swift"
    source = read(path)
    method = require_regex_slice(
        path,
        r"^    public func registerSoraFsPinManifest\(_ transaction: SignedTransactionEnvelope\) async throws.*?(?=^    public func getVpnProfile)",
        "Swift signed pin-register method",
    )
    for needle, label in (
        ("body: transaction.norito", "signed Norito body"),
        ('"Content-Type": "application/x-norito"', "Norito content type"),
        ('"Accept": "application/json"', "JSON negotiation"),
        ("acceptedStatus: 202..<203", "HTTP 202 admission"),
        ('Set(["status", "tx_hash_hex", "manifest_digest_hex"])', "closed response"),
    ):
        require(needle in method, f"Swift pin-register method missing {label}")
    require(
        "ToriiSoraFsPinRegisterRequest" not in source,
        "Swift secret-bearing pin request DTO remains",
    )
    tests = read("IrohaSwift/Tests/IrohaSwiftTests/ToriiClientTests.swift")
    require("testRegisterSoraFsPinManifestPostsOnlySignedNoritoAndReturnsAdmission" in tests, "Swift signed transport test missing")
    require("testRegisterSoraFsPinManifestRejectsPreFinalityFeeClaims" in tests, "Swift admission response guard missing")


def check_csharp_contract():
    client_path = "csharp/src/Hyperledger.Iroha.Sdk/Torii/ToriiClient.cs"
    source = read(client_path)
    method = require_regex_slice(
        client_path,
        r"^    public async Task<ToriiSoraFsPinRegisterResponse> RegisterSoraFsPinManifestAsync\b.*?(?=^    public Task<HttpResponseMessage> OpenSoraFsCidContentAsync)",
        "C# signed pin-register method",
    )
    for needle, label in (
        ("SignedTransactionEnvelope transaction", "signed envelope input"),
        ("transaction.NoritoBytes", "signed Norito body"),
        ('"application/x-norito"', "Norito content type"),
        ('accept: "application/json"', "JSON negotiation"),
        ("HttpStatusCode.Accepted", "HTTP 202 admission"),
        ('fields.SetEquals(["status", "tx_hash_hex", "manifest_digest_hex"])', "closed response"),
    ):
        require(needle in method, f"C# pin-register method missing {label}")
    require(
        "NormalizeSoraFsPinRegisterRequest" not in source,
        "C# secret-bearing request normalizer remains",
    )
    models = read("csharp/src/Hyperledger.Iroha.Sdk/Torii/ToriiModels.cs")
    require(
        "ToriiSoraFsPinRegisterRequest" not in models
        and "ToriiSoraFsPinRegisterWireRequest" not in models
        and "ToriiSoraFsPinAlias" not in models,
        "C# secret-bearing pin request DTOs remain",
    )
    response = re.search(
        r"public sealed record class ToriiSoraFsPinRegisterResponse.*?^\}",
        models,
        flags=re.MULTILINE | re.DOTALL,
    )
    require(response is not None, "C# admission response model is missing")
    for retired in ("PinFee", "Custody", "ChunkerHandle", "SuccessorOf"):
        require(retired not in response.group(0), f"C# response retains retired field {retired}")
    require_contains(
        "csharp/src/Hyperledger.Iroha.Sdk/Torii/ToriiJsonSerializerContext.cs",
        "ToriiSoraFsPinRegisterResponse",
        "C# admission response JSON context",
    )
    tests = read("csharp/tests/Hyperledger.Iroha.Sdk.Tests/ToriiClientTests.cs")
    require("RegisterSoraFsPinManifestAsyncPostsOnlySignedNoritoAndReturnsAdmission" in tests, "C# signed transport test missing")
    require("RegisterSoraFsPinManifestAsyncRejectsNonAdmissionFields" in tests, "C# response guard missing")
    require('[InlineData("private_key")]' in tests, "C# secret response rejection guard missing")



def check_jvm_contract():
    kotlin_register_path = "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstruction.kt"
    kotlin_approve_path = "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/ApprovePinManifestInstruction.kt"
    kotlin_retire_path = "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/RetirePinManifestInstruction.kt"
    java_register_path = "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/RegisterPinManifestInstruction.java"
    java_approve_path = "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/ApprovePinManifestInstruction.java"
    java_retire_path = "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/RetirePinManifestInstruction.java"
    require_contains(kotlin_register_path, "RegisterPinManifestInstruction", "Kotlin paid-pin instruction")
    for path, retired_name in (
        (kotlin_register_path, "submittedEpoch"),
        (kotlin_approve_path, "approvedEpoch"),
        (kotlin_retire_path, "retiredEpoch"),
        (java_register_path, "submittedEpoch"),
        (java_approve_path, "approvedEpoch"),
        (java_retire_path, "retiredEpoch"),
    ):
        require(retired_name not in read(path), f"{path} retains caller-supplied lifecycle time")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt", "builder rejects empty invalid noncanonical and oversized manifest payloads", "Kotlin manifest-payload fail-closed test")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt", "successor digest requires nonzero canonical lowercase 32 byte hex", "Kotlin successor adversarial test")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt", "alias fields are all or nothing and bounded canonical hex", "Kotlin alias adversarial test")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt", "from arguments rejects legacy unknown and missing fields", "Kotlin first-release schema adversarial test")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt", "from arguments rejects retired caller supplied epoch", "Kotlin retired registration epoch test")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/PinManifestLifecycleInstructionTest.kt", "approval rejects retired caller supplied epoch", "Kotlin retired approval epoch test")
    require_contains("kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/PinManifestLifecycleInstructionTest.kt", "retirement rejects retired caller supplied epoch", "Kotlin retired retirement epoch test")
    require_contains(java_register_path, "RegisterPinManifest", "Java paid-pin instruction")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java", "rejectsOversizedManifestPayload();", "Java manifest size adversarial test invocation")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java", "rejectsLegacyAndUnknownArguments();", "Java first-release schema adversarial test invocation")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java", "rejectsMalformedSuccessorDigest();", "Java successor adversarial test invocation")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java", "rejectsPartialAliasBinding();", "Java alias adversarial test invocation")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java", "rejectsRetiredSubmittedEpoch();", "Java retired registration epoch test invocation")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsManifestInstructionBuilderTests.java", "approvePinManifestRejectsRetiredEpochField();", "Java retired approval epoch test invocation")
    require_contains("java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsManifestInstructionBuilderTests.java", "retirePinManifestRejectsRetiredEpochField();", "Java retired retirement epoch test invocation")


def run_checks():
    for path in required_paths:
        require((root / path).exists(), f"required file is missing: {path}")
    check_workflow()
    check_scripts()
    check_rust_wire_contract()
    check_javascript_contract()
    check_python_contract()
    check_swift_contract()
    check_csharp_contract()
    check_jvm_contract()
    print("SoraFS pin-register SDK guard: ok")


def reject_mutation(mutated_path, mutated_text, label):
    text_overrides[mutated_path] = mutated_text
    try:
        run_checks()
    except GuardError as error:
        print(f"negative control rejected {label}")
        print(str(error).splitlines()[0])
        raise SystemExit(0)
    raise SystemExit(f"negative control failed: {label} was not detected")


def workflow_mutation(old, new, label):
    original = read(workflow_path)
    mutated = original.replace(old, new, 1)
    require(mutated != original, f"negative control failed: unable to mutate {label}")
    reject_mutation(workflow_path, mutated, label)


if mode == "--negative-control-workflow-path":
    workflow_mutation('      - "javascript/iroha_js/src/toriiClient.js"\n', "", "workflow path drift")

if mode == "--negative-control-workflow-command":
    workflow_mutation(f"        run: {main_command}", f"        run: {main_command} --skip", "workflow command drift")

if mode == "--negative-control-negative-controls-workflow":
    workflow_mutation(f"          {negative_control_commands[0][1]}\n", "", "negative-control workflow drift")

if mode == "--negative-control-negative-controls-comment-workflow":
    workflow_mutation(
        f"          {negative_control_commands[0][1]}\n",
        f"          # {negative_control_commands[0][1]}\n",
        "commented negative-control workflow drift",
    )

if mode == "--negative-control-negative-controls-order-workflow":
    original = read(workflow_path)
    guard_line = f"        run: {main_command}\n"
    mutated = original.replace(guard_line, "", 1)
    insert = mutated.index("      - name: SoraFS pin-register SDK guard negative controls\n")
    mutated = mutated[:insert] + "      - name: SoraFS pin-register SDK guard\n" + guard_line + mutated[insert:]
    reject_mutation(workflow_path, mutated, "negative-control ordering drift")

if mode == "--negative-control-bytecode-workflow":
    workflow_mutation(
        "      - name: Reject tracked Python bytecode\n"
        f"        run: {bytecode_command}\n",
        "",
        "tracked Python bytecode workflow drift",
    )

if mode == "--negative-control-openapi-test-include":
    target = "crates/iroha_torii/src/openapi.rs"
    original = read(target)
    mutated = original.replace(
        '    include!("openapi/tests/sorafs_contracts.rs");',
        '    include!("openapi/tests/sorafs_contracts_disabled.rs");',
        1,
    )
    require(
        mutated != original,
        "negative control failed: unable to mutate OpenAPI split-test include",
    )
    reject_mutation(target, mutated, "OpenAPI split-test include drift")

if mode == "--negative-control-openapi-test-function":
    target = "crates/iroha_torii/src/openapi/tests/sorafs_contracts.rs"
    original = read(target)
    mutated = original.replace(
        "fn sorafs_pin_register_openapi_is_caller_signed_transaction_transport()",
        "fn sorafs_pin_register_openapi_transport_disabled()",
        1,
    )
    require(
        mutated != original,
        "negative control failed: unable to mutate OpenAPI split-test body",
    )
    reject_mutation(target, mutated, "OpenAPI split-test body drift")

if mode == "--negative-control-jvm-sdk-jdk21-script":
    target = "ci/check_sorafs_pin_register_jvm_sdk.sh"
    original = read(target)
    mutated = original.replace("java -version\n", "", 1)
    require(mutated != original, "negative control failed: unable to mutate JVM SDK JDK 21 script evidence")
    reject_mutation(target, mutated, "JVM SDK JDK 21 script drift")

if mode == "--negative-control-jvm-sdk-java-home-override-script":
    target = "ci/check_sorafs_pin_register_jvm_sdk.sh"
    original = read(target)
    mutated = original.replace(
        "SORAFS_PIN_REGISTER_JVM_SDK_JAVA_HOME",
        "SORAFS_PIN_REGISTER_JVM_SDK_JAVA_HOME_DISABLED",
        1,
    )
    require(mutated != original, "negative control failed: unable to mutate JVM SDK Java home override variable")
    reject_mutation(target, mutated, "JVM SDK Java home override drift")

if mode == "--negative-control-jvm-sdk-java-home-reject-script":
    target = "ci/check_sorafs_pin_register_jvm_sdk.sh"
    original = read(target)
    mutated = original.replace(
        "JAVA_HOME must point to a JDK 21 home for SoraFS pin-register JVM SDK tests.",
        "JAVA_HOME is not checked before fallback.",
        1,
    )
    require(mutated != original, "negative control failed: unable to mutate JVM SDK inherited Java home rejection")
    reject_mutation(target, mutated, "JVM SDK inherited Java home rejection drift")

if mode == "--negative-control-jvm-sdk-setup-order-workflow":
    original = read(workflow_path)
    run_line = f"        run: {jvm_command}\n"
    mutated = original.replace(run_line, "", 1)
    require(mutated != original, "negative control failed: unable to mutate JVM SDK setup order")
    insert = mutated.index(
        "      - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961\n"
    )
    mutated = (
        mutated[:insert]
        + "      - name: SoraFS pin-register JVM and Java SDK tests\n"
        + run_line
        + mutated[insert:]
    )
    reject_mutation(workflow_path, mutated, "JVM SDK setup ordering drift")

if mode == "--negative-control-csharp-sdk-setup-order-workflow":
    original = read(workflow_path)
    run_line = f"        run: {csharp_command}\n"
    mutated = original.replace(run_line, "", 1)
    require(mutated != original, "negative control failed: unable to mutate C# SDK setup order")
    insert = mutated.index(
        "      - uses: actions/setup-dotnet@26b0ec14cb23fa6904739307f278c14f94c95bf1\n"
    )
    mutated = (
        mutated[:insert]
        + "      - name: SoraFS pin-register C# SDK tests\n"
        + run_line
        + mutated[insert:]
    )
    reject_mutation(workflow_path, mutated, "C# SDK setup ordering drift")

if mode == "--negative-control-csharp-sdk-dotnet-version-script":
    target = "ci/check_sorafs_pin_register_csharp_sdk.sh"
    original = read(target)
    mutated = original.replace('printf \'%s\\n\' "${DOTNET_VERSION}"\n', "", 1)
    require(mutated != original, "negative control failed: unable to mutate C# SDK dotnet version evidence")
    reject_mutation(target, mutated, "C# SDK dotnet version script drift")

if mode == "--negative-control-csharp-sdk-dotnet-override-script":
    target = "ci/check_sorafs_pin_register_csharp_sdk.sh"
    original = read(target)
    mutated = original.replace("SORAFS_PIN_REGISTER_DOTNET_BIN", "SORAFS_PIN_DOTNET_BIN", 1)
    require(mutated != original, "negative control failed: unable to mutate C# SDK dotnet override variable")
    reject_mutation(target, mutated, "C# SDK dotnet override drift")

if mode == "--negative-control-csharp-sdk-dotnet-major-script":
    target = "ci/check_sorafs_pin_register_csharp_sdk.sh"
    original = read(target)
    mutated = original.replace("8.0.*) ;;", "7.0.*) ;;", 1)
    require(mutated != original, "negative control failed: unable to mutate C# SDK dotnet major matcher")
    reject_mutation(target, mutated, "C# SDK dotnet major script drift")

if mode == "--negative-control-js-sdk-node-setup-order-workflow":
    original = read(workflow_path)
    install_block = (
        "      - name: Install JavaScript SDK dependencies\n"
        f"        run: {js_install_command}\n"
    )
    mutated = original.replace(install_block, "", 1)
    require(mutated != original, "negative control failed: unable to move JavaScript SDK install before Node setup")
    insert = mutated.index(
        "      - uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38\n"
    )
    mutated = mutated[:insert] + install_block + mutated[insert:]
    reject_mutation(workflow_path, mutated, "JavaScript SDK Node setup ordering drift")

if mode == "--negative-control-python-sdk-setup-order-workflow":
    original = read(workflow_path)
    run_line = f"        run: {python_command}\n"
    mutated = original.replace(run_line, "", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK setup order")
    insert = mutated.index(
        "      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\n"
    )
    mutated = (
        mutated[:insert]
        + "      - name: SoraFS pin-register Python SDK tests\n"
        + run_line
        + mutated[insert:]
    )
    reject_mutation(workflow_path, mutated, "Python SDK setup ordering drift")

if mode == "--negative-control-python-sdk-version-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace('"${VENV_DIR}/bin/python" --version\n', "", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK version evidence")
    reject_mutation(target, mutated, "Python SDK version script drift")

if mode == "--negative-control-python-sdk-override-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace("SORAFS_PIN_REGISTER_PYTHON_BIN", "SORAFS_PIN_REGISTER_PY_BIN", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK override variable")
    reject_mutation(target, mutated, "Python SDK override drift")

if mode == "--negative-control-python-sdk-resolver-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace("resolve_python_312_bin()", "resolve_python_bin()", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK resolver")
    reject_mutation(target, mutated, "Python SDK resolver drift")

if mode == "--negative-control-python-sdk-major-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace("3.12) ;;", "3.11) ;;")
    require(mutated != original, "negative control failed: unable to mutate Python SDK major matcher")
    reject_mutation(target, mutated, "Python SDK major script drift")

if mode == "--negative-control-python-sdk-venv-rebuild-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace('  rm -rf "${VENV_DIR}"\n', "", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK stale venv rebuild")
    reject_mutation(target, mutated, "Python SDK stale venv rebuild drift")

if mode == "--negative-control-python-sdk-bytecode-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace("export PYTHONDONTWRITEBYTECODE=1\n\n", "", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK bytecode guard")
    reject_mutation(target, mutated, "Python SDK bytecode script drift")

if mode == "--negative-control-python-sdk-lock-script":
    target = "ci/check_sorafs_pin_register_python_sdk.sh"
    original = read(target)
    mutated = original.replace("  --require-hashes \\\n", "", 1)
    require(mutated != original, "negative control failed: unable to mutate Python SDK dependency lock")
    reject_mutation(target, mutated, "Python SDK dependency lock drift")

if mode == "--negative-control-swift-sdk-version-script":
    target = "ci/check_sorafs_pin_register_swift_sdk.sh"
    original = read(target)
    mutated = original.replace('"${SWIFTC_BIN}" --version\n', "", 1)
    require(mutated != original, "negative control failed: unable to mutate Swift SDK version evidence")
    reject_mutation(target, mutated, "Swift SDK version script drift")

if mode == "--negative-control-swift-sdk-override-script":
    target = "ci/check_sorafs_pin_register_swift_sdk.sh"
    original = read(target)
    mutated = original.replace("SORAFS_PIN_REGISTER_SWIFTC_BIN", "SORAFS_PIN_SWIFTC_BIN", 1)
    require(mutated != original, "negative control failed: unable to mutate Swift SDK compiler override variable")
    reject_mutation(target, mutated, "Swift SDK compiler override drift")

if mode == "--negative-control-js-sdk-node-version-script":
    target = "ci/check_sorafs_pin_register_js_sdk.sh"
    original = read(target)
    mutated = original.replace('printf \'%s\\n\' "${NODE_VERSION}"\n', "", 1)
    require(mutated != original, "negative control failed: unable to mutate JavaScript SDK Node version evidence")
    reject_mutation(target, mutated, "JavaScript SDK Node version script drift")

if mode == "--negative-control-js-sdk-node-override-script":
    target = "ci/check_sorafs_pin_register_js_sdk.sh"
    original = read(target)
    mutated = original.replace("SORAFS_PIN_REGISTER_JS_SDK_NODE_BIN", "SORAFS_PIN_REGISTER_JS_NODE_BIN", 1)
    require(mutated != original, "negative control failed: unable to mutate JavaScript SDK Node override variable")
    reject_mutation(target, mutated, "JavaScript SDK Node override drift")

if mode == "--negative-control-js-sdk-node-resolver-script":
    target = "ci/check_sorafs_pin_register_js_sdk.sh"
    original = read(target)
    mutated = original.replace("resolve_node_24_bin()", "resolve_node_bin()", 1)
    require(mutated != original, "negative control failed: unable to mutate JavaScript SDK Node resolver")
    reject_mutation(target, mutated, "JavaScript SDK Node resolver drift")

if mode == "--negative-control-js-sdk-node-major-script":
    target = "ci/check_sorafs_pin_register_js_sdk.sh"
    original = read(target)
    mutated = original.replace("v24.*) ;;", "v22.*) ;;", 1)
    require(mutated != original, "negative control failed: unable to mutate JavaScript SDK Node major matcher")
    reject_mutation(target, mutated, "JavaScript SDK Node major script drift")

workflow_modes = {
    "--negative-control-swift-sdk-job-workflow": ("  sorafs_pin_register_swift_sdk_check:\n", "  sorafs_pin_register_swift_sdk_check_disabled:\n", "Swift SDK job drift"),
    "--negative-control-swift-sdk-runner-workflow": ("  sorafs_pin_register_swift_sdk_check:\n    runs-on: macos-latest", "  sorafs_pin_register_swift_sdk_check:\n    runs-on: ubuntu-latest", "Swift SDK runner drift"),
    "--negative-control-swift-sdk-script-workflow": (f"        run: {swift_command}", "        run: bash ci/check_sorafs_pin_register_swift_sdk.sh --skip", "Swift SDK script drift"),
    "--negative-control-swift-sdk-needs-workflow": (main_job_needs_line, "    needs: [sorafs_pin_register_jvm_sdk_tests, sorafs_pin_register_csharp_sdk_tests, sorafs_pin_register_javascript_sdk_tests, sorafs_pin_register_python_sdk_tests]", "Swift SDK dependency drift"),
    "--negative-control-jvm-sdk-job-workflow": ("  sorafs_pin_register_jvm_sdk_tests:\n", "  sorafs_pin_register_jvm_sdk_tests_disabled:\n", "JVM SDK job drift"),
    "--negative-control-jvm-sdk-setup-workflow": ("      - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961\n", "", "JVM SDK setup drift"),
    "--negative-control-jvm-sdk-distribution-workflow": ('          distribution: "temurin"', '          distribution: "zulu"', "JVM SDK Java distribution drift"),
    "--negative-control-jvm-sdk-java-version-workflow": ('          java-version: "21"', '          java-version: "17"', "JVM SDK Java version drift"),
    "--negative-control-jvm-sdk-script-workflow": (f"        run: {jvm_command}", "        run: bash ci/check_sorafs_pin_register_jvm_sdk.sh --skip", "JVM SDK script drift"),
    "--negative-control-jvm-sdk-needs-workflow": (main_job_needs_line, "    needs: [sorafs_pin_register_swift_sdk_check, sorafs_pin_register_csharp_sdk_tests, sorafs_pin_register_javascript_sdk_tests, sorafs_pin_register_python_sdk_tests]", "JVM SDK dependency drift"),
    "--negative-control-csharp-sdk-job-workflow": ("  sorafs_pin_register_csharp_sdk_tests:\n", "  sorafs_pin_register_csharp_sdk_tests_disabled:\n", "C# SDK job drift"),
    "--negative-control-csharp-sdk-setup-workflow": ("      - uses: actions/setup-dotnet@26b0ec14cb23fa6904739307f278c14f94c95bf1\n", "", "C# SDK setup drift"),
    "--negative-control-csharp-sdk-dotnet-version-workflow": ("          dotnet-version: 8.0.x", "          dotnet-version: 7.0.x", "C# SDK dotnet version drift"),
    "--negative-control-csharp-sdk-script-workflow": (f"        run: {csharp_command}", "        run: bash ci/check_sorafs_pin_register_csharp_sdk.sh --skip", "C# SDK script drift"),
    "--negative-control-csharp-sdk-needs-workflow": (main_job_needs_line, "    needs: [sorafs_pin_register_swift_sdk_check, sorafs_pin_register_jvm_sdk_tests, sorafs_pin_register_javascript_sdk_tests, sorafs_pin_register_python_sdk_tests]", "C# SDK dependency drift"),
    "--negative-control-js-sdk-job-workflow": ("  sorafs_pin_register_javascript_sdk_tests:\n", "  sorafs_pin_register_javascript_sdk_tests_disabled:\n", "JavaScript SDK job drift"),
    "--negative-control-js-sdk-runner-workflow": ("  sorafs_pin_register_javascript_sdk_tests:\n    runs-on: ubuntu-latest", "  sorafs_pin_register_javascript_sdk_tests:\n    runs-on: macos-latest", "JavaScript SDK runner drift"),
    "--negative-control-js-sdk-node-setup-workflow": ("      - uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38\n", "", "JavaScript SDK Node setup drift"),
    "--negative-control-js-sdk-node-version-workflow": ('          node-version: "24"', '          node-version: "22"', "JavaScript SDK Node version drift"),
    "--negative-control-js-sdk-node-cache-workflow": ("          cache-dependency-path: javascript/iroha_js/package-lock.json", "          cache-dependency-path: javascript/iroha_js/package.json", "JavaScript SDK cache path drift"),
    "--negative-control-js-sdk-install-workflow": (f"        run: {js_install_command}", "        run: npm install --prefix javascript/iroha_js", "JavaScript SDK install drift"),
    "--negative-control-js-sdk-script-workflow": (f"        run: {js_command}", "        run: bash ci/check_sorafs_pin_register_js_sdk.sh --skip", "JavaScript SDK script drift"),
    "--negative-control-js-sdk-needs-workflow": (main_job_needs_line, "    needs: [sorafs_pin_register_swift_sdk_check, sorafs_pin_register_jvm_sdk_tests, sorafs_pin_register_csharp_sdk_tests, sorafs_pin_register_python_sdk_tests]", "JavaScript SDK dependency drift"),
    "--negative-control-python-sdk-job-workflow": ("  sorafs_pin_register_python_sdk_tests:\n", "  sorafs_pin_register_python_sdk_tests_disabled:\n", "Python SDK job drift"),
    "--negative-control-python-sdk-setup-workflow": ("      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\n", "", "Python SDK setup drift"),
    "--negative-control-python-sdk-version-workflow": ('          python-version: "3.12"', '          python-version: "3.11"', "Python SDK version drift"),
    "--negative-control-python-sdk-script-workflow": (f"        run: {python_command}", "        run: bash ci/check_sorafs_pin_register_python_sdk.sh --skip", "Python SDK script drift"),
    "--negative-control-python-sdk-needs-workflow": (main_job_needs_line, "    needs: [sorafs_pin_register_swift_sdk_check, sorafs_pin_register_jvm_sdk_tests, sorafs_pin_register_csharp_sdk_tests, sorafs_pin_register_javascript_sdk_tests]", "Python SDK dependency drift"),
}

if mode == "--negative-control-js-sdk-install-order-workflow":
    original = read(workflow_path)
    install_line = f"      - name: Install JavaScript SDK dependencies\n        run: {js_install_command}\n"
    mutated = original.replace(install_line, "", 1)
    mutated = mutated.replace(
        f"        run: {js_command}\n",
        f"        run: {js_command}\n" + install_line,
        1,
    )
    reject_mutation(workflow_path, mutated, "JavaScript SDK install ordering drift")

if mode == "--negative-control-js-sdk-test-order-workflow":
    original = read(workflow_path)
    test_line = f"      - name: SoraFS pin-register JavaScript SDK tests\n        run: {js_command}\n"
    mutated = original.replace(test_line, "", 1)
    mutated = mutated.replace(
        f"        run: {main_command}\n",
        f"        run: {main_command}\n" + test_line,
        1,
    )
    reject_mutation(workflow_path, mutated, "JavaScript SDK test ordering drift")

if mode in workflow_modes:
    old, new, label = workflow_modes[mode]
    workflow_mutation(old, new, label)

source_modes = {
    "--negative-control-rust-client-dual-manifest-source": (
        "crates/iroha/src/client.rs",
        "    pub manifest_payload: &'a [u8],\n",
        "    pub manifest_payload: &'a [u8],\n"
        "    pub manifest_bytes: Option<&'a [u8]>,\n",
        "Rust client dual manifest source drift",
    ),
    "--negative-control-rust-client-submitted-epoch": (
        "crates/iroha/src/client.rs",
        "    pub manifest_payload: &'a [u8],\n",
        "    pub manifest_payload: &'a [u8],\n"
        "    pub submitted_epoch: u64,\n",
        "Rust client retired submitted-epoch drift",
    ),
    "--negative-control-rust-client-manifest-b64-wire": (
        "crates/iroha/src/client.rs",
        '            "manifest_payload".into(),\n',
        '            "manifest_b64".into(),\n',
        "Rust client retired manifest_b64 wire key drift",
    ),
    "--negative-control-rust-client-manifest-bound": (
        "crates/iroha/src/client.rs",
        "manifest_payload.len() > sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES",
        "manifest_payload.len() > usize::MAX",
        "Rust client manifest bound drift",
    ),
    "--negative-control-rust-client-canonical-decode": (
        "crates/iroha/src/client.rs",
        "sorafs_manifest::decode_manifest_v1_canonical(manifest_payload)",
        "norito::decode_from_bytes(manifest_payload)",
        "Rust client canonical manifest decode drift",
    ),
    "--negative-control-rust-client-retired-helper": (
        "crates/iroha/src/client.rs",
        "    fn validate_sorafs_pin_register_manifest_payload(manifest_payload: &[u8]) -> Result<()> {\n",
        "    fn sorafs_pin_register_manifest_bytes(manifest_payload: &[u8]) -> &[u8] {\n"
        "        manifest_payload\n"
        "    }\n\n"
        "    fn validate_sorafs_pin_register_manifest_payload(manifest_payload: &[u8]) -> Result<()> {\n",
        "Rust client retired dual-source helper drift",
    ),
    "--negative-control-torii-retired-manifest-b64": (
        "crates/iroha_torii/src/routing.rs",
        "    pub manifest_payload: String,\n",
        "    pub manifest_payload: String,\n"
        "    pub manifest_b64: Option<String>,\n",
        "Torii retired manifest_b64 field drift",
    ),
    "--negative-control-torii-retired-summary-field": (
        "crates/iroha_torii/src/routing.rs",
        "    pub submitted_epoch: u64,\n",
        "    pub submitted_epoch: u64,\n"
        "    pub content_length: u64,\n",
        "Torii retired summary field drift",
    ),
    "--negative-control-torii-manifest-bound": (
        "crates/iroha_torii/src/routing.rs",
        "manifest_payload.len() > SORAFS_PIN_MANIFEST_MAX_BASE64_BYTES",
        "manifest_payload.len() > usize::MAX",
        "Torii encoded manifest bound drift",
    ),
    "--negative-control-torii-canonical-decode": (
        "crates/iroha_torii/src/routing.rs",
        "sorafs_manifest::decode_manifest_v1_canonical(&manifest_bytes)",
        "norito::decode_from_bytes(&manifest_bytes)",
        "Torii canonical manifest decode drift",
    ),
    "--negative-control-torii-retired-helper": (
        "crates/iroha_torii/src/routing.rs",
        "#[cfg(feature = \"app_api\")]\nfn decode_sorafs_pin_manifest_payload(\n",
        "#[cfg(feature = \"app_api\")]\n"
        "fn validate_manifest_payload_matches_request() {}\n\n"
        "#[cfg(feature = \"app_api\")]\n"
        "fn decode_sorafs_pin_manifest_payload(\n",
        "Torii retired manifest matching helper drift",
    ),
    "--negative-control-python-fee-payment-field": (
        "python/iroha_python/src/iroha_python/client.py",
        '        transaction: "SignedTransactionEnvelope",\n',
        '        transaction: "SignedTransactionEnvelope",\n'
        "        fee_payment: object | None = None,\n",
        "Python retired fee_payment field drift",
    ),
    "--negative-control-js-source-endpoint": (
        "javascript/iroha_js/src/toriiClient.js",
        '"/v1/sorafs/pin/register"',
        '"/v1/sorafs/pin/register-disabled"',
        "JavaScript source endpoint drift",
    ),
    "--negative-control-js-adversarial-test": (
        "javascript/iroha_js/test/toriiClient.test.js",
        "registerSorafsPinManifest rejects all unknown and retired fields before fetch",
        "registerSorafsPinManifest unknown-field test disabled",
        "JavaScript adversarial test drift",
    ),
    "--negative-control-python-adversarial-test": (
        "python/iroha_python/tests/client_sorafs_pin_register_test.py",
        "test_pin_register_rejects_pre_finality_fee_claim",
        "test_pin_register_pre_finality_fee_claim_disabled",
        "Python adversarial test drift",
    ),
    "--negative-control-swift-contract-test": (
        "IrohaSwift/Tests/IrohaSwiftTests/ToriiClientTests.swift",
        "testRegisterSoraFsPinManifestRejectsMalformedInputsBeforeRequest",
        "testRegisterSoraFsPinManifestRejectsMalformedInputsDisabled",
        "Swift contract test drift",
    ),
    "--negative-control-swift-retired-request-field": (
        "IrohaSwift/Sources/IrohaSwift/ToriiClient.swift",
        "    public var manifestPayload: String?\n",
        "    public var manifestPayload: String?\n    public var manifest_b64: String?\n",
        "Swift retired request field drift",
    ),
    "--negative-control-csharp-malformed-response-test": (
        "csharp/tests/Hyperledger.Iroha.Sdk.Tests/ToriiClientTests.cs",
        "RegisterSoraFsPinManifestAsyncRejectsMalformedDigestResponse",
        "RegisterSoraFsPinManifestAsyncMalformedResponseDisabled",
        "C# malformed response test drift",
    ),
    "--negative-control-kotlin-builder-test": (
        "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt",
        "builder rejects empty invalid noncanonical and oversized manifest payloads",
        "builder manifest payload test disabled",
        "Kotlin builder test drift",
    ),
    "--negative-control-kotlin-successor-digest-test": (
        "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstructionTest.kt",
        "successor digest requires nonzero canonical lowercase 32 byte hex",
        "successor canonicality test disabled",
        "Kotlin successor canonicality test drift",
    ),
    "--negative-control-java-builder-test": (
        "java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java",
        "rejectsLegacyAndUnknownArguments();",
        "rejectsLegacyAndUnknownArgumentsDisabled();",
        "Java builder test drift",
    ),
    "--negative-control-java-successor-digest-test": (
        "java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsRegisterPinManifestBuilderTests.java",
        "rejectsMalformedSuccessorDigest();",
        "rejectsMalformedSuccessorDigestDisabled();",
        "Java successor canonicality test drift",
    ),
    "--negative-control-js-submitted-epoch-type": (
        "javascript/iroha_js/index.d.ts",
        "  manifestPayload: Buffer | ArrayBuffer | ArrayBufferView;\n",
        "  manifestPayload: Buffer | ArrayBuffer | ArrayBufferView;\n"
        "  submittedEpoch: NumericLike;\n",
        "JavaScript retired submitted-epoch type drift",
    ),
    "--negative-control-kotlin-submitted-epoch-model": (
        "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/RegisterPinManifestInstruction.kt",
        "    @JvmField val manifestPayloadBase64: String,\n",
        "    @JvmField val manifestPayloadBase64: String,\n"
        "    @JvmField val submittedEpoch: Long,\n",
        "Kotlin retired submitted-epoch model drift",
    ),
    "--negative-control-java-submitted-epoch-model": (
        "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/RegisterPinManifestInstruction.java",
        "  private final String manifestPayloadBase64;\n",
        "  private final String manifestPayloadBase64;\n"
        "  private final long submittedEpoch;\n",
        "Java retired submitted-epoch model drift",
    ),
}

if mode in source_modes:
    path, old, new, label = source_modes[mode]
    original = read(path)
    mutated = original.replace(old, new, 1)
    require(mutated != original, f"negative control failed: unable to mutate {label}")
    reject_mutation(path, mutated, label)

if mode:
    raise SystemExit(f"unknown mode: {mode}")

try:
    run_checks()
except GuardError as error:
    raise SystemExit(f"error: {error}") from error
PY
