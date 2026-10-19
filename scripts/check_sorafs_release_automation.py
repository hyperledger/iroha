#!/usr/bin/env python3
"""Validate the committed SoraFS release and conformance workflow contracts."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_sorafs_release_version_map import (  # noqa: E402
    _read_bytes_no_follow,
    _require_regular_repo_file,
)
from sorafs_evidence_json import load_evidence_json


SCHEMA = "sorafs.release.automation.v1"
REQUIRED_RELEASE_SIGNING_PROVIDER = "authenticated_external_signer"
RELEASE_TARGET_RUNNERS: tuple[tuple[str, str], ...] = (
    ("ubuntu-24.04", "x86_64-unknown-linux-gnu"),
    ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
    ("macos-15-intel", "x86_64-apple-darwin"),
    ("macos-14", "aarch64-apple-darwin"),
    ("windows-latest", "x86_64-pc-windows-msvc"),
)
SUPPLY_CHAIN_SOURCE_TARGETS: tuple[str, ...] = (
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
)
RELEASE_DOCUMENTS: dict[str, tuple[str, ...]] = {
    "specs/sorafs/runbooks/index.md": (
        "[Release rollback and yank](./release_rollback_yank.md)",
    ),
    "specs/sorafs_release_pipeline_plan.md": (
        "builds native Linux x86_64/aarch64",
        "executes all three binaries from each clean extraction",
        "`scripts/package_sorafs_cli_candidate.py` assembles the whole platform",
        "exactly the five expected target-triple checksum manifests",
        "The five-target CLI archive implementation is present. Its hosted-run",
        "build, publish, and clean-install all six",
        "`specs/sorafs/runbooks/release_rollback_yank.md`",
        "`sorafs-release-authentication` environment",
        "`scripts/release_manifest_signing.py verify`",
        "never receives a private key or invokes a signer",
        REQUIRED_RELEASE_SIGNING_PROVIDER,
    ),
    "specs/sorafs/runbooks/release_rollback_yank.md": (
        "# SoraFS Release Rollback and Yank",
        "`cargo yank --vers <version> <crate>`",
        "npm deprecate <package>@<version>",
        "Python/PyPI",
        "C#/NuGet",
        "JVM/Android",
        "Swift Package Manager",
        "GitHub CLI artifacts",
        "`withdrawn`, `not_published`, or `failed`",
        "Never reuse a withdrawn version",
    ),
    "specs/sorafs/developer/releases.md": (
        "sorafs-cli-vX.Y.Z",
        "all five native candidate archives",
        "[SoraFS Release Rollback and Yank](../runbooks/release_rollback_yank.md)",
        "`SORAFS_RELEASE_MANIFEST_VERIFIER_PATH`",
        "No private key or signing operation",
        REQUIRED_RELEASE_SIGNING_PROVIDER,
    ),
    "fixtures/documentation/sorafs_release_notes.md": (
        "## Rollback / Yank Record",
        "every package row in `release/version-map.toml`",
        "`<withdrawn | not_published | failed>`",
    ),
}
FORBIDDEN_RELEASE_DOCUMENT_CLAIMS: dict[str, tuple[str, ...]] = {
    "specs/sorafs_release_pipeline_plan.md": (
        "via cross",
        "exactly the three expected platform checksum manifests",
    ),
    "specs/sorafs/developer/releases.md": (
        "git tag -s sorafs-v",
        "invokes the script above",
    ),
}
RELEASE_AUTH_ROOT_DOCUMENTS: tuple[str, ...] = (
    "CHANGELOG.md",
    "roadmap.md",
    "status.md",
)
RELEASE_AUTH_DOCUMENT_EXTENSIONS = frozenset({".md", ".mdx", ".org"})
RELEASE_AUTH_IGNORED_DIRECTORY_NAMES = frozenset({"node_modules"})
MAX_RELEASE_AUTH_TREE_ENTRIES = 65_536
MAX_RELEASE_AUTH_TREE_DEPTH = 16
MAX_RELEASE_AUTH_DOCUMENTS = 60_000
RELEASE_AUTH_FORBIDDEN_PATTERNS: tuple[
    tuple[str, tuple[tuple[str, ...], ...], re.Pattern[str]], ...
] = (
    (
        "retired local manifest-authentication command",
        (("sorafs_cli",), ("manifest",)),
        re.compile(
            r"\bsorafs_cli(?:\.exe)?\s+manifest\s+"
            r"(?:sign|verify-signature)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "retired identity-token signing option",
        (("--identity-token-",),),
        re.compile(
            r"--identity-token-(?:provider|audience|env|file)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "retired ci_sample authentication artifact",
        (("fixtures/sorafs_manifest/ci_sample/manifest.",),),
        re.compile(
            r"fixtures/sorafs_manifest/ci_sample/manifest\."
            r"(?:bundle\.json|sig|sign\.summary\.json|verify\.summary\.json)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "retired local manifest-authentication artifact",
        (("manifest.",),),
        re.compile(
            r"\bmanifest\."
            r"(?:bundle\.json|sign\.summary\.json|verify\.summary\.json)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "generic OpenSSL/RSA signing command",
        (("openssl",), ("-sign", "genrsa", "genpkey")),
        re.compile(
            r"(?m)^[^\n]*\bopenssl[a-z0-9_]*\b(?:\.exe)?[^\n]*"
            r"(?:\bgenrsa\b|\bgenpkey\b|(?:^|\s)-sign(?:=|\s|$))[^\n]*$",
            re.IGNORECASE,
        ),
    ),
    (
        "OIDC-derived local Ed25519 signing material",
        (
            ("oidc", "jwt", "identity token", "identity-token"),
            ("deriv", "seed", "ephemeral"),
            ("ed25519", "key"),
        ),
        re.compile(
            r"(?m)^[^\n]*(?:"
            r"(?:oidc|jwt|identity[ -]?token)[^\n]{0,200}"
            r"(?:deriv(?:e|ed|ation)|seed|ephemeral)[^\n]{0,200}"
            r"(?:ed25519|key)"
            r"|"
            r"(?:deriv(?:e|ed|ation)|seed)[^\n]{0,200}"
            r"(?:ed25519|key)[^\n]{0,200}"
            r"(?:oidc|jwt|identity[ -]?token)"
            r")[^\n]*$",
            re.IGNORECASE,
        ),
    ),
)
RELEASE_AUTH_HISTORICAL_FINDINGS: dict[str, tuple[str, ...]] = {
    "specs/sorafs/reports/sf6_security_review.md": (
        "The retired CLI path derived an ephemeral key from unverified OIDC token bytes",
        "Removed that CLI surface and all production callers",
    ),
}
PACKAGE_RELEASE_SMOKE_SCRIPT = "python/iroha_python/scripts/release_smoke.sh"
PACKAGE_RELEASE_SMOKE_REQUIRED_MARKERS: tuple[str, ...] = (
    'PYTHON_RELEASE_SMOKE_KEEP_DIST',
    'python -m build',
    'pip install "${WHEEL}"',
    'assert hasattr(sdk, "ToriiClient")',
    'python/iroha_python/scripts/run_norito_rpc_smoke.sh',
    'python -m twine check',
    '--dry-run',
    'scripts/release_manifest_signing.py',
)
PACKAGE_RELEASE_SMOKE_FORBIDDEN_MARKERS: tuple[str, ...] = (
    "openssl",
    "cosign",
    ".sigstore",
    "--signing-key",
    "--manifest-out",
    "--require-sigstore",
    "--skip-sigstore",
    "--sigstore-token-env",
    "--cosign-bin",
    "PYTHON_RELEASE_SIGNING_KEY",
    "PYTHON_RELEASE_SIGSTORE",
    "SIGSTORE_ID_TOKEN",
    "release_artifacts.json",
    "CHANGELOG_PREVIEW.md",
    "SHA256SUMS",
    "sign-blob",
)
REFERENCE_SDK_RELEASE_EXAMPLE_REQUIRED_MARKERS: dict[str, tuple[str, ...]] = {
    "scripts/examples/sorafs_reference_sdk_release_supply_chain_canary.args.example": (
        "--kind\nsupply_chain",
        "--supply-chain-source-root",
        "--provenance-certificate-identity",
        "--provenance-oidc-issuer",
        "--provenance-verification-public-key-hex",
    ),
    "scripts/examples/sorafs_reference_sdk_release_collection.args.example": (
        "--require-kind release_archive,signed_manifest,supply_chain,"
        "downstream_bindings,cookbook_smoke,ffi_header_contract,"
        "governance_approval",
        "--supply-chain-source-root",
        "--provenance-certificate-identity",
        "--provenance-oidc-issuer",
        "--provenance-verification-public-key-hex",
        "--signed-manifest-source-context",
        "--signed-manifest-source-context-sha256",
    ),
    "scripts/examples/sorafs_reference_sdk_release_evidence.args.example": (
        "--require-kind release_archive,signed_manifest,supply_chain,"
        "downstream_bindings,cookbook_smoke,ffi_header_contract,"
        "governance_approval",
        "--supply-chain-source-root",
        "--provenance-certificate-identity",
        "--provenance-oidc-issuer",
        "--provenance-verification-public-key-hex",
        "--signed-manifest-source-context",
        "--signed-manifest-source-context-sha256",
    ),
    "scripts/examples/sorafs_reference_sdk_release_signed_manifest_canary.args.example": (
        "--kind\nsigned_manifest", "--signed-manifest-source-context",
        "--signed-manifest-source-context-sha256",
    ),
    "scripts/examples/sorafs_reference_sdk_signed_manifest_canary.args.example": (
        "--kind\nsigned_manifest", "--signed-manifest-source-context",
        "--signed-manifest-source-context-sha256",
    ),
}
REFERENCE_SDK_RELEASE_EXAMPLE_FORBIDDEN_MARKERS: dict[str, tuple[str, ...]] = {
    **{
        f"scripts/examples/{name}": (
            "--manifest-digest-hex", "--policy-digest-hex", "--public-key-fingerprint-hex",
            "--signature-algorithm", "--signing-provider", "--signing-backend",
        )
        for name in (
            "sorafs_reference_sdk_release_signed_manifest_canary.args.example",
            "sorafs_reference_sdk_signed_manifest_canary.args.example",
        )
    },
    "scripts/examples/sorafs_reference_sdk_release_supply_chain_canary.args.example": (
        "--target",
        "--sbom-index-digest-hex",
        "--vulnerability-report-digest-hex",
        "--provenance-bundle-digest-hex",
    ),
}
GENERIC_OPENSSL_SIGNER_RE = re.compile(
    r"(?m)^[^\n]*\bopenssl[a-z0-9_]*\b(?:\.exe)?[^\n]*"
    r"(?:\bgenrsa\b|\bgenpkey\b|(?:^|\s)-sign(?:=|\s|$))[^\n]*$",
    re.IGNORECASE,
)
RUNTIME_PROVIDER_RELEASE_WORKFLOW_MARKERS: tuple[str, ...] = (
    '- "scripts/check_runtime_provider_broker_install.py"',
    '- "scripts/tests/check_runtime_provider_broker_install_test.py"',
    '- "configs/sorafs/runtime_provider_broker/**"',
    '- "crates/irohad/src/runtime_provider_broker.rs"',
    '- "crates/irohad/src/runtime_provider_broker/**"',
    '- "crates/irohad/src/sorafs_pop_runtime.rs"',
    "name: Validate SoraFS CLI source integrity and runtime-provider broker deployment",
    "run: bash ci/check_sorafs_cli_release.sh",
)
POP_BROKER_OPERATION_IDS: dict[str, int] = {
    "OPERATION_POP_RUNTIME_OPEN_V1": 60,
    "OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1": 117,
    "OPERATION_POP_WALLET_RECIPIENT_OPEN_V1": 118,
}
POP_BROKER_RETIRED_SECRET_MARKERS: tuple[str, ...] = (
    "PopRuntimeResolveResultWireV1",
    "PopCredentialRuntimeSecretsV1",
    "enrollment_recipient_secret",
    "wallet_recipient_secret",
)
POP_BROKER_WIRE_FIELD_INVENTORIES: dict[str, tuple[tuple[str, str], ...]] = {
    "PopRuntimeOpenResultWireV1": (
        ("issuer_signer_handle", "String"),
        ("issuer_public_key", "[u8;32]"),
        ("enrollment_recipient_key_id", "String"),
        ("enrollment_recipient_public_key_digest", "[u8;32]"),
        ("wallet_recipient_key_id", "String"),
        ("wallet_recipient_public_key_digest", "[u8;32]"),
        ("wallet_wrapping_key_id", "String"),
    ),
    "PopRecipientOpenRequestWireV1": (
        (
            "encrypted_payload",
            "sorafs_manifest::hybrid_envelope::HybridPayloadEnvelopeV1",
        ),
        ("aad", "Vec<u8>"),
    ),
    "PopRecipientOpenResultWireV1": (("plaintext", "Vec<u8>"),),
    "PopCredentialRuntimeBindingWireV1": (
        ("issuer_policy_digest", "[u8;32]"),
        ("issuer_id", "String"),
        ("issuer_signer_handle", "String"),
        ("issuer_public_key", "[u8;32]"),
        ("enrollment_recipient_key_id", "String"),
        ("enrollment_recipient_public_key_digest", "[u8;32]"),
        ("wallet_recipient_key_id", "String"),
        ("wallet_recipient_public_key_digest", "[u8;32]"),
        ("wallet_wrapping_key_id", "String"),
    ),
}
RUNTIME_PROVIDER_DEPLOYMENT_ASSET_MARKERS: dict[str, tuple[str, ...]] = {
    "configs/sorafs/runtime_provider_broker/README.md": (
        "it does not supply a concrete signing backend,",
        "statically link a reviewed deployment-owned",
        "Do not add credential, private-key, token, plugin, or test-provider arguments.",
        "The expected executable digest must come",
        "The checked-in Linux Governance DAG consumer dependency is mandatory",
        "/run/iroha-runtime-provider-broker-v1/runtime-provider-broker-v1.sock",
        "/private/var/iroha/run/runtime-provider-broker-v1.sock",
        "mode-0600 instance lock",
    ),
    (
        "configs/sorafs/runtime_provider_broker/systemd/"
        "iroha-runtime-provider-broker-v1.service"
    ): (
        "Type=notify",
        "NotifyAccess=main",
        "User=iroha",
        "Group=iroha",
        "RuntimeDirectory=iroha-runtime-provider-broker-v1",
        "RuntimeDirectoryMode=0700",
        "RuntimeDirectoryPreserve=no",
        "ReadWritePaths=/run/iroha-runtime-provider-broker-v1",
        "LimitCORE=0",
        (
            "ExecStart=/usr/local/libexec/iroha-runtime-provider-broker-v1 "
            "--catalog /etc/iroha/runtime-provider-broker/catalog.norito "
            "--broker-policy /etc/iroha/runtime-provider-broker/policy.toml"
        ),
    ),
    (
        "configs/sorafs/runtime_provider_broker/systemd/"
        "sorafs-governance-dag@.service.d/"
        "20-runtime-provider-broker-v1.conf"
    ): (
        "Requires=iroha-runtime-provider-broker-v1.service",
        "After=iroha-runtime-provider-broker-v1.service",
        "User=iroha",
        "Group=iroha",
        "ReadOnlyPaths=/run/iroha-runtime-provider-broker-v1",
    ),
    (
        "configs/sorafs/runtime_provider_broker/launchd/"
        "org.hyperledger.iroha.runtime-provider-broker-v1.plist"
    ): (
        "org.hyperledger.iroha.runtime-provider-broker-v1",
        "/usr/local/libexec/iroha-runtime-provider-broker-v1",
        "/private/etc/iroha/runtime-provider-broker/catalog.norito",
        "<string>--broker-policy</string>",
        "/private/etc/iroha/runtime-provider-broker/policy.toml",
        "<key>UserName</key>",
        "<key>GroupName</key>",
        "<key>SoftResourceLimits</key>\n  <dict>\n    <key>Core</key>",
        "<key>HardResourceLimits</key>\n  <dict>\n    <key>Core</key>",
    ),
    "scripts/check_runtime_provider_broker_install.py": (
        "supervisor_template: PurePosixPath",
        "consumer_assets: tuple[tuple[PurePosixPath, PurePosixPath], ...]",
        "checked-in runtime-provider supervisor template",
        "BROKER_EXECUTABLE_MAX_BYTES_V1",
        "BROKER_POLICY_MAX_BYTES_V1",
        "def _check_broker_policy(",
        "observer_operation_timeout_ms",
        "_sha256_regular_bounded",
        "externally verified release digest",
        "stat.S_IMODE(info.st_mode) & 0o7222",
        "installed runtime-provider consumer drop-in",
        "checked-in platform template",
        "trusted_artifact_owner_uid=0",
        "--expected-catalog",
        "--expected-executable-sha256",
        'layout.platform == "macos"',
        "/private/var/iroha/run/runtime-provider-broker-v1.sock",
    ),
    "scripts/tests/check_runtime_provider_broker_install_test.py": (
        "test_supervisor_asset_is_required",
        "test_supervisor_asset_must_not_be_a_symlink",
        "test_supervisor_asset_must_have_one_hard_link",
        "test_supervisor_asset_rejects_unsafe_permissions",
        "test_supervisor_asset_rejects_untrusted_owner",
        "test_supervisor_asset_must_match_checked_in_template",
        "test_supervisor_asset_race_is_rejected",
        "test_macos_runtime_directory_is_unconditional",
        "test_executable_digest_must_match_external_release_identity",
        "test_executable_digest_must_be_canonical_nonzero_lowercase",
        "test_executable_race_is_rejected",
        "test_consumer_drop_ins_are_required_and_exact",
        "test_consumer_drop_in_hardlink_is_rejected",
    ),
    "crates/irohad/src/runtime_provider_broker.rs": (
        "mod api;",
        "mod launcher;",
        'include!("runtime_provider_broker/protocol.rs");',
    ),
    "crates/iroha_config/src/parameters/defaults.rs": (
        "/run/iroha-runtime-provider-broker-v1/runtime-provider-broker-v1.sock",
        "/private/var/iroha/run/runtime-provider-broker-v1.sock",
    ),
    "crates/irohad/src/runtime_provider_broker/platform.rs": (
        'include!("platform_server_qualification.rs");',
        'include!("pop_recipient_client.rs");',
    ),
    "crates/irohad/src/runtime_provider_broker/platform_server_qualification.rs": (
        "EndpointPolicy",
        "if policy.verify_all_ancestors {",
        "verify_directory(ancestor, policy.expected_service_uid, true)?;",
    ),
    "crates/irohad/src/runtime_provider_broker/platform_server_transport.rs": (
        "endpoint_recovery::prepare_endpoint",
    ),
    "crates/irohad/src/runtime_provider_broker/platform_operation_dispatch.rs": (
        "OPERATION_POP_RUNTIME_OPEN_V1",
        "OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1",
        "OPERATION_POP_WALLET_RECIPIENT_OPEN_V1",
    ),
    "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs": (
        "OPERATION_POP_RUNTIME_OPEN_V1: u16 = 60",
        "OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1: u16 = 117",
        "OPERATION_POP_WALLET_RECIPIENT_OPEN_V1: u16 = 118",
        "PopRuntimeOpenResultWireV1 {",
        "PopRecipientOpenRequestWireV1 {",
        "PopRecipientOpenResultWireV1 {",
        "PopCredentialRuntimeBindingWireV1 {",
    ),
    "crates/irohad/src/runtime_provider_broker/validate_operation_payload.rs": (
        "OPERATION_POP_RUNTIME_OPEN_V1",
        "OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1",
        "OPERATION_POP_WALLET_RECIPIENT_OPEN_V1",
        "validate_pop_recipient_open_request(&open, request.operation)",
    ),
    "crates/irohad/src/runtime_provider_broker/pop_recipient_client.rs": (
        "OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1",
        "OPERATION_POP_WALLET_RECIPIENT_OPEN_V1",
        "PopRecipientOpenRequestWireV1",
        "PopRecipientOpenResultWireV1",
        '.field("private_recipient", &"[REMOTE]")',
    ),
    "crates/irohad/src/sorafs_pop_runtime.rs": (
        "production_builder_has_no_secret_or_fallback_source",
        "provider material remains behind the deployment-supplied registry.",
    ),
    "crates/irohad/src/runtime_provider_broker/launcher.rs": (
        "trusted_runtime_provider_catalog_owner_uid_v1",
        "load_runtime_provider_broker_policy_file_v1",
        "read_runtime_provider_broker_public_file_on_unix_v1",
        "RUNTIME_PROVIDER_BROKER_POLICY_MAX_BYTES_V1",
        "changed_seconds: metadata.ctime()",
        "changed_nanoseconds: metadata.ctime_nsec()",
        "before.owner != trusted_owner_uid",
        "before.mode & 0o7222",
    ),
    "crates/irohad/src/runtime_provider_broker/protocol/platform/endpoint_recovery.rs": (
        "NonBlockingLockExclusive",
        "marker_preexisted: bool",
        "create_lock_exclusively(parent_directory)",
        "if !guard.marker_preexisted",
        "remove_exact_socket_entry_inner",
        "rename_to_quarantine",
        "rustix::fs::RenameFlags::NOREPLACE",
        "metadata.st_nlink == 1",
    ),
    "crates/irohad/src/runtime_provider_broker/server_source_tests.rs": (
        "broker_server_preserves_active_listener_without_lock_or_readiness",
        "broker_server_recovers_exact_stale_socket_after_unclean_exit",
        "broker_server_rejects_active_locked_socket_without_unlinking_it",
        "stale_socket_recovery_detects_identity_substitution_before_unlink",
        "orderly_cleanup_quarantines_before_detecting_identity_substitution",
        "broker_endpoint_rejects_socket_hardlink_alias_without_removal",
    ),
}
RUNTIME_PROVIDER_DEPLOYMENT_FORBIDDEN_MARKERS: dict[str, tuple[str, ...]] = {
    (
        "configs/sorafs/runtime_provider_broker/systemd/"
        "iroha-runtime-provider-broker-v1.service"
    ): (
        "Environment=",
        "EnvironmentFile=",
        "--socket",
        "--plugin",
        "--private-key",
        "--credential",
    ),
    (
        "configs/sorafs/runtime_provider_broker/launchd/"
        "org.hyperledger.iroha.runtime-provider-broker-v1.plist"
    ): (
        "EnvironmentVariables",
        "--socket",
        "--plugin",
        "--private-key",
        "--credential",
    ),
    "scripts/check_runtime_provider_broker_install.py": (
        "--socket",
        "--plugin",
        "--private-key",
        "--credential",
    ),
    "crates/irohad/src/runtime_provider_broker.rs": (
        "OPERATION_POP_RUNTIME_RESOLVE_V1",
        "HybridSecretKey",
        *POP_BROKER_RETIRED_SECRET_MARKERS,
    ),
    "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs": (
        "OPERATION_POP_RUNTIME_RESOLVE_V1",
        "HybridSecretKey",
        *POP_BROKER_RETIRED_SECRET_MARKERS,
    ),
    "crates/irohad/src/runtime_provider_broker/validate_operation_payload.rs": (
        "OPERATION_POP_RUNTIME_RESOLVE_V1",
        "HybridSecretKey",
        *POP_BROKER_RETIRED_SECRET_MARKERS,
    ),
    "crates/irohad/src/runtime_provider_broker/pop_recipient_client.rs": (
        "OPERATION_POP_RUNTIME_RESOLVE_V1",
        "HybridSecretKey",
        ".secret()",
        "recipient_private_key",
        "recipient_secret",
        *POP_BROKER_RETIRED_SECRET_MARKERS,
    ),
}
SORAFS_CLI_RELEASE_GATE_SCRIPT = "ci/check_sorafs_cli_release.sh"
SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT = "ci/check_sorafs_native_authority_runtime.sh"
SORAFS_NATIVE_AUTHORITY_RUNTIME_TEST = "scripts/tests/sorafs_native_authority_runtime_test.py"
SORAFS_SIGNER_CONTRACT_LIBRARIES = (
    "sorafs_manifest", "iroha_data_model", "iroha_executor_data_model", "iroha_schema_gen",
)
SORAFS_SIGNER_CONTRACT_COMMAND = (
    "cargo test --locked "
    + " ".join(f"-p {package}" for package in SORAFS_SIGNER_CONTRACT_LIBRARIES)
    + " --lib"
)
SORAFS_NATIVE_AUTHORITY_PACKAGES = ("iroha_core", "iroha_torii", "irohad", "irohad_lib", "iroha_sccp")
SORAFS_NATIVE_AUTHORITY_FILTERS = (
    "final_promotion", "signer_finality", "sorafs::token::", "signer_operation",
    "signer_custody_history", "signer_check",
    "native_finality_tests::",
    "native_transaction_signer", "external_software_signer",
    "runtime_provider_broker", "runtime_provider_registry",
    "stream_token_custody",
    "validation_fee::tests::newly_dispatchable_native_instruction_fails_until_explicitly_classified",
    "validation_fee::tests::custom_instruction_without_effect_disposition_fails_closed",
    "kura::tests::progress_witness_durability::bound_progress_pair_uses_each_file_directory_snapshot",
)
SORAFS_NATIVE_AUTHORITY_SENTINELS = (
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::check_tests::account_check_repeats_without_history_or_key_index_writes",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::check_tests::account_check_requires_observer_inequality_even_with_both_exact_permissions",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::check_tests::account_check_rechecks_both_account_roles_and_permissions_after_same_block_changes",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::check_tests::account_check_then_revoke_rejects_old_or_fresh_cas_at_current_cut",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::check_tests::account_check_rejects_time_before_native_enrollment_even_after_signed_issuance",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::check_tests::account_check_rejects_noncheck_binding_and_oversized_instruction_at_applied_cut",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::history_tests::account_configuration_requires_exact_native_manager_even_at_genesis_and_cas_on_retry",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::history_tests::account_configuration_rejects_foreign_role_purpose_network_and_malformed_handles",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::history_tests::account_configuration_and_enrollment_accept_operator_selected_signer_handles",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::history_tests::account_enrollment_and_check_require_committed_control_predecessors",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::history_tests::account_history_rejects_missing_or_substituted_head_record_height_and_first_use_indexes",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::history_tests::account_rotation_preserves_first_use_indexes_and_rejects_retired_signer_or_attester_reuse",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::capacity::account_normal_capacity_preserves_two_emergency_revocations_without_publishing",
    "smartcontracts::isi::sorafs_final_promotion_account_custody::tests::capacity::account_preparation_rejects_immutable_collisions_without_publishing_earlier_writes",
    "executor::tests::final_promotion_account_permission_tests::native_account_custody_requires_exact_action_and_deployment_even_at_genesis",
    "executor::tests::final_promotion_account_permission_tests::native_account_custody_direct_and_role_delegation_cannot_expand_action_or_deployment",
    "executor::tests::final_promotion_account_permission_tests::account_custody_self_observation_and_receipt_permissions_fail_closed",
    "validation_fee::tests::final_promotion_account_custody_actions_remain_available_under_validation_fee_policy",
    "external_software_signer::tests::final_promotion_account::final_promotion_account_software_provisioning_rejects_all_handles_and_retains_repair",
    "external_software_signer::tests::final_promotion_account::final_promotion_account_cannot_relabel_a_real_software_binding_or_envelope",
    "external_software_signer::tests::final_promotion_account::final_promotion_roles_are_rejected_before_native_adapter_endpoint_access",
    "smartcontracts::ivm::host::tests::stream_token_custody_namespace_reserves_exact_root_and_all_native_key_families",
    "query::final_promotion_account_custody::observation::tests::exact_account_check_joins_real_finality_and_distinct_current_accounts",
    "query::final_promotion_account_custody::observation::tests::independent_target_digest_binding_and_observer_are_checked_before_preparation",
    "query::final_promotion_account_custody::observation::tests::exact_reviewed_target_and_payload_commitment_cannot_be_replaced_in_signed_check",
    "query::final_promotion_account_custody::observation::tests::successful_check_rechecks_both_accounts_permissions_at_same_or_descendant_cut",
    "query::final_promotion_account_custody::observation::tests::account_interval_requires_both_endpoints_after_native_enrollment_execution",
    "query::final_promotion_account_custody::observation::tests::successful_check_cannot_hide_later_same_block_custody_revocation",
    "query::final_promotion_account_custody::observation::tests::independent_floor_hash_and_committee_context_cannot_come_from_candidate",
    "query::signer_check::tests::bound_check_cannot_cross_native_purpose_or_replace_its_original_round",
    "query::signer_check::tests::one_round_issues_and_binds_only_once_and_failure_cannot_be_retried",
    "query::signer_check::tests::common_binding_rejects_non_check_actions_for_both_closed_purposes",
    "query::signer_check::tests::complete_external_bytes_and_signature_are_retained_by_the_single_owner",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::shared_history::prepared_shared_control_is_unpublished_and_matches_exact_native_provenance",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::shared_history::receipt_control_bytes_cannot_be_replayed_under_account_custody_namespace",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::shared_history::shared_control_keeps_declared_index_identity_and_bounded_canonical_frames",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::shared_history::first_use::receipt_first_use_rows_require_full_provenance_and_original_height_index",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::shared_history::first_use::account_first_use_rows_require_full_provenance_and_original_height_index",
    "query::final_promotion_authority::observation::tests::observer::receipt_check_rejects_self_observation_and_substituted_operator_or_observer",
    "query::final_promotion_authority::observation::tests::observer::receipt_check_retains_distinct_observer_and_operator_through_real_finality",
    "query::final_promotion_authority::observation::tests::observer::receipt_current_check_requires_the_pinned_operator_registered_and_authorized",
    "query::final_promotion_authority::observation::tests::observer::receipt_observer_permission_revoked_before_execution_cannot_supply_a_success",
    "query::final_promotion_authority::observation::tests::observer::receipt_observer_role_permission_and_account_removal_are_rechecked_at_applied_cut",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::observer::receipt_check_observer_and_operator_remain_distinct_even_with_both_grants",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::observer::receipt_check_only_observer_cannot_mutate_custody_or_operations",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::observer::receipt_check_requires_both_exact_deployment_grants_and_original_row_operator",
    "executor::tests::final_promotion_permission_tests::native_receipt_check_observer_permission_never_grants_mutation_or_self_check",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::current_check_rejects_trusted_time_before_native_enrollment_even_after_valid_issuance",
    "sorafs::native_transaction_signer::tests::payload_authorization::every_forwarder_action_belongs_to_exactly_one_native_signer_role",
    "sorafs::native_transaction_signer::tests::payload_authorization::all_native_facades_sign_every_allowed_action_without_rewriting_payload",
    "sorafs::native_transaction_signer::tests::payload_authorization::every_native_facade_rejects_other_roles_and_wrappers_before_all_provider_calls",
    "sorafs::native_transaction_signer::tests::payload_authorization::every_native_facade_rejects_foreign_and_genesis_networks_before_all_provider_calls",
    "sorafs_native_transaction_signer_startup_tests::native_signer_startup_qualifies_exact_configured_provider",
    "runtime_provider_registry::tests::registry_native_signer_uses_catalog_network_before_any_provider_method",
    "runtime_provider_broker::protocol::platform::tests::native_role_authorization_tests::native_role_payload_rejection_precedes_server_backend_io",
    "runtime_provider_broker::protocol::platform::tests::native_role_authorization_tests::native_role_proxy_and_raw_reject_before_probes_or_transport",
    "runtime_provider_broker::protocol::platform::tests::native_role_authorization_tests::native_network_proxy_and_raw_reject_without_poisoning_or_transport",
    "external_software_signer::tests::native_role_authorization::native_client_rejects_cross_role_before_accessing_an_unavailable_endpoint",
    "external_software_signer::tests::native_role_authorization::native_adapter_rejects_cross_role_before_a_revoked_service_and_preserves_valid_signing",
    "query::final_promotion_authority::observation::tests::time_interval::finite_utc_interval_requires_both_custody_endpoints_at_one_applied_cut",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::request_digest::public_request_digest_matches_each_native_custody_and_operation_transition",
    "signer_operation::journal::tests::reader::reader_and_pinned_receipt_keep_the_same_exclusive_lease",
    "signer_operation::tests::final_promotion::lifecycle::concurrent_sign_and_recover_fail_before_io_and_success_releases_the_gate",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::current_check_repeats_without_consuming_ids_fences_audit_or_history",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::check_then_same_block_signer_or_attester_revoke_fences_exact_reexecution_and_applied_cut",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::same_block_completion_invalidates_reserved_check_and_allows_exact_completed_check",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::applied_cut_rechecks_account_and_direct_or_role_permissions_after_native_changes",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::applied_operation_checks_reject_trusted_time_before_original_execution",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::old_completed_checks_survive_new_audit_and_original_expiry_with_fresh_custody",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::whole_check_instruction_bound_precedes_oversized_nested_row_comparison",
    "smartcontracts::isi::sorafs_final_promotion_authority::tests::check::reserved_subject_requires_the_selected_row_active_head_and_original_audit",
    "query::final_promotion_authority::observation::tests::exact_executed_check_joins_real_finality_and_current_native_authority",
    "query::final_promotion_authority::observation::tests::coherent_authenticated_descendant_cut_rechecks_current_authority",
    "query::final_promotion_authority::observation::tests::successful_check_cannot_hide_later_same_block_custody_revocation",
    "query::final_promotion_authority::observation::tests::successful_check_cannot_hide_same_block_or_descendant_permission_revocation",
    "query::final_promotion_authority::observation::tests::rejection_result_is_not_a_successful_check_even_with_real_finality",
    "query::final_promotion_authority::observation::tests::independent_floor_hash_and_committee_context_cannot_come_from_candidate",
    "query::final_promotion_authority::observation::tests::historical_future_dated_qc_cannot_stand_in_for_a_new_round",
    "query::signer_finality::tests::identical_blocks_and_certificates_cannot_authorize_a_foreign_state_network",
    "query::signer_finality::tests::an_invalid_local_certificate_is_not_signer_finality",
    "sorafs::token::signer_finality_native_custody_tests::actual_native_custody_requires_both_certified_blocks_then_accepts_signed_observation",
    "sorafs::token::signer_finality_native_custody_tests::actual_native_custody_rejects_same_height_forged_control_digests",
    "signer_operation::tests::final_promotion::final_promotion_signs_durably_and_public_verification_matches_read_only_recovery",
    "signer_operation::tests::final_promotion::final_promotion_sign_and_recovery_use_only_the_constructor_pinned_statement",
    "native_finality_tests::same_epoch_descendants_bind_the_exact_source_outputs_and_wire",
    "native_finality_tests::native_fixture_signer_rejects_skipped_and_substituted_parents",
    "query::signer_check_test_fixture::tests::test_facade_retains_exact_executed_results_membership_and_certified_parents",
    "query::signer_check_test_fixture::tests::test_facade_rejects_preseeded_history_and_foreign_network_before_publication",
    "query::final_promotion_account_custody::observation::tests::prepared_account_liveness_keeps_original_challenge_and_gates_expired_runtime_work",
    "query::final_promotion_account_custody::observation::tests::prepared_account_observer_is_pinned_before_signing_and_preserved_through_finality",
    "query::final_promotion_account_custody::observation::tests::account_check_preparation_rejects_non_ed25519_observer_before_issuing_a_round",
    "query::final_promotion_authority::observation::tests::receipt_check_preparation_rejects_non_ed25519_observer_before_issuing_a_round",
    "query::signer_check::tests::account_envelope::native_signed_envelope_owner_retains_real_check_bytes_and_canonical_replay",
    "query::signer_check::tests::account_envelope::native_signed_envelope_owner_rejects_sidecars_extras_signatures_and_other_entry_kinds",
    "query::signer_check::tests::account_envelope::native_signed_envelope_owner_uses_the_same_exact_complete_frame_ceiling",
    "query::final_promotion_account_custody::observation::tests::account_verified_check_retains_original_full_floor_after_applied_descendants",
    "query::final_promotion_authority::observation::tests::receipt_verified_check_retains_original_full_floor_after_applied_descendants",
    "query::final_promotion_account_custody::observation::tests::account_verified_check_retains_exact_external_and_check_block_after_descendants",
    "query::final_promotion_authority::observation::tests::receipt_verified_check_retains_exact_external_and_check_block_after_descendants",
    "signer_operation::tests::final_promotion::lifecycle::recovery_only_view_outlives_every_protected_provider_and_retains_the_exact_journal_lease",
    "signer_operation::tests::final_promotion::lifecycle::recovery_only_view_shares_signing_gate_and_releases_it_after_success",
    "signer_operation::tests::final_promotion::lifecycle::recovery_only_view_preserves_shared_poison_without_any_observation_or_journal_io",
)
SORAFS_COSIGN_QUALIFICATION_HELPER = "ci/qualify_sorafs_cosign.py"
SORAFS_COSIGN_VERIFIER_POLICY = "ci/sorafs_cosign_verifier.json"
SORAFS_COSIGN_CRYPTO_TEST = "scripts/tests/sorafs_final_promotion_cosign_crypto_test.py"
SORAFS_CLI_RUST_OWNER_CONTRACT_TEST = (
    "scripts/tests/check_sorafs_rust_owner_contract_test.py"
)
SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND = (
    "python3 -I -S scripts/check_build_efficiency_provenance.py"
)
SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_TEST = (
    "scripts/tests/check_build_efficiency_provenance_test.py"
)
SORAFS_CLI_L1_QUALIFICATION_TESTS = (
    "scripts/tests/check_sorafs_l1_deployment_qualification_test.py",
    "scripts/tests/check_sorafs_l1_resilience_qualification_test.py",
)
SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_SOURCE_PATHS = (
    "scripts/check_sorafs_ai_prescreen_rollout_evidence.py",
    "scripts/check_sorafs_appeal_finance_rollout_evidence.py",
    "scripts/check_sorafs_gateway_compliance_rollout_evidence.py",
    "scripts/check_sorafs_gateway_load_rollout_evidence.py",
    "scripts/check_sorafs_governance_dag_rollout_evidence.py",
    "scripts/check_sorafs_hedging_rollout_evidence.py",
    "scripts/check_sorafs_moderation_panel_rollout_evidence.py",
    "scripts/check_sorafs_orderbook_rollout_evidence.py",
    "scripts/check_sorafs_pdp_rollout_evidence.py",
    "scripts/check_sorafs_pop_credentials_rollout_evidence.py",
    "scripts/check_sorafs_por_rollout_evidence.py",
    "scripts/check_sorafs_potr_rollout_evidence.py",
    "scripts/check_sorafs_repair_rollout_evidence.py",
    "scripts/check_sorafs_reputation_rollout_evidence.py",
    "scripts/check_sorafs_reserve_rent_rollout_evidence.py",
    "scripts/check_sorafs_transparency_rollout_evidence.py",
    "scripts/sorafs_archive_path_components.py",
    "scripts/sorafs_final_promotion_cosign.py",
    "scripts/sorafs_final_promotion_evidence.py",
    "scripts/sorafs_required_kinds.py",
    "scripts/sorafs_verifier_process.py",
    "scripts/tests/conftest.py",
)
SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TESTS = (
    SORAFS_NATIVE_AUTHORITY_RUNTIME_TEST,
    "scripts/tests/check_sorafs_ai_prescreen_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_appeal_finance_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_gateway_compliance_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_gateway_load_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_governance_dag_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_hedging_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_moderation_panel_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_orderbook_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_pdp_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_pop_credentials_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_por_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_potr_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_repair_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_reputation_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_reserve_rent_rollout_evidence_test.py",
    "scripts/tests/check_sorafs_transparency_rollout_evidence_test.py",
    "scripts/tests/sorafs_archive_path_components_test.py",
    "scripts/tests/sorafs_final_promotion_cosign_test.py",
    "scripts/tests/qualify_sorafs_cosign_test.py",
    "scripts/tests/sorafs_final_promotion_evidence_test.py",
    "scripts/tests/sorafs_required_kinds_test.py",
    "scripts/tests/sorafs_verifier_process_test.py",
)
SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TRIGGER_PATHS = frozenset(
    (
        *SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_SOURCE_PATHS,
        *SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TESTS,
        "specs/sorafs/final_promotion_receipt_v1.md",
        "specs/sorafs/signer_production_authority_inventory.md",
        # Native authority includes Kura, State, permissions and their test/support leaves.
        "crates/iroha_core/**",
        "crates/iroha_sccp/**",
        SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT,
        "crates/iroha_executor_data_model/**",
        "crates/iroha_schema_gen/**",
        "specs/references/schema.json",
        "crates/iroha_torii/src/sorafs/**",
        "crates/irohad/src/signer_operation.rs",
        "crates/irohad/src/signer_operation/**",
        "crates/iroha_cli/src/commands/sorafs/**",
        "specs/sorafs/final_promotion_native_authority_v1.md",
        "fixtures/sorafs/final_promotion_cosign/**",
        SORAFS_COSIGN_QUALIFICATION_HELPER, SORAFS_COSIGN_VERIFIER_POLICY,
        SORAFS_COSIGN_CRYPTO_TEST,
    )
)
SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_TRIGGER_PATHS = frozenset(
    {
        "ci/build_efficiency_provenance.json",
        "scripts/check_build_efficiency_provenance.py",
        "scripts/tests/check_build_efficiency_provenance_test.py",
    }
)
SORAFS_CLI_TOPOLOGY_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        "ci/check_sorafs_cli_release.sh",
        "scripts/build_sorafs_topology_qualification_envelope.py",
        "scripts/check_sorafs_l1_deployment_qualification.py",
        "scripts/check_sorafs_l1_resilience_qualification.py",
        "scripts/check_sorafs_release_automation.py",
        "scripts/check_sorafs_release_version_map.py",
        "scripts/release_evidence_crypto.py",
        "scripts/sorafs_checker_preflight.py",
        "scripts/sorafs_evidence_fingerprint.py",
        "scripts/sorafs_evidence_json.py",
        "scripts/sorafs_evidence_paths.py",
        "scripts/sorafs_evidence_sensitivity.py",
        "scripts/sorafs_evidence_validation.py",
        "scripts/sorafs_l1_lane_evidence_inventory.py",
        "scripts/sorafs_path_identity.py",
        "scripts/sorafs_production_readiness_contract.py",
        "scripts/sorafs_response_args.py",
        "scripts/sorafs_runner_preflight.py",
        "scripts/sorafs_software_signer_evidence.py",
        "scripts/sorafs_topology_qualification.py",
        "scripts/taira_constants.py",
        "scripts/tests/check_sorafs_release_automation_test.py",
        "scripts/tests/check_sorafs_l1_deployment_qualification_test.py",
        "scripts/tests/check_sorafs_l1_resilience_qualification_test.py",
        "scripts/tests/sorafs_evidence_json_test.py",
        "scripts/tests/sorafs_foundational_receipt_test_support.py",
        "scripts/tests/sorafs_resilience_test_support.py",
        "scripts/tests/sorafs_response_args_test.py",
        "scripts/tests/sorafs_topology_qualification_test.py",
        "scripts/requirements.txt",
        "scripts/examples/sorafs_l1_deployment_qualification.args.example",
        "scripts/examples/sorafs_l1_deployment_qualification_manifest.json.example",
        "scripts/examples/sorafs_l1_resilience_qualification.args.example",
        "scripts/examples/sorafs_l1_topology_qualification_envelope.md",
        "specs/sorafs/l1_deployment_qualification.md",
        "specs/sorafs/l1_resilience_qualification.md",
    }
)
SORAFS_CLI_RESERVE_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        "ci/check_sorafs_cli_release.sh",
        "crates/iroha/src/client.rs",
        "crates/iroha/src/client/reserve.rs",
        "crates/iroha/src/http_default.rs",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py",
    }
)
SORAFS_CLI_REPAIR_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        "ci/check_sorafs_cli_release.sh",
        "crates/iroha/src/client.rs",
        "crates/iroha/src/client/repair.rs",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py",
    }
)
SORAFS_CLI_RUST_OWNER_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        "ci/check_sorafs_cli_release.sh",
        "crates/iroha_cli/src/commands/sorafs.rs",
        SORAFS_CLI_RUST_OWNER_CONTRACT_TEST,
        "scripts/tests/sorafs_rollout_gate_source_support.py",
        "scripts/tests/state_source_bundle.py",
        "xtask/src/main.rs",
        "xtask/src/sorafs.rs",
        "xtask/src/sorafs/**",
        "crates/iroha_core/**",
        "crates/iroha_sccp/**",
        "crates/iroha_data_model/**",
        "crates/iroha_executor_data_model/**",
    }
)
SORAFS_CLI_PROVIDER_INGEST_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        "ci/check_sorafs_cli_release.sh",
        "crates/iroha_config/**",
        "crates/iroha_crypto/**",
        "crates/iroha_data_model/**",
        "crates/irohad/Cargo.toml",
        "crates/irohad/bins/Cargo.toml",
        "crates/irohad/src/lib.rs",
        "crates/irohad/src/main.rs",
        "crates/irohad/src/sorafs_provider_ingest_runtime.rs",
        "crates/irohad/src/sorafs_provider_ingest_runtime/tests.rs",
        "crates/irohad/src/sorafs_provider_ingest_runtime/tests/**",
        "crates/irohad/src/sorafs_provider_ingest_runtime/**",
        "crates/sorafs_node/**",
        "scripts/tests/check_sorafs_provider_ingest_runtime_contract_test.py",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py",
    }
)
SORAFS_CLI_VERSION_MAP_TRIGGER_PATHS = frozenset(
    {
        "IrohaSwift/Package.swift",
        "IrohaSwift/README.md",
        "IrohaSwift/VERSION",
        "specs/sdk/swift/index.md",
    }
)
SORAFS_CLI_RELEASE_VERSION_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        "ci/check_sorafs_cli_release.sh",
        "crates/sorafs_car/**",
        "crates/sorafs_manifest/**",
        "crates/sorafs_orchestrator/**",
        "release/version-map.toml",
        "scripts/check_sorafs_release_version_map.py",
        "scripts/tests/check_sorafs_release_version_map_test.py",
    }
)
SORAFS_CLI_LOCK_TRIGGER_PATHS = frozenset(
    {
        ".github/workflows/sorafs-cli-release.yml",
        ".gitignore",
        "Cargo.lock",
        "ci/check_sorafs_cli_release.sh",
        "scripts/tests/check_sorafs_release_automation_test.py",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py",
    }
)
RELEASE_VERSION_MAP_CONTRACT_MARKERS: dict[str, tuple[str, ...]] = {
    "scripts/check_sorafs_release_version_map.py": (
        'RELEASE_PACKAGE_IDS = frozenset(\n    {"sorafs-car", "sorafs-manifest", "sorafs-orchestrator"}\n)',
        "release_version must match every CLI release package version",
    ),
    "scripts/tests/check_sorafs_release_version_map_test.py": (
        "test_release_version_must_match_every_cli_release_package",
    ),
}
WORKFLOWS: dict[str, tuple[str, ...]] = {
    ".github/workflows/sorafs-cli-release.yml": (
        '- "scripts/sorafs_javascript_test_events.mjs"',
        '- "scripts/tests/sorafs_javascript_test_events_test.mjs"',
        '"sorafs-cli-v*"',
        '- "scripts/check_sorafs_mobile_parity_reports.py"',
        '- "scripts/tests/check_sorafs_mobile_parity_reports_test.py"',
        "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "scripts/check_sorafs_release_version_map.py",
        "version-map-summary.first.json",
        "version-map-summary.replay.json",
        "cmp version-map-summary.first.json version-map-summary.replay.json",
        "cp version-map-summary.first.json version-map-summary.json",
        "scripts/check_sorafs_reference_sdk_release_evidence.py",
        "scripts/build_sorafs_reference_sdk_release_canary.py",
        '- "scripts/build_sorafs_reference_sdk_supply_chain_sources.py"',
        '- "scripts/build_sorafs_foundational_prerequisite.py"',
        '- "scripts/build_sorafs_topology_qualification_envelope.py"',
        '- "scripts/check_sorafs_production_readiness.py"',
        '- "scripts/check_sorafs_production_promotion_bundle.py"',
        '- "scripts/sorafs_software_signer_receipt.py"',
        '- "scripts/sorafs_reference_sdk_supply_chain.py"',
        '- "scripts/sorafs_reference_sdk_signed_manifest.py"',
        '- "scripts/tests/sorafs_reference_sdk_signed_manifest_test.py"',
        '- "scripts/build_sorafs_java_consumer_artifact.py"',
        '- "scripts/sorafs_java_consumer_artifact.py"',
        '- "scripts/sorafs_sdk_artifact_index.py"',
        '- "scripts/sorafs_sdk_java_artifact_verifier.py"',
        '- "scripts/jvm_classfile.py"',
        '- "scripts/fixtures/SorafsJavaConsumerQualificationRunner.java"',
        '- "scripts/fixtures/SorafsAndroidPackageLinkProbe.java"',
        '- "scripts/tests/sorafs_java_consumer_artifact_test.py"',
        '- "scripts/tests/sorafs_java_dependency_origins_test.py"',
        '- "scripts/tests/sorafs_sdk_artifact_index_test.py"',
        '- "scripts/sorafs_javascript_archive.py"',
        '- "scripts/sorafs_javascript_dependencies.py"',
        '- "scripts/sorafs_javascript_package_source.py"',
        '- "scripts/sorafs_javascript_native_cache.mjs"',
        '- "scripts/tests/sorafs_javascript_archive_fixtures.py"',
        '- "scripts/tests/sorafs_javascript_archive_test.py"',
        '- "scripts/tests/sorafs_javascript_archive_bounds_test.py"',
        '- "scripts/tests/sorafs_javascript_dependencies_test.py"',
        '- "scripts/tests/sorafs_javascript_package_fixtures.py"',
        '- "scripts/tests/sorafs_javascript_package_source_test.py"',
        '- "scripts/tests/sorafs_javascript_package_bounds_test.py"',
        '- "scripts/tests/fixtures/sorafs_npm_archive_v1.tgz"',
        '- "specs/sorafs/javascript_original_archives_v1.md"',
        '- "ci/verify_privacy_python_wheel.py"',
        '- "ci/privacy_sdk_cargo_lockfile_test.sh"',
        '- "scripts/tests/python_wheel_byte_owner_test.py"',
        '- "scripts/tests/python_installed_content_owner_test.py"',
        '- "scripts/tests/python_zip_directory_admission_test.py"',
        '- "scripts/tests/sorafs_python_child_input_content_test.py"',
        '- "scripts/tests/sorafs_python_posix_profile_test.py"',
        '- "scripts/tests/sorafs_python_bootstrap_origin_test.py"',
        '- "scripts/tests/sorafs_python_report_origins_test.py"',
        '- "scripts/tests/sorafs_sdk_python_artifact_verifier_test.py"',
        '- "scripts/fixtures/SorafsPythonConsumerQualificationRunner.py"',
        '- "scripts/sorafs_python_consumer_cases.py"',
        '- "scripts/sorafs_python_consumer_artifact.py"',
        '- "scripts/tests/sorafs_python_child_runner_test.py"',
        '- "scripts/tests/sorafs_python_consumer_artifact_test.py"',
        '- "scripts/build_sorafs_python_consumer_artifact.py"',
        '- "scripts/check_native_sdk_artifact.py"',
        '- "scripts/tests/check_native_sdk_artifact_test.py"',
        '- "scripts/tests/check_native_sdk_bounded_probe_test.py"',
        '- "scripts/sorafs_python_environment.py"',
        '- "scripts/sorafs_python_process.py"',
        '- "scripts/sorafs_python_producer_inputs.py"',
        '- "scripts/sorafs_python_package_source.py"',
        '- "scripts/sorafs_python_publication.py"',
        '- "scripts/sorafs_python_archive.py"',
        '- "scripts/sorafs_python_commands.py"',
        '- "scripts/sorafs_python_report_origins.py"',
        '- "scripts/sorafs_sdk_python_artifact_verifier.py"',
        '- "scripts/tests/sorafs_python_index_fixture.py"',
        '- "scripts/tests/sorafs_python_archive_test.py"',
        '- "scripts/tests/sorafs_python_commands_test.py"',
        '- "scripts/sorafs_python_runtime_inputs.py"',
        '- "scripts/sorafs_python_runtime_custody.py"',
        '- "scripts/sorafs_python_dependency_inputs.py"',
        '- "scripts/sorafs_python_dependency_archive.py"',
        '- "scripts/sorafs_python_dependency_install.py"',
        '- "scripts/tests/build_sorafs_python_consumer_artifact_test.py"',
        '- "scripts/tests/sorafs_python_environment_test.py"',
        '- "scripts/tests/sorafs_python_process_test.py"',
        '- "scripts/tests/sorafs_python_producer_inputs_test.py"',
        '- "scripts/tests/sorafs_python_package_source_test.py"',
        '- "scripts/tests/sorafs_python_publication_test.py"',
        '- "scripts/tests/sorafs_python_runtime_publication_join_test.py"',
        '- "scripts/tests/sorafs_python_runtime_inputs_test.py"',
        '- "scripts/tests/sorafs_python_dependency_install_test.py"',
        '- "specs/sorafs/python_consumer_producer_v1.md"',
        '- "specs/sorafs/python_index_adapter_v1.md"',
        '- "specs/sorafs/python_runtime_inputs_v1.md"',
        '- "specs/sorafs/python_dependency_install_v1.md"',
        '- "specs/sorafs/python_reference_child_v1.md"',
        '- "scripts/sorafs_topology_qualification.py"',
        '- "scripts/sorafs_evidence_json.py"',
        '- "scripts/sorafs_response_args.py"',
        "scripts/run_sorafs_reference_sdk_release_evidence.py",
        "scripts/check_workflow_action_pins.py",
        *RUNTIME_PROVIDER_RELEASE_WORKFLOW_MARKERS,
        '- "Dockerfile"',
        '- "ci/build_efficiency_provenance.json"',
        '- "scripts/build_release_bundle.sh"',
        '- "scripts/build_release_image.sh"',
        '- "scripts/build_release_oci_archive.py"',
        '- "scripts/build_release_tar_gz.py"',
        '- "scripts/build_release_tar_zst.py"',
        '- "scripts/capture_release_command.py"',
        '- "scripts/copy_release_file.py"',
        '- "scripts/copy_release_tree.py"',
        '- "scripts/check_build_efficiency_provenance.py"',
        '- "scripts/generate_release_manifest.py"',
        '- "scripts/generate_sorafs_cli_release_manifest.py"',
        '- "scripts/release_artifact_contract.py"',
        '- "scripts/release_manifest_signing.py"',
        '- "scripts/publish_plan.py"',
        '- "scripts/run_release_pipeline.py"',
        '- "scripts/write_release_checksum.py"',
        '- "scripts/write_release_sha256sums.py"',
        '- "scripts/validate_release_image_bases.py"',
        '- "scripts/requirements.txt"',
        "python3 -m pip install -r scripts/requirements.txt",
        "python3 scripts/check_workflow_action_pins.py",
        "scripts/tests/check_sorafs_reference_sdk_release_evidence_test.py",
        '- "scripts/tests/build_sorafs_reference_sdk_supply_chain_sources_test.py"',
        '- "scripts/tests/build_sorafs_foundational_prerequisite_test.py"',
        '- "scripts/tests/check_sorafs_production_promotion_bundle_test.py"',
        '- "scripts/tests/sorafs_reference_sdk_supply_chain_test.py"',
        '- "scripts/tests/sorafs_topology_qualification_test.py"',
        '- "scripts/tests/sorafs_evidence_json_test.py"',
        '- "scripts/tests/sorafs_foundational_receipt_test_support.py"',
        '- "scripts/tests/sorafs_response_args_test.py"',
        '- "scripts/examples/sorafs_l1_topology_qualification_envelope.md"',
        '- "specs/sorafs/l1_deployment_qualification.md"',
        '- "specs/sorafs_pdp_plan.md"',
        "run: bash ci/check_sorafs_cli_release.sh",
        "scripts/package_iroha_cli_release.sh",
        "scripts/package_sorafs_cli_candidate.py",
        "scripts/tests/package_sorafs_cli_candidate_test.py",
        '- "scripts/tests/build_release_bundle_test.py"',
        '- "scripts/tests/build_release_image_test.py"',
        '- "scripts/tests/check_build_efficiency_provenance_test.py"',
        '- "scripts/tests/capture_release_command_test.py"',
        '- "scripts/tests/release_artifact_contract_test.py"',
        '- "scripts/tests/validate_release_image_bases_test.py"',
        '- "scripts/tests/release_profile_validation_test.py"',
        '- "scripts/tests/release_manifest_signing_test.py"',
        '- "scripts/tests/release_output_parent_cleanup_test.py"',
        '- "scripts/tests/release_output_transaction_cleanup_test.py"',
        '- "scripts/tests/release_manifest_signing_test.sh"',
        '- "scripts/tests/generate_release_manifest_test.py"',
        '- "scripts/tests/generate_sorafs_cli_release_manifest_test.py"',
        '- "scripts/tests/publish_plan_test.py"',
        '- "scripts/tests/check_sorafs_rollout_gate_contract_test.py"',
        '- "python/iroha_python/scripts/release_smoke.sh"',
        '- "python/iroha_python/README.md"',
        '- "specs/sdk/python/release_automation*.md"',
        '- "specs/sdk/python/support_playbook*.md"',
        '- "specs/sorafs_release_pipeline_plan*.md"',
        '- "specs/release_automation_plan*.md"',
        '- "specs/release_runbook*.md"',
        '- "specs/release_artifact_selection*.md"',
        '- "specs/sora_nexus_operator_onboarding*.md"',
        '- "specs/sorafs/foundational_prerequisite_signing.md"',
        '- "CHANGELOG.md"',
        '- "LICENSE"',
        "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
        "anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2",
        "syft-version: v1.44.0",
        "grype-version: v0.112.0",
        "severity-cutoff: high",
        "fail-build: true",
        'cargo build --locked --release -p sorafs_orchestrator --bin sorafs_cli --target "$target"',
        'cargo build --locked --release -p sorafs_car --features cli --bin sorafs_fetch --target "$target"',
        'cargo build --locked --release -p iroha_cli --bin iroha --target "$target"',
        'if [[ "$host_target" != "$target" ]]; then',
        "target: ${{ matrix.target }}",
        '--target "${{ matrix.target }}"',
        'source_commit="${GITHUB_SHA}"',
        'source_date_epoch="$(git show -s --format=%ct "$source_commit")"',
        '--source-commit "$source_commit"',
        '--source-date-epoch "$source_date_epoch"',
        'binary_suffix: ".exe"',
        "find . -type f ! -name SHA256SUMS -print",
        "done > SHA256SUMS",
        "name: sorafs-cli-release-gate-${{ github.run_id }}",
        "path: artifacts/release-gate",
        "artifacts/release-gate/artifacts/sorafs-release/sorafs-release.spdx.json",
        "name: Generate platform binary SBOM",
        "name: Package Iroha CLI and SoraFS FFI header",
        "name: Package Iroha CLI and SoraFS FFI header reproducibly",
        "iroha-first.XXXXXX",
        "iroha-replay.XXXXXX",
        'cmp "${first_out}/${relative}" "${replay_out}/${relative}"',
        "for suffix in .tar.gz.sha256 .manifest.json.sha256; do",
        "cmp candidate-package-first.json candidate-package-replay.json",
        "artifacts/sorafs-cli/iroha-cli",
        "output-file: artifacts/sorafs-cli/sorafs-cli-${{ matrix.target }}.spdx.json",
        "name: Scan platform binary SBOM",
        "output-file: artifacts/sorafs-cli/sorafs-cli-${{ matrix.target }}-vulnerabilities.sarif",
        "specs/sorafs/runbooks/release_rollback_yank.md artifacts/sorafs-cli/ROLLBACK-YANK.md",
        "cp CHANGELOG.md LICENSE artifacts/sorafs-cli/",
        "name: Rebuild deterministic platform archive and run clean-consumer smoke",
        "candidate-package-first.json",
        "candidate-package-replay.json",
        "artifacts/sorafs-cli/platform-archive",
        "name: Stage source release scan evidence",
        "name: Finalize platform checksums",
        "  prepare-release-manifest:",
        "name: Build the canonical foundational manifest twice",
        "python3 scripts/generate_sorafs_cli_release_manifest.py create",
        "name: Upload unsigned foundational manifest for external software signing",
        "  verify-release-auth:",
        "environment: sorafs-release-authentication",
        "runs-on: [self-hosted, linux, x64, sorafs-release-auth]",
        "SORAFS_RELEASE_SIGNATURE_PATH: ${{ vars.SORAFS_RELEASE_SIGNATURE_PATH }}",
        "SORAFS_RELEASE_PUBLIC_KEY_PATH: ${{ vars.SORAFS_RELEASE_PUBLIC_KEY_PATH }}",
        "SORAFS_RELEASE_MANIFEST_VERIFIER_PATH: ${{ vars.SORAFS_RELEASE_MANIFEST_VERIFIER_PATH }}",
        "SORAFS_TRUSTED_RELEASE_SIGNING_FINGERPRINT: ${{ vars.SORAFS_TRUSTED_RELEASE_SIGNING_FINGERPRINT }}",
        "SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256: ${{ vars.SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256 }}",
        "name: Reconcile the foundational manifest with the immutable candidates",
        "name: Verify the protected external Ed25519 manifest tuple",
        "python3 scripts/release_manifest_signing.py verify",
        "name: Upload authenticated foundational manifest tuple",
        "name: Verify authenticated release-manifest candidate binding before provenance",
        "needs: [release-gate, package, verify-release-auth]",
        "sigstore/cosign-installer@ba7bc0a3fef59531c69a25acd34668d6d3fe6f22",
        "name: Verify platform package checksums before signing",
        "signed_artifact_id: ${{ steps.upload-signed.outputs.artifact-id }}",
        "signed_artifact_digest: ${{ steps.upload-signed.outputs.artifact-digest }}",
        "signed_artifact_url: ${{ steps.upload-signed.outputs.artifact-url }}",
        "id: upload-signed",
        '[[ "${#checksum_files[@]}" -ne 5 ]]',
        "sha256sum --check SHA256SUMS",
        "SHA256SUMS contains duplicate file entries",
        "SHA256SUMS does not cover the exact platform candidate file set",
        "actions/attest@a1948c3f048ba23858d222213b7c278aabede763",
        "name: Attest aggregate signed-input provenance",
        "name: Stage offline provenance bundles",
        '[[ "$attestation_path" != "${RUNNER_TEMP}/"*',
        '[[ "$count" -gt 16 ]]',
        "cosign sign-blob --yes --bundle",
        "cosign verify-blob",
        'certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/sorafs-cli-release.yml@${GITHUB_REF}"',
        'certificate-oidc-issuer "https://token.actions.githubusercontent.com"',
        "id-token: write",
        "name: Assemble and validate the canonical SF-11 source indexes",
        "name: Build and gate source-derived SF-11 supply-chain evidence",
        "name: Record the immutable signed-input artifact binding",
        "sorafs.reference_sdk.signed_input_artifact.v1",
        "artifacts/reference-sdk-evidence/l1-topology-qualification.summary.json",
        "artifacts/reference-sdk-evidence/l1-topology-qualification.envelope.json",
        "sorafs.l1.deployment_qualification.trust.v1",
        "--topology-qualification-verification-public-key-hex",
        "--topology-qualification-signer-service-id",
        "--topology-qualification-signer-administrator-id",
        "--topology-qualification-signer-key-revision",
        "--topology-qualification-signer-policy-revision",
        "--topology-qualification-signer-policy-digest-hex",
        "--max-topology-qualification-review-age-secs 1209600",
        "expected one aggregate offline provenance bundle",
        '"signed-input/github-attestations/${target}.json"',
        'gh attestation verify "$provenance_file"',
        "realpath -e --",
        "SORAFS_TRUSTED_GH_CLI_SHA256: ${{ vars.SORAFS_TRUSTED_GH_CLI_SHA256 }}",
        "name: Upload replay-complete SF-11 supply-chain evidence",
        "sf11-source/",
        "  reference-sdk-supply-chain-evidence:",
        "needs: [release-gate, sign]",
        "environment: sorafs-reference-sdk-evidence",
        "SORAFS_REFERENCE_SDK_DEPLOYMENT_ID: ${{ vars.SORAFS_REFERENCE_SDK_DEPLOYMENT_ID }}",
        "SORAFS_REFERENCE_SDK_RECEIPTS_ROOT: ${{ vars.SORAFS_REFERENCE_SDK_RECEIPTS_ROOT }}",
        "SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX: ${{ vars.SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX }}",
        "SORAFS_TRUSTED_GH_CLI_SHA256: ${{ vars.SORAFS_TRUSTED_GH_CLI_SHA256 }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_SUMMARY_PATH: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SUMMARY_PATH }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_ENVELOPE_PATH: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_ENVELOPE_PATH }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_KEY_REVISION: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_KEY_REVISION }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_REVISION: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_REVISION }}",
        "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_DIGEST_HEX: ${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_DIGEST_HEX }}",
        "--external-receipts-root \"$SORAFS_REFERENCE_SDK_RECEIPTS_ROOT\"",
        "--supply-chain-source-root sf11-source",
        "--provenance-certificate-identity \"$certificate_identity\"",
        "--provenance-oidc-issuer \"$oidc_issuer\"",
        '"$SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX"',
        "sf11-source/",
    ),
    ".github/workflows/sorafs-fixtures-nightly.yml": (
        'cron: "17 2 * * *"',
        "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        'python-version: "3.12"',
        "bash ci/check_sorafs_fixtures.sh",
        "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        'go-version: "1.26.x"',
        "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
        'node-version: "24"',
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    ),
    ".github/workflows/sorafs-orchestrator-sdk.yml": (
        "node --test scripts/tests/sorafs_javascript_test_events_test.mjs scripts/tests/sorafs_javascript_child_files_test.mjs scripts/tests/sorafs_javascript_child_input_test.mjs scripts/tests/sorafs_javascript_child_loads_test.mjs scripts/tests/sorafs_javascript_child_session_test.mjs",
        '- "scripts/sorafs_javascript_test_events.mjs"',
        '- "scripts/tests/sorafs_javascript_test_events_test.mjs"',
        'cron: "41 3 * * *"',
        '- "scripts/check_sorafs_mobile_parity_reports.py"',
        '- "scripts/tests/check_sorafs_mobile_parity_reports_test.py"',
        '- "scripts/sorafs_evidence_json.py"',
        '- "scripts/sorafs_evidence_paths.py"',
        '- "scripts/sorafs_evidence_sensitivity.py"',
        '- "scripts/sorafs_path_identity.py"',
        '- "tools/kotlin-fixture-gen/**"',
        '- ".cargo/**"',
        '- "codec/**"',
        '- "scripts/package_mobile_sdk_artifacts.sh"',
        '- "scripts/tests/deploy_localnet_test.py"',
        '- "vendor/**"',
        "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        'python-version: "3.12"',
        "name: Bind the canonical mobile Python",
        'echo "MOBILE_SDK_PYTHON_BINARY=$mobile_python" >> "$GITHUB_ENV"',
        "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
        'node-version: "24"',
        "runs-on: macos-14",
        "  mobile-parity:",
        "  csharp-parity:",
        "actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9",
        "actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
        "bash ci/check_sorafs_python_native_sdk.sh",
        "bash ci/sdk_sorafs_orchestrator.sh",
        "dotnet test Hyperledger.Iroha.Sdk.sln -c Release --no-build",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    ),
}
SORAFS_JAVASCRIPT_CONTENT_PATHS = frozenset({
    "scripts/sorafs_javascript_tree_custody.py",
    "scripts/sorafs_javascript_qualification_source.py",
    "scripts/sorafs_javascript_qualification_custody.py",
    "scripts/fixtures/sorafs_javascript_qualification_sources_v1.json",
    "scripts/tests/sorafs_javascript_qualification_source_test.py",
    "specs/sorafs/javascript_qualification_source_v1.md",
    "scripts/sorafs_javascript_installed.py",
    "scripts/sorafs_javascript_install_metadata.py",
    "scripts/sorafs_javascript_installed_custody.py",
    "scripts/tests/sorafs_javascript_installed_test.py",
})
SORAFS_JAVASCRIPT_CHILD_PATHS = frozenset({
    'scripts/sorafs_javascript_child.mjs',
    'scripts/sorafs_javascript_child_entry.mjs',
    'scripts/sorafs_javascript_child_input.mjs',
    'scripts/sorafs_javascript_child_loads.mjs',
    'scripts/sorafs_javascript_child_session.mjs',
    'scripts/tests/sorafs_javascript_child_fixture.mjs',
    'scripts/tests/sorafs_javascript_child_input_test.mjs',
    'scripts/tests/sorafs_javascript_child_loads_test.mjs',
    'scripts/tests/sorafs_javascript_child_contract_test.mjs',
    'scripts/tests/sorafs_javascript_child_session_test.mjs',
    'scripts/tests/sorafs_javascript_child_abi_contract_test.py',
    'specs/sorafs/javascript_child_bootstrap_v1.md',
    "scripts/sorafs_javascript_child_tools.py",
    "scripts/sorafs_javascript_input_files.py",
    "scripts/sorafs_javascript_parent_input.py",
    "scripts/tests/sorafs_javascript_input_files_test.py",
    "scripts/tests/sorafs_javascript_parent_input_test.py",
    "specs/sorafs/javascript_parent_input_v1.md",
    "scripts/sorafs_javascript_runtime_graph.py",
    "scripts/sorafs_javascript_runtime_inputs.py",
    "scripts/tests/sorafs_javascript_runtime_inputs_test.py",
    "scripts/sorafs_javascript_runtime_custody.py",
    "scripts/tests/sorafs_javascript_runtime_custody_test.py",
    "scripts/sorafs_javascript_child_process.py",
    "scripts/tests/sorafs_javascript_child_process_test.py",
    "specs/sorafs/javascript_runtime_inputs_v1.md",
    "scripts/macho_decoder.py",
    "scripts/tests/macho_decoder_test.py",
    "scripts/sorafs_python_consumer_artifact.py",
    "scripts/sorafs_python_consumer_cases.py",
    "ci/verify_privacy_python_wheel.py",
    "scripts/sorafs_evidence_json.py",
    "scripts/sorafs_evidence_paths.py",
    "scripts/sorafs_evidence_sensitivity.py",
    "scripts/sorafs_path_identity.py",
    "scripts/requirements.txt",
    "ci/check_sorafs_cli_release.sh",
    'scripts/sorafs_javascript_native_cache.mjs',
    'scripts/fixtures/sorafs_javascript_qualification_sources_v1.json',
    "scripts/sorafs_javascript_child_files.mjs",
    "scripts/tests/sorafs_javascript_child_files_test.mjs",
    "scripts/sorafs_javascript_test_events.mjs",
    "scripts/tests/sorafs_javascript_test_events_test.mjs",
})
SORAFS_JAVASCRIPT_PARITY_RUNNER = "ci/sdk_sorafs_orchestrator.sh"
SORAFS_JAVASCRIPT_SOURCE_COMMAND = '    "${node_binary}" --test "${REPO_ROOT}/scripts/tests/sorafs_javascript_child_contract_test.mjs" "${sdk_root}/test/sorafsNativeSuiteStructure.test.js"'
SORAFS_JAVASCRIPT_CHILD_PYTHON_TESTS = (
    "scripts/tests/sorafs_javascript_child_abi_contract_test.py",
    "scripts/tests/sorafs_javascript_input_files_test.py",
    "scripts/tests/sorafs_javascript_parent_input_test.py",
    "scripts/tests/sorafs_javascript_runtime_inputs_test.py",
    "scripts/tests/sorafs_javascript_runtime_custody_test.py",
    "scripts/tests/sorafs_javascript_child_process_test.py",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_accepts_thin_and_nonoverlapping_fat_images",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_rejects_nonzero_fat64_reserved_field",
)
SORAFS_JAVASCRIPT_CHILD_WORKFLOWS = (
    ".github/workflows/sorafs-cli-release.yml",
    ".github/workflows/sorafs-orchestrator-sdk.yml",
)
SORAFS_JAVASCRIPT_CHILD_COMMAND = "node --test scripts/tests/sorafs_javascript_test_events_test.mjs scripts/tests/sorafs_javascript_child_files_test.mjs scripts/tests/sorafs_javascript_child_input_test.mjs scripts/tests/sorafs_javascript_child_loads_test.mjs scripts/tests/sorafs_javascript_child_session_test.mjs"
SORAFS_JAVASCRIPT_CHILD_STEP = (
    "      - name: Verify fixed JavaScript child-custody ownership\n"
    f"        run: {SORAFS_JAVASCRIPT_CHILD_COMMAND}"
)
SORAFS_JAVASCRIPT_NODE_STEP = (
    "      - uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6\n"
    "        with:\n"
    '          node-version: "24"\n'
    "          cache: npm\n"
    "          cache-dependency-path: javascript/iroha_js/package-lock.json"
)


NATIVE_GOVERNANCE_VALIDATION_REQUIRED_ENV = (
    "IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION"
)
MOBILE_SDK_ARTIFACTS_WORKFLOW = ".github/workflows/mobile_sdk_artifacts.yml"
SWIFT_GOVERNANCE_VALIDATOR_TEST = (
    "IrohaSwift/Tests/IrohaSwiftTests/SorafsReferenceValidatorsTests.swift"
)
KOTLIN_GOVERNANCE_VALIDATOR_TEST = (
    "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/sorafs/"
    "SorafsReferenceValidatorsTest.kt"
)
JAVA_GOVERNANCE_VALIDATOR_TEST = (
    "java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/"
    "SorafsReferenceValidatorsTests.java"
)
JAVA_GOVERNANCE_WORKFLOW_STEP_NAME = (
    "name: Test mirrored Java Android Governance DAG reference validators"
)
JAVA_GOVERNANCE_WORKFLOW_STEP_MARKERS = (
    "working-directory: java/iroha_android",
    (
        "ANDROID_HARNESS_MAINS: "
        "org.hyperledger.iroha.android.sorafs.SorafsReferenceValidatorsTests"
    ),
    "--no-daemon",
    "--no-configuration-cache",
    '--project-cache-dir "$MOBILE_SDK_ANDROID_PROJECT_CACHE_DIR/java-sorafs"',
    '-Djava.io.tmpdir="$MOBILE_SDK_ANDROID_GRADLE_TMP_DIR/java-sorafs"',
    (
        "-Dkotlin.daemon.runFilesPath="
        '"$MOBILE_SDK_ANDROID_GRADLE_TMP_DIR/kotlin-daemon-java-sorafs"'
    ),
    "--tests org.hyperledger.iroha.android.GradleHarnessTests",
)
NATIVE_GOVERNANCE_SDK_CONTRACTS: dict[str, tuple[str, ...]] = {
    MOBILE_SDK_ARTIFACTS_WORKFLOW: (
        '- "scripts/check_sorafs_release_automation.py"',
        '- "scripts/tests/check_sorafs_release_automation_test.py"',
        '- "java/iroha_android/**"',
        '- "fixtures/sorafs_manifest/governance/**"',
        "name: Build host SoraFS reference native bridge",
        "cargo build --locked -p connect_norito_bridge --lib --features privacy-production-enabled",
        "cargo build --locked -p kotlin-fixture-gen --features dev-tools --bin kotlin-fixture-gen",
        '- "tools/kotlin-fixture-gen/**"',
        "IROHA_NATIVE_LIBRARY_PATH: ${{ github.workspace }}/target/debug",
        JAVA_GOVERNANCE_WORKFLOW_STEP_NAME,
        *JAVA_GOVERNANCE_WORKFLOW_STEP_MARKERS,
    ),
    SWIFT_GOVERNANCE_VALIDATOR_TEST: (
        "ABI-31 connect_norito_bridge with Governance DAG symbols is required.",
        "guard try requireGovernanceDagNativeBridge() else",
        "XCTFail(\"\\(Self.nativeValidationRequiredMessage) \\(unavailableMessage)\")",
    ),
    KOTLIN_GOVERNANCE_VALIDATOR_TEST: (
        "ABI-31 connect_norito_bridge with Governance DAG symbols is required.",
        "        requireGovernanceDagNativeBridge()\n",
        "throw AssertionError(requiredMessage)",
    ),
    JAVA_GOVERNANCE_VALIDATOR_TEST: (
        "ABI-31 connect_norito_bridge with all SoraFS reference symbols is required.",
        "  private static void requireNativeBridge() {\n",
        (
            "  private static void "
            "validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable()\n"
            "      throws IOException {\n"
            "    requireNativeBridge();\n"
        ),
        "throw new AssertionError(",
    ),
}


def _release_auth_document_paths(root: Path) -> tuple[str, ...]:
    """Return a bounded, no-follow release-auth document inventory."""

    paths = [
        *RELEASE_AUTH_ROOT_DOCUMENTS,
        *RELEASE_AUTH_HISTORICAL_FINDINGS,
    ]
    docs_root = root / "docs"
    try:
        docs_metadata = docs_root.lstat()
    except OSError as error:
        raise ValueError("docs: release-auth documentation tree is missing") from error
    if stat.S_ISLNK(docs_metadata.st_mode) or not stat.S_ISDIR(docs_metadata.st_mode):
        raise ValueError("docs: release-auth documentation tree is missing")

    pending: list[tuple[Path, tuple[str, ...], os.stat_result]] = [
        (docs_root, (), docs_metadata)
    ]
    visited_entries = 0
    document_count = 0
    while pending:
        directory, prefix, expected_metadata = pending.pop()
        relative_directory = "/".join(("docs", *prefix))
        try:
            observed_metadata = directory.lstat()
        except OSError as error:
            raise ValueError(
                f"{relative_directory}: release-auth documentation directory "
                "changed during enumeration"
            ) from error
        if (
            stat.S_ISLNK(observed_metadata.st_mode)
            or not stat.S_ISDIR(observed_metadata.st_mode)
            or (observed_metadata.st_dev, observed_metadata.st_ino)
            != (expected_metadata.st_dev, expected_metadata.st_ino)
        ):
            raise ValueError(
                f"{relative_directory}: release-auth documentation directory "
                "changed during enumeration"
            )
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            raise ValueError(
                f"{relative_directory}: release-auth documentation directory "
                "cannot be enumerated safely"
            ) from error

        for entry in entries:
            if entry.name in RELEASE_AUTH_IGNORED_DIRECTORY_NAMES:
                continue
            visited_entries += 1
            if visited_entries > MAX_RELEASE_AUTH_TREE_ENTRIES:
                raise ValueError(
                    "docs: release-auth documentation tree exceeds its entry limit"
                )
            entry_prefix = (*prefix, entry.name)
            relative = "/".join(("docs", *entry_prefix))
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ValueError(
                    f"{relative}: release-auth documentation entry changed "
                    "during enumeration"
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(
                    f"{relative}: release-auth documentation paths must not "
                    "contain symlinks"
                )
            if stat.S_ISDIR(metadata.st_mode):
                if len(entry_prefix) > MAX_RELEASE_AUTH_TREE_DEPTH:
                    raise ValueError(
                        "docs: release-auth documentation tree exceeds its depth limit"
                    )
                pending.append((directory / entry.name, entry_prefix, metadata))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"{relative}: release-auth documentation tree contains a "
                    "non-regular entry"
                )
            if Path(entry.name).suffix.lower() not in RELEASE_AUTH_DOCUMENT_EXTENSIONS:
                continue
            if metadata.st_nlink != 1:
                raise ValueError(
                    f"{relative}: release-auth documents must not be hard linked"
                )
            document_count += 1
            if document_count > MAX_RELEASE_AUTH_DOCUMENTS:
                raise ValueError(
                    "docs: release-auth documentation tree exceeds its document limit"
                )
            paths.append(relative)
    return tuple(sorted(paths))


def _historical_release_auth_finding_is_allowed(
    relative: str,
    finding: str,
    match_name: str,
) -> bool:
    """Allow only the reviewed SF-6 finding that documents the removed design."""

    if match_name != "OIDC-derived local Ed25519 signing material":
        return False
    markers = RELEASE_AUTH_HISTORICAL_FINDINGS.get(relative)
    return markers is not None and all(marker in finding for marker in markers)


def _validate_release_auth_document_tree(root: Path) -> list[str]:
    """Reject retired or competing release-authentication guidance everywhere."""

    errors: list[str] = []
    for relative in _release_auth_document_paths(root):
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"{relative}: release-auth document must be UTF-8"
            ) from error
        lowered_source = source.lower()
        for match_name, prefilter_groups, pattern in RELEASE_AUTH_FORBIDDEN_PATTERNS:
            if not all(
                any(needle in lowered_source for needle in group)
                for group in prefilter_groups
            ):
                continue
            for match in pattern.finditer(source):
                finding = match.group(0)
                if _historical_release_auth_finding_is_allowed(
                    relative,
                    finding,
                    match_name,
                ):
                    continue
                line_number = source.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{relative}:{line_number}: forbidden release-auth documentation "
                    f"reference ({match_name})"
                )
    return errors


def _validate_package_release_smoke(root: Path) -> list[str]:
    """Keep the Python release harness smoke-only and signer-free."""

    path = _require_regular_repo_file(root, PACKAGE_RELEASE_SMOKE_SCRIPT)
    try:
        source = _read_bytes_no_follow(path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            f"{PACKAGE_RELEASE_SMOKE_SCRIPT}: package release smoke must be UTF-8"
        ) from error
    errors: list[str] = []
    for marker in PACKAGE_RELEASE_SMOKE_REQUIRED_MARKERS:
        if marker not in source:
            errors.append(
                f"{PACKAGE_RELEASE_SMOKE_SCRIPT}: missing package-smoke contract "
                f"marker `{marker}`"
            )
    lowered_source = source.lower()
    for marker in PACKAGE_RELEASE_SMOKE_FORBIDDEN_MARKERS:
        if marker.lower() in lowered_source:
            errors.append(
                f"{PACKAGE_RELEASE_SMOKE_SCRIPT}: signing/provenance marker "
                f"`{marker}` is forbidden in the smoke harness"
            )
    if GENERIC_OPENSSL_SIGNER_RE.search(source) is not None:
        errors.append(
            f"{PACKAGE_RELEASE_SMOKE_SCRIPT}: generic OpenSSL/RSA signing is "
            "forbidden in the smoke harness"
        )
    return errors


def _validate_reference_sdk_release_examples(root: Path) -> list[str]:
    """Require source-bound SF-11 examples and reject retired manual inputs."""

    errors: list[str] = []
    for relative, markers in sorted(
        REFERENCE_SDK_RELEASE_EXAMPLE_REQUIRED_MARKERS.items()
    ):
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"{relative}: reference-SDK release example must be UTF-8"
            ) from error
        for marker in markers:
            if marker not in source:
                errors.append(
                    f"{relative}: missing source-bound example marker `{marker}`"
                )
        for marker in REFERENCE_SDK_RELEASE_EXAMPLE_FORBIDDEN_MARKERS.get(
            relative,
            (),
        ):
            if marker in source:
                errors.append(
                    f"{relative}: retired manual release marker `{marker}`"
                )
    return errors


def _workflow_job(source: str, name: str) -> str | None:
    """Return one top-level workflow job, including its header."""

    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        source,
    )
    return match.group(0) if match is not None else None


def _contract_section(
    source: str,
    start_marker: str,
    end_marker: str,
) -> str | None:
    """Return one bounded source section used by a static SDK contract."""

    try:
        start = source.index(start_marker)
        end = source.index(end_marker, start + len(start_marker))
    except ValueError:
        return None
    return source[start:end]


def _validate_native_governance_sdk_contract(root: Path) -> list[str]:
    """Require fail-closed native Governance DAG parity in release SDK jobs."""

    errors: list[str] = []
    sources: dict[str, str] = {}
    for relative, markers in NATIVE_GOVERNANCE_SDK_CONTRACTS.items():
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"{relative}: native Governance DAG SDK contract must be UTF-8"
            ) from error
        sources[relative] = source
        for marker in markers:
            if marker not in source:
                errors.append(
                    f"{relative}: missing native Governance DAG contract marker "
                    f"`{marker}`"
                )

    workflow = sources[MOBILE_SDK_ARTIFACTS_WORKFLOW]
    required_env_marker = (
        f'{NATIVE_GOVERNANCE_VALIDATION_REQUIRED_ENV}: "1"'
    )
    for job_name in ("apple-mobile-sdk", "android-mobile-sdk"):
        job = _workflow_job(workflow, job_name)
        if job is None:
            errors.append(
                f"{MOBILE_SDK_ARTIFACTS_WORKFLOW}: missing `{job_name}` job"
            )
        elif required_env_marker not in job:
            errors.append(
                f"{MOBILE_SDK_ARTIFACTS_WORKFLOW}: `{job_name}` must require "
                "native Governance DAG validation"
            )
    if workflow.count(required_env_marker) != 2:
        errors.append(
            f"{MOBILE_SDK_ARTIFACTS_WORKFLOW}: native Governance DAG validation "
            "must be required exactly once in each release SDK job"
        )
    java_workflow_section = _contract_section(
        workflow,
        JAVA_GOVERNANCE_WORKFLOW_STEP_NAME,
        "name: Validate Android mobile SDK artifact",
    )
    if java_workflow_section is None:
        errors.append(
            f"{MOBILE_SDK_ARTIFACTS_WORKFLOW}: malformed mirrored Java Android "
            "Governance DAG validation step"
        )
    else:
        for marker in JAVA_GOVERNANCE_WORKFLOW_STEP_MARKERS:
            if marker not in java_workflow_section:
                errors.append(
                    f"{MOBILE_SDK_ARTIFACTS_WORKFLOW}: mirrored Java Android "
                    "Governance DAG validation step is missing "
                    f"`{marker}`"
                )

    swift = sources[SWIFT_GOVERNANCE_VALIDATOR_TEST]
    swift_section = _contract_section(
        swift,
        (
            "func "
            "testValidatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable"
        ),
        "func testSignsOrderbookFixtureWhenNativeBridgeIsAvailable",
    )
    if swift_section is None:
        errors.append(
            f"{SWIFT_GOVERNANCE_VALIDATOR_TEST}: malformed Governance DAG golden test"
        )
    elif "XCTSkipIf(" in swift_section:
        errors.append(
            f"{SWIFT_GOVERNANCE_VALIDATOR_TEST}: Governance DAG golden test "
            "must not unconditionally skip when the native bridge is unavailable"
        )
    for marker in ("XCTSkip(", NATIVE_GOVERNANCE_VALIDATION_REQUIRED_ENV):
        if marker in swift:
            errors.append(
                f"{SWIFT_GOVERNANCE_VALIDATOR_TEST}: native validation must fail "
                f"without the capability-skip marker `{marker}`"
            )

    kotlin = sources[KOTLIN_GOVERNANCE_VALIDATOR_TEST]
    kotlin_section = _contract_section(
        kotlin,
        (
            "fun "
            "validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable"
        ),
        "fun signsOrderbookFixtureWhenNativeBridgeIsAvailable",
    )
    if kotlin_section is None:
        errors.append(
            f"{KOTLIN_GOVERNANCE_VALIDATOR_TEST}: malformed Governance DAG golden test"
        )
    elif (
        "assumeTrue(SorafsReferenceValidators.isNativeAvailable()"
        in kotlin_section
    ):
        errors.append(
            f"{KOTLIN_GOVERNANCE_VALIDATOR_TEST}: Governance DAG golden test "
            "must not unconditionally skip when the native bridge is unavailable"
        )
    for marker in ("assumeTrue(", NATIVE_GOVERNANCE_VALIDATION_REQUIRED_ENV):
        if marker in kotlin:
            errors.append(
                f"{KOTLIN_GOVERNANCE_VALIDATOR_TEST}: native validation must fail "
                f"without the capability-skip marker `{marker}`"
            )

    java = sources[JAVA_GOVERNANCE_VALIDATOR_TEST]
    java_section = _contract_section(
        java,
        (
            "private static void "
            "validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable"
        ),
        "private static void signsOrderbookFixtureWhenNativeBridgeIsAvailable",
    )
    if java_section is None:
        errors.append(
            f"{JAVA_GOVERNANCE_VALIDATOR_TEST}: malformed Governance DAG golden test"
        )
    elif re.search(
        r"if\s*\(\s*!SorafsReferenceValidators\.isNativeAvailable\(\)\s*\)"
        r"\s*\{\s*return;\s*\}",
        java_section,
    ):
        errors.append(
            f"{JAVA_GOVERNANCE_VALIDATOR_TEST}: Governance DAG golden test "
            "must not unconditionally return when the native bridge is unavailable"
        )
    if NATIVE_GOVERNANCE_VALIDATION_REQUIRED_ENV in java:
        errors.append(
            f"{JAVA_GOVERNANCE_VALIDATOR_TEST}: native validation must fail "
            "without an environment-controlled capability return"
        )
    return errors


def _pop_broker_source_tokens(source: str) -> list[str] | None:
    """Read code tokens; comments and literals cannot impersonate declarations."""

    raw_pattern = re.compile(r'(?:br|cr|r)(#{0,255})"')
    literal_pattern = re.compile(
        r'''(?:b|c)?"(?:\\.|[^"\\])*"'''
        r"|(?:b)?'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\])'"
    )
    quote_pattern = re.compile(r'(?:b|c)?"')
    token_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|.")
    tokens: list[str] = []
    cursor = 0
    while cursor < len(source):
        if source[cursor].isspace():
            cursor += 1
        elif source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            cursor = len(source) if end < 0 else end + 1
        elif source.startswith("/*", cursor):
            depth = 1
            cursor += 2
            while cursor < len(source) and depth:
                pair = source[cursor : cursor + 2]
                depth += (pair == "/*") - (pair == "*/")
                cursor += 2 if pair in ("/*", "*/") else 1
            if depth:
                return None
        else:
            raw = raw_pattern.match(source, cursor)
            if raw:
                terminator = '"' + raw.group(1)
                end = source.find(terminator, raw.end())
                if end < 0:
                    return None
                end += len(terminator)
            else:
                literal = literal_pattern.match(source, cursor)
                if literal:
                    end = literal.end()
                elif quote_pattern.match(source, cursor):
                    return None
                else:
                    token = token_pattern.match(source, cursor)
                    assert token is not None
                    end = token.end()
            tokens.append(source[cursor:end])
            cursor = end
    return tokens


def _pop_broker_wire_field_inventory(
    source: str, struct_name: str
) -> tuple[tuple[str, str], ...] | None:
    """Require one canonical, private PoP frame declaration in its owning module."""

    modes = {
        "PopRuntimeOpenResultWireV1": "owned",
        "PopRecipientOpenRequestWireV1": "move_sensitive",
        "PopRecipientOpenResultWireV1": "move_sensitive",
        "PopCredentialRuntimeBindingWireV1": "owned",
    }
    tokens = _pop_broker_source_tokens(source)
    if tokens is None or struct_name not in modes:
        return None
    # Validate all delimiters before considering a declaration, including a
    # malformed duplicate following an otherwise healthy declaration.
    stack: list[tuple[str, int]] = []
    closing: dict[int, int] = {}
    depths: list[int] = []
    for index, token in enumerate(tokens):
        depths.append(len(stack))
        if token in ("(", "[", "{"):
            stack.append((token, index))
        elif token in (")", "]", "}"):
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[token]:
                return None
            closing[stack.pop()[1]] = index
        if token == "struct" and tokens[index + 1 : index + 2] == [struct_name]:
            return None  # Ordinary structs are not this protocol's owner.
    if stack:
        return None

    bodies: list[list[str]] = []
    for index, token in enumerate(tokens):
        if token != "define_broker_wire_struct":
            continue
        if tokens[index + 1 : index + 2] != ["!"]:
            continue
        opening = index + 2
        if opening not in closing:
            return None
        args = tokens[opening + 1 : closing[opening]]
        body_at = args.index("{") if "{" in args else len(args)
        owner = f'"irohad::runtime_provider_broker::protocol::primitives::{struct_name}"'
        if struct_name not in args[:body_at] and owner not in args[:body_at]:
            continue
        expected = [
            modes[struct_name], "frame", owner, ";",
            "pub", "(", "super", ")", struct_name,
        ]
        if (
            depths[index] != 0
            or tokens[opening] != "("
            or args[:body_at] != expected
            or args[-1:] != ["}"]
            or tokens[closing[opening] + 1 : closing[opening] + 2] != [";"]
        ):
            return None
        bodies.append(args[body_at + 1 : -1])
    if len(bodies) != 1:
        return None

    fields: list[tuple[str, str]] = []
    field_start = 0
    brackets: list[str] = []
    for index, token in enumerate(bodies[0]):
        if token in ("<", "[", "("):
            brackets.append(token)
        elif token in (">", "]", ")"):
            if not brackets or brackets.pop() != {">": "<", "]": "[", ")": "("}[token]:
                return None
        elif token == "," and not brackets:
            field = bodies[0][field_start:index]
            if (
                len(field) < 7
                or field[:4] != ["pub", "(", "super", ")"]
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field[4]) is None
                or field[5] != ":"
            ):
                return None
            fields.append((field[4], "".join(field[6:])))
            field_start = index + 1
    if brackets or field_start != len(bodies[0]):
        return None
    return tuple(fields)


def _validate_pop_broker_hard_cut_contract(root: Path) -> list[str]:
    """Pin the compact secret-free PoP broker open protocol."""

    relative_sources = {
        "broker": "crates/irohad/src/runtime_provider_broker.rs",
        "protocol": (
            "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
        ),
        "validator": (
            "crates/irohad/src/runtime_provider_broker/validate_operation_payload.rs"
        ),
        "recipient_client": (
            "crates/irohad/src/runtime_provider_broker/pop_recipient_client.rs"
        ),
        "runtime": "crates/irohad/src/sorafs_pop_runtime.rs",
    }
    sources: dict[str, str] = {}
    for label, relative in relative_sources.items():
        path = _require_regular_repo_file(root, relative)
        try:
            sources[label] = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{relative}: PoP broker source must be UTF-8") from error

    errors: list[str] = []
    protocol = sources["protocol"]
    for operation, wire_id in POP_BROKER_OPERATION_IDS.items():
        if re.search(
            rf"(?m)^\s*pub\(super\)\s+const\s+{re.escape(operation)}\s*:\s*"
            rf"u16\s*=\s*{wire_id}\s*;\s*$",
            protocol,
        ) is None:
            errors.append(
                f"PoP broker operation {operation} must retain wire id {wire_id}"
            )
    if "OPERATION_POP_RUNTIME_RESOLVE_V1" in "\n".join(sources.values()):
        errors.append("PoP broker retired runtime-resolve operation name must remain absent")

    for struct_name, expected_fields in POP_BROKER_WIRE_FIELD_INVENTORIES.items():
        observed_fields = _pop_broker_wire_field_inventory(protocol, struct_name)
        if observed_fields != expected_fields:
            errors.append(
                f"PoP broker wire struct {struct_name} fields must be exactly "
                f"{expected_fields!r}"
            )

    ipc_sources = (
        sources["broker"],
        sources["protocol"],
        sources["validator"],
        sources["recipient_client"],
    )
    if any("HybridSecretKey" in source for source in ipc_sources):
        errors.append("PoP broker IPC must never serialize HybridSecretKey")
    if any(
        marker in source
        for source in ipc_sources
        for marker in POP_BROKER_RETIRED_SECRET_MARKERS
    ):
        errors.append("PoP broker IPC must not serialize private recipient bytes")
    if any(
        marker in sources["recipient_client"]
        for marker in (".secret()", "recipient_private_key", "recipient_secret")
    ):
        errors.append("PoP broker client must not own private recipient bytes")

    production_runtime = sources["runtime"].split("#[cfg(test)]", 1)[0]
    if any(
        marker in production_runtime
        for marker in (
            "HybridSecretKey",
            "PopCredentialRuntimeSecretsV1",
            "PrivateKey",
            ".secret()",
        )
    ):
        errors.append("production PoP runtime must not own private recipient material")
    return errors


def _validate_runtime_provider_deployment_contract(root: Path) -> list[str]:
    """Validate the complete credential-free broker deployment asset inventory."""

    errors: list[str] = []
    for relative, markers in sorted(
        RUNTIME_PROVIDER_DEPLOYMENT_ASSET_MARKERS.items()
    ):
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"{relative}: runtime-provider deployment asset must be UTF-8"
            ) from error
        for marker in markers:
            if marker not in source:
                errors.append(
                    f"{relative}: missing runtime-provider deployment "
                    f"contract marker {marker!r}"
                )
        for marker in RUNTIME_PROVIDER_DEPLOYMENT_FORBIDDEN_MARKERS.get(
            relative, ()
        ):
            if marker in source:
                errors.append(
                    f"{relative}: forbidden runtime-provider deployment "
                    f"marker {marker!r}"
                )
    errors.extend(_validate_pop_broker_hard_cut_contract(root))
    return errors


def _pull_request_path_entries(source: str) -> tuple[str, ...] | None:
    """Return the ordered quoted ``pull_request.paths`` entries, if present."""

    pull_request = re.search(
        r"(?ms)^  pull_request:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        source,
    )
    if pull_request is None:
        return None
    paths = re.search(
        r"(?ms)^    paths:\n(?P<body>(?:      - [^\n]+\n)+)",
        pull_request.group("body"),
    )
    if paths is None:
        return None
    entries = re.findall(r'(?m)^      - "([^"]+)"\s*$', paths.group("body"))
    return tuple(entries)


def _pull_request_paths(source: str) -> frozenset[str] | None:
    """Return the unique quoted ``pull_request.paths`` entries, if present."""

    entries = _pull_request_path_entries(source)
    return None if entries is None else frozenset(entries)


def _validate_cosign_qualification(root: Path, gate: str) -> list[str]:
    """Require mandatory real crypto execution and the reviewed installer version."""
    helper = _read_bytes_no_follow(_require_regular_repo_file(
        root, SORAFS_COSIGN_QUALIFICATION_HELPER
    )).decode("utf-8")
    policy = load_evidence_json(_require_regular_repo_file(
        root, SORAFS_COSIGN_VERIFIER_POLICY
    ), 16 * 1024)
    command = f"python3 {SORAFS_COSIGN_QUALIFICATION_HELPER}\n"
    sequence = "python3 scripts/check_workflow_action_pins.py\n" + command + "python3 -m pytest -q"
    errors: list[str] = []
    if gate.count(command) != 1 or sequence not in gate:
        errors.append("mandatory cosign qualification must execute exactly once without a conditional skip")
    required = (
        SORAFS_COSIGN_CRYPTO_TEST, "--sorafs-cosign-verifier",
        "--sorafs-cosign-verifier-sha256", "results.passed != REQUIRED_CASES",
        "results.skipped", "set(results.collected) != REQUIRED_CASES",
        "len(results.collected) != len(REQUIRED_CASES)",
        "verifier_process.snapshot_executable(source, executable, policy[\"asset_sha256\"])",
        "load_evidence_json(path, 16 * 1024)",
    )
    if any(marker not in helper for marker in required):
        errors.append("mandatory cosign qualification must pin executable bytes and execute every required case")
    release_tag = policy.get("release_tag")
    if not isinstance(release_tag, str) or re.fullmatch(r"v3\.[0-9]+\.[0-9]+", release_tag) is None:
        errors.append("mandatory cosign qualification requires a reviewed release version")
    workflow = _read_bytes_no_follow(_require_regular_repo_file(
        root, ".github/workflows/sorafs-cli-release.yml"
    )).decode("utf-8")
    installer = (
        "      - uses: sigstore/cosign-installer@ba7bc0a3fef59531c69a25acd34668d6d3fe6f22 # v4.1.0\n"
        "        with:\n" + f'          cosign-release: "{release_tag}"\n'
    )
    if workflow.count(installer) != 2:
        errors.append("both cosign installer steps must pin the independently reviewed release version")
    return errors


def _native_authority_shell_contract() -> str:
    """Exact bounded list/execute contract, with one shared Cargo feature graph."""
    arrays = (
        "native_test_packages=(\n"
        + "".join(f"  -p {package}\n" for package in SORAFS_NATIVE_AUTHORITY_PACKAGES)
        + ")\nnative_test_filters=(\n"
        + "".join(f'  "{value}"\n' for value in SORAFS_NATIVE_AUTHORITY_FILTERS)
        + ")\nnative_test_sentinels=(\n"
        + "".join(f'  "{value}"\n' for value in SORAFS_NATIVE_AUTHORITY_SENTINELS)
        + ")\n"
    )
    return "set -euo pipefail\n" + arrays + r'''
native_test_list="$(
  cargo test --locked "${native_test_packages[@]}" --lib -- \
    "${native_test_filters[@]}" --list
)"
for native_test in "${native_test_sentinels[@]}"; do
  if [[ "$(grep -Fxc -- "${native_test}: test" <<<"${native_test_list}" || true)" != 1 ]]; then
    echo "native authority contract must expose each required runnable test exactly once" >&2
    exit 1
  fi
done
cargo test --locked "${native_test_packages[@]}" --lib -- \
  "${native_test_filters[@]}" --include-ignored --nocapture
'''


def _validate_native_authority_runtime(root: Path, gate: str) -> list[str]:
    """Prevent omitted packages, empty collection, conditional execution or ignored tests."""
    command = f"bash {SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT}"
    sequence = (
        "  --exact --include-ignored --nocapture\n" + command
        + '\necho "[sorafs-release] external software signer protocol and CLI tests"'
    )
    errors: list[str] = []
    contract_command = SORAFS_SIGNER_CONTRACT_COMMAND
    contract_sequence = (
        'echo "[sorafs-release] full signer contract libraries"\n'
        + contract_command + "\n" + command
    )
    if gate.count(contract_command) != 1 or contract_sequence not in gate:
        errors.append("mandatory signer contract libraries must run in full without filtering or a conditional skip")
    sequence = sequence.replace(command, contract_sequence)
    if gate.count(command) != 1 or sequence not in gate:
        errors.append("mandatory native authority runtime must execute exactly once without a conditional skip")
    helper = _read_bytes_no_follow(_require_regular_repo_file(
        root, SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT
    )).decode("utf-8")
    active = lambda source: [
        line.strip() for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if active(helper) != active(_native_authority_shell_contract()):
        errors.append("mandatory native authority runtime must retain exact packages, filters, collection checks and fail-closed execution")
    return errors


def _validate_sorafs_cli_release_gate(root: Path) -> list[str]:
    """Require source integrity by default and retain explicitly requested diagnostics."""

    relative = SORAFS_CLI_RELEASE_GATE_SCRIPT
    path = _require_regular_repo_file(root, relative)
    try:
        source = _read_bytes_no_follow(path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{relative}: release gate must be UTF-8") from error

    errors = _validate_cosign_qualification(root, source)
    errors.extend(_validate_native_authority_runtime(root, source))
    errors.extend(_javascript_child_python_controls_errors(source))
    provenance_commands = tuple(
        re.finditer(
            rf"(?m)^{re.escape(SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND)}$",
            source,
        )
    )
    if len(provenance_commands) != 1:
        errors.append(
            f"{relative}: build-efficiency provenance command must appear "
            "exactly once as a standalone fail-closed command"
        )
    if len(provenance_commands) != 1:
        return errors

    provenance_command = provenance_commands[0]
    strict_mode = re.search(r"(?m)^set -euo pipefail$", source)
    if strict_mode is None or strict_mode.start() > provenance_command.start():
        errors.append(
            f"{relative}: strict shell mode must precede the build-efficiency "
            "provenance command"
        )
    if re.search(
        r"(?m)^\s*set (?:\+e|\+o errexit)\s*$",
        source[: provenance_command.start()],
    ):
        errors.append(
            f"{relative}: build-efficiency provenance command must not run with "
            "errexit disabled"
        )
    if source.count(SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_TEST) != 1:
        errors.append(
            f"{relative}: release helper tests must execute the build-efficiency "
            "provenance regression suite exactly once"
        )
    for qualification_test in SORAFS_CLI_L1_QUALIFICATION_TESTS:
        if source.count(qualification_test) != 1:
            errors.append(
                f"{relative}: release helper tests must execute L1 qualification "
                f"regression suite {qualification_test!r} exactly once"
            )
    for promotion_import_test in SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TESTS:
        if source.count(promotion_import_test) != 1:
            errors.append(
                f"{relative}: release helper tests must execute production-promotion "
                f"import regression suite {promotion_import_test!r} exactly once"
            )
    if source.count(SORAFS_CLI_RUST_OWNER_CONTRACT_TEST) != 1:
        errors.append(
            f"{relative}: release helper tests must execute the Rust module-owner "
            "regression suite exactly once"
        )

    first_cargo_command = re.search(r"(?m)^\s*cargo(?:\s|$)", source)
    diagnostics_return = (
        'if [[ "${diagnostics}" != true ]]; then\n'
        '  echo "[sorafs-release] source integrity checks complete; diagnostics were not run"\n'
        "  exit 0\nfi\n"
    )
    broker_phase = (
        'echo "[sorafs-release] runtime-provider broker deployment contracts"\n'
        "python3 scripts/tests/check_runtime_provider_broker_install_test.py\n\n"
    )
    broker_command = "python3 scripts/tests/check_runtime_provider_broker_install_test.py\n"
    if (
        source.count(broker_phase) != 1
        or source.count(broker_command) != 1
        or source.count(diagnostics_return) != 1
        or (source.count(diagnostics_return) == 1
            and source.count(broker_phase) == 1
            and source.index(broker_phase) > source.index(diagnostics_return))
    ):
        errors.append(
            f"{relative}: mandatory broker deployment contracts must run exactly once "
            "before the diagnostics-only return"
        )
    diagnostics_arguments = (
        'diagnostics=false\ncase "$#" in\n'
        '  0) ;;\n  1)\n'
        '    if [[ "$1" != "--diagnostics" ]]; then\n'
        '      echo "usage: $0 [--diagnostics]" >&2\n'
        "      exit 2\n    fi\n    diagnostics=true\n    ;;\n"
        '  *)\n    echo "usage: $0 [--diagnostics]" >&2\n'
        "    exit 2\n    ;;\nesac\n"
    )
    # The mandatory phase has one top-level owner. Remove only the known
    # argument parser and lock-reader definition, then authenticate its complete
    # active prefix so an outer conditional, function, early return or swallowed
    # failure cannot leave a plausible command marker without executing it.
    lock_check_definition = (
        "verify_cargo_lock_unchanged() {\n"
        '  if [[ "$(cargo_lock_sha256)" != "${expected_cargo_lock_sha256}" ]]; then\n'
        '    echo "workspace Cargo.lock changed during the release gate" >&2\n'
        "    exit 1\n  fi\n}\n\n"
    )
    broker_prefix = source.split(broker_phase, 1)[0]
    broker_prefix = broker_prefix.replace(diagnostics_arguments, "", 1)
    broker_prefix = broker_prefix.replace(lock_check_definition, "", 1)
    lock_definition = re.compile(r"(?ms)^cargo_lock_sha256\(\) \{\n.*?^PY\n\}\n")
    broker_prefix, lock_definitions = lock_definition.subn("", broker_prefix)
    active_prefix = tuple(
        line for line in broker_prefix.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    expected_prefix = (
        "set -euo pipefail",
        'repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"',
        'cd "${repo_root}"',
        'echo "[sorafs-release] build-efficiency provenance check"',
        SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
        'echo "[sorafs-release] reviewed shipping feature graph check"',
        "python3 -I -S scripts/check_release_feature_graph.py",
        'export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"',
        'export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"',
        'export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/.target}"',
        'expected_cargo_lock_sha256="$(cargo_lock_sha256)"',
    )
    mandatory_lock_recheck = "verify_cargo_lock_unchanged\n\n"
    broker_boundary = (
        broker_phase
        + mandatory_lock_recheck
        + diagnostics_return
    )
    if (
        lock_definitions != 1
        or source.count(lock_check_definition) != 1
        or len(re.findall(r"(?m)^verify_cargo_lock_unchanged$", source)) != 2
        or active_prefix != expected_prefix
        or source.count(broker_boundary) != 1
        or source.count(
            '\nverify_cargo_lock_unchanged\necho "[sorafs-release] release verification complete"\n'
        ) != 1
    ):
        errors.append(
            f"{relative}: mandatory broker deployment contracts must have the "
            "unconditional fail-closed source-integrity prefix and lock recheck in both modes"
        )
    if (
        source.count(diagnostics_arguments) != 1
        or source.index(diagnostics_arguments) > provenance_command.start()
        or source.count(diagnostics_return) != 1
        or source.index(diagnostics_return) < provenance_command.start()
        or (first_cargo_command is not None
            and source.index(diagnostics_return) > first_cargo_command.start())
    ):
        errors.append(
            f"{relative}: regressions must require explicit --diagnostics after "
            "source integrity checks; unknown arguments must be rejected"
        )
    if first_cargo_command is None:
        errors.append(
            f"{relative}: release gate must contain a Cargo command after the "
            "build-efficiency provenance command"
        )
    else:
        if first_cargo_command.start() < provenance_command.start():
            errors.append(
                f"{relative}: build-efficiency provenance command must run "
                "before every Cargo command"
            )
    return errors


def _javascript_child_source_controls_errors(source: str) -> list[str]:
    """Bind real AST commands to the existing locked npm install before native build."""
    section = _contract_section(source, "\nrun_javascript_parity() {\n", "\nrun_swift_parity() {")
    sequence = "    npm ci\n" + SORAFS_JAVASCRIPT_SOURCE_COMMAND + "\n    CARGO_BUILD_JOBS=1 \\\n"
    if (section is None or section.count(sequence) != 1
            or source.count(SORAFS_JAVASCRIPT_SOURCE_COMMAND) != 1
            or source.count("sorafs_javascript_child_contract_test.mjs") != 1
            or source.count("sorafsNativeSuiteStructure.test.js") != 1):
        return ["JavaScript child source controls must run once after locked npm installation before native build"]
    return []


def _javascript_child_python_controls_errors(source: str) -> list[str]:
    """Require original ABI/input/runtime controls in the actual release pytest batch."""
    batches = re.findall(r"(?m)^python3 -m pytest -q \\\n((?:  [^\n]+\n)+)", source)
    for test in SORAFS_JAVASCRIPT_CHILD_PYTHON_TESTS:
        line = "  " + test + " \\"
        if (len(batches) != 1 or batches[0].splitlines().count(line) != 1
                or source.count(test) != 1):
            return [f"JavaScript child Python control {test!r} must execute once in the release pytest batch"]
    return []


def _javascript_child_controls_workflow_errors(relative: str, source: str) -> list[str]:
    """Require literal triggers and the fixed unconditional Node24 execution step."""
    errors: list[str] = []
    entries = _pull_request_path_entries(source) or ()
    if any(entries.count(path) != 1 for path in SORAFS_JAVASCRIPT_CHILD_PATHS):
        errors.append(f"{relative}: JavaScript child-custody pull_request paths must appear exactly once")
    if relative != ".github/workflows/sorafs-orchestrator-sdk.yml":
        return errors
    job = _workflow_job(source, "sdk-parity")
    if job is None:
        return errors + [f"{relative}: JavaScript child-custody owner requires sdk-parity"]
    # Reuse the existing exact-indentation workflow contract; these are real
    # list items, never text inside a run block or a commented marker.
    steps = [match.group(0).rstrip() for match in re.finditer(
        r"(?ms)^      - .*?(?=^      - |\Z)", job
    )]
    node = [index for index, step in enumerate(steps) if step == SORAFS_JAVASCRIPT_NODE_STEP]
    event = [index for index, step in enumerate(steps) if step == SORAFS_JAVASCRIPT_CHILD_STEP]
    header = job.split("    steps:\n", 1)[0]
    if (len(node) != 1 or len(event) != 1 or event[0] != node[0] + 1
            or job.count(SORAFS_JAVASCRIPT_CHILD_COMMAND) != 1
            or re.search(r"(?m)^    if:", header)):
        errors.append(
            f"{relative}: JavaScript child-custody controls must run unconditionally exactly once "
            "immediately after the fixed Node24 setup"
        )
    return errors


def _mobile_host_jvm_prerequisite_errors(source: str) -> list[str]:
    """Bind the existing host native build and generator before complete JVM tests."""

    job = _workflow_job(source, "android-mobile-sdk")
    if job is None:
        return ["mobile host JVM prerequisites require the existing android-mobile-sdk job"]
    build = (
        '      - name: Build host SoraFS reference native bridge\n'
        '        run: |\n'
        '          set -euo pipefail\n'
        '          cargo build --locked -p connect_norito_bridge --lib --features privacy-production-enabled\n'
        '          cargo build --locked -p kotlin-fixture-gen --features dev-tools --bin kotlin-fixture-gen\n'
        '          fixture_generator="$CARGO_TARGET_DIR/debug/kotlin-fixture-gen"\n'
        '          [[ -f "$fixture_generator" && ! -L "$fixture_generator" && -x "$fixture_generator" ]]\n'
        '          echo "IROHA_KOTLIN_FIXTURE_GEN_BIN=$fixture_generator" >> "$GITHUB_ENV"\n'
        '      - name: Make reviewed Iroha source read-only\n'
        '        run: chmod -R a-w "$GITHUB_WORKSPACE"\n'
    )
    matches = list(re.finditer("^" + re.escape(build), job, re.MULTILINE))
    runtime_prefix = (
        "      - name: Test, lint, publish, and build Android SDK artifacts\n"
        "        working-directory: kotlin\n"
        "        run: |\n"
        "          ./gradlew --no-daemon --no-build-cache --rerun-tasks \\\n"
    )
    runtime = list(re.finditer("^" + re.escape(runtime_prefix), job, re.MULTILINE))
    if len(matches) != 1 or len(runtime) != 1 or matches[0].end() >= runtime[0].start():
        return ["mobile host JVM prerequisites must build and bind the exact dev-tools executable before the complete suite"]
    return []


def _validate_workflow_source(relative: str, source: str) -> list[str]:
    """Return deterministic contract errors for one workflow source."""

    errors: list[str] = []
    if relative == MOBILE_SDK_ARTIFACTS_WORKFLOW:
        errors.extend(_mobile_host_jvm_prerequisite_errors(source))
    if "pull_request_target:" in source:
        errors.append(f"{relative}: pull_request_target is forbidden")
    if re.search(r"\b(?:curl|wget)\b", source):
        errors.append(f"{relative}: network bootstrap commands are forbidden")
    action_refs = re.findall(r"uses:\s*[^\s@]+@([^\s#]+)", source)
    if any(re.fullmatch(r"[0-9a-f]{40}", reference) is None for reference in action_refs):
        errors.append(
            f"{relative}: floating action references are forbidden; pin full commits"
        )
    if "cancel-in-progress: false" not in source:
        errors.append(f"{relative}: release evidence jobs must not be cancelled")
    for marker in WORKFLOWS[relative]:
        if marker not in source:
            errors.append(f"{relative}: missing contract marker `{marker}`")

    if relative in SORAFS_JAVASCRIPT_CHILD_WORKFLOWS:
        errors.extend(_javascript_child_controls_workflow_errors(relative, source))

    if relative == ".github/workflows/sorafs-cli-release.yml":
        pull_request_path_entries = _pull_request_path_entries(source)
        pull_request_paths = _pull_request_paths(source)
        if any((pull_request_path_entries or ()).count(path) != 1
               for path in SORAFS_JAVASCRIPT_CONTENT_PATHS):
            errors.append(
                f"{relative}: JavaScript content source/test triggers must appear exactly once"
            )
        invalid_promotion_trigger_counts = sorted(
            (trigger, (pull_request_path_entries or ()).count(trigger))
            for trigger in SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TRIGGER_PATHS
            if (pull_request_path_entries or ()).count(trigger) != 1
        )
        if invalid_promotion_trigger_counts:
            rendered = ", ".join(
                f"{trigger}={count}"
                for trigger, count in invalid_promotion_trigger_counts
            )
            errors.append(
                f"{relative}: pull_request.paths must list each production-promotion "
                f"import trigger exactly once: {rendered}"
            )
        missing_triggers = sorted(
            SORAFS_CLI_TOPOLOGY_TRIGGER_PATHS - (pull_request_paths or frozenset())
        )
        if missing_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits topology-envelope "
                f"dependency trigger(s): {', '.join(missing_triggers)}"
            )
        missing_provenance_triggers = sorted(
            SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_TRIGGER_PATHS
            - (pull_request_paths or frozenset())
        )
        if missing_provenance_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits build-efficiency "
                "provenance contract trigger(s): "
                f"{', '.join(missing_provenance_triggers)}"
            )
        missing_reserve_triggers = sorted(
            SORAFS_CLI_RESERVE_TRIGGER_PATHS - (pull_request_paths or frozenset())
        )
        if missing_reserve_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits reserve-client "
                f"contract trigger(s): {', '.join(missing_reserve_triggers)}"
            )
        missing_repair_triggers = sorted(
            SORAFS_CLI_REPAIR_TRIGGER_PATHS - (pull_request_paths or frozenset())
        )
        if missing_repair_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits repair-client "
                f"contract trigger(s): {', '.join(missing_repair_triggers)}"
            )
        missing_rust_owner_triggers = sorted(
            SORAFS_CLI_RUST_OWNER_TRIGGER_PATHS - (pull_request_paths or frozenset())
        )
        if missing_rust_owner_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits Rust module-owner "
                f"contract trigger(s): {', '.join(missing_rust_owner_triggers)}"
            )
        missing_provider_ingest_triggers = sorted(
            SORAFS_CLI_PROVIDER_INGEST_TRIGGER_PATHS
            - (pull_request_paths or frozenset())
        )
        if missing_provider_ingest_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits provider-ingest "
                "crash/restart contract trigger(s): "
                f"{', '.join(missing_provider_ingest_triggers)}"
            )
        missing_version_map_triggers = sorted(
            SORAFS_CLI_VERSION_MAP_TRIGGER_PATHS
            - (pull_request_paths or frozenset())
        )
        if missing_version_map_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits Swift version-map "
                f"dependency trigger(s): {', '.join(missing_version_map_triggers)}"
            )
        missing_release_version_triggers = sorted(
            SORAFS_CLI_RELEASE_VERSION_TRIGGER_PATHS
            - (pull_request_paths or frozenset())
        )
        if missing_release_version_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits CLI release-version "
                f"contract trigger(s): {', '.join(missing_release_version_triggers)}"
            )
        missing_lock_triggers = sorted(
            SORAFS_CLI_LOCK_TRIGGER_PATHS - (pull_request_paths or frozenset())
        )
        if missing_lock_triggers:
            errors.append(
                f"{relative}: pull_request.paths omits workspace lock "
                f"contract trigger(s): {', '.join(missing_lock_triggers)}"
            )

    if relative.endswith("sorafs-orchestrator-sdk.yml"):
        jobs_source = source[source.index("jobs:\n") + len("jobs:\n") :]
        for forbidden_marker in ("continue-on-error:", "|| true"):
            if forbidden_marker in jobs_source:
                errors.append(
                    f"{relative}: parity jobs must not contain fail-open marker "
                    f"`{forbidden_marker}`"
                )
        job_inventory = tuple(
            re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", jobs_source)
        )
        expected_job_inventory = (
            "sdk-parity",
            "mobile-parity",
            "csharp-parity",
        )
        if job_inventory != expected_job_inventory:
            errors.append(
                f"{relative}: parity workflow job inventory must be exactly "
                f"{expected_job_inventory}"
            )
        required_job_markers = {
            "sdk-parity": (
                "runs-on: macos-14",
                'IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"',
                "bash ci/check_sorafs_python_native_sdk.sh",
                "bash ci/sdk_sorafs_orchestrator.sh",
            ),
            "mobile-parity": (
                "runs-on: ubuntu-latest",
                'IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"',
                "name: Bind the canonical mobile Python",
                'echo "MOBILE_SDK_PYTHON_BINARY=$mobile_python" >> "$GITHUB_ENV"',
                "actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9",
                'sdkmanager_status="${PIPESTATUS[1]}"',
                'exit "$sdkmanager_status"',
                "cargo fetch --locked",
                'java-version: "21"',
                "Build and authenticate the exact ABI-31 Kotlin bridge",
                'test ! -e "$native_root"',
                "cargo build --locked --offline --release -p connect_norito_bridge",
                "cargo build --locked --offline --release -p kotlin-fixture-gen",
                "--features dev-tools --bin kotlin-fixture-gen",
                '--target "$target" --target-dir "$native_root/cargo-target"',
                "check_native_sdk_artifact.py record",
                '--sdk c-jni --target "$target"',
                'echo "IROHA_NATIVE_LIBRARY_PATH=$native_dir" >> "$GITHUB_ENV"',
                'echo "IROHA_KOTLIN_FIXTURE_GEN_BIN=$native_dir/kotlin-fixture-gen" >> "$GITHUB_ENV"',
                'echo "MOBILE_SDK_ANDROID_ARTIFACT_DIR=$artifact_dir" >> "$GITHUB_ENV"',
                "Require fresh ABI-31 JNI bridge in complete Kotlin and Java suites",
                "working-directory: kotlin",
                "./gradlew --no-daemon --no-build-cache --rerun-tasks",
                "--no-configuration-cache",
                ":core-jvm:test :tools:test",
                ":client-android:testDebugUnitTest",
                ":client-android:testDebugHostNative",
                ":kagemusha-wallet-android:testDebugUnitTest --console=plain",
                "Validate every mobile parity test lane",
                "python3 -I scripts/check_sorafs_mobile_parity_reports.py",
                '--report-root "$MOBILE_SDK_ANDROID_ARTIFACT_DIR/gradle-build/iroha_kotlin_sdk"',
                '> "$MOBILE_SDK_ANDROID_ARTIFACT_DIR/test-execution.json"',
                "Reauthenticate the consumed Kotlin bridge",
                '--artifact "$IROHA_NATIVE_LIBRARY_PATH/libconnect_norito_bridge.so"',
                '--manifest "$SORAFS_MOBILE_NATIVE_MANIFEST"',
                "Upload Kotlin and Java native parity evidence",
                "sorafs-mobile-parity/gradle-build/iroha_kotlin_sdk/*/test-results/**/TEST-*.xml",
                "sorafs-mobile-parity/test-execution.json",
                "if-no-files-found: error",
            ),
            "csharp-parity": (
                "runs-on: ubuntu-24.04",
                'IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"',
                "actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
                "Build and authenticate the exact ABI-31 C# bridge",
                "cargo build --locked --release -p connect_norito_bridge",
                "native-sdk-abi31.json",
                "check_native_sdk_artifact.py record",
                "check_native_sdk_artifact.py verify",
                "dotnet restore Hyperledger.Iroha.Sdk.sln",
                "dotnet build Hyperledger.Iroha.Sdk.sln -c Release --no-restore -warnaserror",
                "Run complete C# ABI-31 parity suite",
                "dotnet test Hyperledger.Iroha.Sdk.sln -c Release --no-build",
            ),
        }
        for job_name, markers in required_job_markers.items():
            job = _workflow_job(source, job_name)
            if job is None:
                errors.append(f"{relative}: missing `{job_name}` job")
                continue
            for marker in markers:
                if marker not in job:
                    errors.append(
                        f"{relative}: `{job_name}` missing contract marker `{marker}`"
                    )
            if job_name == "mobile-parity":
                stages = (
                    "Build and authenticate the exact ABI-31 Kotlin bridge",
                    "Prepare canonical Kotlin test outputs",
                    "Require fresh ABI-31 JNI bridge in complete Kotlin and Java suites",
                    "Validate every mobile parity test lane",
                    "Reauthenticate the consumed Kotlin bridge",
                    "Upload Kotlin and Java native parity evidence",
                )
                offsets = [job.find(f"      - name: {stage}\n") for stage in stages]
                if any(
                    job.count(f"      - name: {stage}\n") != 1 for stage in stages
                ) or offsets != sorted(offsets):
                    errors.append(
                        f"{relative}: mobile native qualification stages must execute "
                        "exactly once in build, test, reauthentication, upload order"
                    )
                if re.findall(r"(?m)^\s*if:\s*(.+)$", job) != ["always()"]:
                    errors.append(
                        f"{relative}: mobile native qualification must not be "
                        "conditional; only evidence upload uses always()"
                    )
                if job.count("check_native_sdk_artifact.py verify") != 2:
                    errors.append(
                        f"{relative}: mobile native artifact must be verified "
                        "before and after executing the consumer tests"
                    )
                if job.count('--target "$target" --target-dir "$native_root/cargo-target"') != 2:
                    errors.append(
                        f"{relative}: mobile native bridge and fixture generator "
                        "must both use the isolated build target"
                    )

    if relative.endswith("sorafs-cli-release.yml"):
        jobs_source = source[source.index("jobs:\n") + len("jobs:\n") :]
        job_inventory = tuple(
            re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", jobs_source)
        )
        expected_job_inventory = (
            "release-gate",
            "package",
            "prepare-release-manifest",
            "verify-release-auth",
            "sign",
            "reference-sdk-supply-chain-evidence",
        )
        if job_inventory != expected_job_inventory:
            errors.append(
                f"{relative}: release workflow job inventory must be exactly "
                f"{expected_job_inventory}"
            )
        if "${{ secrets." in source:
            errors.append(
                f"{relative}: release workflow must not consume GitHub secrets"
            )
        lowered_source = source.lower()
        if any(
            marker in lowered_source
            for marker in (
                "release_manifest_signing.py sign",
                "--external-signer",
                "--signing-seed",
                "signing_seed",
                "private-key",
                "private_key",
                "development-local-signing",
            )
        ):
            errors.append(
                f"{relative}: GitHub release jobs must not receive private signing "
                "material or invoke the foundational Ed25519 signer"
            )
        if source.count("merge-multiple: false") != 3:
            errors.append(
                f"{relative}: candidate downloads must preserve exactly five "
                "artifact-name directories"
            )
        release_gate_job = _workflow_job(source, "release-gate")
        prepare_job = _workflow_job(source, "prepare-release-manifest")
        auth_job = _workflow_job(source, "verify-release-auth")
        promotion_job = _workflow_job(source, "sign")
        supply_chain_job = _workflow_job(
            source,
            "reference-sdk-supply-chain-evidence",
        )
        promotion_guard = (
            "if: ${{ startsWith(github.ref, 'refs/tags/sorafs-cli-v') "
            "|| inputs.sign_artifacts }}"
        )
        if release_gate_job is None:
            errors.append(f"{relative}: missing release gate job")
        else:
            full_history_checkout = (
                "uses: actions/checkout@"
                "df4cb1c069e1874edd31b4311f1884172cec0e10 # v6\n"
                "        with:\n"
                "          fetch-depth: 0"
            )
            if (
                release_gate_job.count(full_history_checkout) != 1
                or source.count("fetch-depth: 0") != 1
            ):
                errors.append(
                    f"{relative}: only the release-gate checkout must fetch the "
                    "complete provenance history"
                )
            if release_gate_job.count(
                f"run: bash {SORAFS_CLI_RELEASE_GATE_SCRIPT}\n"
            ) != 1:
                errors.append(
                    f"{relative}: release-gate job must run the CLI source integrity "
                    "check exactly once without regression diagnostics"
                )
            if (
                release_gate_job.count(
                    "python3 scripts/check_sorafs_release_version_map.py"
                )
                != 2
                or "cmp version-map-summary.first.json version-map-summary.replay.json"
                not in release_gate_job
                or "cp version-map-summary.first.json version-map-summary.json"
                not in release_gate_job
            ):
                errors.append(
                    f"{relative}: version map must be validated exactly twice with "
                    "byte-identical summaries before its release version is consumed"
                )
        if prepare_job is None:
            errors.append(f"{relative}: missing foundational-manifest preparation job")
        else:
            if promotion_guard not in prepare_job:
                errors.append(
                    f"{relative}: foundational-manifest preparation lacks the "
                    "reviewed promotion trigger guard"
                )
            if "needs: [release-gate, package]" not in prepare_job:
                errors.append(
                    f"{relative}: foundational manifest must depend on the release "
                    "gate and all platform packages"
                )
        if auth_job is None:
            errors.append(f"{relative}: missing protected release-authentication job")
        else:
            required_auth_bindings = (
                "SORAFS_RELEASE_SIGNATURE_PATH: ${{ vars.SORAFS_RELEASE_SIGNATURE_PATH }}",
                "SORAFS_RELEASE_PUBLIC_KEY_PATH: ${{ vars.SORAFS_RELEASE_PUBLIC_KEY_PATH }}",
                "SORAFS_RELEASE_MANIFEST_VERIFIER_PATH: ${{ vars.SORAFS_RELEASE_MANIFEST_VERIFIER_PATH }}",
                "SORAFS_TRUSTED_RELEASE_SIGNING_FINGERPRINT: ${{ vars.SORAFS_TRUSTED_RELEASE_SIGNING_FINGERPRINT }}",
                "SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256: ${{ vars.SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256 }}",
            )
            if any(binding not in auth_job for binding in required_auth_bindings):
                errors.append(
                    f"{relative}: release authentication is missing an explicit "
                    "protected public tuple or trust-anchor binding"
                )
            if "needs: [release-gate, prepare-release-manifest]" not in auth_job:
                errors.append(
                    f"{relative}: release authentication must consume the gated "
                    "foundational manifest"
                )
            if promotion_guard not in auth_job:
                errors.append(
                    f"{relative}: release authentication lacks the reviewed "
                    "promotion trigger guard"
                )
            if "environment: sorafs-release-authentication" not in auth_job:
                errors.append(
                    f"{relative}: release authentication must use the protected "
                    "release-authentication environment"
                )
            if (
                "runs-on: [self-hosted, linux, x64, sorafs-release-auth]"
                not in auth_job
            ):
                errors.append(
                    f"{relative}: release authentication must use the protected "
                    "self-hosted release-auth runner"
                )
            if "${{ secrets." in auth_job:
                errors.append(
                    f"{relative}: release authentication must not receive GitHub secrets"
                )
            if any(
                marker in auth_job
                for marker in (
                    "id-token:",
                    "attestations:",
                    "artifact-metadata:",
                    "actions/attest@",
                    "cosign",
                )
            ):
                errors.append(
                    f"{relative}: OIDC and provenance authority must not enter the "
                    "release-authentication job"
                )
            lowered_auth = auth_job.lower()
            forbidden_auth_markers = (
                "release_manifest_signing.py sign",
                "--external-signer",
                "--signing-seed",
                "signing_seed",
                "private-key",
                "private_key",
                "development-local-signing",
            )
            if any(marker in lowered_auth for marker in forbidden_auth_markers):
                errors.append(
                    f"{relative}: release authentication must be verification-only "
                    "and must not receive private signing material"
                )
            if (
                auth_job.count(
                    "python3 scripts/release_manifest_signing.py verify"
                )
                != 2
            ):
                errors.append(
                    f"{relative}: release authentication must verify both the "
                    "protected tuple and its staged public snapshot"
                )
            if (
                auth_job.count(
                    "python3 scripts/generate_sorafs_cli_release_manifest.py check"
                )
                != 1
            ):
                errors.append(
                    f"{relative}: release authentication must reconcile the signed "
                    "manifest with the downloaded candidates exactly once"
                )
            try:
                reconcile = auth_job.index(
                    "name: Reconcile the foundational manifest with the immutable candidates"
                )
                external_verify = auth_job.index(
                    "name: Verify the protected external Ed25519 manifest tuple"
                )
                first_native_verify = auth_job.index(
                    "python3 scripts/release_manifest_signing.py verify"
                )
                stage_signature = auth_job.index(
                    '"$evidence_dir/release_manifest.json.sig"'
                )
                second_native_verify = auth_job.index(
                    "python3 scripts/release_manifest_signing.py verify",
                    first_native_verify + 1,
                )
                upload_auth = auth_job.index(
                    "name: Upload authenticated foundational manifest tuple"
                )
            except ValueError:
                pass
            else:
                if not (
                    reconcile
                    < external_verify
                    <= first_native_verify
                    < stage_signature
                    < second_native_verify
                    < upload_auth
                ):
                    errors.append(
                        f"{relative}: candidate reconciliation, external "
                        "verification, public snapshot, replay verification, and "
                        "authentication upload are out of order"
                    )
        if promotion_job is None:
            errors.append(f"{relative}: missing release promotion job")
        else:
            if promotion_guard not in promotion_job:
                errors.append(
                    f"{relative}: release promotion lacks the reviewed trigger guard"
                )
            if (
                "needs: [release-gate, package, verify-release-auth]"
                not in promotion_job
            ):
                errors.append(
                    f"{relative}: release promotion must depend on protected "
                    "Ed25519 manifest authentication"
                )
            if (
                promotion_job.count(
                    "python3 scripts/generate_sorafs_cli_release_manifest.py check"
                )
                != 1
            ):
                errors.append(
                    f"{relative}: release promotion must reconcile the downloaded "
                    "authenticated manifest with the exact candidate inventory"
                )
        if supply_chain_job is None:
            errors.append(
                f"{relative}: missing reference-SDK supply-chain evidence job"
            )
        else:
            required_bindings = (
                "SORAFS_REFERENCE_SDK_DEPLOYMENT_ID: "
                "${{ vars.SORAFS_REFERENCE_SDK_DEPLOYMENT_ID }}",
                "SORAFS_REFERENCE_SDK_RECEIPTS_ROOT: "
                "${{ vars.SORAFS_REFERENCE_SDK_RECEIPTS_ROOT }}",
                "SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX: "
                "${{ vars.SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX }}",
                "SORAFS_TRUSTED_GH_CLI_SHA256: "
                "${{ vars.SORAFS_TRUSTED_GH_CLI_SHA256 }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_SUMMARY_PATH: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SUMMARY_PATH }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_ENVELOPE_PATH: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_ENVELOPE_PATH }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_KEY_REVISION: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_KEY_REVISION }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_REVISION: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_REVISION }}",
                "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_DIGEST_HEX: "
                "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_DIGEST_HEX }}",
            )
            if promotion_guard not in supply_chain_job:
                errors.append(
                    f"{relative}: reference-SDK source evidence lacks the "
                    "reviewed promotion trigger guard"
                )
            if "needs: [release-gate, sign]" not in supply_chain_job:
                errors.append(
                    f"{relative}: reference-SDK source evidence must consume "
                    "the authenticated signed release"
                )
            if "environment: sorafs-reference-sdk-evidence" not in supply_chain_job:
                errors.append(
                    f"{relative}: reference-SDK source evidence must use its "
                    "protected environment"
                )
            if (
                "runs-on: [self-hosted, linux, x64, sorafs-release-auth]"
                not in supply_chain_job
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must use the "
                    "protected self-hosted release runner"
                )
            if any(binding not in supply_chain_job for binding in required_bindings):
                errors.append(
                    f"{relative}: reference-SDK source evidence is missing an "
                    "external receipt, topology, or public-key binding"
                )
            if "${{ secrets." in supply_chain_job:
                errors.append(
                    f"{relative}: reference-SDK source evidence must not "
                    "receive GitHub secrets"
                )
            if any(
                marker in supply_chain_job
                for marker in (
                    "id-token:",
                    "attestations:",
                    "artifact-metadata:",
                    "actions/attest@",
                    "cosign sign-blob",
                )
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must remain "
                    "verification-only"
                )
            if any(
                marker in supply_chain_job.lower()
                for marker in (
                    "private-key",
                    "private_key",
                    "--external-signer",
                    "signing-seed",
                    "signing_seed",
                )
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must remain "
                    "verification-only"
                )
            required_source_flags = (
                "--supply-chain-source-root sf11-source",
                "--provenance-certificate-identity \"$certificate_identity\"",
                "--provenance-oidc-issuer \"$oidc_issuer\"",
                "$SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX",
            )
            if any(
                marker not in supply_chain_job for marker in required_source_flags
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must pass the "
                    "source root and exact public provenance trust tuple"
                )
            repeated_source_flags = (
                '--provenance-certificate-identity "$certificate_identity"',
                '--provenance-oidc-issuer "$oidc_issuer"',
            )
            if any(
                supply_chain_job.count(marker) != 2
                for marker in repeated_source_flags
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must pass the "
                    "source root and exact public provenance trust tuple"
                )
            expected_commands = (
                "python3 scripts/build_sorafs_reference_sdk_supply_chain_sources.py",
                "python3 scripts/build_sorafs_reference_sdk_release_canary.py",
                "python3 scripts/check_sorafs_reference_sdk_release_evidence.py",
                'gh attestation verify "$provenance_file"',
                "cosign verify-blob",
                "sha256sum --check SHA256SUMS",
            )
            if any(
                supply_chain_job.count(command) != 1
                for command in expected_commands
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must assemble, "
                    "build, verify, and provenance-check exactly once"
                )
            required_source_targets = re.search(
                r"(?ms)^\s+required_targets=\(\n"
                r"(?P<targets>.*?)^\s+\)$",
                supply_chain_job,
            )
            if required_source_targets is None:
                errors.append(
                    f"{relative}: reference-SDK source evidence lacks the "
                    "canonical five-target inventory"
                )
            else:
                source_targets = tuple(
                    line.strip()
                    for line in required_source_targets.group("targets").splitlines()
                    if line.strip()
                )
                if source_targets != SUPPLY_CHAIN_SOURCE_TARGETS:
                    errors.append(
                        f"{relative}: reference-SDK source evidence target "
                        "inventory must match the canonical source order"
                    )
            required_provenance_files = re.search(
                r"(?ms)^\s+provenance_files=\(\n"
                r"(?P<files>.*?)^\s+\)$",
                supply_chain_job,
            )
            expected_provenance_files = (
                '"$archive"',
                '"${candidate}/SHA256SUMS"',
                '"${candidate}/sorafs-release.spdx.json"',
                '"${candidate}/sorafs-release-vulnerabilities.sarif"',
                '"${candidate}/sorafs-cli-${target}.spdx.json"',
                '"${candidate}/sorafs-cli-${target}-vulnerabilities.sarif"',
            )
            if required_provenance_files is None:
                errors.append(
                    f"{relative}: reference-SDK source evidence lacks the "
                    "exact six-file provenance inventory"
                )
            else:
                provenance_files = tuple(
                    line.strip()
                    for line in required_provenance_files.group("files").splitlines()
                    if line.strip()
                )
                if provenance_files != expected_provenance_files:
                    errors.append(
                        f"{relative}: reference-SDK source evidence provenance "
                        "inventory must cover the exact checksum, archive, and "
                        "scan files"
                    )
            for marker in (
                "! -name '*.sigstore.json'",
                "signed candidate SHA256SUMS contains duplicate entries",
                "signed candidate SHA256SUMS does not cover the exact candidate file set",
            ):
                if supply_chain_job.count(marker) != 1:
                    errors.append(
                        f"{relative}: reference-SDK source evidence must "
                        "reconcile the signed checksum manifest with the exact "
                        "candidate inventory"
                    )
            if (
                'actual_gh_sha256="$(sha256sum -- "$gh_path" | cut -d \' \' -f1)"'
                not in supply_chain_job
                or '[[ "$actual_gh_sha256" != "$SORAFS_TRUSTED_GH_CLI_SHA256" ]]'
                not in supply_chain_job
            ):
                errors.append(
                    f"{relative}: reference-SDK source evidence must pin the "
                    "GitHub attestation verifier by protected SHA-256"
                )
            if (
                'workspace_real="$(realpath -e -- "$GITHUB_WORKSPACE")"'
                not in supply_chain_job
                or 'path_real="$(realpath -e -- "$path")"'
                not in supply_chain_job
                or '[[ "$path" != "$path_real" ]]'
                not in supply_chain_job
            ):
                errors.append(
                    f"{relative}: reference-SDK external evidence paths must "
                    "be canonicalized before workspace exclusion"
                )
            if (
                "name: Upload replay-complete SF-11 supply-chain evidence"
                not in supply_chain_job
                or re.search(
                    r"(?m)^\s{12}sf11-source/$",
                    supply_chain_job,
                )
                is None
            ):
                errors.append(
                    f"{relative}: reference-SDK evidence upload must retain "
                    "the complete replay source tree"
                )
            for marker in (
                "SIGNED_INPUT_ARTIFACT_ID: ${{ needs.sign.outputs.signed_artifact_id }}",
                "SIGNED_INPUT_ARTIFACT_DIGEST: ${{ needs.sign.outputs.signed_artifact_digest }}",
                "SIGNED_INPUT_ARTIFACT_URL: ${{ needs.sign.outputs.signed_artifact_url }}",
                '"schema": "sorafs.reference_sdk.signed_input_artifact.v1"',
            ):
                if supply_chain_job.count(marker) != 1:
                    errors.append(
                        f"{relative}: reference-SDK evidence must retain the "
                        "immutable signed-input artifact identity and digest"
                    )
            topology_archive = (
                "artifacts/reference-sdk-evidence/"
                "l1-topology-qualification.summary.json"
            )
            if supply_chain_job.count(topology_archive) != 2:
                errors.append(
                    f"{relative}: reference-SDK evidence must gate and archive "
                    "the exact topology qualification summary"
                )
            topology_envelope_archive = (
                "artifacts/reference-sdk-evidence/"
                "l1-topology-qualification.envelope.json"
            )
            signed_topology_markers = (
                topology_envelope_archive,
                "sorafs.l1.deployment_qualification.trust.v1",
                "--topology-qualification-envelope",
                "--topology-qualification-verification-public-key-hex",
                "--topology-qualification-signer-service-id",
                "--topology-qualification-signer-administrator-id",
                "--topology-qualification-signer-key-revision",
                "--topology-qualification-signer-policy-revision",
                "--topology-qualification-signer-policy-digest-hex",
                "--max-topology-qualification-review-age-secs 1209600",
            )
            if (
                supply_chain_job.count(topology_envelope_archive) != 2
                or any(
                    supply_chain_job.count(marker) != 1
                    for marker in signed_topology_markers[1:]
                )
            ):
                errors.append(
                    f"{relative}: reference-SDK evidence must authenticate and "
                    "archive the independently signed topology envelope"
                )
            if re.search(r"(?m)^\s*['\"]signer_backend['\"]\s*:", supply_chain_job):
                errors.append(
                    f"{relative}: topology trust must not claim a signing backend"
                )
            if (
                '[[ "$SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX" '
                '== "$SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX" ]]'
                not in supply_chain_job
            ):
                errors.append(
                    f"{relative}: topology and provenance evidence must use "
                    "independently administered verification keys"
                )
            if (
                '[[ "$SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID" '
                '== "$SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID" ]]'
                not in supply_chain_job
            ):
                errors.append(
                    f"{relative}: topology signer service and administrator "
                    "identities must be independently administered"
                )
            try:
                download_signed = supply_chain_job.index(
                    "name: Download the authenticated signed release input"
                )
                record_signed = supply_chain_job.index(
                    "name: Record the immutable signed-input artifact binding"
                )
                require_external = supply_chain_job.index(
                    "name: Require protected external source-evidence inputs"
                )
                verify_provenance = supply_chain_job.index(
                    "name: Reverify exact target provenance before source assembly"
                )
                assemble_sources = supply_chain_job.index(
                    "name: Assemble and validate the canonical SF-11 source indexes"
                )
                build_canary = supply_chain_job.index(
                    "name: Build and gate source-derived SF-11 supply-chain evidence"
                )
                upload_evidence = supply_chain_job.index(
                    "name: Upload replay-complete SF-11 supply-chain evidence"
                )
            except ValueError:
                pass
            else:
                if not (
                    download_signed
                    < record_signed
                    < require_external
                    < verify_provenance
                    < assemble_sources
                    < build_canary
                    < upload_evidence
                ):
                    errors.append(
                        f"{relative}: signed input, external trust, provenance "
                        "verification, source assembly, gate, and upload are out "
                        "of order"
                    )

        package_matrix = re.search(
            r"(?ms)^  package:\n.*?^      matrix:\n"
            r"(?P<matrix>.*?)^    runs-on: \$\{\{ matrix\.os \}\}",
            source,
        )
        if package_matrix is None:
            errors.append(f"{relative}: malformed native release matrix")
        else:
            target_runners = tuple(
                re.findall(
                    r"(?m)^          - os: ([^\s#]+)\n"
                    r"            target: ([^\s#]+)$",
                    package_matrix.group("matrix"),
                )
            )
            if target_runners != RELEASE_TARGET_RUNNERS:
                errors.append(
                    f"{relative}: native release matrix must contain exactly the "
                    "reviewed Linux, macOS, and Windows target/runner pairs"
                )
        try:
            global_permissions = source[
                source.index("permissions:") : source.index("concurrency:")
            ]
            sign_job = source[source.index("  sign:") :]
        except ValueError:
            errors.append(f"{relative}: malformed permissions or signing job")
        else:
            global_elevated = [
                permission
                for permission in ("id-token:", "attestations:", "artifact-metadata:")
                if permission in global_permissions
            ]
            if global_elevated:
                errors.append(
                    f"{relative}: OIDC and attestation permissions must be signing-job scoped"
                )
            if "permissions:" not in sign_job or "id-token: write" not in sign_job:
                errors.append(f"{relative}: signing job must request OIDC explicitly")
            for permission in ("attestations: write", "artifact-metadata: write"):
                if permission not in sign_job:
                    errors.append(
                        f"{relative}: signing job must request `{permission}` explicitly"
                    )
            if "if: ${{ startsWith(github.ref, 'refs/tags/sorafs-cli-v') || inputs.sign_artifacts }}" not in sign_job:
                errors.append(f"{relative}: signing job lacks the reviewed trigger guard")
            for output in (
                "signed_artifact_id: ${{ steps.upload-signed.outputs.artifact-id }}",
                "signed_artifact_digest: ${{ steps.upload-signed.outputs.artifact-digest }}",
                "signed_artifact_url: ${{ steps.upload-signed.outputs.artifact-url }}",
                "id: upload-signed",
            ):
                if sign_job.count(output) != 1:
                    errors.append(
                        f"{relative}: signing job must expose the immutable "
                        "signed-artifact identity, digest, and URL"
                    )
            required_targets = re.search(
                r"(?ms)^\s+required_targets=\(\n"
                r"(?P<targets>.*?)^\s+\)$",
                sign_job,
            )
            expected_targets = tuple(
                target for _runner, target in RELEASE_TARGET_RUNNERS
            )
            if required_targets is None:
                errors.append(
                    f"{relative}: signing job lacks the mandatory target inventory"
                )
            else:
                signed_targets = tuple(
                    line.strip()
                    for line in required_targets.group("targets").splitlines()
                    if line.strip()
                )
                if signed_targets != expected_targets:
                    errors.append(
                        f"{relative}: signing job target inventory must exactly "
                        "match the native release matrix"
                    )
            try:
                verify_manifest_binding = sign_job.index(
                    "name: Verify authenticated release-manifest candidate binding before provenance"
                )
                verify_checksums = sign_job.index(
                    "name: Verify platform package checksums before signing"
                )
                attest = sign_job.index(
                    "name: Attest aggregate signed-input provenance"
                )
                stage_attestations = sign_job.index("name: Stage offline provenance bundles")
                sign_blobs = sign_job.index("name: Keyless-sign every release-candidate file")
                upload_signed = sign_job.index("name: Upload signed release candidate")
            except ValueError:
                pass
            else:
                if not (
                    verify_manifest_binding
                    < verify_checksums
                    < attest
                    < stage_attestations
                    < sign_blobs
                    < upload_signed
                ):
                    errors.append(
                        f"{relative}: checksum verification, provenance, signing, and upload are out of order"
                    )
        sbom_action = "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610"
        scan_action = "anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2"
        if source.count(sbom_action) != 2 or source.count(scan_action) != 2:
            errors.append(
                f"{relative}: source and platform packages require exactly one SBOM and vulnerability scan each"
            )
        if source.count("grype-version: v0.112.0") != 2:
            errors.append(
                f"{relative}: source and platform scans must both pin Grype v0.112.0"
            )
        try:
            package_reference = source.index("name: Package Iroha CLI and SoraFS FFI header")
            reproducible_archive = source.index(
                "name: Rebuild deterministic platform archive and run clean-consumer smoke"
            )
            stage_source_scan = source.index("name: Stage source release scan evidence")
            binary_sbom = source.index("name: Generate platform binary SBOM")
            binary_scan = source.index("name: Scan platform binary SBOM")
            checksums = source.index("name: Finalize platform checksums")
            upload = source.index("name: Upload unsigned release candidate")
        except ValueError:
            pass
        else:
            if not (
                package_reference
                < reproducible_archive
                < stage_source_scan
                < binary_sbom
                < binary_scan
                < checksums
                < upload
            ):
                errors.append(
                    f"{relative}: reference packaging, reproducible archive, "
                    "source evidence, platform SBOM, scan, checksum, and upload "
                    "steps are out of order"
                )
        if source.count("python3 scripts/package_sorafs_cli_candidate.py") != 2:
            errors.append(
                f"{relative}: deterministic platform candidate must be built "
                "exactly twice for byte-identical replay"
            )
        if source.count("bash scripts/package_iroha_cli_release.sh") != 2:
            errors.append(
                f"{relative}: deterministic reference-validator package must be "
                "built exactly twice for byte-identical replay"
            )
        if source.count('--source-commit "$source_commit"') != 2:
            errors.append(
                f"{relative}: both reference-validator package replays must bind "
                "the reviewed source commit"
            )
        if source.count('--source-date-epoch "$source_date_epoch"') != 2:
            errors.append(
                f"{relative}: both reference-validator package replays must bind "
                "the canonical source epoch"
            )
        if source.count('cmp \\\n            "${first_out}/${package_name}') != 2:
            errors.append(
                f"{relative}: platform archive and manifest replay comparisons "
                "must both be enforced"
            )
    return errors


def validate_release_automation(root: Path) -> dict[str, Any]:
    """Validate every committed SoraFS workflow and return a closed summary."""

    errors: list[str] = []
    validated: list[str] = []
    for relative in sorted(WORKFLOWS):
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{relative}: workflow must be UTF-8") from error
        errors.extend(_validate_workflow_source(relative, source))
        validated.append(relative)
    errors.extend(_validate_sorafs_cli_release_gate(root))
    for relative, markers in sorted(RELEASE_VERSION_MAP_CONTRACT_MARKERS.items()):
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"{relative}: release-version contract source must be UTF-8"
            ) from error
        for marker in markers:
            if marker not in source:
                errors.append(
                    f"{relative}: missing CLI release-version contract marker "
                    f"`{marker}`"
                )
    for relative, markers in sorted(RELEASE_DOCUMENTS.items()):
        path = _require_regular_repo_file(root, relative)
        try:
            source = _read_bytes_no_follow(path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{relative}: release document must be UTF-8") from error
        for marker in markers:
            if marker not in source:
                errors.append(
                    f"{relative}: missing release-document contract marker `{marker}`"
                )
        for stale_claim in FORBIDDEN_RELEASE_DOCUMENT_CLAIMS.get(relative, ()):
            if stale_claim in source:
                errors.append(
                    f"{relative}: stale release-document claim `{stale_claim}`"
                )
    errors.extend(_validate_release_auth_document_tree(root))
    errors.extend(_validate_package_release_smoke(root))
    errors.extend(_validate_reference_sdk_release_examples(root))
    errors.extend(_validate_native_governance_sdk_contract(root))
    errors.extend(_javascript_child_source_controls_errors(_read_bytes_no_follow(
        _require_regular_repo_file(root, SORAFS_JAVASCRIPT_PARITY_RUNNER)
    ).decode("utf-8")))
    errors.extend(_validate_runtime_provider_deployment_contract(root))
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "schema": SCHEMA,
        "workflow_count": len(validated),
        "workflows": validated,
    }


def main() -> int:
    """Run the release-automation validator from the repository root."""

    try:
        summary = validate_release_automation(SCRIPT_DIR.parent)
    except (OSError, ValueError) as error:
        print(f"error: invalid SoraFS release automation: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
