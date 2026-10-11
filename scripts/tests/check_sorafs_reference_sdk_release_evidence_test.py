"""Tests for scripts/check_sorafs_reference_sdk_release_evidence.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


TEST_DIR = Path(__file__).resolve().parent
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "check_sorafs_reference_sdk_release_evidence.py"
)
SPEC = importlib.util.spec_from_file_location(
    "check_sorafs_reference_sdk_release_evidence",
    MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader  # pragma: no cover - defensive
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

from sorafs_reference_sdk_supply_chain import (  # noqa: E402
    SourceArtifactBinding,
    SupplyChainSourceResult,
    SupplyChainTargetResult,
)
import sorafs_topology_qualification as TOPOLOGY  # noqa: E402
from sorafs_resilience_test_support import (  # noqa: E402
    public_key_from_seed,
    sign,
)


NOW_UNIX = 1_800_700_000
GENERATED_AT = NOW_UNIX - 120
DEPLOYMENT_ID = "reference-sdk-release-2026-06"
ENVIRONMENT = "production"
DIGEST = "12" * 32
DIGEST_2 = "34" * 32
PROVENANCE_CERTIFICATE_IDENTITY = (
    "https://github.com/hyperledger-iroha/iroha/.github/workflows/"
    "sorafs-cli-release.yml@refs/heads/main"
)
PROVENANCE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325"
    "af021a68f707511a"
)
PROVENANCE_VERIFICATION_KEY_FINGERPRINT_HEX = hashlib.sha256(
    bytes.fromhex(PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX)
).hexdigest()
TOPOLOGY_SIGNER_SERVICE_ID = "sorafs-sf11-topology-signer-a"
TOPOLOGY_SIGNER_ADMINISTRATOR_ID = "sorafs-sf11-topology-admin-b"
TOPOLOGY_SIGNER_KEY_REVISION = 7
TOPOLOGY_SIGNER_POLICY_REVISION = 9
TOPOLOGY_SIGNER_POLICY_DIGEST_HEX = hashlib.sha256(
    b"sorafs-sf11-topology-signer-policy-v1"
).hexdigest()
TOPOLOGY_SIGNING_SEED = hashlib.sha256(
    b"sorafs-sf11-topology-qualification-test-key"
).digest()
TOPOLOGY_VERIFICATION_PUBLIC_KEY = public_key_from_seed(TOPOLOGY_SIGNING_SEED)
TOPOLOGY_VERIFICATION_PUBLIC_KEY_HEX = TOPOLOGY_VERIFICATION_PUBLIC_KEY.hex()
TOPOLOGY_MAX_REVIEW_AGE_SECS = 3_600
TOPOLOGY_REVIEWED_AT_UNIX = NOW_UNIX - 60
SOURCE_ARTIFACT_PATHS = {
    "release_rehearsal": "release-rehearsal.json",
    "sbom_index": "sbom-index.json",
    "vulnerability_report": "vulnerability-report.json",
    "provenance_bundle": "provenance-bundle.json",
}
SOURCE_ARTIFACT_DIGESTS = {
    "release_rehearsal": "56" * 32,
    "sbom_index": "78" * 32,
    "vulnerability_report": "9a" * 32,
    "provenance_bundle": "bc" * 32,
}


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def base(schema: str) -> dict:
    return {
        "schema": schema,
        "status": "passed",
        "generated_at_unix": GENERATED_AT,
        "deployment_id": DEPLOYMENT_ID,
        "environment": ENVIRONMENT,
        "deployment_context_reviewed": True,
    }


def release_archive(
    *,
    target_count: int | None = None,
    missing_target: bool = False,
    duplicate_target: bool = False,
) -> dict:
    targets = [
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ]
    if missing_target:
        targets.pop()
    if duplicate_target:
        targets.append(targets[0])
    payload = base("sorafs.reference_sdk.release_archive_canary.v1")
    payload.update(
        {
            "packaging_helper_used": True,
            "deterministic_archive_verified": True,
            "archive_checksums_published": True,
            "binary_checksums_published": True,
            "dist_gitkeep_only_tracked": True,
            "target_count": len(targets) if target_count is None else target_count,
            "targets": targets,
            "archive_index_digest_hex": DIGEST,
            "release_manifest_digest_hex": DIGEST,
            "raw_archives_included": False,
        }
    )
    return payload


def signed_manifest(
    *,
    private_key_absent: bool = True,
    signature_algorithm: str = "ed25519",
    signing_provider: str = "authenticated_external_signer",
    signing_backend: str = "software",
    signing_provider_revision: int = 1,
    signer_response_verified: bool = True,
    policy_digest_hex: str = DIGEST,
    public_key_fingerprint_hex: str = DIGEST,
) -> dict:
    payload = base("sorafs.reference_sdk.signed_manifest_canary.v1")
    payload.update(
        {
            "manifest_signed": True,
            "manifest_signature_verified": True,
            "manifest_sha256_published": True,
            "governed_release_key_used": True,
            "public_key_fingerprint_recorded": True,
            "private_key_absent": private_key_absent,
            "signature_algorithm": signature_algorithm,
            "signing_provider": signing_provider,
            "signing_backend": signing_backend,
            "signing_provider_revision": signing_provider_revision,
            "signer_response_verified": signer_response_verified,
            "manifest_digest_hex": DIGEST,
            "policy_digest_hex": policy_digest_hex,
            "public_key_fingerprint_hex": public_key_fingerprint_hex,
            "raw_manifest_included": False,
        }
    )
    return payload


def supply_chain(
    *,
    high_vulnerability_count: int = 0,
    missing_target: bool = False,
) -> dict:
    targets = list(MODULE.REQUIRED_RELEASE_TARGETS)
    if missing_target:
        targets.pop()
    payload = base("sorafs.reference_sdk.supply_chain_canary.v1")
    payload.update(
        {
            "target_count": len(targets),
            "target_results": [
                {
                    "target": target,
                    "binary_smoke_passed": True,
                    "deterministic_archive_replay_passed": True,
                    "installation_verified": True,
                    "rollback_verified": True,
                    "yank_verified": True,
                    "sbom_generated": True,
                    "critical_vulnerability_count": 0,
                    "high_vulnerability_count": high_vulnerability_count,
                    "oidc_identity_verified": True,
                    "cosign_provenance_verified": True,
                }
                for target in targets
            ],
            "source_artifacts": [
                {
                    "kind": kind,
                    "artifact_path": SOURCE_ARTIFACT_PATHS[kind],
                    "sha256": SOURCE_ARTIFACT_DIGESTS[kind],
                }
                for kind in MODULE.SOURCE_ARTIFACT_KINDS
            ],
            "release_manifest_digest_hex": DIGEST,
            "sbom_index_digest_hex": SOURCE_ARTIFACT_DIGESTS["sbom_index"],
            "vulnerability_report_digest_hex": SOURCE_ARTIFACT_DIGESTS[
                "vulnerability_report"
            ],
            "provenance_bundle_digest_hex": SOURCE_ARTIFACT_DIGESTS[
                "provenance_bundle"
            ],
            "provenance_certificate_identity": (
                PROVENANCE_CERTIFICATE_IDENTITY
            ),
            "provenance_oidc_issuer": PROVENANCE_OIDC_ISSUER,
            "provenance_verification_key_fingerprint_hex": (
                PROVENANCE_VERIFICATION_KEY_FINGERPRINT_HEX
            ),
            "raw_sboms_included": False,
            "raw_vulnerability_reports_included": False,
            "raw_provenance_included": False,
        }
    )
    return payload


def downstream_bindings(
    *,
    package_count: int | None = None,
    missing_package: bool = False,
    duplicate_package: bool = False,
) -> dict:
    packages = ["javascript", "python", "kotlin_jvm", "java_android", "swift", "csharp"]
    if missing_package:
        packages.pop()
    if duplicate_package:
        packages.append(packages[0])
    payload = base("sorafs.reference_sdk.downstream_bindings_canary.v1")
    payload.update(
        {
            "packages": packages,
            "package_count": len(packages) if package_count is None else package_count,
            "sdk_exports_verified": True,
            "validation_outcome_contract_verified": True,
            "version_alignment_verified": True,
            "native_bridge_header_bound": True,
            "published_package_digests_recorded": True,
            "release_manifest_digest_hex": DIGEST,
            "package_index_digest_hex": DIGEST,
            "raw_packages_included": False,
        }
    )
    return payload


def cookbook_smoke(*, duration: int = 600) -> dict:
    payload = base("sorafs.reference_sdk.cookbook_smoke_canary.v1")
    payload.update(
        {
            "published_archive_smoke_passed": True,
            "cookbook_replay_passed": True,
            "fixture_bundle_validation_passed": True,
            "manifest_car_replay_passed": True,
            "validation_outcomes_emitted": True,
            "smoke_duration_seconds": duration,
            "release_manifest_digest_hex": DIGEST,
            "smoke_output_digest_hex": DIGEST,
            "raw_smoke_outputs_included": False,
        }
    )
    return payload


def ffi_header_contract(*, ci_guard: bool = True) -> dict:
    payload = base("sorafs.reference_sdk.ffi_header_contract_canary.v1")
    payload.update(
        {
            "ci_guard_passed": ci_guard,
            "rust_exports_match_header": True,
            "selector_constants_match": True,
            "c_signatures_match": True,
            "bridge_bindings_verified": True,
            "release_manifest_digest_hex": DIGEST,
            "header_digest_hex": DIGEST,
            "ffi_contract_digest_hex": DIGEST,
            "raw_header_included": False,
        }
    )
    return payload


def governance_approval(*, source: str = "governed_release") -> dict:
    payload = base("sorafs.reference_sdk.governance_approval.v1")
    payload.update(
        {
            "approved": True,
            "governance_vote_recorded": True,
            "release_key_roster_bound": True,
            "release_targets_bound": True,
            "downstream_packages_bound": True,
            "smoke_evidence_bound": True,
            "governance_source": source,
            "release_manifest_digest_hex": DIGEST,
            "policy_digest_hex": DIGEST,
            "public_key_fingerprint_hex": DIGEST,
        }
    )
    return payload


def write_complete_evidence(root: Path) -> None:
    write_json(root / "release-archive.json", release_archive())
    write_json(root / "signed-manifest.json", signed_manifest())
    write_json(root / "supply-chain.json", supply_chain())
    write_json(root / "downstream-bindings.json", downstream_bindings())
    write_json(root / "cookbook-smoke.json", cookbook_smoke())
    write_json(root / "ffi-header-contract.json", ffi_header_contract())
    write_json(root / "governance-approval.json", governance_approval())


def source_validation_result(
    *,
    deployment_id: str = DEPLOYMENT_ID,
    environment: str = ENVIRONMENT,
    release_manifest_digest_hex: str = DIGEST,
    release_rehearsal_path: str = SOURCE_ARTIFACT_PATHS["release_rehearsal"],
    sbom_index_path: str = SOURCE_ARTIFACT_PATHS["sbom_index"],
    vulnerability_report_path: str = SOURCE_ARTIFACT_PATHS[
        "vulnerability_report"
    ],
    provenance_bundle_path: str = SOURCE_ARTIFACT_PATHS["provenance_bundle"],
) -> SupplyChainSourceResult:
    """Return the checker layer's deterministic source-validator result."""

    canonical_payload = supply_chain()
    paths = {
        "release_rehearsal": release_rehearsal_path,
        "sbom_index": sbom_index_path,
        "vulnerability_report": vulnerability_report_path,
        "provenance_bundle": provenance_bundle_path,
    }
    return SupplyChainSourceResult(
        generated_at_unix=GENERATED_AT,
        deployment_id=deployment_id,
        environment=environment,
        release_manifest_digest_hex=release_manifest_digest_hex,
        source_artifacts=tuple(
            SourceArtifactBinding(
                kind,
                paths[kind],
                SOURCE_ARTIFACT_DIGESTS[kind],
            )
            for kind in MODULE.SOURCE_ARTIFACT_KINDS
        ),
        target_results=tuple(
            SupplyChainTargetResult(**target_result)
            for target_result in canonical_payload["target_results"]
        ),
        sbom_index_digest_hex=SOURCE_ARTIFACT_DIGESTS["sbom_index"],
        vulnerability_report_digest_hex=SOURCE_ARTIFACT_DIGESTS[
            "vulnerability_report"
        ],
        provenance_bundle_digest_hex=SOURCE_ARTIFACT_DIGESTS[
            "provenance_bundle"
        ],
    )


def deterministic_supply_chain_source_validation_stub(
    _source_root: Path,
    **kwargs,
) -> tuple[SupplyChainSourceResult, list[str]]:
    """Return deterministic source validation without requiring pytest fixtures."""

    assert (
        kwargs["expected_verification_key_fingerprint_hex"]
        == PROVENANCE_VERIFICATION_KEY_FINGERPRINT_HEX
    )
    assert callable(kwargs["verification_receipt_authenticator"])
    return (
        source_validation_result(
            deployment_id=kwargs["expected_deployment_id"],
            environment=kwargs["expected_environment"],
            release_manifest_digest_hex=(
                kwargs["expected_release_manifest_digest_hex"]
            ),
            release_rehearsal_path=kwargs["release_rehearsal_path"],
            sbom_index_path=kwargs["sbom_index_path"],
            vulnerability_report_path=kwargs["vulnerability_report_path"],
            provenance_bundle_path=kwargs["provenance_bundle_path"],
        ),
        [],
    )


@pytest.fixture(autouse=True)
def deterministic_supply_chain_source_validation(monkeypatch) -> None:
    """Keep checker-layer tests independent from the validator's E2E corpus."""

    monkeypatch.setattr(
        MODULE,
        "validate_supply_chain_sources",
        deterministic_supply_chain_source_validation_stub,
    )


RELEASE_MANIFEST_BOUND_FIXTURES = (
    ("release_archive", "release-archive.json", release_archive),
    ("supply_chain", "supply-chain.json", supply_chain),
    ("downstream_bindings", "downstream-bindings.json", downstream_bindings),
    ("cookbook_smoke", "cookbook-smoke.json", cookbook_smoke),
    ("ffi_header_contract", "ffi-header-contract.json", ffi_header_contract),
    ("governance_approval", "governance-approval.json", governance_approval),
)

POLICY_BOUND_FIXTURES = (
    ("governance_approval", "governance-approval.json", governance_approval),
)

RELEASE_KEY_BOUND_FIXTURES = (
    ("governance_approval", "governance-approval.json", governance_approval),
)


def write_topology_qualification(
    root: Path,
    *,
    deployment_id: str = DEPLOYMENT_ID,
    environment: str = ENVIRONMENT,
    reviewed_at_unix: int = TOPOLOGY_REVIEWED_AT_UNIX,
) -> Path:
    path = root / "l1-topology-qualification.summary"
    payload = {
        "schema": "sorafs.l1.deployment_qualification.summary.v1",
        "status": "configuration-qualified",
        "qualification_scope": "pre-deployment-configuration",
        "live_evidence_recognized": False,
        "promotion_eligible": False,
        "manifest_sha256": hashlib.sha256(b"release-manifest").hexdigest(),
        "canonical_manifest_sha256": hashlib.sha256(
            b"canonical-release-manifest"
        ).hexdigest(),
        "deployment": {
            "deployment_id": deployment_id,
            "environment": environment,
            "network": "taira",
            "chain_id": "fc56984b-2be7-431d-840e-21514d1883f0",
            "chain_discriminant": 369,
        },
        "validator_count": 4, "validator_ids": ["taira-validator-1", "taira-validator-2", "taira-validator-3", "taira-validator-4"],
        "storage_provider_count": 2,
        "gateway_count": 2,
        "governance_dag_instance_count": 2,
        "runtime_handle_kinds": [
            "monitoring",
            "external_signer",
            "key_custody",
            "webauthn",
        ],
        "runtime_material_policy_valid": True,
        "signed_model_artifact_count": 1,
        "required_lane_slots": list(TOPOLOGY.CANONICAL_READINESS_LANES),
        "recognized_lane_slot_count": len(TOPOLOGY.CANONICAL_READINESS_LANES),
        "errors": [],
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    binding, errors = TOPOLOGY.load_topology_qualification_binding(
        path,
        expected_deployment_id=deployment_id,
        expected_environment=environment,
    )
    assert errors == []
    assert binding is not None
    envelope = {
        "schema": TOPOLOGY.SIGNED_QUALIFICATION_ENVELOPE_SCHEMA,
        **binding,
        "signer_authentication_kind": "external-ed25519",
        "signer_service_id": TOPOLOGY_SIGNER_SERVICE_ID,
        "signer_administrator_id": TOPOLOGY_SIGNER_ADMINISTRATOR_ID,
        "signer_key_revision": TOPOLOGY_SIGNER_KEY_REVISION,
        "signer_policy_revision": TOPOLOGY_SIGNER_POLICY_REVISION,
        "signer_public_key_fingerprint_sha256": hashlib.sha256(
            TOPOLOGY_VERIFICATION_PUBLIC_KEY
        ).hexdigest(),
        "signer_policy_digest_sha256": TOPOLOGY_SIGNER_POLICY_DIGEST_HEX,
        "reviewed_at_unix": reviewed_at_unix,
        "signature_algorithm": "ed25519",
        "signature_hex": "00" * 64,
    }
    envelope["signature_hex"] = sign(
        TOPOLOGY_SIGNING_SEED,
        TOPOLOGY.topology_qualification_envelope_signing_bytes(envelope),
    ).hex()
    write_json(topology_envelope_path(path), envelope)
    return path


def topology_envelope_path(qualification_path: Path) -> Path:
    """Return the deterministic signed companion path for a topology summary."""

    return qualification_path.with_name(f"{qualification_path.name}.ed25519")


def topology_cli_args(
    qualification_path: Path,
    *,
    omit: frozenset[str] = frozenset(),
) -> list[str]:
    """Return the independently trusted signed-topology checker arguments."""

    options = (
        ("--topology-qualification-summary", str(qualification_path)),
        (
            "--topology-qualification-envelope",
            str(topology_envelope_path(qualification_path)),
        ),
        (
            "--topology-qualification-verification-public-key-hex",
            TOPOLOGY_VERIFICATION_PUBLIC_KEY_HEX,
        ),
        (
            "--topology-qualification-signer-service-id",
            TOPOLOGY_SIGNER_SERVICE_ID,
        ),
        (
            "--topology-qualification-signer-administrator-id",
            TOPOLOGY_SIGNER_ADMINISTRATOR_ID,
        ),
        (
            "--topology-qualification-signer-key-revision",
            str(TOPOLOGY_SIGNER_KEY_REVISION),
        ),
        (
            "--topology-qualification-signer-policy-revision",
            str(TOPOLOGY_SIGNER_POLICY_REVISION),
        ),
        (
            "--topology-qualification-signer-policy-digest-hex",
            TOPOLOGY_SIGNER_POLICY_DIGEST_HEX,
        ),
        (
            "--max-topology-qualification-review-age-secs",
            str(TOPOLOGY_MAX_REVIEW_AGE_SECS),
        ),
    )
    return [
        argument
        for option, value in options
        if option not in omit
        for argument in (option, value)
    ]


def supply_chain_cli_args(
    root: Path,
    *,
    omit: frozenset[str] = frozenset(),
) -> list[str]:
    """Return the checker trust/source arguments, minus selected flags."""

    options = (
        ("--supply-chain-source-root", str(root)),
        (
            "--provenance-certificate-identity",
            PROVENANCE_CERTIFICATE_IDENTITY,
        ),
        ("--provenance-oidc-issuer", PROVENANCE_OIDC_ISSUER),
        (
            "--provenance-verification-public-key-hex",
            PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX,
        ),
    )
    return [
        argument
        for option, value in options
        if option not in omit
        for argument in (option, value)
    ]


def run_gate(
    root: Path,
    *extra: str,
    topology: Path | None = None,
) -> int:
    qualification_path = (
        write_topology_qualification(root) if topology is None else topology
    )
    return MODULE.main(
        [
            "--evidence-dir",
            str(root),
            "--now-unix",
            str(NOW_UNIX),
            *topology_cli_args(qualification_path),
            *supply_chain_cli_args(root),
            *extra,
        ]
    )


def run_gate_omitting_supply_chain_args(
    root: Path,
    omitted: frozenset[str],
    *extra: str,
) -> int:
    """Run the checker without selected source/trust arguments."""

    qualification_path = write_topology_qualification(root)
    return MODULE.main(
        [
            "--evidence-dir",
            str(root),
            "--now-unix",
            str(NOW_UNIX),
            *topology_cli_args(qualification_path),
            *supply_chain_cli_args(root, omit=omitted),
            *extra,
        ]
    )


def test_complete_metadata_evidence_cannot_qualify_release(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["schema"] == "sorafs.reference_sdk.release_evidence_gate.v1"
    assert payload["status"] == "blocked"
    assert payload["valid_archive_index_digests"] == [DIGEST]
    assert payload["valid_ffi_contract_digests"] == [DIGEST]
    assert payload["valid_header_digests"] == [DIGEST]
    assert payload["valid_package_index_digests"] == [DIGEST]
    assert payload["valid_provenance_bundle_digests"] == [
        SOURCE_ARTIFACT_DIGESTS["provenance_bundle"]
    ]
    assert payload["valid_release_manifest_digests"] == []
    assert payload["valid_release_manifest_reference_digests"] == []
    assert payload["valid_release_key_fingerprints"] == []
    assert payload["valid_sbom_index_digests"] == [
        SOURCE_ARTIFACT_DIGESTS["sbom_index"]
    ]
    assert payload["signature_algorithms"] == []
    signed_manifest_artifact = payload["required"]["signed_manifest"]["artifacts"][0]
    assert signed_manifest_artifact["fingerprint"]["signature_algorithm"] == "ed25519"
    supply_chain_artifact = payload["required"]["supply_chain"]["artifacts"][0]
    assert supply_chain_artifact["fingerprint"]["source_artifacts"] == supply_chain()[
        "source_artifacts"
    ]
    source_digests = [
        artifact["sha256"]
        for artifact in supply_chain_artifact["fingerprint"]["source_artifacts"]
    ]
    assert len(source_digests) == len(set(source_digests)) == 4
    assert supply_chain_artifact["fingerprint"][
        "provenance_certificate_identity"
    ] == PROVENANCE_CERTIFICATE_IDENTITY
    assert (
        supply_chain_artifact["fingerprint"]["provenance_oidc_issuer"]
        == PROVENANCE_OIDC_ISSUER
    )
    assert (
        supply_chain_artifact["fingerprint"][
            "provenance_verification_key_fingerprint_hex"
        ]
        == PROVENANCE_VERIFICATION_KEY_FINGERPRINT_HEX
    )
    governance_artifact = payload["required"]["governance_approval"]["artifacts"][0]
    assert governance_artifact["fingerprint"]["public_key_fingerprint_hex"] == DIGEST
    assert payload["valid_smoke_output_digests"] == [DIGEST]
    assert payload["valid_vulnerability_report_digests"] == [
        SOURCE_ARTIFACT_DIGESTS["vulnerability_report"]
    ]
    assert payload["valid_policy_digests"] == []
    assert payload["required"]["release_archive"]["valid"] is False

    assert any("independently pinned source context" in error for error in signed_manifest_artifact["errors"])
    assert signed_manifest_artifact["valid"] is False



def test_release_lane_rejects_mismatched_topology_context(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    topology = write_topology_qualification(
        tmp_path,
        deployment_id="different-production-deployment",
    )

    assert (
        MODULE.main(
            [
                "--evidence-dir",
                str(tmp_path),
                "--now-unix",
                str(NOW_UNIX),
                "--summary-out",
                str(summary),
                *topology_cli_args(topology),
                *supply_chain_cli_args(tmp_path),
            ]
        )
        == 1
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["status"] == "blocked"
    assert (
        "topology qualification deployment_id must match the reviewed lane context"
        in payload["errors"]
    )


@pytest.mark.parametrize(
    "omitted",
    [
        "--topology-qualification-envelope",
        "--topology-qualification-verification-public-key-hex",
        "--topology-qualification-signer-service-id",
        "--topology-qualification-signer-administrator-id",
        "--topology-qualification-signer-key-revision",
        "--topology-qualification-signer-policy-revision",
        "--topology-qualification-signer-policy-digest-hex",
    ],
)
def test_signed_topology_trust_arguments_are_mandatory(
    tmp_path: Path,
    omitted: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_complete_evidence(tmp_path)
    topology = write_topology_qualification(tmp_path)

    assert (
        MODULE.main(
            [
                "--evidence-dir",
                str(tmp_path),
                "--now-unix",
                str(NOW_UNIX),
                *topology_cli_args(topology, omit=frozenset({omitted})),
                *supply_chain_cli_args(tmp_path),
            ]
        )
        == 2
    )
    assert omitted in capsys.readouterr().err


def test_checker_preflight_rejects_reused_topology_and_provenance_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_complete_evidence(tmp_path)

    assert (
        run_gate(
            tmp_path,
            "--provenance-verification-public-key-hex",
            TOPOLOGY_VERIFICATION_PUBLIC_KEY_HEX,
        )
        == 2
    )

    captured = capsys.readouterr()
    assert MODULE.INDEPENDENT_VERIFICATION_KEYS_ERROR in captured.err
    assert TOPOLOGY_VERIFICATION_PUBLIC_KEY_HEX not in captured.err
    assert captured.out == ""


def test_release_only_subset_does_not_require_provenance_key(
    tmp_path: Path,
) -> None:
    release_path = write_json(
        tmp_path / "release-archive.json",
        release_archive(),
    )
    topology = write_topology_qualification(tmp_path)
    summary = tmp_path / "summary.json"

    assert (
        MODULE.main(
            [
                "--evidence",
                str(release_path),
                "--require-kind",
                "release_archive",
                "--now-unix",
                str(NOW_UNIX),
                "--summary-out", str(summary),
                *topology_cli_args(topology),
            ]
        )
        == 1
    )
    result = json.loads(summary.read_text())
    assert result["required"]["signed_manifest"]["valid"] is False
    assert not any("provenance" in error for error in result["errors"])


def test_release_lane_rejects_mutated_topology_signature_without_leaking_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_complete_evidence(tmp_path)
    topology = write_topology_qualification(tmp_path)
    envelope_path = topology_envelope_path(topology)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    signature = envelope["signature_hex"]
    replacement_prefix = "00" if signature[:2] != "00" else "01"
    envelope["signature_hex"] = replacement_prefix + signature[2:]
    write_json(envelope_path, envelope)
    summary = tmp_path / "sf11-summary.json"

    assert (
        run_gate(
            tmp_path,
            "--summary-out",
            str(summary),
            topology=topology,
        )
        == 1
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["topology_qualification"] is None
    assert any("signature must authenticate" in error for error in payload["errors"])
    diagnostics = capsys.readouterr().err
    rendered_errors = json.dumps(payload["errors"])
    assert signature not in diagnostics
    assert envelope["signature_hex"] not in diagnostics
    assert signature not in rendered_errors
    assert envelope["signature_hex"] not in rendered_errors


def test_release_lane_rejects_tampered_topology_payload_without_leaking_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_complete_evidence(tmp_path)
    topology = write_topology_qualification(tmp_path)
    topology_payload = json.loads(topology.read_text(encoding="utf-8"))
    secret_marker = "topology-private-payload-must-not-escape"
    topology_payload["private_key"] = secret_marker
    write_json(topology, topology_payload)
    summary = tmp_path / "sf11-summary.json"

    assert (
        run_gate(
            tmp_path,
            "--summary-out",
            str(summary),
            topology=topology,
        )
        == 1
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["topology_qualification"] is None
    assert any("schema-closed contract" in error for error in payload["errors"])
    assert secret_marker not in json.dumps(payload["errors"])
    assert secret_marker not in capsys.readouterr().err


def test_release_lane_rejects_stale_signed_topology_review(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    topology = write_topology_qualification(
        tmp_path,
        reviewed_at_unix=(
            NOW_UNIX - TOPOLOGY_MAX_REVIEW_AGE_SECS - 1
        ),
    )
    summary = tmp_path / "sf11-summary.json"

    assert (
        run_gate(
            tmp_path,
            "--summary-out",
            str(summary),
            topology=topology,
        )
        == 1
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["topology_qualification"] is None
    assert any(
        "review exceeds the maximum age" in error for error in payload["errors"]
    )


def diagnostic_without_fixture_locations(text: str, fixture_root: Path) -> str:
    """Exclude known source-location prefixes while retaining diagnostic values."""
    prefixes = (f"{fixture_root}/", f"- {fixture_root}/")
    lines = []
    for line in text.splitlines():
        for prefix in prefixes:
            if line.startswith(prefix):
                line = f"<evidence>/{line[len(prefix):]}"
                break
        lines.append(line)
    return "\n".join(lines)


@pytest.mark.parametrize("prefix", ["", "- "])
@pytest.mark.parametrize("echo_value", [False, True])
def test_diagnostic_redaction_distinguishes_location_digits_from_echoed_values(
    prefix: str, echo_value: bool
) -> None:
    fixture_root = Path("/fixtures/10")
    message = "signer_policy_revision must match the trusted signer"
    if echo_value:
        message += ": received 10"
    diagnostic = f"{prefix}{fixture_root}/signed-manifest.json: {message}"
    normalized = diagnostic_without_fixture_locations(diagnostic, fixture_root)
    assert ("10" in normalized) is echo_value
    assert "signed-manifest.json" in normalized
    assert message in normalized


def test_diagnostic_redaction_preserves_paths_embedded_in_error_messages() -> None:
    fixture_root = Path("/fixtures/10")
    diagnostic = f"untrusted revision refers to {fixture_root}/signed-manifest.json"
    assert diagnostic_without_fixture_locations(diagnostic, fixture_root) == diagnostic


@pytest.mark.parametrize(
    ("flag", "replacement", "error_fragment"),
    [
        (
            "--topology-qualification-verification-public-key-hex",
            public_key_from_seed(
                hashlib.sha256(b"substituted-sf11-topology-key").digest()
            ).hex(),
            "signer public-key fingerprint must match the trusted public key",
        ),
        (
            "--topology-qualification-signer-service-id",
            "substituted-sf11-topology-service",
            "signer_service_id must match the trusted authenticated external signer",
        ),
        (
            "--topology-qualification-signer-administrator-id",
            "substituted-sf11-topology-admin",
            "signer_administrator_id must match the trusted authenticated external signer",
        ),
        (
            "--topology-qualification-signer-key-revision",
            # A distinctive valid revision preserves the redaction assertion
            # without colliding with arbitrary digits in temporary paths.
            "1700700123",
            "signer_key_revision must match the trusted authenticated external signer",
        ),
        (
            "--topology-qualification-signer-policy-revision",
            str(TOPOLOGY_SIGNER_POLICY_REVISION + 1),
            "signer_policy_revision must match the trusted authenticated external signer",
        ),
        (
            "--topology-qualification-signer-policy-digest-hex",
            hashlib.sha256(b"substituted-sf11-topology-policy").hexdigest(),
            "signer_policy_digest_sha256 must match the trusted authenticated external signer",
        ),
    ],
)
def test_release_lane_rejects_substituted_topology_trust(
    tmp_path: Path,
    flag: str,
    replacement: str,
    error_fragment: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_complete_evidence(tmp_path)
    topology = write_topology_qualification(tmp_path)
    summary = tmp_path / "sf11-summary.json"

    assert (
        run_gate(
            tmp_path,
            "--summary-out",
            str(summary),
            flag,
            replacement,
            topology=topology,
        )
        == 1
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["topology_qualification"] is None
    assert any(error_fragment in error for error in payload["errors"])
    # Temporary-directory digits are source locations, not echoed trust inputs.
    errors = [
        diagnostic_without_fixture_locations(error, tmp_path)
        for error in payload["errors"]
    ]
    assert replacement not in json.dumps(errors)
    assert replacement not in diagnostic_without_fixture_locations(
        capsys.readouterr().err, tmp_path
    )


def test_bound_fixture_tables_cover_checker_bound_kind_sets() -> None:
    assert (
        tuple(
            kind_name
            for kind_name, _file_name, _factory in RELEASE_MANIFEST_BOUND_FIXTURES
        )
        == MODULE.RELEASE_MANIFEST_BOUND_KINDS
    )
    assert (
        tuple(kind_name for kind_name, _file_name, _factory in POLICY_BOUND_FIXTURES)
        == MODULE.POLICY_BOUND_KINDS
    )
    assert (
        tuple(kind_name for kind_name, _file_name, _factory in RELEASE_KEY_BOUND_FIXTURES)
        == MODULE.RELEASE_KEY_BOUND_KINDS
    )


def test_fixture_inventories_cover_checker_required_sets() -> None:
    assert tuple(release_archive()["targets"]) == MODULE.REQUIRED_RELEASE_TARGETS
    assert MODULE.REQUIRED_RELEASE_TARGETS == (
        MODULE.MANDATORY_RELEASE_TARGETS + MODULE.ADDITIONAL_RELEASE_TARGETS
    )
    assert tuple(downstream_bindings()["packages"]) == (
        MODULE.REQUIRED_DOWNSTREAM_PACKAGES
    )
    assert (
        signed_manifest()["signature_algorithm"]
        in MODULE.ALLOWED_MANIFEST_SIGNATURE_ALGORITHMS
    )


def test_all_manifest_bound_artifacts_reject_signed_manifest_mismatch(
    tmp_path: Path,
) -> None:
    for kind_name, file_name, factory in RELEASE_MANIFEST_BOUND_FIXTURES:
        case_dir = tmp_path / kind_name
        case_dir.mkdir()
        write_complete_evidence(case_dir)
        payload = factory()
        payload["release_manifest_digest_hex"] = DIGEST_2
        write_json(case_dir / file_name, payload)
        summary = case_dir / "summary.json"

        assert run_gate(case_dir, "--summary-out", str(summary)) == 1

        result = json.loads(summary.read_text(encoding="utf-8"))
        required = result["required"][kind_name]
        artifact = required["artifacts"][0]
        assert result["valid_release_manifest_digests"] == []
        assert required["valid"] is False
        assert artifact["valid"] is False
        assert (
            f"{kind_name} release_manifest_digest_hex requires a valid "
            "signed_manifest manifest_digest_hex"
        ) in artifact["errors"]



def test_all_policy_bound_artifacts_reject_signed_manifest_policy_mismatch(
    tmp_path: Path,
) -> None:
    for kind_name, file_name, factory in POLICY_BOUND_FIXTURES:
        case_dir = tmp_path / kind_name
        case_dir.mkdir()
        write_complete_evidence(case_dir)
        payload = factory()
        payload["policy_digest_hex"] = DIGEST_2
        write_json(case_dir / file_name, payload)
        summary = case_dir / "summary.json"

        assert run_gate(case_dir, "--summary-out", str(summary)) == 1

        result = json.loads(summary.read_text(encoding="utf-8"))
        required = result["required"][kind_name]
        artifact = required["artifacts"][0]
        assert result["valid_policy_digests"] == []
        assert required["valid"] is False
        assert artifact["valid"] is False
        assert (
            f"{kind_name} policy_digest_hex requires a valid "
            "signed_manifest policy_digest_hex"
        ) in artifact["errors"]



def test_all_release_key_bound_artifacts_reject_signed_manifest_key_mismatch(
    tmp_path: Path,
) -> None:
    for kind_name, file_name, factory in RELEASE_KEY_BOUND_FIXTURES:
        case_dir = tmp_path / kind_name
        case_dir.mkdir()
        write_complete_evidence(case_dir)
        payload = factory()
        payload["public_key_fingerprint_hex"] = DIGEST_2
        write_json(case_dir / file_name, payload)
        summary = case_dir / "summary.json"

        assert run_gate(case_dir, "--summary-out", str(summary)) == 1

        result = json.loads(summary.read_text(encoding="utf-8"))
        required = result["required"][kind_name]
        artifact = required["artifacts"][0]
        assert result["valid_release_key_fingerprints"] == []
        assert required["valid"] is False
        assert artifact["valid"] is False
        assert (
            f"{kind_name} public_key_fingerprint_hex requires a valid "
            "signed_manifest public_key_fingerprint_hex"
        ) in artifact["errors"]



def test_multiple_unauthenticated_release_manifest_anchors_fail_closed(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = signed_manifest()
    payload["manifest_digest_hex"] = DIGEST_2
    write_json(tmp_path / "signed-manifest-alt.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    assert result["valid_release_manifest_digests"] == []
    anchors = result["required"]["signed_manifest"]["artifacts"]
    assert len(anchors) == 2
    assert all(not artifact["valid"] for artifact in anchors)
    assert all(any("independently pinned source context" in error for error in artifact["errors"]) for artifact in anchors)



def test_multiple_unauthenticated_policy_anchors_fail_closed(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = signed_manifest()
    payload["policy_digest_hex"] = DIGEST_2
    write_json(tmp_path / "signed-manifest-alt.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    assert result["valid_policy_digests"] == []
    anchors = result["required"]["signed_manifest"]["artifacts"]
    assert len(anchors) == 2
    assert all(not artifact["valid"] for artifact in anchors)
    assert all(any("independently pinned source context" in error for error in artifact["errors"]) for artifact in anchors)



def test_multiple_unauthenticated_release_key_anchors_fail_closed(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = signed_manifest()
    payload["public_key_fingerprint_hex"] = DIGEST_2
    write_json(tmp_path / "signed-manifest-alt.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    assert result["valid_release_key_fingerprints"] == []
    anchors = result["required"]["signed_manifest"]["artifacts"]
    assert len(anchors) == 2
    assert all(not artifact["valid"] for artifact in anchors)
    assert all(any("independently pinned source context" in error for error in artifact["errors"]) for artifact in anchors)



def test_response_file_arguments_cannot_bypass_manifest_authentication(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    topology = write_topology_qualification(tmp_path)
    args = tmp_path / "reference-sdk.args"
    args.write_text(
        (
            f"--evidence-dir {tmp_path}\n"
            f"--now-unix {NOW_UNIX}\n"
            f"--topology-qualification-summary {topology}\n"
            "--topology-qualification-envelope "
            f"{topology_envelope_path(topology)}\n"
            "--topology-qualification-verification-public-key-hex "
            f"{TOPOLOGY_VERIFICATION_PUBLIC_KEY_HEX}\n"
            "--topology-qualification-signer-service-id "
            f"{TOPOLOGY_SIGNER_SERVICE_ID}\n"
            "--topology-qualification-signer-administrator-id "
            f"{TOPOLOGY_SIGNER_ADMINISTRATOR_ID}\n"
            "--topology-qualification-signer-key-revision "
            f"{TOPOLOGY_SIGNER_KEY_REVISION}\n"
            "--topology-qualification-signer-policy-revision "
            f"{TOPOLOGY_SIGNER_POLICY_REVISION}\n"
            "--topology-qualification-signer-policy-digest-hex "
            f"{TOPOLOGY_SIGNER_POLICY_DIGEST_HEX}\n"
            "--max-topology-qualification-review-age-secs "
            f"{TOPOLOGY_MAX_REVIEW_AGE_SECS}\n"
            f"--supply-chain-source-root {tmp_path}\n"
            "--provenance-certificate-identity "
            f"{PROVENANCE_CERTIFICATE_IDENTITY}\n"
            f"--provenance-oidc-issuer {PROVENANCE_OIDC_ISSUER}\n"
            "--provenance-verification-public-key-hex "
            f"{PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX}\n"
        ),
        encoding="utf-8",
    )

    assert MODULE.main([f"@{args}"]) == 1



@pytest.mark.parametrize("field,anchor_field,fixtures", (
    ("release_manifest_digest_hex", "manifest_digest_hex", RELEASE_MANIFEST_BOUND_FIXTURES),
    ("policy_digest_hex", "policy_digest_hex", POLICY_BOUND_FIXTURES),
    ("public_key_fingerprint_hex", "public_key_fingerprint_hex", RELEASE_KEY_BOUND_FIXTURES),
))
def test_binding_helper_preserves_exact_digest_comparison_without_claiming_custody(field, anchor_field, fixtures):
    """Exercise binding mechanics in isolation; these are not release-authenticated artifacts."""
    for kind_name, file_name, factory in fixtures:
        for candidate_digest in (DIGEST, DIGEST_2):
            payload = factory()
            payload[field] = candidate_digest
            artifact = MODULE.build_evidence_artifact(Path(file_name), DIGEST, payload, [], MODULE.FINGERPRINT_FIELDS)
            assert artifact["valid"] is True, artifact["errors"]
            errors = []
            message = f"{kind_name} {field} must reference a valid signed_manifest {anchor_field}"
            MODULE.validate_bound_evidence_digest_references(
                required_kinds=MODULE.DEFAULT_REQUIRED_KINDS,
                missing_anchor_required_kinds=("signed_manifest",),
                bound_artifacts=[(kind_name, artifact)],
                valid_anchor_digests={DIGEST}, digest_field=field, errors=errors,
                binding_error_template="{kind_name} " + f"{field} must reference a valid signed_manifest {anchor_field}",
                missing_anchor_error_template="{kind_name} " + f"{field} requires a valid signed_manifest {anchor_field}",
            )
            assert artifact["valid"] is (candidate_digest == DIGEST)
            assert artifact["errors"] == ([] if candidate_digest == DIGEST else [message])
            assert not errors if candidate_digest == DIGEST else any(message in error for error in errors)


@pytest.mark.parametrize("label", ("valid_release_manifest_digests", "valid_policy_digests", "valid_release_key_fingerprints"))
def test_active_digest_selection_rejects_multiple_values_in_isolation(label):
    """Retain the mixed-anchor rejection without manufacturing hardware qualification."""
    errors = []
    assert MODULE.require_single_active_digest({DIGEST}, errors, label=label) == {DIGEST}
    assert errors == []
    assert MODULE.require_single_active_digest({DIGEST, DIGEST_2}, errors, label=label) == set()
    assert errors == [f"{label} must contain exactly one active digest"]


def test_missing_release_archive_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    (tmp_path / "release-archive.json").unlink()

    assert run_gate(tmp_path) == 1


@pytest.mark.parametrize("kind", MODULE.DEFAULT_REQUIRED_KINDS)
def test_selecting_one_kind_cannot_remove_signed_manifest_authentication(tmp_path: Path, kind):
    write_complete_evidence(tmp_path)
    (tmp_path / "signed-manifest.json").unlink()
    summary = tmp_path / "summary.json"
    assert run_gate(tmp_path, "--require-kind", kind, "--summary-out", str(summary)) == 1
    result = json.loads(summary.read_text())
    assert result["status"] == "blocked"
    assert result["required"]["signed_manifest"]["valid"] is False
    assert result["required"]["signed_manifest"]["artifact_count"] == 0
    assert result["valid_release_manifest_digests"] == []


def test_stale_release_archive_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = release_archive()
    payload["generated_at_unix"] = NOW_UNIX - MODULE.DEFAULT_MAX_EVIDENCE_AGE_SECS - 1
    write_json(tmp_path / "release-archive.json", payload)

    assert run_gate(tmp_path) == 1


def test_raw_archive_leakage_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = release_archive()
    payload["raw_archive"] = "leaked"
    write_json(tmp_path / "release-archive.json", payload)

    assert run_gate(tmp_path) == 1


def test_release_archive_requires_all_targets(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "release-archive.json", release_archive(missing_target=True))

    assert run_gate(tmp_path) == 1


def test_release_archive_requires_minimum_target_count(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "release-archive.json", release_archive(target_count=3))

    assert run_gate(tmp_path) == 1


def test_release_archive_target_count_must_match_unique_targets(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(tmp_path / "release-archive.json", release_archive(target_count=6))

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["release_archive"]["artifacts"][0]
    assert "target_count must match unique targets count" in artifact["errors"]


def test_release_archive_targets_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "release-archive.json",
        release_archive(duplicate_target=True),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["release_archive"]["artifacts"][0]
    assert "targets must not contain duplicate values" in artifact["errors"]
    assert "target_count must match unique targets count" in artifact["errors"]


def test_release_archive_targets_must_not_include_unknown_values(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = release_archive()
    payload["targets"].append("riscv64-unknown-linux-gnu")
    payload["target_count"] = len(payload["targets"])
    write_json(tmp_path / "release-archive.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["release_archive"]["artifacts"][0]
    assert "targets must not include unknown values" in artifact["errors"]


def test_signed_manifest_rejects_private_key_presence(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "signed-manifest.json", signed_manifest(private_key_absent=False))

    assert run_gate(tmp_path) == 1


@pytest.mark.parametrize("provider", ("external_ed25519_hsm", "local_file"))
def test_signed_manifest_rejects_legacy_or_unapproved_provider(
    tmp_path: Path,
    provider: str,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signing_provider=provider),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    artifact = json.loads(summary.read_text(encoding="utf-8"))["required"][
        "signed_manifest"
    ]["artifacts"][0]
    assert (
        any("independently pinned source context" in error for error in artifact["errors"])
    )

    assert artifact["valid"] is False



def test_signed_manifest_rejects_unauthenticated_hardware_backend(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signing_backend="hsm"),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    artifact = json.loads(summary.read_text(encoding="utf-8"))["required"][
        "signed_manifest"
    ]["artifacts"][0]
    assert any("independently pinned source context" in error for error in artifact["errors"])
    assert artifact["valid"] is False



def test_signed_manifest_rejects_legacy_hsm_verification_field(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = signed_manifest()
    payload["hsm_signature_verified"] = payload.pop("signer_response_verified")
    write_json(tmp_path / "signed-manifest.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    artifact = json.loads(summary.read_text(encoding="utf-8"))["required"][
        "signed_manifest"
    ]["artifacts"][0]
    assert (
        "signed_manifest evidence fields must match the schema-closed contract"
        in artifact["errors"]
    )
    assert "signed_manifest evidence fields must match the schema-closed contract" in artifact["errors"]


def test_signed_manifest_requires_verified_signer_response(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signer_response_verified=False),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    artifact = json.loads(summary.read_text(encoding="utf-8"))["required"][
        "signed_manifest"
    ]["artifacts"][0]
    assert "signed_manifest evidence fields must match the schema-closed contract" in artifact["errors"]


@pytest.mark.parametrize(
    ("field", "expected_error"),
    (
        ("policy_digest_hex", "policy_digest_hex must not be zero"),
        (
            "public_key_fingerprint_hex",
            "public_key_fingerprint_hex must not be zero",
        ),
    ),
)
def test_signed_manifest_rejects_zero_policy_or_key_binding(
    tmp_path: Path,
    field: str,
    expected_error: str,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = signed_manifest()
    payload[field] = "0" * 64
    write_json(tmp_path / "signed-manifest.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    artifact = json.loads(summary.read_text(encoding="utf-8"))["required"][
        "signed_manifest"
    ]["artifacts"][0]
    assert expected_error in artifact["errors"]


def test_signed_manifest_requires_positive_provider_revision(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signing_provider_revision=0),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    artifact = json.loads(summary.read_text(encoding="utf-8"))["required"][
        "signed_manifest"
    ]["artifacts"][0]
    assert "signed_manifest evidence fields must match the schema-closed contract" in artifact["errors"]


def test_supply_chain_requires_all_five_targets(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "supply-chain.json", supply_chain(missing_target=True))

    assert run_gate(tmp_path) == 1


def test_supply_chain_rejects_high_vulnerabilities(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "supply-chain.json",
        supply_chain(high_vulnerability_count=1),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["supply_chain"]["artifacts"][0]
    assert "high_vulnerability_count must be zero" in artifact["errors"]


@pytest.mark.parametrize(
    ("omitted_option", "expected_error"),
    (
        (
            "--supply-chain-source-root",
            "supply_chain validation requires --supply-chain-source-root",
        ),
        (
            "--provenance-certificate-identity",
            "supply_chain validation requires "
            "--provenance-certificate-identity",
        ),
        (
            "--provenance-oidc-issuer",
            "supply_chain validation requires --provenance-oidc-issuer",
        ),
        (
            "--provenance-verification-public-key-hex",
            "supply_chain validation requires a non-zero raw Ed25519 "
            "--provenance-verification-public-key-hex",
        ),
    ),
)
def test_supply_chain_requires_source_and_trust_inputs(
    tmp_path: Path,
    omitted_option: str,
    expected_error: str,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"

    assert (
        run_gate_omitting_supply_chain_args(
            tmp_path,
            frozenset({omitted_option}),
            "--summary-out",
            str(summary),
        )
        == 1
    )

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert expected_error in artifact["errors"]


def test_supply_chain_rejects_source_validation_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    monkeypatch.setattr(
        MODULE,
        "validate_supply_chain_sources",
        lambda *_args, **_kwargs: (None, ["release rehearsal could not be opened"]),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert (
        "supply-chain source: release rehearsal could not be opened"
        in artifact["errors"]
    )


def test_supply_chain_rejects_derived_field_mismatch(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload["sbom_index_digest_hex"] = DIGEST_2
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert (
        "sbom_index_digest_hex must equal the source-derived value"
        in artifact["errors"]
    )


def test_supply_chain_rejects_reordered_source_bindings(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload["source_artifacts"][0], payload["source_artifacts"][1] = (
        payload["source_artifacts"][1],
        payload["source_artifacts"][0],
    )
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert (
        "source_artifacts kinds must match the canonical four-source order"
        in artifact["errors"]
    )
    assert "source_artifacts must equal the source-derived value" in artifact[
        "errors"
    ]


def test_supply_chain_rejects_tampered_source_binding(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload["source_artifacts"][2]["sha256"] = DIGEST_2
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert "source_artifacts must equal the source-derived value" in artifact[
        "errors"
    ]


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    (
        (
            "provenance_certificate_identity",
            "https://example.invalid/untrusted-workflow",
            "provenance_certificate_identity must match the operator-trusted "
            "identity",
        ),
        (
            "provenance_oidc_issuer",
            "https://issuer.example.invalid",
            "provenance_oidc_issuer must match the operator-trusted issuer",
        ),
        (
            "provenance_verification_key_fingerprint_hex",
            DIGEST_2,
            "provenance_verification_key_fingerprint_hex must match the "
            "operator-trusted key",
        ),
    ),
)
def test_supply_chain_rejects_trust_metadata_mismatch(
    tmp_path: Path,
    field: str,
    value: str,
    expected_error: str,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload[field] = value
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert expected_error in artifact["errors"]


def test_supply_chain_public_trust_metadata_does_not_exempt_secret_fields(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload["private_key"] = "11" * 32
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert any("sensitive" in error for error in artifact["errors"])


def test_supply_chain_untrusted_secret_like_metadata_remains_scanned(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload["provenance_oidc_issuer"] = (
        "authorization: bearer not-a-public-issuer"
    )
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert (
        "provenance_oidc_issuer must not contain secret-looking values in "
        "release evidence"
        in artifact["errors"]
    )
    assert (
        "provenance_oidc_issuer must match the operator-trusted issuer"
        in artifact["errors"]
    )


def test_release_evidence_payloads_are_schema_closed(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = supply_chain()
    payload["legacy_supply_chain_alias"] = True
    write_json(tmp_path / "supply-chain.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["supply_chain"]["artifacts"][0]
    assert (
        "supply_chain evidence fields must match the schema-closed contract"
        in artifact["errors"]
    )


def test_signed_manifest_requires_policy_digest(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = signed_manifest()
    del payload["policy_digest_hex"]
    write_json(tmp_path / "signed-manifest.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["valid_policy_digests"] == []
    required = payload["required"]["signed_manifest"]
    artifact = required["artifacts"][0]
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert "policy_digest_hex must be a non-empty string" in artifact["errors"]


def test_signed_manifest_rejects_rsa_sha256_signature_algorithm(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signature_algorithm="rsa-sha256"),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["signed_manifest"]["artifacts"][0]
    assert artifact["valid"] is False
    assert "signature_algorithm must be `ed25519`" in artifact["errors"]
    assert payload["valid_release_manifest_digests"] == []


def test_signed_manifest_rejects_unsupported_signature_algorithm(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signature_algorithm="none"),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["signed_manifest"]
    artifact = required["artifacts"][0]
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert "signature_algorithm must be `ed25519`" in artifact["errors"]
    assert payload["valid_release_manifest_digests"] == []


def test_signed_manifest_unsupported_signature_algorithm_stdout_does_not_echo_algorithm(
    tmp_path: Path,
    capsys,
) -> None:
    write_complete_evidence(tmp_path)
    invalid_algorithm = "none"
    write_json(
        tmp_path / "signed-manifest.json",
        signed_manifest(signature_algorithm=invalid_algorithm),
    )

    assert run_gate(tmp_path) == 1

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    diagnostics = json.dumps(payload, sort_keys=True)
    assert "signature_algorithm must be `ed25519`" in diagnostics
    assert invalid_algorithm not in diagnostics
    assert "signature_algorithm must be `ed25519`" in captured.err
    assert invalid_algorithm not in captured.err


def test_stale_signed_manifest_does_not_anchor_release_bound_evidence(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = signed_manifest()
    payload["generated_at_unix"] = NOW_UNIX - MODULE.DEFAULT_MAX_EVIDENCE_AGE_SECS - 1
    write_json(tmp_path / "signed-manifest.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["release_archive"]
    artifact = required["artifacts"][0]
    assert payload["valid_release_manifest_digests"] == []
    assert payload["valid_release_manifest_reference_digests"] == []
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "release_archive release_manifest_digest_hex requires a valid "
        "signed_manifest manifest_digest_hex"
    ]


def test_downstream_bindings_require_all_packages(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(
        tmp_path / "downstream-bindings.json",
        downstream_bindings(missing_package=True),
    )

    assert run_gate(tmp_path) == 1


def test_downstream_bindings_require_minimum_package_count(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "downstream-bindings.json", downstream_bindings(package_count=4))

    assert run_gate(tmp_path) == 1


def test_downstream_package_count_must_match_unique_packages(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "downstream-bindings.json",
        downstream_bindings(package_count=7),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["downstream_bindings"]["artifacts"][0]
    assert "package_count must match unique packages count" in artifact["errors"]


def test_downstream_packages_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    write_json(
        tmp_path / "downstream-bindings.json",
        downstream_bindings(duplicate_package=True),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["downstream_bindings"]["artifacts"][0]
    assert "packages must not contain duplicate values" in artifact["errors"]
    assert "package_count must match unique packages count" in artifact["errors"]


def test_downstream_packages_must_not_include_unknown_values(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = downstream_bindings()
    payload["packages"].append("shadow-sdk-package")
    payload["package_count"] = len(payload["packages"])
    write_json(tmp_path / "downstream-bindings.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["downstream_bindings"]["artifacts"][0]
    assert "packages must not include unknown values" in artifact["errors"]


def test_downstream_bindings_require_release_manifest_binding(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = downstream_bindings()
    del payload["release_manifest_digest_hex"]
    write_json(tmp_path / "downstream-bindings.json", payload)

    assert run_gate(tmp_path) == 1


def test_release_archive_manifest_digest_must_match_signed_manifest(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = release_archive()
    payload["release_manifest_digest_hex"] = DIGEST_2
    write_json(tmp_path / "release-archive.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["release_archive"]
    artifact = required["artifacts"][0]
    assert payload["valid_release_manifest_reference_digests"] == []
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert all(error in artifact["errors"] for error in [
        "release_archive release_manifest_digest_hex requires a valid "
        "signed_manifest manifest_digest_hex"
    ])


def test_governance_policy_digest_must_match_signed_manifest(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = governance_approval()
    payload["policy_digest_hex"] = DIGEST_2
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["governance_approval"]
    artifact = required["artifacts"][0]
    assert payload["valid_policy_digests"] == []
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert all(error in artifact["errors"] for error in [
        "governance_approval policy_digest_hex requires a valid "
        "signed_manifest policy_digest_hex"
    ])


def test_governance_release_key_fingerprint_is_required(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = governance_approval()
    del payload["public_key_fingerprint_hex"]
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["governance_approval"]
    artifact = required["artifacts"][0]
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert "public_key_fingerprint_hex must be a non-empty string" in artifact["errors"]


def test_governance_release_key_fingerprint_must_match_signed_manifest(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = governance_approval()
    payload["public_key_fingerprint_hex"] = DIGEST_2
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["governance_approval"]
    artifact = required["artifacts"][0]
    assert payload["valid_release_key_fingerprints"] == []
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert all(error in artifact["errors"] for error in [
        "governance_approval public_key_fingerprint_hex requires a valid "
        "signed_manifest public_key_fingerprint_hex"
    ])


def test_cookbook_smoke_duration_above_threshold_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "cookbook-smoke.json", cookbook_smoke(duration=4_000))

    assert run_gate(tmp_path) == 1


def test_cookbook_smoke_duration_must_be_integer(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "cookbook-smoke.json", cookbook_smoke(duration=12.5))
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["cookbook_smoke"]["artifacts"][0]
    assert artifact["valid"] is False
    assert "smoke_duration_seconds must be a positive integer" in artifact["errors"]


def test_ffi_contract_requires_ci_guard(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "ffi-header-contract.json", ffi_header_contract(ci_guard=False))

    assert run_gate(tmp_path) == 1


def test_governance_source_must_be_release_governance(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "governance-approval.json", governance_approval(source="local"))

    assert run_gate(tmp_path) == 1


def test_explicit_unknown_schema_fails(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "unknown.json",
        {"schema": "sorafs.reference_sdk.unknown.v1"},
    )

    assert (
        MODULE.main(
            [
                "--evidence",
                str(path),
                "--now-unix",
                str(NOW_UNIX),
                *topology_cli_args(write_topology_qualification(tmp_path)),
            ]
        )
        == 1
    )


def test_unknown_directory_artifact_is_ignored_for_subset(tmp_path: Path) -> None:
    write_json(tmp_path / "release-archive.json", release_archive())
    write_json(tmp_path / "unknown.json", {"schema": "sorafs.reference_sdk.unknown.v1"})

    summary = tmp_path / "summary.json"
    assert run_gate(tmp_path, "--require-kind", "release_archive", "--summary-out", str(summary)) == 1
    result = json.loads(summary.read_text())
    assert result["recognized_artifact_count"] == 1
    assert result["required"]["signed_manifest"]["valid"] is False
    assert not any("unknown" in error for error in result["errors"])


def test_invalid_optional_artifact_fails_subset_gate(tmp_path: Path) -> None:
    write_json(tmp_path / "release-archive.json", release_archive())
    write_json(tmp_path / "signed-manifest.json", signed_manifest(private_key_absent=False))

    assert run_gate(tmp_path, "--require-kind", "release_archive") == 1


def test_unknown_required_kind_returns_usage_error(tmp_path: Path) -> None:
    assert (
        MODULE.main(
            [
                "--evidence-dir",
                str(tmp_path),
                "--require-kind",
                "unknown",
                "--now-unix",
                str(NOW_UNIX),
                *topology_cli_args(write_topology_qualification(tmp_path)),
            ]
        )
        == 2
    )
