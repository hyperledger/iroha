"""Strict first-release privacy verifier backend label tests."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from iroha_python._privacy_backends import (
    _VERIFIER_BACKEND_REGISTRY_LABELS_V1,
    _is_verifier_backend_registry_label_v1,
    _require_verifier_backend_registry_label_v1,
    _verifier_backend_registry_tag_v1,
)


def _registry_literals(path: str, marker: str, end: str) -> frozenset[str]:
    root = Path(__file__).resolve().parents[3]
    source = (root / path).read_text("utf-8")
    assert source.count(marker) == 1, (path, marker)
    body = source.split(marker, 1)[1].split(end, 1)[0]
    labels = re.findall(r'"((?:halo2|stark|pipa-r)/[^"\n]*)"', body)
    assert labels and len(labels) == len(set(labels)), (path, labels)
    return frozenset(labels)


@pytest.mark.parametrize(
    "path,marker,end,subset",
    [
        (
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/zk/VerifyingKeyBackendTag.kt",
            "val VERIFIER_BACKEND_REGISTRY_LABELS_V1:", "),\n        )", "all",
        ),
        (
            "csharp/src/Hyperledger.Iroha.Sdk/Zk/VerifierBackendRegistryLabels.cs",
            "private static readonly string[] SupportedLabels =", "];", "all",
        ),
        (
            "csharp/src/Hyperledger.Iroha.Sdk/Zk/VerifyingKeyBackendTag.cs",
            "private static readonly HashSet<string> ProductionNativePipaRPastaBackends =", "};", "pipa-r",
        ),
        (
            "IrohaSwift/Sources/IrohaSwift/VerifyingKeyBackendTag.swift",
            "private static let productionNativePipaRPastaBackends: Set<String> =", "]", "pipa-r",
        ),
        (
            "IrohaSwift/Sources/IrohaSwift/VerifyingKeyBackendTag.swift",
            "private static let productionLabels: Set<String> =", "]", "all",
        ),
        (
            "javascript/iroha_js/src/verifyingKeyClient.js",
            "const PRODUCTION_VERIFY_BACKEND_LABELS_V1 =", "]);", "all",
        ),
        (
            "javascript/iroha_js/index.d.ts",
            "export type ToriiVerifierBackendLabelV1 =", ";", "all",
        ),
    ],
)
def test_each_sdk_registry_mirror_matches_the_exact_rust_owner(
    path: str, marker: str, end: str, subset: str
) -> None:
    # Registry acceptance is source parity, not production qualification.
    canonical = _registry_literals(
        "crates/iroha_data_model/src/zk.rs",
        "pub const ZK_VERIFIER_BACKEND_REGISTRY_LABELS_V1:",
        "];",
    )
    assert len(canonical) == 7
    assert _VERIFIER_BACKEND_REGISTRY_LABELS_V1 == canonical
    expected = (
        frozenset(label for label in canonical if label.startswith("pipa-r/"))
        if subset == "pipa-r" else canonical
    )
    assert _registry_literals(path, marker, end) == expected, path


def test_privacy_verifier_registry_is_closed_exact_and_engine_typed() -> None:
    expected = frozenset(
        {
            "pipa-r/pasta",
            "pipa-r/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1",
            "pipa-r/pasta/confidential-transfer-v1",
            "pipa-r/pasta/confidential-unshield-full-v1",
            "pipa-r/pasta/confidential-unshield-change-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        }
    )
    assert len(expected) == 7
    assert _VERIFIER_BACKEND_REGISTRY_LABELS_V1 == expected
    for backend in expected:
        expected_tag = ("native-pipa-r-pasta" if backend.startswith("pipa-r/") else "stark")
        assert _verifier_backend_registry_tag_v1(backend) == expected_tag
        assert _is_verifier_backend_registry_label_v1(backend)
        assert (
            _require_verifier_backend_registry_label_v1(backend, "backend")
            == backend
        )


def test_privacy_verifier_registry_rejects_aliases_retired_and_hostile_labels() -> None:
    unsupported = (
        "",
        "halo2/ipa",
        "halo2/pasta/ivm-execution-v1",
        "halo2/pasta/kaigi-authorization-v1",
        "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
        "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3",
        "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4",
        "halo2/pasta/kaigi-usage-v1",
        "pipa-r/ipa/pasta/kaigi-authorization-v1",
        "pipa-r/pasta/kaigi-usage-v1/",
        "halo2/pasta/kaigi-roster-v1",
        "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
        "unknown/privacy/backend",
        "halo2/unknown-native-v1",
        "halo2/ipa:unknown-native-v1",
        "stark/unknown-native-v1",
        "halo2/bn254",
        "groth16",
        "groth16/bls12-377",
        " halo2/ipa",
        "halo2/ipa ",
        "\thalo2/ipa",
        "halo2/ipa\n",
        "halo2\uFF0Fipa",
        "halo2/\u200Bipa",
        "h\u0430lo2/ipa",
        "halo2/ipa\0",
        "HALO2/IPA",
        "stark/FRI",
        "stark/fri",
        "stark/fri/poseidon2-goldilocks",
        "stark/fri/sha256_goldilocks.v1",
        "halo2/ipa::ivm-replay-binding-v1",
        "halo2//ipa",
        "halo2/ipa:",
        "halo2/ipa.",
        "halo2/ipa/.ivm-replay-binding-v1",
        "halo2/ipa:ivm..execution-v1",
        "halo2/pasta/ipa-pasta-cycle-v1",
        "halo2/ipa-pasta-cycle-v1",
        "halo2/pasta/ivm-overlay-bind",
        "halo2/pasta/kagemusha-v1-invalid-eq",
        "halo2/pasta/kagemusha-v1-invalid-ep",
        "../halo2/ipa",
        "halo2/ipa/orchard",
        "halo2-ipa-orchard",
        "halo2/ipa/penumbra",
        "halo2/ipa/masp",
        "halo2/ipa/monero",
        "halo2/ipa/curve-tree",
        "halo2/pasta/tiny-add",
        "halo2/ipa/tiny-add",
        "halo2/ipa:tiny-add",
        "halo2/pasta/asset-hidden-transfer-public-test",
        "halo2/ipa/asset-hidden-transfer-public-test",
        "halo2/ipa:asset-hidden-transfer-public-test",
        "stark/fri/miden",
        "stark/fri/miden/claimed-production",
        "stark/fri/latest",
        "stark/fri/random-profile",
        "stark/fri/sha512-goldilocks",
        "stark/fri/audit-proof-v1",
        "stark/fri/sha256 goldilocks",
        "stark/fri/sha256+goldilocks",
        "fcmp++",
        "halo2/ipa+mock",
        "halo2/ipa:production-ready",
        "halo2/ipa:claimed-production",
        "halo2/ipa:mainnet-ready",
        "halo2/ipa:release-ready",
        "halo2/ipa:certified-mainnet",
        "halo2/ipa:third-party-audited",
        "halo2/ipa/orchard:production-ready",
        "orchard:mainnet-ready",
        "penumbra-masp:external-security-review",
        "jindo-lattice-pcs-zk:release-ready",
        "miden-stark:dev-fixture",
        "sis-hints-anoncred-pq-v0",
        "sis-with-hints",
        "sis-with-hints:s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        "halo2/ipa/orchard:kzg",
        "orchard:universal-srs",
        "penumbra-masp:kzg",
        "jindo-lattice-pcs-zk:trusted-setup",
        "miden-stark:ptau",
        "sis-with-hints:groth16",
        "pq-masp-stark-fri:kzg",
        "stark/fri/audit-signoff",
        "stark/fri/externally-audited",
        "stark/fri/boi-audited",
        "stark/fri/external-security-review",
        "stark/fri/security-review-passed",
        "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
        "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        "stark/fri/a-u-d-i-t-c-l-a-i-m",
        "stark/fri/dev-fixture",
        "stark/fri/d-e-v-f-i-x-t-u-r-e",
        "stark/fri/test",
        "stark/fri/t-e-s-t",
        "stark/fri/todo",
        "stark/fri/t-o-d-o",
        "stark/fri/draft-only",
        "stark/fri/d-r-a-f-t",
        "stark/fri/pending-audit",
        "stark/fri/replace-before-mainnet",
        "stark/fri/not-production-ready",
        "halo2/ipa:dev-fixture",
        "halo2/ipa:todo-proof",
        "halo2/ipa:t-o-d-o-proof",
        "halo2/ipa:draft-proof",
        "halo2/ipa:d-r-a-f-t-proof",
        "halo2/ipa:pending-audit",
        "halo2/ipa:replace-before-production",
        "halo2/ipa:not-for-production",
        "halo2/ipa:dummy",
        "halo2/ipa:f-a-k-e",
        "halo2/ipa:stub",
        "halo2/kzg",
        "halo2/pasta/mock",
        "kzg/powersoftau",
    )
    for backend in unsupported:
        assert _verifier_backend_registry_tag_v1(backend) is None, backend
        assert not _is_verifier_backend_registry_label_v1(backend), backend
        with pytest.raises(ValueError, match="unsupported verifier-registry label"):
            _require_verifier_backend_registry_label_v1(backend, "backend")
    for backend in (None, b"halo2/ipa", 1, object()):
        assert _verifier_backend_registry_tag_v1(backend) is None
        assert not _is_verifier_backend_registry_label_v1(backend)
        with pytest.raises(TypeError, match="must be a string"):
            _require_verifier_backend_registry_label_v1(backend, "backend")


def test_each_privacy_verifier_registry_label_rejects_structural_mutations() -> None:
    for label in _VERIFIER_BACKEND_REGISTRY_LABELS_V1:
        replacement = "y" if label.endswith("x") else "x"
        mutations = {
            f" {label}",
            f"{label} ",
            label.upper(),
            f"{label}/",
            f"{label}\0",
            f"{label}\u200b",
            label.replace("/", "//", 1),
            f"{label[:-1]}{replacement}",
        }
        mutations.discard(label)
        for mutation in mutations:
            assert not _is_verifier_backend_registry_label_v1(mutation), (
                mutation,
                label,
            )
