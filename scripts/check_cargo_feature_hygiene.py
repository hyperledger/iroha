#!/usr/bin/env python3
"""Validate explicit ownership of foundational Cargo features.

Prerequisites: Python 3.11+, or Python 3.9/3.10 with the repository's pinned
``tomli`` dependency installed. The check is read-only and requires no
environment variables.
"""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python <3.11
    import tomli as tomllib


FOUNDATIONAL_DEPENDENCIES = frozenset(
    {
        "iroha_core",
        "iroha_core_privacy",
        "iroha_core_zk",
        "iroha_crypto",
        "iroha_data_model",
        "iroha_torii",
        "norito",
    }
)

# These aggregates are the stable ownership boundary for shipping builds. The
# implementation features remain available for focused tests
# while callers depend on the smaller vocabulary below.
EXPECTED_FEATURES: dict[str, dict[str, tuple[str, ...]]] = {
    "norito": {
        "mutation-testing": (),
        "default": ("node-codec",),
        "base-codec": ("json",),
        "node-codec": (
            "base-codec",
            "compression",
            "columnar",
            "json-std-io",
            "simd-accel",
            "crc-key-hash",
            "simdutf8-validate",
            "parallel-stage1-rayon",
        ),
        "columnar": (),
        "compression": (),
        "crc-key-hash": (),
        "gpu-compression": ("compression", "dep:gpuzstd_metal"),
        "json": (),
        "json-std-io": (),
        "mutation-testing": (),
        "parallel-stage1": (),
        "parallel-stage1-rayon": ("rayon", "parallel-stage1"),
        "rayon": ("dep:rayon",),
        "simd-accel": (),
        "simdutf8": ("dep:simdutf8",),
        "simdutf8-validate": ("simdutf8",),
    },
    "iroha_crypto": {
        "default": ("node-crypto",),
        "application": ("rand", "json", "ecc-batch", "bfv-accel", "pqc"),
        # The exact CRT-NTT ring products and the NEON/AVX2 kernels of the
        # shared FHE arithmetic; both return the words of the scalar reference.
        "bfv-accel": ("iroha_fhe/simd",),
        "bls": (
            "dep:arrayvec",
            "dep:ark-serialize",
            "dep:blst",
            "dep:blstrs",
            "dep:group",
            "dep:pairing",
            "dep:w3f-bls",
        ),
        "consensus": ("rand", "bls"),
        "ecc-batch": ("ed25519-dalek/batch",),
        "gost": (
            "dep:once_cell",
            "dep:num-bigint",
            "dep:num-traits",
            "dep:streebog",
            "dep:crypto-bigint",
        ),
        "json": ("norito/json",),
        "node-crypto": ("application", "consensus", "gost", "sm", "rayon"),
        "pqc": (
            "dep:pqcrypto-traits",
            "dep:pqcrypto-mldsa",
            "dep:soranet_pq",
        ),
        "rand": (),
        "rayon": ("dep:rayon",),
        "sm": (
            "sm-ccm",
            "dep:sm2",
            "dep:sm3",
            "dep:sm4",
            "dep:rfc6979",
            "dep:sm4_gcm",
            "sm-neon",
        ),
        "sm-ccm": (),
        "sm-neon": ("dep:sm4-neon", "dep:sm3-neon"),
    },
    "iroha_data_model": {
        "mutation-testing": (),
        "default": ("application-model",),
        "application-model": ("pqc", "bls", "gost", "sm"),
        "bls": ("iroha_crypto/bls",),
        "gost": ("iroha_crypto/gost",),
        "http": (),
        "pqc": ("iroha_crypto/pqc", "sorafs_manifest/pqc"),
        "privacy-exact12-conformance": (),
        "sm": ("iroha_crypto/sm",),
        "transparent_api": (
            "iroha_data_model_derive/transparent_api",
            "iroha_model_base/transparent_api",
        ),
    },
    "iroha_core": {"default": ("node", "simd"),
 "runtime": ("json", "bls", "zk-ipa-native"),
 "node": ("runtime", "proofs-stark", "app_api", "gost", "sm", "telemetry", "zk-preverify"),
 "proofs-stark": ("zk-stark",),
 "proofs-full": ("proofs-stark", "zk-ipa-native"),
 "app_api": (),
 "bls": ("iroha_crypto/bls", "iroha_data_model/bls"),
 "expensive-telemetry": ("telemetry", "iroha_telemetry/metric-instrumentation"),
 "gost": ("iroha_config/gost", "iroha_crypto/gost", "iroha_data_model/gost"),
 "json": ("iroha_crypto/json", "iroha_primitives/json"),
 "sm": ("iroha_config/sm", "iroha_crypto/sm", "iroha_data_model/sm"),
 "telemetry": (),
 "simd": ("iroha_primitives/simd-accel", "iroha_core_privacy/simd"),
 "zk-ipa-native": (),
 "zk-preverify": ("iroha_core_zk/zk-preverify",),
 "zk-stark": ("iroha_core_zk/zk-stark", "iroha_core_privacy/zk-stark")},
    "iroha_core_zk": {
        "dev-tools": (),
        "default": ("proofs-stark", "zk-preverify"),
        "proofs-stark": ("zk-stark",),
        "zk-stark": ("dep:fastpq_prover",),
        "zk-preverify": (),
        "test-utils": (),
        "zk-tests": ("test-utils",),
    },
    "iroha_torii": {
        "mutation-testing": (),
        "default": ("node-api",),
        "node-api": (
            "app_api",
            "app_api_https",
            "transparent_api",
            "app_api_wss",
            "connect",
            "push",
            "telemetry",
            "schema",
            "proofs-full",
            "ipa-commitment",
            "zk-verify-batch",
            "gost",
            "sm",
        ),
        "proofs-stark": ("zk-stark",),
        "proofs-full": ("proofs-stark",),
        "app_api": ("dep:kotodama_lang",),
        "app_api_https": (),
        "app_api_wss": ("dep:tokio-tungstenite",),
        "connect": (),
        "telemetry": (
            "iroha_telemetry",
            "iroha_core/telemetry",
            "iroha_futures/telemetry",
            "dep:prometheus",
        ),
        "gost": (
            "iroha_config/gost",
            "iroha_core/gost",
            "iroha_crypto/gost",
            "iroha_data_model/gost",
        ),
        "sm": (
            "iroha_config/sm",
            "iroha_core/sm",
            "iroha_crypto/sm",
            "iroha_data_model/sm",
            "iroha_telemetry?/sm",
        ),
        "ipa-commitment": ("dep:iroha_zkp_halo2",),
        "profiling": ("dep:pprof", "dep:bytes"),
        "iroha_schema": ("dep:iroha_schema",),
        "iroha_schema_gen": ("dep:iroha_schema_gen",),
        "iroha_telemetry": ("dep:iroha_telemetry",),
        "push": ("app_api",),
        "schema": ("iroha_schema", "iroha_schema_gen"),
        "transparent_api": ("iroha_data_model/transparent_api",),
        "zk-stark": ("iroha_core/zk-stark",),
        "zk-verify-batch": ("dep:iroha_zkp_halo2", "app_api"),
    },
    "irohad_lib": {"default": ("daemon", "iroha_core/simd"),
 "mutation-testing": (),
 "daemon": ("telemetry",
            "schema-endpoint",
            "gost",
            "sm",
            "dag-recovery-verify",
            "expensive-telemetry",
            "iroha_core/node",
            "iroha_torii/node-api",
            "iroha_crypto/consensus",
            "iroha_crypto/pqc",
            "norito/node-codec"),
 "telemetry": ("iroha_telemetry",
               "iroha_telemetry/event-exporter",
               "iroha_core/telemetry",
               "iroha_torii/telemetry"),
 "expensive-telemetry": ("telemetry", "iroha_core/expensive-telemetry"),
 "gost": ("iroha_core/gost",
          "iroha_crypto/gost",
          "iroha_data_model/gost",
          "iroha_config/gost",
          "iroha_torii/gost"),
 "sm": ("iroha_core/sm",
        "iroha_crypto/sm",
        "iroha_data_model/sm",
        "iroha_config/sm",
        "iroha_genesis/sm",
        "iroha_telemetry/sm",
        "iroha_torii/sm"),
 "dag-recovery-verify": (),
 "iroha_telemetry": ("dep:iroha_telemetry",),
 "schema-endpoint": ("iroha_torii/schema",)},
    "iroha_cli_lib": {"default": ("bridge", "offline-visual-codecs"),
 "bridge": (),
 "offline-visual-codecs": ("dep:image",)},
    "iroha": {
        "mutation-testing": (),
        "default": ("tls-rustls-native-roots", "gost", "sm"),
        "gost": ("iroha_crypto/gost", "iroha_data_model/gost"),
        "sm": ("iroha_crypto/sm", "iroha_data_model/sm"),
        "tls-rustls-native-roots": (
            "reqwest/rustls-tls-native-roots",
            "tokio-tungstenite/rustls-tls-native-roots",
            "tungstenite/rustls-tls-native-roots",
        ),
    },
    "iroha_config": {
        "default": ("gost", "sm"),
        "gost": ("iroha_crypto/gost", "iroha_data_model/gost"),
        "sm": ("iroha_crypto/sm", "iroha_data_model/sm"),
        "sm-ffi-openssl": ("sm", "iroha_crypto/sm-ffi-openssl"),
    },
    "iroha_genesis": {
        "default": ("sm",),
        "sm": ("iroha_config/sm", "iroha_crypto/sm", "iroha_data_model/sm"),
        "sm-ffi-openssl": (
            "sm",
            "iroha_config/sm-ffi-openssl",
            "iroha_crypto/sm-ffi-openssl",
        ),
    },
    "iroha_telemetry": {
        "default": (),
        "event-exporter": (
            "dep:futures",
            "dep:iroha_logger",
            "dep:time",
            "dep:tokio",
            "dep:tokio-tungstenite",
            "dep:url",
            "tokio/fs",
            "tokio/io-util",
            "tokio/macros",
            "tokio/net",
            "tokio/rt",
            "tokio/sync",
            "tokio/time",
        ),
        "metric-instrumentation": (
            "iroha_telemetry_derive/metric-instrumentation",
        ),
        "sm": ("iroha_config/sm", "iroha_data_model/sm"),
    },
    "ivm": {
        "default": ("metal",),
        "cuda": ("dep:cust", "iroha_accel/cuda"),
        "metal": (
            "dep:objc2-metal",
            "dep:objc2",
            "dep:objc2-foundation",
            "dep:dispatch2",
        ),
    },
    "iroha_primitives": {
        "default": ("json", "simd-accel"),
        "json": (),
        "simd-accel": (),
    },
    "iroha_kagami": {
        "default": ("gost", "sm"),
        "gost": ("iroha_config/gost", "iroha_crypto/gost", "iroha_data_model/gost"),
        "sm": (
            "iroha_config/sm",
            "iroha_crypto/sm",
            "iroha_data_model/sm",
            "iroha_genesis/sm",
        ),
    },
    "iroha_zkp_halo2": {
        "default": ("full", "parallel"),
        "full": (
            "model-primitives",
            "dep:halo2curves",
            "dep:once_cell",
            "dep:fastpq_isi",
            "dep:iroha_fhe",
            "dep:zeroize",
            "dep:iroha_crypto",
            "dep:tiny-keccak",
            "dep:thiserror",
            "dep:norito",
            "dep:hex",
            "dep:parking_lot",
        ),
        "model-primitives": ("dep:iroha_zkp_poseidon",),
        "parallel": ("full", "dep:rayon"),
    },

    "irohad": {"default": ("daemon", "irohad_lib/default"),
 "daemon": ("irohad_lib/daemon",
            "telemetry",
            "schema-endpoint",
            "gost",
            "sm",
            "dag-recovery-verify",
            "expensive-telemetry"),
 "external-software-signer-bin": ("daemon",),
 "dev-tools": ("daemon", "zk-stark", "irohad_lib/dev-tools"),
 "accel-metal": ("fastpq-gpu", "irohad_lib/accel-metal"),
 "accel-cuda": ("fastpq-gpu", "irohad_lib/accel-cuda"),
 "test-network-private-settlement-route-control": ("irohad_lib/test-network-private-settlement-route-control",),
 "test-network-parliament-signers": ("irohad_lib/test-network-parliament-signers",),
 "test-network-disposable-broker": ("daemon", "irohad_lib/test-network-disposable-broker"),
 "fastpq-gpu": ("irohad_lib/fastpq-gpu",),
 "zk-stark": ("irohad_lib/zk-stark",),
 "sm": ("irohad_lib/sm",),
 "gost": ("irohad_lib/gost",),
 "sm-ffi-openssl": ("sm", "irohad_lib/sm-ffi-openssl"),
 "beep": ("irohad_lib/beep",),
 "dag-recovery-verify": ("irohad_lib/dag-recovery-verify",),
 "telemetry": ("irohad_lib/telemetry",),
 "expensive-telemetry": ("telemetry", "irohad_lib/expensive-telemetry"),
 "dev-telemetry": ("telemetry", "irohad_lib/dev-telemetry"),
 "telegram-alerts": ("telemetry", "irohad_lib/telegram-alerts"),
 "schema-endpoint": ("irohad_lib/schema-endpoint",),
 "profiling-endpoint": ("irohad_lib/profiling-endpoint",)},
    "iroha_cli": {"default": ("cli", "bridge", "offline-visual-codecs"),
 "cli": (),
 "bridge": ("iroha_cli_lib/bridge",),
 "offline-visual-codecs": ("iroha_cli_lib/offline-visual-codecs",),
 "dev-tools": ("cli",),
 "cli_integration_harness": ("iroha_cli_lib/cli_integration_harness",)},
    "iroha_core_privacy": {"default": ("zk-stark", "simd"),
 "zk-stark": (),
 "simd": ("sha3/asm",),
 "privacy-release-evidence": ("zk-stark", "iroha_data_model/privacy-exact12-conformance"),
 "test-utils": ("dep:rand_08",)},
    "iroha_core_timed_ovn": {"test-utils": ("dep:rand",), "default": ()},
}


# These features are deliberately absent from their defining package's local
# default, but are selected by another shipping package for that consumer's
# context. They remain exact-pinned in ``EXPECTED_FEATURES`` and must not drift
# into the defining package's default closure without an explicit policy change.
CONTEXTUAL_SHIPPING_FEATURES: dict[str, tuple[str, ...]] = {
    "norito": (),
    "iroha_crypto": (),
    "iroha_data_model": (
        "http",
        "privacy-exact12-conformance",
        "transparent_api",
    ),
    "iroha_core": ("expensive-telemetry",),
    "iroha_core_zk": (),
    "iroha_torii": (),
    "irohad_lib": (),
    "iroha_cli_lib": (),
    "iroha": (),
    "iroha_config": (),
    "iroha_genesis": (),
    "iroha_telemetry": ("event-exporter", "metric-instrumentation", "sm"),
    "ivm": ("cuda",),
    "iroha_primitives": (),
    "iroha_kagami": (),
    "iroha_zkp_halo2": (),

    "irohad": (),
    "iroha_cli": (),
    "iroha_core_privacy": (),
    "iroha_core_timed_ovn": (),
}


# Every remaining Cargo-visible feature that is not reachable from the local
# default is an explicit non-shipping surface or qualified alternative. This
# and ``CONTEXTUAL_SHIPPING_FEATURES`` form a closed inventory: adding an
# optional dependency may create an implicit Cargo feature, and that new
# feature must receive exactly one classification.
EXPLICIT_OPT_IN_FEATURES: dict[str, tuple[str, ...]] = {
    "norito": (
        "adaptive-telemetry",
        "adaptive-telemetry-log",
        "bench",
        "bench-internal",
        "codec-gpu",
        "codec-gpu-cuda",
        "codec-gpu-metal",
        "cuda-crc64",
        "cuda-stage1",
        "dev-tools",
        "gpu-compression",
        "metal-crc64",
        "metal-stage1",
        "mutation-testing",
        "schema-structural",
        "stage1-validate",
        "streaming-fixed-point-dct",
        "streaming-neural-filter",
    ),
    "iroha_crypto": (
        "bfv-test-fixtures",
        "crypto-parity-tests",
        "dev-tools",
        "sm-ffi-openssl",
        "sm-neon-force",
    ),
    "iroha_data_model": (
        "bench",
        "dev-tools",
        "fault_injection",
        "mutation-testing",
        "test-fixtures",
        "trybuild-tests",
    ),
    "iroha_core": ("bench",
 "cuda",
 "dev-tests",
 "dev-tools",
 "fastpq-gpu",
 "iroha-core-tests",
 "mutation-testing",
 "privacy-release-evidence",
 "profiling",
 "proofs-full",
 "quic",
 "sm-ffi-openssl",
 "state-commitment-prototypes",
 "test-network-parliament-signers",
 "test-network-private-settlement-evidence",
 "zk-proof-tags",
 "zk-tests"),
    "iroha_core_zk": (
        "dev-tools",
        "test-utils",
        "zk-tests",
    ),
    "iroha_torii": (
        "bench",
        "mutation-testing",
        "profiling",
        "test-fixtures",
        "test-network-private-settlement-route-control",
        "ws_integration_tests",
        "zk-proof-tags",
        "zk-tests",
    ),
    "irohad_lib": ("accel-cuda",
 "accel-metal",
 "beep",
 "dev-telemetry",
 "dev-tools",
 "fastpq-gpu",
 "mutation-testing",
 "profiling-endpoint",
 "sm-ffi-openssl",
 "telegram-alerts",
 "test-network-disposable-broker",
 "test-network-parliament-signers",
 "test-network-private-settlement-route-control",
 "zk-stark"),
    "iroha_cli_lib": ("cli_integration_harness",),
    "iroha": (
        "mutation-testing",
        "test-fixtures",
        "test-network-private-settlement-evidence",
        "tls-native",
        "tls-native-vendored",
        "tls-rustls-webpki-roots",
    ),
    "iroha_config": ("sm-ffi-openssl",),
    "iroha_genesis": ("dev-tools", "sm-ffi-openssl"),
    "iroha_telemetry": (
        "dev-telemetry",
        "telegram",
    ),
    "ivm": (
        "beep",
        "bench",
        "cuda-hardware-tests",
        "dev-tools",
        "ivm_vrf_tests",
        "ivm_zk_tests",
        "metal-hardware-tests",
    ),
    "iroha_primitives": ("bench", "trybuild-tests"),
    "iroha_kagami": ("dev-tools",),
    "iroha_zkp_halo2": ("bench", "schema-structural"),

    "irohad": ("accel-cuda", "accel-metal", "beep", "dev-telemetry", "dev-tools", "external-software-signer-bin", "fastpq-gpu", "profiling-endpoint", "sm-ffi-openssl", "telegram-alerts", "test-network-disposable-broker", "test-network-parliament-signers", "test-network-private-settlement-route-control", "zk-stark"),
    "iroha_cli": ("cli_integration_harness", "dev-tools"),
    "iroha_core_privacy": ("fastpq-replay-measurement", "privacy-release-evidence", "test-utils"),
    "iroha_core_timed_ovn": ("test-utils",),
}


# Explicit opt-ins must not leak into dependencies compiled for ordinary member
# targets. These exact consumers are non-shipping fixture/tool contexts whose
# normal dependencies intentionally need the named surface. Keeping this as a
# closed, occurrence-checked inventory makes every exception reviewable.
NONSHIPPING_EXPLICIT_OPT_IN_DEPENDENCY_ALLOWLIST: tuple[
    tuple[str, str, str], ...
] = (
    ("xtask", "iroha", "test-fixtures"),
    ("xtask", "iroha_torii", "profiling"),
    ("xtask", "iroha_torii", "ws_integration_tests"),
    ("xtask", "norito", "bench-internal"),
)


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _dependency_tables(document: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = document.get(section)
        if isinstance(table, dict):
            yield section, table

    targets = document.get("target", {})
    if not isinstance(targets, dict):
        return
    for target_name, target in targets.items():
        if not isinstance(target, dict):
            continue
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            table = target.get(section)
            if isinstance(table, dict):
                yield f"target.{target_name}.{section}", table


def cargo_visible_features(document: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Return explicit and implicit Cargo features declared by one manifest.

    Cargo creates a same-named feature for an optional dependency unless an
    explicit ``dep:<name>`` reference suppresses that shorthand. Keeping the
    implicit entries in this inventory prevents a newly optional dependency
    from silently creating an unreviewed opt-in feature.
    """

    raw_features = document.get("features", {})
    if not isinstance(raw_features, dict):
        raise ValueError("missing [features] table")

    features: dict[str, tuple[str, ...]] = {}
    for feature, raw_members in raw_features.items():
        if not isinstance(feature, str) or not feature:
            raise ValueError("feature names must be non-empty strings")
        if not isinstance(raw_members, list) or not all(
            isinstance(member, str) and member for member in raw_members
        ):
            raise ValueError(f"feature `{feature}` members must be non-empty strings")
        features[feature] = tuple(raw_members)

    explicit_dependency_references = {
        member.removeprefix("dep:")
        for members in features.values()
        for member in members
        if member.startswith("dep:")
    }
    optional_dependencies: set[str] = set()
    for _section, dependencies in _dependency_tables(document):
        optional_dependencies.update(
            dependency
            for dependency, specification in dependencies.items()
            if isinstance(specification, dict)
            and specification.get("optional") is True
        )
    for dependency in sorted(optional_dependencies - explicit_dependency_references):
        features.setdefault(dependency, (f"dep:{dependency}",))

    return features


def local_default_feature_closure(
    features: dict[str, tuple[str, ...]],
) -> frozenset[str]:
    """Return local Cargo features reachable from the local ``default`` feature.

    A non-weak dependency forward (``crate/feature``) activates an optional
    dependency just like its same-named implicit feature. Weak forwards
    (``crate?/feature``) remain conditional and terminal, as do explicit
    optional-dependency activations (``dep:crate``). Bare names are traversed
    only when they name another local explicit or implicit feature.
    """

    if "default" not in features:
        return frozenset()

    reachable: set[str] = set()
    pending = ["default"]
    while pending:
        feature = pending.pop()
        if feature in reachable:
            continue
        reachable.add(feature)
        for member in features[feature]:
            if (
                member in features
                and not member.startswith("dep:")
                and "/" not in member
            ):
                pending.append(member)
                continue
            dependency, separator, _dependency_feature = member.partition("/")
            if (
                separator
                and not dependency.endswith("?")
                and features.get(dependency) == (f"dep:{dependency}",)
            ):
                pending.append(dependency)
    return frozenset(reachable)


def _member_manifest(root: Path, member: str | Path) -> Path:
    path = root / member
    return path if path.name == "Cargo.toml" else path / "Cargo.toml"


def _workspace_patterns(workspace: dict[str, Any], field: str) -> list[str]:
    raw_patterns = workspace.get(field, [])
    if not isinstance(raw_patterns, list):
        raise ValueError(f"`workspace.{field}` must be an array")

    patterns: list[str] = []
    for raw_pattern in raw_patterns:
        if not isinstance(raw_pattern, str):
            raise ValueError(f"`workspace.{field}` paths must be strings")
        normalized = raw_pattern.replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            not normalized
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != normalized
        ):
            raise ValueError(
                f"`workspace.{field}` contains an invalid path: {raw_pattern!r}"
            )
        patterns.append(normalized)
    return patterns


def _expand_member_patterns(
    root: Path,
    patterns: Iterable[str],
    *,
    require_match: bool,
) -> set[Path]:
    manifests: set[Path] = set()
    root = root.resolve()
    for pattern in patterns:
        matched_manifests: set[Path] = set()
        for candidate in root.glob(pattern):
            manifest = _member_manifest(root, candidate)
            if not manifest.is_file():
                continue
            resolved = manifest.resolve()
            try:
                resolved.relative_to(root)
            except ValueError as error:
                raise ValueError(
                    f"workspace member resolves outside the repository: {manifest}"
                ) from error
            matched_manifests.add(resolved)
        if require_match and not matched_manifests:
            raise ValueError(f"workspace member pattern matches no manifests: {pattern}")
        manifests.update(matched_manifests)
    return manifests


def workspace_member_manifests(
    root: Path, workspace: dict[str, Any]
) -> tuple[Path, ...]:
    """Expand, exclude, and deduplicate every Cargo workspace member manifest."""

    members = _workspace_patterns(workspace, "members")
    if not members:
        raise ValueError("`workspace.members` must contain at least one path")
    excludes = _workspace_patterns(workspace, "exclude")
    included = _expand_member_patterns(root, members, require_match=True)
    excluded = _expand_member_patterns(root, excludes, require_match=False)
    return tuple(sorted(included - excluded))


def _dependency_target_and_features(
    dependency: str,
    specification: Any,
    workspace_dependencies: dict[str, Any],
) -> tuple[str, frozenset[str]]:
    """Resolve a dependency alias and its locally selected Cargo features."""

    inherited: Any = None
    if isinstance(specification, dict) and specification.get("workspace") is True:
        inherited = workspace_dependencies.get(dependency)

    target_package = dependency
    selected_features: set[str] = set()
    for candidate in (inherited, specification):
        if not isinstance(candidate, dict):
            continue
        package = candidate.get("package")
        if isinstance(package, str) and package:
            target_package = package
        raw_features = candidate.get("features", [])
        if isinstance(raw_features, list):
            selected_features.update(
                feature
                for feature in raw_features
                if isinstance(feature, str) and feature
            )

    return target_package, frozenset(selected_features)


def _non_dev_explicit_opt_in_dependency_selections(
    document: dict[str, Any], workspace_dependencies: dict[str, Any]
) -> tuple[tuple[str, str, str, str], ...]:
    """Return non-dev dependency selections of classified explicit opt-ins.

    Rows contain the dependency table, local dependency key, resolved package,
    and selected feature. Workspace dependency features are inherited when the
    member uses ``workspace = true``; ``package`` keys resolve aliases.
    """

    selections: list[tuple[str, str, str, str]] = []
    for section, dependencies in _dependency_tables(document):
        if section.rsplit(".", 1)[-1] == "dev-dependencies":
            continue
        for dependency, specification in dependencies.items():
            target_package, selected_features = _dependency_target_and_features(
                dependency, specification, workspace_dependencies
            )
            opt_ins = EXPLICIT_OPT_IN_FEATURES.get(target_package)
            if opt_ins is None:
                continue
            for feature in sorted(selected_features & frozenset(opt_ins)):
                selections.append((section, dependency, target_package, feature))
    return tuple(selections)


# These are protocol owners even when all optional model features are disabled.
MANDATORY_MODEL_JSON_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "iroha_crypto": ("json",),
    "iroha_primitives": ("json",),
    "iroha_version": (),
    "norito": ("base-codec",),
    "norito_derive": (),
}


def _check_mandatory_model_json_dependencies(
    document: dict[str, Any], manifest_path: Path
) -> list[str]:
    """Require aggregate protocol JSON without an optional feature switch."""

    dependencies = document.get("dependencies", {})
    errors: list[str] = []
    for name, required_features in MANDATORY_MODEL_JSON_DEPENDENCIES.items():
        specification = dependencies.get(name) if isinstance(dependencies, dict) else None
        if (
            not isinstance(specification, dict)
            or specification.get("optional", False) is not False
        ):
            errors.append(
                f"{manifest_path}: mandatory model JSON dependency `{name}` must be "
                "a non-optional normal dependency"
            )
            continue
        selected = specification.get("features", [])
        if (
            not isinstance(selected, list)
            or not all(isinstance(feature, str) for feature in selected)
            or not set(required_features).issubset(selected)
        ):
            errors.append(
                f"{manifest_path}: mandatory model JSON dependency `{name}` must "
                f"select {list(required_features)!r} unconditionally"
            )
    return errors


# The CLI implementation always owns its complete runtime; only the thin
# executable's target selection is controlled by its `cli` feature.
MANDATORY_CLI_RUNTIME_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "iroha_core": ("node",),
    "iroha_crypto": ("consensus",),
    "norito": ("node-codec",),
}


def _check_mandatory_cli_runtime_dependencies(
    document: dict[str, Any], manifest_path: Path
) -> list[str]:
    """Reject partial or optionally activated CLI runtime implementations."""
    dependencies = document.get("dependencies", {})
    errors: list[str] = []
    for name, required in MANDATORY_CLI_RUNTIME_DEPENDENCIES.items():
        specification = dependencies.get(name) if isinstance(dependencies, dict) else None
        if not isinstance(specification, dict) or specification.get("optional", False) is not False:
            errors.append(
                f"{manifest_path}: mandatory CLI runtime dependency `{name}` must be "
                "a non-optional normal dependency"
            )
            continue
        selected = specification.get("features", [])
        if (not isinstance(selected, list)
                or not all(isinstance(feature, str) for feature in selected)
                or not set(required).issubset(selected)):
            errors.append(
                f"{manifest_path}: mandatory CLI runtime dependency `{name}` must "
                f"select {list(required)!r} unconditionally"
            )
    return errors


MANDATORY_CORE_BACKENDS: dict[str, tuple[str, ...]] = {
    "iroha_core": ("kaigi_zk",),
    "iroha_core_zk": ("kaigi_zk", "iroha_plonk", "iroha_plonk_gadgets", "iroha_pasta"),
}


def _check_mandatory_core_backends(
    document: dict[str, Any], manifest_path: Path, owners: tuple[str, ...]
) -> list[str]:
    """Require canonical native owners as unconditional normal dependencies."""

    dependencies = document.get("dependencies", {})
    errors: list[str] = []
    for owner in owners:
        specification = dependencies.get(owner) if isinstance(dependencies, dict) else None
        if (
            not isinstance(specification, dict)
            or specification.get("optional", False) is not False
            or specification.get("path") != f"../{owner}"
            or specification.get("package", owner) != owner
        ):
            errors.append(
                f"{manifest_path}: mandatory Core backend `{owner}` must retain "
                "its non-optional local owner"
            )
    return errors


def _check_mandatory_daemon_cuda(document: dict[str, Any], manifest_path: Path) -> list[str]:
    """Keep daemon CUDA on the single mandatory Linux/Windows dependency row."""
    scope = 'cfg(any(target_os = "linux", target_os = "windows"))'
    targets = document.get("target", {})
    if (document.get("dependencies", {}).get("ivm") != {"workspace": True}
            or targets.get(scope, {}).get("dependencies", {}).get("ivm") != {"workspace": True, "features": ["cuda"]}
            or any("ivm" in value.get("dependencies", {}) for key, value in targets.items() if key != scope)
            or "ivm-cuda" in document.get("features", {})):
        return [f"{manifest_path}: mandatory daemon CUDA requires the exact Linux/Windows target dependency"]
    return []


def _check_expected_features(
    document: dict[str, Any], manifest_path: Path
) -> list[str]:
    package = document.get("package", {})
    package_name = package.get("name") if isinstance(package, dict) else None
    expected = EXPECTED_FEATURES.get(package_name)
    if expected is None:
        return []

    errors = _check_mandatory_core_backends(
        document, manifest_path, MANDATORY_CORE_BACKENDS.get(package_name, ())
    )
    if package_name == "irohad_lib":
        errors.extend(_check_mandatory_daemon_cuda(document, manifest_path))
    if package_name == "iroha_data_model":
        errors.extend(_check_mandatory_model_json_dependencies(document, manifest_path))
    if package_name == "iroha_cli_lib":
        errors.extend(_check_mandatory_cli_runtime_dependencies(document, manifest_path))
    if package_name == "iroha_core_zk":
        dependencies = document.get("dependencies", {})
        specification = (
            dependencies.get("fastpq_prover")
            if isinstance(dependencies, dict)
            else None
        )
        if not isinstance(specification, dict) or specification.get("optional") is not True:
            errors.append(
                f"{manifest_path}: STARK field dependency `fastpq_prover` must be "
                "an optional normal dependency enabled by `zk-stark`"
            )
    try:
        actual_features = cargo_visible_features(document)
    except ValueError as error:
        return [f"{manifest_path}: {error}"]

    contextual_members = CONTEXTUAL_SHIPPING_FEATURES.get(package_name)
    opt_in_members = EXPLICIT_OPT_IN_FEATURES.get(package_name)
    if contextual_members is None:
        return [f"{manifest_path}: missing contextual shipping feature inventory"]
    if opt_in_members is None:
        return [f"{manifest_path}: missing explicit opt-in feature inventory"]
    if tuple(sorted(set(contextual_members))) != contextual_members:
        errors.append(
            f"{manifest_path}: contextual shipping feature inventory must be "
            "sorted and contain no duplicates"
        )
    if tuple(sorted(set(opt_in_members))) != opt_in_members:
        errors.append(
            f"{manifest_path}: explicit opt-in feature inventory must be sorted "
            "and contain no duplicates"
        )
    contextual = frozenset(contextual_members)
    opt_in = frozenset(opt_in_members)
    reachable = local_default_feature_closure(actual_features)
    actual_names = frozenset(actual_features)
    expected_names = frozenset(expected)
    expected_portable = expected_names - contextual - opt_in

    for feature in sorted(actual_names - reachable - contextual - opt_in):
        errors.append(
            f"{manifest_path}: Cargo feature `{feature}` is unclassified; "
            "add it to the portable default closure, contextual shipping "
            "inventory, or explicit opt-in inventory"
        )
    for feature in sorted(contextual - actual_names):
        errors.append(
            f"{manifest_path}: stale contextual shipping feature `{feature}` is "
            "not declared by Cargo"
        )
    for feature in sorted(opt_in - actual_names):
        errors.append(
            f"{manifest_path}: stale explicit opt-in feature `{feature}` is not "
            "declared by Cargo"
        )
    for feature in sorted(contextual & opt_in):
        errors.append(
            f"{manifest_path}: feature `{feature}` is classified as both "
            "contextual shipping and explicit opt-in"
        )
    for feature in sorted(contextual & reachable):
        errors.append(
            f"{manifest_path}: contextual shipping feature `{feature}` is "
            "reachable from local `default`"
        )
    for feature in sorted(opt_in & reachable):
        errors.append(
            f"{manifest_path}: explicit opt-in feature `{feature}` is reachable "
            "from `default`"
        )
    for feature in sorted(contextual - expected_names):
        errors.append(
            f"{manifest_path}: contextual shipping feature `{feature}` lacks an "
            "exact feature pin"
        )
    for feature in sorted(reachable - expected_portable):
        errors.append(
            f"{manifest_path}: default-reachable feature `{feature}` lacks an "
            "exact portable feature pin"
        )
    for feature in sorted(expected_portable - reachable):
        errors.append(
            f"{manifest_path}: portable feature `{feature}` is not reachable "
            "from `default`"
        )

    for feature, expected_members in expected.items():
        actual_members = actual_features.get(feature)
        if actual_members is None:
            errors.append(f"{manifest_path}: missing feature aggregate `{feature}`")
            continue
        if actual_members != expected_members:
            errors.append(
                f"{manifest_path}: feature `{feature}` must be "
                f"{list(expected_members)!r}, found {actual_members!r}"
            )
    return errors


def _check_model_storage_boundary(
    documents: dict[str, dict[str, Any]], workspace_dependencies: dict[str, Any]
) -> list[str]:
    """Reject storage engines in the model's declared non-dev dependency closure.

    Include optional and target-specific dependencies and build dependencies:
    no supported feature or platform may reconnect model compilation to storage.
    Dependency aliases and workspace inheritance use the same resolution as
    the feature guard. Development dependencies intentionally stay outside it.
    """

    graph: dict[str, set[str]] = {}
    for package, document in documents.items():
        graph[package] = {
            _dependency_target_and_features(name, spec, workspace_dependencies)[0]
            for section, dependencies in _dependency_tables(document)
            if section.rsplit(".", 1)[-1] != "dev-dependencies"
            for name, spec in dependencies.items()
        }
    errors: list[str] = []
    for origin in ("iroha_model_base", "iroha_data_model"):
        pending = [(origin,)] if origin in graph else []
        seen: set[str] = set()
        while pending:
            path = pending.pop(0)
            package = path[-1]
            if package in seen:
                continue
            seen.add(package)
            if package in {"mv", "concread"}:
                errors.append(
                    f"model storage dependency boundary: {' -> '.join(path)}; "
                    "model codecs must not depend on runtime storage"
                )
                continue
            pending.extend((*path, child) for child in sorted(graph.get(package, ())))
    return errors


def check_repository(root: Path) -> list[str]:
    """Return deterministic feature-hygiene violations for ``root``."""

    root = root.resolve()
    root_manifest_path = root / "Cargo.toml"
    root_manifest = _load_toml(root_manifest_path)
    workspace = root_manifest.get("workspace", {})
    if not isinstance(workspace, dict):
        return [f"{root_manifest_path}: missing [workspace] table"]
    workspace_dependencies = workspace.get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        return [f"{root_manifest_path}: `workspace.dependencies` must be a table"]

    errors: list[str] = []
    for label, policy in (
        ("contextual shipping", CONTEXTUAL_SHIPPING_FEATURES),
        ("explicit opt-in", EXPLICIT_OPT_IN_FEATURES),
    ):
        missing_policies = sorted(set(EXPECTED_FEATURES) - set(policy))
        stale_policies = sorted(set(policy) - set(EXPECTED_FEATURES))
        if missing_policies:
            errors.append(
                f"{root_manifest_path}: guarded packages lack {label} feature "
                f"inventories: {missing_policies}"
            )
        if stale_policies:
            errors.append(
                f"{root_manifest_path}: {label} feature inventories name "
                f"unguarded packages: {stale_policies}"
            )
    for dependency in sorted(FOUNDATIONAL_DEPENDENCIES):
        specification = workspace_dependencies.get(dependency)
        if not isinstance(specification, dict):
            errors.append(
                f"{root_manifest_path}: workspace dependency `{dependency}` "
                "must use a table with `default-features = false`"
            )
            continue
        if specification.get("default-features") is not False:
            errors.append(
                f"{root_manifest_path}: workspace dependency `{dependency}` "
                "must set `default-features = false`"
            )
        if "features" in specification:
            errors.append(
                f"{root_manifest_path}: workspace dependency `{dependency}` "
                "must not inject features"
            )

    try:
        member_manifests = workspace_member_manifests(root, workspace)
    except ValueError as error:
        return [*errors, f"{root_manifest_path}: {error}"]

    raw_allowlist = NONSHIPPING_EXPLICIT_OPT_IN_DEPENDENCY_ALLOWLIST
    if tuple(sorted(set(raw_allowlist))) != raw_allowlist:
        errors.append(
            f"{root_manifest_path}: non-shipping explicit opt-in dependency "
            "allowlist must be sorted and contain no duplicates"
        )
    allowlist = frozenset(raw_allowlist)
    valid_allowlist: set[tuple[str, str, str]] = set()
    for consumer, dependency, feature in sorted(allowlist):
        if feature not in EXPLICIT_OPT_IN_FEATURES.get(dependency, ()):
            errors.append(
                f"{root_manifest_path}: non-shipping explicit opt-in dependency "
                f"allowlist entry `{consumer} -> {dependency}/{feature}` does not "
                "name a classified explicit opt-in feature"
            )
            continue
        valid_allowlist.add((consumer, dependency, feature))

    model_boundary_documents: dict[str, dict[str, Any]] = {}
    workspace_package_names: set[str] = set()
    observed_allowlist_entries: set[tuple[str, str, str]] = set()
    for manifest_path in member_manifests:
        document = _load_toml(manifest_path)
        package = document.get("package", {})
        package_name = package.get("name") if isinstance(package, dict) else None
        if isinstance(package_name, str) and package_name:
            workspace_package_names.add(package_name)
            model_boundary_documents[package_name] = document
            for section, dependency_key, target_package, feature in (
                _non_dev_explicit_opt_in_dependency_selections(
                    document, workspace_dependencies
                )
            ):
                entry = (package_name, target_package, feature)
                if entry in valid_allowlist:
                    observed_allowlist_entries.add(entry)
                    continue
                alias = (
                    ""
                    if dependency_key == target_package
                    else f" (package `{target_package}`)"
                )
                errors.append(
                    f"{manifest_path}: package `{package_name}` [{section}] "
                    f"dependency `{dependency_key}`{alias} selects explicit opt-in "
                    f"feature `{feature}` from a non-dev dependency declaration"
                )
        errors.extend(_check_expected_features(document, manifest_path))
        for section, dependencies in _dependency_tables(document):
            for dependency in sorted(FOUNDATIONAL_DEPENDENCIES & dependencies.keys()):
                specification = dependencies[dependency]
                if not isinstance(specification, dict) or specification.get(
                    "default-features"
                ) is not False:
                    errors.append(
                        f"{manifest_path}: [{section}] `{dependency}` must set "
                        "`default-features = false` and select features locally"
                    )

    errors.extend(_check_model_storage_boundary(model_boundary_documents, workspace_dependencies))

    for consumer, dependency, feature in sorted(
        valid_allowlist - observed_allowlist_entries
    ):
        if dependency not in workspace_package_names:
            continue
        errors.append(
            f"{root_manifest_path}: stale non-shipping explicit opt-in dependency "
            f"allowlist entry `{consumer} -> {dependency}/{feature}` is not selected "
            "by a non-dev workspace dependency declaration"
        )

    return errors


def main() -> int:
    """Run the command-line feature-hygiene check."""

    parser = argparse.ArgumentParser(
        description=(
            "Reject workspace-level feature injection and implicit defaults in "
            "every Cargo workspace member."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root containing Cargo.toml (default: inferred)",
    )
    args = parser.parse_args()

    errors = check_repository(args.root)
    if errors:
        print("Cargo feature hygiene violations:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("Cargo feature hygiene check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
