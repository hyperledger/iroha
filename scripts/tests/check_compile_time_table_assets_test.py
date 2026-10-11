"""Tests for the compile-time Rust static asset verifier."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/check_compile_time_table_assets.py"
SPEC = importlib.util.spec_from_file_location(
    "check_compile_time_table_assets", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_checked_in_compile_time_assets_and_preimages_are_exact() -> None:
    counts = MODULE.audit_repository(ROOT)
    assert counts == MODULE.AuditCounts(
        manifests=10,
        assets=82,
        bytes=314_076,
        source_preimages=89,
    )


def test_declaration_slice_uses_exact_name_line_count_and_final_lf() -> None:
    source = b"const FIRST: [u8; 1] = [1];\nconst SECOND: [u8; 2] = [\n    2,\n    3,\n];\n"
    assert MODULE.declaration_slice(source, "SECOND", 4) == (
        b"const SECOND: [u8; 2] = [\n    2,\n    3,\n];\n"
    )
    with pytest.raises(MODULE.AssetError, match="semicolon \\+ LF"):
        MODULE.declaration_slice(source, "SECOND", 3)
    with pytest.raises(MODULE.AssetError, match="exactly once"):
        MODULE.declaration_slice(source, "MISSING", 1)


def test_line_span_slice_pins_start_count_and_final_lf() -> None:
    source = b"first\nsecond\nthird\n"
    assert MODULE.line_span_slice(source, 2, 2) == b"second\nthird\n"
    with pytest.raises(MODULE.AssetError, match="exceeds source bounds"):
        MODULE.line_span_slice(source, 3, 2)
    with pytest.raises(MODULE.AssetError, match="does not end with LF"):
        MODULE.line_span_slice(b"first\nsecond", 2, 1)


def test_raw_string_payload_recovers_exact_literal_bytes() -> None:
    span = b'    let value = r#"first\nsecond\n"#;\n'
    assert MODULE.rust_raw_string_payload(span) == b"first\nsecond\n"
    with pytest.raises(MODULE.AssetError, match="no r# raw string"):
        MODULE.rust_raw_string_payload(b'let value = "ordinary";\n')
    with pytest.raises(MODULE.AssetError, match="no raw string terminator"):
        MODULE.rust_raw_string_payload(b'let value = r#"unterminated\n')


def test_suffix_include_inventory_rejects_unmanifested_consumers(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    manifest_path = root / "crate/src/assets/template_manifest.json"
    manifested = manifest_path.parent / "manifested.tmpl"
    extra = root / "crate/src/other/extra.tmpl"
    consumer = MODULE.IncludeConsumer(root / "crate/src/lib.rs", "include_str", None)

    MODULE._verify_suffix_include_inventory(
        root, manifest_path, {manifested}, {manifested: [consumer]}, ".tmpl"
    )
    with pytest.raises(MODULE.AssetError, match=r"extra=\['extra\.tmpl'\]"):
        MODULE._verify_suffix_include_inventory(
            root,
            manifest_path,
            {manifested},
            {manifested: [consumer], extra: [consumer]},
            ".tmpl",
        )


def test_current_include_preimage_is_exact_and_rejects_historical_fields(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    manifest_dir = root / "crate/src/assets"
    source = root / "crate/src/lib.rs"
    consumer = MODULE.IncludeConsumer(source, "include_str", None)
    exact = [{"path": "../lib.rs"}]

    MODULE._verify_current_include_preimage(
        root, manifest_dir, exact, consumer, "asset.source_preimages"
    )
    with pytest.raises(MODULE.AssetError, match="unknown fields: start_line"):
        MODULE._verify_current_include_preimage(
            root,
            manifest_dir,
            [{"path": "../lib.rs", "start_line": 1}],
            consumer,
            "asset.source_preimages",
        )
    with pytest.raises(MODULE.AssetError, match="live include consumer"):
        MODULE._verify_current_include_preimage(
            root,
            manifest_dir,
            [{"path": "../other.rs"}],
            consumer,
            "asset.source_preimages",
        )
    with pytest.raises(MODULE.AssetError, match="exactly one"):
        MODULE._verify_current_include_preimage(
            root, manifest_dir, [], consumer, "asset.source_preimages"
        )


def test_current_include_scope_is_explicitly_limited_to_soracloud_manifests() -> None:
    soracloud_manifest = next(iter(MODULE.CURRENT_INCLUDE_CONSUMER_MANIFESTS))
    MODULE._verify_manifest_scope(
        soracloud_manifest, MODULE.CURRENT_INCLUDE_CONSUMER_SCOPE
    )

    with pytest.raises(MODULE.AssetError, match="source hash scope must be"):
        MODULE._verify_manifest_scope(soracloud_manifest, MODULE.LINE_SPAN_HASH_SCOPE)
    with pytest.raises(MODULE.AssetError, match="not enabled"):
        MODULE._verify_manifest_scope(
            Path("crates/example/src/assets/manifest.json"),
            MODULE.CURRENT_INCLUDE_CONSUMER_SCOPE,
        )


def test_historical_source_owner_can_differ_from_moved_consumer(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    consumer = root / "crates/new/src/assets"
    preimage = {"path": "../tables.rs", "source_path": "crates/old/src/tables.rs"}
    assert MODULE._historical_source_path(root, consumer, preimage, "fixture") == "crates/old/src/tables.rs"
    assert MODULE._historical_source_path(root, consumer, {"path": "../tables.rs"}, "fixture") == "crates/new/src/tables.rs"
    with pytest.raises(MODULE.AssetError, match="escapes"):
        MODULE._historical_source_path(root, consumer, {"source_path": "../escape.rs"}, "fixture")
