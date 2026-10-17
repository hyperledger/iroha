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
        bytes=315_740,
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


def _literal_asset_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """One authenticated byte asset with a deterministic historical source owner."""
    import hashlib
    import json

    root = tmp_path.resolve()
    crate = root / "crate"
    source = crate / "src/lib.rs"
    assets = source.parent / "assets"
    assets.mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "asset_fixture"\nversion = "0.1.0"\n')
    (assets / "table.bin").write_bytes(b"\x01")
    historical = b"const TABLE: [u8; 1] = [1];\n"
    manifest_path = Path("crate/src/assets/manifest.json")
    manifest = {
        "format_version": 1,
        "source_commit": "1" * 40,
        "source_slice_hash_scope": MODULE.DECLARATION_HASH_SCOPE,
        "assets": [{
            "path": "table.bin",
            "byte_length": 1,
            "sha256": hashlib.sha256(b"\x01").hexdigest(),
            "layout": "one unsigned byte",
            "source_preimages": [{
                "path": "../lib.rs",
                "constant": "TABLE",
                "physical_lines": 1,
                "sha256": hashlib.sha256(historical).hexdigest(),
            }],
        }],
    }
    (root / manifest_path).write_text(json.dumps(manifest))
    source.write_text('const TABLE: &[u8; 1] = include_bytes!("assets/table.bin");\n')
    monkeypatch.setattr(MODULE, "MANIFEST_PATHS", (manifest_path,))
    monkeypatch.setattr(MODULE, "_git_blob", lambda *_arguments: historical)
    return root, source


@pytest.mark.parametrize("extra", [
    'fn read() { let bytes = include_bytes!("assets/table.bin"); }\n',
    'static AGAIN: &[u8; 1] = include_bytes!("assets/table.bin");\n',
    'fn read() { consume(include_bytes!("assets/table.bin")); }\n',
    'fn read() { let bytes = include_bytes! { r#"assets/table.bin"# }; }\n',
])
def test_duplicate_literal_consumers_refuse_even_outside_const_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str
) -> None:
    root, source = _literal_asset_fixture(tmp_path, monkeypatch)
    assert MODULE.audit_repository(root) == MODULE.AuditCounts(1, 1, 1, 1)
    source.write_text(source.read_text() + extra)
    with pytest.raises(MODULE.AssetError, match="exactly one.*found 2"):
        MODULE.audit_repository(root)


def test_build_script_literal_duplicate_is_also_a_consumer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, source = _literal_asset_fixture(tmp_path, monkeypatch)
    (source.parents[1] / "build.rs").write_text(
        'fn main() { let bytes = include_bytes!("src/assets/table.bin"); }\n'
    )
    with pytest.raises(MODULE.AssetError, match="exactly one.*found 2"):
        MODULE.audit_repository(root)


@pytest.mark.parametrize("opening,closing", [("(", ")"), ("[", "]"), ("{", "}")])
@pytest.mark.parametrize("literal", [
    '"assets/table.bin"',
    'r"assets/table.bin"',
    'r###"assets/table.bin"###',
    '"assets/ta\\x62le.bin"',
    '"assets/ta\\u{6_2}le.bin"',
    '"assets/ta\\\n    ble.bin"',
])
def test_typed_owner_preserves_length_across_literal_and_token_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opening: str, closing: str, literal: str
) -> None:
    root, source = _literal_asset_fixture(tmp_path, monkeypatch)
    source.write_text(
        "pub(crate) const TABLE: & /* type */ [u8; 0_1] = "
        f"std::include_bytes /* name */ ! {opening} /* argument */ {literal} /* tail */, {closing};\n"
    )
    assert MODULE.audit_repository(root) == MODULE.AuditCounts(1, 1, 1, 1)
    source.write_text(source.read_text().replace("[u8; 0_1]", "[u8; 2]"))
    with pytest.raises(MODULE.AssetError, match="declares 2 bytes.*expected 1"):
        MODULE.audit_repository(root)


def test_sole_untyped_local_include_does_not_replace_constant_length_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, source = _literal_asset_fixture(tmp_path, monkeypatch)
    source.write_text('fn read() { let bytes = include_bytes!("assets/table.bin"); }\n')
    with pytest.raises(MODULE.AssetError, match="declares None bytes.*expected 1"):
        MODULE.audit_repository(root)


def test_comments_and_literal_examples_do_not_create_asset_consumers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, source = _literal_asset_fixture(tmp_path, monkeypatch)
    fake = 'const SPOOF: &[u8; 1] = include_bytes!("assets/table.bin");'
    source.write_text(source.read_text() + (
        f"// {fake}\n"
        f"/* outer /* nested */ {fake} */\n"
        'const TEXT: &str = "const SPOOF: &[u8; 1] = include_bytes!(\\"assets/table.bin\\");";\n'
        f'const RAW: &str = r###"{fake}"###;\n'
        f'const BYTE_RAW: &[u8] = br###"{fake}"###;\n'
        f'const C_RAW: &core::ffi::CStr = cr###"{fake}"###;\n'
        "fn lifetime<'a>(value: &'a str) { let character = 'x'; }\n"
    ))
    assert MODULE.audit_repository(root) == MODULE.AuditCounts(1, 1, 1, 1)


def test_raw_c_literal_mask_preserves_offsets_and_hides_fake_include_tokens() -> None:
    spec = importlib.util.spec_from_file_location(
        "asset_test_rust_lexical_index", ROOT / "scripts/zk_rust_lexical_index.py"
    )
    assert spec is not None and spec.loader is not None
    lexical = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = lexical
    spec.loader.exec_module(lexical)
    source = 'const TEXT: &core::ffi::CStr = cr###"quoted " include_bytes!("fake.bin")\nend"###;\nfn real() {}\n'
    masked = lexical.mask(source)
    assert len(masked) == len(source)
    assert [index for index, character in enumerate(masked) if character == "\n"] == [
        index for index, character in enumerate(source) if character == "\n"
    ]
    assert "include_bytes" not in masked
    assert "fn real() {}" in masked


def test_raw_literal_contents_are_not_reinterpreted_as_comments_or_delimiters(tmp_path: Path) -> None:
    crate = tmp_path / "crate"
    source = crate / "src/lib.rs"
    source.parent.mkdir(parents=True)
    path = 'assets/a"#)/*literal*/table.bin'
    source.write_text(f'fn read() {{ let bytes = include_bytes![r###"{path}"###]; }}\n')
    assert MODULE._include_consumers(crate) == {
        (source.parent / path).resolve(): [MODULE.IncludeConsumer(source, "include_bytes", None)]
    }


@pytest.mark.parametrize("expression,reason", [
    ('"assets/table.bin" + suffix', "one complete string literal"),
    ('"assets/table.bin", "other.bin"', "one complete string literal"),
    ('"assets/ta\\qble.bin"', "unsupported Rust string escape"),
    ('"assets/ta\\xFFble.bin"', "invalid Rust ASCII escape"),
    ('"assets/ta\\u{D800}ble.bin"', "invalid Rust Unicode scalar"),
    ('"assets/ta\\u{110000}ble.bin"', "invalid Rust Unicode scalar"),
    ('"assets/ta\\0ble.bin"', "contains NUL"),
    ('""', "empty"),
])
def test_literal_argument_errors_are_not_silently_downgraded(
    tmp_path: Path, expression: str, reason: str
) -> None:
    crate = tmp_path / "crate"
    source = crate / "src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text(f"fn read() {{ let bytes = include_bytes!({expression}); }}\n")
    with pytest.raises(MODULE.AssetError, match=reason):
        MODULE._include_consumers(crate)


def test_mismatched_macro_delimiter_and_unterminated_literals_refuse(tmp_path: Path) -> None:
    crate = tmp_path / "crate"
    source = crate / "src/lib.rs"
    source.parent.mkdir(parents=True)
    for text, reason in [
        ('fn read() { let bytes = include_bytes!["assets/table.bin"); }', "one complete string literal"),
        ('fn read() { let bytes = include_bytes!("assets/table.bin', "unterminated include path"),
        ('fn read() { let bytes = include_bytes!(r##"assets/table.bin"#); }', "unterminated raw include path"),
    ]:
        source.write_text(text)
        with pytest.raises(MODULE.AssetError, match=reason):
            MODULE._include_consumers(crate)


def test_nonliteral_expansion_does_not_fabricate_authenticated_literal_consumer(tmp_path: Path) -> None:
    crate = tmp_path / "crate"
    source = crate / "src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        'const GENERATED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/table.bin"));\n'
        'const INDIRECT: &str = include_str!(PATH_EXPRESSION);\n'
    )
    # Expansion is explicitly outside this lexical inventory. It cannot supply
    # the direct owner or declared length required to authenticate a manifest row.
    assert MODULE._include_consumers(crate) == {}


def test_raw_and_ordinary_include_str_calls_share_literal_consumer_accounting(tmp_path: Path) -> None:
    crate = tmp_path / "crate"
    source = crate / "src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        'const TEXT: &str = include_str!("assets/message.txt");\n'
        'fn read() { consume(include_str /* macro */ ! { r##"assets/message.txt"##, }); }\n'
        '// include_str!("assets/ignored.txt")\n'
    )
    assert MODULE._include_consumers(crate) == {
        (source.parent / "assets/message.txt").resolve(): [
            MODULE.IncludeConsumer(source, "include_str", None),
            MODULE.IncludeConsumer(source, "include_str", None),
        ]
    }
