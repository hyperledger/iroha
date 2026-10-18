#!/usr/bin/env python3
"""Verify versioned static assets consumed by direct Rust literal includes.

This source inventory counts literal include_bytes!/include_str! invocations in
const, static and local expressions. It does not expand macros or generated
source, resolve macro aliases, or guess paths from concat!/env! expressions.
Those unexpanded forms are outside this literal-asset qualification. Manifest
assets still require exactly one direct consumer and an explicit byte length.
"""

from __future__ import annotations

import argparse
import importlib.util
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_LEXICAL_SPEC = importlib.util.spec_from_file_location(
    "iroha_static_asset_rust_lexical_index", Path(__file__).with_name("zk_rust_lexical_index.py")
)
assert _LEXICAL_SPEC is not None and _LEXICAL_SPEC.loader is not None
RUST_LEXICAL = importlib.util.module_from_spec(_LEXICAL_SPEC)
sys.modules[_LEXICAL_SPEC.name] = RUST_LEXICAL
_LEXICAL_SPEC.loader.exec_module(RUST_LEXICAL)

MANIFEST_PATHS = (
    Path(
        "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/"
        "falcon512/assets/manifest.json"
    ),
    Path("crates/iroha_core_privacy/src/privacy_engines/zk_x509/assets/manifest.json"),
    Path("crates/ivm/src/assets/manifest.json"),
    Path("crates/ivm/src/assets/iso20022_schema_v1/manifest.json"),
    Path("crates/ivm/src/assets/text_v1/manifest.json"),
    Path("crates/kotodama_lang/src/assets/diagnostics_v1/manifest.json"),
    Path("crates/fastpq_isi/src/assets/manifest.json"),
    Path("crates/iroha_cli/src/soracloud/assets/v1/template_manifest.json"),
    Path("crates/iroha_cli/src/soracloud/templates/v1/static/manifest.json"),
    Path("crates/iroha_torii/src/sorafs/assets/evidence_viewer_v1/manifest.json"),
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DECLARATION_HASH_SCOPE = "complete Rust constant declaration including trailing LF"
LINE_SPAN_HASH_SCOPE = "line-count-pinned Rust extraction span including trailing LF"
STRUCTURED_TABLE_HASH_SCOPE = (
    "line-count-pinned Rust structured-table projection span including trailing LF"
)
CURRENT_INCLUDE_CONSUMER_SCOPE = "current Rust compile-time include consumer"
CURRENT_INCLUDE_CONSUMER_MANIFESTS = frozenset(
    {
        Path("crates/ivm/src/assets/iso20022_schema_v1/manifest.json"),
        Path("crates/kotodama_lang/src/assets/diagnostics_v1/manifest.json"),
        Path("crates/iroha_cli/src/soracloud/assets/v1/template_manifest.json"),
        Path("crates/iroha_cli/src/soracloud/templates/v1/static/manifest.json"),
        Path("crates/fastpq_isi/src/assets/manifest.json"),
    }
)
CONST_DECLARATION_RE = re.compile(
    r"\bconst\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:"
)
INCLUDE_CALL_RE = re.compile(
    r"(?<![\w])(?:r#)?(?P<macro>include_bytes|include_str)\s*!\s*(?P<opening>[([{])"
)
BYTE_INCLUDE_OWNER_RE = re.compile(
    r"\bconst\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*&\s*"
    r"(?:'static\s*)?\[\s*u8\s*;\s*(?P<length>[0-9][0-9_]*)\s*\]\s*=\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*(?:r#)?(?P<macro>include_bytes)\s*!"
)
MANIFEST_FIELDS = frozenset(
    {
        "format_version",
        "source_commit",
        "source_slice_hash_scope",
        "asset_inventory_suffix",
        "canonical_ron",
        "assets",
    }
)
ASSET_FIELDS = frozenset(
    {"path", "byte_length", "sha256", "layout", "source_preimages"}
)
DECLARATION_PREIMAGE_FIELDS = frozenset(
    {"path", "constant", "physical_lines", "sha256", "source_commit", "source_path"}
)
LINE_SPAN_PREIMAGE_FIELDS = frozenset(
    {"path", "start_line", "physical_lines", "sha256", "source_commit", "source_path"}
)
CURRENT_INCLUDE_PREIMAGE_FIELDS = frozenset({"path"})


class AssetError(ValueError):
    """One compile-time static asset failed its sealed contract."""


@dataclass(frozen=True)
class AuditCounts:
    """Counts emitted by a successful repository audit."""

    manifests: int
    assets: int
    bytes: int
    source_preimages: int


@dataclass(frozen=True)
class IncludeConsumer:
    """One compile-time Rust include of a manifest asset."""

    source: Path
    macro: str
    declared_length: int | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: inferred from this script)",
    )
    return parser.parse_args()


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssetError(f"{context} must be a JSON object")
    return value


def _exact_fields(value: dict[str, Any], expected: frozenset[str], context: str) -> None:
    unknown = sorted(set(value) - expected)
    if unknown:
        raise AssetError(f"{context} has unknown fields: {', '.join(unknown)}")


def _positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AssetError(f"{context} must be a positive integer")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise AssetError(f"{context} must be a non-empty string")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_path(root: Path, base: Path, raw: str, context: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        raise AssetError(f"{context} must be repository-relative")
    unresolved = base / candidate
    if unresolved.is_symlink():
        raise AssetError(f"{context} must not be a symlink: {raw}")
    resolved = unresolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise AssetError(f"{context} escapes the repository: {raw}") from error
    return resolved


def _historical_source_path(root: Path, base: Path, preimage: dict[str, Any], context: str) -> str:
    """Resolve the immutable source owner, independently of a moved consumer."""
    if "source_path" in preimage:
        return _safe_path(root, root, _string(preimage["source_path"], f"{context}.source_path"), f"{context}.source_path").relative_to(root).as_posix()
    return _safe_path(root, base, _string(preimage.get("path"), f"{context}.path"), f"{context}.path").relative_to(root).as_posix()


def declaration_slice(source: bytes, constant: str, physical_lines: int) -> bytes:
    """Return one line-count-pinned constant declaration from a historical blob."""

    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssetError("historical Rust source is not UTF-8") from error
    lines = text.splitlines(keepends=True)
    starts = []
    for index, line in enumerate(lines):
        match = CONST_DECLARATION_RE.search(line)
        if match is not None and match.group("name") == constant:
            starts.append(index)
    if len(starts) != 1:
        raise AssetError(
            f"historical Rust source must declare const {constant} exactly once; "
            f"found {len(starts)}"
        )
    start = starts[0]
    end = start + physical_lines
    if end > len(lines):
        raise AssetError(
            f"const {constant} declares {physical_lines} lines beyond source EOF"
        )
    declaration = "".join(lines[start:end]).encode("utf-8")
    if not declaration.endswith(b";\n"):
        raise AssetError(
            f"line-count-pinned const {constant} does not end with semicolon + LF"
        )
    return declaration


def line_span_slice(source: bytes, start_line: int, physical_lines: int) -> bytes:
    """Return an exact line-count-pinned span from a historical source blob."""

    lines = source.splitlines(keepends=True)
    start = start_line - 1
    end = start + physical_lines
    if start < 0 or end > len(lines):
        raise AssetError(
            f"historical Rust span {start_line}+{physical_lines} exceeds source bounds"
        )
    span = b"".join(lines[start:end])
    if not span.endswith(b"\n"):
        raise AssetError("line-count-pinned Rust extraction span does not end with LF")
    return span


def rust_raw_string_payload(source_slice: bytes) -> bytes:
    """Extract the payload of one `r#"..."#` literal from a sealed Rust span."""

    start = source_slice.find(b'r#"')
    if start < 0:
        raise AssetError("sealed Rust extraction span has no r# raw string literal")
    start += 3
    end = source_slice.find(b'"#', start)
    if end < 0:
        raise AssetError("sealed Rust extraction span has no raw string terminator")
    return source_slice[start:end]


def _git_blob(root: Path, commit: str, relative: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "show", f"{commit}:{relative}"],
            cwd=root,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        diagnostic = error.stderr.decode("utf-8", errors="replace").strip()
        raise AssetError(
            f"cannot read historical source {commit}:{relative}: {diagnostic}"
        ) from error


def _crate_root(path: Path, repository_root: Path) -> Path:
    candidate = path.parent
    while candidate != repository_root:
        if (candidate / "Cargo.toml").is_file():
            return candidate
        candidate = candidate.parent
    raise AssetError(f"asset manifest is not inside a Cargo package: {path}")


def _skip_space(masked: str, position: int) -> int:
    """Skip whitespace and comments already blanked by the Rust lexical mask."""
    while position < len(masked) and masked[position].isspace():
        position += 1
    return position


def _ordinary_include_path(token: str, context: str) -> str:
    """Decode Rust string escapes without Python/JSON escape reinterpretation."""
    result: list[str] = []
    position = 1
    end = len(token) - 1
    escapes = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    while position < end:
        character = token[position]
        position += 1
        if character != "\\":
            result.append(character)
            continue
        if position >= end:
            raise AssetError(f"{context}: unterminated string escape")
        escaped = token[position]
        position += 1
        if escaped in escapes:
            result.append(escapes[escaped])
        elif escaped == "x":
            digits = token[position:position + 2]
            if len(digits) != 2 or re.fullmatch(r"[0-7][0-9A-Fa-f]", digits) is None:
                raise AssetError(f"{context}: invalid Rust ASCII escape")
            result.append(chr(int(digits, 16)))
            position += 2
        elif escaped == "u":
            match = re.match(r"\{([0-9A-Fa-f][0-9A-Fa-f_]*)\}", token[position:end])
            if match is None:
                raise AssetError(f"{context}: invalid Rust Unicode escape")
            digits = match.group(1).replace("_", "")
            if len(digits) > 6:
                raise AssetError(f"{context}: invalid Rust Unicode scalar")
            value = int(digits, 16)
            if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                raise AssetError(f"{context}: invalid Rust Unicode scalar")
            result.append(chr(value))
            position += match.end()
        elif escaped == "\n":
            while position < end and token[position] in " \t\r\n":
                position += 1
        else:
            raise AssetError(f"{context}: unsupported Rust string escape")
    return "".join(result)


def _literal_include_path(
    source: str, masked: str, invocation: re.Match[str], context: str
) -> str | None:
    """Read a direct string literal; macro-expanded expressions are out of scope.

    This lexical check does not expand concat!/env!, resolve macro aliases or
    count macro expansion instances. Nonliteral arguments are never guessed or
    admitted as authenticated literal-asset consumers.
    """
    position = _skip_space(masked, invocation.end())
    raw = re.compile(r'r(?P<hashes>#*)"').match(source, position)
    if raw is not None:
        terminator = '"' + raw.group("hashes")
        closing = source.find(terminator, raw.end())
        if closing < 0:
            raise AssetError(f"{context}: unterminated raw include path")
        path = source[raw.end():closing]
        end = closing + len(terminator)
    elif position < len(source) and source[position] == '"':
        end = position + 1
        while end < len(source):
            if source[end] == "\\":
                end += 2
            elif source[end] == '"':
                end += 1
                break
            else:
                end += 1
        else:
            raise AssetError(f"{context}: unterminated include path")
        path = _ordinary_include_path(source[position:end], context)
    else:
        return None
    tail = _skip_space(masked, end)
    if tail < len(masked) and masked[tail] == ",":
        tail = _skip_space(masked, tail + 1)
    expected = {"(": ")", "[": "]", "{": "}"}[invocation.group("opening")]
    if tail >= len(masked) or masked[tail] != expected:
        raise AssetError(f"{context}: include path must be one complete string literal")
    if not path or "\0" in path:
        raise AssetError(f"{context}: include path is empty or contains NUL")
    return path


def _include_consumers(crate_root: Path) -> dict[Path, list[IncludeConsumer]]:
    """Find every direct literal include, including local and static consumers.

    Only a directly assigned typed byte-array const supplies a declared length;
    other byte includes still count toward ownership and cannot replace that
    length admission. Comments and string examples are excluded. Macro expansion
    and generated source are outside this literal-source inventory.
    """
    consumers: dict[Path, list[IncludeConsumer]] = {}
    sources = list((crate_root / "src").rglob("*.rs"))
    build_script = crate_root / "build.rs"
    if build_script.is_file():
        sources.append(build_script)
    for source in sorted(sources):
        if source.is_symlink() or not source.is_file():
            continue
        text = source.read_text(encoding="utf-8")
        masked = RUST_LEXICAL.mask(text)
        declared_lengths = {
            match.start("macro"): int(match.group("length").replace("_", ""))
            for match in BYTE_INCLUDE_OWNER_RE.finditer(masked)
        }
        for invocation in INCLUDE_CALL_RE.finditer(masked):
            context = f"{source}:{text.count(chr(10), 0, invocation.start()) + 1}"
            path = _literal_include_path(text, masked, invocation, context)
            if path is None:
                continue  # Explicit nonliteral/macro-expansion scope above.
            included = (source.parent / path).resolve()
            macro = invocation.group("macro")
            consumers.setdefault(included, []).append(
                IncludeConsumer(source, macro, declared_lengths.get(invocation.start("macro")))
            )
    return consumers


def _verify_suffix_include_inventory(
    root: Path,
    manifest_path: Path,
    manifest_assets: set[Path],
    consumers: dict[Path, list[IncludeConsumer]],
    suffix: str,
) -> None:
    """Require every crate include target with ``suffix`` to be manifested."""

    included_assets = {
        path for path in consumers if path.name.endswith(suffix)
    }
    if included_assets != manifest_assets:
        missing = sorted(
            path.name for path in manifest_assets.difference(included_assets)
        )
        extra = sorted(path.name for path in included_assets.difference(manifest_assets))
        raise AssetError(
            f"{manifest_path.relative_to(root)}: compile-time include inventory "
            f"mismatch for *{suffix}; missing={missing}, extra={extra}"
        )


def _verify_canonical_file(
    root: Path, manifest_dir: Path, raw: Any, context: str
) -> None:
    canonical = _object(raw, context)
    _exact_fields(canonical, frozenset({"path", "byte_length", "sha256"}), context)
    path = _safe_path(
        root,
        manifest_dir,
        _string(canonical.get("path"), f"{context}.path"),
        f"{context}.path",
    )
    if not path.is_file():
        raise AssetError(f"{context}.path is missing: {path.relative_to(root)}")
    data = path.read_bytes()
    expected_length = _positive_int(canonical.get("byte_length"), f"{context}.byte_length")
    expected_sha = _string(canonical.get("sha256"), f"{context}.sha256")
    if SHA256_RE.fullmatch(expected_sha) is None:
        raise AssetError(f"{context}.sha256 is not canonical lowercase SHA-256")
    if len(data) != expected_length or _sha256(data) != expected_sha:
        raise AssetError(f"{context} length or SHA-256 does not match its manifest")


def _verify_current_include_preimage(
    root: Path,
    manifest_dir: Path,
    preimages: Any,
    consumer: IncludeConsumer,
    context: str,
) -> None:
    """Verify one explicit provenance link to the live compile-time consumer."""

    if not isinstance(preimages, list) or len(preimages) != 1:
        raise AssetError(f"{context} must contain exactly one current include consumer")
    preimage_context = f"{context}[0]"
    preimage = _object(preimages[0], preimage_context)
    _exact_fields(preimage, CURRENT_INCLUDE_PREIMAGE_FIELDS, preimage_context)
    source = _safe_path(
        root,
        manifest_dir,
        _string(preimage.get("path"), f"{preimage_context}.path"),
        f"{preimage_context}.path",
    )
    if source != consumer.source:
        raise AssetError(
            f"{preimage_context}.path resolves to {source.relative_to(root)}, "
            f"but the live include consumer is {consumer.source.relative_to(root)}"
        )


def _verify_manifest_scope(relative_manifest: Path, scope: str) -> None:
    """Require explicitly selected manifests to use current include provenance."""

    requires_current_include = relative_manifest in CURRENT_INCLUDE_CONSUMER_MANIFESTS
    if requires_current_include and scope != CURRENT_INCLUDE_CONSUMER_SCOPE:
        raise AssetError(
            f"{relative_manifest}: source hash scope must be "
            f"{CURRENT_INCLUDE_CONSUMER_SCOPE!r}"
        )
    if not requires_current_include and scope == CURRENT_INCLUDE_CONSUMER_SCOPE:
        raise AssetError(
            f"{relative_manifest}: current include provenance is not enabled for "
            "this manifest"
        )


def audit_repository(root: Path) -> AuditCounts:
    """Verify every checked-in compile-time static manifest and consumer."""

    root = root.resolve()
    assets_seen: set[Path] = set()
    total_bytes = 0
    total_preimages = 0

    for relative_manifest in MANIFEST_PATHS:
        manifest_path = root / relative_manifest
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise AssetError(f"required asset manifest is missing: {relative_manifest}")
        manifest = _object(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            str(relative_manifest),
        )
        _exact_fields(manifest, MANIFEST_FIELDS, str(relative_manifest))
        if manifest.get("format_version") != 1:
            raise AssetError(f"{relative_manifest}: format_version must be 1")
        scope = _string(
            manifest.get("source_slice_hash_scope"),
            f"{relative_manifest}.source_slice_hash_scope",
        )
        if scope not in {
            DECLARATION_HASH_SCOPE,
            LINE_SPAN_HASH_SCOPE,
            STRUCTURED_TABLE_HASH_SCOPE,
            CURRENT_INCLUDE_CONSUMER_SCOPE,
        }:
            raise AssetError(f"{relative_manifest}: unsupported source hash scope")
        _verify_manifest_scope(relative_manifest, scope)
        commit = manifest.get("source_commit")
        if scope == CURRENT_INCLUDE_CONSUMER_SCOPE:
            if "source_commit" in manifest:
                raise AssetError(
                    f"{relative_manifest}: current include provenance must omit source_commit"
                )
        else:
            commit = _string(commit, f"{relative_manifest}.source_commit")
            if COMMIT_RE.fullmatch(commit) is None:
                raise AssetError(f"{relative_manifest}: source_commit is not a full Git id")
        inventory_suffix = manifest.get("asset_inventory_suffix")
        if inventory_suffix is not None:
            inventory_suffix = _string(
                inventory_suffix, f"{relative_manifest}.asset_inventory_suffix"
            )
            if (
                not inventory_suffix.startswith(".")
                or inventory_suffix == "."
                or Path(inventory_suffix).name != inventory_suffix
            ):
                raise AssetError(
                    f"{relative_manifest}.asset_inventory_suffix must be a file suffix"
                )
        if "canonical_ron" in manifest:
            _verify_canonical_file(
                root,
                manifest_path.parent,
                manifest["canonical_ron"],
                f"{relative_manifest}.canonical_ron",
            )

        rows = manifest.get("assets")
        if not isinstance(rows, list) or not rows:
            raise AssetError(f"{relative_manifest}.assets must be a non-empty array")
        crate_root = _crate_root(manifest_path, root)
        consumers = _include_consumers(crate_root)
        manifest_assets: set[Path] = set()
        for index, raw_row in enumerate(rows):
            context = f"{relative_manifest}.assets[{index}]"
            row = _object(raw_row, context)
            _exact_fields(row, ASSET_FIELDS, context)
            asset = _safe_path(
                root,
                manifest_path.parent,
                _string(row.get("path"), f"{context}.path"),
                f"{context}.path",
            )
            if asset.parent != manifest_path.parent:
                raise AssetError(f"{context}.path must name a sibling asset file")
            if asset.name in {"manifest.json", "README.md"}:
                raise AssetError(f"{context}.path names manifest metadata, not an asset")
            if inventory_suffix is not None and not asset.name.endswith(inventory_suffix):
                raise AssetError(
                    f"{context}.path must end with inventory suffix {inventory_suffix}"
                )
            if asset in assets_seen or asset in manifest_assets:
                raise AssetError(f"duplicate asset path: {asset.relative_to(root)}")
            if not asset.is_file() or asset.is_symlink():
                raise AssetError(f"asset is missing or not a regular file: {asset}")
            data = asset.read_bytes()
            expected_length = _positive_int(
                row.get("byte_length"), f"{context}.byte_length"
            )
            expected_sha = _string(row.get("sha256"), f"{context}.sha256")
            if SHA256_RE.fullmatch(expected_sha) is None:
                raise AssetError(f"{context}.sha256 is not canonical lowercase SHA-256")
            if len(data) != expected_length:
                raise AssetError(
                    f"{asset.relative_to(root)} has {len(data)} bytes, "
                    f"expected {expected_length}"
                )
            observed_sha = _sha256(data)
            if observed_sha != expected_sha:
                raise AssetError(
                    f"{asset.relative_to(root)} SHA-256 {observed_sha} != {expected_sha}"
                )
            _string(row.get("layout"), f"{context}.layout")
            asset_consumers = consumers.get(asset, [])
            if len(asset_consumers) != 1:
                raise AssetError(
                    f"{asset.relative_to(root)} must have exactly one compile-time "
                    f"include consumer; found {len(asset_consumers)}"
                )
            consumer = asset_consumers[0]
            expected_macro = "include_bytes" if asset.suffix == ".bin" else "include_str"
            if consumer.macro != expected_macro:
                raise AssetError(
                    f"{consumer.source.relative_to(root)} uses {consumer.macro}! for "
                    f"{asset.name}; expected {expected_macro}!"
                )
            if consumer.macro == "include_bytes":
                if consumer.declared_length != expected_length:
                    raise AssetError(
                        f"{consumer.source.relative_to(root)} declares "
                        f"{consumer.declared_length} bytes for {asset.name}, "
                        f"expected {expected_length}"
                    )
            else:
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise AssetError(
                        f"{asset.relative_to(root)} is not valid UTF-8 for include_str!"
                    ) from error

            preimages = row.get("source_preimages")
            if not isinstance(preimages, list) or not preimages:
                raise AssetError(f"{context}.source_preimages must be non-empty")
            if scope == CURRENT_INCLUDE_CONSUMER_SCOPE:
                _verify_current_include_preimage(
                    root,
                    manifest_path.parent,
                    preimages,
                    consumer,
                    f"{context}.source_preimages",
                )
                total_preimages += 1
                manifest_assets.add(asset)
                assets_seen.add(asset)
                total_bytes += len(data)
                continue
            for preimage_index, raw_preimage in enumerate(preimages):
                preimage_context = f"{context}.source_preimages[{preimage_index}]"
                preimage = _object(raw_preimage, preimage_context)
                preimage_fields = (
                    DECLARATION_PREIMAGE_FIELDS
                    if scope == DECLARATION_HASH_SCOPE
                    else LINE_SPAN_PREIMAGE_FIELDS
                )
                _exact_fields(preimage, preimage_fields, preimage_context)
                relative_source = _historical_source_path(root, manifest_path.parent, preimage, preimage_context)
                physical_lines = _positive_int(
                    preimage.get("physical_lines"),
                    f"{preimage_context}.physical_lines",
                )
                expected_preimage_sha = _string(
                    preimage.get("sha256"), f"{preimage_context}.sha256"
                )
                if SHA256_RE.fullmatch(expected_preimage_sha) is None:
                    raise AssetError(
                        f"{preimage_context}.sha256 is not canonical lowercase SHA-256"
                )
                preimage_commit = preimage.get("source_commit", commit)
                if not isinstance(preimage_commit, str) or COMMIT_RE.fullmatch(
                    preimage_commit
                ) is None:
                    raise AssetError(
                        f"{preimage_context}.source_commit is not a full Git id"
                    )
                historical = _git_blob(root, preimage_commit, relative_source)
                if scope == DECLARATION_HASH_SCOPE:
                    constant = _string(
                        preimage.get("constant"), f"{preimage_context}.constant"
                    )
                    source_slice = declaration_slice(
                        historical, constant, physical_lines
                    )
                    source_label = f"::{constant}"
                else:
                    start_line = _positive_int(
                        preimage.get("start_line"),
                        f"{preimage_context}.start_line",
                    )
                    source_slice = line_span_slice(
                        historical, start_line, physical_lines
                    )
                    source_label = f":{start_line}+{physical_lines}"
                    if scope != STRUCTURED_TABLE_HASH_SCOPE:
                        expected_asset = rust_raw_string_payload(source_slice)
                        if expected_asset != data:
                            raise AssetError(
                                f"historical {relative_source}{source_label} raw string "
                                f"does not equal {asset.relative_to(root)}"
                            )
                observed_preimage_sha = _sha256(source_slice)
                if observed_preimage_sha != expected_preimage_sha:
                    raise AssetError(
                        f"historical {relative_source}{source_label} SHA-256 "
                        f"{observed_preimage_sha} != {expected_preimage_sha}"
                    )
                total_preimages += 1

            manifest_assets.add(asset)
            assets_seen.add(asset)
            total_bytes += len(data)

        if inventory_suffix is not None:
            _verify_suffix_include_inventory(
                root,
                manifest_path,
                manifest_assets,
                consumers,
                inventory_suffix,
            )

        actual_assets: set[Path] = set()
        for path in manifest_path.parent.iterdir():
            if path.name in {"manifest.json", "README.md"}:
                continue
            if inventory_suffix is not None and not path.name.endswith(inventory_suffix):
                continue
            if path.is_dir() and not path.is_symlink():
                continue
            if path.is_symlink() or not path.is_file():
                raise AssetError(
                    f"{path.relative_to(root)} must be a regular non-symlink asset"
                )
            actual_assets.add(path.resolve())
        if actual_assets != manifest_assets:
            missing = sorted(path.name for path in manifest_assets - actual_assets)
            extra = sorted(path.name for path in actual_assets - manifest_assets)
            raise AssetError(
                f"{relative_manifest}: asset inventory mismatch; "
                f"missing={missing}, extra={extra}"
            )

    return AuditCounts(
        manifests=len(MANIFEST_PATHS),
        assets=len(assets_seen),
        bytes=total_bytes,
        source_preimages=total_preimages,
    )


def main() -> int:
    args = parse_args()
    try:
        counts = audit_repository(args.root)
    except (AssetError, OSError, json.JSONDecodeError) as error:
        print(f"compile-time static asset check failed: {error}", file=sys.stderr)
        return 1
    print(
        "compile-time static assets: "
        f"manifests={counts.manifests} assets={counts.assets} "
        f"bytes={counts.bytes} source_preimages={counts.source_preimages}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
