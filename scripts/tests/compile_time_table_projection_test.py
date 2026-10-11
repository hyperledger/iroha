"""Exact source-projection tests for compile-time tables moved out of Rust."""

from __future__ import annotations

import ast
import collections
import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KOTODAMA_MANIFEST = (
    ROOT / "crates/kotodama_lang/src/assets/diagnostics_v1/manifest.json"
)
ISO_MANIFEST = ROOT / "crates/ivm/src/assets/iso20022_schema_v1/manifest.json"
REGISTRY_PROVIDER_SHA256 = (
    "271d94e13fd7e983489121d0b1cae601e04ce60dcb2f3a0dd44e5bdb1fc452f2"
)


def _git_text(commit: str, path: Path) -> str:
    relative = path.resolve().relative_to(ROOT).as_posix()
    return subprocess.check_output(
        ["git", "show", f"{commit}:{relative}"], cwd=ROOT, text=True
    )


def _rust_string(text: str, position: int) -> tuple[str, int]:
    while position < len(text) and text[position].isspace():
        position += 1
    raw = re.match(r'r(#+)?"', text[position:])
    if raw is not None:
        hashes = raw.group(1) or ""
        start = position + raw.end()
        end = text.find('"' + hashes, start)
        if end < 0:
            raise AssertionError("unterminated Rust raw string")
        return text[start:end], end + 1 + len(hashes)
    if position >= len(text) or text[position] != '"':
        raise AssertionError(f"expected Rust string at offset {position}")
    end = position + 1
    while end < len(text):
        if text[end] == "\\":
            end += 2
            continue
        if text[end] == '"':
            return ast.literal_eval(text[position : end + 1]), end + 1
        end += 1
    raise AssertionError("unterminated Rust string")


def _balanced(
    text: str, position: int, opening: str = "{", closing: str = "}"
) -> tuple[str, int]:
    if text[position] != opening:
        raise AssertionError(f"expected {opening!r} at offset {position}")
    depth = 0
    cursor = position
    while cursor < len(text):
        if text[cursor] == '"' or (
            text[cursor] == "r" and re.match(r'r(#+)?"', text[cursor:])
        ):
            _, cursor = _rust_string(text, cursor)
            continue
        if text[cursor] == opening:
            depth += 1
        elif text[cursor] == closing:
            depth -= 1
            if depth == 0:
                return text[position + 1 : cursor], cursor + 1
        cursor += 1
    raise AssertionError(f"unterminated {opening}{closing} region")


def _split_top_level(expression: str) -> list[str]:
    values: list[str] = []
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    start = 0
    cursor = 0
    while cursor < len(expression):
        if expression[cursor] == '"':
            _, cursor = _rust_string(expression, cursor)
            continue
        character = expression[cursor]
        if character in "([{":
            stack.append(character)
        elif character in ")]}":
            if not stack or stack.pop() != pairs[character]:
                raise AssertionError("unbalanced Rust expression")
        elif character == "," and not stack:
            values.append(expression[start:cursor].strip())
            start = cursor + 1
        cursor += 1
    tail = expression[start:].strip()
    if tail:
        values.append(tail)
    return values


def _decode_field(raw: str) -> str:
    decoded: list[str] = []
    cursor = 0
    escapes = {"\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
    while cursor < len(raw):
        if raw[cursor] != "\\":
            decoded.append(raw[cursor])
            cursor += 1
            continue
        cursor += 1
        if cursor >= len(raw) or raw[cursor] not in escapes:
            raise AssertionError("invalid versioned-table escape")
        decoded.append(escapes[raw[cursor]])
        cursor += 1
    return "".join(decoded)


def _table_rows(path: Path) -> list[tuple[str, ...]]:
    data = path.read_text(encoding="utf-8")
    if not data.endswith("\n") or "\r" in data:
        raise AssertionError(f"{path} does not use canonical LF lines")
    return [
        tuple(_decode_field(value) for value in line.split("\t"))
        for line in data.splitlines()[2:]
    ]


def _declaration(source: str, constant: str, physical_lines: int) -> str:
    lines = source.splitlines(keepends=True)
    starts = [
        index
        for index, line in enumerate(lines)
        if re.search(r"\bconst\s+" + re.escape(constant) + r"\s*:", line)
    ]
    if len(starts) != 1:
        raise AssertionError(f"expected one declaration for {constant}")
    return "".join(lines[starts[0] : starts[0] + physical_lines])


def _field_string(body: str, name: str, start: int = 0) -> tuple[str, int]:
    match = re.search(r"\b" + re.escape(name) + r"\s*:\s*", body[start:])
    if match is None:
        raise AssertionError(f"missing struct field {name}")
    return _rust_string(body, start + match.end())


def _manifest_asset(manifest_path: Path, asset_name: str) -> tuple[dict, dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [row for row in manifest["assets"] if row["path"] == asset_name]
    if len(rows) != 1:
        raise AssertionError(f"manifest has no unique {asset_name}")
    row = rows[0]
    data = (manifest_path.parent / asset_name).read_bytes()
    if len(data) != row["byte_length"]:
        raise AssertionError(f"{asset_name} length drifted")
    if hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise AssertionError(f"{asset_name} digest drifted")
    return manifest, row


def _sealed_declaration(
    manifest_path: Path, asset_name: str, constant: str
) -> str:
    manifest, row = _manifest_asset(manifest_path, asset_name)
    preimage = row["source_preimages"][0]
    path = (manifest_path.parent / preimage["path"]).resolve()
    source = _git_text(preimage.get("source_commit", manifest["source_commit"]), path)
    declaration = _declaration(source, constant, preimage["physical_lines"])
    if hashlib.sha256(declaration.encode()).hexdigest() != preimage["sha256"]:
        raise AssertionError(f"historical {constant} preimage drifted")
    return declaration


def _parse_diagnostic_explanations(block: str) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    position = 0
    while match := re.search(r"explanation!\s*\(", block[position:]):
        cursor = position + match.end()
        code, cursor = _rust_string(block, cursor)
        phase = re.match(r"\s*,\s*([A-Za-z]+)\s*,", block[cursor:])
        if phase is None:
            raise AssertionError("diagnostic phase is absent")
        cursor += phase.end()
        summary, cursor = _rust_string(block, cursor)
        comma = re.match(r"\s*,", block[cursor:])
        if comma is None:
            raise AssertionError("diagnostic help separator is absent")
        cursor += comma.end()
        help_text, cursor = _rust_string(block, cursor)
        rows.append((code, phase.group(1), summary, help_text))
        position = cursor
    return rows


def _parse_struct_cases(
    block: str, struct_name: str, fields: tuple[str, ...]
) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    position = 0
    while match := re.search(re.escape(struct_name) + r"\s*\{", block[position:]):
        body, position = _balanced(block, position + match.end() - 1)
        cursor = 0
        row: list[str] = []
        for field in fields:
            if field == "phase":
                phase = re.search(
                    r"\bphase\s*:\s*DiagnosticPhase::([A-Za-z]+)", body[cursor:]
                )
                if phase is None:
                    raise AssertionError("case phase is absent")
                row.append(phase.group(1))
                cursor += phase.end()
            elif field == "line":
                line = re.search(r"\bline\s*:\s*(\d+)", body[cursor:])
                if line is None:
                    raise AssertionError("case line is absent")
                row.append(line.group(1))
                cursor += line.end()
            else:
                value, cursor = _field_string(body, field, cursor)
                row.append(value)
        rows.append(tuple(row))
    return rows


def _const_array(source: str, name: str, type_pattern: str) -> str:
    match = re.search(
        r"const\s+" + re.escape(name) + r"\s*:\s*" + type_pattern + r"\s*=\s*&?\[",
        source,
    )
    if match is None:
        raise AssertionError(f"missing array {name}")
    bracket = source.index("[", match.end() - 1)
    return _balanced(source, bracket, "[", "]")[0]


def _iso_kind(expression: str) -> tuple[str, str]:
    compact = re.sub(r"\s+", "", expression)
    simple = {
        "FieldKind::Text": "text",
        "FieldKind::Numeric": "numeric",
        "FieldKind::Amount": "amount",
        "FieldKind::Instrument": "instrument",
        "FieldKind::Date": "date",
        "FieldKind::DateTime": "datetime",
    }
    if compact in simple:
        return simple[compact], "-"
    identifier = re.fullmatch(
        r"FieldKind::Identifier\(IdentifierKind::([A-Za-z]+)\)", compact
    )
    if identifier is not None:
        return "identifier:" + identifier.group(1).lower(), "-"
    if not compact.startswith("FieldKind::Enum(&[") or not compact.endswith("])"):
        raise AssertionError(f"unknown ISO field kind {expression}")
    values = [
        ast.literal_eval(value)
        for value in _split_top_level(
            expression[expression.index("[") + 1 : expression.rindex("]")]
        )
    ]
    return "enum", "|".join(values)


def _iso_fields(source: str, owner: str) -> list[tuple[str, ...]]:
    body = _const_array(source, owner + "_FIELDS", r"&\[FieldSpec\]")
    rows: list[tuple[str, ...]] = []
    position = 0
    while match := re.search(
        r"FieldSpec::(required|optional|limited)\s*\(", body[position:]
    ):
        constructor = match.group(1)
        arguments, position = _balanced(body, position + match.end() - 1, "(", ")")
        values = _split_top_level(arguments)
        if constructor == "required":
            path, kind = values
            requirement, maximum = "required", "none"
        elif constructor == "optional":
            path, kind = values
            requirement, maximum = "optional", "none"
        else:
            path, minimum, maximum, kind = values
            requirement = {"true": "required", "false": "optional"}[minimum]
        field_kind, enum_values = _iso_kind(kind)
        rows.append(
            (
                "field",
                owner,
                ast.literal_eval(path),
                requirement,
                maximum,
                field_kind,
                enum_values,
                "-",
            )
        )
    return rows


def _alias_rows(body: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    position = 0
    while match := re.search(r"AliasSpec\s*\{", body[position:]):
        item, position = _balanced(body, position + match.end() - 1)
        alias = re.search(r'alias\s*:\s*("(?:\\.|[^"\\])*")', item)
        canonical = re.search(r'canonical\s*:\s*("(?:\\.|[^"\\])*")', item)
        if alias is None or canonical is None:
            raise AssertionError("incomplete ISO alias")
        rows.append((ast.literal_eval(alias.group(1)), ast.literal_eval(canonical.group(1))))
    return rows


def _iso_aliases(source: str, owner: str) -> list[tuple[str, ...]]:
    schema = re.search(
        r"const\s+"
        + re.escape(owner)
        + r"_SCHEMA\s*:\s*MessageSchema\s*=\s*MessageSchema\s*\{",
        source,
    )
    if schema is None:
        raise AssertionError(f"missing schema {owner}")
    body, _ = _balanced(source, source.index("{", schema.end() - 1))
    aliases = re.search(r"aliases\s*:\s*", body)
    if aliases is None:
        raise AssertionError(f"missing aliases for {owner}")
    tail = body[aliases.end() :].lstrip()
    if tail.startswith("&[]"):
        pairs: list[tuple[str, str]] = []
    elif tail.startswith("&["):
        bracket = body.index("[", aliases.end())
        pairs = _alias_rows(_balanced(body, bracket, "[", "]")[0])
    else:
        reference = re.match(r"([A-Z0-9_]+)", tail)
        if reference is None:
            raise AssertionError(f"invalid aliases for {owner}")
        pairs = _alias_rows(
            _const_array(source, reference.group(1), r"&\[AliasSpec\]")
        )
    return [
        ("alias", owner, alias, "-", "-", "-", "-", canonical)
        for alias, canonical in pairs
    ]


class CompileTimeTableProjectionTests(unittest.TestCase):
    def test_byte_exact_tsv_assets_are_lf_normalized_on_checkout(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        self.assertTrue(
            {
                "*.tsv text eol=lf",
                "*.ndjson text eol=lf",
            }.issubset(attributes)
        )

    def test_kotodama_tables_are_bound_to_their_current_consumer(self) -> None:
        # These first-release tables evolve with the language. Verify their current
        # closed schemas and ownership instead of claiming an obsolete Rust preimage.
        for filename, width in [
            ("diagnostic_explanations_v1.tsv", 6),
            ("compile_fail_cases_v1.tsv", 6),
            ("secret_reject_cases_v1.tsv", 4),
        ]:
            manifest, asset = _manifest_asset(KOTODAMA_MANIFEST, filename)
            self.assertEqual(manifest["source_slice_hash_scope"], "current Rust compile-time include consumer")
            self.assertNotIn("source_commit", manifest)
            self.assertEqual(asset["source_preimages"], [{"path": "../../../build.rs"}])
            path = KOTODAMA_MANIFEST.parent / filename
            rows = _table_rows(path)
            self.assertEqual(int(path.read_text().splitlines()[0].split("\t")[1]), len(rows))
            self.assertTrue(all(len(row) == width for row in rows))
            self.assertEqual(len({row[0] for row in rows}), len(rows))
        explanations = dict((row[0], row[1:]) for row in _table_rows(KOTODAMA_MANIFEST.parent / "diagnostic_explanations_v1.tsv"))
        for code in ["E_TEST_REJECTION_EXPECTATION", "E_CONFLICTING_ERROR_TYPE", "E_POSITIONAL_ARGUMENT_ORDER", "E_POSITIONAL_STRUCT_PATTERN"]:
            self.assertIn(code, explanations)
            self.assertTrue(all(explanations[code]))
        self.assertNotIn("E_DUPLICATE_ERROR_CODE", explanations)

    def test_iso_schema_is_closed_and_bound_to_its_current_consumer(self) -> None:
        manifest, asset = _manifest_asset(ISO_MANIFEST, "schema_v1.tsv")
        self.assertEqual(
            manifest["source_slice_hash_scope"],
            "current Rust compile-time include consumer",
        )
        self.assertNotIn("source_commit", manifest)
        self.assertEqual(asset["source_preimages"], [{"path": "../../../build.rs"}])
        rows = _table_rows(ISO_MANIFEST.parent / "schema_v1.tsv")
        self.assertTrue(all(len(row) == 8 for row in rows))
        self.assertEqual(
            collections.Counter(row[0] for row in rows),
            {"schema": 19, "field": 193, "alias": 183},
        )
        owners = [row[1] for row in rows if row[0] == "schema"]
        self.assertEqual(len(owners), len(set(owners)))
        self.assertTrue(all(row[1] in owners for row in rows))
        self.assertIn(
            ("alias", "PACS009", "AppHdr/CreDt", "-", "-", "-", "-", "AppHdr/CreDt"),
            rows,
        )
        self.assertIn(
            (
                "alias",
                "PACS009",
                "Document/FICdtTrf/GrpHdr/MsgId",
                "-",
                "-",
                "-",
                "-",
                "MsgId",
            ),
            rows,
        )
        self.assertNotIn(
            ("alias", "PACS009", "AppHdr/CreDt", "-", "-", "-", "-", "CreDtTm"),
            rows,
        )

    def test_registry_single_provider_preserves_exact_ids_order_and_one_pass(self) -> None:
        provider_path = (
            ROOT / "crates/iroha_data_model/src/isi/registry/wire_ids.rs"
        )
        provider = provider_path.read_text(encoding="utf-8")
        start = provider.index("pub(super) const ALL:")
        end = provider.index("\n];", start) + 3
        rows: list[tuple[str, str, str, str]] = []
        for match in re.finditer(
            r"(built_in_wire_id|governance_wire_id)!\(\s*(.*?)\s*=>\s*"
            r'"((?:\\.|[^"\\])*)"(?:\s*,\s*'
            r"(register|register_with_id|register_with_id_slice))?\s*\)",
            provider[start:end],
            re.DOTALL,
        ):
            scope = "governance" if match.group(1) == "governance_wire_id" else "base"
            type_name = re.sub(r"\s+", "", match.group(2))
            mode = match.group(4) or "register_slice"
            rows.append((scope, type_name, mode, match.group(3)))
        self.assertEqual(len(rows), 395)
        self.assertEqual(len({row[1] for row in rows}), len(rows))
        self.assertEqual(len({row[3] for row in rows}), len(rows))
        self.assertEqual(
            collections.Counter(row[2] for row in rows),
            {
                "register_slice": 359,
                "register": 36,
            },
        )
        self.assertIn(
            ("base", "crate::isi::kagemusha_wallet::KagemushaWalletLedgerV1",
             "register", "iroha.kagemusha.wallet.ledger.v1"),
            rows,
        )
        self.assertIn(
            ("base", "crate::isi::register_dataspace_asset_definition::RegisterDataspaceAssetDefinition",
             "register_slice", "iroha.asset_definition.dataspace.register.v1"),
            rows,
        )
        for retired in (
            "TopUpKagemushaV1", "TopUpKagemushaOrdinaryV1", "RedeemKagemushaV1",
            "ProposeKagemushaVerifierPolicyInstallV1",
            "ProposeKagemushaVerifierReleaseInstallV1",
            "ProposeKagemushaVerifierReleaseActivateV1",
            "ProposeKagemushaVerifierReleaseRetireV1",
        ):
            self.assertFalse(any(retired in row[1] for row in rows), retired)
        canonical = "".join("\t".join(row) + "\n" for row in rows).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), REGISTRY_PROVIDER_SHA256)
        registry = (
            ROOT / "crates/iroha_data_model/src/isi/registry.rs"
        ).read_text(encoding="utf-8")
        production = registry.split("\n#[cfg(test)]\nmod tests", 1)[0]
        self.assertNotIn("ALL_REGISTRARS", production)
        self.assertIn("wire_ids::register_all()", production)
        self.assertNotIn("wire_ids::remap_all", production)


if __name__ == "__main__":
    unittest.main()
