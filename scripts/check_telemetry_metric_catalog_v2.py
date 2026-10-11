#!/usr/bin/env python3
"""Guard the typed telemetry metric catalog against semantic source drift.

The pinned ledger covers every catalog row's ``define_metrics!`` construction
order, Rust field, Prometheus kind, labels, buckets, registration state,
exported name, and help text.  The guard intentionally uses only the Python
standard library.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

CATALOG = Path("crates/iroha_telemetry/src/metrics/catalog_v2.tsv")
SOURCE = Path("crates/iroha_telemetry/src/metrics.rs")
HEADER = "# iroha-telemetry-metric-catalog-v2"
CATALOG_BYTES = 89_244
CATALOG_SHA256 = "9ee1cf67b0a4cd2bb2047382235dcb928dd8fdbabb6b78b572070991264c0b30"
CATALOG_BLAKE3 = "cb8a2c06089ea22def6b728133db214199cf4adf07640b0bbbb2ff63d9d2e264"
ROWS = 656
REGISTERED = 623
LEDGER_BYTES = 194_810
LEDGER_SHA256 = "a5bb9851e1bd6d13e38269049d91c6bec1ab930b6308dfd9e694daaa1875c535"
DSL_MACROS_TOKENS_SHA256 = "b3ad59602eaeb1d685353d0403594fed447953e7d308b9f04a73142cbe628873"
FACTORY_TOKENS_SHA256 = "41a07ee3fc3e40d3c0d18b7dd9200f5a11d75f1e3fe1bf074fe36b380be8c19f"
SUFFIX_TOKENS_SHA256 = "f4f80f55c7d9abcfec0cfe322525122e1d21e580bb6277b78f8b105a562998a0"
METHOD_COUNTS = {
    "float_counter_vec": 6,
    "float_gauge": 10,
    "float_gauge_vec": 31,
    "gauge": 208,
    "gauge_vec": 89,
    "histogram_vec": 2,
    "histogram_vec_with_buckets": 47,
    "histogram_with_buckets": 19,
    "int_counter": 34,
    "int_counter_vec": 176,
    "int_gauge": 12,
    "int_gauge_vec": 22,
}

RETIRED_CONSENSUS_VRF_METRICS = (
    "sumeragi_vrf_commits_emitted_total",
    "sumeragi_vrf_reveals_emitted_total",
    "sumeragi_vrf_reveals_late_total",
    "sumeragi_vrf_non_reveal_penalties_total",
    "sumeragi_vrf_non_reveal_by_signer",
    "sumeragi_vrf_no_participation_total",
    "sumeragi_vrf_no_participation_by_signer",
    "sumeragi_vrf_rejects_total_by_reason",
)

RETIRED_LEGACY_DA_GATE_METRICS = (
    "sumeragi_da_gate_block_total",
    "sumeragi_da_gate_last_reason",
    "sumeragi_da_gate_last_satisfied",
    "sumeragi_da_gate_satisfied_total",
    "sumeragi_da_manifest_guard_total",
    "sumeragi_da_manifest_cache_total",
    "sumeragi_da_spool_cache_total",
    "sumeragi_da_pin_intent_spool_total",
    "sumeragi_da_votes_ingested_total",
)

RETIRED_IVM_BINDING_PROVER_METRICS = (
    "torii_zk_ivm_prove_inflight",
    "torii_zk_ivm_prove_queued",
)

RETIRED_HALO2_CONFIGURATION_METRICS = (
    "zk_halo2_enabled",
    "zk_halo2_curve_id",
    "zk_halo2_backend_id",
    "zk_halo2_max_k",
    "zk_halo2_verifier_budget_ms",
    "zk_halo2_verifier_max_batch",
    "zk_halo2_verifier_worker_threads",
    "zk_halo2_verifier_queue_cap",
)

RETIRED_METRICS = (
    RETIRED_CONSENSUS_VRF_METRICS
    + RETIRED_LEGACY_DA_GATE_METRICS
    + RETIRED_IVM_BINDING_PROVER_METRICS
    + RETIRED_HALO2_CONFIGURATION_METRICS
    + (
        "zk_verifier_cache_events_total",
        "iroha_zk_verifier_cache_events_total",
        "nexus_public_lane_reward_total",
    )
)

DSL_MACROS_START = "macro_rules! metric_field_type {"
DSL_MACROS_END = "define_metrics! {"
FACTORY_START = "#[derive(Clone, Copy)]\nstruct MetricSpec {"
FACTORY_END = "#[cfg(test)]\nmod metric_catalog_tests {"
DSL_SECTIONS = ("fields", "prefix", "construct", "suffix", "initialize", "epilogue")


class GuardError(ValueError):
    """Raised when the bounded Rust grammar used by this guard is violated."""


def _matching_delimiter(text: str, opening: int, opener: str, closer: str) -> int:
    """Return the matching delimiter, respecting strings and comments."""
    if opening >= len(text) or text[opening] != opener:
        raise GuardError(f"expected `{opener}` at byte {opening}")
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_depth = 0
    index = opening
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_depth:
            if pair == "/*":
                block_depth += 1
                index += 1
            elif pair == "*/":
                block_depth -= 1
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif pair == "//":
            line_comment = True
            index += 1
        elif pair == "/*":
            block_depth = 1
            index += 1
        elif char == '"':
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise GuardError(f"unclosed `{opener}` at byte {opening}")


def _matching_paren(text: str, opening: int) -> int:
    """Return the matching close parenthesis, respecting strings and comments."""
    return _matching_delimiter(text, opening, "(", ")")


def _split_top_level(arguments: str, separator: str = ",") -> list[str]:
    """Split Rust tokens at a top-level separator."""
    parts: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_depth = 0
    pairs = {")": "(", "]": "[", "}": "{"}
    index = 0
    while index < len(arguments):
        char = arguments[index]
        pair = arguments[index : index + 2]
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_depth:
            if pair == "/*":
                block_depth += 1
                index += 1
            elif pair == "*/":
                block_depth -= 1
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif pair == "//":
            line_comment = True
            index += 1
        elif pair == "/*":
            block_depth = 1
            index += 1
        elif char == '"':
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}" and stack:
            expected = pairs[char]
            if stack[-1] != expected:
                raise GuardError("unbalanced Rust argument delimiters")
            stack.pop()
        elif char == separator and not stack:
            parts.append(arguments[start:index])
            start = index + 1
        index += 1
    parts.append(arguments[start:])
    while parts and not _compact_rust(parts[-1]):
        parts.pop()
    return parts


def _compact_rust(text: str) -> str:
    """Remove comments and insignificant whitespace outside string literals."""
    output: list[str] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_depth:
            if pair == "/*":
                block_depth += 1
                index += 1
            elif pair == "*/":
                block_depth -= 1
                index += 1
        elif quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif pair == "//":
            line_comment = True
            index += 1
        elif pair == "/*":
            block_depth = 1
            index += 1
        elif char == '"':
            quote = char
            output.append(char)
        elif not char.isspace():
            output.append(char)
        index += 1
    if quote or block_depth:
        raise GuardError("unterminated string or block comment")
    return "".join(output)


def _canonical_expression(text: str) -> str:
    """Canonicalize an expression, including semantically inert trailing commas."""
    value = _compact_rust(text).rstrip(",")
    previous = None
    while previous != value:
        previous = value
        value = re.sub(r",(?=[]})])", "", value)
    return value


def _strip_rust_comments(text: str) -> str:
    """Remove Rust comments while retaining strings and token separation."""
    output: list[str] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if line_comment:
            if char == "\n":
                line_comment = False
                output.append(char)
        elif block_depth:
            if pair == "/*":
                block_depth += 1
                index += 1
            elif pair == "*/":
                block_depth -= 1
                index += 1
            elif char == "\n":
                output.append(char)
        elif quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif pair == "//":
            line_comment = True
            output.append(" ")
            index += 1
        elif pair == "/*":
            block_depth = 1
            output.append(" ")
            index += 1
        elif char == '"':
            quote = char
            output.append(char)
        else:
            output.append(char)
        index += 1
    if quote or block_depth:
        raise GuardError("unterminated string or block comment")
    return "".join(output)


def _skip_trivia(text: str, index: int) -> int:
    """Skip whitespace and Rust comments from ``index``."""
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        pair = text[index : index + 2]
        if pair == "//":
            newline = text.find("\n", index + 2)
            return len(text) if newline < 0 else _skip_trivia(text, newline + 1)
        if pair == "/*":
            depth = 1
            cursor = index + 2
            while cursor < len(text) and depth:
                nested = text[cursor : cursor + 2]
                if nested == "/*":
                    depth += 1
                    cursor += 2
                elif nested == "*/":
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise GuardError(f"unclosed block comment at byte {index}")
            index = cursor
            continue
        break
    return index


def _define_metrics_sections(source: str) -> dict[str, str]:
    """Parse the single top-level ``define_metrics!`` invocation."""
    invocations = list(re.finditer(r"\bdefine_metrics!\s*\{", source))
    if len(invocations) != 1:
        raise GuardError(
            f"define_metrics invocation count: expected 1, got {len(invocations)}"
        )
    opening = source.find("{", invocations[0].start())
    closing = _matching_delimiter(source, opening, "{", "}")
    body = source[opening + 1 : closing]
    sections: dict[str, str] = {}
    index = 0
    for expected in DSL_SECTIONS:
        index = _skip_trivia(body, index)
        name_match = re.match(r"[A-Za-z_]\w*", body[index:])
        if not name_match:
            raise GuardError(f"define_metrics section `{expected}` is missing")
        name = name_match.group(0)
        if name != expected:
            raise GuardError(
                f"define_metrics section order changed: expected `{expected}`, got `{name}`"
            )
        index += name_match.end()
        index = _skip_trivia(body, index)
        parameter: str | None = None
        if index < len(body) and body[index] == "(":
            parameter_end = _matching_paren(body, index)
            parameter = _compact_rust(body[index + 1 : parameter_end])
            index = _skip_trivia(body, parameter_end + 1)
        if expected in {"prefix", "initialize"}:
            if parameter != "metrics":
                raise GuardError(
                    f"define_metrics section `{expected}` parameter changed: {parameter!r}"
                )
        elif parameter is not None:
            raise GuardError(f"define_metrics section `{expected}` gained a parameter")
        if index >= len(body) or body[index] != "{":
            raise GuardError(f"define_metrics section `{expected}` has no body")
        section_end = _matching_delimiter(body, index, "{", "}")
        sections[expected] = body[index + 1 : section_end]
        index = section_end + 1
    if _skip_trivia(body, index) != len(body):
        raise GuardError("unexpected tokens after define_metrics epilogue")
    return sections


def _field_definitions(fields: str) -> dict[str, tuple[str, list[str]]]:
    """Parse metric field kinds and arguments from the DSL fields section."""
    definitions: dict[str, tuple[str, list[str]]] = {}
    for statement in _split_top_level(fields, ";"):
        declaration = _strip_rust_comments(statement).strip()
        while declaration.startswith("#["):
            attribute_end = _matching_delimiter(declaration, 1, "[", "]")
            declaration = declaration[attribute_end + 1 :].lstrip()
        visibility = re.match(r"pub(?:\s*\([^)]*\))?\s+", declaration)
        if visibility:
            declaration = declaration[visibility.end() :]
        field_match = re.match(
            r"(?P<field>[A-Za-z_]\w*)\s*:\s*(?P<kind>[a-z_]+)\s*\(",
            declaration,
        )
        if not field_match:
            raise GuardError(
                "define_metrics field is outside the bounded grammar: "
                f"{_compact_rust(declaration)[:80]}"
            )
        field = field_match.group("field")
        kind = field_match.group("kind")
        if field in definitions:
            raise GuardError(f"duplicate define_metrics field `{field}`")
        opening = declaration.find("(", field_match.start("kind"))
        closing = _matching_paren(declaration, opening)
        if declaration[closing + 1 :].strip():
            raise GuardError(f"unexpected tokens after define_metrics field `{field}`")
        arguments = _split_top_level(declaration[opening + 1 : closing])
        definitions[field] = (kind, arguments)
    return definitions


def _construction_order(construct: str) -> list[str]:
    """Parse catalog construction groups from the DSL construct section."""
    fields: list[str] = []
    index = 0
    while True:
        index = _skip_trivia(construct, index)
        if index == len(construct):
            break
        if construct[index] != "[":
            raise GuardError(f"expected construct field group at byte {index}")
        closing = _matching_delimiter(construct, index, "[", "]")
        group = _strip_rust_comments(construct[index + 1 : closing])
        group_fields = re.findall(r"\b[A-Za-z_]\w*\b", group)
        residue = re.sub(r"\b[A-Za-z_]\w*\b", "", group)
        if residue.strip():
            raise GuardError("construct field group contains non-identifier tokens")
        # The real macro uses $($construct_field:ident)*: an empty group
        # constructs no metrics, while its optional statements still execute.
        fields.extend(group_fields)
        index = _skip_trivia(construct, closing + 1)
        if index < len(construct) and construct[index] == "{":
            index = _matching_delimiter(construct, index, "{", "}") + 1
    if len(fields) != len(set(fields)):
        duplicates = sorted(
            field for field, count in collections.Counter(fields).items() if count > 1
        )
        raise GuardError(f"duplicate constructed metric fields: {duplicates}")
    return fields


def _dsl_calls(
    source: str,
) -> tuple[list[tuple[str, str, str, str, str]], dict[str, str], list[str]]:
    """Return catalog factory calls encoded by the ``define_metrics!`` DSL."""
    try:
        sections = _define_metrics_sections(source)
        definitions = _field_definitions(sections["fields"])
        construction = _construction_order(sections["construct"])
        non_raw = [field for field, (kind, _) in definitions.items() if kind != "raw"]
        missing = [field for field in non_raw if field not in set(construction)]
        if missing:
            raise GuardError(f"metric fields missing from construction: {missing}")
        aliases = {
            "view_changes_gauge": "gauge",
        }
        scalar_methods = {"float_gauge", "gauge", "int_counter", "int_gauge"}
        vector_methods = {
            "float_counter_vec",
            "float_gauge_vec",
            "gauge_vec",
            "histogram_vec",
            "int_counter_vec",
            "int_gauge_vec",
        }
        calls: list[tuple[str, str, str, str, str]] = []
        for field in construction:
            if field not in definitions:
                raise GuardError(f"constructed metric `{field}` has no field definition")
            kind, arguments = definitions[field]
            if kind == "raw":
                raise GuardError(f"raw field `{field}` entered catalog construction")
            method = aliases.get(kind, kind)
            labels = ""
            buckets = ""
            if method == "histogram_vec_with_buckets":
                if len(arguments) != 2:
                    raise GuardError(f"metric field `{field}` has the wrong arity")
                buckets = _canonical_expression(arguments[0])
                labels = _canonical_expression(arguments[1])
            elif method == "histogram_with_buckets":
                if len(arguments) != 1:
                    raise GuardError(f"metric field `{field}` has the wrong arity")
                buckets = _canonical_expression(arguments[0])
            elif method in vector_methods:
                if len(arguments) != 1:
                    raise GuardError(f"metric field `{field}` has the wrong arity")
                labels = _canonical_expression(arguments[0])
            elif method in scalar_methods:
                if arguments:
                    raise GuardError(f"metric field `{field}` has the wrong arity")
            else:
                raise GuardError(f"metric field `{field}` uses unknown kind `{kind}`")
            calls.append((field, field, method, labels, buckets))
    except GuardError as error:
        return [], {}, [str(error)]
    return calls, sections, []


def _catalog_rows(raw: bytes) -> tuple[list[tuple[str, str, str, bool]], list[str]]:
    findings: list[str] = []
    if len(raw) != CATALOG_BYTES:
        findings.append(f"catalog bytes: expected {CATALOG_BYTES}, got {len(raw)}")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CATALOG_SHA256:
        findings.append(f"catalog sha256: expected {CATALOG_SHA256}, got {digest}")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        return [], findings + [f"catalog is not UTF-8: {error}"]
    if not lines or lines[0] != HEADER:
        return [], findings + ["catalog header/version changed"]

    rows: list[tuple[str, str, str, bool]] = []
    keys: set[str] = set()
    names: set[str] = set()
    registered = 0
    for ordinal, line in enumerate(lines[1:], 1):
        fields = line.split("\t")
        if len(fields) != 4:
            findings.append(f"catalog row {ordinal} has {len(fields)} fields, expected 4")
            continue
        key, name, help_text, registration = fields
        if not key or not name or not help_text:
            findings.append(f"catalog row {ordinal} has an empty required field")
        if key in keys:
            findings.append(f"duplicate metric key `{key}`")
        if name in names:
            findings.append(f"duplicate metric name `{name}`")
        keys.add(key)
        names.add(name)
        if registration == "registered":
            is_registered = True
            registered += 1
        elif registration == "unregistered":
            is_registered = False
        else:
            findings.append(f"catalog row {ordinal} has invalid registration `{registration}`")
            is_registered = False
        rows.append((key, name, help_text, is_registered))
    if len(rows) != ROWS:
        findings.append(f"catalog rows: expected {ROWS}, got {len(rows)}")
    if registered != REGISTERED:
        findings.append(f"registered rows: expected {REGISTERED}, got {registered}")
    return rows, findings


def _semantic_ledger(
    rows: list[tuple[str, str, str, bool]],
    calls: list[tuple[str, str, str, str, str]],
) -> bytes:
    if len(rows) != len(calls):
        raise GuardError(f"catalog/source row count differs: {len(rows)} != {len(calls)}")
    records: list[str] = []
    for ordinal, (row, call) in enumerate(zip(rows, calls), 1):
        key, name, help_text, registered = row
        source_key, variable, method, labels, buckets = call
        if key != source_key:
            raise GuardError(
                f"catalog/source order differs at row {ordinal}: `{key}` != `{source_key}`"
            )
        record = {
            "buckets": buckets,
            "help": help_text,
            "key": key,
            "labels": labels,
            "method": method,
            "name": name,
            "ordinal": ordinal,
            "registered": registered,
            "variable": variable,
        }
        records.append(json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return ("\n".join(records) + "\n").encode("utf-8")


def check_contents(catalog_raw: bytes, source: str) -> list[str]:
    """Return deterministic findings for the supplied catalog and Rust source."""
    rows, findings = _catalog_rows(catalog_raw)
    calls, sections, source_findings = _dsl_calls(source)
    findings.extend(source_findings)

    consumer = 'include_str!("metrics/catalog_v2.tsv")'
    if source.count(consumer) != 1:
        findings.append(f"catalog consumer count: expected 1, got {source.count(consumer)}")
    if "catalog_v1.tsv" in source:
        findings.append("obsolete catalog_v1 consumer remains")
    expected_literals = (
        "const METRIC_CATALOG_V2_ROWS: usize = 656;",
        "const METRIC_CATALOG_V2_REGISTERED: usize = 623;",
        "const METRIC_CATALOG_V2_BYTES: usize = 89_244;",
        CATALOG_BLAKE3,
    )
    for literal in expected_literals:
        if source.count(literal) != 1:
            findings.append(f"Rust catalog invariant changed or duplicated: {literal}")
    catalog_keys = {row[0] for row in rows}
    catalog_names = {row[1] for row in rows}
    compacted_source = _compact_rust(source)
    for retired in RETIRED_METRICS:
        if retired in catalog_keys or retired in catalog_names:
            findings.append(f"retired metric catalog row returned: {retired}")
        if re.search(r"\b" + re.escape(retired) + r"\b", compacted_source):
            findings.append(f"retired metric source returned: {retired}")

    if len(calls) != ROWS:
        findings.append(f"DSL factory calls: expected {ROWS}, got {len(calls)}")
    if calls:
        method_counts = dict(sorted(collections.Counter(call[2] for call in calls).items()))
        if method_counts != METHOD_COUNTS:
            findings.append(
                f"factory method inventory changed: expected {METHOD_COUNTS}, got {method_counts}"
            )
    if rows and calls:
        try:
            ledger = _semantic_ledger(rows, calls)
        except (GuardError, ValueError) as error:
            findings.append(str(error))
        else:
            if len(ledger) != LEDGER_BYTES:
                findings.append(f"semantic ledger bytes: expected {LEDGER_BYTES}, got {len(ledger)}")
            ledger_digest = hashlib.sha256(ledger).hexdigest()
            if ledger_digest != LEDGER_SHA256:
                findings.append(
                    f"semantic ledger sha256: expected {LEDGER_SHA256}, got {ledger_digest}"
                )

    if re.search(r"metric_specs\s*\.\s*(?:opts|histogram_opts)\s*\(", source):
        findings.append("direct metric option construction bypasses the typed factory")
    construction = sections.get("construct", "")
    if "register_guarded(" in construction or "register!(" in construction:
        findings.append("duplicated metric registration remains in the construction pass")

    if source.count(DSL_MACROS_START) != 1 or source.count(DSL_MACROS_END) != 1:
        findings.append("define_metrics macro implementation boundary changed")
    else:
        dsl_macros = source.split(DSL_MACROS_START, 1)[1].split(DSL_MACROS_END, 1)[0]
        macro_tokens = _compact_rust(DSL_MACROS_START + dsl_macros).encode("utf-8")
        digest = hashlib.sha256(macro_tokens).hexdigest()
        if digest != DSL_MACROS_TOKENS_SHA256:
            findings.append(
                "define_metrics macro source sha256: "
                f"expected {DSL_MACROS_TOKENS_SHA256}, got {digest}"
            )

    if source.count(FACTORY_START) != 1 or source.count(FACTORY_END) != 1:
        findings.append("typed factory implementation boundary changed")
    else:
        factory = source.split(FACTORY_START, 1)[1].split(FACTORY_END, 1)[0]
        factory_tokens = _compact_rust(FACTORY_START + factory).encode("utf-8")
        digest = hashlib.sha256(factory_tokens).hexdigest()
        if digest != FACTORY_TOKENS_SHA256:
            findings.append(
                f"typed factory source sha256: expected {FACTORY_TOKENS_SHA256}, got {digest}"
            )

    suffix = sections.get("suffix")
    if suffix is not None:
        digest = hashlib.sha256(_compact_rust(suffix).encode("utf-8")).hexdigest()
        if digest != SUFFIX_TOKENS_SHA256:
            findings.append(
                "post-catalog suffix source sha256: "
                f"expected {SUFFIX_TOKENS_SHA256}, got {digest}"
            )
    return findings


def check(root: Path) -> list[str]:
    """Return deterministic findings for a repository root."""
    catalog_path = root / CATALOG
    source_path = root / SOURCE
    if not catalog_path.is_file():
        return [f"missing catalog: {CATALOG}"]
    if not source_path.is_file():
        return [f"missing source: {SOURCE}"]
    try:
        return check_contents(catalog_path.read_bytes(), source_path.read_text(encoding="utf-8"))
    except (GuardError, OSError, UnicodeError, ValueError) as error:
        return [f"guard parse failed: {error}"]


def self_test(root: Path) -> list[str]:
    """Exercise independent catalog, call-site, and factory-source mutations in memory."""
    catalog = (root / CATALOG).read_bytes()
    source = (root / SOURCE).read_text(encoding="utf-8")
    failures: list[str] = []
    baseline = check_contents(catalog, source)
    if baseline:
        return ["self-test baseline failed: " + "; ".join(baseline)]

    # Match the real zero-or-more identifier grammar without accepting malformed
    # groups or using an empty group to hide a missing metric construction.
    valid_groups = (
        ("empty section", "", []),
        ("empty group", "[]", []),
        ("empty group with comments", "[/* no metrics */] [alpha]", ["alpha"]),
        (
            "empty group with retained statements",
            "[] { let cache = Vec::new(); } [alpha] [] { let ready = true; } [beta]",
            ["alpha", "beta"],
        ),
    )
    for label, construct, expected in valid_groups:
        try:
            actual = _construction_order(construct)
        except GuardError as error:
            failures.append(f"self-test valid `{label}` was rejected: {error}")
        else:
            if actual != expected:
                failures.append(f"self-test valid `{label}` changed construction order")
    for construct in ("[alpha, beta]", "[42]", "[] +", "[alpha", "[alpha] [alpha]"):
        try:
            _construction_order(construct)
        except GuardError:
            pass
        else:
            failures.append(f"self-test malformed construct was accepted: {construct}")

    construction_mutations = (
        ("unknown field", "[unknown_metric txs isi", "has no field definition"),
        ("duplicate field", "[txs txs isi", "duplicate constructed metric fields"),
        ("missing field behind empty group", "[] [isi", "metric fields missing from construction"),
        ("raw field", "[registry txs isi", "raw field `registry` entered catalog construction"),
    )
    for label, replacement, expected_finding in construction_mutations:
        mutated_source = source.replace("[txs isi", replacement, 1)
        if mutated_source == source:
            failures.append(f"self-test construction mutation `{label}` did not alter its input")
            continue
        _, _, source_findings = _dsl_calls(mutated_source)
        if not any(expected_finding in finding for finding in source_findings):
            failures.append(f"self-test construction mutation `{label}` missed its intended gate")

    unknown_kind_source = source.replace(
        'pub txs: int_counter_vec(&["type"]);', 'pub txs: unknown_metric_kind();', 1
    )
    _, _, unknown_kind_findings = _dsl_calls(unknown_kind_source)
    if not any(
        "uses unknown kind `unknown_metric_kind`" in finding
        for finding in unknown_kind_findings
    ):
        failures.append("self-test unknown metric kind missed its intended gate")

    lines = catalog.splitlines(keepends=True)
    duplicate_catalog = b"".join(lines[:2] + [lines[1]] + lines[3:])
    _, duplicate_findings = _catalog_rows(duplicate_catalog)
    if (
        "duplicate metric key `txs`" not in duplicate_findings
        or "duplicate metric name `txs`" not in duplicate_findings
    ):
        failures.append("self-test duplicate catalog identity missed its intended gates")
    malformed_catalog = b"".join(
        [lines[0], lines[1].rstrip(b"\n") + b"\textra\n"] + lines[2:]
    )
    _, malformed_findings = _catalog_rows(malformed_catalog)
    if "catalog row 1 has 5 fields, expected 4" not in malformed_findings:
        failures.append("self-test malformed catalog row missed its intended gate")
    calls, _, source_findings = _dsl_calls(source)
    rows, catalog_findings = _catalog_rows(catalog)
    if source_findings or catalog_findings:
        failures.append("self-test independent ledger inputs failed their baseline")
    else:
        reordered = [calls[1], calls[0]] + calls[2:]
        try:
            _semantic_ledger(rows, reordered)
        except GuardError as error:
            if "catalog/source order differs at row 1" not in str(error):
                failures.append("self-test catalog order failed at an unrelated gate")
        else:
            failures.append("self-test catalog order was not rejected")

    retired_kind_source = source.replace(
        "pub block_height: int_counter();",
        "pub block_height: dropped_messages_counter();",
        1,
    )
    if retired_kind_source == source:
        failures.append("self-test retired-kind mutation did not alter its input")
    else:
        expected_retired_kind = (
            "metric field `block_height` uses unknown kind `dropped_messages_counter`"
        )
        _, _, retired_kind_findings = _dsl_calls(retired_kind_source)
        if expected_retired_kind not in retired_kind_findings:
            failures.append("self-test retired-kind mutation missed its unknown-kind gate")
        guard_findings = check_contents(catalog, retired_kind_source)
        if not guard_findings or expected_retired_kind not in guard_findings:
            failures.append("self-test retired-kind mutation was not refused by the whole guard")

    retired_halo2 = RETIRED_HALO2_CONFIGURATION_METRICS[0]
    retired_halo2_findings = check_contents(
        catalog, source + f'\nconst RETIRED_HALO2_PROBE: &str = "{retired_halo2}";\n'
    )
    if f"retired metric source returned: {retired_halo2}" not in retired_halo2_findings:
        failures.append("self-test failed to reject a retired Halo2 configuration metric source token")

    retired_probe = RETIRED_LEGACY_DA_GATE_METRICS[0]
    retired_findings = check_contents(
        catalog,
        source + f'\nconst RETIRED_METRIC_PROBE: &str = "{retired_probe}";\n',
    )
    expected_retired_finding = f"retired metric source returned: {retired_probe}"
    if expected_retired_finding not in retired_findings:
        failures.append(
            "self-test failed to reject a retired legacy DA-gate metric source token"
        )

    mutations = [
        (
            "registration",
            catalog.replace(b"\tregistered\n", b"\tunregistered\n", 1),
            source,
        ),
        ("catalog-name", catalog.replace(b"txs\ttxs", b"txs\ttxz", 1), source),
        (
            "dsl-kind",
            catalog,
            source.replace(
                'pub txs: int_counter_vec(&["type"]);',
                'pub txs: gauge_vec(&["type"]);',
                1,
            ),
        ),
        (
            "dsl-label",
            catalog,
            source.replace(
                'pub txs: int_counter_vec(&["type"]);',
                'pub txs: int_counter_vec(&["kind"]);',
                1,
            ),
        ),
        ("construction-order", catalog, source.replace("[txs isi", "[isi txs", 1)),
        ("bucket", catalog, source.replace("-10.0,", "-11.0,", 1)),
        (
            "macro-dispatch",
            catalog,
            source.replace(
                "$metrics.gauge(stringify!($field))",
                "$metrics.int_gauge(stringify!($field))",
                1,
            ),
        ),
        ("factory-body", catalog, source.replace("if registered {", "if !registered {", 1)),
        ("second-consumer", catalog, source + '\nconst EXTRA: &str = include_str!("metrics/catalog_v2.tsv");\n'),
    ]
    for label, mutated_catalog, mutated_source in mutations:
        if mutated_catalog == catalog and mutated_source == source:
            failures.append(f"self-test mutation `{label}` did not alter its input")
        elif not check_contents(mutated_catalog, mutated_source):
            failures.append(f"self-test mutation `{label}` was not rejected")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    findings = self_test(root) if args.self_test else check(root)
    if findings:
        for finding in findings:
            print(f"telemetry metric catalog v2 guard: {finding}")
        return 1
    suffix = "; mutation self-test passed" if args.self_test else ""
    print(
        "telemetry metric catalog v2 guard: "
        f"{ROWS} rows, {REGISTERED} registered, ledger_sha256={LEDGER_SHA256}{suffix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
