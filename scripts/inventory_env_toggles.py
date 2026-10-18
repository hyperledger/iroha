#!/usr/bin/env python3
"""
Inventory environment-variable toggles across Rust sources.

The script scans `.rs` files under the repository root for common environment
lookup patterns (`env::var*`, `env!`, `option_env!`) and emits a deterministic
inventory. Use the JSON output for tooling/CI checks and the Markdown output for
human review of production vs test/dev usage.

No dependencies or environment settings are required. Scope analysis recognizes
explicit cfg attributes conservatively; it is not a Rust compiler or a module
reachability proof. Unknown conditions and unproved helper guards remain in the
source file's base scope. Only the requested report paths are written.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

TEST_PATH_HINTS = {
    "tests",
    "integration_tests",
    "iroha_test_network",
    "iroha_test_samples",
}
TEST_FILE_STEMS = frozenset({"test", "tests"})

# Top-level search roots (falls back to the repo root if none exist).
SEARCH_ROOTS = (
    "crates",
    "xtask",
    "tools",
    "integration_tests",
    "tests",
    "examples",
    "sdk",
    "IrohaSwift",
    "mochi",
    "benchmarks",
    "fuzz",
)

# Directories to skip during the walk (keep the list conservative to avoid
# traversing build artefacts).
SKIP_DIRS = {
    ".build",
    ".git",
    "target",
    "target-codex",
    "target_codex",
    "target-snapshot",
    "target-wallet",
    "build",
    "vendor",
    "artifacts",
    "node_modules",
}

ENV_PATTERNS: Sequence[re.Pattern[str]] = (
    re.compile(r"""\b(?:std::)?env::var(?:_os)?\(\s*"([A-Za-z0-9_]+)"""),
    re.compile(r"""\benv!\(\s*"([A-Za-z0-9_]+)"""),
    re.compile(r"""\boption_env!\(\s*"([A-Za-z0-9_]+)"""),
)
RAW_LITERAL = re.compile(r'(?:br|cr|r)(#{0,255})"')
QUOTED_LITERAL = re.compile(r'(?:b|c)?"')
CHAR_LITERAL = re.compile(
    r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'"
)
RUST_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


@dataclasses.dataclass(frozen=True)
class EnvReference:
    name: str
    path: Path
    line: int
    scope: str
    context: str


def iter_rust_files(root: Path) -> Iterable[Path]:
    candidates = [root / entry for entry in SEARCH_ROOTS if (root / entry).exists()]
    if not candidates:
        candidates = [root]

    for base in candidates:
        for path in base.rglob("*.rs"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            yield path


def classify_scope(path: Path) -> str:
    """Classify a Rust source by its build role and test-shard convention."""

    parts = set(path.parts)
    if path.name == "build.rs":
        return "build"
    stem = path.stem
    if (
        TEST_PATH_HINTS.intersection(parts)
        or stem in TEST_FILE_STEMS
        or stem.endswith(("_test", "_tests"))
    ):
        return "test"
    if "benches" in parts:
        return "bench"
    if "examples" in parts:
        return "example"
    if {"xtask", "tools"}.intersection(parts):
        return "tool"
    return "prod"


def extract_references(path: Path) -> List[EnvReference]:
    refs: List[EnvReference] = []
    scope = classify_scope(path)

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return refs

    # Most Rust files contain no literal reads. Preserve the inventory's existing
    # literal-only scope without tokenizing sources that cannot contribute rows.
    if not any(pattern.search(line) for line in lines for pattern in ENV_PATTERNS):
        return refs

    cfg_masks = compute_cfg_masks(lines)

    for idx, line in enumerate(lines, start=1):
        is_test, is_debug = cfg_masks[idx - 1]
        if is_test:
            local_scope = "test"
        elif is_debug:
            local_scope = "debug"
        else:
            local_scope = scope
        for pattern in ENV_PATTERNS:
            for match in pattern.finditer(line):
                name = match.group(1)
                refs.append(
                    EnvReference(
                        name=name,
                        path=path.relative_to(REPO_ROOT),
                        line=idx,
                        scope=local_scope,
                        context=line.strip(),
                    )
                )
    return refs


def collect_inventory(root: Path) -> List[EnvReference]:
    refs: List[EnvReference] = []
    for file_path in iter_rust_files(root):
        refs.extend(extract_references(file_path))
    refs.sort(key=lambda r: (r.name, str(r.path), r.line))
    return refs


def rust_scope_tokens(source: str) -> List[tuple[str, int]]:
    """Read structural tokens and line numbers without interpreting literal text."""

    tokens: List[tuple[str, int]] = []
    offset = line = 0
    while offset < len(source):
        start = offset
        if source.startswith("//", offset):
            end = source.find("\n", offset)
            offset = len(source) if end < 0 else end
        elif source.startswith("/*", offset):
            depth = 1
            offset += 2
            while offset < len(source) and depth:
                if source.startswith("/*", offset):
                    depth += 1
                    offset += 2
                elif source.startswith("*/", offset):
                    depth -= 1
                    offset += 2
                else:
                    offset += 1
        elif source[offset].isspace():
            offset += 1
        else:
            raw = RAW_LITERAL.match(source, offset)
            quoted = QUOTED_LITERAL.match(source, offset)
            character = CHAR_LITERAL.match(source, offset)
            if raw:
                closing = '"' + raw.group(1)
                end = source.find(closing, raw.end())
                offset = len(source) if end < 0 else end + len(closing)
                token = "<literal>"
            elif quoted:
                offset = quoted.end()
                while offset < len(source):
                    if source[offset] == "\\":
                        offset = min(offset + 2, len(source))
                    elif source[offset] == '"':
                        offset += 1
                        break
                    else:
                        offset += 1
                token = "<literal>"
            elif character:
                offset = character.end()
                token = "<literal>"
            else:
                identifier = RUST_IDENTIFIER.match(source, offset)
                offset = identifier.end() if identifier else offset + 1
                token = source[start:offset]
            tokens.append((token, line))
        line += source.count("\n", start, offset)
    return tokens


def cfg_arguments(tokens: Sequence[str], name: str) -> List[List[str]] | None:
    """Split one complete attribute/predicate call; malformed input is unknown."""

    if len(tokens) < 3 or list(tokens[:2]) != [name, "("] or tokens[-1] != ")":
        return None
    arguments: List[List[str]] = []
    current: List[str] = []
    stack: List[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for token in tokens[2:-1]:
        if token in ("(", "[", "{"):
            stack.append(token)
        elif token in pairs:
            if not stack or stack.pop() != pairs[token]:
                return None
        if token == "," and not stack:
            if not current:
                return None
            arguments.append(current)
            current = []
        else:
            current.append(token)
    if stack:
        return None
    if current:
        arguments.append(current)
    return arguments


def cfg_possible(tokens: Sequence[str], flag: str, depth: int = 0) -> set[bool]:
    """Overapproximate a predicate with the selected flag false and others unknown."""

    unknown = {False, True}
    if depth > 64:
        return unknown
    if list(tokens) == [flag] or list(tokens) == ["false"]:
        return {False}
    if list(tokens) == ["true"]:
        return {True}
    for operator in ("all", "any", "not"):
        arguments = cfg_arguments(tokens, operator)
        if arguments is None:
            continue
        values = [cfg_possible(argument, flag, depth + 1) for argument in arguments]
        if operator == "not":
            return {not value for value in values[0]} if len(values) == 1 else unknown
        result = {operator == "all"}
        for value in values:
            result = {
                (left and right) if operator == "all" else (left or right)
                for left in result for right in value
            }
        return result
    return unknown


def cfg_attribute_possible(tokens: Sequence[str], flag: str, depth: int = 0) -> set[bool]:
    """Include cfg_attr's unapplied branch; unrelated attributes impose no bound."""

    if depth > 64:
        return {False, True}
    arguments = cfg_arguments(tokens, "cfg")
    if arguments is not None:
        return cfg_possible(arguments[0], flag) if len(arguments) == 1 else {False, True}
    arguments = cfg_arguments(tokens, "cfg_attr")
    if arguments is None or len(arguments) < 2:
        return {True}
    condition = cfg_possible(arguments[0], flag)
    active = {True}
    for attribute in arguments[1:]:
        active = {
            left and right
            for left in active
            for right in cfg_attribute_possible(attribute, flag, depth + 1)
        }
    return {(not selected) or included for selected in condition for included in active}


def compute_cfg_masks(lines: Sequence[str]) -> List[tuple[bool, bool]]:
    """Identify only line scopes whose explicit attributes require test or debug.

    Mixed scopes on one line remain unclassified. This deliberately does not
    infer control flow from cfg! expressions, helper names or external modules.
    """

    tokens = rust_scope_tokens("\n".join(lines))
    masks: List[tuple[bool, bool] | None] = [None] * len(lines)
    stack = [(False, False)]
    pending = (False, False)
    delimiters: List[str] = []
    index = 0
    while index < len(tokens):
        token, line = tokens[index]
        start = index + 1
        inner = start < len(tokens) and tokens[start][0] == "!"
        if inner:
            start += 1
        if token == "#" and start < len(tokens) and tokens[start][0] == "[":
            end = start + 1
            nesting = 1
            while end < len(tokens) and nesting:
                nesting += (tokens[end][0] == "[") - (tokens[end][0] == "]")
                end += 1
            if nesting:
                break
            attribute = [value for value, _ in tokens[start + 1:end - 1]]
            required = tuple(True not in cfg_attribute_possible(attribute, flag)
                             for flag in ("test", "debug_assertions"))
            # Attributes within signatures, tuple expressions or array elements
            # do not constrain the surrounding item. Leave their smaller scopes
            # unclassified rather than applying them to the following body.
            if not delimiters:
                if inner:
                    stack[-1] = tuple(left or right for left, right in zip(stack[-1], required))
                else:
                    pending = tuple(left or right for left, right in zip(pending, required))
            index = end
            continue
        current = tuple(left or right for left, right in zip(stack[-1], pending))
        previous = masks[line]
        masks[line] = current if previous is None else tuple(
            left and right for left, right in zip(previous, current)
        )
        if token == "{":
            stack.append(current)
            pending = (False, False)
        elif token == "}":
            if len(stack) > 1:
                stack.pop()
            pending = (False, False)
        elif token in ("(", "["):
            delimiters.append(token)
        elif token in (")", "]"):
            if delimiters:
                delimiters.pop()
        elif token in (";", ",") and not delimiters:
            pending = (False, False)
        index += 1
    return [mask if mask is not None else (False, False) for mask in masks]


def build_summary(refs: Sequence[EnvReference]) -> Dict[str, Dict[str, object]]:
    summary: Dict[str, Dict[str, object]] = {}
    by_name: Dict[str, List[EnvReference]] = defaultdict(list)
    for ref in refs:
        by_name[ref.name].append(ref)

    for name, entries in sorted(by_name.items()):
        scope_counts = Counter(ref.scope for ref in entries)
        summary[name] = {
            "counts": dict(sorted(scope_counts.items())),
            "paths": [
                {
                    "path": str(ref.path),
                    "line": ref.line,
                    "scope": ref.scope,
                    "context": ref.context,
                }
                for ref in entries
            ],
        }
    return summary


def write_json(output: Path, refs: Sequence[EnvReference]) -> None:
    data = {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "command": "python3 scripts/inventory_env_toggles.py --json specs/agents/env_var_inventory.json --md specs/agents/env_var_inventory.md",
        "root": REPO_ROOT.name,
        "total_refs": len(refs),
        "unique_vars": len({ref.name for ref in refs}),
        "variables": build_summary(refs),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(output: Path, refs: Sequence[EnvReference]) -> None:
    summary = build_summary(refs)
    lines: List[str] = []
    lines.append("# Environment toggle inventory")
    lines.append("")
    lines.append(
        "_Last refreshed via `python3 scripts/inventory_env_toggles.py --json specs/agents/env_var_inventory.json --md specs/agents/env_var_inventory.md`_"
    )
    lines.append("")
    lines.append(
        f"Total references: **{len(refs)}** · Unique variables: **{len(summary)}**"
    )
    lines.append("")

    for name, data in summary.items():
        counts = data["counts"]
        counts_str = ", ".join(f"{scope}: {count}" for scope, count in counts.items())
        lines.append(f"## {name} ({counts_str})")
        lines.append("")
        for entry in data["paths"]:
            lines.append(
                f"- {entry['scope']}: {entry['path']}:{entry['line']} — `{entry['context']}`"
            )
        lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory environment-variable toggles across Rust sources."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root to scan (defaults to repo root).",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        help="Write JSON inventory to this path.",
    )
    parser.add_argument(
        "--md",
        dest="md_path",
        type=Path,
        help="Write Markdown summary to this path.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    refs = collect_inventory(args.root)

    if args.json_path:
        write_json(args.json_path, refs)
    if args.md_path:
        write_markdown(args.md_path, refs)

    if not args.json_path and not args.md_path:
        for ref in refs:
            print(f"{ref.name}\t{ref.scope}\t{ref.path}:{ref.line}\t{ref.context}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
