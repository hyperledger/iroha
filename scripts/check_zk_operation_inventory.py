#!/usr/bin/env python3
"""Check the ZK operation and admission-route inventory against the source.

`specs/zk_operation_inventory.json` maps every operation of the ZK, privacy,
FHE and authenticated-State products through its native instruction (type and
wire id), handler, proof relation and verifier (or the typed refusal that
stands in for one), authority checks, Kotodama binding, Torii routes and the
files of the six SDK families and of the native bridges that reference it. It
also lists the generic verification, preverification, verifying-key
registration, genesis and restore routes, the native and in-circuit digests
each product uses and every site where an uploaded key, a source hash or
catalog membership selects what a proof establishes. This script is the drift
guard for that file. It fails when:

* an instruction of the registry is in a listed family and is not an
  operation, a registry module is not classed, a registry type outside the
  families has a family name or its handler calls a proof verifier (directly
  or through functions of its file) and it is neither listed nor excluded with
  a reason, a file that generates handlers by macro is not listed with its
  verifier calls, or a listed type, wire id, definition or handler differs
  from the source;
* a handler contains an authority check the operation does not list, or lists
  one the handler does not contain; a listed operation's handler calls a proof
  verifier while its verification is recorded as not applicable;
* the closed protocol list (`PrivacyProtocolIdV1`), its labels, proof systems,
  engines, security models, dispatch arms or compiled-profile arms differ, or
  the cited test that asserts which profiles construct does not name a
  protocol recorded as constructed;
* the thirteen Exact12 roles (`PrivacyActionRoleV1`), their protocols or the
  typed dispatch registry (verification, limitation, effect class, delivery)
  differ from the recorded rows, or a row's state effects are not what its
  verification, its effect class and the admission gate of the handler imply;
* a second authoritative route for an Exact12 role appears: the envelope is
  assembled outside its one assembler, an envelope identity is assigned at an
  unrecorded site, a second instruction carries an envelope, statement or
  proof, the handler prepares, resolves the role, dispatches or consumes an
  effect more than once, a role's native verifier is called outside its
  engine, the dispatch and the recorded non-admission tooling, a verified
  effect is consumed or matched at an unrecorded site, an action-driver
  operation names no role, or a retired duplicate is back;
* a closed enum the inventory mirrors gains or loses a variant: the generic
  proof relations, the native PIPA-R circuits, the RAM-LFE classes,
  backends, verification modes and opening variants, the SoraCloud FHE job
  kinds, decryption modes and typed native roles, and the transaction
  executables;
* a syscall or Kotodama builtin of a listed family, or an operation tag of the
  instruction bridge, is not listed, or a recorded number or binding differs;
* a Torii route of a listed path family is not listed (read from the compiled
  route catalog and from `specs/sdk_operation_inventory.tsv`), a route outside
  them has a family word and is not excluded, a recorded method, path,
  surface, effect or SDK projection differs from its row, a route's handler
  is not a Torii function, a route whose handler names an instruction is not
  linked to that operation, or the Torii files that name an instruction
  differ from the recorded ones;
* a verifier or validator entry point is called in a production file, or a
  number of times, that the entry-point census does not record under an
  admission route class (so a new admission route cannot appear unclassed);
* a file of an SDK family or of a native bridge starts or stops referencing a
  listed instruction or route, or an SDK declaration with a family name is
  added or removed;
* a selector token (a verifying-key registry read, an inline key, a
  node-configured key reference, the all-protocol qualification record, an
  uploaded verifier description, a compiled-profile comparison) appears in a
  file or count the inventory does not record, a production file starts
  including Rust source bytes, or a selection site has neither a rejection
  test nor an open defect with an owning task;
* the hash-primitive census of a product's owner files differs;
* a recorded path, symbol or test is gone (a test must carry `#[test]` and not
  `#[ignore]`; a test whose file or top-level module compiles only with a
  Cargo feature outside the crate's defaults must record that `feature` and
  then counts as not running by default), or a key of another inventory, a
  requirement id or a task id does not resolve;
* a status claims more than its evidence: an `implemented` operation whose
  recorded path from the handler does not name the verifier; a cited test that
  neither reaches the verifier nor says what it covers instead; a
  `test_evidence` that differs from what the cited tests show; `refused`
  without the refusal; delivery other than `not_delivered` while an owning
  task is not `implemented` in the graph.

Reading is textual. A symbol is found as text after collapsing whitespace; an
enum, a constant list, a match, a function body and an `impl` block are read
by brace matching on text whose comments and literals are blanked. It is a
source regression guard, not a Rust parser and not a substitute for the tests
it names. An inventory entry establishes no readiness: `presence` only says a
type is registered.

Limits, stated once:

* Reach. A cited test "reaches" a verifier when its code, the functions it
  calls in its own file (a call is followed when the file defines exactly one
  function of that name; an `impl Execute for T` block when the code names `T`
  and an `execute...` call) or the functions of its `reaches` list name the
  verifier or a function on the operation's recorded path to it. That shows
  the test is about the verifier. It does not show that the call runs, or
  that a valid proof is accepted rather than an invalid one rejected.
* Authority. Checks are found in a handler's own `impl` blocks, or in its
  explicitly recorded original-invocation entry: listed check
  names, permission tokens, comparisons with the signer and every function
  that receives the signer. A check inside a shared helper is recorded with
  `scope: file` and anchored, so its removal fails; one added inside such a
  helper is not detected.
* Original invocation. An explicit entry records the typed dispatch, required
  context parameter and exact unconditional detached refusal. These are source
  anchors; Rust typing and runtime custody tests establish provenance.
* Handler tripwire. A verifier call is found in the handler's blocks and in
  the functions of its file they call, `helper_depth` levels deep; deeper or
  cross-file calls, and callees of an original-invocation entry, are found by
  the entry-point census only if the verifier
  is one of its tokens. Macro-generated handlers are read per file.
* Entry points. The census counts calls of the listed entry points. A new
  verifier function that is no token, and a restore validator whose name has
  no family word, are not seen, except for the explicitly counted restore
  methods `validate_for_key` and `validate_at_committed_height`. Named AXT
  validators are included. Individually listed AXT consistency guards remain
  source anchors; this does not infer arbitrary new validation expressions.
* SDK and bridge scans find a type name, a quoted wire id or a route path
  literal. A name built from parts at run time is not found.
* Digests. The census counts primitive names from a closed list in each
  product's owner paths; a primitive under a name outside the list is not
  counted.
* Exact12 single route. The scan reads code without comments, literals and
  test-gated items. A destructuring pattern of the envelope type counts as an
  assembly; an envelope built through a type alias or a macro, and a native
  verifier reached through a function that is not a recorded verifier, are
  not seen.

Maintenance. The inventory is edited by hand; `--refresh` does the mechanical
part: it recomputes the SDK and bridge references of every operation and
route, the Torii files that name each instruction, the SDK declaration list,
the selector, source-inclusion and entry-point censuses and the digest
census, and rewrites the recorded row of every listed route. It keeps every
classification and prints what it changed. New instructions, routes, selector
files, entry-point calls and declarations that no rule classifies are
reported by the check that follows; `--propose` prints a skeleton for each
unlisted instruction and route.

Prerequisites: Python 3.9+ standard library, run from a checkout. `rustc` is
used to read the compiled route catalog (the same std-only exporter as
`scripts/sdk_operation_inventory.py`); `--no-compile` skips it and checks
routes against the tracked TSV only. No environment variables are read.

Usage:
    python3 scripts/check_zk_operation_inventory.py
    python3 scripts/check_zk_operation_inventory.py --show       # one line per operation
    python3 scripts/check_zk_operation_inventory.py --refresh    # rewrite mechanical parts
    python3 scripts/check_zk_operation_inventory.py --propose    # skeletons, writes nothing
    python3 scripts/check_zk_operation_inventory.py --with-plan-check
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "specs/zk_operation_inventory.json"
GRAPH = "specs/zk_delivery_graph.json"
LEDGER = "specs/zk_delivery_reconciliation.json"
ROUTE_TSV = "specs/sdk_operation_inventory.tsv"
ROUTE_EXPORTER = "scripts/sdk_operation_inventory.rs"
SCHEMA = "iroha.zk_operation_inventory.v1"
TASK = "F.1"

SDK_FAMILIES = ("rust", "kotlin_java_android", "swift", "javascript", "python", "csharp")
BRIDGES = "native_bridges"
PRESENCE = ("registered", "carrier", "absent")
VERIFICATION = ("implemented", "binding_only", "signature_only", "refused", "not_applicable", "absent")
STATE_EFFECTS = ("implemented", "gated", "unreachable", "none", "absent")
DELIVERY = ("not_delivered", "delivered")
TESTED = ("implemented", "binding_only", "signature_only")
EVIDENCE = ("default", "not_default", "none")
ROLES = ("proof_effect", "proof_verification", "administrative", "effect", "refused", "absent")
CARRIERS = ("executable", "syscall", "block_artifact", "torii_route", "absent")
SELECTORS = ("uploaded_key", "source_hash", "catalog_membership", "node_configuration", "cargo_feature")
ADMISSION_ROUTES = (
    "generic_verification",
    "ivm_syscalls",
    "torii",
    "preverification",
    "verifying_key_registration",
    "direct_protocol_instructions",
    "genesis",
    "restore",
)
DIGEST_ROLES = (
    "catalog_commitments",
    "kaigi_authorization",
    "confidential_spentness",
    "mkhe_proof_hashes",
)
SKIP_DIRS = frozenset(
    {
        "build",
        "node_modules",
        "__pycache__",
        "target",
        ".gradle",
        "bin",
        "obj",
        "dist",
        ".build",
        ".git",
        "DerivedData",
    }
)


# Files found under a set of roots of one checkout, kept for the process: the checker is a
# short-lived command and its tests substitute contents through `Tree(overrides=...)`.
_WALKS: dict[tuple, list[str]] = {}


class Tree:
    """Read-only view of the checkout. Tests substitute file contents."""

    def __init__(self, root: Path = ROOT, overrides: dict[str, str | None] | None = None) -> None:
        self.root = Path(root)
        self.overrides = dict(overrides or {})
        self._cache: dict[str, str | None] = {}
        self._walks: dict[tuple, list[str]] = {}

    def read(self, path: str) -> str | None:
        if path in self.overrides:
            return self.overrides[path]
        if path not in self._cache:
            file = self.root / path
            try:
                self._cache[path] = file.read_text(encoding="utf-8", errors="replace") if file.is_file() else None
            except OSError:
                self._cache[path] = None
        return self._cache[path]

    def exists(self, path: str) -> bool:
        if path in self.overrides:
            return self.overrides[path] is not None
        return (self.root / path).exists()

    def walk(self, roots: list[str], extensions: tuple[str, ...]) -> list[str]:
        """Repository-relative files under `roots` with one of `extensions`, sorted."""
        key = (tuple(roots), tuple(extensions))
        shared = (str(self.root),) + key
        if key not in self._walks and shared in _WALKS:
            self._walks[key] = _WALKS[shared]
        if key not in self._walks:
            found: set[str] = set()
            for root in roots:
                base = self.root / root
                if base.is_file():
                    if root.endswith(extensions):
                        found.add(root)
                    continue
                for directory, names, files in os.walk(base):
                    names[:] = sorted(name for name in names if name not in SKIP_DIRS)
                    for file in files:
                        if file.endswith(extensions):
                            found.add(os.path.relpath(os.path.join(directory, file), self.root))
            self._walks[key] = _WALKS[shared] = sorted(found)
        files = set(self._walks[key])
        for path, text in self.overrides.items():
            if not path.endswith(extensions):
                continue
            if not any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots):
                continue
            if text is None:
                files.discard(path)
            else:
                files.add(path)
        return sorted(files)


# --------------------------------------------------------------------------- text readers


def squash(text: str) -> str:
    """Collapse every whitespace run so a symbol survives reformatting."""
    return " ".join(text.split())


_SQUASHED: dict[int, tuple[str, str]] = {}


def contains(text: str, symbol: str) -> bool:
    key = id(text)
    cached = _SQUASHED.get(key)
    if cached is None or cached[0] is not text:
        cached = (text, squash(text))
        _SQUASHED[key] = cached
    return squash(symbol) in cached[1]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def balanced(text: str, start: int, opening: str = "{", closing: str = "}") -> int | None:
    """Index after the delimiter that closes the one at `start`."""
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def block_after(text: str, pattern: str) -> str | None:
    """Brace-delimited body following the first match of `pattern`."""
    match = re.search(pattern, text)
    if match is None:
        return None
    start = text.find("{", match.end() - 1)
    if start < 0:
        return None
    end = balanced(text, start)
    return None if end is None else text[start + 1 : end - 1]


def strip_attributes(text: str) -> str:
    out = []
    index = 0
    while index < len(text):
        if text.startswith("#[", index):
            end = balanced(text, index + 1, "[", "]")
            if end is None:
                break
            index = end
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def split_top_level(text: str) -> list[str]:
    parts, depth, current = [], 0, []
    for char in text:
        if char in "({[<":
            depth += 1
        elif char in ")}]>":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def enum_variants(text: str, name: str) -> list[str] | None:
    body = block_after(text, r"\benum\s+" + re.escape(name) + r"\s*\{")
    if body is None:
        return None
    body = strip_attributes(strip_comments(body))
    variants = []
    for part in split_top_level(body):
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", part)
        if match:
            variants.append(match.group(1))
    return variants


def string_list(text: str, name: str) -> list[str] | None:
    """String literals of a `const NAME: ... = &[ ... ];` or `[ ... ]` list."""
    match = re.search(r"\b(?:const|static)\s+" + re.escape(name) + r"\b[^=]*=\s*&?\[", text)
    if match is None:
        return None
    end = balanced(text, match.end() - 1, "[", "]")
    if end is None:
        return None
    return re.findall(r'"([^"]*)"', strip_comments(text[match.end() : end - 1]))


def fn_body(text: str, name: str) -> str | None:
    return block_after(text, r"\bfn\s+" + re.escape(name) + r"\s*(?:<[^>]*>)?\s*\(")


def match_arms(body: str, owner: str = "Self") -> dict[str, str]:
    """Map `Owner::Variant` patterns of a match to the head of their arm."""
    arms: dict[str, str] = {}
    body = strip_attributes(strip_comments(body))
    pattern = re.compile(
        r"((?:" + re.escape(owner) + r"::\w+(?:\s*\([^)]*\))?\s*\|?\s*)+)=>\s*\{?\s*(\"[^\"]*\"|[A-Za-z_][\w:]*)"
    )
    for match in pattern.finditer(body):
        for variant in re.findall(re.escape(owner) + r"::(\w+)", match.group(1)):
            arms.setdefault(variant, match.group(2).strip('"'))
    return arms


_ATTRIBUTES_BEFORE = re.compile(r"((?:#\[[^\]]*\]\s*)+)(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?$")


def has_test(tree: Tree, path: str, name: str) -> str | None:
    """None when `name` is a test compiled from `path`, else the reason."""
    text = tree.read(path)
    if text is None:
        return f"{path}: file is missing"
    declared = re.search(r"\bfn\s+" + re.escape(name) + r"\s*\(", text)
    if declared is not None:
        before = _ATTRIBUTES_BEFORE.search(text[max(0, declared.start() - 600) : declared.start()])
        attributes = before.group(1) if before else ""
        if not re.search(r"#\[(?:tokio::)?test\b", attributes) and "test_case" not in attributes:
            return f"{path}: fn {name} has no #[test] attribute"
        if "#[ignore" in attributes:
            return f"{path}: test {name} is #[ignore]d"
        if "cfg(any())" in attributes:
            return f"{path}: test {name} is compiled out"
        return None
    macro = re.search(r"\b([a-z_]+)!\(\s*" + re.escape(name) + r"\s*\{", text)
    if macro is not None:
        definition = block_after(text, r"macro_rules!\s+" + re.escape(macro.group(1)) + r"\s*\{")
        if definition is not None and "#[test]" in definition:
            return None
        return f"{path}: {macro.group(1)}!({name} ...) is not a test macro of this file"
    return f"{path}: test {name} not found"


def default_features(tree: Tree, crate: str) -> set[str]:
    """The features of `crates/<crate>` that its `default` feature enables, transitively."""
    text = tree.read(f"crates/{crate}/Cargo.toml") or ""
    section = re.search(r"^\[features\][^\n]*\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
    table: dict[str, list[str]] = {}
    if section is not None:
        body = re.sub(r"#[^\n]*", "", section.group(1))
        for name, items in re.findall(r"^([\w-]+)\s*=\s*\[(.*?)\]", body, re.M | re.S):
            table[name] = re.findall(r'"([^"]+)"', items)
    enabled: set[str] = set()
    queue = ["default"]
    while queue:
        name = queue.pop()
        if name not in enabled:
            enabled.add(name)
            queue.extend(item for item in table.get(name, []) if item in table)
    return enabled


def target_required_feature(tree: Tree, crate: str, relative: str) -> str | None:
    """The non-default feature a Cargo target of `crates/<crate>` rooted at `relative` requires."""
    text = tree.read(f"crates/{crate}/Cargo.toml") or ""
    defaults = default_features(tree, crate)
    for table in re.findall(r"^\[\[(?:bin|test|example|bench)\]\][^\n]*\n(.*?)(?=^\[|\Z)", text, re.M | re.S):
        body = re.sub(r"#[^\n]*", "", table)
        root = re.search(r'^path\s*=\s*"([^"]+)"', body, re.M)
        required = re.search(r"^required-features\s*=\s*\[(.*?)\]", body, re.M | re.S)
        if root is None or required is None or root.group(1) != relative:
            continue
        for feature in re.findall(r'"([^"]+)"', required.group(1)):
            if feature not in defaults:
                return feature
    return None


def feature_gate(tree: Tree, path: str) -> str | None:
    """The non-default Cargo feature gating the top-level module that holds `path`, if any.

    Three gates are read: `required-features` of the Cargo target whose `path` is the file (a
    binary, test, example or bench target), an inner `#![cfg(... feature = "..." ...)]` of the
    file itself (an integration test under `tests/`), and `#[cfg(feature = "...")] mod name;` in
    the crate's `src/lib.rs`.
    """
    crate_of = re.match(r"crates/([^/]+)/(.*)", path)
    if crate_of is not None:
        required = target_required_feature(tree, crate_of.group(1), crate_of.group(2))
        if required is not None:
            return required
        defaults = default_features(tree, crate_of.group(1))
        for attribute in re.findall(r"#!\[cfg\(([^\]]*)\)\]", tree.read(path) or ""):
            for feature in re.findall(r'feature\s*=\s*"([^"]+)"', attribute):
                if feature not in defaults:
                    return feature
    match = re.match(r"(crates/([^/]+)/src)/([^/.]+)", path)
    if match is None:
        return None
    root, crate, module = match.groups()
    gate = re.search(
        r'#\[cfg\(feature\s*=\s*"([^"]+)"\)\]\s*(?:(?:#\[[^\]]*\]|//[^\n]*)\s*)*'
        r"(?:pub(?:\([a-z]+\))?\s+)?mod\s+" + re.escape(module) + r"\s*;",
        tree.read(f"{root}/lib.rs") or "",
    )
    if gate is None or gate.group(1) in default_features(tree, crate):
        return None
    return gate.group(1)


def runs_by_default(test: dict) -> bool:
    """A cited test counts as default-running unless it is `#[ignore]`d or feature-gated."""
    return not test.get("ignored") and not test.get("feature")


# --------------------------------------------------------------------------- textual reach

REACH_DEPTH = 4
_RUST_LITERAL = re.compile(
    r'''"(?:\\.|[^"\\])*"|r(#*)".*?"\1|'(?:\\.|[^\\'])'|//[^\n]*|/\*.*?\*/''', re.S
)
_FN_DECL = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
_IMPL_DECL = re.compile(r"\bimpl\b(?:\s*<[^{};]*?>)?\s+(?:([\w:]+)(?:\s*<[^{};]*?>)?\s+for\s+)?([\w:]+)")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*(?:::\s*<[^>;{}]*>\s*)?\(")
_STRUCTURE = re.compile(r"[(){};\[\]]")


def code_only(text: str) -> str:
    """`text` with comments and the contents of string and character literals blanked.

    Offsets and line breaks are kept, so a position in the result is a position in `text`.
    """
    def blank(match: re.Match) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))
    return _RUST_LITERAL.sub(blank, text)


def body_start(code: str, index: int) -> int | None:
    """The `{` that opens the item whose signature starts at `index`, or None for a declaration."""
    depth = 0
    for match in _STRUCTURE.finditer(code, index):
        char = match.group(0)
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0:
            return match.start() if char == "{" else None
    return None


class RustIndex:
    """Function and `impl` bodies of one Rust file, read by brace matching on its code-only text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.code = code_only(text)
        closes: dict[int, int] = {}
        stack: list[int] = []
        for match in re.finditer(r"[{}]", self.code):
            if match.group(0) == "{":
                stack.append(match.start())
            elif stack:
                closes[stack.pop()] = match.end()
        self.closes = closes
        self.functions: dict[str, list[tuple[int, int]]] = {}
        for match in _FN_DECL.finditer(self.code):
            start = body_start(self.code, match.end())
            if start is not None and start in closes:
                self.functions.setdefault(match.group(1), []).append((start, closes[start]))
        test_macros = [
            match.group(1) for match in re.finditer(r"\bmacro_rules!\s+([A-Za-z_]\w*)\s*\{", self.code)
            if "#[test]" in self.code[match.end() - 1 : closes.get(match.end() - 1, match.end())]
        ]
        if test_macros:
            invocation = re.compile(r"\b(?:" + "|".join(test_macros) + r")!\(\s*([A-Za-z_]\w*)\s*\{")
            for match in invocation.finditer(self.code):
                if match.end() - 1 in closes:
                    self.functions.setdefault(match.group(1), []).append((match.end() - 1, closes[match.end() - 1]))
        self.impls: list[dict] = []
        for match in _IMPL_DECL.finditer(self.code):
            start = body_start(self.code, match.end())
            if start is not None and start in closes:
                self.impls.append({
                    "trait": (match.group(1) or "").split("::")[-1],
                    "type": match.group(2).split("::")[-1],
                    "start": match.start(),
                    "span": (start, closes[start]),
                })

    def item_span(self, position: int) -> tuple[int, int] | None:
        """The body of the item whose signature starts at `position`."""
        start = body_start(self.code, position)
        return (start, self.closes[start]) if start is not None and start in self.closes else None

    def enclosing(self, position: int) -> tuple[str | None, str | None]:
        """(function, impl type) whose bodies contain `position`; the innermost function."""
        function, best = None, None
        for name, spans in self.functions.items():
            for start, end in spans:
                if start <= position < end and (best is None or start > best):
                    function, best = name, start
        owner, best = None, None
        for block in self.impls:
            start, end = block["span"]
            if start <= position < end and (best is None or start > best):
                owner, best = block["type"], start
        return function, owner

    def closure(self, spans: list[tuple[int, int]], depth: int = REACH_DEPTH, stop: frozenset = frozenset(),
                raw: bool = False) -> str:
        """The code of `spans` and of what they call in this file, `depth` levels deep.

        A call is followed when the file defines exactly one function of that name, and an
        `impl Execute for T` block is followed when the code names `T` and an `execute...` call.
        Names in `stop` are not followed. A test written through a `#[test]` macro of the file
        (`name!(test_name { ... })`) counts as a function. With `raw`, the same spans are returned
        with their comments and literals.
        """
        out: list[str] = []
        seen_functions: set[str] = set()
        seen_impls: set[int] = set()
        seen_spans: set[tuple[int, int]] = set()
        words: set[str] = set()
        frontier = list(spans)
        for level in range(depth + 1):
            following: list[tuple[int, int]] = []
            for span in frontier:
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                body = self.code[span[0] : span[1]]
                out.append(self.text[span[0] : span[1]] if raw else body)
                if level == depth:
                    continue
                words |= set(_IDENTIFIER.findall(body))
                for callee in set(_CALL.findall(body)):
                    if callee in seen_functions or callee in stop:
                        continue
                    definitions = self.functions.get(callee, [])
                    if len(definitions) == 1:
                        seen_functions.add(callee)
                        following.append(definitions[0])
            if level < depth and any(word.startswith("execute") for word in words):
                for block in self.impls:
                    if block["trait"] == "Execute" and block["type"] in words and block["start"] not in seen_impls \
                            and block["type"] not in stop:
                        seen_impls.add(block["start"])
                        following.append(block["span"])
            frontier = following
        return "\n".join(out)


_INDEXES: dict[tuple[int, int], RustIndex] = {}


def rust_index(text: str) -> RustIndex:
    """The cached index of a file's text (keyed by content, so trees with overrides share it)."""
    key = (len(text), hash(text))
    index = _INDEXES.get(key)
    if index is None:
        index = _INDEXES[key] = RustIndex(text)
    return index


def symbol_position(text: str, symbol: str) -> int | None:
    """Offset of `symbol` in `text`, with any whitespace run matching any other."""
    parts = symbol.split()
    if not parts:
        return None
    match = re.search(r"\s+".join(re.escape(part) for part in parts), text)
    return match.start() if match else None


def anchor_names(tree: Tree, anchor: dict) -> list[str]:
    """Names by which code refers to the function or `impl` block a `{path, symbol}` anchor is in.

    A `fn name(` symbol gives `name`; an `impl Trait for Type` symbol gives `Type`. Any other symbol
    gives the function that contains it, or the type when that function is a trait method of an
    `impl` block (`execute`).
    """
    symbol = anchor.get("symbol", "")
    declared = re.search(r"\bfn\s+([A-Za-z_]\w*)", symbol)
    if declared:
        return [declared.group(1)]
    if re.match(r"\s*impl\b", symbol):
        head = re.sub(r"<[^<>]*>\s*$", "", re.sub(r"\s*\{\s*$", "", symbol))
        last = re.search(r"([\w:]+)\s*$", head)
        return [last.group(1).split("::")[-1]] if last else []
    text = tree.read(anchor.get("path", ""))
    if text is None:
        return []
    position = symbol_position(text, symbol)
    if position is None:
        return []
    function, owner = rust_index(text).enclosing(position)
    if function in (None, "execute", "execute_authorized") and owner:
        return [owner]
    return [function] if function else []


def anchor_item_text(tree: Tree, anchor: dict, *, signature: bool = False) -> str | None:
    """Read one anchored item's raw body, or only its signature when requested."""
    text = tree.read(anchor.get("path", ""))
    if text is None:
        return None
    position = symbol_position(text, anchor.get("symbol", ""))
    if position is None:
        return None
    span = rust_index(text).item_span(position)
    if span is None:
        return None
    return text[position:span[0]] if signature else text[span[0]:span[1]]


def anchor_closure(tree: Tree, anchor: dict, stop: frozenset = frozenset()) -> str | None:
    """Code of the function or `impl` block a `{path, symbol}` anchor declares, with what it calls.

    An `impl ... for Type` anchor stands for every `impl` block of `Type` in the file, so a handler
    that delegates to another trait of its type is read whole.
    """
    text = tree.read(anchor.get("path", ""))
    if text is None:
        return None
    position = symbol_position(text, anchor.get("symbol", ""))
    if position is None:
        return None
    index = rust_index(text)
    span = index.item_span(position)
    if span is None:
        return None
    spans = [span]
    if re.match(r"\s*impl\b", anchor.get("symbol", "")):
        owner = anchor_names(tree, anchor)
        spans += [block["span"] for block in index.impls if owner and block["type"] == owner[0] and block["span"] != span]
    return index.closure(spans, stop=stop)


def test_closure(tree: Tree, test: dict, stop: frozenset = frozenset()) -> str | None:
    """Code of a cited test and of what it calls in its own file."""
    text = tree.read(test.get("path", ""))
    if text is None:
        return None
    index = rust_index(text)
    spans = index.functions.get(test.get("test", ""))
    return index.closure(spans, stop=stop) if spans else None


def names(code: str, name: str) -> bool:
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", code) is not None


def reach(tree: Tree, test: dict, targets: list[str], stop: frozenset = frozenset(),
          also: list[str] | None = None) -> str | None:
    """None when the cited test reaches one of `targets`, else why it does not.

    The test's code (with what it calls in its file) must name the first link of its `reaches`
    list, each link's code must name the next, and the last code must name a target. With `also`,
    the test's own code or that last code must in addition name one of those words. Reading is
    textual: it shows that the names are there, not that the calls run.
    """
    code = test_closure(tree, test, stop)
    if code is None:
        return f"fn {test.get('test')} has no body in {test.get('path')}"
    first = code
    step = f"test {test.get('test')}"
    for link in test.get("reaches", []):
        link_names = anchor_names(tree, link)
        if not link_names:
            return f"`reaches` link `{link.get('symbol')}` is not a function or impl of {link.get('path')}"
        if not any(names(code, name) for name in link_names):
            return f"{step} does not name `{link_names[0]}`"
        code = anchor_closure(tree, link, stop)
        if code is None:
            return f"`reaches` link `{link.get('symbol')}` has no body in {link.get('path')}"
        step = f"`{link_names[0]}`"
    hit = [target for target in targets if names(code, target)]
    if not hit:
        return f"{step} does not name {' or '.join(f'`{target}`' for target in dict.fromkeys(targets)) or 'any target'}"
    if also and not any(names(first, word) or names(code, word) for word in also):
        return f"{step} names `{hit[0]}` and none of {also}"
    return None


def verifier_name(verifier: dict) -> str | None:
    """The function a `verifier` record names: its `name`, else the function of its symbol."""
    if verifier.get("name"):
        return verifier["name"]
    symbol = verifier.get("symbol", "")
    declared = re.search(r"\bfn\s+([A-Za-z_]\w*)", symbol)
    if declared:
        return declared.group(1)
    called = re.search(r"([A-Za-z_]\w*)\s*\(", symbol)
    return called.group(1) if called else None


# --------------------------------------------------------------------------- scanners


def registry_entries(tree: Tree, registry: dict) -> list[dict]:
    text = tree.read(registry["path"]) or ""
    macros = "|".join(re.escape(name) for name in registry.get("entry_macros", []))
    entries = []
    for match in re.finditer(r"\b(" + macros + r')!\(\s*([\w:]+)\s*=>\s*"([^"]+)"', text):
        type_path = match.group(2)
        for prefix in registry.get("strip_prefixes", []):
            if type_path.startswith(prefix):
                type_path = type_path[len(prefix) :]
        parts = type_path.split("::")
        entries.append(
            {
                "type": type_path,
                "name": parts[-1],
                "module": parts[-2] if len(parts) > 1 else "",
                "wire_id": match.group(3),
            }
        )
    return entries


def module_scope(registry: dict, entry: dict) -> str:
    """`in`, `out` or `unclassed` for one registry entry."""
    module = registry.get("modules", {}).get(entry["module"])
    if module is None:
        return "unclassed"
    scope = module.get("scope")
    if scope == "full":
        return "in"
    if scope == "partial":
        return "in" if re.search(module.get("pattern", "$^"), entry["name"]) else "out"
    return "out"


def handler_impls(tree: Tree, roots: list[str]) -> dict[str, list[dict]]:
    """`impl Execute for T` blocks by the last segment of T."""
    impls: dict[str, list[dict]] = {}
    for path in tree.walk(roots, (".rs",)):
        text = tree.read(path) or ""
        if "impl Execute for" not in text:
            continue
        for match in re.finditer(r"^([ \t]*)impl Execute for ([\w:]+) \{", text, re.M):
            closing = re.compile(r"^" + match.group(1) + r"\}", re.M).search(text, match.end())
            body = text[match.start() : closing.end()] if closing else text[match.start() :]
            impls.setdefault(match.group(2).split("::")[-1], []).append(
                {"path": path, "symbol": "impl Execute for " + match.group(2), "body": body}
            )
    return impls


def tsv_rows(text: str | None) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    header: list[str] | None = None
    for line in (text or "").splitlines():
        if not line or line.startswith("#"):
            continue
        cells = line.split("\t")
        if header is None:
            header = cells
            continue
        row = dict(zip(header, cells))
        rows[row["route_id"]] = row
    return rows


def compiled_catalog(root: Path) -> str | None:
    """Run the std-only route exporter; None when it cannot be built."""
    try:
        with tempfile.TemporaryDirectory(prefix="iroha-zk-operations-") as temporary:
            binary = Path(temporary) / "route-catalog"
            subprocess.run(
                ["rustc", "--edition=2024", "--crate-name", "sdk_operation_inventory",
                 str(root / ROUTE_EXPORTER), "-o", str(binary)],
                cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            return subprocess.run(
                [str(binary)], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout.decode("utf-8")
    except (OSError, subprocess.CalledProcessError):
        return None


def route_in_scope(routes: dict, path: str) -> bool:
    return any(path.startswith(prefix) for prefix in routes.get("path_prefixes", []))


def sdk_files(tree: Tree, family: dict) -> list[str]:
    files = tree.walk(family["roots"], tuple(family["extensions"]))
    excluded = [re.compile(pattern) for pattern in family.get("exclude", [])]
    return [path for path in files if not any(pattern.search(path) for pattern in excluded)]


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def sdk_references(tree: Tree, sdk: dict, names: dict[str, str], wire_ids: dict[str, str], paths: dict[str, list[str]]) -> dict:
    """{subject: {family: [{path, via}]}} for instruction names, wire ids and route path literals.

    A name matches as a whole identifier, a wire id as a quoted string literal, an exact route path
    when no path character follows it and a parameterized route by its literal prefix.
    """
    quoted = re.compile("[\"'`](" + "|".join(sorted(map(re.escape, wire_ids), key=len, reverse=True)) + ")[\"'`]") if wire_ids else None
    exact = sorted((literal for literal in paths if not literal.endswith("/")), key=len, reverse=True)
    exact_pattern = re.compile("(" + "|".join(map(re.escape, exact)) + r")(?![A-Za-z0-9_\-/])") if exact else None
    prefixes = sorted(literal for literal in paths if literal.endswith("/"))
    found: dict[str, dict[str, list[dict]]] = {}

    def add(subject: str, family: str, path: str, via: str) -> None:
        rows = found.setdefault(subject, {}).setdefault(family, [])
        for row in rows:
            if row["path"] == path:
                if via not in row["via"]:
                    row["via"].append(via)
                    row["via"].sort()
                return
        rows.append({"path": path, "via": [via]})

    for family in sdk["families"]:
        for path in sdk_files(tree, family):
            text = tree.read(path) or ""
            for name in names.keys() & set(_IDENTIFIER.findall(text)):
                add(names[name], family["id"], path, "type_name")
            if quoted is not None:
                for wire_id in set(quoted.findall(text)):
                    add(wire_ids[wire_id], family["id"], path, "wire_id")
            if "/v1/" in text or "v1/" in text:
                if exact_pattern is not None:
                    for literal in set(exact_pattern.findall(text)):
                        for subject in paths[literal]:
                            add(subject, family["id"], path, "route_path")
                for literal in prefixes:
                    if literal in text:
                        for subject in paths[literal]:
                            add(subject, family["id"], path, "route_path")
    for families in found.values():
        for rows in families.values():
            rows.sort(key=lambda row: row["path"])
    return found


def route_literal(path: str) -> str | None:
    """The longest parameter-free part of a route path that identifies it in SDK source."""
    parts = [part for part in re.split(r"\{[^}]*\}", path) if len(part.strip("/")) > 0]
    if not parts:
        return None
    best = max(parts, key=len)
    return best if len(best) >= 8 else None


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def snake(name: str) -> str:
    """`camelCase` and `PascalCase` names as `snake_case`, so one pattern reads every SDK language."""
    return _CAMEL.sub("_", name).lower()


def sdk_surface(tree: Tree, sdk: dict) -> list[dict]:
    """Declarations with a family name: [{family, path, product, symbols}].

    Patterns are matched against the snake_case form of a name; the name is recorded as written.
    """
    surface = sdk.get("surface_scan", {})
    keyword = re.compile(surface.get("name_pattern", "$^"))
    rules = [(re.compile(rule["pattern"]), rule["product"]) for rule in surface.get("products", [])]
    out = []
    for family in sdk["families"]:
        declaration = re.compile(family["declaration_pattern"], re.M)
        for path in sdk_files(tree, family):
            text = tree.read(path) or ""
            if path.endswith(".rs"):
                text = production_text(text)
            by_product: dict[str, set[str]] = {}
            for match in declaration.finditer(text):
                name = next((group for group in match.groups() if group), "")
                word = snake(name)
                if not name or not keyword.search(word):
                    continue
                product = next((product for pattern, product in rules if pattern.search(word)), "unclassified")
                by_product.setdefault(product, set()).add(name)
            for product in sorted(by_product):
                out.append({"family": family["id"], "path": path, "product": product, "symbols": sorted(by_product[product])})
    return out


_TEST_GATE = re.compile(r"#\[cfg\((?:all\(\s*)?test\b[^\]]*\]")
_ITEM = re.compile(
    r"\s*(?:#\[[^\]]*\]\s*|//[^\n]*\n\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|const\s+(?=fn\b)|extern\s+\"[^\"]*\"\s+)*"
    r"(?:(?:fn|mod|impl|const|static|use|struct|enum|type|trait)\b|macro_rules!|\w+!)"
)
_RUST_TOKEN = re.compile(
    r'''"(?:\\.|[^"\\])*"|r(#*)".*?"\1|'(?:\\.|[^\\'])'|//[^\n]*|/\*.*?\*/|[{};]''', re.S
)


def rust_item_end(text: str, start: int) -> int:
    """Index after the item starting at `start`: its closing brace or its semicolon.

    Strings, character literals and comments are skipped, so a brace inside one does not count.
    """
    depth = 0
    for token in _RUST_TOKEN.finditer(text, start):
        char = token.group(0)
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth <= 0:
                return token.end()
        elif char == ";" and depth == 0:
            return token.end()
    return len(text)


def production_text(text: str) -> str:
    """`text` without its test-gated items (`#[cfg(test)]` and `#[cfg(all(test, ...))]`).

    A gated module, function, constant or macro call is dropped whole; a gated field or expression
    is dropped to the end of its line.
    """
    if "cfg(" not in text:
        return text
    out, index = [], 0
    while True:
        gate = _TEST_GATE.search(text, index)
        if gate is None:
            out.append(text[index:])
            break
        out.append(text[index : gate.start()])
        if _ITEM.match(text, gate.end()):
            index = rust_item_end(text, gate.end())
        else:
            newline = text.find("\n", text.find("\n", gate.end()) + 1)
            index = newline if newline >= 0 else len(text)
    return "".join(out)


def production_rust(tree: Tree, roots: list[str], exclude: list[str]) -> list[str]:
    patterns = [re.compile(pattern) for pattern in exclude]
    return [path for path in tree.walk(roots, (".rs",)) if not any(pattern.search(path) for pattern in patterns)]


def selector_census(tree: Tree, census: dict) -> list[dict]:
    """[{token, path, count}] for every selector token in the scanned production files."""
    rows = []
    files = production_rust(tree, census["roots"], census.get("exclude", []))
    tokens = [(token["id"], re.compile(token["pattern"])) for token in census["tokens"]]
    for path in files:
        text = production_text(tree.read(path) or "")
        for token, pattern in tokens:
            count = len(pattern.findall(text))
            if count:
                rows.append({"token": token, "path": path, "count": count})
    rows.sort(key=lambda row: (row["token"], row["path"]))
    return rows


def source_inclusion_census(tree: Tree, census: dict) -> list[dict]:
    """[{path, count}] for production files that include Rust source bytes."""
    pattern = re.compile(census["pattern"])
    rows = []
    for path in production_rust(tree, census["roots"], census.get("exclude", [])):
        count = len(pattern.findall(production_text(tree.read(path) or "")))
        if count:
            rows.append({"path": path, "count": count})
    return rows


def digest_census(tree: Tree, digests: dict, group: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    tokens = [(token["id"], re.compile(token["pattern"])) for token in digests["primitive_tokens"]]
    for path in production_rust(tree, group["owner_paths"], digests.get("exclude", [])):
        text = production_text(tree.read(path) or "")
        for token, pattern in tokens:
            count = len(pattern.findall(text))
            if count:
                counts[token] = counts.get(token, 0) + count
    return dict(sorted(counts.items()))


def entry_point_census(tree: Tree, census: dict) -> list[dict]:
    """[{token, path, count}] for every verifier or validator entry point named in production code.

    Comments, literals and test-gated items are not counted. A token whose pattern captures a name
    gives one row per name (`name`); names matching `out_of_scope_names` are left out.
    """
    skipped = [re.compile(item["pattern"]) for item in census.get("out_of_scope_names", [])]
    rows = []
    for token in census.get("tokens", []):
        pattern = re.compile(token["pattern"])
        needle = token.get("needle")
        roots = token.get("roots", census.get("roots", []))
        for path in production_rust(tree, roots, census.get("exclude", [])):
            raw = tree.read(path) or ""
            if needle and needle not in raw:
                continue
            code = code_only(production_text(raw))
            if pattern.groups:
                counts: dict[str, int] = {}
                for name in pattern.findall(code):
                    if not any(skip.search(name) for skip in skipped):
                        counts[name] = counts.get(name, 0) + 1
                rows.extend({"token": token["id"], "name": name, "path": path, "count": count}
                            for name, count in counts.items())
            else:
                count = len(pattern.findall(code))
                if count:
                    rows.append({"token": token["id"], "path": path, "count": count})
    rows.sort(key=lambda row: (row["token"], row.get("name", ""), row["path"]))
    return rows


# --------------------------------------------------------------------------- Exact12 single route

ENVELOPE_IDENTITY_FIELDS = (
    "wire_magic", "catalog_commitment", "protocol_id", "proof_system_id", "engine_id", "parameter_id",
    "parameter_digest", "verifier_digest", "statement_schema_digest", "engine_manifest_digest", "statement_digest",
)
ROLE_VERIFICATION = ("implemented", "refused")
EFFECT_USES = ("ledger_application", "read_only_evidence", "construction")
_NOT_AN_EXPRESSION = re.compile(r"(?:->|\bstruct|\bimpl|\bfor|\benum|\bunion)\s*$")


def drop_gated_items(text: str, gates: list[str]) -> str:
    """`text` without the items that follow an attribute matching one of the `gates` patterns."""
    for pattern in gates:
        gate = re.compile(pattern)
        out, index = [], 0
        while True:
            match = gate.search(text, index)
            if match is None:
                out.append(text[index:])
                break
            out.append(text[index : match.start()])
            if _ITEM.match(text, match.end()):
                index = rust_item_end(text, match.end())
            else:
                newline = text.find("\n", text.find("\n", match.end()) + 1)
                index = newline if newline >= 0 else len(text)
        text = "".join(out)
    return text


_FAMILY_WORD = "rivacy"
_MENTIONS_FAMILY: dict[str, tuple[tuple[float, int], bool]] = {}


def mentions_privacy(tree: Tree, path: str) -> bool:
    """Whether the file's path or text names the privacy family.

    Every Exact12 type, engine module and the owning crate carry the word, so a file without it
    cannot assemble an envelope, call a native verifier or consume an effect. The answer for an
    unchanged file on disk is kept for the process, which keeps repeated checks cheap.
    """
    if _FAMILY_WORD in path:
        return True
    if path in tree.overrides:
        return _FAMILY_WORD in (tree.overrides[path] or "")
    file = tree.root / path
    try:
        status = file.stat()
    except OSError:
        return False
    stamp = (status.st_mtime, status.st_size)
    cached = _MENTIONS_FAMILY.get(str(file))
    if cached is None or cached[0] != stamp:
        cached = (stamp, _FAMILY_WORD in (tree.read(path) or ""))
        _MENTIONS_FAMILY[str(file)] = cached
    return cached[1]


_SCAN_MEMO: dict[tuple, object] = {}


class RouteScan:
    """Production code of the single-route scan: no comments, literals or test-gated items.

    Only files that name the privacy family are read (`mentions_privacy`). What is read from a
    file is kept for the process under the file's content, so a repeated check reads again only
    the files that changed.
    """

    def __init__(self, tree: Tree, scan: dict) -> None:
        self.tree = tree
        self.gates = tuple(scan.get("test_gates", []))
        self.files = [path for path in production_rust(tree, scan.get("roots", []), scan.get("exclude", []))
                      if mentions_privacy(tree, path)]
        self._code: dict[str, str] = {}
        self._keys: dict[str, tuple] = {}

    def key(self, path: str) -> tuple:
        """Identity of the file's content and of the gates it is read under."""
        if path not in self._keys:
            raw = self.tree.read(path) or ""
            self._keys[path] = (len(raw), hash(raw), self.gates)
        return self._keys[path]

    def memo(self, path: str, what: tuple, compute):
        key = (what,) + self.key(path)
        if key not in _SCAN_MEMO:
            _SCAN_MEMO[key] = compute()
        return _SCAN_MEMO[key]

    def code(self, path: str) -> str:
        if path not in self._code:
            raw = self.tree.read(path) or ""
            self._code[path] = self.memo(
                path, ("code",), lambda: code_only(drop_gated_items(production_text(raw), list(self.gates))))
        return self._code[path]

    def holding(self, needle: str) -> list[str]:
        """Scanned files whose raw text has `needle` (a cheap filter before `code`)."""
        return [path for path in self.files
                if self.memo(path, ("holds", needle), lambda: needle in (self.tree.read(path) or ""))]

    def calls(self, name: str) -> dict[str, int]:
        """{path: count} of calls of `name` (its definition is not a call)."""
        pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*(?:::\s*<[^>;{}]*>\s*)?\(")

        def count(path: str) -> int:
            code = self.code(path)
            return sum(1 for match in pattern.finditer(code)
                       if not re.search(r"\bfn\s+$", code[max(0, match.start() - 8) : match.start()]))

        counts: dict[str, int] = {}
        for path in self.holding(name):
            found = self.memo(path, ("calls", name), lambda: count(path))
            if found:
                counts[path] = found
        return counts


def envelope_assemblies(scan: RouteScan, type_name: str) -> list[dict]:
    """[{path, function, kind}] for every production expression that assembles `type_name`.

    `kind` is `literal` for `Type { .. }` and `self_literal` for `Self { .. }` inside an
    inherent `impl Type` block. A return type before a function body is not an expression.
    """
    literal = re.compile(r"(?<![A-Za-z0-9_])(?:[A-Za-z_]\w*\s*::\s*)*" + re.escape(type_name) + r"\s*\{")

    def read(path: str) -> list[tuple[str | None, str]]:
        code = scan.code(path)
        index = rust_index(code)
        found = []
        for match in literal.finditer(code):
            if not _NOT_AN_EXPRESSION.search(code[max(0, match.start() - 16) : match.start()]):
                found.append((index.enclosing(match.start())[0], "literal"))
        for block in index.impls:
            if block["type"] != type_name or block["trait"]:
                continue
            start, end = block["span"]
            for match in re.finditer(r"\bSelf\s*\{", code[start:end]):
                position = start + match.start()
                if not _NOT_AN_EXPRESSION.search(code[max(0, position - 16) : position]):
                    found.append((index.enclosing(position)[0], "self_literal"))
        return found

    rows = []
    for path in scan.holding(type_name):
        for function, kind in scan.memo(path, ("assemblies", type_name), lambda: read(path)):
            rows.append({"path": path, "function": function, "kind": kind})
    return rows


_IDENTITY_ASSIGNMENT = re.compile(r"\benvelope\s*\.\s*(?:" + "|".join(ENVELOPE_IDENTITY_FIELDS) + r")\s*=(?!=)")


def envelope_field_assignments(scan: RouteScan) -> dict[str, int]:
    """{path: count} of production assignments to an identity field of a value named `envelope`."""
    counts: dict[str, int] = {}
    for path in scan.holding("envelope"):
        count = scan.memo(
            path, ("identity_assignments",),
            lambda: len(_IDENTITY_ASSIGNMENT.findall(scan.code(path)))
            if _IDENTITY_ASSIGNMENT.search(scan.tree.read(path) or "") else 0,
        )
        if count:
            counts[path] = count
    return counts


def struct_fields_of_types(code: str, types: list[str]) -> list[tuple[str, str, str]]:
    """[(struct, field, type)] for every named struct field whose type is one of `types`."""
    found = []
    wanted = "|".join(re.escape(name) for name in types)
    for match in re.finditer(r"\bstruct\s+([A-Za-z_]\w*)[^;{(]*\{", code):
        end = balanced(code, match.end() - 1)
        if end is None:
            continue
        body = strip_attributes(code[match.end() : end - 1])
        for field in split_top_level(body):
            declared = re.match(r"(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*(.*)$", field, re.S)
            if declared and re.search(r"(?<![A-Za-z0-9_])(?:" + wanted + r")(?![A-Za-z0-9_])", declared.group(2)):
                hit = re.search(wanted, declared.group(2))
                found.append((match.group(1), declared.group(1), hit.group(0)))
    return found


def registry_rows(text: str, table: str) -> list[dict] | None:
    """Rows of the typed dispatch table: [{role, verification, limitation, effect_class}]."""
    start = re.search(r"\bconst\s+" + re.escape(table) + r"\b[^=]*=\s*\[", text)
    if start is None:
        return None
    end = balanced(text, start.end() - 1, "[", "]")
    if end is None:
        return None
    rows = []
    body = strip_comments(text[start.end() : end - 1])
    for call in re.finditer(r"\brow\s*\(", body):
        close = balanced(body, call.end() - 1, "(", ")")
        if close is None:
            return None
        arguments = split_top_level(body[call.end() : close - 1])
        if len(arguments) != 3:
            return None
        role, verification, effect_class = (" ".join(argument.split()) for argument in arguments)
        limitation = re.fullmatch(r"unsupported\(\s*PrivacyRoleLimitationV1::(\w+)\s*\)", verification)
        rows.append({
            "role": role.split("::")[-1],
            "verification": "implemented" if verification == "IMPLEMENTED" else "refused" if limitation else None,
            "limitation": limitation.group(1) if limitation else None,
            "effect_class": effect_class.split("::")[-1],
        })
    return rows


def driver_operations(text: str, table: str) -> list[dict] | None:
    """Rows of the action driver's operation table: [{name, role}] with constants resolved."""
    start = re.search(r"\bconst\s+" + re.escape(table) + r"\b[^=]*=\s*\[", text)
    if start is None:
        return None
    end = balanced(text, start.end() - 1, "[", "]")
    if end is None:
        return None
    constants = dict(re.findall(r'\bconst\s+(\w+)\s*:\s*&str\s*=\s*"([^"]*)"\s*;', text))
    rows = []
    for operation, role in re.findall(
        r"operation\s*:\s*(\w+)\s*,\s*role\s*:\s*PrivacyActionRoleV1::(\w+)", strip_comments(text[start.end() : end - 1])
    ):
        rows.append({"name": constants.get(operation), "role": role})
    return rows


_KEYWORDS = frozenset({"if", "while", "match", "return", "for", "in", "loop", "let", "else", "move", "as", "fn"})


def argument_callees(code: str, words: tuple[str, ...]) -> set[str]:
    """Functions and methods that receive one of `words` as an argument, in code-only text.

    For each use of a word the enclosing parentheses are walked outwards: a constructor or path
    in `CamelCase` and a macro are passed through, a statement boundary ends the walk. A parameter
    declaration (`word: Type`) and a `let word` binding are not uses.
    """
    found: set[str] = set()
    if not words:
        return found
    pattern = re.compile(r"(?<![A-Za-z0-9_.])(?:" + "|".join(re.escape(word) for word in words) + r")(?![A-Za-z0-9_])")
    for match in pattern.finditer(code):
        after = code[match.end() : match.end() + 3]
        if re.match(r"\s*:(?!:)", after) or re.search(r"\blet\s+(?:mut\s+)?$", code[max(0, match.start() - 16) : match.start()]):
            continue
        index = match.start() - 1
        closed = braces = 0
        while index >= 0:
            char = code[index]
            if char == "}":
                braces += 1
            elif char == "{":
                if braces == 0:
                    break
                braces -= 1
            elif braces:
                pass
            elif char in ")]":
                closed += 1
            elif char == "[":
                closed = max(0, closed - 1)
            elif char == "(":
                if closed:
                    closed -= 1
                else:
                    head = re.search(r"([A-Za-z_]\w*)\s*(?:::\s*<[^<>]*>\s*)?$", code[max(0, index - 96) : index])
                    name = head.group(1) if head else None
                    if name in _KEYWORDS:
                        break
                    if name and not name[0].isupper():
                        found.add(name)
                        break
            elif char == ";":
                break
            index -= 1
    return found


def authority_tokens(code: str, raw: str, registry: dict) -> set[str]:
    """Authority checks of handler code: listed check names and permission tokens (also inside string
    literals of `raw`), comparisons with the authority and every function that receives the authority
    and is not a recorded pass-through."""
    found = set(re.findall(registry.get("authority_token_pattern", "$^"), strip_comments(raw)))
    comparison = re.compile(registry.get("authority_comparison_pattern", "$^"))
    found |= {squash(match.group(0)) for match in comparison.finditer(code)}
    passthrough = {item["symbol"] for item in registry.get("authority_passthrough", [])}
    found |= argument_callees(code, tuple(registry.get("authority_words", []))) - passthrough
    return found


def handler_scope(tree: Tree, block: dict, name: str, depth: int = 0, raw: bool = False) -> str:
    """Code of a handler: its `impl Execute` block and the other trait impls of the type in that file.

    With `depth`, what that code calls in the file is included that many levels deep. With `raw`,
    comments and literals are kept.
    """
    text = tree.read(block["path"]) or ""
    index = rust_index(text)
    spans = [item["span"] for item in index.impls if item["type"] == name]
    if not spans:
        return block["body"] if raw else code_only(block["body"])
    return index.closure(spans, depth=depth, raw=raw)


def macro_handler_files(tree: Tree, roots: list[str]) -> list[str]:
    """Files whose `impl Execute` is written for a macro variable; their handlers have no literal type."""
    return [path for path in tree.walk(roots, (".rs",)) if re.search(r"impl Execute for \$", tree.read(path) or "")]


def syscall_constants(text: str) -> dict[str, int]:
    return {
        match.group(1): int(match.group(2), 16)
        for match in re.finditer(r"pub const SYSCALL_([A-Z0-9_]+): u32 = 0x([0-9A-Fa-f]+);", text)
    }


def instruction_tags(text: str) -> dict[str, int]:
    return {
        match.group(1): int(match.group(2))
        for match in re.finditer(r"pub const SMARTCONTRACT_INSTRUCTION_TAG_([A-Z0-9_]+): u64 = (\d+);", text)
    }


def builtin_syscalls(text: str) -> dict[str, list[str]]:
    """{syscall: [builtin, ...]} from the `Self::X | Self::Y => &[s::SYSCALL_Z, ...]` arms."""
    out: dict[str, list[str]] = {}
    for match in re.finditer(r"((?:Self::\w+\s*\|?\s*)+)=>\s*\{?\s*&\[([^\]]*)\]", strip_comments(text)):
        builtins = re.findall(r"Self::(\w+)", match.group(1))
        for syscall in re.findall(r"SYSCALL_([A-Z0-9_]+)", match.group(2)):
            out.setdefault(syscall, []).extend(builtins)
    return {syscall: sorted(set(builtins)) for syscall, builtins in out.items()}


# --------------------------------------------------------------------------- generic walks


def walk(node, trail=""):
    """Yield (trail, dict) for every dict in a JSON value."""
    if isinstance(node, dict):
        yield trail, node
        for key, value in node.items():
            yield from walk(value, f"{trail}.{key}" if trail else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            label = value.get("id", index) if isinstance(value, dict) else index
            yield from walk(value, f"{trail}[{label}]")


def resolve_key(document, key: str) -> bool:
    """`section/id/...`: dict keys, or list items by `id`, `key`, `name`, `variant` or `symbol`."""
    node = document
    for part in key.split("/"):
        if isinstance(node, dict):
            if part not in node:
                return False
            node = node[part]
        elif isinstance(node, list):
            hit = None
            for item in node:
                if isinstance(item, dict) and part in (
                    item.get("id"), item.get("key"), item.get("name"), item.get("variant"), item.get("symbol")
                ):
                    hit = item
                    break
                if item == part:
                    hit = item
                    break
            if hit is None:
                return False
            node = hit
        else:
            return False
    return True


# --------------------------------------------------------------------------- the check


class Checker:
    def __init__(self, inventory: dict, tree: Tree | None = None, catalog: str | None = None) -> None:
        self.inv = inventory
        self.tree = tree or Tree()
        self.catalog = catalog
        self.errors: list[str] = []
        self.notes: list[str] = []
        self._json: dict[str, object] = {}
        self._production: dict[str, str] = {}
        self._gates: dict[str, str | None] = {}

    def error(self, message: str) -> None:
        self.errors.append(message)

    def json_file(self, path: str):
        if path not in self._json:
            text = self.tree.read(path)
            try:
                self._json[path] = json.loads(text) if text is not None else None
            except json.JSONDecodeError:
                self._json[path] = None
        return self._json[path]

    def production(self, path: str) -> str:
        """The file's text without test-gated items (cached)."""
        if path not in self._production:
            self._production[path] = production_text(self.tree.read(path) or "")
        return self._production[path]

    def gate(self, path: str) -> str | None:
        """The non-default feature gating the module of `path` (cached)."""
        if path not in self._gates:
            self._gates[path] = feature_gate(self.tree, path)
        return self._gates[path]

    def tasks(self) -> dict[str, dict]:
        graph = self.json_file(GRAPH) or {}
        return {task["id"]: task for task in graph.get("tasks", []) if isinstance(task, dict) and "id" in task}

    # ---- header

    def check_header(self) -> None:
        inv = self.inv
        if inv.get("schema") != SCHEMA:
            self.error(f"schema must be {SCHEMA}")
        if inv.get("task") != TASK:
            self.error(f"task must be {TASK}")
        for key in ("what", "not_a_readiness_claim", "consumed_by", "status_vocabulary", "products", "operations",
                    "registry", "exact12", "generic_relations", "ram_lfe", "soracloud", "executables", "syscalls",
                    "routes", "admission_routes", "digests", "guarantee_selection", "sdk", "requirements",
                    "requirement_mapping", "relations", "inventories"):
            if key not in inv:
                self.error(f"missing section `{key}`")
        tasks = self.tasks()
        task = tasks.get(TASK)
        if task is None:
            self.error(f"{GRAPH} has no task {TASK}")
        else:
            dependents = sorted(other["id"] for other in tasks.values() if TASK in other.get("requires", []))
            if sorted(inv.get("consumed_by", [])) != dependents:
                self.error(f"consumed_by must be the graph's dependents of {TASK}: {dependents}")

    # ---- anchors, tests, references

    def check_anchors(self) -> None:
        tasks = self.tasks()
        inventories = self.inv.get("inventories", {})
        route_ids = {route["id"] for route in self.inv.get("routes", {}).get("list", [])}
        operation_ids = {operation["id"] for operation in self.inv.get("operations", [])}
        relation_ids = {relation["id"] for relation in self.inv.get("relations", [])}
        for trail, node in walk(self.inv):
            if "path" in node and "symbol" in node and isinstance(node["symbol"], str) and "test" not in node:
                text = self.tree.read(node["path"])
                if text is None:
                    self.error(f"{trail}: {node['path']} is missing")
                elif not contains(text, node["symbol"]):
                    self.error(f"{trail}: `{node['symbol']}` is not in {node['path']}")
                elif node["path"].endswith(".rs") and ".reaches[" not in trail \
                        and not contains(self.production(node["path"]), node["symbol"]):
                    self.error(f"{trail}: `{node['symbol']}` is only in test code of {node['path']}")
            if "path" in node and "test" in node:
                reason = has_test(self.tree, node["path"], node["test"])
                gate = self.gate(node["path"])
                if gate != node.get("feature"):
                    if gate is not None:
                        self.error(
                            f"{trail}: test {node['test']} is compiled only with feature `{gate}`; "
                            f'record "feature": "{gate}"'
                        )
                    else:
                        self.error(
                            f"{trail}: test {node['test']} is recorded under feature `{node.get('feature')}`, "
                            f"which does not gate its module"
                        )
                if node.get("ignored"):
                    if reason is None:
                        self.error(f"{trail}: test {node['test']} is recorded as #[ignore]d and is not")
                    elif not reason.endswith("is #[ignore]d"):
                        self.error(f"{trail}: {reason}")
                elif reason:
                    self.error(f"{trail}: {reason}")
            if "inventory" in node and "key" in node:
                path = inventories.get(node["inventory"], {}).get("path")
                if path is None:
                    self.error(f"{trail}: inventory `{node['inventory']}` is not declared")
                    continue
                document = self.json_file(path)
                if document is None:
                    if inventories[node["inventory"]].get("optional_until"):
                        self.notes.append(
                            f"{trail}: {path} is not in the tree yet (owned by "
                            f"{inventories[node['inventory']]['optional_until']}); key `{node['key']}` unchecked"
                        )
                    else:
                        self.error(f"{trail}: {path} is missing or not JSON")
                elif not resolve_key(document, node["key"]):
                    self.error(f"{trail}: key `{node['key']}` does not resolve in {path}")
            for key in ("owner_tasks", "tasks"):
                for task in node.get(key, []) if isinstance(node.get(key), list) else []:
                    if task not in tasks:
                        self.error(f"{trail}: task {task} is not in {GRAPH}")
            if isinstance(node.get("owner_task"), str) and node["owner_task"] not in tasks:
                self.error(f"{trail}: task {node['owner_task']} is not in {GRAPH}")
            for route in node.get("routes", []) if isinstance(node.get("routes"), list) and trail != "routes" else []:
                if isinstance(route, str) and route not in route_ids:
                    self.error(f"{trail}: route {route} is not a listed route")
            for operation in node.get("operations", []) if isinstance(node.get("operations"), list) and trail else []:
                if isinstance(operation, str) and operation not in operation_ids:
                    self.error(f"{trail}: operation {operation} is not a listed operation")
            for operation in node.get("consumers", []) if isinstance(node.get("consumers"), list) else []:
                if operation not in operation_ids:
                    self.error(f"{trail}: consumer {operation} is not a listed operation")
            if isinstance(node.get("operation"), str) and node["operation"] not in operation_ids:
                self.error(f"{trail}: operation {node['operation']} is not a listed operation")
            if isinstance(node.get("relation"), str) and node["relation"] not in relation_ids:
                self.error(f"{trail}: relation {node['relation']} is not a listed relation")
        for name, entry in inventories.items():
            if not entry.get("optional_until") and self.tree.read(entry["path"]) is None:
                self.error(f"inventories.{name}: {entry['path']} is missing")

    # ---- registry and operations

    def check_registry(self) -> None:
        registry = self.inv.get("registry", {})
        entries = registry_entries(self.tree, registry)
        if not entries:
            self.error(f"registry: no instruction entry read from {registry.get('path')}")
            return
        by_type = {entry["type"]: entry for entry in entries}
        modules = registry.get("modules", {})
        seen_modules = {entry["module"] for entry in entries}
        for module in sorted(seen_modules - set(modules)):
            names = sorted(entry["name"] for entry in entries if entry["module"] == module)
            self.error(f"registry: module `{module}` ({', '.join(names[:4])}...) is not classed in registry.modules")
        for module in sorted(set(modules) - seen_modules):
            self.error(f"registry: module `{module}` is classed but the registry has no instruction in it")
        for module, record in modules.items():
            if record.get("scope") not in ("full", "partial", "out"):
                self.error(f"registry.modules.{module}: scope must be full, partial or out")
            if not record.get("reason"):
                self.error(f"registry.modules.{module}: reason is required")
            if record.get("scope") == "partial" and not record.get("pattern"):
                self.error(f"registry.modules.{module}: a partial module needs a pattern")
        operations = {op["isi"]["type"]: op for op in self.inv.get("operations", []) if op.get("isi")}
        in_scope = {entry["type"] for entry in entries if module_scope(registry, entry) == "in"}
        for type_path in sorted(in_scope - set(operations)):
            self.error(
                f"registry: {type_path} (`{by_type[type_path]['wire_id']}`) is in a listed family and is not an operation"
            )
        for type_path in sorted(set(operations) - set(by_type)):
            self.error(f"operations[{operations[type_path]['id']}]: {type_path} is not in the instruction registry")
        for type_path in sorted(set(operations) & set(by_type) - in_scope):
            self.error(f"operations[{operations[type_path]['id']}]: {type_path} is outside the classed families")
        tripwire = registry.get("tripwire", {})
        name_pattern = re.compile(tripwire.get("name_pattern", "$^"))
        excluded_names = {item["type"]: item for item in tripwire.get("name_exclusions", [])}
        for entry in entries:
            if entry["type"] in in_scope:
                continue
            if name_pattern.search(entry["name"]) and entry["type"] not in excluded_names:
                self.error(
                    f"registry: {entry['type']} has a family name and is neither an operation nor excluded "
                    "in registry.tripwire.name_exclusions"
                )
        for type_path, item in excluded_names.items():
            if type_path not in by_type:
                self.error(f"registry.tripwire.name_exclusions: {type_path} is not in the registry")
            elif type_path in in_scope or not name_pattern.search(by_type[type_path]["name"]):
                self.error(f"registry.tripwire.name_exclusions: {type_path} needs no exclusion")
            if not item.get("reason"):
                self.error(f"registry.tripwire.name_exclusions: {type_path} needs a reason")
        impls = handler_impls(self.tree, tripwire.get("handler_roots", []))
        call_pattern = re.compile(tripwire.get("handler_call_pattern", "$^"))
        excluded_calls = {item["type"]: item for item in tripwire.get("handler_exclusions", [])}
        by_name = {entry["name"]: entry for entry in entries}
        calling: dict[str, set[str]] = {}
        helper_depth = tripwire.get("helper_depth", 0)
        for name, blocks in impls.items():
            if name not in by_name:
                continue
            for block in blocks:
                calls = set(call_pattern.findall(handler_scope(self.tree, block, name, helper_depth)))
                if calls:
                    calling.setdefault(by_name[name]["type"], set()).update(calls)
        macros = {item.get("path"): item for item in tripwire.get("macro_generated", [])}
        generated = macro_handler_files(self.tree, tripwire.get("handler_roots", []))
        for path in generated:
            calls = sorted(set(call_pattern.findall(code_only(self.production(path)))))
            item = macros.get(path)
            if item is None:
                self.error(
                    f"registry.tripwire.macro_generated: {path} writes `impl Execute` for a macro variable; its "
                    f"handlers have no literal type, so list the file with its verifier calls {calls}"
                )
            elif sorted(item.get("calls", [])) != calls:
                self.error(f"registry.tripwire.macro_generated: {path} calls {calls}, recorded {sorted(item.get('calls', []))}")
        for path, item in macros.items():
            if path not in generated:
                self.error(f"registry.tripwire.macro_generated: {path} no longer generates handlers by macro")
            if not item.get("reason"):
                self.error(f"registry.tripwire.macro_generated: {path} needs a reason")
        for type_path, calls in sorted(calling.items()):
            if type_path in in_scope:
                continue
            excluded = excluded_calls.get(type_path)
            if excluded is None:
                self.error(
                    f"registry: the handler of {type_path} calls {', '.join(sorted(calls))} and the instruction is "
                    "neither an operation nor excluded in registry.tripwire.handler_exclusions"
                )
            elif sorted(excluded.get("calls", [])) != sorted(calls):
                self.error(
                    f"registry.tripwire.handler_exclusions: {type_path} calls {sorted(calls)}, recorded "
                    f"{sorted(excluded.get('calls', []))}"
                )
        for type_path, item in excluded_calls.items():
            if type_path not in calling or type_path in in_scope:
                self.error(f"registry.tripwire.handler_exclusions: {type_path} needs no exclusion")
            if not item.get("reason"):
                self.error(f"registry.tripwire.handler_exclusions: {type_path} needs a reason")
        self.check_operations(by_type, impls)

    def check_operations(self, by_type: dict[str, dict], impls: dict[str, list[dict]]) -> None:
        operations = self.inv.get("operations", [])
        products = {product["id"] for product in self.inv.get("products", [])}
        ids = [operation.get("id") for operation in operations]
        for identifier in sorted({identifier for identifier in ids if ids.count(identifier) > 1}):
            self.error(f"operations: id {identifier} is listed more than once")
        registry = self.inv.get("registry", {})
        passthrough = {item.get("symbol") for item in registry.get("authority_passthrough", [])}
        for item in registry.get("authority_passthrough", []):
            if not item.get("what"):
                self.error(f"registry.authority_passthrough[{item.get('symbol')}]: `what` must say why it is not a check")
        received: set[str] = set()
        tripwire = registry.get("tripwire", {})
        verifier_calls = re.compile(tripwire.get("handler_call_pattern", "$^"))
        helper_depth = tripwire.get("helper_depth", 0)
        absent_patterns = []
        for operation in operations:
            label = f"operations[{operation.get('id')}]"
            if operation.get("product") not in products:
                self.error(f"{label}: product `{operation.get('product')}` is not a listed product")
            if operation.get("role") not in ROLES:
                self.error(f"{label}: role must be one of {ROLES}")
            if not operation.get("owner_tasks"):
                self.error(f"{label}: owner_tasks is required")
            isi = operation.get("isi")
            if isi:
                entry = by_type.get(isi.get("type"))
                if entry is None:
                    continue
                if isi.get("wire_id") != entry["wire_id"]:
                    self.error(f"{label}: wire id is `{entry['wire_id']}` in the registry, recorded `{isi.get('wire_id')}`")
                if not isinstance(isi.get("defined_in"), dict):
                    self.error(f"{label}: isi.defined_in is required")
                handler = operation.get("handler")
                blocks = impls.get(entry["name"], [])
                if not isinstance(handler, dict):
                    self.error(f"{label}: handler is required for a registered instruction")
                    continue
                block = next((block for block in blocks if block["path"] == handler.get("path")), None)
                if block is None:
                    self.error(f"{label}: no `impl Execute for ...{entry['name']}` in {handler.get('path')}")
                    continue
                if squash(block["symbol"]) != squash(handler.get("symbol", "")):
                    self.error(f"{label}: handler symbol is `{block['symbol']}`, recorded `{handler.get('symbol')}`")
                execution = self.operation_execution_entry(label, operation)
                if operation.get("invocation"):
                    raw_scope = anchor_item_text(self.tree, execution) or ""
                    scope = code_only(raw_scope)
                else:
                    scope = handler_scope(self.tree, block, entry["name"])
                    raw_scope = handler_scope(self.tree, block, entry["name"], raw=True)
                received |= argument_callees(scope, tuple(registry.get("authority_words", [])))
                found = authority_tokens(scope, raw_scope, registry)
                listed = {check["symbol"] for check in operation.get("authority", []) if check.get("scope", "handler") == "handler"}
                for token in sorted(found - listed):
                    self.error(
                        f"{label}: the handler contains the authority check `{token}`, which is not listed "
                        "(a function that receives the authority and decides nothing goes in registry.authority_passthrough)"
                    )
                for token in sorted(listed - found):
                    self.error(f"{label}: authority check `{token}` is not in the handler body")
                for check in operation.get("authority", []):
                    if check.get("scope", "handler") not in ("handler", "file"):
                        self.error(f"{label}: authority scope must be handler or file")
                    if check.get("scope") == "file" and not check.get("what"):
                        self.error(f"{label}: authority check `{check.get('symbol')}` outside the handler needs `what`")
                if not operation.get("authority") and not operation.get("authority_note"):
                    self.error(f"{label}: an operation with no authority check needs authority_note")
                calls = sorted(set(verifier_calls.findall(
                    scope if operation.get("invocation") else handler_scope(self.tree, block, entry["name"], helper_depth)
                )))
                if calls and operation.get("status", {}).get("verification") in ("not_applicable", "absent") \
                        and not operation.get("verifier_calls_note"):
                    self.error(
                        f"{label}: the handler calls {', '.join(calls)} and verification is recorded as "
                        f"`{operation['status']['verification']}`; record the relation, or say in verifier_calls_note why this is no proof verification"
                    )
            else:
                carrier = operation.get("carrier", {})
                if carrier.get("kind") not in CARRIERS:
                    self.error(f"{label}: an operation without an instruction needs carrier.kind in {CARRIERS}")
                if carrier.get("kind") == "absent":
                    if not carrier.get("registry_pattern"):
                        self.error(f"{label}: an absent operation needs carrier.registry_pattern")
                    else:
                        absent_patterns.append((label, re.compile(carrier["registry_pattern"])))
                elif not carrier.get("evidence"):
                    self.error(f"{label}: carrier.evidence is required")
            targets, also, stop = self.operation_targets(label, operation)
            self.check_status(label, operation, targets, also, stop)
        for symbol in sorted(passthrough - received):
            self.error(f"registry.authority_passthrough[{symbol}]: no listed handler passes the authority to it")
        for label, pattern in absent_patterns:
            for entry in by_type.values():
                if pattern.search(entry["name"]):
                    self.error(
                        f"{label}: recorded as absent, but the registry now has {entry['type']}; list it as an operation"
                    )

    def operation_execution_entry(self, label: str, operation: dict) -> dict:
        """Check an original-invocation entry while retaining its detached registry refusal.

        This source inventory checks explicit linkage and exact refusal/context anchors;
        Rust typing and runtime custody tests establish the invocation's authority.
        """
        handler = operation.get("handler", {})
        invocation = operation.get("invocation")
        if invocation is None:
            return handler
        if not isinstance(invocation, dict) or not handler:
            self.error(f"{label}: invocation requires a registered handler and an entry record")
            return handler
        entry, dispatch = invocation.get("entry", {}), invocation.get("dispatch", {})
        entry_names = anchor_names(self.tree, entry)
        entry_code = anchor_item_text(self.tree, entry, signature=True)
        dispatch_code = anchor_item_text(self.tree, dispatch)
        if not entry_names or entry_code is None or dispatch_code is None:
            self.error(f"{label}: invocation entry and dispatch must name existing functions")
            return handler
        entry_code, dispatch_code = code_only(entry_code), code_only(dispatch_code)
        instruction = operation.get("isi", {}).get("type", "").rsplit("::", 1)[-1]
        if not instruction or not names(dispatch_code, instruction) or not names(dispatch_code, entry_names[0]):
            self.error(f"{label}: invocation dispatch must name the exact instruction and entry")
        for field, code in (("dispatch_guard", dispatch_code), ("context_parameter", entry_code)):
            expected = invocation.get(field)
            if not isinstance(expected, str) or not expected or squash(expected) not in squash(code):
                self.error(f"{label}: invocation {field} is absent from its function")
        text = self.tree.read(handler.get("path", "")) or ""
        block = block_after(text, re.escape(handler.get("symbol", "")))
        detached = fn_body(block or "", "execute")
        refusal = invocation.get("detached_body")
        refusal_code = code_only(refusal).strip() if isinstance(refusal, str) else ""
        error_call = re.match(r"Err\s*\(", refusal_code)
        if not error_call or balanced(refusal_code, error_call.end() - 1, "(", ")") != len(refusal_code) \
                or re.search(r"\breturn\b", refusal_code):
            self.error(f"{label}: invocation detached_body must be one unconditional Err expression")
        if not isinstance(refusal, str) or not refusal or detached is None \
                or squash(strip_comments(detached)) != squash(refusal):
            self.error(f"{label}: detached handler must retain its exact unconditional refusal")
        return entry

    def dispatch_entries(self) -> list[str]:
        """Functions through which every protocol of the closed list is dispatched."""
        dispatch = self.inv.get("exact12", {}).get("dispatch", {})
        entry = verifier_name(dispatch.get("entry") or {})
        return [name for name in (dispatch.get("function"), entry) if name]

    def check_constructed_profile(self, label: str, row: dict, profiles: dict) -> None:
        """A `constructed` compiled profile is asserted by the section's cited default test."""
        test = profiles.get("constructed_test")
        if not isinstance(test, dict) or not runs_by_default(test):
            self.error(f"{label}: exact12.compiled_profiles.constructed_test must cite a test that runs by default")
            return
        reason = reach(self.tree, test, [profiles.get("function", "")], also=[row.get("variant", "")])
        if reason is not None:
            self.error(f"{label}: compiled_profile.state is `constructed`, but {reason}")

    def operation_targets(self, label: str, operation: dict) -> tuple[list[str], dict | None, frozenset]:
        """(names a cited test must reach, protocol alternative, names not followed) for an operation.

        The targets are the operation's own `verifier` when it records one (the function its handler
        calls, where that is not the relation's), else the verifier of each relation it names; and,
        once the recorded `verifier_path` from the handler to that verifier holds, every function on
        that path.
        """
        verification = operation.get("status", {}).get("verification")
        if verification not in TESTED:
            return [], None, frozenset()
        relations = {item["id"]: item for item in self.inv.get("relations", [])}
        entries = self.dispatch_entries()
        targets: list[str] = []
        also = None
        stop: frozenset = frozenset()
        names_ = [operation["relation"]] if isinstance(operation.get("relation"), str) else list(operation.get("relations", []))
        own = operation.get("verifier")
        if isinstance(own, dict) and verifier_name(own):
            targets.append(verifier_name(own))
            names_ = []
        for name in names_:
            verifier = relations.get(name, {}).get("verifier")
            if verifier and verifier_name(verifier):
                targets.append(verifier_name(verifier))
        reference = operation.get("relation_ref", "")
        if own:
            pass
        elif reference == "exact12":
            targets.extend(entries)
        elif reference.startswith("exact12/protocols/"):
            variant = reference.rsplit("/", 1)[-1]
            row = next((row for row in self.inv.get("exact12", {}).get("protocols", []) if row.get("variant") == variant), None)
            if row is not None and verifier_name(row.get("verifier", {})):
                targets.append(verifier_name(row["verifier"]))
                also = {"entries": entries, "words": [variant]}
                stop = frozenset(entries)
        if not targets:
            return [], None, frozenset()
        path_targets = list(targets) + (list(also["entries"]) if also else [])
        return targets + self.check_verifier_path(label, operation, path_targets), also, stop

    def check_verifier_path(self, label: str, operation: dict, targets: list[str]) -> list[str]:
        """Names of the `verifier_path` links, each shown to name the next and the last a target."""
        handler = self.operation_execution_entry(label, operation) if isinstance(operation.get("handler"), dict) else None
        links = operation.get("verifier_path")
        if links is None:
            links = [handler] if handler else []
        if not links:
            self.error(f"{label}: an operation without an instruction handler needs verifier_path (entry point to verifier)")
            return []
        if handler and (links[0].get("path"), squash(links[0].get("symbol", ""))) != (handler["path"], squash(handler["symbol"])):
            self.error(f"{label}: verifier_path starts at the handler")
        found: list[str] = []
        for position, link in enumerate(links):
            link_names = anchor_names(self.tree, link)
            code = anchor_closure(self.tree, link)
            if code is None or not link_names:
                self.error(f"{label}: verifier_path link `{link.get('symbol')}` is not a function or impl of {link.get('path')}")
                return found
            following = anchor_names(self.tree, links[position + 1]) if position + 1 < len(links) else targets
            if not any(names(code, name) for name in following):
                self.error(
                    f"{label}: verifier_path: `{link_names[0]}` does not name "
                    f"{' or '.join(f'`{name}`' for name in following) or 'the next link'}; the operation does not reach its verifier this way"
                )
                return found
            found.extend(link_names)
        return found

    def check_evidence(self, label: str, record: dict, verification: str | None, targets: list[str],
                       also: dict | None = None, stop: frozenset = frozenset(), key: str = "tests",
                       required: bool = True) -> None:
        """Every cited test reaches a target or says what it covers; `test_evidence` is what was found.

        A test with `covers` is never counted. With the record's `test_words`, a reaching test also
        names one of them. `also` gives a second way to reach: one of its `entries` together with
        one of its `words` (a shared dispatcher or backend verifier plus what selects this row).
        """
        if verification not in TESTED:
            if "test_evidence" in record:
                self.error(f"{label}: test_evidence belongs to a status in {TESTED}")
            return
        if not targets:
            self.error(f"{label}: needs a function (verifier or site) its cited tests can be checked against")
            return
        default = other = False
        words = record.get("test_words")
        for test in record.get(key, []):
            if test.get("covers"):
                continue
            reason = reach(self.tree, test, targets, stop, also=words)
            if reason is not None and also:
                if reach(self.tree, test, also["entries"], stop, also=also["words"]) is None:
                    reason = None
            if reason is not None:
                self.error(
                    f"{label}: {reason}, so it is no evidence for `{targets[0]}`; cite a test that calls it, "
                    "give the test's `reaches` path, or say what it `covers`"
                )
                continue
            if runs_by_default(test):
                default = True
            else:
                other = True
        if not required:
            return
        observed = "default" if default else "not_default" if other else "none"
        if record.get("test_evidence") != observed:
            self.error(
                f"{label}: test_evidence is `{observed}` (a cited test that runs by default reaches `{targets[0]}`: "
                f"{'yes' if default else 'no'}), recorded `{record.get('test_evidence')}`"
            )
        if observed != "default" and not record.get("test_note"):
            self.error(f"{label}: test_evidence `{observed}` needs test_note saying what does and does not run by default")

    def check_status(self, label: str, record: dict, targets: list[str] | None = None,
                     also: dict | None = None, stop: frozenset = frozenset()) -> None:
        status = record.get("status")
        if not isinstance(status, dict):
            self.error(f"{label}: status is required")
            return
        for key, allowed in (("presence", PRESENCE), ("verification", VERIFICATION),
                             ("state_effects", STATE_EFFECTS), ("delivery", DELIVERY)):
            if status.get(key) not in allowed:
                self.error(f"{label}: status.{key} must be one of {allowed}")
        expected_presence = "registered" if record.get("isi") else (
            "absent" if record.get("carrier", {}).get("kind") == "absent" else "carrier"
        )
        if "isi" in record or "carrier" in record:
            if status.get("presence") != expected_presence:
                self.error(f"{label}: status.presence must be `{expected_presence}`")
        relation = record.get("relation")
        relations = {item["id"]: item for item in self.inv.get("relations", [])}
        verification = status.get("verification")
        if verification in ("implemented", "binding_only", "signature_only", "refused"):
            if relation is None and not record.get("relations") and not record.get("relation_ref"):
                self.error(f"{label}: verification `{verification}` needs a relation")
        if record.get("relation_ref") and not resolve_key(self.inv, record["relation_ref"]):
            self.error(f"{label}: relation_ref `{record['relation_ref']}` does not resolve in this inventory")
        for name in list(record.get("relations", [])) + list(record.get("also_admits", [])):
            if name not in relations:
                self.error(f"{label}: relation {name} is not a listed relation")
        if verification == "refused" and not record.get("refusal"):
            self.error(f"{label}: verification `refused` needs the refusal (path and symbol)")
        if verification == "implemented":
            names = [relation] if isinstance(relation, str) else list(record.get("relations", []))
            for name in names:
                item = relations.get(name)
                if item is not None and item.get("status") != "implemented":
                    self.error(f"{label}: verification is `implemented`, but relation {name} is `{item.get('status')}`")
        self.check_evidence(label, record, verification, targets or [], also, stop)
        if verification == "not_applicable" and record.get("role") in ("proof_effect", "proof_verification"):
            self.error(f"{label}: a proof operation cannot have verification `not_applicable`")
        if status.get("delivery") != "not_delivered":
            tasks = self.tasks()
            open_tasks = [task for task in record.get("owner_tasks", []) if tasks.get(task, {}).get("status") != "implemented"]
            if open_tasks or not record.get("owner_tasks"):
                self.error(
                    f"{label}: delivery is `{status.get('delivery')}` while {', '.join(open_tasks) or 'no owning task'} "
                    f"is not `implemented` in {GRAPH}"
                )
        if status.get("delivery") == "not_delivered" and not status.get("missing"):
            self.error(f"{label}: status.missing must say what the delivery lacks")

    def relation_core(self, label: str, relation: dict, name: str | None) -> dict | None:
        """The shared verifier a relation's own verifier reaches, as a second way for a test to reach it.

        `core` is `{path, symbol, via: [links]}`: the relation's verifier must name the first link,
        each link the next and the last the core. A test that calls the core counts only when it also
        names one of the relation's `test_words`, because other relations share the core.
        """
        core = relation.get("core")
        if not isinstance(core, dict):
            return None
        target = verifier_name(core)
        code = anchor_closure(self.tree, relation.get("verifier") or {}) if name else None
        if not target or code is None or not relation.get("test_words"):
            self.error(f"{label}: core needs a function symbol, a verifier with a body and test_words")
            return None
        step = name
        for link in list(core.get("via", [])) + [core]:
            link_names = anchor_names(self.tree, link)
            if not link_names or not any(names(code, item) for item in link_names):
                self.error(f"{label}: core: `{step}` does not name `{(link_names or [link.get('symbol')])[0]}`")
                return None
            step = link_names[0]
            code = anchor_closure(self.tree, link) or ""
        return {"entries": [target], "words": relation["test_words"]}

    def check_products(self) -> None:
        operations = self.inv.get("operations", [])
        used = {operation.get("product") for operation in operations}
        used |= {row.get("product") for row in self.inv.get("exact12", {}).get("protocols", [])}
        ledger = self.json_file(LEDGER) or {}
        requirement_ids = {record["id"] for record in ledger.get("requirements", [])}
        digests = {group["product"] for group in self.inv.get("digests", {}).get("products", [])}
        for product in self.inv.get("products", []):
            label = f"products[{product.get('id')}]"
            if product.get("id") not in used:
                self.error(f"{label}: no operation belongs to this product")
            for requirement in product.get("requirements", []):
                if requirement not in requirement_ids:
                    self.error(f"{label}: {requirement} is not a requirement of {LEDGER}")
            if not product.get("requirements"):
                self.error(f"{label}: requirements is required")
            if not product.get("owner_tasks"):
                self.error(f"{label}: owner_tasks is required")
            if product.get("id") not in digests:
                self.error(f"{label}: digests.products has no entry for this product")
        for relation in self.inv.get("relations", []):
            label = f"relations[{relation.get('id')}]"
            if relation.get("status") not in ("implemented", "binding_only", "signature_only", "unavailable", "absent"):
                self.error(f"{label}: status must be implemented, binding_only, signature_only, unavailable or absent")
            if relation.get("status") in ("implemented", "binding_only", "signature_only") and not relation.get("verifier"):
                self.error(f"{label}: a `{relation.get('status')}` relation needs its verifier")
            name = verifier_name(relation.get("verifier") or {})
            self.check_evidence(label, relation, relation.get("status"), [name] if name else [],
                                self.relation_core(label, relation, name))
            if relation.get("status") == "unavailable" and not relation.get("refusal"):
                self.error(f"{label}: an `unavailable` relation needs its refusal")
            if not relation.get("guarantee"):
                self.error(f"{label}: guarantee must say what the relation establishes")

    # ---- closed lists

    def check_enum(self, label: str, record: dict, listed: list[str]) -> None:
        text = self.tree.read(record["path"])
        if text is None:
            self.error(f"{label}: {record['path']} is missing")
            return
        variants = enum_variants(text, record["enum"])
        if variants is None:
            self.error(f"{label}: enum {record['enum']} not found in {record['path']}")
        elif variants != listed:
            self.error(f"{label}: {record['enum']} has variants {variants}, recorded {listed}")

    def check_exact12(self) -> None:
        section = self.inv.get("exact12", {})
        rows = section.get("protocols", [])
        source = section.get("source", {})
        text = self.tree.read(source.get("path", "")) or ""
        self.check_enum("exact12", {"path": source.get("path", ""), "enum": source.get("enum", "")},
                        [row.get("variant") for row in rows])
        if len(rows) != section.get("count"):
            self.error(f"exact12: count is {section.get('count')}, {len(rows)} protocols listed")
        implementation = block_after(text, r"\bimpl\s+" + re.escape(source.get("enum", "")) + r"\s*\{") or ""
        all_list = re.search(r"\bALL\s*:[^=]*=\s*\[([^\]]*)\]", implementation)
        if all_list is None or re.findall(r"Self::(\w+)", all_list.group(1)) != [row.get("variant") for row in rows]:
            self.error("exact12: the ALL list of the protocol enum differs from the recorded order")
        for key, function in (("label", "canonical_label"), ("security_model", "security_model"),
                              ("proof_system", "expected_proof_system"), ("engine", "expected_engine")):
            body = fn_body(implementation, function)
            arms = match_arms(body or "")
            for row in rows:
                value = arms.get(row.get("variant"), "").split("::")[-1]
                if value != row.get(key):
                    self.error(f"exact12[{row.get('variant')}]: {function} gives `{value}`, recorded `{row.get(key)}`")
        dispatch = section.get("dispatch", {})
        dispatch_text = self.tree.read(dispatch.get("path", "")) or ""
        dispatch_body = fn_body(dispatch_text, dispatch.get("function", "")) or ""
        dispatched = sorted(set(re.findall(re.escape(dispatch.get("statement_enum", "")) + r"::(\w+)\s*\(", strip_comments(dispatch_body))))
        if dispatched != sorted(row.get("variant") for row in rows):
            self.error(f"exact12: the dispatch of {dispatch.get('function')} has arms {dispatched}")
        profiles = section.get("compiled_profiles", {})
        profile_text = self.tree.read(profiles.get("path", "")) or ""
        profile_arms = match_arms(fn_body(profile_text, profiles.get("function", "")) or "", source.get("enum", ""))
        for row in rows:
            label = f"exact12[{row.get('variant')}]"
            target = profile_arms.get(row.get("variant"))
            if target != row.get("compiled_profile", {}).get("arm"):
                self.error(f"{label}: {profiles.get('function')} dispatches to `{target}`, recorded "
                           f"`{row.get('compiled_profile', {}).get('arm')}`")
            state = row.get("compiled_profile", {}).get("state")
            if state not in ("constructed", "refused"):
                self.error(f"{label}: compiled_profile.state must be constructed or refused")
            if state == "refused" and not (row["compiled_profile"].get("gate") and row["compiled_profile"].get("tests")):
                self.error(f"{label}: a refused compiled profile needs its gate and a test")
            if target == "Err" and state != "refused":
                self.error(f"{label}: the compiled profile arm is an error, state must be refused")
            if row.get("ledger_effect") is None or "verifier" not in row:
                self.error(f"{label}: verifier and ledger_effect are required")
            if state == "refused" and row.get("status", {}).get("verification") == "implemented":
                self.error(f"{label}: a protocol whose compiled profile is refused cannot have verification `implemented`")
            name = verifier_name(row.get("verifier") or {})
            if name and not names(code_only(dispatch_body), name):
                self.error(f"{label}: {dispatch.get('function')} does not call the recorded verifier `{name}`")
            entries = self.dispatch_entries()
            self.check_status(label, row, [name] if name else [], {"entries": entries, "words": [row.get("variant")]},
                              frozenset(entries))
            if state == "constructed":
                self.check_constructed_profile(label, row, profiles)
        effects = section.get("ledger_effects", {})
        variants = enum_variants(self.tree.read(effects.get("path", "")) or "", effects.get("enum", ""))
        recorded = sorted({effect for row in rows for effect in row.get("ledger_effect", [])})
        if variants is None or sorted(variants) != recorded:
            self.error(f"exact12: {effects.get('enum')} has variants {variants}, the protocols use {recorded}")

    # ---- Exact12 roles and the single route

    def handler_is_gated(self, handler: dict, gate: str) -> bool:
        """Whether the instruction handler's `impl` block still calls the admission gate `gate`."""
        text = self.production(handler.get("path", ""))
        symbol = handler.get("symbol", "")
        body = block_after(text, r"\s+".join(re.escape(part) for part in symbol.split()) + r"\s*\{") if symbol else None
        return body is not None and names(code_only(body), gate)

    def check_action_roles(self) -> None:
        section = self.inv.get("exact12", {})
        roles = section.get("roles")
        if not isinstance(roles, dict):
            self.error("exact12: `roles` is required (the thirteen typed roles of the twelve protocols)")
            return
        rows = roles.get("list", [])
        listed = [row.get("role") for row in rows]
        source = roles.get("source", {})
        self.check_enum("exact12.roles", {"path": source.get("path", ""), "enum": source.get("enum", "")}, listed)
        if len(rows) != roles.get("count"):
            self.error(f"exact12.roles: count is {roles.get('count')}, {len(rows)} roles listed")
        text = self.tree.read(source.get("path", "")) or ""
        implementation = block_after(text, r"\bimpl\s+" + re.escape(source.get("enum", "")) + r"\s*\{") or ""
        all_list = re.search(r"\bALL\s*:[^=]*=\s*\[([^\]]*)\]", implementation)
        if all_list is None or re.findall(r"Self::(\w+)", all_list.group(1)) != listed:
            self.error("exact12.roles: the ALL list of the role enum differs from the recorded order")
        protocol_arms = match_arms(fn_body(implementation, "protocol_id") or "")
        protocols = {row.get("variant"): row for row in section.get("protocols", [])}
        registry = roles.get("registry", {})
        registry_text = self.production(registry.get("path", ""))
        table = registry_rows(registry_text, registry.get("table", ""))
        if table is None:
            self.error(f"exact12.roles.registry: table {registry.get('table')} not found in {registry.get('path')}")
            table = []
        elif [row["role"] for row in table] != listed:
            self.error(f"exact12.roles.registry: {registry.get('table')} lists {[row['role'] for row in table]}, recorded {listed}")
        typed = {row["role"]: row for row in table}
        limitations = enum_variants(registry_text, registry.get("limitations", {}).get("enum", "")) or []
        effect_classes = enum_variants(registry_text, registry.get("effect_classes", {}).get("enum", "")) or []
        delivered_in_code = len(re.findall(r"PrivacyRoleDeliveryV1\s*::\s*Delivered\b", code_only(registry_text)))
        for key in ("json_view_test", "profile_agreement_test"):
            test = registry.get(key)
            if not isinstance(test, dict) or not runs_by_default(test):
                self.error(f"exact12.roles.registry.{key}: must cite a test that runs by default")
        if not roles.get("tests"):
            self.error("exact12.roles: tests are required")
        dispatch = section.get("dispatch", {})
        dispatch_code = anchor_closure(self.tree, {"path": dispatch.get("path", ""),
                                                   "symbol": "fn " + dispatch.get("function", "") + "("}) or ""
        instruction = section.get("single_route", {}).get("handler", {}).get("entry", {})
        gate = roles.get("gate_site")
        gated = self.handler_is_gated(instruction, "resolve_qualified_privacy_activation_v1")
        if gated and not isinstance(gate, dict):
            self.error("exact12.roles: the handler calls the admission gate; record it as `gate_site`")
        if not gated and gate is not None:
            self.error("exact12.roles: the handler no longer calls the admission gate; remove `gate_site` and "
                       "record applied roles as `implemented`")
        tasks = self.tasks()
        seen_protocols: list[str] = []
        for row in rows:
            label = f"exact12.roles[{row.get('role')}]"
            protocol = row.get("protocol")
            if protocol_arms.get(row.get("role"), "").split("::")[-1] != protocol:
                self.error(f"{label}: protocol_id gives `{protocol_arms.get(row.get('role'))}`, recorded `{protocol}`")
            if protocol not in protocols:
                self.error(f"{label}: protocol `{protocol}` is not a listed protocol")
            if protocol not in seen_protocols:
                seen_protocols.append(protocol)
            elif seen_protocols[-1] != protocol:
                self.error(f"{label}: the roles of one protocol are listed together")
            verification = row.get("verification")
            if verification not in ROLE_VERIFICATION:
                self.error(f"{label}: verification must be one of {ROLE_VERIFICATION}")
            if (verification == "refused") != bool(row.get("limitation")):
                self.error(f"{label}: a refused role records its limitation, an implemented one none")
            if row.get("limitation") and row["limitation"] not in limitations:
                self.error(f"{label}: limitation `{row['limitation']}` is not a variant of the limitation enum")
            if row.get("effect_class") not in effect_classes:
                self.error(f"{label}: effect_class `{row.get('effect_class')}` is not a variant of the effect-class enum")
            code_row = typed.get(row.get("role"))
            if code_row is not None:
                for key in ("verification", "limitation", "effect_class"):
                    if code_row[key] != row.get(key):
                        self.error(f"{label}: the typed registry gives {key} `{code_row[key]}`, recorded `{row.get(key)}`")
            expected_ledger = "None" if row.get("effect_class") == "VerifyOnly" else row.get("effect_class")
            if row.get("ledger_effect") != expected_ledger:
                self.error(f"{label}: effect class `{row.get('effect_class')}` hands over ledger effect "
                           f"`{expected_ledger}`, recorded `{row.get('ledger_effect')}`")
            expected_effects = (
                "unreachable" if verification == "refused"
                else "none" if row.get("effect_class") == "VerifyOnly"
                else "gated" if gated else "implemented"
            )
            if row.get("state_effects") != expected_effects:
                self.error(
                    f"{label}: state_effects must be `{expected_effects}` (verification `{verification}`, effect class "
                    f"`{row.get('effect_class')}`, admission gate {'present' if gated else 'absent'}), "
                    f"recorded `{row.get('state_effects')}`"
                )
            if row.get("delivery") not in DELIVERY:
                self.error(f"{label}: delivery must be one of {DELIVERY}")
            elif row["delivery"] == "delivered":
                open_tasks = [task for task in row.get("owner_tasks", []) if tasks.get(task, {}).get("status") != "implemented"]
                if open_tasks or not row.get("owner_tasks") or verification != "implemented":
                    self.error(f"{label}: delivery is `delivered` while {', '.join(open_tasks) or 'its verification'} "
                               "is not implemented")
            elif not row.get("missing"):
                self.error(f"{label}: missing must say what the delivery lacks")
            if not row.get("owner_tasks"):
                self.error(f"{label}: owner_tasks is required")
            if not row.get("native_verifiers"):
                self.error(f"{label}: native_verifiers is required")
            for verifier in row.get("native_verifiers", []):
                if not names(dispatch_code, verifier.get("name", "")):
                    self.error(f"{label}: the dispatch `{dispatch.get('function')}` does not reach native verifier "
                               f"`{verifier.get('name')}`")
        delivered_rows = sum(1 for row in rows if row.get("delivery") == "delivered")
        if bool(delivered_in_code) != bool(delivered_rows):
            self.error(f"exact12.roles: the typed registry constructs `Delivered` {delivered_in_code} time(s), "
                       f"{delivered_rows} role(s) recorded as delivered")
        for variant, protocol in protocols.items():
            own = [row for row in rows if row.get("protocol") == variant]
            if not own:
                self.error(f"exact12.roles: protocol {variant} has no role")
                continue
            if {row.get("verification") for row in own} != {protocol.get("status", {}).get("verification")}:
                self.error(f"exact12.roles: protocol {variant} is recorded `{protocol.get('status', {}).get('verification')}`, "
                           f"its roles {sorted({str(row.get('verification')) for row in own})}")
            if sorted({row.get("ledger_effect") for row in own}) != sorted(protocol.get("ledger_effect", [])):
                self.error(f"exact12.roles: protocol {variant} records ledger effects {protocol.get('ledger_effect')}, "
                           f"its roles {sorted({str(row.get('ledger_effect')) for row in own})}")

    def check_exact12_single_route(self) -> None:
        section = self.inv.get("exact12", {})
        route = section.get("single_route")
        if not isinstance(route, dict):
            self.error("exact12: `single_route` is required (the guard of the single Exact12 path)")
            return
        prefix = "exact12.single_route"
        scan = RouteScan(self.tree, route.get("scan", {}))
        rows = section.get("roles", {}).get("list", []) if isinstance(section.get("roles"), dict) else []
        role_names = [row.get("role") for row in rows]

        # One assembler of the envelope.
        envelope = route.get("envelope", {})
        type_name = envelope.get("type", "")
        assembler = envelope.get("assembler", {})
        assembler_name = verifier_name(assembler) or ""
        inside = 0
        for found in envelope_assemblies(scan, type_name):
            if found["path"] == assembler.get("path") and found["function"] == assembler_name:
                inside += 1
            else:
                self.error(
                    f"{prefix}: {found['path']}: `{found['function']}` assembles {type_name} outside `{assembler_name}`; "
                    f"a second envelope assembler is a second authoritative route. Bind through "
                    f"`{type_name}::{assembler_name}`"
                )
        if inside != 1:
            self.error(f"{prefix}: `{assembler_name}` of {assembler.get('path')} must assemble {type_name} exactly once, "
                       f"found {inside}")
        recorded = {item.get("path"): item.get("count") for item in envelope.get("field_assignments", [])}
        observed = envelope_field_assignments(scan)
        for path in sorted(set(recorded) | set(observed)):
            if recorded.get(path) != observed.get(path):
                self.error(
                    f"{prefix}: {path} assigns an envelope identity field {observed.get(path, 0)} time(s), recorded "
                    f"{recorded.get(path, 0)}; an identity is derived by `{assembler_name}`, not assigned"
                )
        for item in envelope.get("field_assignments", []):
            if not item.get("why"):
                self.error(f"{prefix}: field_assignments[{item.get('path')}] needs `why`")
        if not envelope.get("tests"):
            self.error(f"{prefix}: envelope.tests are required")

        # One instruction that carries an envelope, statement or proof.
        instruction = route.get("instruction", {})
        carrier = instruction.get("carrier", {})
        carried: list[tuple[str, str, str]] = []
        for path in production_rust(self.tree, instruction.get("roots", []), route.get("scan", {}).get("exclude", [])):
            for struct, field, _ in struct_fields_of_types(scan.code(path), instruction.get("carried_types", [])):
                carried.append((path, struct, field))
        expected = (carrier.get("path"), carrier.get("struct"), carrier.get("field"))
        if expected not in carried:
            self.error(f"{prefix}: {carrier.get('struct')}.{carrier.get('field')} of {carrier.get('path')} does not carry "
                       f"an Exact12 envelope")
        for found in carried:
            if found != expected:
                self.error(
                    f"{prefix}: {found[0]}: `{found[1]}.{found[2]}` carries an Exact12 envelope, statement or proof; "
                    f"`{carrier.get('struct')}` is the only instruction that does"
                )
        if instruction.get("type") not in {operation["id"] for operation in self.inv.get("operations", [])}:
            self.error(f"{prefix}: instruction {instruction.get('type')} is not a listed operation")

        # One call of each stage of the handler.
        handler = route.get("handler", {})
        handler_code = scan.code(handler.get("path", ""))
        handler_index = rust_index(handler_code)
        for item in handler.get("single_calls", []):
            call = item.get("call", "")
            pattern = re.compile(
                r"(?<![A-Za-z0-9_])" + r"\s*::\s*".join(re.escape(part) for part in call.split("::")) + r"\s*\("
            )
            positions = [match.start() for match in pattern.finditer(handler_code)
                         if not re.search(r"\bfn\s+$", handler_code[max(0, match.start() - 8) : match.start()])]
            if len(positions) != 1:
                self.error(
                    f"{prefix}: `{call}` is called {len(positions)} time(s) in production code of {handler.get('path')}; "
                    "the single path calls it once"
                )
                continue
            if item.get("inside") not in handler_index.enclosing(positions[0]):
                self.error(f"{prefix}: `{call}` is no longer called inside `{item.get('inside')}`")

        # One consumer of a verified effect for ledger application.
        effects = route.get("effects", {})
        consumers = effects.get("ledger_consumers", [])
        recorded = {item.get("path"): item.get("count") for item in consumers}
        observed = scan.calls("into_ledger")
        for path in sorted(set(recorded) | set(observed)):
            if recorded.get(path) != observed.get(path):
                self.error(f"{prefix}: {path} consumes a verified effect (`into_ledger`) {observed.get(path, 0)} time(s), "
                           f"recorded {recorded.get(path, 0)}; only the handler applies an effect")
        for item in consumers:
            if item.get("use") not in EFFECT_USES:
                self.error(f"{prefix}: ledger_consumers[{item.get('path')}].use must be one of {EFFECT_USES}")
        applying = [item.get("path") for item in consumers if item.get("use") == "ledger_application"]
        if applying != [handler.get("path")]:
            self.error(f"{prefix}: exactly the handler applies a verified effect, recorded {applying}")
        enum = effects.get("enum", {})
        variants = enum_variants(self.tree.read(enum.get("path", "")) or "", enum.get("enum", "")) or []
        variant_use = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(enum.get("enum", "")) + r"\s*::\s*(\w+)")
        matching = {path for path in scan.holding(enum.get("enum", "\0")) if variant_use.search(scan.code(path))}
        recorded_matchers = {item.get("path") for item in effects.get("matchers", [])}
        for path in sorted(matching ^ recorded_matchers):
            self.error(
                f"{prefix}: {path} "
                + ("names a variant of the verified ledger effect and is not a recorded matcher"
                   if path in matching else "is a recorded matcher and names no variant of the verified ledger effect")
            )
        for item in effects.get("matchers", []):
            if item.get("use") not in EFFECT_USES:
                self.error(f"{prefix}: matchers[{item.get('path')}].use must be one of {EFFECT_USES}")
        for variant in variants:
            arms = len(re.findall(
                re.escape(enum.get("enum", "")) + r"\s*::\s*" + re.escape(variant) + r"\b\s*(?:\([^)]*\))?\s*=>",
                handler_code,
            ))
            if arms != 1:
                self.error(f"{prefix}: the handler has {arms} executor arm(s) for effect `{variant}`; one state executor "
                           "per effect")

        # One caller of each native verifier outside its engine.
        native = route.get("native_verifiers", {})
        tooling = {item.get("path") for item in native.get("non_admission_callers", [])}
        used_tooling: set[str] = set()

        def check_callers(label: str, verifier: dict, allowed: set[str], required: list[str]) -> None:
            name = verifier.get("name", "")
            scope = verifier.get("engine_scope", "")
            if not scope or not any(path.startswith(scope) for path in scan.files):
                self.error(f"{label}: engine_scope `{scope}` holds no scanned file")
            callers = scan.calls(name)
            for path in sorted(callers):
                if path.startswith(scope) or path in allowed:
                    continue
                if path in tooling:
                    used_tooling.add(path)
                    continue
                self.error(
                    f"{label}: native verifier `{name}` is called in {path}, outside its engine, its one admission "
                    "caller and the recorded non-admission tooling; that is a second verifier route"
                )
            for path in required:
                if path not in callers:
                    self.error(f"{label}: {path} no longer calls native verifier `{name}`")
                elif callers[path] != 1:
                    self.error(
                        f"{label}: {path} calls native verifier `{name}` {callers[path]} time(s); "
                        "its one admission caller must call it exactly once"
                    )

        for row in rows:
            for verifier in row.get("native_verifiers", []):
                check_callers(f"{prefix}: role {row.get('role')}", verifier, {native.get("dispatch")},
                              [native.get("dispatch")])
        operations = {operation["id"]: operation for operation in self.inv.get("operations", [])}
        for item in route.get("administrative_proof_operations", []):
            label = f"{prefix}: administrative operation {item.get('id')}"
            if item.get("id") not in operations:
                self.error(f"{label}: not a listed operation")
            callers = list(item.get("callers", []))
            check_callers(label, item.get("verifier", {}), set(callers), callers)
            operation = operations.get(item.get("id"))
            if operation and operation.get("invocation"):
                entry = self.operation_execution_entry(label, operation)
                if item.get("executor") != entry:
                    self.error(f"{label}: its executor must be the recorded invocation entry")
                self.check_verifier_path(label, operation, [item.get("verifier", {}).get("name", "\0")])
            else:
                code = anchor_closure(self.tree, item.get("executor", {})) or ""
                if not names(code, item.get("verifier", {}).get("name", "\0")):
                    self.error(f"{label}: its executor does not call `{item.get('verifier', {}).get('name')}`")
        for path in sorted(tooling - used_tooling):
            self.error(f"{prefix}: non_admission_callers[{path}] calls no recorded native verifier; remove the row")

        # Entries of the path.
        entries = {entry.get("id"): entry for entry in route.get("entries", [])}
        for required in ("direct_instruction", "action_driver", "generic_verification", "contract_or_proved_executable"):
            if required not in entries:
                self.error(f"{prefix}: entries must record `{required}`")
        for identifier, entry in entries.items():
            if not isinstance(entry.get("applicable"), bool):
                self.error(f"{prefix}: entries[{identifier}].applicable must be true or false")
            if not entry.get("tests"):
                self.error(f"{prefix}: entries[{identifier}] needs tests")
            if entry.get("applicable") is False and not entry.get("refusals"):
                self.error(f"{prefix}: entries[{identifier}] is not an entry of the path and must record its refusals")
        driver = entries.get("action_driver", {})
        driver_path = driver.get("site", {}).get("path", "")
        driver_text = self.production(driver_path)
        table = driver_operations(driver_text, driver.get("table", ""))
        recorded_operations = [{"name": item.get("name"), "role": item.get("role")}
                               for item in route.get("driver_operations", [])]
        if table is None:
            self.error(f"{prefix}: operation table {driver.get('table')} not found in {driver_path}")
        elif table != recorded_operations:
            self.error(f"{prefix}: {driver.get('table')} of {driver_path} is {table}, recorded {recorded_operations}")
        by_role: dict[str, str] = {}
        for item in recorded_operations:
            if item["role"] not in role_names:
                self.error(f"{prefix}: driver operation {item['name']} names `{item['role']}`, which is not a role")
            elif item["role"] in by_role:
                self.error(f"{prefix}: driver operations {by_role[item['role']]} and {item['name']} name one role")
            else:
                by_role[item["role"]] = item["name"]
        for row in rows:
            if row.get("driver_operation") != by_role.get(row.get("role")):
                self.error(f"{prefix}: role {row.get('role')} records driver operation `{row.get('driver_operation')}`, "
                           f"the driver table gives `{by_role.get(row.get('role'))}`")
        driver_code = scan.code(driver_path) if driver_path else ""
        for call in ("require_supported_privacy_action_role_v1", "require_canonical_role_submission_v1"):
            if not re.search(r"(?<![A-Za-z0-9_])" + call + r"\s*\(", driver_code):
                self.error(f"{prefix}: the action driver no longer calls `{call}`")
        for forbidden in ("verify_privacy_envelope_v1", enum.get("enum", "\0")):
            if names(driver_code, forbidden):
                self.error(f"{prefix}: the action driver names `{forbidden}`; it owns no verifier and no effect")

        # Retired duplicates stay retired.
        for item in route.get("retired", []):
            label = f"{prefix}: retired[{item.get('id')}]"
            for key in ("what", "replaced_by", "equivalence", "tests"):
                if not item.get(key):
                    self.error(f"{label}: `{key}` is required")
            for absent in item.get("absent", []):
                if re.search(absent.get("pattern", "\0"), self.production(absent.get("path", ""))):
                    self.error(f"{label}: `{absent.get('pattern')}` is back in {absent.get('path')}; "
                               "the duplicate route was retired")

    def check_generic(self) -> None:
        section = self.inv.get("generic_relations", {})
        self.check_enum("generic_relations", section.get("source", {}), [row.get("variant") for row in section.get("relations", [])])
        adapters = section.get("execution_adapters", {})
        self.check_enum("generic_relations.execution_adapters", adapters.get("source", {"path": "", "enum": ""}),
                        [row.get("variant") for row in adapters.get("list", [])])
        self.check_native_circuits(section)

    def check_native_circuits(self, section: dict) -> None:
        """Pin the native enum, admission list, relation mapping and circuit constants."""
        label = "generic_relations.native_circuits"
        circuits = section.get("native_circuits", {})
        source = circuits.get("source", {})
        rows = [row for row in section.get("relations", []) if row.get("circuits")]
        recorded = sorted(row.get("variant", "") for row in rows)
        variants = circuits.get("variants", [])
        self.check_enum(label, source, variants)
        if sorted(variants) != recorded:
            self.error(f"{label}: native variants {variants} differ from typed circuit relations {recorded}")
        text = self.production(source.get("path", ""))
        constant = circuits.get("constant", "")
        declaration = re.search(r"\bconst\s+" + re.escape(constant) + r"\b[^=]*=\s*\[", text)
        end = balanced(text, declaration.end() - 1, "[", "]") if declaration else None
        body = code_only(text[declaration.end():end - 1]) if end and declaration else ""
        listed = re.findall(r"Self::(\w+)", body) if re.fullmatch(r"\s*(?:Self::\w+\s*,?\s*)+", body) else None
        if listed != variants:
            self.error(f"{label}: {constant} lists {listed}, recorded {variants}")
        selector = section.get("selector", {})
        mapping = match_arms(fn_body(self.production(selector.get("path", "")), "compiled_relation") or "",
                             "super::native_pipa_r::" + source.get("enum", ""))
        expected = {row["variant"]: "ProofRelation::" + row["variant"] for row in rows}
        if mapping != expected:
            self.error(f"{label}: compiled_relation maps {mapping}, recorded {expected}")
        dispatches = circuits.get("kind_dispatch", {})
        for function, dispatch in dispatches.items():
            selected = [row for row in rows if row.get("circuit_source", {}).get("selector") == function]
            body = code_only(fn_body(text, function) or "")
            actual = dict(re.findall(r"Self::(\w+)\s*=>\s*Some\(\s*([\w:]+)\s*\)", body))
            expected = {row["variant"]: dispatch.get("owner", "") + "::" + row["circuit_source"]["kind"]
                        for row in selected}
            if not selected or actual != expected:
                self.error(f"{label}: {function} selects {actual}, recorded {expected}")
            actual = match_arms(fn_body(self.production(dispatch.get("path", "")), "circuit_id") or "")
            expected = {row["circuit_source"]["kind"]: dispatch.get("constant_prefix", "") + row["circuit_source"]["constant"]
                        for row in selected}
            if actual != expected:
                self.error(f"{label}: {function} circuit_id maps {actual}, recorded {expected}")
        delegate = code_only(fn_body(text, "circuit_id") or "")
        expected_delegate = ("if let Some(kind) = self.kaigi() { kind.circuit_id() } else { "
                             "self.confidential().expect().circuit_id() }")
        if re.sub(r"\s+", "", delegate) != re.sub(r"\s+", "", expected_delegate):
            self.error(f"{label}: circuit_id must delegate to its selected native kind")
        identifiers = []
        for row in rows:
            anchor = row.get("circuit_source", {})
            if anchor.get("selector") not in dispatches:
                self.error(f"{label}[{row.get('variant')}]: circuit_source requires its native kind selector")
            path, name = anchor.get("path", ""), anchor.get("constant", "")
            # First-release circuit identities are literal constants, never inferred aliases.
            match = re.search(r"\bconst\s+" + re.escape(name) + r'\s*:\s*&str\s*=\s*"([^"\\]*)"\s*;',
                              strip_comments(self.production(path))) if name else None
            value = match.group(1) if match else None
            if value is None or row["circuits"] != [value]:
                self.error(f"{label}[{row.get('variant')}]: {path}::{name} is {value!r}, recorded {row['circuits']}")
            identifiers.extend(row["circuits"])
        if len(set(identifiers)) != len(identifiers):
            self.error(f"{label}: each native relation requires a distinct circuit identity")

    def check_ram_lfe(self) -> None:
        section = self.inv.get("ram_lfe", {})
        openings = section.get("openings", {})
        listed = {(row.get("path"), row.get("name")) for row in openings.get("types", [])}
        pattern = re.compile(openings.get("type_pattern", "$^"))
        found = {(path, name) for path in openings.get("sources", []) for name in pattern.findall(self.tree.read(path) or "")}
        for path, name in sorted(found - listed):
            self.error(f"ram_lfe.openings: {name} is declared in {path} and is not listed")
        for path, name in sorted(listed - found):
            self.error(f"ram_lfe.openings: {name} is not declared in {path}")
        for key in ("classes", "backends", "verification_modes", "attestations"):
            part = section.get(key, {})
            self.check_enum(f"ram_lfe.{key}", part.get("source", {}), [row.get("variant") for row in part.get("list", [])])
            for row in part.get("list", []):
                if "status" in row:
                    self.check_status(f"ram_lfe.{key}[{row.get('variant')}]", row)

    def check_soracloud(self) -> None:
        section = self.inv.get("soracloud", {})
        for key in ("job_kinds", "decryption_modes"):
            part = section.get(key, {})
            self.check_enum(f"soracloud.{key}", part.get("source", {}), [row.get("variant") for row in part.get("list", [])])
            for row in part.get("list", []):
                if "status" in row:
                    self.check_status(f"soracloud.{key}[{row.get('variant')}]", row)
        roles = section.get("native_roles", {})
        body = fn_body(self.tree.read(roles.get("path", "")) or "", roles.get("function", ""))
        found = sorted(re.findall(r"::([A-Z0-9_]+_CIRCUIT_ID_V1)\b", body or ""))
        recorded = sorted(row.get("constant") for row in roles.get("list", []))
        if found != recorded:
            self.error(f"soracloud.native_roles: {roles.get('function')} lists {found}, recorded {recorded}")

    def check_executables(self) -> None:
        section = self.inv.get("executables", {})
        self.check_enum("executables", section.get("source", {}), [row.get("variant") for row in section.get("list", [])])
        for row in section.get("list", []):
            if row.get("proof_carrying") and not row.get("operation"):
                self.error(f"executables[{row.get('variant')}]: a proof-carrying executable names its operation")

    def check_syscalls(self) -> None:
        section = self.inv.get("syscalls", {})
        constants = syscall_constants(self.tree.read(section.get("path", "")) or "")
        if not constants:
            self.error(f"syscalls: no syscall constant read from {section.get('path')}")
            return
        pattern = re.compile(section.get("name_pattern", "$^"))
        listed = {row["name"]: row for row in section.get("list", [])}
        excluded = {row["name"]: row for row in section.get("excluded", [])}
        for name in sorted(constants):
            if pattern.search(name) and name not in listed and name not in excluded:
                self.error(f"syscalls: SYSCALL_{name} has a family name and is neither listed nor excluded")
        for name in sorted(set(listed) | set(excluded)):
            if name not in constants:
                self.error(f"syscalls: SYSCALL_{name} is not in {section.get('path')}")
        for name, row in excluded.items():
            if not row.get("reason"):
                self.error(f"syscalls.excluded[{name}]: reason is required")
        builtins = builtin_syscalls(self.tree.read(section.get("builtins_path", "")) or "")
        for name, row in listed.items():
            if name in constants and row.get("number") != f"0x{constants[name]:02X}":
                self.error(f"syscalls[{name}]: number is 0x{constants[name]:02X}, recorded {row.get('number')}")
            if sorted(row.get("kotodama_builtins", [])) != builtins.get(name, []):
                self.error(f"syscalls[{name}]: Kotodama builtins are {builtins.get(name, [])}, recorded "
                           f"{sorted(row.get('kotodama_builtins', []))}")
            if not row.get("host"):
                self.error(f"syscalls[{name}]: host handler is required")
        tags = instruction_tags(self.tree.read(section.get("path", "")) or "")
        recorded = {row["name"]: row.get("value") for row in section.get("instruction_bridge", {}).get("tags", [])}
        if tags != recorded:
            self.error(f"syscalls.instruction_bridge: operation tags are {tags}, recorded {recorded}")

    # ---- routes

    def check_routes(self) -> None:
        routes = self.inv.get("routes", {})
        tsv = tsv_rows(self.tree.read(ROUTE_TSV))
        if not tsv:
            self.error(f"routes: {ROUTE_TSV} has no row")
            return
        listed = {route["id"]: route for route in routes.get("list", [])}
        products = {product["id"] for product in self.inv.get("products", [])} | {"admission"}
        sources = [("tracked TSV", tsv)]
        if self.catalog is not None:
            compiled = tsv_rows(self.catalog)
            sources.append(("compiled route catalog", compiled))
            drift = sorted(set(tsv) ^ set(compiled))
            in_scope_drift = [
                identifier for identifier in drift
                if route_in_scope(routes, (tsv.get(identifier) or compiled.get(identifier))["path"])
            ]
            if in_scope_drift:
                self.error(f"routes: {ROUTE_TSV} and the compiled route catalog differ in listed families: {in_scope_drift}")
            elif drift:
                self.notes.append(
                    f"routes: {ROUTE_TSV} differs from the compiled route catalog outside the listed families "
                    f"({len(drift)} rows, e.g. {drift[0]}); run python3 scripts/sdk_operation_inventory.py --write"
                )
        for origin, rows in sources:
            for identifier, row in sorted(rows.items()):
                if route_in_scope(routes, row["path"]) and identifier not in listed:
                    self.error(f"routes: {identifier} ({row['method']} {row['path']}) of the {origin} is in a listed "
                               "path family and is not listed")
        for identifier, route in listed.items():
            label = f"routes[{identifier}]"
            row = tsv.get(identifier)
            if row is None:
                self.error(f"{label}: not a row of {ROUTE_TSV}")
                continue
            if not route_in_scope(routes, row["path"]):
                self.error(f"{label}: {row['path']} is outside routes.path_prefixes")
            for key in ("method", "path", "surface", "effect", "sdk"):
                if route.get(key) != row[key]:
                    self.error(f"{label}: {key} is `{row[key]}` in {ROUTE_TSV}, recorded `{route.get(key)}`")
            if route.get("product") not in products:
                self.error(f"{label}: product `{route.get('product')}` is not a listed product")
            if not route.get("handler"):
                self.error(f"{label}: handler is required")
            if not route.get("does"):
                self.error(f"{label}: `does` must say what the route does")
        self.check_route_links(listed)
        self.check_route_tripwire(routes, sources)

    def instruction_names(self) -> dict[str, str]:
        """{type name: operation id} of the listed instructions."""
        return {operation["isi"]["type"].split("::")[-1]: operation["id"]
                for operation in self.inv.get("operations", []) if operation.get("isi")}

    def torii_builders(self) -> dict[str, list[str]]:
        """{operation id: Torii production files that name its instruction type}."""
        builders = self.inv.get("routes", {}).get("builders", {})
        type_names = self.instruction_names()
        observed: dict[str, list[str]] = {}
        for path in production_rust(self.tree, builders.get("roots", []), builders.get("exclude", [])):
            raw = self.tree.read(path) or ""
            if not any(name in raw for name in type_names):
                continue
            words = set(_IDENTIFIER.findall(code_only(self.production(path))))
            for name in sorted(type_names.keys() & words):
                observed.setdefault(type_names[name], []).append(path)
        return observed

    def check_route_links(self, listed: dict[str, dict]) -> None:
        """A route's handler is a Torii function, and a route that builds an instruction is linked to it."""
        type_names = self.instruction_names()
        operations = {operation["id"]: operation for operation in self.inv.get("operations", [])}
        depth = self.inv.get("routes", {}).get("builders", {}).get("handler_depth", 1)
        building: dict[str, set[str]] = {}
        for identifier, route in listed.items():
            handler = route.get("handler")
            if not isinstance(handler, dict):
                continue
            label = f"routes[{identifier}]"
            if not re.search(r"\bfn\s+\w+", handler.get("symbol", "")):
                self.error(f"{label}: handler must be the Torii handler function (`fn name(`), not `{handler.get('symbol')}`")
                continue
            text = self.tree.read(handler.get("path", ""))
            position = symbol_position(text, handler["symbol"]) if text is not None else None
            span = rust_index(text).item_span(position) if position is not None else None
            if span is None:
                self.error(f"{label}: handler `{handler['symbol']}` has no body in {handler.get('path')}")
                continue
            code = rust_index(text).closure([span], depth=depth)
            for link in route.get("handler_calls", []):
                link_names = anchor_names(self.tree, link)
                called = anchor_closure(self.tree, link)
                if not link_names or called is None or not any(names(code, name) for name in link_names):
                    self.error(f"{label}: the handler does not call `{(link_names or [link.get('symbol')])[0]}` (handler_calls)")
                    break
                code += "\n" + called
            for name in type_names:
                if names(code, name):
                    building.setdefault(type_names[name], set()).add(identifier)
        observed = self.torii_builders()
        for identifier, operation in operations.items():
            if not operation.get("isi"):
                continue
            label = f"operations[{identifier}]"
            for route in sorted(building.get(identifier, set()) - set(operation.get("routes", []))):
                self.error(f"{label}: the handler of route {route} names this instruction and the route is not in `routes`")
            files = observed.get(identifier, [])
            if operation.get("torii", []) != files:
                self.error(f"{label}: Torii files naming the instruction are {files}, recorded {operation.get('torii', [])}; run --refresh")
            if files and not building.get(identifier) and not operation.get("routes_note"):
                self.error(
                    f"{label}: Torii names this instruction in {', '.join(files)} and no listed route's handler does; "
                    "list the route that builds it, or say in routes_note why none does"
                )

    def check_route_tripwire(self, routes: dict, sources: list[tuple[str, dict]]) -> None:
        """A route outside the listed path families whose id or path has a family word is excluded with a reason."""
        tripwire = routes.get("tripwire", {})
        pattern = re.compile(tripwire.get("pattern", "$^"), re.I)
        prefixes = tripwire.get("out_of_scope_prefixes", [])
        exclusions = {item.get("id"): item for item in tripwire.get("exclusions", [])}
        used_prefixes: set[str] = set()
        seen: set[str] = set()
        for origin, rows in sources:
            for identifier, row in sorted(rows.items()):
                seen.add(identifier)
                if route_in_scope(routes, row["path"]) or not pattern.search(identifier + " " + row["path"]):
                    continue
                prefix = next((item for item in prefixes if row["path"].startswith(item.get("prefix", "\0"))), None)
                if prefix is not None:
                    used_prefixes.add(prefix["prefix"])
                elif identifier not in exclusions:
                    self.error(
                        f"routes.tripwire: {identifier} ({row['method']} {row['path']}) of the {origin} has a family "
                        "word and is in no listed path family; list its family in routes.path_prefixes or exclude it with a reason"
                    )
        for item in prefixes:
            if not item.get("reason"):
                self.error(f"routes.tripwire.out_of_scope_prefixes[{item.get('prefix')}]: reason is required")
            if item.get("prefix") not in used_prefixes:
                self.error(f"routes.tripwire.out_of_scope_prefixes[{item.get('prefix')}]: no route with a family word is under it")
        for identifier, item in exclusions.items():
            if not item.get("reason"):
                self.error(f"routes.tripwire.exclusions[{identifier}]: reason is required")
            if identifier not in seen:
                self.error(f"routes.tripwire.exclusions[{identifier}]: not a row of {ROUTE_TSV}")

    def check_admission_routes(self) -> None:
        section = self.inv.get("admission_routes", {})
        for name in ADMISSION_ROUTES:
            record = section.get(name)
            if not isinstance(record, dict):
                self.error(f"admission_routes: `{name}` is required")
                continue
            if not record.get("sites"):
                self.error(f"admission_routes.{name}: at least one site is required")
            if not record.get("what"):
                self.error(f"admission_routes.{name}: `what` is required")
            if name == "restore":
                for site in record.get("sites", []):
                    field = site.get("state_field")
                    if field is None:
                        continue
                    if not isinstance(field, str) or not field.startswith("world."):
                        self.error("admission_routes.restore: state_field must name an original World field")
                        continue
                    if not site.get("what"):
                        self.error(f"admission_routes.restore: the guard for {field} needs `what`")
                    if not any(ref.get("inventory") == "state" and ref.get("key") == f"fields/{field}"
                               for ref in record.get("references", [])):
                        self.error(f"admission_routes.restore: the guard for {field} needs its State inventory reference")
            targets = [target for site in record.get("sites", []) for target in anchor_names(self.tree, site)]
            if record.get("tests"):
                self.check_evidence(f"admission_routes.{name}", record, "implemented", targets, required=False)
        for name in section:
            if name not in ADMISSION_ROUTES and name not in ("note", "entry_point_census", "excluded"):
                self.error(f"admission_routes: unknown route class `{name}`")
        for item in section.get("excluded", []):
            if not (item.get("id") and item.get("reason") and item.get("site")):
                self.error(f"admission_routes.excluded[{item.get('id')}]: id, site and reason are required")
        self.check_entry_points(section)

    def check_entry_points(self, section: dict) -> None:
        """Every verifier and validator entry point named in production code is classed under a route."""
        census = section.get("entry_point_census")
        if not isinstance(census, dict):
            self.error("admission_routes.entry_point_census is required")
            return
        classes = set(ADMISSION_ROUTES) | set(census.get("other_classes", {}))
        token_ids = {token.get("id") for token in census.get("tokens", [])}
        for relation in self.inv.get("relations", []):
            name = verifier_name(relation.get("verifier") or {})
            if name and relation.get("status") in TESTED and not any(
                re.search(token["pattern"], name + "(") for token in census.get("tokens", [])
            ):
                self.error(f"admission_routes.entry_point_census: the verifier `{name}` of relation {relation['id']} has no token")
        for item in census.get("out_of_scope_names", []):
            if not item.get("reason"):
                self.error(f"admission_routes.entry_point_census.out_of_scope_names[{item.get('pattern')}]: reason is required")

        def key(row: dict) -> tuple:
            return (row.get("token"), row.get("name", ""), row.get("path"))

        recorded = {key(row): row for row in census.get("occurrences", [])}
        observed = {key(row): row for row in entry_point_census(self.tree, census)}
        excluded = {item.get("id") for item in section.get("excluded", [])}
        for item in sorted(set(recorded) | set(observed)):
            subject = f"`{item[1] or item[0]}` in {item[2]}"
            before, after = recorded.get(item), observed.get(item)
            if before is None:
                self.error(
                    f"admission_routes.entry_point_census: {subject} occurs {after['count']} times and is not classed; "
                    "a new verifier or validator call is a new admission route or belongs to a recorded one"
                )
                continue
            if after is None:
                self.error(f"admission_routes.entry_point_census: {subject} no longer occurs; run --refresh")
                continue
            if before.get("count") != after["count"]:
                self.error(
                    f"admission_routes.entry_point_census: {subject} occurs {after['count']} times, recorded "
                    f"{before.get('count')}; review the route and run --refresh"
                )
            route = before.get("route")
            if route not in classes:
                self.error(f"admission_routes.entry_point_census: {subject} is not classed under a route class (route: {route})")
                continue
            if route in census.get("other_classes", {}):
                if route == "excluded":
                    if before.get("excluded") not in excluded:
                        self.error(f"admission_routes.entry_point_census: {subject} names no entry of admission_routes.excluded")
                elif route != "definition" and not before.get("note"):
                    self.error(f"admission_routes.entry_point_census: {subject} is classed `{route}` and needs a note")
                continue
            sites = section.get(route, {}).get("sites", [])
            if route == "restore" and item[1]:
                listed = any(site.get("path") == item[2] and item[1] in site.get("symbol", "") for site in sites)
            else:
                listed = any(site.get("path") == item[2] for site in sites)
            if not listed:
                self.error(
                    f"admission_routes.{route}: {subject} is classed here and no site of the class names it"
                )
        for token in census.get("tokens", []):
            if token.get("id") not in {row.get("token") for row in census.get("occurrences", [])}:
                self.error(f"admission_routes.entry_point_census.tokens[{token.get('id')}]: the token occurs nowhere")
        if len(token_ids) != len(census.get("tokens", [])):
            self.error("admission_routes.entry_point_census.tokens: ids must be unique")

    # ---- digests

    def check_digests(self) -> None:
        digests = self.inv.get("digests", {})
        for group in digests.get("products", []):
            label = f"digests.products[{group.get('product')}]"
            observed = digest_census(self.tree, digests, group)
            if observed != group.get("census"):
                self.error(f"{label}: hash-primitive census is {observed}, recorded {group.get('census')}")
            if "native" not in group or "in_circuit" not in group:
                self.error(f"{label}: native and in_circuit are required")
            for key in ("native", "in_circuit"):
                value = group.get(key)
                if isinstance(value, dict):
                    if not value.get("none"):
                        self.error(f"{label}.{key}: an object here must give `none` with the reason")
                elif not value:
                    self.error(f"{label}.{key}: list the digests or give {{\"none\": reason}}")
        roles = {role["id"] for role in digests.get("named_roles", [])}
        for role in DIGEST_ROLES:
            if role not in roles:
                self.error(f"digests.named_roles: `{role}` is required")
        for role in digests.get("named_roles", []):
            if not role.get("native"):
                self.error(f"digests.named_roles[{role.get('id')}]: native digest evidence is required")

    # ---- guarantee selection

    def check_guarantee_selection(self) -> None:
        section = self.inv.get("guarantee_selection", {})
        sites = section.get("sites", [])
        for site in sites:
            label = f"guarantee_selection.sites[{site.get('id')}]"
            if site.get("selector") not in SELECTORS:
                self.error(f"{label}: selector must be one of {SELECTORS}")
            if not site.get("site"):
                self.error(f"{label}: site (path and symbol) is required")
            if not site.get("rejection_tests") and not site.get("open_defect"):
                self.error(f"{label}: cite a rejection test or record an open defect with its owning task")
            defect = site.get("open_defect")
            if defect is not None and not (defect.get("owner_task") and defect.get("what")):
                self.error(f"{label}: open_defect needs owner_task and what")
            if site.get("chooses_guarantee") not in (True, False):
                self.error(f"{label}: chooses_guarantee must say whether the selector can change what a proof establishes")
            if site.get("chooses_guarantee") and not defect:
                self.error(f"{label}: a selector that can choose a guarantee is an open defect")
            targets = [name for anchor in [site.get("site") or {}] + list(site.get("guards", []))
                       for name in anchor_names(self.tree, anchor)]
            if site.get("rejection_tests") or site.get("chooses_guarantee") is False:
                self.check_evidence(label, site, "implemented", targets, key="rejection_tests",
                                    required=site.get("chooses_guarantee") is False)
        for selector in SELECTORS[:3]:
            if not any(site.get("selector") == selector for site in sites):
                self.error(f"guarantee_selection: no site with selector `{selector}`")
        census = section.get("selector_census", {})
        site_ids = {site.get("id") for site in sites}
        recorded = census.get("occurrences", [])
        before = {(row["token"], row["path"]): row.get("count") for row in recorded}
        after = {(row["token"], row["path"]): row["count"] for row in selector_census(self.tree, census)}
        for key in sorted(set(before) | set(after)):
            if before.get(key) != after.get(key):
                self.error(
                    f"guarantee_selection.selector_census: `{key[0]}` occurs {after.get(key, 0)} times in {key[1]}, "
                    f"recorded {before.get(key) or 0}; review the site and run --refresh"
                )
        for row in recorded:
            if row.get("site") not in site_ids:
                self.error(
                    f"guarantee_selection.selector_census: `{row['token']}` in {row['path']} is not classed under a "
                    f"listed site (site: {row.get('site')})"
                )
        used_sites = {row.get("site") for row in recorded}
        for token in census.get("tokens", []):
            if not any(row["token"] == token.get("id") for row in recorded):
                self.error(f"guarantee_selection.selector_census.tokens[{token.get('id')}]: the token occurs nowhere")
        inclusion = section.get("source_inclusion_census", {})
        observed_files = source_inclusion_census(self.tree, inclusion)
        classed = {row["path"]: row for row in inclusion.get("files", [])}
        for row in observed_files:
            record = classed.get(row["path"])
            if record is None:
                self.error(f"guarantee_selection.source_inclusion_census: {row['path']} includes Rust source bytes "
                           f"{row['count']} times and is not classed")
            elif record.get("count") != row["count"]:
                self.error(f"guarantee_selection.source_inclusion_census: {row['path']} includes Rust source bytes "
                           f"{row['count']} times, recorded {record.get('count')}")
        for path, record in classed.items():
            if path not in {row["path"] for row in observed_files}:
                self.error(f"guarantee_selection.source_inclusion_census: {path} no longer includes Rust source bytes")
            if record.get("use") not in ("identity", "export"):
                self.error(f"guarantee_selection.source_inclusion_census[{path}]: use must be identity or export")
            if record.get("use") == "identity" and record.get("site") not in site_ids:
                self.error(f"guarantee_selection.source_inclusion_census[{path}]: an identity use names its site")

    # ---- SDK

    def reference_subjects(self) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]]]:
        names: dict[str, str] = {}
        wire_ids: dict[str, str] = {}
        paths: dict[str, list[str]] = {}
        for operation in self.inv.get("operations", []):
            isi = operation.get("isi")
            if not isi:
                continue
            names[isi["type"].split("::")[-1]] = operation["id"]
            wire_ids[isi["wire_id"]] = operation["id"]
        for route in self.inv.get("routes", {}).get("list", []):
            literal = route.get("sdk_literal")
            if literal:
                paths.setdefault(literal, []).append("route:" + route["id"])
        return names, wire_ids, paths

    def observed_references(self) -> dict:
        """References from the six SDK families and, as the group `native_bridges`, from the bridge crates."""
        names, wire_ids, paths = self.reference_subjects()
        sdk = self.inv.get("sdk", {})
        groups = list(sdk.get("families", []))
        bridges = sdk.get("native_bridges", {})
        if bridges.get("roots"):
            groups.append({"id": BRIDGES, "roots": bridges["roots"], "extensions": bridges.get("extensions", [".rs"]),
                           "exclude": bridges.get("exclude", [])})
        return sdk_references(self.tree, {"families": groups}, names, wire_ids, paths)

    def check_sdk(self) -> None:
        sdk = self.inv.get("sdk", {})
        families = [family.get("id") for family in sdk.get("families", [])]
        if tuple(families) != SDK_FAMILIES:
            self.error(f"sdk.families must be exactly {SDK_FAMILIES}")
            return
        for family in sdk.get("families", []):
            if not sdk_files(self.tree, family):
                self.error(f"sdk.families[{family['id']}]: no source file under {family.get('roots')}")
        observed = self.observed_references()

        def compare(label: str, subject: str, recorded: dict) -> None:
            for family in SDK_FAMILIES:
                want = observed.get(subject, {}).get(family, [])
                have = recorded.get(family) if isinstance(recorded, dict) else None
                if have is None:
                    self.error(f"{label}: sdk.{family} is required (an empty list when no file references it)")
                    continue
                if have != want:
                    before = {row["path"] for row in have}
                    after = {row["path"] for row in want}
                    detail = []
                    if after - before:
                        detail.append("now referenced by " + ", ".join(sorted(after - before)))
                    if before - after:
                        detail.append("no longer referenced by " + ", ".join(sorted(before - after)))
                    if not detail:
                        detail.append("the way a file references it changed")
                    self.error(f"{label}: sdk.{family}: {'; '.join(detail)}; run --refresh")

        bridges = sdk.get("native_bridges", {})
        if not bridges.get("roots") or not sdk_files(self.tree, {"roots": bridges.get("roots", []),
                                                                 "extensions": bridges.get("extensions", [".rs"]),
                                                                 "exclude": bridges.get("exclude", [])}):
            self.error("sdk.native_bridges: roots with source files are required")
        for operation in self.inv.get("operations", []):
            if operation.get("isi"):
                compare(f"operations[{operation['id']}]", operation["id"], operation.get("sdk", {}))
                want = observed.get(operation["id"], {}).get(BRIDGES, [])
                if operation.get(BRIDGES) != want:
                    before = {row["path"] for row in operation.get(BRIDGES) or []}
                    after = {row["path"] for row in want}
                    self.error(
                        f"operations[{operation['id']}]: native_bridges: now referenced by {sorted(after - before)}, "
                        f"no longer by {sorted(before - after)}; run --refresh"
                    )
            elif "sdk" in operation:
                for family in SDK_FAMILIES:
                    if family not in operation["sdk"]:
                        self.error(f"operations[{operation['id']}]: sdk.{family} is required")
        for route in self.inv.get("routes", {}).get("list", []):
            if route.get("sdk_literal"):
                compare(f"routes[{route['id']}]", "route:" + route["id"], route.get("sdk_files", {}))
        surface = sdk_surface(self.tree, sdk)
        recorded = sdk.get("surface", [])
        if surface != recorded:
            before = {(row["family"], row["path"], row["product"], symbol) for row in recorded for symbol in row["symbols"]}
            after = {(row["family"], row["path"], row["product"], symbol) for row in surface for symbol in row["symbols"]}
            for item in sorted(after - before)[:40]:
                self.error(f"sdk.surface: {item[0]} declares `{item[3]}` in {item[1]} ({item[2]}) and it is not listed; "
                           "review it and run --refresh")
            for item in sorted(before - after)[:40]:
                self.error(f"sdk.surface: `{item[3]}` is no longer declared in {item[1]} ({item[0]}); run --refresh")
            if len(after ^ before) > 80:
                self.error(f"sdk.surface: {len(after ^ before)} declarations differ in total")
        for row in surface:
            if row["product"] == "unclassified":
                self.error(f"sdk.surface: {row['path']} declares {row['symbols']} and no rule of "
                           "sdk.surface_scan.products classes them")
        known = {product["id"] for product in self.inv.get("products", [])} | set(sdk.get("surface_scan", {}).get("other_products", []))
        for rule in sdk.get("surface_scan", {}).get("products", []):
            if rule.get("product") not in known:
                self.error(f"sdk.surface_scan.products: `{rule.get('product')}` is not a product")

    # ---- requirements

    def check_requirements(self) -> None:
        ledger = self.json_file(LEDGER)
        if ledger is None:
            self.error(f"requirements: {LEDGER} is missing or not JSON")
            return
        expected: dict[str, set[str]] = {"requirements": set(), "findings": set()}
        for section in expected:
            for record in ledger.get(section, []):
                if TASK in record.get("task_ids", []):
                    expected[section].add(record["id"])
        recorded = self.inv.get("requirements", {})
        for section, identifiers in expected.items():
            listed = {record.get("id") for record in recorded.get(section, [])}
            for identifier in sorted(identifiers - listed):
                self.error(f"requirements.{section}: {identifier} maps to {TASK} in {LEDGER} and is not addressed here")
            for identifier in sorted(listed - identifiers):
                self.error(f"requirements.{section}: {identifier} does not map to {TASK} in {LEDGER}")
            for record in recorded.get(section, []):
                if not record.get("addressed_by"):
                    self.error(f"requirements.{section}[{record.get('id')}]: addressed_by is required")
                for pointer in record.get("addressed_by", []):
                    if not resolve_key(self.inv, pointer):
                        self.error(f"requirements.{section}[{record.get('id')}]: `{pointer}` does not resolve in this inventory")
        mapping = self.inv.get("requirement_mapping", {})
        if not mapping.get("checker") or not mapping.get("enforced_by"):
            self.error("requirement_mapping: cite the plan checker and the rules that enforce the mapping")

    # ---- driver

    def check(self) -> list[str]:
        self.errors = []
        self.notes = []
        self.check_header()
        if self.errors and any(error.startswith("missing section") for error in self.errors):
            return self.errors
        self.check_anchors()
        self.check_registry()
        self.check_products()
        self.check_exact12()
        self.check_action_roles()
        self.check_exact12_single_route()
        self.check_generic()
        self.check_ram_lfe()
        self.check_soracloud()
        self.check_executables()
        self.check_syscalls()
        self.check_routes()
        self.check_admission_routes()
        self.check_digests()
        self.check_guarantee_selection()
        self.check_sdk()
        self.check_requirements()
        return self.errors

    # ---- maintenance

    def refresh(self) -> list[str]:
        """Recompute the mechanical parts in place; return what changed."""
        changes: list[str] = []
        inv = self.inv
        observed = self.observed_references()
        builders = self.torii_builders()
        for operation in inv.get("operations", []):
            if not operation.get("isi"):
                continue
            new = {family: observed.get(operation["id"], {}).get(family, []) for family in SDK_FAMILIES}
            if operation.get("sdk") != new:
                changes.append(f"operations[{operation['id']}].sdk")
                operation["sdk"] = new
            bridges = observed.get(operation["id"], {}).get(BRIDGES, [])
            if operation.get(BRIDGES) != bridges:
                changes.append(f"operations[{operation['id']}].{BRIDGES}")
                operation[BRIDGES] = bridges
            files = builders.get(operation["id"], [])
            if operation.get("torii", []) != files:
                changes.append(f"operations[{operation['id']}].torii")
                operation["torii"] = files
        tsv = tsv_rows(self.tree.read(ROUTE_TSV))
        for route in inv.get("routes", {}).get("list", []):
            row = tsv.get(route["id"])
            if row is not None:
                for key in ("method", "path", "surface", "effect", "sdk"):
                    if route.get(key) != row[key]:
                        changes.append(f"routes[{route['id']}].{key}")
                        route[key] = row[key]
            if route.get("sdk_literal"):
                new = {family: observed.get("route:" + route["id"], {}).get(family, []) for family in SDK_FAMILIES}
                if route.get("sdk_files") != new:
                    changes.append(f"routes[{route['id']}].sdk_files")
                    route["sdk_files"] = new
        surface = sdk_surface(self.tree, inv.get("sdk", {}))
        if inv.get("sdk", {}).get("surface") != surface:
            changes.append("sdk.surface")
            inv["sdk"]["surface"] = surface
        section = inv.get("guarantee_selection", {})
        census = section.get("selector_census", {"roots": [], "tokens": []})
        classed = {(row["token"], row["path"]): row.get("site") for row in census.get("occurrences", [])}
        occurrences = [
            dict(row, site=classed.get((row["token"], row["path"])))
            for row in selector_census(self.tree, census)
        ]
        if census.get("occurrences") != occurrences:
            changes.append("guarantee_selection.selector_census.occurrences")
            census["occurrences"] = occurrences
        inclusion = section.get("source_inclusion_census", {})
        counts = {row["path"]: row["count"] for row in source_inclusion_census(self.tree, inclusion)}
        for record in inclusion.get("files", []):
            if record["path"] in counts and record.get("count") != counts[record["path"]]:
                changes.append(f"guarantee_selection.source_inclusion_census[{record['path']}].count")
                record["count"] = counts[record["path"]]
        digests = inv.get("digests", {})
        for group in digests.get("products", []):
            census = digest_census(self.tree, digests, group)
            if group.get("census") != census:
                changes.append(f"digests.products[{group['product']}].census")
                group["census"] = census
        entry_points = inv.get("admission_routes", {}).get("entry_point_census")
        if isinstance(entry_points, dict):
            kept = {(row.get("token"), row.get("name", ""), row.get("path")): row for row in entry_points.get("occurrences", [])}
            rows = []
            for row in entry_point_census(self.tree, entry_points):
                previous = kept.get((row["token"], row.get("name", ""), row["path"]), {})
                rows.append(dict(row, **{key: value for key, value in previous.items()
                                         if key in ("route", "note", "excluded")}) if previous else dict(row, route=None))
            if entry_points.get("occurrences") != rows:
                changes.append("admission_routes.entry_point_census.occurrences")
                entry_points["occurrences"] = rows
        return changes

    def propose(self) -> list[str]:
        lines: list[str] = []
        registry = self.inv.get("registry", {})
        entries = registry_entries(self.tree, registry)
        listed = {op["isi"]["type"] for op in self.inv.get("operations", []) if op.get("isi")}
        impls = handler_impls(self.tree, registry.get("tripwire", {}).get("handler_roots", []))
        for entry in entries:
            if module_scope(registry, entry) != "in" or entry["type"] in listed:
                continue
            blocks = impls.get(entry["name"], [])
            skeleton = {
                "id": entry["type"],
                "product": "TODO",
                "role": "TODO",
                "isi": {"type": entry["type"], "wire_id": entry["wire_id"],
                        "defined_in": {"path": "TODO", "symbol": "pub struct " + entry["name"]}},
                "handler": {"path": blocks[0]["path"], "symbol": blocks[0]["symbol"]} if blocks else "TODO",
                "authority": [{"path": blocks[0]["path"], "symbol": token}
                              for token in sorted(authority_tokens(
                                  handler_scope(self.tree, blocks[0], entry["name"]),
                                  handler_scope(self.tree, blocks[0], entry["name"], raw=True), registry))] if blocks else [],
                "status": {"presence": "registered", "verification": "TODO", "state_effects": "TODO",
                           "delivery": "not_delivered", "missing": "TODO"},
                "owner_tasks": ["TODO"],
            }
            lines.append(json.dumps(skeleton, indent=2))
        routes = self.inv.get("routes", {})
        listed_routes = {route["id"] for route in routes.get("list", [])}
        for identifier, row in sorted(tsv_rows(self.tree.read(ROUTE_TSV)).items()):
            if route_in_scope(routes, row["path"]) and identifier not in listed_routes:
                lines.append(json.dumps({"id": identifier, "method": row["method"], "path": row["path"],
                                         "surface": row["surface"], "effect": row["effect"], "sdk": row["sdk"],
                                         "product": "TODO", "handler": "TODO", "does": "TODO",
                                         "sdk_literal": route_literal(row["path"])}, indent=2))
        return lines


def load(root: Path = ROOT) -> dict:
    return json.loads((root / INVENTORY).read_text(encoding="utf-8"))


def write_inventory(inventory: dict, root: Path = ROOT) -> None:
    """Write the inventory in its stable text form (used by `--refresh` only)."""
    (root / INVENTORY).write_text(dump(inventory), encoding="utf-8")


def _inline(value) -> str | None:
    """`value` on one line when it is a small leaf: scalars, or one level of scalars."""
    if isinstance(value, dict):
        if not all(not isinstance(item, (dict, list)) or (isinstance(item, list) and all(not isinstance(x, (dict, list)) for x in item))
                   for item in value.values()):
            return None
    elif isinstance(value, list):
        if not all(not isinstance(item, (dict, list)) for item in value):
            return None
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 140 else None


def _dump(value, depth: int, out: list[str]) -> None:
    pad = " " * depth
    inline = _inline(value)
    if inline is not None or not isinstance(value, (dict, list)) or not value:
        out.append(inline if inline is not None else json.dumps(value, ensure_ascii=False))
        return
    if isinstance(value, dict):
        out.append("{\n")
        for index, (key, item) in enumerate(value.items()):
            out.append(f"{pad} {json.dumps(key, ensure_ascii=False)}: ")
            _dump(item, depth + 1, out)
            out.append(",\n" if index + 1 < len(value) else "\n")
        out.append(pad + "}")
    else:
        out.append("[\n")
        for index, item in enumerate(value):
            out.append(pad + " ")
            _dump(item, depth + 1, out)
            out.append(",\n" if index + 1 < len(value) else "\n")
        out.append(pad + "]")


def dump(inventory: dict) -> str:
    """Stable JSON text: one-space indentation, small leaf objects and lists on one line."""
    out: list[str] = []
    _dump(inventory, 0, out)
    return "".join(out) + "\n"


def show(inventory: dict) -> list[str]:
    lines = []
    for operation in inventory.get("operations", []):
        status = operation.get("status", {})
        wire = operation["isi"]["wire_id"] if operation.get("isi") else f"<{operation.get('carrier', {}).get('kind')}>"
        lines.append(
            f"{operation['id']:<64} {operation.get('product', ''):<24} {status.get('presence', ''):<10} "
            f"verification={status.get('verification', ''):<15} effects={status.get('state_effects', ''):<12} "
            f"delivery={status.get('delivery', '')}  {wire}"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--show", action="store_true", help="print one line per operation")
    parser.add_argument("--refresh", action="store_true", help="rewrite the mechanical parts, then check")
    parser.add_argument("--propose", action="store_true", help="print skeletons for unlisted instructions and routes")
    parser.add_argument("--no-compile", action="store_true", help="do not read the compiled route catalog with rustc")
    parser.add_argument("--with-plan-check", action="store_true",
                        help="also run scripts/check_zk_delivery_plan.py, which enforces the requirement mapping")
    args = parser.parse_args(argv)
    try:
        inventory = load()
    except (OSError, json.JSONDecodeError) as error:
        print(f"zk_operation_inventory: cannot read {INVENTORY}: {error}", file=sys.stderr)
        return 2
    if args.show:
        print("\n".join(show(inventory)))
        return 0
    catalog = None
    if not args.no_compile:
        catalog = compiled_catalog(ROOT)
        if catalog is None:
            print("zk_operation_inventory: rustc could not build the route exporter; routes are checked against "
                  f"{ROUTE_TSV} only", file=sys.stderr)
    checker = Checker(inventory, Tree(), catalog)
    if args.propose:
        print("\n".join(checker.propose()) or "nothing to propose")
        return 0
    if args.refresh:
        changes = checker.refresh()
        write_inventory(inventory)
        for change in changes:
            print(f"refreshed {change}")
        print(f"zk_operation_inventory: refreshed {len(changes)} recorded facts")
    errors = checker.check()
    for note in checker.notes:
        print(f"note: {note}", file=sys.stderr)
    if args.with_plan_check:
        plan = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_zk_delivery_plan.py")],
                              cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if plan.returncode != 0:
            errors.append("scripts/check_zk_delivery_plan.py failed: " + plan.stdout.strip().splitlines()[-1])
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"zk_operation_inventory: {len(errors)} inconsistencies", file=sys.stderr)
        return 1
    operations = inventory["operations"]
    registered = sum(1 for operation in operations if operation.get("isi"))
    print(
        f"zk_operation_inventory: {len(operations)} operations ({registered} registered instructions), "
        f"{len(inventory['exact12']['protocols'])} protocols, {len(inventory['routes']['list'])} routes, "
        f"{len(inventory['guarantee_selection']['sites'])} selection sites match the tree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
