#!/usr/bin/env python3
"""Check the protocol economic invariant matrix against the source.

`specs/zk_economic_invariants.json` classifies every economic effect of the
value-bearing ZK and privacy products (private issuance, transparent supply
change, deposit, withdrawal, reserve movement, settlement, inter-pool
movement) and records, for each effect, its handler, the ledger invariants
that are checked independently of the proof verifier with their enforcement
sites, the authorized source of issued units, what stays exposed when a proof
is accepted wrongly (hidden inflation, reserve theft and transparent minting
are separate answers) and the tests that mutate the effect. It also records,
per protocol, how retained state stays readable, how an effect is cancelled or
expires, how a failure rolls back and how assets leave under key or policy
revocation and correction, and the policy of root publication and history.
This script is the drift guard for that file. It fails when:

* an operation of `specs/zk_operation_inventory.json` is not classified, a
  classified operation is gone, a value-bearing operation has no effect row,
  an effect row names an operation classified as moving no value, the
  handler of an operation classified as moving no value starts to name a
  ledger-value identifier (directly or through functions of its file) that
  its entry does not record, or an operation recorded as refused or absent
  gains state effects in the operation inventory;
* a product of the operation inventory is not a protocol entry, a
  value-bearing protocol lacks one of the lifecycle answers, or a lifecycle
  answer has neither an enforcement site nor an open defect;
* a closed list the matrix mirrors changes in the source: the twelve
  protocols, the ledger-effect classes the verifier returns, the
  proof-managed transitions, the public-reserve owners and the constant list
  of protocols that may own a reserve, the root roles with their management
  and the protocols they belong to, the protocol lifecycle states, the
  value-balance directions and the
  committed World maps that hold pool or nullifier state (so another
  shielded pool cannot appear without a protocol entry or a recorded reason
  for leaving it out);
* an effect row disagrees with the operation inventory about its checked execution entry or
  about whether the effect is implemented, gated, unreachable or absent;
* a cited handler, enforcement site, apply site or carrier is gone (text is
  compared after collapsing whitespace; a site given `within` must lie in the
  body of that function, block or match arm), or an invariant enforced by
  absence finds one of its forbidden identifiers in the recorded scope;
* a cited test is gone, carries no `#[test]`, is `#[ignore]`d, is gated by a
  Cargo feature the entry does not record, does not name what the entry says
  it exercises, or does not contain a rejection text the entry says it
  asserts (the same text must also be in a file of the effect's enforcement
  sites); a verifier-fault harness is not compiled only for tests;
* an effect that a proof authorizes does not answer all three of hidden
  inflation, reserve theft and transparent minting, answers "no transparent
  minting" without an invariant that justifies it, records a public reserve
  without admitting that inflated hidden value can leave through it, or
  lacks both a mutation test and an open defect for the missing one;
* a ledger invariant is described as proof soundness: every enforced
  invariant lists what it does not establish, a bound on a reserve, a public
  supply figure or a custody balance must list proof soundness and hidden
  conservation, and the word is refused in invariant statements and exposure
  bounds;
* an invariant recorded as not enforced, a lifecycle answer recorded as not
  defined or a missing mutation test has no open defect, a defect names a
  task that is not in the delivery graph, its site is gone, or nothing
  references it;
* root publication and history: a publication or history site is gone, a
  lifecycle state other than `Active` is not recorded as a suspension switch
  with its defect and its open entry of the runtime-validity census, or a
  file of the recorded scope gains or loses a suspension word;
* a requirement or revision-6 finding the reconciliation ledger maps to F.3
  is not addressed, or a recorded count differs from the recomputed one.

Reading is textual, with the readers of
`scripts/check_zk_operation_inventory.py`: a symbol is found as text after
collapsing whitespace, and function bodies, `impl` blocks and match arms are
read by brace matching on text whose comments and literals are blanked. The
check shows that a named site and test exist and name each other. It does not
run the tests, and it does not show that an invariant is sufficient: an
`enforced` invariant says that the ledger refuses the recorded mutation, never
that a proof relation is sound or that hidden value is conserved.

Limits, stated once:

* Value tripwire. A handler classified as moving no value is read with the
  functions of its file it calls, `helper_depth` levels deep, for the
  identifiers of `tripwire.pattern`. Value moved through a function of
  another file under a name outside the pattern is not seen.
* Absence. An invariant enforced by absence is a token search in the recorded
  scope; a call through an alias or another file is not seen.
* Lines. `line` is the line of `symbol` when the file was last refreshed; the
  symbol is authoritative and the check does not fail when only the line
  moves. `--refresh` rewrites the lines; `--strict-lines` fails on a stale
  one.
* Suspension census. Words are counted in the non-test code of the recorded
  files; a switch under another name or in another file is not counted.

Prerequisites: Python 3.9+ standard library, run from a checkout. No
environment variables are read and nothing is compiled.

Usage:
    python3 scripts/check_zk_economic_invariants.py
    python3 scripts/check_zk_economic_invariants.py --show          # one line per effect
    python3 scripts/check_zk_economic_invariants.py --defects       # one line per open defect
    python3 scripts/check_zk_economic_invariants.py --refresh       # rewrite lines, census counts, summary
    python3 scripts/check_zk_economic_invariants.py --strict-lines  # also fail on a stale `line`
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_zk_operation_inventory as readers  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "specs/zk_economic_invariants.json"
OPERATIONS = "specs/zk_operation_inventory.json"
CENSUS = "specs/zk_runtime_validity_census.json"
GRAPH = "specs/zk_delivery_graph.json"
LEDGER = "specs/zk_delivery_reconciliation.json"
SCHEMA = "iroha.zk_economic_invariants.v1"
OPERATIONS_SCHEMA = "iroha.zk_operation_inventory.v1"
TASK = "F.3"

EFFECT_CLASSES = (
    "private_issuance",
    "transparent_supply_change",
    "deposit",
    "withdrawal",
    "reserve_movement",
    "settlement",
    "inter_pool_movement",
)
FAILURE_KINDS = ("hidden_inflation", "reserve_theft", "transparent_minting")
INVARIANT_KINDS = (
    "exact_reserve_debit_before_equal_credit",
    "existing_asset_movement",
    "committed_issuance_allowance",
    "asset_namespace_isolation",
    "cross_pool_conservation",
    "fixed_public_supply",
    "bounded_custody",
    "spent_once",
    "ledger_derived_successor",
    "no_transparent_boundary",
    "authorized_source",
    "bounded_lifetime",
    "supply_representation_gate",
)
INVARIANT_STATUS = ("enforced", "enforced_by_absence", "not_enforced", "not_applicable")
EFFECT_STATUS = ("implemented", "gated", "unreachable", "absent")
TEST_STATUS = ("existing", "added")
POSSIBLE = ("yes", "no", "not_applicable")
BOUNDARIES = (
    "public_reserve", "closed_fixed_public_supply", "closed_hidden_supply", "transparent_custody", "not_built",
)
NOT_ESTABLISHED = ("proof_soundness", "hidden_conservation", "depositor_protection")
ISSUANCE_SOURCES = (
    "governance_authority",
    "existing_transparent_balance",
    "pool_reserve",
    "session_custody",
    "funded_vault",
    "existing_pool_units",
    "issuer_authority",
    "none",
)
LIFECYCLE_KEYS = ("retained_state_readability", "cancellation_expiry", "failure_atomicity")
EXIT_KEYS = ("key_revocation", "policy_revocation", "correction")
ANSWER_STATUS = ("defined", "not_defined", "not_applicable")
NO_VALUE_REASONS = (
    "administrative",
    "verification_only",
    "refused_no_value",
    "absent_no_value",
    "metering_only",
    "record_without_units",
    "policy_only",
    "carrier_without_value",
)
DEFECT_KINDS = (
    "invariant_not_enforced",
    "issuance_unbounded",
    "exit_not_defined",
    "suspension_switch",
    "mutation_test_missing",
    "harness_seam_missing",
    "effect_absent",
    "enforcement_untested",
)
SWITCH_CLASSES = ("lifecycle_switch", "word_only")
# A bound on a balance or on a public figure. It limits what can leave; it proves nothing about
# the relation, so such an invariant must say so.
BOUNDING_KINDS = frozenset({"exact_reserve_debit_before_equal_credit", "fixed_public_supply", "bounded_custody"})
# Invariants that justify the answer "a wrongly accepted proof cannot mint transparent units".
NO_MINT_KINDS = frozenset({
    "exact_reserve_debit_before_equal_credit", "existing_asset_movement", "no_transparent_boundary", "bounded_custody",
})
REQUIRED_KEYS = (
    "schema", "task", "plan", "checker", "what", "not_a_soundness_claim", "consumed_by", "observed", "vocabulary",
    "sources", "requirements", "closed_lists", "protocols", "effects", "operations", "tripwire", "root_policy",
    "defects", "summary",
)
VOCABULARY = {
    "effect_class": EFFECT_CLASSES,
    "failure_kind": FAILURE_KINDS,
    "invariant_kind": INVARIANT_KINDS,
    "invariant_status": INVARIANT_STATUS,
    "effect_status": EFFECT_STATUS,
    "does_not_establish": NOT_ESTABLISHED,
    "boundary": BOUNDARIES,
    "issuance_source": ISSUANCE_SOURCES,
    "no_value_reason": NO_VALUE_REASONS,
    "defect_kind": DEFECT_KINDS,
}
# How an operation's `state_effects` in the operation inventory maps to the status of its rows.
EFFECT_STATUS_OF = {
    "implemented": ("implemented",),
    "gated": ("gated", "unreachable"),
    "unreachable": ("unreachable",),
    "absent": ("absent",),
}
_ARROW = re.compile(r"=>")


def line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def arm_span(code: str, position: int) -> tuple[int, int] | None:
    """Body of the match arm whose pattern starts at `position`: a block, or an expression up to its comma."""
    arrow = _ARROW.search(code, position)
    if arrow is None or arrow.start() - position > 600:
        return None
    index = arrow.end()
    while index < len(code) and code[index].isspace():
        index += 1
    if index < len(code) and code[index] == "{":
        end = readers.balanced(code, index)
        return None if end is None else (index, end)
    depth = 0
    for cursor in range(index, len(code)):
        char = code[cursor]
        if char in "({[":
            depth += 1
        elif char in ")}]":
            if depth == 0:
                return index, cursor
            depth -= 1
        elif char == "," and depth == 0:
            return index, cursor
    return None


def block_span(text: str, anchor: str) -> tuple[int, int] | None:
    """Span of the body that `anchor` opens in `text`: a function, an `impl`, a block or a match arm."""
    position = readers.symbol_position(text, anchor)
    if position is None:
        return None
    index = readers.rust_index(text)
    code = index.code
    squashed = anchor.strip()
    after = _skip_space(code, position + _length(text, position, anchor))
    if "=>" in squashed or code.startswith("=>", after):
        return arm_span(code, position)
    if squashed.endswith("{"):
        brace = position + _length(text, position, anchor) - 1
        end = index.closes.get(brace)
        return None if end is None else (brace, end)
    span = index.item_span(position)
    if span is not None:
        return span
    return arm_span(code, position)


def _length(text: str, position: int, anchor: str) -> int:
    """Length in `text` of the match of `anchor` at `position` (whitespace runs may differ)."""
    parts = anchor.split()
    match = re.compile(r"\s+".join(re.escape(part) for part in parts)).match(text, position)
    return match.end() - position if match else len(anchor)


def _skip_space(code: str, index: int) -> int:
    while index < len(code) and code[index].isspace():
        index += 1
    return index


def absence_scopes(invariant: dict) -> list[dict]:
    """The scopes of an invariant enforced by absence: one object or a list of them."""
    absence = invariant.get("absence")
    if isinstance(absence, dict):
        return [absence]
    return [scope for scope in absence or [] if isinstance(scope, dict)]


def word_in(code: str, word: str) -> bool:
    """`word` in `code` as a whole identifier, or as a prefix when it ends with `_`."""
    if word.endswith("_"):
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(word), code) is not None
    return readers.names(code, word)


class Checker:
    """One pass over the matrix. `errors` is the result; `notes` are advisory."""

    def __init__(self, inventory: dict, tree: readers.Tree | None = None, strict_lines: bool = False) -> None:
        self.inventory = inventory
        self.tree = tree or readers.Tree()
        self.strict_lines = strict_lines
        self.errors: list[str] = []
        self.notes: list[str] = []
        self._json: dict[str, object] = {}
        self.referenced_defects: set[str] = set()

    # ----------------------------------------------------------------- helpers

    def error(self, message: str) -> None:
        self.errors.append(message)

    def document(self, path: str):
        """A tracked JSON document, read through the tree so tests can substitute it."""
        if path not in self._json:
            text = self.tree.read(path)
            try:
                self._json[path] = json.loads(text) if text is not None else None
            except json.JSONDecodeError:
                self._json[path] = None
            if self._json[path] is None:
                self.error(f"{path}: missing or not JSON")
        return self._json[path]

    def operations(self) -> dict[str, dict]:
        document = self.document(OPERATIONS) or {}
        return {item["id"]: item for item in document.get("operations", [])}

    def operation_handler(self, operation: dict) -> dict | None:
        """Resolve the checked execution entry, including original-invocation custody."""
        if not operation.get("handler"):
            return None
        checker = readers.Checker(self.document(OPERATIONS) or {}, self.tree)
        handler = checker.operation_execution_entry(f"operation {operation.get('id')}", operation)
        self.errors.extend(checker.errors)
        return handler

    def tasks(self) -> set[str]:
        graph = self.document(GRAPH) or {}
        return {task["id"] for task in graph.get("tasks", [])}

    def defects(self) -> dict[str, dict]:
        return {item.get("id", ""): item for item in self.inventory.get("defects", [])}

    def effects(self) -> dict[str, dict]:
        return {item.get("id", ""): item for item in self.inventory.get("effects", [])}

    def protocols(self) -> dict[str, dict]:
        return {item.get("id", ""): item for item in self.inventory.get("protocols", [])}

    def locate(self, anchor: dict, label: str) -> tuple[str, int] | None:
        """(file text, offset of the symbol) for a `{path, symbol, within?}` anchor, or None after an error."""
        if not isinstance(anchor, dict) or not anchor.get("path") or not anchor.get("symbol"):
            self.error(f"{label}: an anchor needs `path` and `symbol`")
            return None
        text = self.tree.read(anchor["path"])
        if text is None:
            self.error(f"{label}: {anchor['path']} is missing")
            return None
        start, end = 0, len(text)
        if anchor.get("within"):
            span = block_span(text, anchor["within"])
            if span is None:
                self.error(f"{label}: `{anchor['within']}` opens no body in {anchor['path']}")
                return None
            start, end = span
        position = readers.symbol_position(text[start:end], anchor["symbol"])
        if position is None:
            scope = f" inside `{anchor['within']}`" if anchor.get("within") else ""
            self.error(f"{label}: `{anchor['symbol']}` is not in {anchor['path']}{scope}")
            return None
        position += start
        if "line" in anchor:
            actual = line_of(text, position)
            if anchor["line"] != actual:
                message = f"{label}: `line` {anchor['line']} is stale, the symbol is at {anchor['path']}:{actual}"
                if self.strict_lines:
                    self.error(message)
                else:
                    self.notes.append(message)
        return text, position

    def cite(self, identifiers, label: str, kind: str | None = None) -> None:
        """Record defect references and require each to be an open defect."""
        known = self.defects()
        for identifier in identifiers or []:
            self.referenced_defects.add(identifier)
            if identifier not in known:
                self.error(f"{label}: defect `{identifier}` is not recorded")
            elif kind and known[identifier].get("kind") not in (kind if isinstance(kind, tuple) else (kind,)):
                self.error(f"{label}: defect `{identifier}` is not of kind {kind}")

    def test(self, test: dict, label: str, site_files: set[str] | None) -> None:
        """A cited test exists, runs by default (or records its feature) and names what it claims.

        With `site_files`, a rejection text the test asserts must also be in one of those files.
        """
        path, name = test.get("path"), test.get("test")
        if not path or not name:
            self.error(f"{label}: a test needs `path` and `test`")
            return
        if test.get("status") not in TEST_STATUS:
            self.error(f"{label}: test {name} needs `status` in {TEST_STATUS}")
        if not test.get("shows"):
            self.error(f"{label}: test {name} must say what it `shows`")
        reason = readers.has_test(self.tree, path, name)
        if reason is not None:
            self.error(f"{label}: {reason}")
            return
        gate = readers.feature_gate(self.tree, path)
        if gate != test.get("feature"):
            self.error(f"{label}: test {name} is gated by feature {gate!r}, recorded {test.get('feature')!r}")
        code = readers.test_closure(self.tree, test) or ""
        for word in test.get("exercises", []):
            if not word_in(code, word):
                self.error(f"{label}: test {name} does not name `{word}`")
        text = self.tree.read(path) or ""
        index = readers.rust_index(text)
        raw = index.closure(index.functions.get(name, []), raw=True)
        for literal in test.get("asserts", []):
            if readers.squash(literal) not in readers.squash(raw):
                self.error(f"{label}: test {name} does not contain the rejection text `{literal}`")
            elif site_files is not None and not any(
                    readers.squash(literal) in readers.squash(self.tree.read(file) or "") for file in site_files):
                self.error(f"{label}: the rejection text `{literal}` of test {name} is in no enforcement-site file of the effect")
        if test.get("harness"):
            self.harness(test["harness"], f"{label}: test {name}")

    def harness(self, harness: dict, label: str) -> None:
        """A verifier-fault harness exists and is compiled only for tests."""
        if self.locate(harness, f"{label} harness") is None:
            return
        included_by = harness.get("included_by")
        if not included_by or not included_by.get("path") or not included_by.get("symbol"):
            self.error(f"{label}: a harness records the `included_by` line that compiles its file")
            return
        parent = self.tree.read(included_by["path"])
        if parent is None:
            self.error(f"{label}: {included_by['path']} is missing")
            return
        if not readers.contains(parent, included_by["symbol"]):
            self.error(f"{label}: `{included_by['symbol']}` is not in {included_by['path']}, so the harness is not compiled")
        elif readers.contains(readers.production_text(parent), included_by["symbol"]):
            self.error(f"{label}: `{included_by['symbol']}` is outside `#[cfg(test)]` in {included_by['path']}; "
                       "a verifier-fault harness must be test-only")

    # ------------------------------------------------------------------ checks

    def check_shape(self) -> None:
        inventory = self.inventory
        for key in REQUIRED_KEYS:
            if key not in inventory:
                self.error(f"top level: `{key}` is missing")
        if inventory.get("schema") != SCHEMA:
            self.error(f"schema is {inventory.get('schema')!r}, expected {SCHEMA!r}")
        if inventory.get("task") != TASK:
            self.error(f"task is {inventory.get('task')!r}, expected {TASK!r}")
        if inventory.get("checker") != "scripts/check_zk_economic_invariants.py":
            self.error("checker must name scripts/check_zk_economic_invariants.py")
        vocabulary = inventory.get("vocabulary", {})
        for name, values in VOCABULARY.items():
            if sorted(vocabulary.get(name, {})) != sorted(values):
                self.error(f"vocabulary.{name} must define exactly {list(values)}")
        tasks = self.tasks()
        for task in inventory.get("consumed_by", []):
            if task not in tasks:
                self.error(f"consumed_by: task `{task}` is not in {GRAPH}")

    def check_sources(self) -> None:
        operations = self.document(OPERATIONS) or {}
        if operations.get("schema") != OPERATIONS_SCHEMA:
            self.error(f"{OPERATIONS}: schema is {operations.get('schema')!r}, expected {OPERATIONS_SCHEMA!r}")
        recorded = self.inventory.get("sources", {})
        for key, path in (("operation_inventory", OPERATIONS), ("runtime_validity_census", CENSUS), ("graph", GRAPH),
                          ("reconciliation", LEDGER)):
            if recorded.get(key, {}).get("path") != path:
                self.error(f"sources.{key}.path must be {path}")
            self.document(path)

    def enum(self, record: dict, label: str) -> list[str] | None:
        text = self.tree.read(record.get("path", ""))
        if text is None:
            self.error(f"{label}: {record.get('path')} is missing")
            return None
        variants = readers.enum_variants(text, record.get("enum", ""))
        if variants is None:
            self.error(f"{label}: enum {record.get('enum')} is not in {record.get('path')}")
        return variants

    def compare(self, label: str, recorded: list[str], actual: list[str] | None) -> bool:
        if actual is None:
            return False
        if sorted(recorded) != sorted(actual):
            missing = sorted(set(actual) - set(recorded))
            stale = sorted(set(recorded) - set(actual))
            self.error(f"{label}: source has {missing or 'nothing'} unrecorded, the matrix has {stale or 'nothing'} stale")
            return False
        return True

    def check_closed_lists(self) -> None:
        lists = self.inventory.get("closed_lists", {})
        operations = self.document(OPERATIONS) or {}
        protocols = self.protocols()
        effects = self.effects()

        exact12 = lists.get("exact12", {})
        variants = self.enum(exact12, "closed_lists.exact12")
        self.compare("closed_lists.exact12", exact12.get("variants", []), variants)
        listed = {item["variant"]: item for item in operations.get("exact12", {}).get("protocols", [])}
        self.compare("closed_lists.exact12 against the operation inventory", exact12.get("variants", []), list(listed))
        by_variant = {item.get("exact12_variant"): item for item in protocols.values() if item.get("exact12_variant")}
        self.compare("protocols with `exact12_variant`", list(by_variant), exact12.get("variants", []))
        for variant, protocol in by_variant.items():
            entry = listed.get(variant)
            if entry is None:
                continue
            if entry.get("product") != protocol.get("id"):
                self.error(f"protocol {protocol.get('id')}: {variant} belongs to product {entry.get('product')} in the operation inventory")
            if sorted(entry.get("ledger_effect", [])) != sorted(protocol.get("ledger_effects", [])):
                self.error(f"protocol {protocol.get('id')}: ledger_effects {protocol.get('ledger_effects')} differ from the "
                           f"operation inventory {entry.get('ledger_effect')}")

        ledger = lists.get("ledger_effects", {})
        variants = self.enum(ledger, "closed_lists.ledger_effects")
        classes = {item.get("variant"): item for item in ledger.get("classes", [])}
        self.compare("closed_lists.ledger_effects", list(classes), variants)
        for variant, item in classes.items():
            label = f"closed_lists.ledger_effects.{variant}"
            arm = item.get("arm", {})
            located = self.locate(arm, label)
            users = [p for p in by_variant.values() if variant in p.get("ledger_effects", [])]
            if item.get("value_bearing"):
                if not item.get("effects"):
                    self.error(f"{label}: a value-bearing class lists its effect rows")
                for identifier in item.get("effects", []):
                    row = effects.get(identifier)
                    if row is None:
                        self.error(f"{label}: effect `{identifier}` is not recorded")
                    elif row.get("protocol") not in [p.get("id") for p in users]:
                        self.error(f"{label}: effect `{identifier}` belongs to a protocol whose verifier does not return this class")
                for protocol in users:
                    if not protocol.get("value_bearing"):
                        self.error(f"{label}: protocol {protocol.get('id')} returns a value-bearing class and is recorded as moving no value")
            else:
                if item.get("effects"):
                    self.error(f"{label}: a class recorded as moving no value has effect rows")
                if not item.get("forbidden"):
                    self.error(f"{label}: a class recorded as moving no value lists the identifiers its arm must not name")
                if located is not None:
                    text, position = located
                    span = arm_span(readers.rust_index(text).code, position)
                    if span is None:
                        self.error(f"{label}: `{arm.get('symbol')}` opens no match arm")
                    else:
                        body = readers.rust_index(text).code[span[0] : span[1]]
                        for word in item.get("forbidden", []):
                            if word_in(body, word):
                                self.error(f"{label}: the arm names `{word}`, so the class is no longer value-free")

        transitions = lists.get("proof_managed_transitions", {})
        recorded = {item.get("variant"): item for item in transitions.get("variants", [])}
        self.compare("closed_lists.proof_managed_transitions", list(recorded), self.enum(transitions, "closed_lists.proof_managed_transitions"))
        for variant, item in recorded.items():
            if item.get("protocol") not in protocols:
                self.error(f"closed_lists.proof_managed_transitions.{variant}: protocol `{item.get('protocol')}` is not recorded")

        owners = lists.get("reserve_owners", {})
        recorded = {item.get("variant"): item for item in owners.get("variants", [])}
        self.compare("closed_lists.reserve_owners", list(recorded), self.enum(owners, "closed_lists.reserve_owners"))
        constant = owners.get("protocol_list", {})
        text = self.tree.read(constant.get("path", "")) or ""
        match = re.search(r"\bconst\s+" + re.escape(constant.get("name", "?")) + r"\b[^=]*=\s*\[", text)
        members: list[str] | None = None
        if match is None:
            self.error(f"closed_lists.reserve_owners: const {constant.get('name')} is not in {constant.get('path')}")
        else:
            end = readers.balanced(text, match.end() - 1, "[", "]")
            members = re.findall(r"PrivacyProtocolIdV1::(\w+)", readers.strip_comments(text[match.end() : end or match.end()]))
            self.compare("closed_lists.reserve_owners.protocol_list", constant.get("members", []), members)
        reserve_protocols = sorted(item.get("exact12_variant") for item in protocols.values()
                                   if item.get("pool", {}).get("boundary") == "public_reserve" and item.get("exact12_variant"))
        if members is not None and reserve_protocols != sorted(members):
            self.error(f"protocols with boundary public_reserve are {reserve_protocols}; the source lets {sorted(members)} own a reserve")
        for variant, item in recorded.items():
            protocol = protocols.get(item.get("protocol", ""))
            if protocol is None or protocol.get("pool", {}).get("boundary") != "public_reserve":
                self.error(f"closed_lists.reserve_owners.{variant}: protocol `{item.get('protocol')}` is not recorded with a public reserve")

        roles = lists.get("root_roles", {})
        recorded = {item.get("variant"): item for item in roles.get("roles", [])}
        if self.compare("closed_lists.root_roles", list(recorded), self.enum(roles, "closed_lists.root_roles")):
            text = self.tree.read(roles["path"]) or ""
            body = readers.fn_body(text, roles.get("management_function", "management")) or ""
            for names, management in re.findall(r"((?:Self::\w+\s*\|?\s*)+)=>\s*\{?\s*PrivacyRootManagementV1::(\w+)", body):
                for variant in re.findall(r"Self::(\w+)", names):
                    if recorded.get(variant, {}).get("management") != management:
                        self.error(f"closed_lists.root_roles.{variant}: source management is {management}, "
                                   f"recorded {recorded.get(variant, {}).get('management')}")
            users: dict[str, list[str]] = {variant: [] for variant in recorded}
            compatible = readers.fn_body(text, roles.get("compatibility_function", "is_compatible_with")) or ""
            for names, role in re.findall(r"\(\s*((?:PrivacyProtocolIdV1::\w+\s*\|?\s*)+),\s*Self::(\w+)\s*\)", compatible):
                for variant in re.findall(r"PrivacyProtocolIdV1::(\w+)", names):
                    users.setdefault(role, []).append(listed.get(variant, {}).get("product", variant))
            for variant, item in recorded.items():
                if sorted(item.get("protocols", [])) != sorted(users.get(variant, [])):
                    self.error(f"closed_lists.root_roles.{variant}: the source makes it a root of {sorted(users.get(variant, []))}, "
                               f"recorded {sorted(item.get('protocols', []))}")

        states = lists.get("lifecycle_states", {})
        recorded = {item.get("variant"): item for item in states.get("states", [])}
        self.compare("closed_lists.lifecycle_states", list(recorded), self.enum(states, "closed_lists.lifecycle_states"))
        switches = {item.get("state") for item in self.inventory.get("root_policy", {}).get("generic_suspension_switch", {}).get("found", [])}
        for variant, item in recorded.items():
            if item.get("admits_value_effects"):
                continue
            if variant not in switches:
                self.error(f"closed_lists.lifecycle_states.{variant}: a state that admits no value effect is recorded under "
                           "root_policy.generic_suspension_switch.found")

        self.check_pool_state(lists.get("pool_state", {}), protocols)

        directions = lists.get("value_balance_directions", {})
        recorded = {item.get("variant"): item for item in directions.get("variants", [])}
        self.compare("closed_lists.value_balance_directions", list(recorded), self.enum(directions, "closed_lists.value_balance_directions"))
        for variant, item in recorded.items():
            if item.get("effect_class") not in EFFECT_CLASSES:
                self.error(f"closed_lists.value_balance_directions.{variant}: effect_class must be one of {EFFECT_CLASSES}")

    def pool_state_fields(self, record: dict) -> list[str] | None:
        """Fields of the committed World struct whose name says they hold pool or nullifier state."""
        text = self.tree.read(record.get("path", ""))
        if text is None:
            self.error(f"closed_lists.pool_state: {record.get('path')} is missing")
            return None
        body = readers.block_after(text, r"\bpub struct " + re.escape(record.get("struct", "?")) + r"\s*\{")
        if body is None:
            self.error(f"closed_lists.pool_state: struct {record.get('struct')} is not in {record.get('path')}")
            return None
        try:
            pattern = re.compile(record.get("pattern", ""))
        except re.error as error:
            self.error(f"closed_lists.pool_state.pattern is not a regular expression: {error}")
            return None
        names = re.findall(r"pub(?:\([a-z]+\))?\s+([a-z_0-9]+)\s*:", readers.strip_comments(body))
        return [name for name in names if pattern.search(name)]

    def check_pool_state(self, record: dict, protocols: dict[str, dict]) -> None:
        """Every committed map that holds pool or nullifier state belongs to a protocol or is excluded with a reason."""
        recorded = {item.get("field"): item for item in record.get("fields", [])}
        if not self.compare("closed_lists.pool_state", list(recorded), self.pool_state_fields(record)):
            return
        for field, item in recorded.items():
            label = f"closed_lists.pool_state.{field}"
            owners = item.get("protocols", [])
            if bool(owners) == bool(item.get("out_of_scope")):
                self.error(f"{label}: names its `protocols`, or says why it is `out_of_scope`")
            for owner in owners:
                if owner not in protocols:
                    self.error(f"{label}: protocol `{owner}` is not recorded")

    def answer(self, answer, label: str) -> None:
        """A lifecycle answer: defined with a site, not defined with a defect, or not applicable with a reason."""
        if not isinstance(answer, dict) or answer.get("status") not in ANSWER_STATUS:
            self.error(f"{label}: needs `status` in {ANSWER_STATUS}")
            return
        if not answer.get("statement"):
            self.error(f"{label}: needs a `statement`")
        if answer["status"] == "defined":
            if not answer.get("sites"):
                self.error(f"{label}: a defined answer cites at least one site")
            for site in answer.get("sites", []):
                self.locate(site, label)
            for test in answer.get("tests", []):
                self.test(test, label, None)
        elif answer["status"] == "not_defined":
            if not answer.get("defects"):
                self.error(f"{label}: an answer that is not defined cites an open defect")
        self.cite(answer.get("defects"), label)

    def check_protocols(self) -> None:
        operations = self.document(OPERATIONS) or {}
        products = [item["id"] for item in operations.get("products", [])]
        protocols = self.protocols()
        self.compare("protocols against the products of the operation inventory", list(protocols), products)
        tasks = self.tasks()
        effects = self.effects()
        classified = self.inventory.get("operations", {})
        by_product: dict[str, list[str]] = {}
        for identifier, operation in self.operations().items():
            by_product.setdefault(operation.get("product", ""), []).append(identifier)
        for identifier, protocol in protocols.items():
            label = f"protocol {identifier}"
            for task in protocol.get("owner_tasks", []):
                if task not in tasks:
                    self.error(f"{label}: task `{task}` is not in {GRAPH}")
            if not protocol.get("owner_tasks"):
                self.error(f"{label}: needs `owner_tasks`")
            rows = sorted(row for row, effect in effects.items() if effect.get("protocol") == identifier)
            if sorted(protocol.get("effects", [])) != rows:
                self.error(f"{label}: `effects` {protocol.get('effects')} differ from the rows of this protocol {rows}")
            if bool(protocol.get("value_bearing")) != bool(rows):
                self.error(f"{label}: value_bearing is {protocol.get('value_bearing')} with {len(rows)} effect rows")
            orphans = [operation for operation in by_product.get(identifier, [])
                       if classified.get(operation, {}).get("value_bearing") and not rows
                       and not protocol.get("rows_recorded_under")]
            if orphans:
                self.error(f"{label}: operations {orphans} move value; record their rows here or name the protocols "
                           "that hold them under `rows_recorded_under`")
            for other in protocol.get("rows_recorded_under", []):
                if other not in protocols or not protocols[other].get("value_bearing"):
                    self.error(f"{label}: rows_recorded_under names `{other}`, which is not a value-bearing protocol")
            self.cite(protocol.get("defects"), label)
            if not protocol.get("value_bearing"):
                if rows:
                    self.error(f"{label}: a protocol recorded as moving no value has effect rows")
                if not protocol.get("why_no_value"):
                    self.error(f"{label}: a protocol recorded as moving no value says why")
                continue
            pool = protocol.get("pool", {})
            if pool.get("boundary") not in BOUNDARIES:
                self.error(f"{label}: pool.boundary must be one of {BOUNDARIES}")
            for key in ("unit", "supply_source"):
                if not pool.get(key):
                    self.error(f"{label}: pool.{key} is missing")
            lifecycle = protocol.get("lifecycle", {})
            for key in LIFECYCLE_KEYS:
                self.answer(lifecycle.get(key), f"{label}: lifecycle.{key}")
            for key in EXIT_KEYS:
                self.answer(lifecycle.get("exits", {}).get(key), f"{label}: lifecycle.exits.{key}")

    def site_files(self, effect: dict) -> set[str]:
        files = {effect.get("handler", {}).get("path", "")}
        for invariant in effect.get("invariants", []):
            files.update(site.get("path", "") for site in invariant.get("sites", []))
            files.update(scope.get("path", "") for scope in absence_scopes(invariant))
        files.update(site.get("path", "") for site in effect.get("apply_sites", []))
        files.discard("")
        return files

    def check_effects(self) -> None:
        operations = self.operations()
        protocols = self.protocols()
        exact12 = {item["variant"]: item for item in (self.document(OPERATIONS) or {}).get("exact12", {}).get("protocols", [])}
        seen: set[str] = set()
        for effect in self.inventory.get("effects", []):
            identifier = effect.get("id", "")
            label = f"effect {identifier}"
            if not identifier or identifier in seen:
                self.error(f"{label}: ids are unique and not empty")
            seen.add(identifier)
            protocol = protocols.get(effect.get("protocol", ""))
            if protocol is None:
                self.error(f"{label}: protocol `{effect.get('protocol')}` is not recorded")
                continue
            if effect.get("class") not in EFFECT_CLASSES:
                self.error(f"{label}: class must be one of {EFFECT_CLASSES}")
            if not effect.get("summary"):
                self.error(f"{label}: needs a `summary`")
            operation = operations.get(effect.get("operation", ""))
            if operation is None:
                self.error(f"{label}: operation `{effect.get('operation')}` is not in {OPERATIONS}")
                continue
            handler = effect.get("handler")
            status = effect.get("effect_status")
            execution = self.operation_handler(operation)
            if execution:
                expected = {key: execution[key] for key in ("path", "symbol")}
                if not handler or {key: handler.get(key) for key in ("path", "symbol")} != expected:
                    self.error(f"{label}: handler differs from the operation inventory ({expected})")
            elif status == "absent":
                if handler:
                    self.error(f"{label}: an absent effect has no handler to cite")
            elif not handler:
                self.error(f"{label}: an operation without a handler records its carrier site as `handler`")
            if handler:
                self.locate(handler, f"{label}: handler")
            allowed = EFFECT_STATUS_OF.get(operation.get("status", {}).get("state_effects"), ())
            if status not in EFFECT_STATUS:
                self.error(f"{label}: effect_status must be one of {EFFECT_STATUS}")
            elif status not in allowed:
                self.error(f"{label}: effect_status {status} contradicts the operation inventory, which records "
                           f"{operation.get('status', {}).get('state_effects')} for {operation['id']}")
            elif status == "unreachable" and operation.get("status", {}).get("state_effects") == "gated":
                compiled = exact12.get(protocol.get("exact12_variant", ""), {}).get("compiled_profile", {}).get("state")
                if compiled != "refused":
                    self.error(f"{label}: unreachable needs a refused compiled profile in the operation inventory, found {compiled}")
            for site in effect.get("apply_sites", []):
                self.locate(site, f"{label}: apply site")
            source = effect.get("authorized_issuance_source", {})
            if source.get("kind") not in ISSUANCE_SOURCES or not source.get("statement"):
                self.error(f"{label}: authorized_issuance_source needs `kind` in {ISSUANCE_SOURCES} and a `statement`")
            elif effect.get("class") == "private_issuance" and source["kind"] == "none":
                self.error(f"{label}: private issuance names who may issue")
            for site in source.get("sites", []):
                self.locate(site, f"{label}: issuance source")
            self.cite(effect.get("defects"), label)
            live = status in ("implemented", "gated")
            if not live:
                if not effect.get("required_before_enabling"):
                    self.error(f"{label}: an effect that cannot run records `required_before_enabling`")
                if not effect.get("defects"):
                    self.error(f"{label}: an effect that cannot run cites the open defect of its owner")
            self.check_invariants(effect, label, live)
            self.check_exposure(effect, label, protocol, live)
            self.check_mutation_tests(effect, label, live)

    def check_invariants(self, effect: dict, label: str, live: bool) -> None:
        invariants = effect.get("invariants", [])
        if live and not invariants:
            self.error(f"{label}: a reachable effect names at least one ledger invariant")
        files = self.site_files(effect)
        for index, invariant in enumerate(invariants):
            where = f"{label}: invariant {index} ({invariant.get('kind')})"
            if invariant.get("kind") not in INVARIANT_KINDS:
                self.error(f"{where}: kind must be one of {INVARIANT_KINDS}")
            status = invariant.get("status")
            if status not in INVARIANT_STATUS:
                self.error(f"{where}: status must be one of {INVARIANT_STATUS}")
                continue
            statement = invariant.get("statement", "")
            if not statement:
                self.error(f"{where}: needs a `statement`")
            if re.search(r"sound", statement, re.I):
                self.error(f"{where}: a ledger invariant is not described as soundness; say what it bounds")
            self.cite(invariant.get("defects"), where)
            if status in ("enforced", "enforced_by_absence"):
                absent = invariant.get("does_not_establish", [])
                unknown = [item for item in absent if item not in NOT_ESTABLISHED]
                if unknown:
                    self.error(f"{where}: does_not_establish has unknown entries {unknown}")
                if "proof_soundness" not in absent:
                    self.error(f"{where}: an enforced ledger invariant lists `proof_soundness` under does_not_establish")
                if invariant.get("kind") in BOUNDING_KINDS and "hidden_conservation" not in absent:
                    self.error(f"{where}: a bound on a reserve, a public supply figure or a custody balance lists "
                               "`hidden_conservation` under does_not_establish")
            if status == "enforced":
                if not invariant.get("sites"):
                    self.error(f"{where}: an enforced invariant cites its enforcement site")
                for site in invariant.get("sites", []):
                    self.locate(site, where)
            elif status == "enforced_by_absence":
                scopes = absence_scopes(invariant)
                if not scopes:
                    self.error(f"{where}: an invariant enforced by absence records its `absence` scope")
                for absence in scopes:
                    text = self.tree.read(absence.get("path", ""))
                    if text is None or not absence.get("within") or not absence.get("forbidden"):
                        self.error(f"{where}: absence needs an existing `path`, `within` and `forbidden`")
                        continue
                    span = block_span(text, absence["within"])
                    if span is None:
                        self.error(f"{where}: `{absence['within']}` opens no body in {absence['path']}")
                        continue
                    index = readers.rust_index(text)
                    body = index.closure([span], depth=absence.get("helper_depth", 0))
                    for word in absence["forbidden"]:
                        if word_in(body, word):
                            self.error(f"{where}: `{word}` appears in `{absence['within']}` of {absence['path']}; "
                                       "the invariant no longer holds by absence")
            elif status == "not_enforced":
                if not invariant.get("defects"):
                    self.error(f"{where}: an invariant that is not enforced cites an open defect with its owner")
            elif not invariant.get("why"):
                self.error(f"{where}: not_applicable says `why`")
            for test in invariant.get("tests", []):
                self.test(test, where, files)

    def check_exposure(self, effect: dict, label: str, protocol: dict, live: bool) -> None:
        proof = effect.get("proof", {})
        if not isinstance(proof.get("authorizes"), bool):
            self.error(f"{label}: proof.authorizes says whether a proof authorizes this effect")
            return
        exposure = effect.get("exposure_after_erroneous_acceptance", {})
        if sorted(key for key in exposure if key != "summary") != sorted(FAILURE_KINDS):
            self.error(f"{label}: exposure_after_erroneous_acceptance answers exactly {list(FAILURE_KINDS)}")
            return
        for kind in FAILURE_KINDS:
            answer = exposure[kind]
            if answer.get("possible") not in POSSIBLE:
                self.error(f"{label}: exposure {kind}.possible must be one of {POSSIBLE}")
            if not answer.get("bound"):
                self.error(f"{label}: exposure {kind}.bound says what limits it, or why it cannot happen")
            elif re.search(r"sound", answer["bound"], re.I):
                self.error(f"{label}: exposure {kind}.bound is not described as soundness; say what bounds it")
        if not proof["authorizes"]:
            if not proof.get("why"):
                self.error(f"{label}: an effect that no proof authorizes says who authorizes it under proof.why")
            if any(exposure[kind].get("possible") != "not_applicable" for kind in FAILURE_KINDS):
                self.error(f"{label}: without a proof every exposure answer is not_applicable")
            return
        if not exposure.get("summary"):
            self.error(f"{label}: exposure needs a `summary`")
        if not live:
            return
        kinds = {invariant.get("kind") for invariant in effect.get("invariants", [])
                 if invariant.get("status") in ("enforced", "enforced_by_absence")}
        if exposure["transparent_minting"].get("possible") == "no" and not kinds & NO_MINT_KINDS:
            self.error(f"{label}: `transparent_minting: no` needs an enforced invariant of kind {sorted(NO_MINT_KINDS)}")
        boundary = protocol.get("pool", {}).get("boundary")
        if boundary == "public_reserve":
            if exposure["hidden_inflation"].get("possible") == "yes" and exposure["reserve_theft"].get("possible") != "yes":
                self.error(f"{label}: with a public reserve, hidden value created by a wrongly accepted proof can leave "
                           "through it; reserve_theft must be `yes` with its bound")
        elif boundary in ("closed_fixed_public_supply", "closed_hidden_supply"):
            if exposure["reserve_theft"].get("possible") == "yes":
                self.error(f"{label}: a closed pool has no reserve to take from")
            if "no_transparent_boundary" not in kinds:
                self.error(f"{label}: an effect of a closed pool records the enforced invariant `no_transparent_boundary`")

    def check_mutation_tests(self, effect: dict, label: str, live: bool) -> None:
        tests = effect.get("mutation_tests", [])
        files = self.site_files(effect)
        for test in tests:
            self.test(test, f"{label}: mutation test", files)
        if not live:
            return
        if effect.get("proof", {}).get("authorizes"):
            missing = [identifier for identifier in effect.get("defects", [])
                       if self.defects().get(identifier, {}).get("kind") in ("mutation_test_missing", "harness_seam_missing")]
            harnessed = [test for test in tests if test.get("verifier_fault")]
            if not harnessed and not missing:
                self.error(f"{label}: a proof-authorized effect has a verifier-fault mutation test (`verifier_fault: true`) "
                           "or an open defect of kind mutation_test_missing or harness_seam_missing")
        if not tests:
            missing = [identifier for identifier in effect.get("defects", [])
                       if self.defects().get(identifier, {}).get("kind") in ("mutation_test_missing", "enforcement_untested")]
            if not missing:
                self.error(f"{label}: a reachable effect cites a mutation test or an open defect for the missing one")

    def value_tokens(self, operation: dict) -> list[str] | None:
        """Ledger-value identifiers in the checked execution entry and its same-file callees."""
        handler = self.operation_handler(operation)
        if not handler:
            return None
        tripwire = self.inventory.get("tripwire", {})
        text = self.tree.read(handler["path"]) or ""
        index = readers.rust_index(text)
        position = readers.symbol_position(text, handler["symbol"])
        span = index.item_span(position) if position is not None else None
        if span is None:
            return None
        spans = [span]
        if re.match(r"\s*impl\b", handler["symbol"]):
            owner = readers.anchor_names(self.tree, handler)
            spans += [block["span"] for block in index.impls if owner and block["type"] == owner[0] and block["span"] != span]
        code = index.closure(spans, depth=tripwire.get("helper_depth", 2))
        return sorted(set(re.findall(tripwire.get("pattern", r"(?!)"), code)))

    def check_operations(self) -> None:
        operations = self.operations()
        classified = self.inventory.get("operations", {})
        self.compare(f"operations against {OPERATIONS}", list(classified), list(operations))
        tripwire = self.inventory.get("tripwire", {})
        try:
            re.compile(tripwire.get("pattern", ""))
        except re.error as error:
            self.error(f"tripwire.pattern is not a regular expression: {error}")
            return
        if not tripwire.get("pattern") or not isinstance(tripwire.get("helper_depth"), int):
            self.error("tripwire needs `pattern` and an integer `helper_depth`")
            return
        effects = self.effects()
        rows_of: dict[str, list[str]] = {}
        for identifier, effect in effects.items():
            rows_of.setdefault(effect.get("operation", ""), []).append(identifier)
            for extra in effect.get("also_operations", []):
                rows_of.setdefault(extra, []).append(identifier)
                if extra not in operations:
                    self.error(f"effect {identifier}: also_operations names `{extra}`, which is not in {OPERATIONS}")
        for identifier, entry in classified.items():
            label = f"operation {identifier}"
            operation = operations.get(identifier)
            if operation is None:
                continue
            rows = sorted(rows_of.get(identifier, []))
            if entry.get("value_bearing") is True:
                if not rows:
                    self.error(f"{label}: a value-bearing operation has no effect row")
                if sorted(entry.get("effects", [])) != rows:
                    self.error(f"{label}: `effects` {entry.get('effects')} differ from the rows that name it {rows}")
                continue
            if entry.get("value_bearing") is not False:
                self.error(f"{label}: value_bearing is true or false")
                continue
            if rows:
                self.error(f"{label}: recorded as moving no value, yet rows {rows} name it")
            if entry.get("reason") not in NO_VALUE_REASONS:
                self.error(f"{label}: reason must be one of {NO_VALUE_REASONS}")
            state = operation.get("status", {}).get("state_effects")
            if entry.get("reason") in ("refused_no_value", "absent_no_value") and state not in ("unreachable", "absent", "none"):
                self.error(f"{label}: recorded as {entry.get('reason')}, but the operation inventory records its effects as "
                           f"{state}; classify the operation again")
            if not entry.get("note"):
                self.error(f"{label}: an operation recorded as moving no value says why in `note`")
            tokens = self.value_tokens(operation)
            recorded = sorted(entry.get("value_tokens", []))
            if tokens is None:
                if recorded:
                    self.error(f"{label}: value_tokens recorded for an operation without a readable handler")
                continue
            if tokens != recorded:
                self.error(f"{label}: its handler names the ledger-value identifiers {tokens}, recorded {recorded}; "
                           "classify the operation again or record why each identifier moves no value")
            if recorded and not entry.get("value_tokens_note"):
                self.error(f"{label}: value_tokens need a `value_tokens_note` saying why they move no value")

    def census_counts(self) -> list[list]:
        """[path, count] of suspension words in the non-test code of the recorded files."""
        census = self.inventory.get("root_policy", {}).get("suspension_census", {})
        pattern = re.compile(census.get("pattern", r"(?!)"))
        out = []
        for path in self.tree.walk(census.get("roots", []), (".rs",)):
            if any(re.search(exclude, path) for exclude in census.get("exclude", [])):
                continue
            text = self.tree.read(path) or ""
            count = len(pattern.findall(readers.code_only(readers.production_text(text))))
            if count:
                out.append([path, count])
        return out

    def check_root_policy(self) -> None:
        policy = self.inventory.get("root_policy", {})
        for key in ("statement", "publication", "history", "generic_suspension_switch", "suspension_census"):
            if key not in policy:
                self.error(f"root_policy: `{key}` is missing")
        for section in ("publication", "history"):
            block = policy.get(section, {})
            if not block.get("statement"):
                self.error(f"root_policy.{section}: needs a `statement`")
            if not block.get("sites"):
                self.error(f"root_policy.{section}: cites at least one site")
            for site in block.get("sites", []):
                self.locate(site, f"root_policy.{section}")
            for test in block.get("tests", []):
                self.test(test, f"root_policy.{section}", None)
            self.cite(block.get("defects"), f"root_policy.{section}")
        switch = policy.get("generic_suspension_switch", {})
        if switch.get("required") != "none":
            self.error("root_policy.generic_suspension_switch.required must be `none`")
        census = self.document(CENSUS) or {}
        entries = {entry.get("id"): entry for entry in census.get("entries", [])}
        for item in switch.get("found", []):
            label = f"root_policy.generic_suspension_switch.{item.get('id')}"
            self.locate(item.get("site", {}), label)
            for site in item.get("consulted_at", []):
                self.locate(site, f"{label}: consulted_at")
            for key in ("effect_on_roots", "effect_on_exits"):
                if not item.get(key):
                    self.error(f"{label}: `{key}` is missing")
            if not item.get("defect"):
                self.error(f"{label}: a suspension switch is an open defect with an owner")
            self.cite([item.get("defect")] if item.get("defect") else [], label, "suspension_switch")
            reference = item.get("census")
            if reference:
                entry = entries.get(reference)
                if entry is None:
                    self.error(f"{label}: census entry `{reference}` is not in {CENSUS}")
                elif entry.get("status") != "open":
                    self.error(f"{label}: census entry `{reference}` is {entry.get('status')}; the switch is recorded as open here")
        if switch.get("found") and switch.get("holds") is not False:
            self.error("root_policy.generic_suspension_switch.holds must be false while a switch is recorded")
        if not switch.get("found") and switch.get("holds") is not True:
            self.error("root_policy.generic_suspension_switch.holds must be true when no switch is recorded")
        recorded = policy.get("suspension_census", {})
        try:
            actual = {path: count for path, count in self.census_counts()}
        except re.error as error:
            self.error(f"root_policy.suspension_census.pattern is not a regular expression: {error}")
            return
        listed = {item.get("path"): item for item in recorded.get("files", [])}
        for path, count in actual.items():
            item = listed.get(path)
            if item is None:
                self.error(f"root_policy.suspension_census: {path} has {count} suspension words and is not recorded")
            elif item.get("count") != count:
                self.error(f"root_policy.suspension_census: {path} has {count} suspension words, recorded {item.get('count')}")
        for path, item in listed.items():
            if path not in actual:
                self.error(f"root_policy.suspension_census: {path} is recorded and has no suspension word")
            if item.get("class") not in SWITCH_CLASSES or not item.get("note"):
                self.error(f"root_policy.suspension_census: {path} needs `class` in {SWITCH_CLASSES} and a `note`")
            if item.get("class") == "lifecycle_switch":
                self.cite(item.get("defects"), f"root_policy.suspension_census: {path}", "suspension_switch")
                if not item.get("defects"):
                    self.error(f"root_policy.suspension_census: {path} is a lifecycle switch and cites no defect")

    def check_defects(self) -> None:
        tasks = self.tasks()
        seen: set[str] = set()
        for defect in self.inventory.get("defects", []):
            identifier = defect.get("id", "")
            label = f"defect {identifier}"
            if not identifier or identifier in seen:
                self.error(f"{label}: ids are unique and not empty")
            seen.add(identifier)
            if defect.get("kind") not in DEFECT_KINDS:
                self.error(f"{label}: kind must be one of {DEFECT_KINDS}")
            owners = defect.get("owner", [])
            if not owners or not isinstance(owners, list):
                self.error(f"{label}: `owner` lists the tasks that close it")
            for owner in owners if isinstance(owners, list) else []:
                if owner not in tasks:
                    self.error(f"{label}: owner `{owner}` is not in {GRAPH}")
                elif owner == TASK:
                    self.error(f"{label}: the matrix records defects, it does not own their repair")
            for key in ("summary", "required"):
                if not defect.get(key):
                    self.error(f"{label}: `{key}` is missing")
            if "line" not in defect:
                self.error(f"{label}: records the `line` of its site")
            self.locate(defect, label)
        for identifier in sorted(seen - self.referenced_defects):
            self.error(f"defect {identifier}: nothing in the matrix references it")

    def check_requirements(self) -> None:
        ledger = self.document(LEDGER) or {}
        mapped = [item["id"] for section in ("requirements", "findings", "prior_findings", "original_tasks")
                  for item in ledger.get(section, []) if TASK in item.get("task_ids", [])]
        addressed = {item.get("id"): item for item in self.inventory.get("requirements", {}).get("addressed", [])}
        self.compare(f"requirements against the entries {LEDGER} maps to {TASK}", list(addressed), mapped)
        for identifier, item in addressed.items():
            if not item.get("where"):
                self.error(f"requirement {identifier}: `where` lists the sections that address it")
            for key in item.get("where", []):
                if not readers.resolve_key(self.inventory, key):
                    self.error(f"requirement {identifier}: `{key}` does not resolve in the matrix")

    def summary(self) -> dict:
        effects = self.inventory.get("effects", [])
        operations = self.inventory.get("operations", {})
        invariants = [invariant for effect in effects for invariant in effect.get("invariants", [])]
        tests = {(test.get("path"), test.get("test")) for effect in effects for test in effect.get("mutation_tests", [])}
        tests |= {(test.get("path"), test.get("test")) for invariant in invariants for test in invariant.get("tests", [])}
        added = {(test.get("path"), test.get("test")) for effect in effects
                 for test in effect.get("mutation_tests", []) + [t for i in effect.get("invariants", []) for t in i.get("tests", [])]
                 if test.get("status") == "added"}
        return {
            "protocols": len(self.inventory.get("protocols", [])),
            "value_bearing_protocols": sum(1 for item in self.inventory.get("protocols", []) if item.get("value_bearing")),
            "operations": len(operations),
            "value_bearing_operations": sum(1 for item in operations.values() if item.get("value_bearing")),
            "effects": len(effects),
            "effects_by_class": {name: sum(1 for effect in effects if effect.get("class") == name) for name in EFFECT_CLASSES},
            "effects_by_status": {name: sum(1 for effect in effects if effect.get("effect_status") == name) for name in EFFECT_STATUS},
            "invariants_by_status": {name: sum(1 for item in invariants if item.get("status") == name) for name in INVARIANT_STATUS},
            "cited_tests": len(tests),
            "added_tests": len(added),
            "defects": len(self.inventory.get("defects", [])),
            "suspension_switches": len(self.inventory.get("root_policy", {}).get("generic_suspension_switch", {}).get("found", [])),
        }

    def check_summary(self) -> None:
        actual = self.summary()
        if self.inventory.get("summary") != actual:
            self.error(f"summary differs from the recomputed counts: {json.dumps(actual, sort_keys=True)}")

    def check(self) -> list[str]:
        self.errors = []
        self.notes = []
        self.referenced_defects = set()
        self.check_shape()
        self.check_sources()
        if self.errors:
            return self.errors
        self.check_closed_lists()
        self.check_protocols()
        self.check_effects()
        self.check_operations()
        self.check_root_policy()
        self.check_defects()
        self.check_requirements()
        self.check_summary()
        return self.errors

    # ----------------------------------------------------------------- refresh

    def refresh(self) -> list[str]:
        """Rewrite the mechanical parts: `line` of every anchor that has one, census counts and the summary."""
        changes: list[str] = []
        for trail, node in readers.walk(self.inventory):
            if "line" not in node or not node.get("path") or not node.get("symbol"):
                continue
            text = self.tree.read(node["path"])
            if text is None:
                continue
            start = 0
            if node.get("within"):
                span = block_span(text, node["within"])
                if span is None:
                    continue
                start = span[0]
                text_scope = text[span[0] : span[1]]
            else:
                text_scope = text
            position = readers.symbol_position(text_scope, node["symbol"])
            if position is None:
                continue
            actual = line_of(text, start + position)
            if node["line"] != actual:
                changes.append(f"{trail}.line {node['line']} -> {actual}")
                node["line"] = actual
        census = self.inventory.get("root_policy", {}).get("suspension_census", {})
        listed = {item.get("path"): item for item in census.get("files", [])}
        for path, count in self.census_counts():
            if path in listed and listed[path].get("count") != count:
                changes.append(f"root_policy.suspension_census[{path}].count {listed[path].get('count')} -> {count}")
                listed[path]["count"] = count
        actual = self.summary()
        if self.inventory.get("summary") != actual:
            changes.append("summary")
            self.inventory["summary"] = actual
        return changes


def load(root: Path = ROOT) -> dict:
    return json.loads((root / INVENTORY).read_text(encoding="utf-8"))


def write_inventory(inventory: dict, root: Path = ROOT) -> None:
    """Write the matrix in the stable text form the plan inventories share (used by `--refresh` only)."""
    (root / INVENTORY).write_text(readers.dump(inventory), encoding="utf-8")


def show(inventory: dict) -> list[str]:
    lines = []
    for effect in inventory.get("effects", []):
        exposure = effect.get("exposure_after_erroneous_acceptance", {})
        answers = " ".join(f"{kind}={exposure.get(kind, {}).get('possible', '?')}" for kind in FAILURE_KINDS)
        enforced = sum(1 for item in effect.get("invariants", []) if item.get("status") in ("enforced", "enforced_by_absence"))
        lines.append(
            f"{effect.get('id', ''):<46} {effect.get('class', ''):<26} {effect.get('effect_status', ''):<12} "
            f"invariants={enforced}/{len(effect.get('invariants', []))} tests={len(effect.get('mutation_tests', []))} "
            f"defects={len(effect.get('defects', []))}  {answers}"
        )
    return lines


def show_defects(inventory: dict) -> list[str]:
    return [
        f"{defect.get('id', ''):<44} {defect.get('kind', ''):<24} owner={','.join(defect.get('owner', [])):<14} "
        f"{defect.get('path', '')}:{defect.get('line', '?')}  {defect.get('summary', '')}"
        for defect in inventory.get("defects", [])
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--show", action="store_true", help="print one line per effect row")
    parser.add_argument("--defects", action="store_true", help="print one line per open defect")
    parser.add_argument("--refresh", action="store_true", help="rewrite lines, census counts and the summary, then check")
    parser.add_argument("--strict-lines", action="store_true", help="fail when a recorded `line` is stale")
    args = parser.parse_args(argv)
    try:
        inventory = load()
    except (OSError, json.JSONDecodeError) as error:
        print(f"zk_economic_invariants: cannot read {INVENTORY}: {error}", file=sys.stderr)
        return 2
    if args.show:
        print("\n".join(show(inventory)))
        return 0
    if args.defects:
        print("\n".join(show_defects(inventory)))
        return 0
    checker = Checker(inventory, readers.Tree(), strict_lines=args.strict_lines)
    if args.refresh:
        changes = checker.refresh()
        write_inventory(inventory)
        for change in changes:
            print(f"refreshed {change}")
        print(f"zk_economic_invariants: refreshed {len(changes)} recorded facts")
    errors = checker.check()
    for note in checker.notes:
        print(f"note: {note}", file=sys.stderr)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"zk_economic_invariants: {len(errors)} inconsistencies", file=sys.stderr)
        return 1
    summary = inventory["summary"]
    print(
        f"zk_economic_invariants: {summary['effects']} effects of {summary['value_bearing_protocols']} value-bearing protocols "
        f"({summary['value_bearing_operations']} of {summary['operations']} operations), "
        f"{summary['cited_tests']} cited tests, {summary['defects']} open defects, "
        f"{summary['suspension_switches']} suspension switches match the tree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
