#!/usr/bin/env python3
"""Check the one-call and prepared operation contract fixtures without Rust.

`fixtures/zk/operation_v1/` holds the machine-readable operation contract of
`specs/zk_operation_contract.md` (`contract.json`, rendered from
`crates/iroha/src/client/operation_contract.rs`) and its single-operation
scenarios. The Rust test `tracked_contract_equals_the_rust_tables` compares
`contract.json` with the renderer byte for byte. This script checks what can be
checked from the files and the Rust source text alone, so that a port to an SDK
family starts from a set that is consistent by itself:

* the contract against its owners: the stage, state, event and error
  vocabularies of `fixtures/zk/workflow_v1/state_machine.json`; every batch
  bound against the defining expression of its constant or committed default in
  the data-model source and against `specs/zk_resource_contract.json`; the
  definite dispatch rows and the outcome-unknown evidence against
  `crates/iroha/src/client/transaction_dispatch_error.rs` and
  `crates/iroha/src/client.rs`;
* the contract's own shape: the call order and stages of the design memo, the
  fifteen shared error codes, the fields every bound error carries, the two
  provisional artifacts and their records, one default finality mode that is
  `authenticated`, the custody rules and the provisional review state;
* every scenario: schema, vocabulary of every op, option, token, code, stage,
  state and status; every scripted entry consumed by exactly one effect; the
  preconditions of every advanced call; the trace safety of every call (an
  unresolved identity is read first, re-dispatched only as identical bytes
  under explicit authorization after a fresh exact-absence read, never rebuilt
  or signed again; read-only recovery reads only; a cancelled or cancelling
  operation starts nothing; nothing is built or signed after a local
  verification failure or an upload refusal; a finality read follows exactly
  the state-resolved candidates of the authenticated mode; polls stay within
  the call's observation bound); the outcome each token implies; and the bound
  refusals recomputed from the request;
* coverage: every rule, category, call stage, durable state, status, op,
  dispatch class and finality mode appears in the scenario set, and
  cancellation is requested before and after a possible admission;
* the manifest lists exactly the scenario files and no pending file exists;
* the specification names every identifier of the contract and states its
  provisional review.

Prerequisites: Python 3.9+ standard library, run from a checkout. No environment
variable is read and nothing is written. Exit status 0 when the set is
consistent, 1 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import json
import operator
import re
import sys
from pathlib import Path

FIXTURES = "fixtures/zk/operation_v1"
REDUCER = "fixtures/zk/workflow_v1/state_machine.json"
SPEC = "specs/zk_operation_contract.md"
RESOURCE_CONTRACT = "specs/zk_resource_contract.json"
DISPATCH_SOURCE = "crates/iroha/src/client/transaction_dispatch_error.rs"
CLIENT_SOURCE = "crates/iroha/src/client.rs"
SOURCES = (DISPATCH_SOURCE, CLIENT_SOURCE)

PROVISIONAL_NOTE = "Provisional, pending plan-author review"
ONE_CALL = "execute_operation"
CALLS = ("prepare", "prove", "local_verify", "build", "sign", "submit", "await_finality")
PIPELINE_STAGES = ("plan", "prove", "local_verify", "build", "sign", "submit", "reconcile", "finality")
HANDLE_CALLS = ("run", "recover", "cancel", "progress")
JOURNAL_STAGES = ("load", "store")
SHARED_CODES = (
    "InvalidInput",
    "NonCanonicalEncoding",
    "UnsupportedOperation",
    "BindingMismatch",
    "ResourceLimitExceeded",
    "ProofInvalid",
    "AuthorizationDenied",
    "Expired",
    "ReplayRejected",
    "LocalResourceUnavailable",
    "EvidenceUnavailable",
    "SubmissionOutcomeUnknown",
    "FinalityPending",
    "Rejected",
    "CancelledBeforeSubmission",
)
JOURNAL_CODES = ("StorageCorrupted", "JournalConflict")
BOUND_ERROR_FIELDS = ("bound", "actual", "maximum")
ARTIFACTS = (("PreparedZkOperationV1", "prepare"), ("BuiltZkOperationV1", "build"))
BATCH_LIMITS = (
    "attachment.max_actions",
    "attachment.max_occurrences",
    "attachment.occurrence_max_bytes",
    "attachment.signed_frame_max_bytes",
    "transaction.max_decompressed_bytes",
    "transaction.max_tx_bytes",
)
FINALITY_MODES = ("authenticated", "torii_status")
DISPATCH_CLASSES = ("accepted", "already_known", "refused", "deferred", "not_dispatched", "ambiguous")
DEFINITE_RESULTS = {"AlreadyKnown": "already_known", "Refused": "refused", "Deferred": "deferred"}
CUSTODY_RULES = (
    "opaque_signer_handles",
    "secure_randomness",
    "no_private_material_upload",
    "public_artifacts_only",
    "zeroize_private_material",
)
RULES = (
    "prepare_refuses_over_bound_batches",
    "local_verification_before_signing",
    "persist_before_dispatch",
    "reconcile_read_only_first",
    "no_clock_closes_an_identity",
    "identical_bytes_only",
    "cancellation_never_recalls",
    "external_signature_verified_before_persisting",
    "custody_stays_local",
    "authenticated_finality_by_default",
    "dispatch_classified_by_closed_table",
)
CATEGORIES = (
    "happy_path",
    "finality_modes",
    "interruption_before_submission",
    "interruption_after_ambiguous_submission",
    "cancellation",
    "local_verification",
    "batch_bounds",
    "external_signing",
    "custody",
    "dispatch_classification",
)
OPS = ("execute",) + CALLS + ("recover", "cancel", "progress")
OPTIONS = {
    "observation_timeout_ms": int,
    "poll_interval_ms": int,
    "retransmit_identical_bytes": bool,
    "retry_rejected_step": bool,
}
# Script tokens: name -> whether the token takes an argument after the colon.
PLAIN, CODE, MATERIAL = "plain", "code", "material"
TOKENS = {
    "proofs": {"ok": PLAIN, "fail": CODE, "upload_required": MATERIAL, "interrupt": PLAIN},
    "local_verifications": {"ok": PLAIN, "invalid": PLAIN, "fail": CODE, "interrupt": PLAIN},
    "builds": {"ok": PLAIN, "fail": CODE, "interrupt": PLAIN},
    "signs": {"ok": PLAIN, "wrong_key": PLAIN, "wrong_bytes": PLAIN, "fail": CODE, "interrupt": PLAIN},
    "dispatches": {
        "accepted": PLAIN,
        "already_known": PLAIN,
        "refused": PLAIN,
        "deferred": PLAIN,
        "not_dispatched": CODE,
        "ambiguous": PLAIN,
        "interrupt": PLAIN,
    },
    "statuses": {
        "applied": PLAIN,
        "rejected": PLAIN,
        "expired": PLAIN,
        "observed": PLAIN,
        "absent": PLAIN,
        "read_failed": PLAIN,
        "unbound_response": PLAIN,
        "interrupt": PLAIN,
    },
    "finality_proofs": {"verified": PLAIN, "unavailable": PLAIN, "mismatch": PLAIN, "interrupt": PLAIN},
}
# The script list each effect consumes.
EFFECT_LISTS = {
    "prove": "proofs",
    "local_verify": "local_verifications",
    "build": "builds",
    "sign": "signs",
    "dispatch": "dispatches",
    "status": "statuses",
    "finality": "finality_proofs",
}
EFFECT = re.compile(r"^(?:(prove|local_verify|build|sign|dispatch|status|finality):([1-8])|sleep:(\d+))$")
READ_EFFECTS = ("status", "finality", "sleep")
# The only effects each advanced or handle call may cause; `execute` may cause any.
OP_EFFECTS = {
    "prepare": (),
    "prove": ("prove",),
    "local_verify": ("local_verify",),
    "build": ("build",),
    "sign": ("sign",),
    "submit": ("dispatch",),
    "await_finality": READ_EFFECTS,
    "recover": READ_EFFECTS,
    "cancel": (),
    "progress": (),
}
ATTACHMENT_KINDS = ("proof", "key_material")
SIGNERS = ("handle", "external")
RESULT_FIELDS = ("error", "stage", "action_index", "bound", "actual", "maximum", "resumable", "has_transaction_identity")
UNRESOLVED_CODES = {"SubmissionOutcomeUnknown": ("submitting", "outcome_unknown"), "FinalityPending": ("pending",)}
LABEL = re.compile(r"^[a-z0-9_]{1,96}$")


def ids(entries: list) -> list:
    """Identifiers of a vocabulary given as strings or as objects with `id`."""
    return [entry.get("id") if isinstance(entry, dict) else entry for entry in entries]


# ---------------------------------------------------------------------- Rust source reading
_COMMENT = re.compile(r"//[^\n]*")
_LITERAL = re.compile(r"\b(\d[\d_]*?)_?(?:u8|u16|u32|u64|u128|usize)?\b")
_NAME = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\(\s*\))?")
_OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv}


def rust_definition(text: str, symbol: str, anchor: str | None = None) -> str | None:
    """The defining expression of `const SYMBOL: T = EXPR;` or the body of `fn SYMBOL() -> T { EXPR }`.

    With an anchor, only the text after the first occurrence of the anchor is searched.
    """
    if anchor is not None:
        start = text.find(anchor)
        if start < 0:
            return None
        text = text[start:]
    name = re.escape(symbol)
    constant = re.search(rf"\bconst\s+{name}\s*:\s*[^=;]+=\s*(.*?);", text, re.S)
    if constant:
        return _COMMENT.sub("", constant.group(1)).strip()
    function = re.search(rf"\bfn\s+{name}\s*\(\s*\)\s*->\s*[A-Za-z0-9_:<>]+\s*\{{(.*?)\n\s*\}}", text, re.S)
    if function:
        return _COMMENT.sub("", function.group(1)).strip()
    return None


def evaluate(expression: str, text: str, anchor: str | None = None, depth: int = 0) -> int:
    """Evaluate the integer arithmetic of a Rust constant expression textually.

    Literals may carry `_` separators and an integer suffix; `nonzero!(..)` is read as its
    argument; a name stands for another constant or argument-free function of the same text.
    Anything else raises `ValueError`.
    """
    if depth > 8:
        raise ValueError("constant definitions nest too deeply")
    body = re.sub(r"\bnonzero!\s*\(", "(", _COMMENT.sub("", expression))

    def literal(match: re.Match) -> str:
        return match.group(1).replace("_", "")

    body = _LITERAL.sub(literal, body)

    def name(match: re.Match) -> str:
        definition = rust_definition(text, match.group(1), anchor)
        if definition is None:
            raise ValueError(f"no definition of `{match.group(1)}`")
        return f"({evaluate(definition, text, anchor, depth + 1)})"

    body = _NAME.sub(name, body)
    tree = ast.parse(body, mode="eval")

    def value(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
            return _OPERATORS[type(node.op)](value(node.left), value(node.right))
        raise ValueError(f"`{expression}` is not integer arithmetic")

    return value(tree)


def definite_rows(text: str) -> list:
    """The rows of `DEFINITE_DISPATCH_ROWS` as (status, envelope, reject, details, class) tuples."""
    start = text.find("DEFINITE_DISPATCH_ROWS: &[DefiniteDispatchRow]")
    end = text.find("\n};", start)
    if start < 0 or end < 0:
        return []
    rows = re.findall(
        r'definite\(\s*(\d+)\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*(true|false)\s*,\s*([A-Za-z]+)\s*,?\s*\)',
        text[start:end],
    )
    return [
        (int(status), envelope, reject, details == "true", DEFINITE_RESULTS.get(result, result))
        for status, envelope, reject, details, result in rows
    ]


def string_constant(text: str, symbol: str) -> str | None:
    match = re.search(rf"\bconst\s+{re.escape(symbol)}\s*:\s*&str\s*=\s*\"([^\"]*)\"\s*;", text)
    return match.group(1) if match else None


class Checker:
    """Collects every inconsistency of one fixture tree."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.problems: list[str] = []
        self.seen = {
            "rules": set(),
            "categories": set(),
            "states": set(),
            "statuses": set(),
            "ops": set(),
            "error_stages": set(),
            "dispatch_classes": set(),
            "finality_modes": set(),
            "cancel_before": False,
            "cancel_after": False,
        }

    def problem(self, where: str, message: str) -> None:
        self.problems.append(f"{where}: {message}")

    def load(self, relative: str):
        path = self.root / relative
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            self.problem(relative, f"cannot be read as JSON: {error}")
            return None

    def read(self, relative: str) -> str | None:
        try:
            return (self.root / relative).read_text(encoding="utf-8")
        except OSError as error:
            self.problem(relative, f"cannot be read: {error}")
            return None

    # ------------------------------------------------------------------ contract
    def check_contract(self, contract: dict, machine: dict) -> dict:
        where = f"{FIXTURES}/contract.json"
        if contract.get("schema") != "iroha.zk_operation.contract.v1":
            self.problem(where, "unknown schema")
        review = contract.get("review", {})
        if review.get("state") != "provisional_pending_plan_author_review":
            self.problem(where, "the review state must stay provisional until the plan author reviews it")
        if not str(review.get("decisions", "")).endswith(".md"):
            self.problem(where, "the provisional review must name its decisions file")
        if contract.get("specification") != SPEC:
            self.problem(where, f"`specification` must be {SPEC}")

        stages = ids(machine.get("stages", []))
        events = ids(machine.get("transaction_events", []))
        states = machine.get("transaction_states", [])
        codes = ids(machine.get("error_codes", []))
        shared = [entry.get("id") for entry in machine.get("error_codes", []) if entry.get("shared_operation_code")]
        transitions = machine.get("transaction_transitions", [])

        one_call = contract.get("one_call", {})
        if one_call.get("id") != ONE_CALL or one_call.get("runs") != list(CALLS) or one_call.get("durable") is not True:
            self.problem(where, f"`one_call` must be the durable `{ONE_CALL}` running {', '.join(CALLS)}")
        calls = contract.get("calls", [])
        if ids(calls) != list(CALLS):
            self.problem(where, "calls differ from the memo order prepare, prove, local_verify, build, sign, submit, await_finality")
        reported = []
        applied = []
        for call in calls:
            for stage in call.get("stages", []):
                if stage not in stages:
                    self.problem(where, f"call `{call.get('id')}` reports unknown stage `{stage}`")
                reported.append(stage)
            for event in call.get("events", []):
                if event not in events:
                    self.problem(where, f"call `{call.get('id')}` applies unknown event `{event}`")
                applied.append(event)
        if tuple(reported) != PIPELINE_STAGES:
            self.problem(where, f"the calls must report the pipeline stages {', '.join(PIPELINE_STAGES)} in order")
        handle = contract.get("handle_calls", [])
        if ids(handle) != list(HANDLE_CALLS):
            self.problem(where, f"handle calls must be {', '.join(HANDLE_CALLS)}")
        for entry in handle:
            for stage in entry.get("stages", []):
                if stage not in stages:
                    self.problem(where, f"handle call `{entry.get('id')}` reports unknown stage `{stage}`")
        if contract.get("journal_stages") != list(JOURNAL_STAGES):
            self.problem(where, f"journal stages must be {', '.join(JOURNAL_STAGES)}")
        reducer = contract.get("reducer", {})
        if reducer.get("table") != REDUCER:
            self.problem(where, f"the reducer must be {REDUCER}")
        if reducer.get("initial_state") != "planned" or "planned" not in ids(states):
            self.problem(where, "the reducer's initial state must be `planned`")
        applied.extend(reducer.get("cancel_events", []))
        for event in events:
            if event not in applied:
                self.problem(where, f"no call applies reducer event `{event}`")

        durable = contract.get("durable_states", [])
        expected = [state for state in states if state.get("id") != "planned"]
        if [(s.get("id"), s.get("may_still_commit"), s.get("holds_signed_bytes")) for s in durable] != [
            (s.get("id"), s.get("may_still_commit"), s.get("holds_signed_bytes")) for s in expected
        ]:
            self.problem(where, "durable states differ from the reducer's states after `planned`")

        if tuple(ids(contract.get("error_codes", []))) != SHARED_CODES or tuple(shared) != SHARED_CODES:
            self.problem(where, "error codes differ from the fifteen shared operation codes")
        for entry in contract.get("error_codes", []):
            if not entry.get("meaning"):
                self.problem(where, f"error code `{entry.get('id')}` has no meaning")
        journal_codes = contract.get("journal_error_codes", [])
        if tuple(journal_codes) != JOURNAL_CODES or any(code not in codes or code in shared for code in journal_codes):
            self.problem(where, "journal error codes must be the journal extensions StorageCorrupted and JournalConflict")
        fields = {field.get("name"): field for field in contract.get("error_fields", [])}
        for name in ("code", "stage", "action_index", "bound", "actual", "maximum", "transaction", "detail", "progress"):
            if name not in fields:
                self.problem(where, f"error field `{name}` is missing")
        for name in ("code", "stage", "detail"):
            if fields.get(name, {}).get("always") is not True:
                self.problem(where, f"every error must carry `{name}`")
        for name in BOUND_ERROR_FIELDS:
            if fields.get(name, {}).get("required_for") != ["ResourceLimitExceeded"]:
                self.problem(where, f"`ResourceLimitExceeded` must carry `{name}`")
        for code in ("SubmissionOutcomeUnknown", "FinalityPending"):
            if code not in fields.get("transaction", {}).get("required_for", []):
                self.problem(where, f"`{code}` must carry the transaction identity")
        for field in fields.values():
            for code in field.get("required_for", []):
                if code not in codes:
                    self.problem(where, f"error field `{field.get('name')}` names unknown code `{code}`")

        self.check_artifacts(where, contract)
        batch = contract.get("batch", {})
        if batch != {
            "atomicity": "one_signed_transaction",
            "split": "never",
            "over_bound": "ResourceLimitExceeded",
            "over_bound_stage": "plan",
        }:
            self.problem(where, "a batch must be one signed transaction, never split, refused over bound at `plan`")
        self.check_limits(where, contract, stages)

        local = contract.get("local_verification", {})
        if (
            local.get("failure_code") != "ProofInvalid"
            or local.get("failure_stage") != "local_verify"
            or local.get("failure_dispatches") is not False
            or local.get("failure_returns_to") != "prepared"
            or local.get("authority") != "diagnostic_only"
        ):
            self.problem(where, "a local verification failure must be a diagnostic ProofInvalid at local_verify that dispatches nothing")
        custody = contract.get("custody", {})
        material = custody.get("private_material", [])
        if not material or len(material) != len(set(material)):
            self.problem(where, "private material must be a non-empty set of kinds")
        if tuple(ids(custody.get("rules", []))) != CUSTODY_RULES:
            self.problem(where, f"custody rules must be {', '.join(CUSTODY_RULES)}")
        if custody.get("upload_refusal_code") != "UnsupportedOperation":
            self.problem(where, "an upload of private material must be refused with UnsupportedOperation")
        for rule in custody.get("rules", []):
            if not rule.get("statement"):
                self.problem(where, f"custody rule `{rule.get('id')}` has no statement")

        modes = contract.get("finality_modes", [])
        if tuple(ids(modes)) != FINALITY_MODES:
            self.problem(where, f"finality modes must be {', '.join(FINALITY_MODES)}")
        defaults = [mode.get("id") for mode in modes if mode.get("default")]
        if defaults != ["authenticated"]:
            self.problem(where, "exactly one default finality mode must exist, and it must be `authenticated`")
        for mode in modes:
            authenticated = mode.get("id") == "authenticated"
            if mode.get("trusts_torii") is authenticated or mode.get("closes_on_expired_status") is authenticated:
                self.problem(where, f"finality mode `{mode.get('id')}` trusts the wrong source")
            if authenticated and "SumeragiFinalityVerifier" not in str(mode.get("closing_evidence")):
                self.problem(where, "the authenticated mode must close on SumeragiFinalityVerifier evidence")

        self.check_dispatch(where, contract.get("dispatch_classification", {}), events, transitions)
        rules = contract.get("rules", [])
        if tuple(ids(rules)) != RULES:
            self.problem(where, "rules differ from the contract's rule set")
        for rule in rules:
            if not rule.get("statement"):
                self.problem(where, f"rule `{rule.get('id')}` has no statement")
        return {
            "stages": stages,
            "states": [state.get("id") for state in durable],
            "may_still_commit": [state.get("id") for state in durable if state.get("may_still_commit")],
            "statuses": ids(machine.get("workflow_statuses", [])),
            "evidence": machine.get("attempt_evidence", []),
            "codes": list(SHARED_CODES) + list(JOURNAL_CODES),
            "call_stages": {call.get("id"): call.get("stages", []) for call in calls},
            "handle_stages": {entry.get("id"): entry.get("stages", []) for entry in handle},
            "limits": {limit.get("id"): limit for limit in contract.get("batch_limits", [])},
            "material": material,
            "rules": ids(rules),
            "classes": ids(contract.get("dispatch_classification", {}).get("classes", [])),
            "class_codes": {
                entry.get("id"): entry.get("error_code")
                for entry in contract.get("dispatch_classification", {}).get("classes", [])
            },
        }

    def check_artifacts(self, where: str, contract: dict) -> None:
        artifacts = contract.get("artifacts", [])
        if [(artifact.get("name"), artifact.get("returned_by")) for artifact in artifacts] != list(ARTIFACTS):
            self.problem(where, "the artifacts must be PreparedZkOperationV1 from prepare and BuiltZkOperationV1 from build")
        records = {record.get("name"): record for record in contract.get("records", [])}
        for artifact in artifacts + list(records.values()):
            names = [field.get("name") for field in artifact.get("fields", [])]
            if not names or len(names) != len(set(names)):
                self.problem(where, f"`{artifact.get('name')}` needs uniquely named fields")
            for field in artifact.get("fields", []):
                if not field.get("type") or not field.get("meaning"):
                    self.problem(where, f"`{artifact.get('name')}.{field.get('name')}` needs a type and a meaning")
                for record in re.findall(r"\b([A-Z][A-Za-z]*V1)\b", str(field.get("type"))):
                    if record.endswith(("SlotV1", "EntryV1", "SnapshotV1")) and record not in records:
                        self.problem(where, f"`{artifact.get('name')}.{field.get('name')}` names undefined record `{record}`")
        fields = {artifact.get("name"): [field.get("name") for field in artifact.get("fields", [])] for artifact in artifacts}
        for name in ("intent_digest", "statements", "attachment_slots", "resource_quote", "parameters"):
            if name not in fields.get("PreparedZkOperationV1", []):
                self.problem(where, f"PreparedZkOperationV1 lacks `{name}`")
        for name in ("signing_bytes", "signing_prehash", "entrypoint_hash"):
            if name not in fields.get("BuiltZkOperationV1", []):
                self.problem(where, f"BuiltZkOperationV1 lacks `{name}`")

    def check_limits(self, where: str, contract: dict, stages: list) -> None:
        limits = contract.get("batch_limits", [])
        if tuple(ids(limits)) != BATCH_LIMITS:
            self.problem(where, f"batch limits must be {', '.join(BATCH_LIMITS)} in checking order")
        resource = self.load(RESOURCE_CONTRACT) or {}
        bounds = {bound.get("id"): bound for bound in resource.get("bounds", [])}
        texts: dict[str, str | None] = {}
        for limit in limits:
            identifier = limit.get("id")
            for stage in limit.get("checked_at", []):
                if stage not in stages:
                    self.problem(where, f"bound `{identifier}` is checked at unknown stage `{stage}`")
            if "plan" not in limit.get("checked_at", []):
                self.problem(where, f"bound `{identifier}` must be checked at `plan`")
            if not isinstance(limit.get("maximum"), int) or limit.get("maximum") <= 0:
                self.problem(where, f"bound `{identifier}` needs a positive maximum")
                continue
            bound = bounds.get(identifier)
            if bound is None:
                self.problem(where, f"bound `{identifier}` is not a bound of {RESOURCE_CONTRACT}")
            else:
                owner = bound.get("owner", {})
                if bound.get("value") != limit.get("maximum"):
                    self.problem(where, f"bound `{identifier}` differs from {RESOURCE_CONTRACT}: {limit.get('maximum')} != {bound.get('value')}")
                if owner.get("path") != limit.get("path") or owner.get("symbol") != limit.get("symbol"):
                    self.problem(where, f"bound `{identifier}` names another owner than {RESOURCE_CONTRACT}")
                if (bound.get("source") == "committed") != (limit.get("committed") is True):
                    self.problem(where, f"bound `{identifier}` is committed in {RESOURCE_CONTRACT} exactly when it is committed here")
            path = limit.get("path", "")
            if path not in texts:
                texts[path] = self.read(path)
            text = texts[path]
            if text is None:
                continue
            anchor = "pub mod transaction {" if limit.get("committed") else None
            definition = rust_definition(text, str(limit.get("symbol")), anchor)
            try:
                value = evaluate(definition, text, anchor) if definition is not None else None
            except (SyntaxError, ValueError) as error:
                self.problem(path, f"`{limit.get('symbol')}` cannot be evaluated: {error}")
                continue
            if value is None:
                self.problem(path, f"`{limit.get('symbol')}` is not defined")
            elif value != limit.get("maximum"):
                self.problem(where, f"bound `{identifier}` differs from the source: {limit.get('maximum')} != {value} ({path}: {limit.get('symbol')})")

    def check_dispatch(self, where: str, dispatch: dict, events: list, transitions: list) -> None:
        classes = dispatch.get("classes", [])
        if tuple(ids(classes)) != DISPATCH_CLASSES:
            self.problem(where, f"dispatch classes must be {', '.join(DISPATCH_CLASSES)}")
        for entry in classes:
            code = entry.get("error_code")
            if code is not None and code not in SHARED_CODES:
                self.problem(where, f"dispatch class `{entry.get('id')}` names unknown code `{code}`")
            event = entry.get("event")
            if event not in events or not any(
                row.get("from") == "submitting" and row.get("event") == event for row in transitions
            ):
                self.problem(where, f"dispatch class `{entry.get('id')}` names no reducer event from `submitting`")
        if dispatch.get("acknowledged_statuses") != [200, 202]:
            self.problem(where, "only HTTP 200 and 202 acknowledge a dispatch")
        source = self.read(DISPATCH_SOURCE) or ""
        rows = [
            (row.get("status"), row.get("envelope_code"), row.get("reject_code"), row.get("details_repeat_reject_code"), row.get("class"))
            for row in dispatch.get("definite_rows", [])
        ]
        expected = definite_rows(source)
        if not expected:
            self.problem(DISPATCH_SOURCE, "DEFINITE_DISPATCH_ROWS cannot be read")
        elif rows != expected:
            self.problem(where, "definite_rows differ from DEFINITE_DISPATCH_ROWS of the submission owner")
        client = self.read(CLIENT_SOURCE) or ""
        unknown = dispatch.get("outcome_unknown_evidence", {})
        expected_unknown = {
            "envelope_code": string_constant(client, "TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE"),
            "reject_code": string_constant(client, "TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE"),
            "identity_headers": [
                string_constant(client, "TRANSACTION_ENTRYPOINT_HASH_HEADER"),
                string_constant(client, "SIGNED_TRANSACTION_HASH_HEADER"),
            ],
        }
        for key, value in expected_unknown.items():
            if unknown.get(key) != value:
                self.problem(where, f"outcome-unknown evidence `{key}` differs from {CLIENT_SOURCE}")
        if unknown.get("status") != 503 or unknown.get("class") != "ambiguous":
            self.problem(where, "outcome-unknown evidence must be HTTP 503 and classified ambiguous")
        if any(row[2] == unknown.get("reject_code") for row in rows):
            self.problem(where, "an outcome-unknown claim must never be a definite row")
        bound = rust_definition(client, "TRANSACTION_SUBMISSION_RESPONSE_MAX_BYTES")
        try:
            maximum = evaluate(bound, client) if bound is not None else None
        except (SyntaxError, ValueError):
            maximum = None
        if maximum is None or dispatch.get("max_response_bytes") != maximum:
            self.problem(where, f"max_response_bytes differs from {CLIENT_SOURCE}")
        closure = ids(dispatch.get("identity_closure", []))
        for rule in ("no_clock_closes_an_identity", "identical_bytes_only"):
            if rule not in closure:
                self.problem(where, f"identity closure must state `{rule}`")

    # ------------------------------------------------------------------ scenarios
    @staticmethod
    def first_violation(actions: list, limits: dict):
        """(bound, action_index, actual, maximum, exact) of the first bound a request crosses."""
        def maximum(identifier: str) -> int:
            return limits.get(identifier, {}).get("maximum", 0)

        if len(actions) > maximum("attachment.max_actions"):
            return ("attachment.max_actions", maximum("attachment.max_actions"), len(actions), maximum("attachment.max_actions"), True)
        slots = [(index, slot) for index, action in enumerate(actions) for slot in action.get("attachments", [])]
        if len(slots) > maximum("attachment.max_occurrences"):
            index = slots[maximum("attachment.max_occurrences")][0]
            return ("attachment.max_occurrences", index, len(slots), maximum("attachment.max_occurrences"), True)
        for index, slot in slots:
            if slot.get("length", 0) > maximum("attachment.occurrence_max_bytes"):
                return ("attachment.occurrence_max_bytes", index, slot.get("length"), maximum("attachment.occurrence_max_bytes"), True)
        total = sum(slot.get("length", 0) for _, slot in slots)
        if total > maximum("attachment.signed_frame_max_bytes"):
            # The frame also holds the descriptor and framing: the sum is a lower bound.
            return ("attachment.signed_frame_max_bytes", None, total, maximum("attachment.signed_frame_max_bytes"), False)
        return None

    def check_request(self, where: str, request: dict, vocabulary: dict) -> dict:
        actions = request.get("actions")
        if not isinstance(actions, list) or not actions:
            self.problem(where, "the request needs at least one action")
            actions = []
        for action in actions:
            slots = action.get("attachments") if isinstance(action, dict) else None
            if not isinstance(slots, list):
                self.problem(where, "every action lists its attachment slots")
                continue
            for slot in slots:
                if slot.get("kind") not in ATTACHMENT_KINDS:
                    self.problem(where, f"unknown attachment kind `{slot.get('kind')}`")
                if type(slot.get("length")) is not int or slot.get("length") <= 0:
                    self.problem(where, "an attachment slot needs a positive length")
        if request.get("signer", "handle") not in SIGNERS:
            self.problem(where, f"unknown signer `{request.get('signer')}`")
        mode = request.get("finality", "authenticated")
        if mode not in FINALITY_MODES:
            self.problem(where, f"unknown finality mode `{mode}`")
        self.seen["finality_modes"].add(mode)
        return {
            "actions": len(actions),
            "slots": sum(len(action.get("attachments", [])) for action in actions if isinstance(action, dict)),
            "violation": self.first_violation(actions, vocabulary["limits"]),
            "mode": mode,
        }

    def check_script(self, where: str, script: dict, vocabulary: dict) -> None:
        for name, entries in script.items():
            allowed = TOKENS.get(name)
            if allowed is None:
                self.problem(where, f"unknown script list `{name}`")
                continue
            for token in entries:
                head, _, argument = str(token).partition(":")
                kind = allowed.get(head)
                if kind is None:
                    self.problem(where, f"unknown `{name}` token `{token}`")
                elif kind == PLAIN and argument:
                    self.problem(where, f"`{name}` token `{token}` takes no argument")
                elif kind == CODE and argument not in vocabulary["codes"]:
                    self.problem(where, f"unknown error code `{argument}`")
                elif kind == MATERIAL and argument not in vocabulary["material"]:
                    self.problem(where, f"`{token}` names no private material of the contract")
                if name == "dispatches" and head in DISPATCH_CLASSES:
                    self.seen["dispatch_classes"].add(head)

    def check_result(self, where: str, op: str, result, vocabulary: dict) -> None:
        if isinstance(result, dict):
            if result.get("error") not in vocabulary["codes"]:
                self.problem(where, f"unknown error code `{result.get('error')}`")
            stage = result.get("stage")
            allowed = set(JOURNAL_STAGES)
            if op == "execute":
                allowed |= set(PIPELINE_STAGES) | {"cancel"}
            elif op in vocabulary["call_stages"]:
                allowed |= set(vocabulary["call_stages"][op])
            else:
                allowed |= set(vocabulary["handle_stages"].get(op, []))
            if stage not in allowed:
                self.problem(where, f"`{op}` cannot report stage `{stage}`")
            else:
                self.seen["error_stages"].add(stage)
            unknown = set(result) - set(RESULT_FIELDS)
            if unknown:
                self.problem(where, f"unknown result fields {sorted(unknown)}")
            bound = [field for field in BOUND_ERROR_FIELDS if field in result]
            if result.get("error") == "ResourceLimitExceeded":
                if len(bound) != len(BOUND_ERROR_FIELDS):
                    self.problem(where, "ResourceLimitExceeded must carry bound, actual and maximum")
                elif result["actual"] <= result["maximum"]:
                    self.problem(where, "ResourceLimitExceeded needs an actual value above the maximum")
            elif bound or "action_index" in result:
                self.problem(where, "only ResourceLimitExceeded carries bound fields")
            if result.get("error") in UNRESOLVED_CODES and result.get("has_transaction_identity") is False:
                self.problem(where, f"`{result.get('error')}` must carry the transaction identity")
        elif result not in ("completed", "ok", "interrupted"):
            self.problem(where, f"unknown result `{result}`")

    def walk(self, where: str, op: str, call: dict, context: dict) -> tuple:
        """Consume the script along the trace and return the outcome its tokens imply.

        The outcome is ("interrupted",), ("error", code, stage), ("closed", outcome) or None.
        """
        effects = call.get("expect", {}).get("effects", [])
        script = call.get("script", {})
        options = call.get("options", {})
        stored = context["stored"]
        cursor = {name: 0 for name in EFFECT_LISTS.values()}
        implied = None
        previous = None
        for position, effect in enumerate(effects):
            match = EFFECT.match(str(effect))
            if match is None:
                self.problem(where, f"malformed effect `{effect}`")
                continue
            last = position == len(effects) - 1
            following = effects[position + 1] if not last else None
            if match.group(3) is not None:
                interval = options.get("poll_interval_ms", 1000)
                if previous is None or previous[0] != "status" or not str(following).startswith("status:"):
                    self.problem(where, "a sleep must separate two status reads")
                if int(match.group(3)) != interval:
                    self.problem(where, f"`{effect}` differs from the poll interval {interval}")
                continue
            kind, ordinal = match.group(1), int(match.group(2))
            if ordinal != context["ordinal"]:
                self.problem(where, f"`{effect}` names identity {ordinal}; only identity {context['ordinal']} exists")
            if kind not in OP_EFFECTS.get(op, (kind,)):
                self.problem(where, f"`{op}` cannot cause `{effect}`")
            tokens = script.get(EFFECT_LISTS[kind], [])
            index = cursor[EFFECT_LISTS[kind]]
            if index >= len(tokens):
                self.problem(where, f"`{effect}` consumes no scripted `{EFFECT_LISTS[kind]}` entry")
                previous = (kind, None)
                continue
            token = str(tokens[index])
            cursor[EFFECT_LISTS[kind]] += 1
            head, _, argument = token.partition(":")

            def end(outcome: tuple) -> None:
                nonlocal implied
                if not last:
                    self.problem(where, f"`{effect}` ({token}) must end the call, but `{following}` follows")
                implied = outcome

            def then(expected: str, allowed_last: bool) -> None:
                if last and not allowed_last:
                    self.problem(where, f"`{effect}` ({token}) cannot end `{op}`")
                elif not last and not str(following).startswith(expected):
                    self.problem(where, f"`{effect}` ({token}) must be followed by `{expected}{ordinal}`, not `{following}`")

            stops = op != "execute" or call.get("interrupt_after") is not None
            if head == "interrupt":
                if kind == "dispatch":
                    # The bytes may have left: the next call treats the outcome as unknown.
                    context["possible_admission"] = True
                end(("interrupted",))
            elif kind == "prove":
                if head == "ok":
                    then("local_verify:", stops)
                elif head == "fail":
                    end(("error", argument, "prove"))
                else:
                    end(("error", "UnsupportedOperation", "prove"))
            elif kind == "local_verify":
                if not (previous == ("prove", "ok") or (previous is None and op == "local_verify")):
                    self.problem(where, f"`{effect}` must verify the proof of the immediately preceding prove")
                if head == "ok":
                    then("build:", stops)
                elif head == "invalid":
                    end(("error", "ProofInvalid", "local_verify"))
                else:
                    end(("error", argument, "local_verify"))
            elif kind == "build":
                if not (previous == ("local_verify", "ok") or (previous is None and op == "build")):
                    self.problem(where, f"`{effect}` must follow a successful local verification")
                if head == "ok":
                    then("sign:", stops)
                else:
                    end(("error", argument, "build"))
            elif kind == "sign":
                if not (previous == ("build", "ok") or (previous is None and stored == "ready_to_sign")):
                    self.problem(where, f"`{effect}` must sign the persisted payload of a successful build")
                if head == "ok":
                    then("dispatch:", stops)
                elif head in ("wrong_key", "wrong_bytes"):
                    end(("error", "BindingMismatch", "sign"))
                else:
                    end(("error", argument, "sign"))
            elif kind == "dispatch":
                first = previous == ("sign", "ok") or (previous is None and stored == "signed")
                if not first:
                    if context["status"] in ("cancelling", "cancelled"):
                        self.problem(where, f"a {context['status']} operation re-dispatched `{effect}`")
                    if not options.get("retransmit_identical_bytes"):
                        self.problem(where, f"`{effect}` re-dispatched an unresolved identity without authorization")
                    if previous != ("status", "absent"):
                        self.problem(where, f"`{effect}` was not preceded by a fresh exact-absence read")
                admitted_before = context["possible_admission"]
                if head in ("accepted", "already_known", "ambiguous"):
                    context["possible_admission"] = True
                    then("status:", op == "submit")
                elif head in ("refused", "deferred", "not_dispatched") and not admitted_before:
                    # The class's own code, or for a failure before any byte left the code of its cause.
                    code = argument if head == "not_dispatched" else context["class_codes"].get(head)
                    if code is None:
                        self.problem(where, f"dispatch class `{head}` names no code in contract.json")
                    end(("error", code, "submit"))
                else:
                    then("status:", op == "submit")
            elif kind == "status":
                mode = context["mode"]
                if head in ("applied", "rejected") and mode == "authenticated":
                    then("finality:", False)
                elif head in ("applied", "rejected", "expired") and mode == "torii_status":
                    end(("closed", "applied" if head == "applied" else "rejected"))
                elif str(following).startswith("finality:"):
                    self.problem(where, f"`{following}` follows `{effect}` ({token}), which selects no candidate")
            elif kind == "finality":
                if context["mode"] != "authenticated":
                    self.problem(where, f"`{effect}` is a finality read in the torii_status mode")
                if previous not in (("status", "applied"), ("status", "rejected")):
                    self.problem(where, f"`{effect}` must follow a state-resolved candidate")
                if head == "verified":
                    end(("closed", previous[1] if previous else "applied"))
                elif head == "unavailable":
                    end(("error", "EvidenceUnavailable", "finality"))
                else:
                    end(("error", "BindingMismatch", "finality"))
            previous = (kind, head)
        for name, tokens in script.items():
            if name in cursor and cursor[name] != len(tokens):
                self.problem(where, f"scripted `{name}` entry {cursor[name] + 1} is not consumed")
        # The local observation bound limits the polls of one call; it never closes an identity.
        slept = sum(int(match.group(3)) for match in map(EFFECT.match, map(str, effects)) if match and match.group(3))
        if slept > options.get("observation_timeout_ms", 0):
            self.problem(where, f"the call observes {slept} ms, beyond its observation bound")
        return implied

    def check_call(self, where: str, call: dict, context: dict, vocabulary: dict) -> None:
        op = call.get("op")
        if op not in OPS:
            self.problem(where, f"unknown op `{op}`")
            return
        self.seen["ops"].add(op)
        options = call.get("options", {})
        for key, value in options.items():
            if key not in OPTIONS or type(value) is not OPTIONS[key]:
                self.problem(where, f"unknown or malformed option `{key}`")
        self.check_script(where, call.get("script", {}), vocabulary)
        interrupt_after = call.get("interrupt_after")
        if interrupt_after is not None and interrupt_after not in vocabulary["states"]:
            self.problem(where, f"`interrupt_after` names unknown state `{interrupt_after}`")
        expect = call.get("expect")
        if not isinstance(expect, dict):
            self.problem(where, "missing `expect`")
            return
        result = expect.get("result")
        self.check_result(where, op, result, vocabulary)
        effects = expect.get("effects")
        if not isinstance(effects, list):
            self.problem(where, "`effects` must list the ordered external effects")
            expect["effects"] = effects = []

        stored = context["state"]
        status = context["status"]
        # Preconditions of the advanced and handle calls.
        last_op, last_result = context["last"]
        preconditions = {
            "prepare": stored is None,
            "prove": stored in ("prepared", "proving"),
            "local_verify": last_op == "prove" and last_result == "ok",
            "build": last_op == "local_verify" and last_result == "ok",
            "sign": stored == "ready_to_sign",
            "submit": stored == "signed",
            "await_finality": stored in vocabulary["may_still_commit"],
            "recover": stored is not None,
            "cancel": stored is not None,
            "progress": stored is not None,
        }
        if not preconditions.get(op, True):
            self.problem(where, f"`{op}` is not valid after state `{stored}` and the previous call `{last_op}`")
        if status in ("completed", "cancelled", "failed") and effects:
            self.problem(where, f"a {status} operation caused `{effects[0]}`")
        if status == "cancelling":
            for effect in effects:
                if not str(effect).startswith(READ_EFFECTS):
                    self.problem(where, f"a cancelling operation caused `{effect}`")
        if op == "recover":
            for effect in effects:
                if not str(effect).startswith(READ_EFFECTS):
                    self.problem(where, f"read-only recovery caused `{effect}`")
        if stored in vocabulary["may_still_commit"] and op in ("execute", "await_finality", "recover") and effects:
            if not str(effects[0]).startswith("status:"):
                self.problem(where, f"resume of an unresolved identity started with `{effects[0]}`")

        context["stored"] = stored
        implied = self.walk(where, op, call, context)
        state = expect.get("state")
        # The bound refusal is recomputed from the request.
        violation = context["request"]["violation"]
        if stored is None and op in ("prepare", "execute"):
            if violation is not None:
                bound, index, actual, maximum, exact = violation
                if not isinstance(result, dict) or result.get("error") != "ResourceLimitExceeded" or result.get("stage") != "plan":
                    self.problem(where, f"the request crosses `{bound}` and must be refused with ResourceLimitExceeded at `plan`")
                else:
                    if result.get("bound") != bound or result.get("maximum") != maximum:
                        self.problem(where, f"the refusal must name bound `{bound}` with maximum {maximum}")
                    if result.get("action_index") != index:
                        self.problem(where, f"the refusal must carry action_index {index}")
                    if (exact and result.get("actual") != actual) or (not exact and result.get("actual", 0) < actual):
                        self.problem(where, f"the refusal must carry actual {actual}")
                if effects or expect.get("journal") != "absent":
                    self.problem(where, "an over-bound request has no effect and creates no journal: nothing is split")
                context["last"] = (op, "refused")
                return
            if isinstance(result, dict) and result.get("stage") == "plan" and result.get("error") == "ResourceLimitExceeded":
                if result.get("bound") not in ("attachment.signed_frame_max_bytes", "transaction.max_decompressed_bytes", "transaction.max_tx_bytes"):
                    self.problem(where, "a refusal of a count or slot bound the request does not cross")
        if expect.get("journal") is not None:
            if expect.get("journal") != "absent" or not (isinstance(result, dict) and stored is None):
                self.problem(where, "`journal: absent` is only the result of a refused first call")
            context["last"] = (op, "refused")
            return
        if expect.get("status") not in vocabulary["statuses"]:
            self.problem(where, f"unknown operation status `{expect.get('status')}`")
        if state not in vocabulary["states"]:
            self.problem(where, f"`{state}` is not a durable state of an operation")
        self.seen["states"].add(state)
        self.seen["statuses"].add(expect.get("status"))
        self.check_outcome(where, op, call, implied, result, state, expect.get("status"), stored, context, vocabulary)
        self.check_status(where, result, state, expect.get("status"), vocabulary)
        artifact = expect.get("artifact")
        if op == "prepare" and result == "ok":
            if artifact != {"kind": "PreparedZkOperationV1", "actions": context["request"]["actions"], "attachment_slots": context["request"]["slots"]}:
                self.problem(where, "a prepared batch is one PreparedZkOperationV1 with every action and slot of the request")
        elif op == "build" and result == "ok":
            if artifact != {"kind": "BuiltZkOperationV1"}:
                self.problem(where, "a successful build returns one BuiltZkOperationV1")
        elif artifact is not None:
            self.problem(where, "only a successful prepare or build returns an artifact")
        identity = expect.get("identity")
        if identity is not None:
            if set(identity) - {"dispatches", "possible_admissions", "evidence"}:
                self.problem(where, "unknown identity fields")
            if identity.get("possible_admissions", 0) > identity.get("dispatches", 0):
                self.problem(where, "more possible admissions than counted dispatches")
            if identity.get("evidence") not in (None, *vocabulary["evidence"]):
                self.problem(where, f"unknown evidence `{identity.get('evidence')}`")
            if (identity.get("evidence") is not None) != (state in ("finalized", "rejected")):
                self.problem(where, "terminal evidence exists exactly for a finalized or rejected identity")
        if op == "cancel":
            if stored in vocabulary["may_still_commit"]:
                self.seen["cancel_after"] = True
                if expect.get("status") != "cancelling" or state != stored:
                    self.problem(where, "cancelling an identity that may still commit only stops observation")
            elif stored in ("prepared", "proving", "ready_to_sign", "signed"):
                self.seen["cancel_before"] = True
                if expect.get("status") != "cancelled" or state != "cancelled_before_submission":
                    self.problem(where, "cancellation before any possible admission ends cancelled_before_submission")
            elif state != stored:
                self.problem(where, "cancelling a terminal operation changes nothing")
        context["state"] = state
        context["status"] = expect.get("status")
        context["last"] = (op, result if result != "interrupted" else "interrupted")

    def check_outcome(self, where, op, call, implied, result, state, status, stored, context, vocabulary) -> None:
        interrupt_after = call.get("interrupt_after")
        if implied == ("interrupted",) or interrupt_after is not None:
            if result != "interrupted":
                self.problem(where, "an interrupted process must report `interrupted`")
            if interrupt_after is not None and state != interrupt_after:
                self.problem(where, f"the process stopped after storing `{interrupt_after}`, not `{state}`")
            return
        if implied is not None and implied[0] == "error":
            _, code, stage = implied
            if not isinstance(result, dict) or result.get("error") != code or result.get("stage") != stage:
                self.problem(where, f"the trace implies {code} at stage `{stage}`, not {result}")
            if code in ("ProofInvalid", "UnsupportedOperation") or stage in ("prove", "local_verify", "build"):
                if state != "prepared":
                    self.problem(where, f"after {code} at `{stage}` the operation returns to `prepared`, not `{state}`")
            if stage == "sign" and state != "ready_to_sign":
                self.problem(where, f"after {code} at `sign` the payload stays `ready_to_sign`, not `{state}`")
            if stage == "submit":
                expected = "rejected" if code == "Rejected" else "signed"
                if state != expected:
                    self.problem(where, f"after {code} at `submit` the identity is `{expected}`, not `{state}`")
            return
        if implied is not None and implied[0] == "closed":
            if implied[1] == "applied":
                if state != "finalized" or result not in ("completed", "ok") or (result == "ok") != (op == "recover"):
                    self.problem(where, "an authenticated or state-resolved Applied finalizes the operation")
            elif state != "rejected" or not (isinstance(result, dict) and result.get("error") in ("Rejected", "Expired")):
                self.problem(where, "a closing rejection or expiry rejects the identity")
            return
        # No token ended the call.
        if isinstance(result, dict):
            code = result.get("error")
            if code in UNRESOLVED_CODES:
                if state not in UNRESOLVED_CODES[code]:
                    self.problem(where, f"{code} cannot leave the identity `{state}`")
                if result.get("stage") != "reconcile":
                    self.problem(where, f"{code} at the end of the observation bound is reported at `reconcile`")
            elif code == "CancelledBeforeSubmission":
                if status != "cancelled" or result.get("stage") != "cancel":
                    self.problem(where, "CancelledBeforeSubmission is reported at `cancel` by a cancelled operation")
            elif not (code == "ResourceLimitExceeded" and result.get("stage") == "plan"):
                self.problem(where, f"no scripted token explains {code}")
        elif result == "completed":
            if stored != "finalized" and call.get("expect", {}).get("effects"):
                self.problem(where, "`completed` without a closing token")
        elif result == "ok" and op == "execute":
            self.problem(where, "the one-call returns `completed`, an error or `interrupted`")
        if state in ("finalized", "rejected") and stored not in ("finalized", "rejected"):
            self.problem(where, f"`{state}` without the evidence that closes an identity")

    def check_status(self, where: str, result, state: str, status: str, vocabulary: dict) -> None:
        if (status == "completed") != (state == "finalized"):
            self.problem(where, "status `completed` holds exactly when the identity is finalized")
        if status == "cancelling" and state not in vocabulary["may_still_commit"]:
            self.problem(where, "status `cancelling` needs an identity that may still commit")
        if status == "cancelled" and state not in ("cancelled_before_submission", "rejected"):
            self.problem(where, "status `cancelled` needs no unresolved identity")
        if status == "failed" and state != "rejected":
            self.problem(where, "status `failed` needs a rejected identity")
        if state == "cancelled_before_submission" and status != "cancelled":
            self.problem(where, "`cancelled_before_submission` belongs to a cancelled operation")
        if result == "completed" and status != "completed":
            self.problem(where, "`completed` needs a completed operation")

    def check_scenario(self, name: str, scenario: dict, vocabulary: dict) -> None:
        where = f"{FIXTURES}/scenarios/{name}"
        if scenario.get("schema") != "iroha.zk_operation.scenario.v1":
            self.problem(where, "unknown schema")
        if f"{scenario.get('id')}.json" != name or not LABEL.match(str(scenario.get("id"))):
            self.problem(where, "the file must be named by the scenario id")
        if scenario.get("category") not in CATEGORIES:
            self.problem(where, f"unknown category `{scenario.get('category')}`")
        self.seen["categories"].add(scenario.get("category"))
        if not scenario.get("description"):
            self.problem(where, "missing description")
        rules = scenario.get("rules", [])
        if not rules:
            self.problem(where, "a scenario exercises at least one rule")
        for rule in rules:
            if rule not in vocabulary["rules"]:
                self.problem(where, f"unknown rule `{rule}`")
            self.seen["rules"].add(rule)
        request = self.check_request(where, scenario.get("request", {}), vocabulary)
        calls = scenario.get("calls", [])
        if not calls:
            self.problem(where, "a scenario needs at least one call")
        context = {
            "request": request,
            "mode": request["mode"],
            "state": None,
            "stored": None,
            "status": None,
            "last": (None, None),
            "possible_admission": False,
            "ordinal": 1,
            "class_codes": vocabulary["class_codes"],
        }
        for index, call in enumerate(calls):
            self.check_call(f"{where} call {index}", call, context, vocabulary)

    # ---------------------------------------------------------------------- spec
    def check_spec(self, contract: dict, vocabulary: dict) -> None:
        text = self.read(SPEC)
        if text is None:
            return
        if PROVISIONAL_NOTE not in text:
            self.problem(SPEC, f"does not state `{PROVISIONAL_NOTE}`")
        decisions = contract.get("review", {}).get("decisions", "")
        if not decisions or decisions not in text:
            self.problem(SPEC, "does not link the provisional decisions file")
        named = {
            "call": [ONE_CALL] + list(CALLS) + list(HANDLE_CALLS),
            "stage": vocabulary["stages"],
            "durable state": vocabulary["states"],
            "error code": vocabulary["codes"],
            "error field": [field.get("name") for field in contract.get("error_fields", [])],
            "artifact": [artifact.get("name") for artifact in contract.get("artifacts", []) + contract.get("records", [])],
            "artifact field": [
                field.get("name")
                for artifact in contract.get("artifacts", []) + contract.get("records", [])
                for field in artifact.get("fields", [])
            ],
            "bound": [limit.get("id") for limit in contract.get("batch_limits", [])]
            + [limit.get("symbol") for limit in contract.get("batch_limits", [])],
            "finality mode": ids(contract.get("finality_modes", [])),
            "dispatch class": vocabulary["classes"],
            "private material": vocabulary["material"],
            "custody rule": ids(contract.get("custody", {}).get("rules", [])),
            "rule": vocabulary["rules"],
        }
        for what, values in named.items():
            for value in values:
                if f"`{value}`" not in text:
                    self.problem(SPEC, f"does not name {what} `{value}`")
        plain = text.replace(",", "")
        for limit in contract.get("batch_limits", []):
            if str(limit.get("maximum")) not in plain:
                self.problem(SPEC, f"does not state the maximum {limit.get('maximum')} of `{limit.get('id')}`")

    # ---------------------------------------------------------------------- run
    def check_manifest(self, manifest: dict) -> list:
        where = f"{FIXTURES}/manifest.json"
        if manifest.get("schema") != "iroha.zk_operation.fixtures.v1":
            self.problem(where, "unknown schema")
        if manifest.get("contract") != SPEC or manifest.get("contract_json") != "contract.json":
            self.problem(where, f"must name {SPEC} and contract.json")
        if manifest.get("reducer") != "../workflow_v1/state_machine.json":
            self.problem(where, "must name the shared reducer ../workflow_v1/state_machine.json")
        directory = self.root / FIXTURES
        pending = []
        for entry in manifest.get("pending", []):
            if not entry.get("file") or not entry.get("owner") or not entry.get("reason"):
                self.problem(where, "a pending file needs its file, owner and reason")
                continue
            pending.append(entry["file"])
            if (directory / entry["file"]).exists():
                self.problem(where, f"`{entry['file']}` is listed as pending but exists; list it as a fixture")
        known = {"README.md", "manifest.json", "contract.json", "scenarios"}
        for path in sorted(directory.iterdir()) if directory.is_dir() else []:
            if path.name not in known:
                self.problem(where, f"`{path.name}` is not a fixture of the manifest")
        listed = manifest.get("scenarios", [])
        scenarios = directory / "scenarios"
        present = sorted(path.name for path in scenarios.glob("*")) if scenarios.is_dir() else []
        if listed != present:
            self.problem(where, "`scenarios` must list exactly the files of scenarios/, sorted")
        return present

    def run(self) -> dict:
        contract = self.load(f"{FIXTURES}/contract.json")
        machine = self.load(REDUCER)
        manifest = self.load(f"{FIXTURES}/manifest.json")
        summary = {"scenarios": 0, "rules": 0}
        if contract is None or machine is None or manifest is None:
            return summary
        vocabulary = self.check_contract(contract, machine)
        present = self.check_manifest(manifest)
        for name in present:
            scenario = self.load(f"{FIXTURES}/scenarios/{name}")
            if scenario is not None:
                self.check_scenario(name, scenario, vocabulary)
        self.check_spec(contract, vocabulary)
        scenarios = f"{FIXTURES}/scenarios"
        coverage = {
            "rules": ("exercises rule", vocabulary["rules"]),
            "categories": ("is of category", CATEGORIES),
            "states": ("leaves the operation in state", vocabulary["states"]),
            "statuses": ("leaves the operation", vocabulary["statuses"]),
            "ops": ("calls", OPS),
            "error_stages": ("reports an error at stage", PIPELINE_STAGES),
            "dispatch_classes": ("dispatches with class", vocabulary["classes"]),
            "finality_modes": ("requests finality mode", FINALITY_MODES),
        }
        for key, (what, values) in coverage.items():
            for value in values:
                if value not in self.seen[key]:
                    self.problem(scenarios, f"no scenario {what} `{value}`")
        if not self.seen["cancel_before"]:
            self.problem(scenarios, "no scenario cancels before any possible admission")
        if not self.seen["cancel_after"]:
            self.problem(scenarios, "no scenario cancels after a possible admission")
        summary["scenarios"] = len(present)
        summary["rules"] = len(vocabulary["rules"])
        return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: the checkout of this script)",
    )
    arguments = parser.parse_args(argv)
    checker = Checker(arguments.root)
    summary = checker.run()
    if checker.problems:
        for problem in checker.problems:
            print(problem, file=sys.stderr)
        print(f"operation contract: {len(checker.problems)} inconsistencies", file=sys.stderr)
        return 1
    print(
        "operation contract: "
        f"{summary['scenarios']} scenarios exercise {summary['rules']} rules; "
        "contract, source owners, traces and specification are consistent"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
