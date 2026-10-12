#!/usr/bin/env python3
"""Check the durable workflow fixture set without Rust.

`fixtures/zk/workflow_v1/` holds the machine-readable state machine, canonical
byte vectors and scenario fixtures of `specs/zk_durable_workflow.md`. The Rust
tests in `crates/iroha/src/workflow/` execute them. This script checks what can
be checked from the files alone, so that a port to another SDK family starts
from a set that is consistent by itself:

* the state machine: closed vocabularies, a deterministic transition table,
  every state reachable, no exit from a terminal state, and the safety shape of
  the table (a state that may still commit is never reopened, rebuilt, signed
  again or cancelled, and is dispatched again only under the retransmission
  guard);
* every scenario: schema, vocabulary of every script token, state, status,
  code and stage, and a partial-completion statement recomputed from the step
  states (six lists, a partition of the steps, nothing rolled back);
* every scenario trace: a call that starts with an unresolved transaction
  first reads the outcome of that identity, a replacement identity is built
  only after the previous one was closed and only in a call that authorizes it,
  an unresolved identity is dispatched again only in a call that authorizes
  retransmission and after a status read, and a cancelled or cancelling
  workflow builds, signs, dispatches and starts nothing;
* coverage: every rule, category, transaction state, round state and workflow
  status of the state machine appears in the scenario set, and cancellation is
  requested in every transaction and round state;
* the byte vectors: each record digest is the Iroha hash of the record domain
  followed by the record bytes, and each progress report uses known states;
* the specification names every state, status, error code and limit.

Exit status 0 when the set is consistent, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FIXTURES = "fixtures/zk/workflow_v1"
SPEC = "specs/zk_durable_workflow.md"
RECORD_DOMAIN = b"iroha:durable-workflow:record:v1\0"

CATEGORIES = (
    "happy_path",
    "interruption_before_submission",
    "interruption_after_ambiguous_submission",
    "interruption_after_irreversible_progress",
    "dispatch_classification",
    "reconciliation",
    "retransmission",
    "replacement_identity",
    "cancellation",
    "duplicate_resume",
    "storage_corruption",
    "uncertain_write",
    "offchain_round",
    "bounds_and_bindings",
)
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
    "SubmissionOutcomeUnknown",
    "FinalityPending",
    "Rejected",
    "CancelledBeforeSubmission",
)
OPS = ("run", "recover", "cancel", "progress", "corrupt")
OPTIONS = (
    "observation_timeout_ms",
    "poll_interval_ms",
    "retransmit_identical_bytes",
    "retry_rejected_step",
)
DRIVER_MODES = ("present", "absent", "wrong_identity")
FAULT_MODES = ("unavailable", "lost", "published")
CORRUPTIONS = ("flip_bit", "truncate", "append_byte", "foreign_journal", "status_completed")
# Script tokens: name -> whether the token takes an error code after the colon.
PLAIN, CODE, NAMES = "plain", "code", "names"
TOKENS = {
    "builds": {
        "ok": PLAIN,
        "fail": CODE,
        "wrong_intent": PLAIN,
        "oversized": PLAIN,
        "empty": PLAIN,
        "repeat_payload": PLAIN,
        "interrupt": PLAIN,
    },
    "signs": {"ok": PLAIN, "fail": CODE, "wrong_identity": PLAIN, "interrupt": PLAIN},
    "dispatches": {
        "accepted": PLAIN,
        "already_known": PLAIN,
        "refused": PLAIN,
        "not_admitted": CODE,
        "ambiguous": PLAIN,
        "interrupt": PLAIN,
    },
    "statuses": {
        "applied": PLAIN,
        "rejected": PLAIN,
        "expired": PLAIN,
        "observed": PLAIN,
        "hint_applied": PLAIN,
        "hint_rejected": PLAIN,
        "absent": PLAIN,
        "read_failed": PLAIN,
        "unbound_response": PLAIN,
        "interrupt": PLAIN,
    },
    "round_starts": {
        "completed": NAMES,
        "completed_reordered": NAMES,
        "completed_duplicate": NAMES,
        "completed_missing_custody": NAMES,
        "completed_wrong_round": NAMES,
        "completed_context_changed": NAMES,
        "waiting": NAMES,
        "failed": CODE,
        "error": CODE,
        "interrupt": PLAIN,
    },
}
TOKENS["round_recoveries"] = dict(TOKENS["round_starts"], not_started=PLAIN)
EFFECT = re.compile(
    r"^(?:(build|dispatch|status):(\d+)#(\d+)|sign:(\d+)#(\d+)|sleep:\d+|round_start:\d+"
    r"|round_recover:\d+|concurrent:cancel:[a-z_]+|concurrent:run:[A-Za-z_]+)$"
)
LABEL = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
SAFE_EFFECTS = ("status:", "sleep:", "round_recover:", "concurrent:")


def iroha_hash(data: bytes) -> bytes:
    """Blake2b-256 with the least significant bit of the last byte set."""
    digest = bytearray(hashlib.blake2b(data, digest_size=32).digest())
    digest[-1] |= 1
    return bytes(digest)


def ids(entries: list) -> list[str]:
    """Identifiers of a vocabulary given as strings or as objects with `id`."""
    return [entry["id"] if isinstance(entry, dict) else entry for entry in entries]


class Checker:
    """Collects every inconsistency of one fixture tree."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.problems: list[str] = []
        self.seen_states: set[str] = set()
        self.seen_statuses: set[str] = set()
        self.seen_rules: set[str] = set()
        self.seen_categories: set[str] = set()
        self.seen_cancel_states: set[str] = set()

    def problem(self, where: str, message: str) -> None:
        self.problems.append(f"{where}: {message}")

    def load(self, relative: str):
        path = self.root / relative
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            self.problem(relative, f"cannot be read as JSON: {error}")
            return None

    # ------------------------------------------------------------ state machine
    def check_state_machine(self, machine: dict) -> dict:
        where = f"{FIXTURES}/state_machine.json"
        if machine.get("schema") != "iroha.durable_workflow.state_machine.v1":
            self.problem(where, "unknown schema")
        if machine.get("atomicity") != "per_transaction_only":
            self.problem(where, "atomicity must be per_transaction_only")
        if machine.get("journal_version") != 1:
            self.problem(where, "journal_version must be 1")
        vocabulary = {}
        for key in (
            "workflow_kinds",
            "step_kinds",
            "workflow_statuses",
            "workflow_events",
            "transaction_states",
            "transaction_events",
            "transaction_guards",
            "round_states",
            "round_events",
            "round_guards",
            "attempt_evidence",
            "error_codes",
            "stages",
            "rules",
        ):
            values = ids(machine.get(key, []))
            if not values:
                self.problem(where, f"`{key}` is empty")
            if len(values) != len(set(values)):
                self.problem(where, f"`{key}` repeats an identifier")
            vocabulary[key] = values
        self.check_transaction_table(where, machine, vocabulary)
        self.check_round_and_workflow_tables(where, machine, vocabulary)

        shared = [
            entry["id"] for entry in machine.get("error_codes", []) if entry.get("shared_operation_code")
        ]
        if tuple(shared) != SHARED_CODES:
            self.problem(where, "the shared operation error codes differ from the contract")
        for name, value in machine.get("limits", {}).items():
            if not isinstance(value, int) or value <= 0:
                self.problem(where, f"limit `{name}` must be a positive integer")
        for rule in machine.get("rules", []):
            if not rule.get("statement"):
                self.problem(where, f"rule `{rule.get('id')}` has no statement")
        vocabulary["may_still_commit"] = [
            state["id"] for state in machine.get("transaction_states", []) if state.get("may_still_commit")
        ]
        vocabulary["round_unresolved"] = [
            state["id"] for state in machine.get("round_states", []) if state.get("unresolved")
        ]
        vocabulary["terminal_statuses"] = [
            status["id"] for status in machine.get("workflow_statuses", []) if status.get("terminal")
        ]
        vocabulary["limits"] = machine.get("limits", {})
        return vocabulary

    def check_transaction_table(self, where: str, machine: dict, vocabulary: dict) -> None:
        rows = machine.get("transaction_transitions", [])
        states = vocabulary["transaction_states"]
        commit = {
            state["id"] for state in machine.get("transaction_states", []) if state.get("may_still_commit")
        }
        seen = set()
        guards_by_pair: dict[tuple[str, str], list[str]] = {}
        for row in rows:
            key = (row.get("from"), row.get("event"), row.get("guard"))
            if key in seen:
                self.problem(where, f"transaction transition {key} is listed twice")
            seen.add(key)
            if row.get("from") not in states or row.get("to") not in states:
                self.problem(where, f"transaction transition {key} uses an unknown state")
            if row.get("event") not in vocabulary["transaction_events"]:
                self.problem(where, f"transaction transition {key} uses an unknown event")
            if row.get("guard") not in vocabulary["transaction_guards"]:
                self.problem(where, f"transaction transition {key} uses an unknown guard")
            guards_by_pair.setdefault((row.get("from"), row.get("event")), []).append(row.get("guard"))
            # Safety shape of the table.
            if row.get("from") in commit and row.get("event") in (
                "open_attempt",
                "cancel",
                "build_started",
                "build_failed",
                "payload_built",
                "signed",
            ):
                self.problem(where, f"{key}: a state that may still commit is reopened, rebuilt or cancelled")
            if row.get("to") == "submitting":
                if row.get("event") != "dispatch_intent":
                    self.problem(where, f"{key}: only a dispatch intent enters `submitting`")
                expected = (
                    "always"
                    if row.get("from") == "signed"
                    else "retransmission_authorized_after_exact_absence"
                )
                if row.get("guard") != expected:
                    self.problem(where, f"{key}: a dispatch from `{row.get('from')}` needs guard `{expected}`")
            if row.get("event") == "open_attempt" and row.get("from") not in ("planned", "rejected"):
                self.problem(where, f"{key}: an identity is opened only from `planned` or `rejected`")
        for pair, guards in guards_by_pair.items():
            if len(guards) > 1 and sorted(guards) != ["no_possible_admission", "possible_admission"]:
                self.problem(where, f"transaction transitions for {pair} are not mutually exclusive")
        used_states = {row.get("from") for row in rows} | {row.get("to") for row in rows}
        used_events = {row.get("event") for row in rows}
        for state in states:
            if state not in used_states:
                self.problem(where, f"transaction state `{state}` has no transition")
        for event in vocabulary["transaction_events"]:
            if event not in used_events:
                self.problem(where, f"transaction event `{event}` has no transition")
        reachable = {"planned"}
        changed = True
        while changed:
            changed = False
            for row in rows:
                if row.get("from") in reachable and row.get("to") not in reachable:
                    reachable.add(row.get("to"))
                    changed = True
        for state in states:
            if state not in reachable:
                self.problem(where, f"transaction state `{state}` is unreachable from `planned`")
        for final in ("finalized", "cancelled_before_submission"):
            if any(row.get("from") == final for row in rows):
                self.problem(where, f"terminal transaction state `{final}` has an exit")

    def check_round_and_workflow_tables(self, where: str, machine: dict, vocabulary: dict) -> None:
        for row in machine.get("round_transitions", []):
            if row.get("from") not in vocabulary["round_states"] or row.get("to") not in vocabulary["round_states"]:
                self.problem(where, f"round transition {row} uses an unknown state")
            if row.get("event") not in vocabulary["round_events"]:
                self.problem(where, f"round transition {row} uses an unknown event")
            if row.get("guard") not in vocabulary["round_guards"]:
                self.problem(where, f"round transition {row} uses an unknown guard")
            if row.get("event") in ("round_intent", "round_restart_intent") and row.get("guard") != "not_cancelling":
                self.problem(where, "round start and restart intents need guard `not_cancelling`")
            if row.get("event") == "round_not_started" and row.get("guard") != "while_cancelling":
                self.problem(where, "a never-started round is reset only `while_cancelling`")
            if row.get("from") in ("round_completed", "round_failed"):
                self.problem(where, f"terminal round state `{row.get('from')}` has an exit")
        terminal = {
            status["id"] for status in machine.get("workflow_statuses", []) if status.get("terminal")
        }
        for row in machine.get("workflow_transitions", []):
            if row.get("from") not in vocabulary["workflow_statuses"] or row.get("to") not in vocabulary["workflow_statuses"]:
                self.problem(where, f"workflow transition {row} uses an unknown status")
            if row.get("event") not in vocabulary["workflow_events"]:
                self.problem(where, f"workflow transition {row} uses an unknown event")
            if row.get("from") in terminal:
                self.problem(where, f"terminal workflow status `{row.get('from')}` has an exit")

    # ---------------------------------------------------------------- scenarios
    def check_code(self, where: str, code: str, vocabulary: dict) -> None:
        if code not in vocabulary["error_codes"]:
            self.problem(where, f"unknown error code `{code}`")

    def check_plan(self, where: str, plan: dict, vocabulary: dict) -> list[dict]:
        if plan.get("kind") not in vocabulary["workflow_kinds"]:
            self.problem(where, f"unknown workflow kind `{plan.get('kind')}`")
        if not LABEL.match(str(plan.get("instance", ""))):
            self.problem(where, "plan instance is not a valid label")
        driver = plan.get("driver", {})
        if not LABEL.match(str(driver.get("id", ""))) or not isinstance(driver.get("schema_version"), int):
            self.problem(where, "plan driver needs a label id and an integer schema_version")
        steps = plan.get("steps", [])
        limits = vocabulary["limits"]
        if not 1 <= len(steps) <= limits.get("max_steps", 0):
            self.problem(where, "plan step count is out of bounds")
        labels = [step.get("label") for step in steps]
        if len(labels) != len(set(labels)):
            self.problem(where, "plan repeats a step label")
        for step in steps:
            if not LABEL.match(str(step.get("label", ""))):
                self.problem(where, f"step label `{step.get('label')}` is not a valid label")
            kind = step.get("kind")
            if kind not in vocabulary["step_kinds"]:
                self.problem(where, f"unknown step kind `{kind}`")
            if kind == "transaction":
                maximum = step.get("max_transaction_identities", 1)
                if not 1 <= maximum <= limits.get("max_transaction_identities_per_step", 0):
                    self.problem(where, "transaction identity bound is out of range")
            elif kind == "offchain_round":
                maximum = step.get("max_transcript_bytes", limits.get("max_round_transcript_bytes", 0))
                if type(maximum) is not int or not 1 <= maximum <= limits.get("max_round_transcript_bytes", 0):
                    self.problem(where, "round transcript bound is out of range")
                for key in ("irreversible", "participants_required", "custody_handles_required"):
                    if key not in step:
                        self.problem(where, f"round step `{step.get('label')}` lacks `{key}`")
        return steps

    def check_script(self, where: str, script: dict, vocabulary: dict) -> None:
        for name, entries in script.items():
            allowed = TOKENS.get(name)
            if allowed is None:
                self.problem(where, f"unknown script list `{name}`")
                continue
            for token in entries:
                head, _, argument = token.partition(":")
                kind = allowed.get(head)
                if kind is None:
                    self.problem(where, f"unknown `{name}` token `{token}`")
                elif kind == PLAIN and argument:
                    self.problem(where, f"`{name}` token `{token}` takes no argument")
                elif kind == CODE:
                    self.check_code(where, argument, vocabulary)
                elif kind == NAMES and head != "waiting" and not argument:
                    self.problem(where, f"`{name}` token `{token}` needs participants")

    def expected_partial(self, steps: list[dict], states: list[str], vocabulary: dict) -> dict:
        lists = {
            "confirmed_steps": [],
            "irreversible_steps": [],
            "unresolved_steps": [],
            "failed_steps": [],
            "not_started_steps": [],
            "rolled_back_steps": [],
        }
        for index, (step, state) in enumerate(zip(steps, states)):
            if state in ("finalized", "round_completed"):
                lists["confirmed_steps"].append(index)
                if step.get("kind") == "transaction" or step.get("irreversible"):
                    lists["irreversible_steps"].append(index)
            elif state in vocabulary["may_still_commit"] or state in vocabulary["round_unresolved"]:
                lists["unresolved_steps"].append(index)
            elif state in ("rejected", "round_failed"):
                lists["failed_steps"].append(index)
            else:
                lists["not_started_steps"].append(index)
        return lists

    def check_expect(self, where: str, expect: dict, steps: list[dict], vocabulary: dict):
        """Check one expectation; return (status, states) of the stored journal or None."""
        result = expect.get("result")
        if isinstance(result, dict):
            self.check_code(where, result.get("error", ""), vocabulary)
            if "stage" in result and result["stage"] not in vocabulary["stages"]:
                self.problem(where, f"unknown stage `{result['stage']}`")
            if result.get("progress") not in (None, "unavailable", "last_validated"):
                self.problem(where, "unknown error progress expectation")
            unknown = set(result) - {
                "error",
                "stage",
                "step",
                "bounds",
                "resumable",
                "has_transaction_identity",
                "progress",
            }
            if unknown:
                self.problem(where, f"unknown result fields {sorted(unknown)}")
        elif result not in ("completed", "ok", "absent", "interrupted"):
            self.problem(where, f"unknown result `{result}`")
        effects = expect.get("effects")
        if not isinstance(effects, list):
            self.problem(where, "`effects` must list the ordered external effects")
            effects = []
        for effect in effects:
            if not EFFECT.match(effect):
                self.problem(where, f"malformed effect `{effect}`")
        if "journal" in expect:
            if expect["journal"] == "unreadable":
                self.check_code(where, expect.get("journal_error", ""), vocabulary)
            elif expect["journal"] != "absent":
                self.problem(where, f"unknown journal expectation `{expect['journal']}`")
            if effects and expect["journal"] == "unreadable":
                self.problem(where, "an unreadable journal must cause no external effect")
            return None
        status = expect.get("status")
        states = expect.get("steps", [])
        if status not in vocabulary["workflow_statuses"]:
            self.problem(where, f"unknown workflow status `{status}`")
        if len(states) != len(steps):
            self.problem(where, "`steps` must give the state of every plan step")
            return None
        for step, state in zip(steps, states):
            allowed = (
                vocabulary["transaction_states"]
                if step.get("kind") == "transaction"
                else vocabulary["round_states"]
            )
            if state not in allowed:
                self.problem(where, f"state `{state}` is not a state of a {step.get('kind')} step")
        partial = expect.get("partial_completion")
        expected = self.expected_partial(steps, states, vocabulary)
        if partial != expected:
            self.problem(where, f"partial_completion {partial} does not follow from the step states {expected}")
        done = [state in ("finalized", "round_completed") for state in states]
        current = done.index(False) if False in done else None
        if any(done[index] for index in range(len(done)) if current is not None and index > current):
            self.problem(where, "a later step is done before an earlier one")
        unresolved = bool(expected["unresolved_steps"])
        if (status == "completed") != (current is None):
            self.problem(where, "status `completed` must hold exactly when every step is done")
        if status == "cancelling" and not unresolved:
            self.problem(where, "status `cancelling` needs an unresolved step")
        if status in ("cancelled", "failed") and unresolved:
            self.problem(where, f"status `{status}` cannot have an unresolved step")
        if status == "failed" and not expected["failed_steps"]:
            self.problem(where, "status `failed` needs a failed step")
        self.seen_states.update(states)
        self.seen_statuses.add(status)
        return status, states

    def check_trace(self, where: str, call: dict, previous, steps: list[dict], vocabulary: dict) -> None:
        """Safety properties of one call's effect trace given the journal before it."""
        trace = call.get("expect", {}).get("effects", [])
        concurrent = call.get("concurrent")
        if not isinstance(concurrent, dict):
            concurrent = {}
        trigger = concurrent.get("when", "")
        if isinstance(trigger, str) and trigger.startswith("effect:"):
            effect = trigger[len("effect:"):]
            if effect not in trace:
                self.problem(where, "effect-triggered concurrency never reaches its trigger")
            else:
                position = trace.index(effect) + 1
                marker = f"concurrent:{concurrent.get('action')}:"
                if position >= len(trace) or not trace[position].startswith(marker):
                    self.problem(where, "effect-triggered actor must act immediately inside its call")
                elif concurrent.get("action") == "cancel":
                    for later in trace[position + 1:]:
                        if not later.startswith(SAFE_EFFECTS):
                            self.problem(where, f"an effect after concurrent cancellation caused `{later}`")
        effects = [
            effect for effect in trace if not effect.startswith("concurrent:")
        ]
        options = call.get("options", {})
        if call.get("op") in ("cancel", "progress", "corrupt") and call.get("expect", {}).get("effects"):
            self.problem(where, f"`{call.get('op')}` must cause no external effect")
        if call.get("op") == "recover":
            for effect in effects:
                if not effect.startswith(SAFE_EFFECTS):
                    self.problem(where, f"read-only recovery caused `{effect}`")
        if previous is None:
            return
        status, states = previous
        if status in ("cancelled", "cancelling", "completed", "failed"):
            for effect in effects:
                if not effect.startswith(SAFE_EFFECTS):
                    self.problem(where, f"a {status} workflow caused `{effect}`")
        done = [state in ("finalized", "round_completed") for state in states]
        if False not in done:
            return
        current = done.index(False)
        state = states[current]
        if state in vocabulary["may_still_commit"] and effects:
            # The resume rule: the first effect is the read of the original identity.
            if not effects[0].startswith(f"status:{current}#"):
                self.problem(where, f"resume of an unresolved transaction started with `{effects[0]}`")
        builds = [EFFECT.match(effect) for effect in effects if effect.startswith("build:")]
        for build in builds:
            step, ordinal = int(build.group(2)), int(build.group(3))
            if step != current or ordinal == 1:
                continue
            if state != "rejected" and not self.closed_earlier_in_call(effects, step, ordinal):
                self.problem(where, f"identity {step}#{ordinal} was built while the previous one was `{state}`")
            if not options.get("retry_rejected_step"):
                self.problem(where, f"identity {step}#{ordinal} was built without `retry_rejected_step`")
        if state in vocabulary["may_still_commit"]:
            for index, effect in enumerate(effects):
                if effect.startswith(f"dispatch:{current}#"):
                    if not options.get("retransmit_identical_bytes"):
                        self.problem(where, f"`{effect}` re-dispatched an unresolved identity without authorization")
                    if index == 0 or not effects[index - 1].startswith(f"status:{current}#"):
                        self.problem(where, f"`{effect}` was not preceded by a fresh status read")
                    break

    @staticmethod
    def closed_earlier_in_call(effects: list[str], step: int, ordinal: int) -> bool:
        """Whether the previous identity was read in this call before the replacement was built."""
        build = f"build:{step}#{ordinal}"
        read = f"status:{step}#{ordinal - 1}"
        return read in effects and effects.index(read) < effects.index(build)

    def check_scenario(self, name: str, scenario: dict, vocabulary: dict) -> None:
        where = f"{FIXTURES}/scenarios/{name}"
        if scenario.get("schema") != "iroha.durable_workflow.scenario.v1":
            self.problem(where, "unknown schema")
        if f"{scenario.get('id')}.json" != name:
            self.problem(where, "the file must be named by the scenario id")
        if scenario.get("category") not in CATEGORIES:
            self.problem(where, f"unknown category `{scenario.get('category')}`")
        self.seen_categories.add(scenario.get("category"))
        if not scenario.get("description"):
            self.problem(where, "missing description")
        for rule in scenario.get("rules", []):
            if rule not in vocabulary["rules"]:
                self.problem(where, f"unknown rule `{rule}`")
            self.seen_rules.add(rule)
        steps = self.check_plan(where, scenario.get("plan", {}), vocabulary)
        calls = scenario.get("calls", [])
        if not calls:
            self.problem(where, "a scenario needs at least one call")
        previous = None
        for index, call in enumerate(calls):
            here = f"{where} call {index}"
            if call.get("op") not in OPS:
                self.problem(here, f"unknown op `{call.get('op')}`")
            for key in call.get("options", {}):
                if key not in OPTIONS:
                    self.problem(here, f"unknown option `{key}`")
            if call.get("driver", "present") not in DRIVER_MODES:
                self.problem(here, f"unknown driver mode `{call.get('driver')}`")
            self.check_script(here, call.get("script", {}), vocabulary)
            concurrent = call.get("concurrent")
            if "concurrent" in call and not isinstance(concurrent, dict):
                self.problem(here, "malformed `concurrent`")
            elif concurrent is not None:
                known = vocabulary["transaction_states"] + vocabulary["round_states"]
                trigger = concurrent.get("when")
                effect_trigger = (
                    isinstance(trigger, str)
                    and trigger.startswith("effect:")
                    and not trigger.startswith("effect:concurrent:")
                    and EFFECT.fullmatch(trigger[len("effect:"):]) is not None
                )
                if (trigger not in known and not effect_trigger) or concurrent.get("action") not in ("cancel", "run"):
                    self.problem(here, "malformed `concurrent`")
                elif concurrent.get("action") == "cancel" and not effect_trigger:
                    self.seen_cancel_states.add(trigger)
            if call.get("op") == "cancel" and previous is not None:
                # The state cancellation found: the current step, or the last one when all are done.
                _, states = previous
                pending = [state for state in states if state not in ("finalized", "round_completed")]
                self.seen_cancel_states.add(pending[0] if pending else states[-1])
            fault = call.get("storage_fault")
            if fault is not None and (fault.get("mode") not in FAULT_MODES or not isinstance(fault.get("store"), int)):
                self.problem(here, "malformed `storage_fault`")
            if call.get("op") == "corrupt" and call.get("mode") not in CORRUPTIONS:
                self.problem(here, f"unknown corruption `{call.get('mode')}`")
            expect = call.get("expect")
            if not isinstance(expect, dict):
                self.problem(here, "missing `expect`")
                continue
            self.check_trace(here, call, previous, steps, vocabulary)
            checked = self.check_expect(here, expect, steps, vocabulary)
            previous = checked if checked is not None else (previous if "journal" not in expect else None)

    # ------------------------------------------------------------------ vectors
    def check_vectors(self, vectors: dict, vocabulary: dict) -> None:
        where = f"{FIXTURES}/vectors.json"
        def check_input(value: dict, key: str, digest: str, domain: bytes) -> None:
            try:
                data = bytes.fromhex(value.get(key + "_hex", ""))
            except (TypeError, ValueError):
                self.problem(where, f"{key}_hex is not hexadecimal")
                return
            if not data or iroha_hash(domain + data).hex() != value.get(digest):
                self.problem(where, f"{key}_hex does not reproduce {digest}")
            if not isinstance(value.get(key), dict) or not value[key]:
                self.problem(where, f"{key} semantic input is missing")

        if vectors.get("schema") != "iroha.durable_workflow.vectors.v1":
            self.problem(where, "unknown schema")
        check_input(vectors, "plan", "plan_digest", b"iroha:durable-workflow:plan:v1\0")
        check_input(vectors, "identity", "workflow_id", b"iroha:durable-workflow:id:v1\0")
        records = vectors.get("records", [])
        if not records:
            self.problem(where, "no records")
        for record in records:
            name = record.get("name")
            check_input(record, "journal", "journal_digest", b"iroha:durable-workflow:journal:v1\0")
            try:
                data = bytes.fromhex(record.get("record_hex", ""))
            except ValueError:
                self.problem(where, f"record `{name}` is not hexadecimal")
                continue
            if len(data) > vocabulary["limits"].get("max_journal_bytes", 0):
                self.problem(where, f"record `{name}` exceeds the journal bound")
            if iroha_hash(RECORD_DOMAIN + data).hex() != record.get("record_digest"):
                self.problem(where, f"record `{name}`: record_digest is not the Iroha hash of the domain and the bytes")
            progress = record.get("progress", {})
            if progress.get("sequence") != record.get("sequence"):
                self.problem(where, f"record `{name}`: progress sequence differs")
            if progress.get("status") not in vocabulary["workflow_statuses"]:
                self.problem(where, f"record `{name}`: unknown status")
            if progress.get("atomicity") != "per_transaction_only":
                self.problem(where, f"record `{name}`: atomicity must be per_transaction_only")
            known = vocabulary["transaction_states"] + vocabulary["round_states"]
            for step in progress.get("steps", []):
                if step.get("state") not in known:
                    self.problem(where, f"record `{name}`: unknown step state `{step.get('state')}`")
            if progress.get("partial_completion", {}).get("rolled_back_steps") != []:
                self.problem(where, f"record `{name}`: something is reported as rolled back")
        for key in ("plan_digest", "workflow_id", "round_identity_step_1", "transcript_digest_step_1"):
            value = vectors.get(key, "")
            if not re.fullmatch(r"[0-9a-f]{64}", value) or int(value[-1], 16) % 2 == 0:
                self.problem(where, f"`{key}` is not a marked 32-byte Iroha hash")

    # --------------------------------------------------------------------- spec
    def check_spec(self, vocabulary: dict) -> None:
        path = self.root / SPEC
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            self.problem(SPEC, f"cannot be read: {error}")
            return
        named = {
            "transaction_states": "transaction state",
            "round_states": "round state",
            "workflow_statuses": "workflow status",
            "error_codes": "error code",
            "workflow_kinds": "workflow kind",
        }
        for key, what in named.items():
            for value in vocabulary[key]:
                if f"`{value}`" not in text:
                    self.problem(SPEC, f"does not name {what} `{value}`")
        plain = text.replace(",", "")
        for name, value in vocabulary["limits"].items():
            if not re.search(rf"\|\s*{value}\s*\|", plain):
                self.problem(SPEC, f"limit table lacks the value {value} of `{name}`")
        if "per_transaction_only" not in text:
            self.problem(SPEC, "does not state the atomicity")

    # ---------------------------------------------------------------------- run
    def run(self) -> dict:
        machine = self.load(f"{FIXTURES}/state_machine.json")
        manifest = self.load(f"{FIXTURES}/manifest.json")
        vectors = self.load(f"{FIXTURES}/vectors.json")
        summary = {"scenarios": 0, "rules": 0}
        if machine is None or manifest is None:
            return summary
        vocabulary = self.check_state_machine(machine)
        if manifest.get("schema") != "iroha.durable_workflow.fixtures.v1":
            self.problem(f"{FIXTURES}/manifest.json", "unknown schema")
        listed = manifest.get("scenarios", [])
        directory = self.root / FIXTURES / "scenarios"
        present = sorted(path.name for path in directory.glob("*")) if directory.is_dir() else []
        if listed != present:
            self.problem(f"{FIXTURES}/manifest.json", "`scenarios` must list exactly the files of scenarios/, sorted")
        for name in present:
            scenario = self.load(f"{FIXTURES}/scenarios/{name}")
            if scenario is not None:
                self.check_scenario(name, scenario, vocabulary)
        if vectors is not None:
            self.check_vectors(vectors, vocabulary)
        self.check_spec(vocabulary)

        scenarios = f"{FIXTURES}/scenarios"
        for rule in vocabulary["rules"]:
            if rule not in self.seen_rules:
                self.problem(scenarios, f"no scenario exercises rule `{rule}`")
        for category in CATEGORIES:
            if category not in self.seen_categories:
                self.problem(scenarios, f"no scenario of category `{category}`")
        for state in vocabulary["transaction_states"] + vocabulary["round_states"]:
            if state not in self.seen_states:
                self.problem(scenarios, f"no scenario leaves a step in state `{state}`")
        for status in vocabulary["workflow_statuses"]:
            if status not in self.seen_statuses:
                self.problem(scenarios, f"no scenario leaves the workflow `{status}`")
        for state in vocabulary["transaction_states"] + vocabulary["round_states"]:
            if state not in self.seen_cancel_states:
                self.problem(scenarios, f"no scenario cancels a workflow whose current step is `{state}`")
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
        print(f"durable workflow contract: {len(checker.problems)} inconsistencies", file=sys.stderr)
        return 1
    print(
        "durable workflow contract: "
        f"{summary['scenarios']} scenarios exercise {summary['rules']} rules; "
        "state machine, traces, vectors and specification are consistent"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
