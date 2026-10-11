"""Tests for scripts/check_durable_workflow_contract.py.

The tracked fixture set must pass. Each mutation of a copy must fail with the
message that names the broken rule, so the checker cannot pass by checking
nothing.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_durable_workflow_contract.py"
SPEC = importlib.util.spec_from_file_location("check_durable_workflow_contract", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)

FIXTURES = checker.FIXTURES
AMBIGUOUS = "ambiguous_dispatch_then_applied_continues_without_resubmitting.json"
REPLACEMENT = "replacement_identity_only_after_authoritative_rejection_and_explicit_retry.json"
CANCEL = "cancel_while_outcome_unknown_stops_observation_only.json"
RETRANSMISSION = "authorized_retransmission_sends_identical_bytes_after_exact_absence.json"


class Tree:
    """A temporary copy of the fixture set and the specification."""

    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        shutil.copytree(ROOT / FIXTURES, self.root / FIXTURES)
        (self.root / "specs").mkdir()
        shutil.copy(ROOT / checker.SPEC, self.root / checker.SPEC)

    def path(self, name: str) -> Path:
        return self.root / FIXTURES / name

    def edit(self, name: str, change) -> None:
        path = self.path(name)
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def problems(self) -> list[str]:
        check = checker.Checker(self.root)
        check.run()
        return check.problems

    def close(self) -> None:
        self.directory.cleanup()


class TrackedSet(unittest.TestCase):
    def test_tracked_fixture_set_is_consistent(self) -> None:
        check = checker.Checker(ROOT)
        summary = check.run()
        self.assertEqual(check.problems, [])
        self.assertGreaterEqual(summary["scenarios"], 40)
        self.assertEqual(checker.main(["--root", str(ROOT)]), 0)

    def test_iroha_hash_sets_the_marker_bit(self) -> None:
        digest = checker.iroha_hash(b"")
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest[-1] & 1, 1)
        # Blake2b-256 of the empty string ends in 0xa8; the marker makes it 0xa9.
        self.assertEqual(
            digest.hex(),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a9",
        )

    def test_vocabulary_helper_reads_strings_and_objects(self) -> None:
        self.assertEqual(checker.ids(["a", {"id": "b"}]), ["a", "b"])


class Mutations(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree()
        self.addCleanup(self.tree.close)
        self.assertEqual(self.tree.problems(), [], "the copy must start consistent")

    def assert_problem(self, fragment: str) -> None:
        problems = self.tree.problems()
        self.assertTrue(
            any(fragment in problem for problem in problems),
            f"no problem mentions {fragment!r}: {problems[:5]}",
        )
        self.assertEqual(checker.main(["--root", str(self.tree.root)]), 1)

    def scenario(self, name: str, change) -> None:
        self.tree.edit(f"scenarios/{name}", change)

    def test_effect_trigger_must_be_an_external_effect(self) -> None:
        self.scenario("cancel_during_round_recovery_prevents_restart.json", lambda value:
                      value["calls"][1]["concurrent"].update(when="effect:concurrent:cancel:cancelling"))
        self.assert_problem("malformed `concurrent`")

    def test_concurrent_actor_must_be_an_object(self) -> None:
        for actor in (None, [], "cancel"):
            with self.subTest(actor=actor):
                self.scenario("cancel_during_round_recovery_prevents_restart.json", lambda value:
                              value["calls"][1].update(concurrent=actor))
                self.assert_problem("malformed `concurrent`")

    def test_effect_trigger_must_be_reached(self) -> None:
        self.scenario("cancel_during_round_recovery_prevents_restart.json", lambda value:
                      value["calls"][1]["concurrent"].update(when="effect:round_recover:1"))
        self.assert_problem("effect-triggered concurrency never reaches its trigger")

    def test_effect_actor_must_act_inside_the_call(self) -> None:
        def change(value):
            effects = value["calls"][1]["expect"]["effects"]
            effects[1], effects[2] = effects[2], effects[1]
        self.scenario("cancel_during_round_recovery_prevents_restart.json", change)
        self.assert_problem("effect-triggered actor must act immediately inside its call")

    def test_round_cannot_restart_after_effect_triggered_cancellation(self) -> None:
        self.scenario("cancel_during_round_recovery_prevents_restart.json", lambda value:
                      value["calls"][1]["expect"]["effects"].append("round_start:0"))
        self.assert_problem("an effect after concurrent cancellation caused `round_start:0`")

    # ---- state machine
    def test_state_that_may_commit_must_not_be_cancellable(self) -> None:
        def change(machine):
            machine["transaction_transitions"].append(
                {"from": "pending", "event": "cancel", "guard": "always", "to": "cancelled_before_submission"}
            )

        self.tree.edit("state_machine.json", change)
        self.assert_problem("may still commit is reopened, rebuilt or cancelled")

    def test_unresolved_identity_must_not_be_replaced(self) -> None:
        def change(machine):
            machine["transaction_transitions"].append(
                {"from": "outcome_unknown", "event": "open_attempt", "guard": "identities_remaining", "to": "prepared"}
            )

        self.tree.edit("state_machine.json", change)
        self.assert_problem("may still commit is reopened, rebuilt or cancelled")

    def test_retransmission_needs_its_guard(self) -> None:
        def change(machine):
            for row in machine["transaction_transitions"]:
                if row["from"] == "outcome_unknown" and row["event"] == "dispatch_intent":
                    row["guard"] = "dispatches_remaining"

        self.tree.edit("state_machine.json", change)
        self.assert_problem("needs guard `retransmission_authorized_after_exact_absence`")

    def test_ambiguous_rows_are_rejected(self) -> None:
        def change(machine):
            machine["transaction_transitions"].append(
                {"from": "planned", "event": "open_attempt", "guard": "identities_remaining", "to": "prepared"}
            )

        self.tree.edit("state_machine.json", change)
        self.assert_problem("not mutually exclusive")

    def test_terminal_status_has_no_exit(self) -> None:
        def change(machine):
            machine["workflow_transitions"].append(
                {"from": "cancelled", "event": "all_steps_done", "to": "completed"}
            )

        self.tree.edit("state_machine.json", change)
        self.assert_problem("terminal workflow status `cancelled` has an exit")

    def test_atomicity_cannot_be_changed(self) -> None:
        self.tree.edit("state_machine.json", lambda machine: machine.update(atomicity="workflow"))
        self.assert_problem("atomicity must be per_transaction_only")

    def test_shared_error_codes_are_fixed(self) -> None:
        def change(machine):
            machine["error_codes"][0]["id"] = "BadInput"

        self.tree.edit("state_machine.json", change)
        self.assert_problem("shared operation error codes differ")

    # ---- scenarios
    def test_manifest_must_list_every_scenario(self) -> None:
        self.tree.edit("manifest.json", lambda manifest: manifest["scenarios"].pop())
        self.assert_problem("must list exactly the files")

    def test_partial_completion_must_follow_from_step_states(self) -> None:
        def change(scenario):
            scenario["calls"][0]["expect"]["partial_completion"]["unresolved_steps"] = []

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("does not follow from the step states")

    def test_nothing_is_ever_rolled_back(self) -> None:
        def change(scenario):
            scenario["calls"][-1]["expect"]["partial_completion"]["rolled_back_steps"] = [0]

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("does not follow from the step states")

    def test_resume_must_read_before_anything_else(self) -> None:
        def change(scenario):
            effects = scenario["calls"][1]["expect"]["effects"]
            effects.insert(0, "dispatch:0#1")

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("resume of an unresolved transaction started with `dispatch:0#1`")

    def test_unresolved_identity_is_not_resent_without_authorization(self) -> None:
        def change(scenario):
            effects = scenario["calls"][1]["expect"]["effects"]
            effects.insert(1, "dispatch:0#1")

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("re-dispatched an unresolved identity without authorization")

    def test_retransmission_needs_a_fresh_read(self) -> None:
        def change(scenario):
            call = scenario["calls"][1]
            call["expect"]["effects"] = ["status:0#1", "sleep:1000", "dispatch:0#1", "status:0#1"]

        self.scenario(RETRANSMISSION, change)
        self.assert_problem("was not preceded by a fresh status read")

    def test_replacement_needs_explicit_retry(self) -> None:
        def change(scenario):
            del scenario["calls"][2]["options"]

        self.scenario(REPLACEMENT, change)
        self.assert_problem("was built without `retry_rejected_step`")

    def test_replacement_needs_a_closed_identity(self) -> None:
        def change(scenario):
            # Pretend the first identity was still pending when the second was built.
            expect = scenario["calls"][1]["expect"]
            expect["steps"] = ["pending", "planned"]
            expect["partial_completion"].update(failed_steps=[], unresolved_steps=[0])

        self.scenario(REPLACEMENT, change)
        self.assert_problem("was built while the previous one was `pending`")

    def test_cancelling_workflow_starts_nothing(self) -> None:
        def change(scenario):
            scenario["calls"][2]["expect"]["effects"].append("build:1#1")

        self.scenario(CANCEL, change)
        self.assert_problem("a cancelling workflow caused `build:1#1`")

    def test_read_only_recovery_sends_nothing(self) -> None:
        def change(scenario):
            scenario["calls"][3]["expect"]["effects"].append("dispatch:0#1")

        self.scenario(CANCEL, change)
        self.assert_problem("read-only recovery caused `dispatch:0#1`")

    def test_unknown_tokens_states_and_codes_are_rejected(self) -> None:
        def change(scenario):
            call = scenario["calls"][0]
            call["script"]["dispatches"] = ["maybe"]
            call["expect"]["steps"][0] = "sent"
            call["expect"]["result"]["error"] = "Whatever"

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("unknown `dispatches` token `maybe`")
        self.assert_problem("state `sent` is not a state of a transaction step")
        self.assert_problem("unknown error code `Whatever`")

    def test_status_must_agree_with_steps(self) -> None:
        def change(scenario):
            scenario["calls"][0]["expect"]["status"] = "completed"

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("status `completed` must hold exactly when every step is done")

    def test_every_rule_needs_a_scenario(self) -> None:
        def change(machine):
            machine["rules"].append({"id": "new_rule", "statement": "Something new."})

        self.tree.edit("state_machine.json", change)
        self.assert_problem("no scenario exercises rule `new_rule`")

    def test_cancellation_is_exercised_in_every_state(self) -> None:
        def change(scenario):
            del scenario["calls"][1:]

        self.scenario("cancel_while_ready_to_sign_drops_the_payload.json", change)
        self.assert_problem("no scenario cancels a workflow whose current step is `ready_to_sign`")

    def test_corrupted_journal_causes_no_effect(self) -> None:
        def change(scenario):
            scenario["calls"][2]["expect"]["effects"] = ["status:0#1"]

        self.scenario("bit_flip_is_detected_and_nothing_is_sent.json", change)
        self.assert_problem("an unreadable journal must cause no external effect")

    # ---- vectors and specification
    def test_record_digest_is_recomputed(self) -> None:
        def change(vectors):
            record = vectors["records"][0]
            record["record_hex"] = record["record_hex"][:-2] + "00"

        self.tree.edit("vectors.json", change)
        self.assert_problem("record_digest is not the Iroha hash")

    def test_specification_must_name_every_state_and_limit(self) -> None:
        spec = self.tree.root / checker.SPEC
        text = spec.read_text(encoding="utf-8")
        spec.write_text(
            text.replace("`outcome_unknown`", "`unknown`").replace("16,777,216", "1"),
            encoding="utf-8",
        )
        self.assert_problem("does not name transaction state `outcome_unknown`")
        self.assert_problem("limit table lacks the value 16777216")


if __name__ == "__main__":
    unittest.main()
