"""Tests for scripts/check_operation_contract.py.

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
SCRIPT = ROOT / "scripts" / "check_operation_contract.py"
SPEC = importlib.util.spec_from_file_location("check_operation_contract", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)

FIXTURES = checker.FIXTURES
COPIED = (
    checker.REDUCER,
    checker.SPEC,
    checker.RESOURCE_CONTRACT,
    checker.DISPATCH_SOURCE,
    checker.CLIENT_SOURCE,
    "crates/iroha_data_model/src/transaction/signed_attachments.rs",
    "crates/iroha_data_model/src/parameter/system.rs",
)
HAPPY = "one_call_finalizes_on_authenticated_evidence.json"
AMBIGUOUS = "ambiguous_submit_is_recovered_read_only.json"
RETRANSMISSION = "process_dies_during_dispatch_then_only_authorized_identical_bytes_are_resent.json"
LOCAL = "local_verification_failure_dispatches_nothing.json"
OVER_BOUND = "over_bound_action_count_is_refused_at_prepare_without_a_split.json"
EXTERNAL = "external_signature_mismatch_is_refused_before_persisting.json"
UPLOAD = "private_material_upload_is_refused.json"
TORII = "torii_status_mode_is_explicit_and_trusts_the_queried_torii.json"
EXPIRY = "authenticated_mode_never_closes_on_torii_reported_expiry.json"
CANCEL_AFTER = "cancel_after_dispatch_stops_observation_only.json"
CANCEL_BEFORE = "cancel_before_dispatch_drops_the_signed_bytes.json"


class Tree:
    """A temporary copy of the fixture set, its reducer, specification and source owners."""

    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        shutil.copytree(ROOT / FIXTURES, self.root / FIXTURES)
        for relative in COPIED:
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, self.root / relative)

    def path(self, name: str) -> Path:
        return self.root / FIXTURES / name

    def edit(self, name: str, change) -> None:
        path = self.path(name)
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def replace(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        assert old in text, f"{old!r} not in {relative}"
        path.write_text(text.replace(old, new), encoding="utf-8")

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
        self.assertGreaterEqual(summary["scenarios"], 20)
        self.assertEqual(summary["rules"], len(checker.RULES))
        self.assertEqual(checker.main(["--root", str(ROOT)]), 0)

    def test_source_expressions_are_evaluated_textually(self) -> None:
        text = "pub const A: usize = 9 * 1024 * 1024;\npub const B: usize =\n    A + 64 * 1024;\n"
        self.assertEqual(checker.evaluate(checker.rust_definition(text, "B"), text), 9_502_720)
        function = "pub mod transaction {\n    pub const fn cap() -> NonZeroU64 {\n        // ten MiB\n        nonzero!(10_485_760_u64)\n    }\n}\n"
        self.assertEqual(
            checker.evaluate(checker.rust_definition(function, "cap", "pub mod transaction {"), function),
            10_485_760,
        )
        with self.assertRaises(ValueError):
            checker.evaluate("A.pow(2)", text)

    def test_definite_rows_are_read_from_the_source(self) -> None:
        rows = checker.definite_rows((ROOT / checker.DISPATCH_SOURCE).read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(rows), 10)
        self.assertEqual(rows[0][4], "already_known")
        self.assertTrue(all(row[4] in checker.DISPATCH_CLASSES for row in rows))


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

    def contract(self, change) -> None:
        self.tree.edit("contract.json", change)

    # ---- the contract against its owners
    def test_call_order_is_the_memo_order(self) -> None:
        def change(contract):
            calls = contract["calls"]
            calls[2], calls[3] = calls[3], calls[2]

        self.contract(change)
        self.assert_problem("calls differ from the memo order")

    def test_shared_error_codes_are_fixed(self) -> None:
        self.contract(lambda contract: contract["error_codes"].pop())
        self.assert_problem("error codes differ from the fifteen shared operation codes")

    def test_bound_errors_carry_actual_and_maximum(self) -> None:
        def change(contract):
            for field in contract["error_fields"]:
                if field["name"] == "maximum":
                    field["required_for"] = []

        self.contract(change)
        self.assert_problem("`ResourceLimitExceeded` must carry `maximum`")

    def test_batch_limit_must_equal_the_source_and_the_resource_contract(self) -> None:
        def change(contract):
            contract["batch_limits"][0]["maximum"] = 17

        self.contract(change)
        self.assert_problem("bound `attachment.max_actions` differs from the source")
        self.assert_problem("differs from specs/zk_resource_contract.json")

    def test_a_changed_source_constant_is_detected(self) -> None:
        self.tree.replace(
            "crates/iroha_data_model/src/transaction/signed_attachments.rs",
            "pub const SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1: usize = 16;",
            "pub const SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1: usize = 15;",
        )
        self.assert_problem("bound `attachment.max_occurrences` differs from the source")

    def test_a_changed_committed_default_is_detected(self) -> None:
        self.tree.replace(
            "crates/iroha_data_model/src/parameter/system.rs",
            "nonzero!(10_485_760_u64)",
            "nonzero!(10_485_761_u64)",
        )
        self.assert_problem("bound `transaction.max_tx_bytes` differs from the source")
        self.assert_problem("bound `transaction.max_decompressed_bytes` differs from the source")

    def test_definite_rows_must_equal_the_submission_owner(self) -> None:
        def change(contract):
            contract["dispatch_classification"]["definite_rows"][0]["class"] = "refused"

        self.contract(change)
        self.assert_problem("definite_rows differ from DEFINITE_DISPATCH_ROWS")

    def test_a_new_source_row_must_be_published(self) -> None:
        self.tree.replace(
            checker.DISPATCH_SOURCE,
            'definite(429, "queue_full", "PRTRY:QUEUE_FULL", true, Deferred),',
            'definite(429, "queue_full", "PRTRY:QUEUE_FULL", true, Deferred),\n'
            '        definite(429, "queue_overflow", "PRTRY:QUEUE_OVERFLOW", true, Deferred),',
        )
        self.assert_problem("definite_rows differ from DEFINITE_DISPATCH_ROWS")

    def test_scenario_codes_follow_the_rendered_class_codes(self) -> None:
        def change(contract):
            for entry in contract["dispatch_classification"]["classes"]:
                if entry["id"] == "deferred":
                    entry["error_code"] = "AuthorizationDenied"

        self.contract(change)
        self.assert_problem("the trace implies AuthorizationDenied at stage `submit`")

    def test_outcome_unknown_evidence_must_equal_the_client(self) -> None:
        def change(contract):
            contract["dispatch_classification"]["outcome_unknown_evidence"]["reject_code"] = "other"

        self.contract(change)
        self.assert_problem("outcome-unknown evidence `reject_code` differs")

    def test_only_authenticated_finality_is_the_default(self) -> None:
        def change(contract):
            for mode in contract["finality_modes"]:
                mode["default"] = mode["id"] == "torii_status"

        self.contract(change)
        self.assert_problem("exactly one default finality mode")

    def test_review_state_stays_provisional(self) -> None:
        self.contract(lambda contract: contract["review"].update(state="reviewed"))
        self.assert_problem("must stay provisional")

    def test_batches_are_never_split(self) -> None:
        self.contract(lambda contract: contract["batch"].update(split="when_over_bound"))
        self.assert_problem("never split")

    def test_durable_states_follow_the_reducer(self) -> None:
        self.contract(lambda contract: contract["durable_states"].pop(0))
        self.assert_problem("durable states differ from the reducer")

    # ---- scenarios
    def test_local_verification_failure_ends_the_call(self) -> None:
        def change(scenario):
            scenario["calls"][0]["expect"]["effects"].append("build:1")
            scenario["calls"][0]["script"]["builds"] = ["ok"]

        self.scenario(LOCAL, change)
        self.assert_problem("(invalid) must end the call")

    def test_build_needs_a_local_verification(self) -> None:
        def change(scenario):
            call = scenario["calls"][1]
            call["expect"]["effects"].remove("local_verify:1")
            del call["script"]["local_verifications"]

        self.scenario(LOCAL, change)
        self.assert_problem("must follow a successful local verification")

    def test_retransmission_needs_authorization(self) -> None:
        self.scenario(RETRANSMISSION, lambda scenario: scenario["calls"][2].pop("options"))
        self.assert_problem("re-dispatched an unresolved identity without authorization")

    def test_retransmission_needs_a_fresh_exact_absence_read(self) -> None:
        def change(scenario):
            scenario["calls"][2]["script"]["statuses"] = ["observed", "applied"]

        self.scenario(RETRANSMISSION, change)
        self.assert_problem("was not preceded by a fresh exact-absence read")

    def test_resume_reads_first(self) -> None:
        def change(scenario):
            scenario["calls"][1]["expect"]["effects"].insert(0, "dispatch:1")
            scenario["calls"][1]["script"]["dispatches"] = ["accepted"]

        self.scenario(RETRANSMISSION, change)
        self.assert_problem("resume of an unresolved identity started with `dispatch:1`")

    def test_read_only_recovery_sends_nothing(self) -> None:
        def change(scenario):
            call = scenario["calls"][1]
            call["expect"]["effects"].append("dispatch:1")
            call["script"]["dispatches"] = ["ambiguous"]

        self.scenario(AMBIGUOUS, change)
        self.assert_problem("read-only recovery caused `dispatch:1`")

    def test_over_bound_refusal_is_recomputed(self) -> None:
        self.scenario(OVER_BOUND, lambda scenario: scenario["calls"][0]["expect"]["result"].update(action_index=15))
        self.assert_problem("the refusal must carry action_index 16")

    def test_over_bound_request_is_never_split(self) -> None:
        def change(scenario):
            scenario["calls"][1]["expect"]["effects"] = ["prove:1"]
            scenario["calls"][1]["script"] = {"proofs": ["ok"]}

        self.scenario(OVER_BOUND, change)
        self.assert_problem("nothing is split")

    def test_external_mismatch_is_not_persisted_or_dispatched(self) -> None:
        def change(scenario):
            call = scenario["calls"][4]
            call["expect"]["effects"].append("dispatch:1")
            call["script"]["dispatches"] = ["accepted"]

        self.scenario(EXTERNAL, change)
        self.assert_problem("(wrong_key) must end the call")

    def test_advanced_calls_need_their_preconditions(self) -> None:
        def change(scenario):
            # Build without a preceding local verification.
            del scenario["calls"][2]

        self.scenario(EXTERNAL, change)
        self.assert_problem("`build` is not valid after")

    def test_upload_refusal_has_no_network_effect(self) -> None:
        def change(scenario):
            scenario["calls"][0]["expect"]["effects"].append("upload:witness")

        self.scenario(UPLOAD, change)
        self.assert_problem("malformed effect `upload:witness`")

    def test_upload_refusal_is_unsupported_operation_at_prove(self) -> None:
        self.scenario(UPLOAD, lambda scenario: scenario["calls"][0]["expect"]["result"].update(error="AuthorizationDenied"))
        self.assert_problem("the trace implies UnsupportedOperation at stage `prove`")

    def test_unknown_private_material_is_rejected(self) -> None:
        self.scenario(UPLOAD, lambda scenario: scenario["calls"][0]["script"].update(proofs=["upload_required:password"]))
        self.assert_problem("names no private material of the contract")

    def test_torii_status_mode_reads_no_finality_proof(self) -> None:
        def change(scenario):
            call = scenario["calls"][0]
            call["expect"]["effects"].append("finality:1")
            call["script"]["finality_proofs"] = ["verified"]

        self.scenario(TORII, change)
        self.assert_problem("is a finality read in the torii_status mode")

    def test_authenticated_mode_never_closes_on_expiry(self) -> None:
        def change(scenario):
            expect = scenario["calls"][0]["expect"]
            expect["state"] = "rejected"
            expect["status"] = "failed"
            expect["result"] = {"error": "Expired", "stage": "reconcile"}
            del expect["identity"]

        self.scenario(EXPIRY, change)
        self.assert_problem("no scripted token explains Expired")

    def test_observation_stays_within_its_bound(self) -> None:
        self.scenario(HAPPY, lambda scenario: scenario["calls"][0]["options"].update(observation_timeout_ms=0))
        self.assert_problem("beyond its observation bound")

    def test_unconsumed_script_entries_are_rejected(self) -> None:
        self.scenario(HAPPY, lambda scenario: scenario["calls"][0]["script"]["statuses"].append("applied"))
        self.assert_problem("scripted `statuses` entry 3 is not consumed")

    def test_cancelling_operation_starts_nothing(self) -> None:
        def change(scenario):
            call = scenario["calls"][2]
            call["expect"]["effects"] = ["status:1", "dispatch:1", "status:1"]
            call["script"] = {"statuses": ["absent", "observed"], "dispatches": ["accepted"]}

        self.scenario(CANCEL_AFTER, change)
        self.assert_problem("a cancelling operation re-dispatched `dispatch:1`")

    def test_cancellation_before_admission_drops_the_bytes(self) -> None:
        self.scenario(CANCEL_BEFORE, lambda scenario: scenario["calls"][1]["expect"].update(status="cancelling"))
        self.assert_problem("cancellation before any possible admission ends cancelled_before_submission")

    def test_unknown_tokens_and_codes_are_rejected(self) -> None:
        def change(scenario):
            call = scenario["calls"][0]
            call["script"]["dispatches"] = ["maybe"]
            call["expect"]["result"] = {"error": "Whatever", "stage": "submit"}

        self.scenario(LOCAL, change)
        self.assert_problem("unknown `dispatches` token `maybe`")
        self.assert_problem("unknown error code `Whatever`")

    # ---- coverage, manifest and specification
    def test_every_rule_needs_a_scenario(self) -> None:
        def change(contract):
            contract["rules"].append({"id": "new_rule", "statement": "Something new."})

        self.contract(change)
        self.assert_problem("rules differ from the contract's rule set")

    def test_every_call_stage_needs_an_error_scenario(self) -> None:
        def change(scenario):
            call = scenario["calls"][0]
            call["script"]["local_verifications"] = ["ok"]
            call["script"]["builds"] = ["fail:LocalResourceUnavailable"]
            call["expect"]["effects"].append("build:1")
            call["expect"]["result"] = {"error": "LocalResourceUnavailable", "stage": "build", "resumable": True}

        self.scenario(LOCAL, change)
        self.assert_problem("no scenario reports an error at stage `local_verify`")

    def test_manifest_must_list_every_scenario(self) -> None:
        self.tree.edit("manifest.json", lambda manifest: manifest["scenarios"].pop())
        self.assert_problem("must list exactly the files")

    def test_a_pending_file_cannot_appear_silently(self) -> None:
        self.tree.path("vectors.json").write_text("{}\n", encoding="utf-8")
        self.assert_problem("`vectors.json` is listed as pending but exists")

    def test_specification_names_every_identifier(self) -> None:
        self.tree.replace(checker.SPEC, "`local_verify`", "`local verification`")
        self.assert_problem("does not name stage `local_verify`")

    def test_specification_states_the_provisional_review(self) -> None:
        self.tree.replace(checker.SPEC, checker.PROVISIONAL_NOTE, "Reviewed")
        self.assert_problem(f"does not state `{checker.PROVISIONAL_NOTE}`")


if __name__ == "__main__":
    unittest.main()
