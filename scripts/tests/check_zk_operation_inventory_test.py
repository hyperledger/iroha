"""Drift tests for the ZK operation and admission-route inventory checker.

Every mutation is applied in memory: the inventory is deep-copied and the tree is read
through `Tree(overrides=...)`. Nothing in the checkout is written.

Run with either of:
    python3 -m unittest scripts/tests/check_zk_operation_inventory_test.py
    python3 -m pytest -q scripts/tests/check_zk_operation_inventory_test.py
"""

from __future__ import annotations

import copy
import importlib.util
import io
import re
from collections import Counter
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "check_zk_operation_inventory.py"
_SPEC = importlib.util.spec_from_file_location("check_zk_operation_inventory", _PATH)
C = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = C
_SPEC.loader.exec_module(C)

INVENTORY = C.load()
REGISTRY = "crates/iroha_data_model/src/isi/registry/wire_ids.rs"
PRIVACY_MODEL = "crates/iroha_data_model/src/privacy.rs"
PRIVACY_HANDLERS = "crates/iroha_core/src/smartcontracts/isi/privacy.rs"
VERIFIER = "crates/iroha_core_privacy/src/privacy_verifier.rs"
PROFILES = "crates/iroha_core_privacy/src/privacy_profiles.rs"
SYSCALLS = "crates/ivm_abi/src/syscalls.rs"
BUILTINS = "crates/kotodama_surface/src/builtins.rs"
VERIFICATION = "crates/iroha_core_zk/src/verification.rs"
ZK_LIB = "crates/iroha_core_zk/src/lib.rs"
REAL = C.Tree()


def source(path: str) -> str:
    text = REAL.read(path)
    assert text is not None, path
    return text


def replaced(path: str, old: str, new: str) -> dict:
    text = source(path)
    assert old in text, f"{old!r} is not in {path}"
    return {path: text.replace(old, new, 1)}


def appended_registry(line: str) -> dict:
    """The registry with one more entry before the closing of the `ALL` list."""
    text = source(REGISTRY)
    # The list closes at the first `];` line after its last entry, whatever item follows it.
    closing = text.index("\n];\n", text.rindex("\n    built_in_wire_id!(")) + 1
    return {REGISTRY: f"{text[:closing]}    {line}\n{text[closing:]}"}


def run(method: str, inventory: dict | None = None, overrides: dict | None = None, catalog: str | None = None) -> list[str]:
    checker = C.Checker(inventory if inventory is not None else INVENTORY, C.Tree(C.ROOT, overrides), catalog)
    getattr(checker, method)()
    return checker.errors


def edited(edit) -> dict:
    inventory = copy.deepcopy(INVENTORY)
    edit(inventory)
    return inventory


def operation(inventory: dict, identifier: str) -> dict:
    return next(item for item in inventory["operations"] if item["id"] == identifier)


def protocol(inventory: dict, variant: str) -> dict:
    return next(item for item in inventory["exact12"]["protocols"] if item["variant"] == variant)


class Base(unittest.TestCase):
    def assert_fails(self, errors: list[str], fragment: str) -> None:
        self.assertTrue(any(fragment in error for error in errors), f"{fragment!r} not in {errors[:8]}")

    def assert_clean(self, errors: list[str]) -> None:
        self.assertEqual(errors, [])


class TrackedInventory(Base):
    """The tracked file against the real tree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = C.compiled_catalog(C.ROOT)
        cls.checker = C.Checker(INVENTORY, C.Tree(), cls.catalog)
        cls.errors = cls.checker.check()

    def test_tracked_inventory_matches_the_source(self) -> None:
        self.assert_clean(self.errors)

    def test_every_route_family_row_of_the_compiled_catalog_is_listed(self) -> None:
        if self.catalog is None:
            self.skipTest("rustc is not available to build the route exporter")
        compiled = C.tsv_rows(self.catalog)
        listed = {route["id"] for route in INVENTORY["routes"]["list"]}
        in_scope = {identifier for identifier, row in compiled.items() if C.route_in_scope(INVENTORY["routes"], row["path"])}
        self.assertEqual(in_scope, listed)

    def test_every_in_scope_registry_entry_is_an_operation_with_its_wire_id(self) -> None:
        entries = C.registry_entries(REAL, INVENTORY["registry"])
        self.assertGreater(len(entries), 300)
        in_scope = {entry["type"]: entry["wire_id"] for entry in entries if C.module_scope(INVENTORY["registry"], entry) == "in"}
        recorded = {item["isi"]["type"]: item["isi"]["wire_id"] for item in INVENTORY["operations"] if item.get("isi")}
        self.assertEqual(in_scope, recorded)
        self.assertIn("privacy::SubmitPrivacyProofV1", recorded)
        self.assertEqual(recorded["privacy::SubmitPrivacyProofV1"], "iroha.privacy.submit_proof.v1")

    def test_presence_is_never_recorded_as_delivery(self) -> None:
        records = list(INVENTORY["operations"]) + list(INVENTORY["exact12"]["protocols"])
        self.assertTrue(records)
        for record in records:
            self.assertEqual(record["status"]["delivery"], "not_delivered", record.get("id", record.get("variant")))
            self.assertTrue(record["status"]["missing"])
        states = {record["status"]["verification"] for record in records}
        self.assertTrue({"implemented", "refused", "not_applicable", "absent", "signature_only"} <= states)

    def test_the_twelve_protocols_are_exact_and_distinguish_their_four_states(self) -> None:
        rows = INVENTORY["exact12"]["protocols"]
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({row["label"] for row in rows}), 12)
        refused = {row["variant"] for row in rows if row["compiled_profile"]["state"] == "refused"}
        self.assertEqual(refused, {"ZkAcePqAuthorizationV1", "IrohaZkAmsV1", "VegaExistingCredentialZkV1", "IrohaZkX509StarkP256V1"})
        for row in rows:
            self.assertEqual(row["status"]["presence"], "registered")
            self.assertIn(row["status"]["state_effects"], ("gated", "unreachable"))
            expected = "refused" if row["variant"] in refused else "implemented"
            self.assertEqual(row["status"]["verification"], expected)

    def test_every_listed_class_job_and_role_is_present(self) -> None:
        self.assertEqual([row["variant"] for row in INVENTORY["ram_lfe"]["classes"]["list"]], ["Affine", "Bounded", "Refresh"])
        self.assertEqual([row["variant"] for row in INVENTORY["soracloud"]["job_kinds"]["list"]],
                         ["Add", "Multiply", "RotateLeft", "Bootstrap"])
        self.assertEqual(len(INVENTORY["soracloud"]["native_roles"]["list"]), 5)
        products = {product["id"] for product in INVENTORY["products"]}
        for needed in ("wg", "axt", "ivm_proof", "kaigi", "voting", "ram_lfe", "soracloud_fhe", "confidential_assets"):
            self.assertIn(needed, products)
        for name in C.ADMISSION_ROUTES:
            self.assertIn(name, INVENTORY["admission_routes"])

    def test_every_selection_site_has_a_test_or_an_owned_defect(self) -> None:
        sites = INVENTORY["guarantee_selection"]["sites"]
        self.assertGreaterEqual(len(sites), 15)
        selectors = {site["selector"] for site in sites}
        self.assertTrue({"uploaded_key", "source_hash", "catalog_membership"} <= selectors)
        for site in sites:
            self.assertTrue(site.get("rejection_tests") or site.get("open_defect"), site["id"])
            if site["chooses_guarantee"]:
                self.assertIn("owner_task", site["open_defect"])

    def test_main_passes_and_show_lists_every_operation(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(C.main(["--no-compile"]), 0)
        self.assertIn("match the tree", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(C.main(["--show"]), 0)
        self.assertEqual(len(out.getvalue().splitlines()), len(INVENTORY["operations"]))

    def test_refresh_reproduces_the_tracked_mechanical_parts(self) -> None:
        inventory = copy.deepcopy(INVENTORY)
        self.assertEqual(C.Checker(inventory, C.Tree(), None).refresh(), [])
        self.assertEqual(inventory, INVENTORY)
        operation(inventory, "kaigi::JoinKaigi")["sdk"] = {}
        inventory["sdk"]["surface"] = []
        inventory["guarantee_selection"]["selector_census"]["occurrences"][0]["count"] += 1
        inventory["digests"]["products"][0]["census"] = {}
        changes = C.Checker(inventory, C.Tree(), None).refresh()
        self.assertIn("operations[kaigi::JoinKaigi].sdk", changes)
        self.assertIn("sdk.surface", changes)
        self.assertEqual(inventory, INVENTORY)


class Registry(Base):
    def test_new_instruction_in_a_listed_family_fails(self) -> None:
        overrides = appended_registry('built_in_wire_id!(privacy::SubmitPrivacyBatchV1 => "iroha.privacy.submit_batch.v1"),')
        self.assert_fails(run("check_registry", overrides=overrides),
                          "privacy::SubmitPrivacyBatchV1 (`iroha.privacy.submit_batch.v1`) is in a listed family and is not an operation")

    def test_new_instruction_matching_a_partial_family_fails(self) -> None:
        overrides = appended_registry('built_in_wire_id!(soracloud::OpenSoracloudFheResult => "soracloud::OpenSoracloudFheResult"),')
        self.assert_fails(run("check_registry", overrides=overrides), "soracloud::OpenSoracloudFheResult")

    def test_new_registry_module_must_be_classed(self) -> None:
        overrides = appended_registry('built_in_wire_id!(wg::AssertSomethingV1 => "iroha.wg.assert.v1"),')
        self.assert_fails(run("check_registry", overrides=overrides), "module `wg`")

    def test_family_name_in_an_out_of_scope_module_fails(self) -> None:
        overrides = appended_registry('built_in_wire_id!(sorafs::SubmitSorafsZkProofV2 => "iroha.sorafs.zk_proof.v2"),')
        self.assert_fails(run("check_registry", overrides=overrides), "sorafs::SubmitSorafsZkProofV2 has a family name")

    def test_instruction_recorded_as_absent_fails_when_it_appears(self) -> None:
        overrides = appended_registry('built_in_wire_id!(zk::AssertStateWitnessV1 => "iroha.zk.assert_state_witness.v1"),')
        errors = run("check_registry", overrides=overrides)
        self.assert_fails(errors, "operations[wg.witness_assertion]: recorded as absent, but the registry now has zk::AssertStateWitnessV1")
        self.assert_fails(errors, "zk::AssertStateWitnessV1 (`iroha.zk.assert_state_witness.v1`) is in a listed family")

    def test_changed_wire_id_fails(self) -> None:
        overrides = replaced(REGISTRY, '"iroha.privacy.submit_proof.v1"', '"iroha.privacy.submit_proof.v2"')
        self.assert_fails(run("check_registry", overrides=overrides),
                          "operations[privacy::SubmitPrivacyProofV1]: wire id is `iroha.privacy.submit_proof.v2`")

    def test_removed_instruction_fails(self) -> None:
        text = source(REGISTRY)
        line = next(line for line in text.splitlines() if "kaigi::JoinKaigi =>" in line)
        self.assert_fails(run("check_registry", overrides={REGISTRY: text.replace(line + "\n", "")}),
                          "kaigi::JoinKaigi is not in the instruction registry")

    def test_operation_outside_the_classed_families_fails(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["registry"]["modules"]["kaigi"] = {"scope": "out", "reason": "test"}
        self.assert_fails(run("check_registry", edited(edit)), "kaigi::JoinKaigi is outside the classed families")

    def test_stale_module_and_exclusion_fail(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["registry"]["modules"]["no_such_module"] = {"scope": "out", "reason": "test"}
            inventory["registry"]["tripwire"]["name_exclusions"].append({"type": "sorafs::Gone", "reason": "test"})
            inventory["registry"]["tripwire"]["handler_exclusions"].append(
                {"type": "vpn::SettleVpnLease", "calls": ["verify_nothing"], "reason": "test"})
        errors = run("check_registry", edited(edit))
        self.assert_fails(errors, "module `no_such_module` is classed but the registry has no instruction in it")
        self.assert_fails(errors, "sorafs::Gone is not in the registry")
        self.assert_fails(errors, "vpn::SettleVpnLease needs no exclusion")

    def test_handler_that_starts_verifying_a_proof_fails(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/vpn.rs"
        text = source(path)
        head = "impl Execute for SettleVpnLease {"
        self.assertIn(head, text)
        body_start = text.index("{", text.index("fn execute", text.index(head)) )
        mutated = text[: body_start + 1] + "\n        verify_lease_proof(&self)?;" + text[body_start + 1 :]
        self.assert_fails(run("check_registry", overrides={path: mutated}),
                          "the handler of vpn::SettleVpnLease calls verify_lease_proof")

    def test_recorded_handler_exclusion_must_name_the_actual_calls(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["registry"]["tripwire"]["handler_exclusions"][0]["calls"] = ["verify_other_envelope"]
        self.assert_fails(run("check_registry", edited(edit)), "sorafs::ApprovePinManifest calls ['verify_council_envelope']")

    def test_handler_symbol_and_path_are_checked(self) -> None:
        def wrong_path(inventory: dict) -> None:
            operation(inventory, "zk::VerifyProof")["handler"]["path"] = "crates/iroha_core/src/smartcontracts/isi/kaigi.rs"
        self.assert_fails(run("check_registry", edited(wrong_path)), "no `impl Execute for ...VerifyProof`")

        def wrong_symbol(inventory: dict) -> None:
            operation(inventory, "zk::VerifyProof")["handler"]["symbol"] = "impl Execute for VerifyProof"
        self.assert_fails(run("check_registry", edited(wrong_symbol)), "handler symbol is `impl Execute for zk::VerifyProof`")

    def test_authority_checks_are_compared_in_both_directions(self) -> None:
        def drop(inventory: dict) -> None:
            operation(inventory, "verifying_keys::RegisterVerifyingKey")["authority"] = [
                check for check in operation(inventory, "verifying_keys::RegisterVerifyingKey")["authority"]
                if check["symbol"] != "CanManageVerifyingKeys"
            ]
        self.assert_fails(run("check_registry", edited(drop)), "the handler contains the authority check `CanManageVerifyingKeys`")

        def invent(inventory: dict) -> None:
            operation(inventory, "zk::PruneProofs")["authority"] = [
                {"path": operation(inventory, "zk::PruneProofs")["handler"]["path"], "symbol": "ensure_privacy_governance"}]
        self.assert_fails(run("check_registry", edited(invent)), "authority check `ensure_privacy_governance` is not in the handler body")

        text = source(PRIVACY_HANDLERS)
        head = "impl Execute for SubmitPrivacyProofV1 {"
        mark = "let submission = PreparedPrivacySubmissionV1::prepare(self, state_transaction)?;"
        index = text.index(mark, text.index(head))
        mutated = text[:index] + "ensure_privacy_governance(authority, state_transaction)?;\n        " + text[index:]
        self.assert_fails(run("check_registry", overrides={PRIVACY_HANDLERS: mutated}),
                          "operations[privacy::SubmitPrivacyProofV1]: the handler contains the authority check `ensure_privacy_governance`")

    def test_operation_without_authority_needs_a_note(self) -> None:
        def edit(inventory: dict) -> None:
            del operation(inventory, "zk::VerifyProof")["authority_note"]
        self.assert_fails(run("check_registry", edited(edit)), "an operation with no authority check needs authority_note")

    def test_operation_shape_is_checked(self) -> None:
        def edit(inventory: dict) -> None:
            operation(inventory, "kaigi::JoinKaigi")["product"] = "nothing"
            operation(inventory, "kaigi::LeaveKaigi")["role"] = "magic"
            operation(inventory, "kaigi::EndKaigi")["owner_tasks"] = []
            inventory["operations"].append(copy.deepcopy(operation(inventory, "kaigi::CreateKaigi")))
            operation(inventory, "wg.witness_assertion")["carrier"] = {"kind": "absent"}
            operation(inventory, "axt.envelope")["carrier"] = {"kind": "syscall"}
            operation(inventory, "ivm_proof.proved_invocation")["carrier"] = {"kind": "telepathy"}
        errors = run("check_registry", edited(edit))
        self.assert_fails(errors, "operations[kaigi::JoinKaigi]: product `nothing` is not a listed product")
        self.assert_fails(errors, "operations[kaigi::LeaveKaigi]: role must be one of")
        self.assert_fails(errors, "operations[kaigi::EndKaigi]: owner_tasks is required")
        self.assert_fails(errors, "id kaigi::CreateKaigi is listed more than once")
        self.assert_fails(errors, "an absent operation needs carrier.registry_pattern")
        self.assert_fails(errors, "operations[axt.envelope]: carrier.evidence is required")
        self.assert_fails(errors, "needs carrier.kind in")


class Status(Base):
    def test_delivery_needs_every_owning_task_implemented(self) -> None:
        def edit(inventory: dict) -> None:
            operation(inventory, "kaigi::JoinKaigi")["status"]["delivery"] = "delivered"
        self.assert_fails(run("check_registry", edited(edit)), "delivery is `delivered` while P.7 is not `implemented`")

    def test_test_evidence_is_what_the_cited_tests_show(self) -> None:
        def no_tests(inventory: dict) -> None:
            operation(inventory, "kaigi::JoinKaigi")["tests"] = []
        errors = run("check_registry", edited(no_tests))
        self.assert_fails(errors, "operations[kaigi::JoinKaigi]: test_evidence is `none`")
        self.assert_fails(errors, "operations[kaigi::JoinKaigi]: test_evidence `none` needs test_note")

        def only_ignored(inventory: dict) -> None:
            item = operation(inventory, "game::VerifyExecutionProofV1")
            self.assertEqual(item["test_evidence"], "not_default")
            item["test_evidence"] = "default"
        self.assert_fails(run("check_registry", edited(only_ignored)),
                          "operations[game::VerifyExecutionProofV1]: test_evidence is `not_default`")

        def only_feature_gated(inventory: dict) -> None:
            item = operation(inventory, "kaigi::RecordKaigiUsage")
            self.assertTrue(all(test.get("feature") or test.get("covers") for test in item["tests"]))
            item["test_evidence"] = "default"
        self.assert_fails(run("check_registry", edited(only_feature_gated)),
                          "operations[kaigi::RecordKaigiUsage]: test_evidence is `not_default`")

        def note_dropped(inventory: dict) -> None:
            del operation(inventory, "game::SettleGameSessionV1")["test_note"]
        self.assert_fails(run("check_registry", edited(note_dropped)),
                          "operations[game::SettleGameSessionV1]: test_evidence `none` needs test_note")

        def evidence_on_a_refusal(inventory: dict) -> None:
            operation(inventory, "zk::SubmitBallot")["test_evidence"] = "default"
        self.assert_fails(run("check_registry", edited(evidence_on_a_refusal)),
                          "operations[zk::SubmitBallot]: test_evidence belongs to a status in")

        def unavailable(inventory: dict) -> None:
            item = operation(inventory, "zk::SubmitBallot")
            item["status"]["verification"] = "implemented"
            item["tests"] = operation(inventory, "kaigi::JoinKaigi")["tests"]
        self.assert_fails(run("check_registry", edited(unavailable)),
                          "verification is `implemented`, but relation voting.standalone_ballot is `unavailable`")

    def test_a_cited_test_reaches_the_verifier_or_says_what_it_covers(self) -> None:
        preflight = {"path": VERIFIER, "test": "private_ivm_preflight_uses_retained_anchor_and_current_mutation_head"}

        def preflight_as_evidence(inventory: dict) -> None:
            row = protocol(inventory, "IrohaIvmPrivateNoteStarkV1")
            row["tests"] = [dict(preflight)]
        errors = run("check_exact12", edited(preflight_as_evidence))
        self.assert_fails(errors, "exact12[IrohaIvmPrivateNoteStarkV1]: test private_ivm_preflight_uses_retained_anchor_and_current_mutation_head "
                                  "does not name `verify_ivm_private_note_action_v1`")
        self.assertEqual(protocol(INVENTORY, "IrohaIvmPrivateNoteStarkV1")["test_evidence"], "none")

        def prover_side_test(inventory: dict) -> None:
            operation(inventory, "nexus::RegisterVerifiedFeeSponsorVaultAllocation")["tests"] = [
                {"path": "crates/fastpq_prover/src/axt_binding/tests.rs", "test": "bind_axt_batch_rejects_parameter_mismatch"}]
        errors = run("check_registry", edited(prover_side_test))
        self.assert_fails(errors, "operations[nexus::RegisterVerifiedFeeSponsorVaultAllocation]: test bind_axt_batch_rejects_parameter_mismatch does not name")
        self.assert_fails(errors, "operations[nexus::RegisterVerifiedFeeSponsorVaultAllocation]: test_evidence is `none`")

        def table_test(inventory: dict) -> None:
            relation = next(item for item in inventory["relations"] if item["id"] == "native_pipa_r.confidential_transfer")
            relation["tests"] = [{"path": "crates/iroha_core_zk/src/verification/tests.rs",
                                  "test": "every_admitted_native_circuit_has_one_explicit_relation"}]
        self.assert_fails(run("check_products", edited(table_test)),
                          "relations[native_pipa_r.confidential_transfer]: test every_admitted_native_circuit_has_one_explicit_relation does not name `verify_for_relation`")

        def another_relation(inventory: dict) -> None:
            relation = next(item for item in inventory["relations"] if item["id"] == "native_pipa_r.confidential_transfer")
            relation["tests"] = [{"path": "crates/iroha_core_zk/src/verification/tests.rs",
                                  "test": "backend_confusion_and_unknown_circuits_reject_before_crypto"}]
        self.assert_fails(run("check_products", edited(another_relation)), "and none of ['ConfidentialTransfer']")

    def test_emptying_a_cited_test_changes_the_evidence(self) -> None:
        text = source(VERIFIER)
        row = protocol(INVENTORY, "AnonymousPgcKOutOfNV1")
        self.assertEqual(row["test_evidence"], "default")
        for test in row["tests"]:
            start = text.index("{", text.index(f"fn {test['test']}("))
            text = text[:start] + "{}" + text[C.balanced(text, start):]
        self.assert_fails(run("check_exact12", overrides={VERIFIER: text}),
                          "exact12[AnonymousPgcKOutOfNV1]: test_evidence is `none`")

    def test_an_operation_reaches_its_verifier_through_its_recorded_path(self) -> None:
        self.assert_clean([error for error in run("check_registry") if "verifier_path" in error])

        def cut(inventory: dict) -> None:
            operation(inventory, "private_settlement::FinalizeAtomicPrivateSettlementV1")["verifier_path"].pop()
        self.assert_fails(run("check_registry", edited(cut)),
                          "operations[private_settlement::FinalizeAtomicPrivateSettlementV1]: verifier_path: `plan_private_settlement_receipt_v1` does not name")

        def elsewhere(inventory: dict) -> None:
            item = operation(inventory, "zk::VerifyProof")
            item["verifier_path"][0] = operation(inventory, "zk::PruneProofs")["handler"]
        self.assert_fails(run("check_registry", edited(elsewhere)), "operations[zk::VerifyProof]: verifier_path starts at the handler")

        def no_entry(inventory: dict) -> None:
            del operation(inventory, "private_settlement.committee_leg_validation")["verifier_path"]
        self.assert_fails(run("check_registry", edited(no_entry)),
                          "operations[private_settlement.committee_leg_validation]: an operation without an instruction handler needs verifier_path")

        handler = "crates/iroha_core/src/smartcontracts/isi/game.rs"
        overrides = replaced(handler, "crate::execution_proofs::verify_execution_proof_v1(&self.proof)", "check(&self.proof)")
        self.assert_fails(run("check_registry", overrides=overrides),
                          "operations[game::VerifyExecutionProofV1]: verifier_path: `VerifyExecutionProofV1` does not name `verify_execution_proof_v1`")

    def test_a_handler_that_calls_a_verifier_records_a_verification(self) -> None:
        def edit(inventory: dict) -> None:
            item = operation(inventory, "kaigi::CreateKaigi")
            item["status"]["verification"] = "not_applicable"
            item["role"] = "effect"
            for key in ("relation", "test_evidence", "test_note"):
                item.pop(key, None)
        self.assert_fails(run("check_registry", edited(edit)),
                          "operations[kaigi::CreateKaigi]: the handler calls verify_authorization and verification is recorded as `not_applicable`")

    def test_refused_and_proof_roles_need_their_evidence(self) -> None:
        def edit(inventory: dict) -> None:
            del operation(inventory, "zk::SubmitBallot")["refusal"]
            del operation(inventory, "bridge::SubmitBridgeProof")["relation"]
            operation(inventory, "kaigi::RecordKaigiUsage")["status"]["verification"] = "not_applicable"
            operation(inventory, "kaigi::CreateKaigi")["status"]["presence"] = "absent"
            operation(inventory, "kaigi::EndKaigi")["status"]["state_effects"] = "wonderful"
            del operation(inventory, "kaigi::SetKaigiRelayManifest")["status"]["missing"]
            operation(inventory, "privacy::SubmitPrivacyProofV1")["relation_ref"] = "exact12/nowhere"
            operation(inventory, "zk::VerifyProof")["also_admits"] = ["generic.no_such_relation"]
        errors = run("check_registry", edited(edit))
        self.assert_fails(errors, "operations[zk::SubmitBallot]: verification `refused` needs the refusal")
        self.assert_fails(errors, "operations[bridge::SubmitBridgeProof]: verification `refused` needs a relation")
        self.assert_fails(errors, "operations[kaigi::RecordKaigiUsage]: a proof operation cannot have verification `not_applicable`")
        self.assert_fails(errors, "operations[kaigi::CreateKaigi]: status.presence must be `registered`")
        self.assert_fails(errors, "operations[kaigi::EndKaigi]: status.state_effects must be one of")
        self.assert_fails(errors, "operations[kaigi::SetKaigiRelayManifest]: status.missing must say what the delivery lacks")
        self.assert_fails(errors, "relation_ref `exact12/nowhere` does not resolve")
        self.assert_fails(errors, "relation generic.no_such_relation is not a listed relation")

    def test_products_and_relations_are_checked(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["products"].append({"id": "unused", "title": "x", "requirements": ["REQ-999"], "owner_tasks": ["F.1"]})
            inventory["products"][0]["requirements"] = []
            inventory["products"][1]["owner_tasks"] = []
            inventory["digests"]["products"] = inventory["digests"]["products"][1:]
            relations = {relation["id"]: relation for relation in inventory["relations"]}
            relations["native_pipa_r.kaigi_usage"]["tests"] = []
            del relations["native_pipa_r.kaigi_authorization"]["verifier"]
            del relations["ram_lfe.execution"]["refusal"]
            relations["fastpq.axt"]["status"] = "ready"
            relations["race.race_v1"]["guarantee"] = ""
        errors = run("check_products", edited(edit))
        self.assert_fails(errors, "products[unused]: no operation belongs to this product")
        self.assert_fails(errors, "products[unused]: REQ-999 is not a requirement")
        self.assert_fails(errors, "products[generic_proof]: requirements is required")
        self.assert_fails(errors, "products[fastpq_ordinary_effects]: owner_tasks is required")
        self.assert_fails(errors, "products[generic_proof]: digests.products has no entry for this product")
        self.assert_fails(errors, "relations[native_pipa_r.kaigi_usage]: test_evidence is `none`")
        self.assert_fails(errors, "relations[native_pipa_r.kaigi_authorization]: a `implemented` relation needs its verifier")
        self.assert_fails(errors, "relations[ram_lfe.execution]: an `unavailable` relation needs its refusal")
        self.assert_fails(errors, "relations[fastpq.axt]: status must be")
        self.assert_fails(errors, "relations[race.race_v1]: guarantee must say what the relation establishes")


class Exact12(Base):
    def test_thirteenth_protocol_fails(self) -> None:
        overrides = replaced(PRIVACY_MODEL, '    #[norito(rename = "pq-masp-stark-v1")]\n    PqMaspStarkV1,\n}',
                             '    #[norito(rename = "pq-masp-stark-v1")]\n    PqMaspStarkV1,\n    /// New.\n    NewProtocolV1,\n}')
        self.assert_fails(run("check_exact12", overrides=overrides), "PrivacyProtocolIdV1 has variants")

    def test_reordered_all_list_fails(self) -> None:
        overrides = replaced(PRIVACY_MODEL, "        Self::ZkAcePqAuthorizationV1,\n        Self::AnonymousPgcKOutOfNV1,",
                             "        Self::AnonymousPgcKOutOfNV1,\n        Self::ZkAcePqAuthorizationV1,")
        self.assert_fails(run("check_exact12", overrides=overrides), "the ALL list of the protocol enum differs")

    def test_changed_label_engine_and_security_model_fail(self) -> None:
        overrides = replaced(PRIVACY_MODEL, 'Self::PqMaspStarkV1 => "pq-masp-stark-v1",', 'Self::PqMaspStarkV1 => "pq-masp-stark-v2",')
        self.assert_fails(run("check_exact12", overrides=overrides), "exact12[PqMaspStarkV1]: canonical_label gives `pq-masp-stark-v2`")

        def edit(inventory: dict) -> None:
            protocol(inventory, "OrchardHalo2ActionsV1")["engine"] = "NativeFcmpPlusPlus"
            protocol(inventory, "MoneroFcmpPlusPlusV1")["security_model"] = "PostQuantumQrom"
            protocol(inventory, "VeRangeTransparentRangeV1")["proof_system"] = "Halo2IpaPasta"
        errors = run("check_exact12", edited(edit))
        self.assert_fails(errors, "exact12[OrchardHalo2ActionsV1]: expected_engine gives `NativeHalo2Orchard`")
        self.assert_fails(errors, "exact12[MoneroFcmpPlusPlusV1]: security_model gives `ClassicalRom`")
        self.assert_fails(errors, "exact12[VeRangeTransparentRangeV1]: expected_proof_system gives `IrohaVeRangeP256`")

    def test_removed_dispatch_arm_fails(self) -> None:
        text = source(VERIFIER)
        arm = "        PrivacyStatementV1::PqMaspStarkV1(statement) => {\n            verify_pq_masp_action_v1(statement, proof, envelope, context)?\n        }\n"
        self.assertIn(arm, text)
        self.assert_fails(run("check_exact12", overrides={VERIFIER: text.replace(arm, "")}), "the dispatch of verify_privacy_envelope_after_compiled_activation_v1")

    def test_changed_compiled_profile_arm_fails(self) -> None:
        overrides = replaced(PROFILES, "PrivacyProtocolIdV1::OrchardHalo2ActionsV1 => compiled_orchard_profile_v1(),",
                             "PrivacyProtocolIdV1::OrchardHalo2ActionsV1 => Err(CompiledPrivacyProfileErrorV1::EngineUnavailable { protocol_id }),")
        errors = run("check_exact12", overrides=overrides)
        self.assert_fails(errors, "exact12[OrchardHalo2ActionsV1]: compiled_privacy_profile_v1 dispatches to `Err`")
        self.assert_fails(errors, "the compiled profile arm is an error, state must be refused")

    def test_refused_profile_cannot_be_recorded_as_implemented(self) -> None:
        def edit(inventory: dict) -> None:
            row = protocol(inventory, "VegaExistingCredentialZkV1")
            row["status"]["verification"] = "implemented"
        self.assert_fails(run("check_exact12", edited(edit)),
                          "a protocol whose compiled profile is refused cannot have verification `implemented`")

    def test_refused_profile_needs_gate_and_test_and_count_is_checked(self) -> None:
        def edit(inventory: dict) -> None:
            del protocol(inventory, "IrohaZkAmsV1")["compiled_profile"]["gate"]
            protocol(inventory, "PqMaspStarkV1")["compiled_profile"]["state"] = "ready"
            inventory["exact12"]["count"] = 11
            protocol(inventory, "IrohaJindoPolynomialCommitmentV1")["status"]["delivery"] = "delivered"
        errors = run("check_exact12", edited(edit))
        self.assert_fails(errors, "exact12[IrohaZkAmsV1]: a refused compiled profile needs its gate and a test")
        self.assert_fails(errors, "exact12[PqMaspStarkV1]: compiled_profile.state must be constructed or refused")
        self.assert_fails(errors, "exact12: count is 11, 12 protocols listed")
        self.assert_fails(errors, "exact12[IrohaJindoPolynomialCommitmentV1]: delivery is `delivered` while P.12 is not `implemented`")

    def test_new_ledger_effect_fails(self) -> None:
        overrides = replaced(VERIFIER, "    ZkX509Certificate(VerifiedZkX509CertificateEffectV1),\n}",
                             "    ZkX509Certificate(VerifiedZkX509CertificateEffectV1),\n    /// New.\n    NewEffect(u8),\n}")
        self.assert_fails(run("check_exact12", overrides=overrides), "VerifiedPrivacyLedgerEffectsV1 has variants")


class ClosedLists(Base):
    def test_native_circuit_constants_and_relation_mapping_are_pinned(self) -> None:
        self.assert_clean(run("check_generic"))
        path = "crates/kaigi_zk/src/usage_v1.rs"
        overrides = replaced(path, '"pipa-r/pasta/kaigi-usage-v1"', '"pipa-r/pasta/another-usage-v1"')
        self.assert_fails(run("check_generic", overrides=overrides), "native_circuits[KaigiUsage]")
        overrides = replaced(VERIFICATION,
                             "NativeRelationV1::KaigiUsage => ProofRelation::KaigiUsage",
                             "NativeRelationV1::KaigiUsage => ProofRelation::KaigiAuthorization")
        self.assert_fails(run("check_generic", overrides=overrides), "native_circuits: compiled_relation maps")

    def test_native_admission_list_cannot_omit_duplicate_or_hide_a_relation(self) -> None:
        path = "crates/iroha_core_zk/src/native_pipa_r.rs"
        for substitute in ("", "        Self::KaigiAuthorization,\n", "        OTHER_RELATION,\n"):
            overrides = replaced(path, "        Self::KaigiUsage,\n", substitute)
            self.assert_fails(run("check_generic", overrides=overrides), "native_circuits: ALL lists")

    def test_native_kind_substitution_and_lower_circuit_swaps_fail(self) -> None:
        path = "crates/iroha_core_zk/src/native_pipa_r.rs"
        for original, substitute, fragment in (
            ("Self::KaigiUsage => Some(KaigiRelation::Usage)",
             "Self::KaigiUsage => Some(KaigiRelation::Authorization)", "kaigi selects"),
            ("Self::ConfidentialTransfer => Some(Kind::Transfer)",
             "Self::ConfidentialTransfer => Some(Kind::Full)", "confidential selects"),
            ("if let Some(kind) = self.kaigi() {\n            kind.circuit_id()",
             "if let Some(_kind) = self.kaigi() {\n            KaigiRelation::Usage.circuit_id()", "circuit_id must delegate"),
        ):
            self.assert_fails(run("check_generic", overrides=replaced(path, original, substitute)), fragment)
        for path, original, substitute, fragment in (
            ("crates/kaigi_zk/src/native.rs", "Self::Usage => KAIGI_USAGE_CIRCUIT_ID_V1",
             "Self::Usage => KAIGI_AUTHORIZATION_CIRCUIT_ID_V1", "kaigi circuit_id maps"),
            ("crates/iroha_core_zk/src/confidential_native/mod.rs", "Self::Transfer => super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID",
             "Self::Transfer => super::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID", "confidential circuit_id maps"),
        ):
            self.assert_fails(run("check_generic", overrides=replaced(path, original, substitute)), fragment)

    def test_unused_lookalike_constant_cannot_supply_the_native_identity(self) -> None:
        path = "crates/kaigi_zk/src/usage_v1.rs"
        overrides = replaced(path, '"pipa-r/pasta/kaigi-usage-v1"', '"pipa-r/pasta/wrong-usage-v1"')
        overrides[path] += '\npub const UNUSED_CIRCUIT_ID: &str = "pipa-r/pasta/kaigi-usage-v1";\n'

        def unrelated(inventory: dict) -> None:
            row = next(row for row in inventory["generic_relations"]["relations"] if row["variant"] == "KaigiUsage")
            row["circuit_source"]["constant"] = "UNUSED_CIRCUIT_ID"
        self.assert_fails(run("check_generic", edited(unrelated), overrides), "kaigi circuit_id maps")

    def test_native_circuit_identity_cannot_be_omitted_or_duplicated_in_inventory(self) -> None:
        def omitted(inventory: dict) -> None:
            row = next(row for row in inventory["generic_relations"]["relations"] if row["variant"] == "KaigiUsage")
            del row["circuit_source"]
        self.assert_fails(run("check_generic", edited(omitted)), "native_circuits[KaigiUsage]")

        def duplicate(inventory: dict) -> None:
            rows = {row["variant"]: row for row in inventory["generic_relations"]["relations"]}
            rows["KaigiUsage"]["circuits"] = rows["KaigiAuthorization"]["circuits"]
            rows["KaigiUsage"]["circuit_source"] = rows["KaigiAuthorization"]["circuit_source"]
        self.assert_fails(run("check_generic", edited(duplicate)), "each native relation requires a distinct circuit identity")

    def test_new_generic_relation_and_circuit_fail(self) -> None:
        overrides = replaced(VERIFICATION, "    KaigiUsage,\n}", "    KaigiUsage,\n    /// New.\n    VoteBallot,\n}")
        self.assert_fails(run("check_generic", overrides=overrides), "ProofRelation has variants")
        path = "crates/iroha_core_zk/src/native_pipa_r.rs"
        overrides = replaced(path, "    ConfidentialChangeUnshield,\n}", "    ConfidentialChangeUnshield,\n    VoteBallot,\n}")
        self.assert_fails(run("check_generic", overrides=overrides), "NativeRelationV1 has variants")
        overrides = replaced(path, "        Self::KaigiUsage,\n", "        Self::KaigiUsage,\n        Self::VoteBallot,\n")
        self.assert_fails(run("check_generic", overrides=overrides), "native_circuits: ALL lists")
        path = "crates/iroha_core_privacy/src/execution_proofs/registry.rs"
        overrides = replaced(path, "enum CompiledAdapterV1 {\n    RaceV1,\n}", "enum CompiledAdapterV1 {\n    RaceV1,\n    ClassedRaceV1,\n}")
        self.assert_fails(run("check_generic", overrides=overrides), "generic_relations.execution_adapters: CompiledAdapterV1 has variants")

    def test_ram_lfe_class_backend_and_opening_drift_fail(self) -> None:
        path = "crates/iroha_crypto/src/ram_lfe/class.rs"
        overrides = replaced(path, "    Refresh,\n}", "    Refresh,\n    /// New.\n    Recursive,\n}")
        self.assert_fails(run("check_ram_lfe", overrides=overrides), "ram_lfe.classes: RamLfeClassV1 has variants")
        path = "crates/iroha_crypto/src/ram_lfe.rs"
        overrides = replaced(path, "    /// HKDF-SHA3-512 commitment-bound PRF evaluator.\n    HkdfSha3_512PrfV1,\n", "")
        self.assert_fails(run("check_ram_lfe", overrides=overrides), "ram_lfe.backends: RamLfeBackend has variants")
        path = "crates/iroha_data_model/src/ram_lfe.rs"
        overrides = {path: source(path) + "\n/// New.\npub struct RamLfeThresholdOpeningShareV1 {}\n"}
        self.assert_fails(run("check_ram_lfe", overrides=overrides),
                          "ram_lfe.openings: RamLfeThresholdOpeningShareV1 is declared in crates/iroha_data_model/src/ram_lfe.rs and is not listed")

        def edit(inventory: dict) -> None:
            inventory["ram_lfe"]["openings"]["types"].append({"name": "RamLfeGoneOpening", "path": path})
            inventory["ram_lfe"]["classes"]["list"][0]["status"]["delivery"] = "delivered"
        errors = run("check_ram_lfe", edited(edit))
        self.assert_fails(errors, "ram_lfe.openings: RamLfeGoneOpening is not declared")
        self.assert_fails(errors, "ram_lfe.classes[Affine]: delivery is `delivered`")

    def test_soracloud_job_kind_mode_and_role_drift_fail(self) -> None:
        path = "crates/iroha_data_model/src/soracloud/fhe.rs"
        text = source(path)
        marker = "    /// Deterministic bootstrap/relinearization refresh over one input.\n    Bootstrap,\n}"
        self.assertIn(marker, text)
        overrides = {path: text.replace(marker, marker[:-1] + "    /// New.\n    Compare,\n}")}
        self.assert_fails(run("check_soracloud", overrides=overrides), "soracloud.job_kinds: FheJobOperationV1 has variants")
        marker = "    ThresholdService,\n}"
        self.assertIn(marker, text)
        overrides = {path: text.replace(marker, "    ThresholdService,\n    /// New.\n    Committee,\n}")}
        self.assert_fails(run("check_soracloud", overrides=overrides), "soracloud.decryption_modes: DecryptionAuthorityModeV1 has variants")
        overrides = replaced(ZK_LIB, "        iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,\n    ]\n    .contains(&circuit_id)",
                             "        iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,\n        iroha_data_model::soracloud::SORACLOUD_FHE_THRESHOLD_SHARE_CIRCUIT_ID_V1,\n    ]\n    .contains(&circuit_id)") \
            if "SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,\n    ]\n    .contains(&circuit_id)" in source(ZK_LIB) else None
        if overrides is None:
            body = "fn is_typed_native_stark_circuit_id(circuit_id: &str) -> bool {\n    ["
            overrides = replaced(ZK_LIB, body, body + "\n        iroha_data_model::soracloud::SORACLOUD_FHE_THRESHOLD_SHARE_CIRCUIT_ID_V1,")
        self.assert_fails(run("check_soracloud", overrides=overrides), "soracloud.native_roles: is_typed_native_stark_circuit_id lists")

    def test_new_executable_variant_fails(self) -> None:
        path = "crates/iroha_data_model/src/transaction/executable.rs"
        overrides = replaced(path, "        Batch(ConstVec<ExecutableBatchItem>),\n    }",
                             "        Batch(ConstVec<ExecutableBatchItem>),\n        /// New.\n        Proved(IvmProved),\n    }")
        self.assert_fails(run("check_executables", overrides=overrides), "executables: Executable has variants")

        def edit(inventory: dict) -> None:
            row = next(row for row in inventory["executables"]["list"] if row["variant"] == "IvmProved")
            del row["operation"]
        self.assert_fails(run("check_executables", edited(edit)), "a proof-carrying executable names its operation")


class Syscalls(Base):
    def test_new_family_syscall_fails(self) -> None:
        overrides = {SYSCALLS: source(SYSCALLS) + "\n/// New.\npub const SYSCALL_ZK_SHIELD_APPLY: u32 = 0x65;\n"}
        self.assert_fails(run("check_syscalls", overrides=overrides), "SYSCALL_ZK_SHIELD_APPLY has a family name and is neither listed nor excluded")

    def test_changed_number_binding_and_tag_fail(self) -> None:
        overrides = replaced(SYSCALLS, "pub const SYSCALL_VERIFY_PROOF: u32 = 0xF6;", "pub const SYSCALL_VERIFY_PROOF: u32 = 0xF3;")
        self.assert_fails(run("check_syscalls", overrides=overrides), "syscalls[VERIFY_PROOF]: number is 0xF3, recorded 0xF6")
        overrides = replaced(BUILTINS, "Self::VerifyProof => &[s::SYSCALL_VERIFY_PROOF],",
                             "Self::VerifyProof | Self::VerifyProofInline => &[s::SYSCALL_VERIFY_PROOF],")
        self.assert_fails(run("check_syscalls", overrides=overrides), "syscalls[VERIFY_PROOF]: Kotodama builtins are ['VerifyProof', 'VerifyProofInline']")
        overrides = {SYSCALLS: source(SYSCALLS) + "\npub const SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_PRIVACY_PROOF: u64 = 3;\n"}
        self.assert_fails(run("check_syscalls", overrides=overrides), "syscalls.instruction_bridge: operation tags are")

    def test_removed_syscall_and_missing_host_fail(self) -> None:
        overrides = replaced(SYSCALLS, "pub const SYSCALL_ZK_VERIFY_BATCH: u32 = 0x64;", "")

        def edit(inventory: dict) -> None:
            del inventory["syscalls"]["list"][0]["host"]
            inventory["syscalls"]["excluded"].append({"name": "ZK_ROOTS_GET"})
        errors = run("check_syscalls", edited(edit), overrides)
        self.assert_fails(errors, "SYSCALL_ZK_VERIFY_BATCH is not in")
        self.assert_fails(errors, "host handler is required")
        self.assert_fails(errors, "syscalls.excluded[ZK_ROOTS_GET]: reason is required")


class Routes(Base):
    HEADER = "route_id\tmethod\tpath\tsurface\tauthentication\tadmission\teffect\ttransport\tfeature_gate\tsdk\topenapi\tmcp\tprivate_no_store"

    def row(self, identifier: str, method: str, path: str) -> str:
        return f"{identifier}\t{method}\t{path}\tpublic\ttorii_default\tpublic\tread\thttp\talways\ttrue\ttrue\ttrue\tfalse"

    def test_new_route_in_a_listed_family_fails_from_the_tsv_and_from_the_catalog(self) -> None:
        tsv = source(C.ROUTE_TSV)
        extra = self.row("zk.shield.apply", "POST", "/v1/zk/shield")
        self.assert_fails(run("check_routes", overrides={C.ROUTE_TSV: tsv + extra + "\n"}),
                          "routes: zk.shield.apply (POST /v1/zk/shield) of the tracked TSV is in a listed path family and is not listed")
        errors = run("check_routes", catalog=tsv + extra + "\n")
        self.assert_fails(errors, "zk.shield.apply (POST /v1/zk/shield) of the compiled route catalog is in a listed path family")
        self.assert_fails(errors, "and the compiled route catalog differ in listed families: ['zk.shield.apply']")

    def test_route_outside_the_families_is_only_a_note(self) -> None:
        tsv = source(C.ROUTE_TSV)
        checker = C.Checker(INVENTORY, C.Tree(), tsv + self.row("vpn.lease.read", "GET", "/v1/vpn/leases/{id}") + "\n")
        checker.check_routes()
        self.assertEqual(checker.errors, [])
        self.assertTrue(any("outside the listed families" in note for note in checker.notes))

    def test_changed_and_removed_rows_fail(self) -> None:
        tsv = source(C.ROUTE_TSV)
        line = next(line for line in tsv.splitlines() if line.startswith("zk.roots.read\t"))
        self.assert_fails(run("check_routes", overrides={C.ROUTE_TSV: tsv.replace(line, line.replace("\tPOST\t", "\tGET\t"))}),
                          "routes[zk.roots.read]: method is `GET`")
        self.assert_fails(run("check_routes", overrides={C.ROUTE_TSV: tsv.replace(line + "\n", "")}),
                          "routes[zk.roots.read]: not a row of")
        self.assert_fails(run("check_routes", overrides={C.ROUTE_TSV: self.HEADER + "\n"}), "has no row")

    def test_route_shape_is_checked(self) -> None:
        def edit(inventory: dict) -> None:
            routes = {route["id"]: route for route in inventory["routes"]["list"]}
            routes["zk.roots.read"]["product"] = "nothing"
            del routes["zk.vote.tally"]["handler"]
            routes["proof.read"]["does"] = ""
            inventory["routes"]["path_prefixes"].remove("/v1/kaigi/")
        errors = run("check_routes", edited(edit))
        self.assert_fails(errors, "routes[zk.roots.read]: product `nothing` is not a listed product")
        self.assert_fails(errors, "routes[zk.vote.tally]: handler is required")
        self.assert_fails(errors, "routes[proof.read]: `does` must say what the route does")
        self.assert_fails(errors, "is outside routes.path_prefixes")

    def test_admission_route_classes_are_required(self) -> None:
        def edit(inventory: dict) -> None:
            del inventory["admission_routes"]["restore"]
            inventory["admission_routes"]["genesis"]["sites"] = []
            inventory["admission_routes"]["telepathy"] = {"what": "x", "sites": [1]}
        errors = run("check_admission_routes", edited(edit))
        self.assert_fails(errors, "admission_routes: `restore` is required")
        self.assert_fails(errors, "admission_routes.genesis: at least one site is required")
        self.assert_fails(errors, "unknown route class `telepathy`")


def small_sdk(inventory: dict) -> dict:
    """The inventory with tiny SDK roots, refreshed, so SDK mutations run fast."""
    inventory = copy.deepcopy(inventory)
    roots = {
        "rust": ["crates/zk_ace_prover/src"],
        "kotlin_java_android": ["kotlin/client-android/src/main"],
        "swift": ["IrohaSwift/Sources/IrohaSwiftTransferUI"],
        "javascript": ["javascript/iroha_js/src/instructionBuilders.js", "javascript/iroha_js/src/norito.js"],
        "python": ["python/iroha_native/src/iroha_native"],
        "csharp": ["csharp/src/Hyperledger.Iroha.Sdk/Kaigi"],
    }
    for family in inventory["sdk"]["families"]:
        family["roots"] = [root for root in roots[family["id"]] if (C.ROOT / root).exists()] or family["roots"]
    C.Checker(inventory, C.Tree(), None).refresh()
    return inventory


class Sdk(Base):
    @classmethod
    def setUpClass(cls) -> None:
        cls.small = small_sdk(INVENTORY)

    def test_small_baseline_is_clean(self) -> None:
        self.assert_clean(run("check_sdk", self.small))

    def test_new_file_referencing_an_instruction_fails(self) -> None:
        path = "javascript/iroha_js/src/instructionBuilders.js"
        if not (C.ROOT / path).exists():
            self.skipTest("fixture SDK file moved")
        new = "csharp/src/Hyperledger.Iroha.Sdk/Kaigi/NewPrivacyCall.cs"
        overrides = {new: "namespace X { class Y { void Z() { var t = typeof(SubmitPrivacyProofV1); } } }"}
        self.assert_fails(run("check_sdk", self.small, overrides),
                          f"operations[privacy::SubmitPrivacyProofV1]: sdk.csharp: now referenced by {new}")

    def test_wire_id_literal_and_route_path_are_found(self) -> None:
        new = "python/iroha_native/src/iroha_native/new_privacy.py"
        overrides = {new: 'WIRE = "iroha.privacy.submit_proof.v1"\nPATH = "/v1/zk/vk/register"\nOTHER = "/v1/zk/vk/registered"\n'}
        errors = run("check_sdk", self.small, overrides)
        self.assert_fails(errors, f"operations[privacy::SubmitPrivacyProofV1]: sdk.python: now referenced by {new}")
        self.assert_fails(errors, f"routes[contracts.zk_vk_register_post]: sdk.python: now referenced by {new}")
        self.assertFalse(any("routes[contracts.zk_vk_get]" in error for error in errors), errors)

    def test_file_that_stops_referencing_fails(self) -> None:
        item = next((item for item in self.small["operations"] if item.get("isi") and item["sdk"]["javascript"]), None)
        if item is None:
            self.skipTest("no JavaScript reference in the small fixture")
        path = item["sdk"]["javascript"][0]["path"]
        self.assert_fails(run("check_sdk", self.small, {path: "// emptied\n"}),
                          f"operations[{item['id']}]: sdk.javascript: no longer referenced by {path}")

    def test_new_declaration_with_a_family_name_fails(self) -> None:
        new = "python/iroha_native/src/iroha_native/new_kaigi.py"
        overrides = {new: "def join_kaigi_one_call(client):\n    return None\n\ndef unrelated():\n    return None\n"}
        errors = run("check_sdk", self.small, overrides)
        self.assert_fails(errors, f"sdk.surface: python declares `join_kaigi_one_call` in {new} (kaigi) and it is not listed")
        self.assertFalse(any("unrelated" in error for error in errors))

    def test_declaration_names_are_read_in_snake_case_with_word_boundaries(self) -> None:
        self.assertEqual(C.snake("buildAxtDescriptor"), "build_axt_descriptor")
        self.assertEqual(C.snake("IVMProvedTransaction"), "ivm_proved_transaction")
        self.assertEqual(C.snake("resolve_identifier"), "resolve_identifier")
        new = "csharp/src/Hyperledger.Iroha.Sdk/Kaigi/Names.cs"
        text = (
            "namespace X { public class Names {\n"
            "    public static int BuildAxtDescriptor(int a) { return a; }\n"
            "    public static int MaxTxSelection(int a) { return a; }\n"
            "    public static int ResolveIdentifierOneCall(int a) { return a; }\n"
            "} }\n"
        )
        errors = run("check_sdk", self.small, {new: text})
        self.assert_fails(errors, f"sdk.surface: csharp declares `BuildAxtDescriptor` in {new} (axt)")
        self.assert_fails(errors, f"sdk.surface: csharp declares `ResolveIdentifierOneCall` in {new} (ram_lfe)")
        self.assertFalse(any("MaxTxSelection" in error for error in errors), errors)

    def test_rust_declarations_in_test_code_are_not_listed(self) -> None:
        new = "crates/zk_ace_prover/src/extra.rs"
        text = "fn submit_privacy_proof_one_call() {}\n#[cfg(test)]\nmod tests {\n    fn kaigi_fixture() {}\n}\n"
        errors = run("check_sdk", self.small, {new: text})
        self.assert_fails(errors, f"sdk.surface: rust declares `submit_privacy_proof_one_call` in {new} (exact12_admission)")
        self.assertFalse(any("kaigi_fixture" in error for error in errors), errors)

    def test_declaration_no_rule_classes_fails(self) -> None:
        inventory = copy.deepcopy(self.small)
        inventory["sdk"]["surface_scan"]["products"] = [
            rule for rule in inventory["sdk"]["surface_scan"]["products"] if rule["product"] != "kaigi"]
        new = "python/iroha_native/src/iroha_native/new_kaigi.py"
        self.assert_fails(run("check_sdk", inventory, {new: "def join_kaigi_one_call(client):\n    return None\n"}),
                          "no rule of sdk.surface_scan.products classes them")

    def test_family_set_and_rules_are_checked(self) -> None:
        def five(inventory: dict) -> None:
            inventory["sdk"]["families"].pop()
        self.assert_fails(run("check_sdk", edited(five)), "sdk.families must be exactly")

        inventory = copy.deepcopy(self.small)
        inventory["sdk"]["families"][2]["roots"] = ["IrohaSwift/NoSuchDirectory"]
        inventory["sdk"]["surface_scan"]["products"].append({"pattern": "x", "product": "no_such_product"})
        del operation(inventory, "kaigi::JoinKaigi")["sdk"]["swift"]
        errors = run("check_sdk", inventory)
        self.assert_fails(errors, "sdk.families[swift]: no source file under")
        self.assert_fails(errors, "sdk.surface_scan.products: `no_such_product` is not a product")
        self.assert_fails(errors, "operations[kaigi::JoinKaigi]: sdk.swift is required")


def small_selection(inventory: dict) -> dict:
    inventory = copy.deepcopy(inventory)
    section = inventory["guarantee_selection"]
    section["selector_census"]["roots"] = ["crates/iroha_core/src/smartcontracts/isi/kaigi", "crates/iroha_core_zk/src/verification.rs",
                                           "crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs", "crates/iroha_core/src/smartcontracts/isi/game.rs",
                                           "crates/iroha_core_privacy/src/privacy_state.rs", "crates/iroha_core/src/state.rs",
                                           "crates/iroha_core/src/smartcontracts/ivm/host.rs", "crates/iroha_data_model/src/proof.rs",
                                           "crates/iroha_torii/src/routing.rs"]
    section["source_inclusion_census"]["roots"] = ["crates/iroha_core_privacy/src/execution_proofs"]
    checker = C.Checker(inventory, C.Tree(), None)
    known = {(row["token"], row["path"]): row["site"] for row in section["selector_census"]["occurrences"]}
    checker.refresh()
    for row in section["selector_census"]["occurrences"]:
        row["site"] = known[(row["token"], row["path"])]
    return inventory


class GuaranteeSelection(Base):
    @classmethod
    def setUpClass(cls) -> None:
        cls.small = small_selection(INVENTORY)

    def test_small_baseline_is_clean(self) -> None:
        self.assert_clean(run("check_guarantee_selection", self.small))

    def test_new_registry_read_fails(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs"
        text = source(path)
        mark = "pub fn validate_execution_receipt_at("
        mutated = text.replace(mark, "fn pick(world: &W, id: &Id) { let _ = world.verifying_keys.get(id); }\n" + mark, 1)
        self.assert_fails(run("check_guarantee_selection", self.small, {path: mutated}),
                          f"`verifying_key_registry_read` occurs 1 times in {path}, recorded 0")

    def test_selector_added_in_a_test_module_is_not_counted(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs"
        mutated = source(path) + "\n#[cfg(test)]\nmod more_tests {\n    fn pick(world: &W, id: &Id) { let _ = world.verifying_keys.get(id); }\n}\n"
        self.assert_clean(run("check_guarantee_selection", self.small, {path: mutated}))

    def test_changed_count_and_unclassed_occurrence_fail(self) -> None:
        inventory = copy.deepcopy(self.small)
        rows = inventory["guarantee_selection"]["selector_census"]["occurrences"]
        rows[0]["count"] += 2
        rows[1]["site"] = None
        errors = run("check_guarantee_selection", inventory)
        self.assert_fails(errors, f"`{rows[0]['token']}` occurs {rows[0]['count'] - 2} times in {rows[0]['path']}, recorded {rows[0]['count']}")
        self.assert_fails(errors, f"`{rows[1]['token']}` in {rows[1]['path']} is not classed under a listed site")

    def test_new_source_inclusion_fails_and_test_only_inclusion_does_not(self) -> None:
        path = "crates/iroha_core_privacy/src/execution_proofs/registry.rs"
        text = source(path)
        mutated = 'const SOURCE: &[u8] = include_bytes!("registry.rs");\n' + text
        self.assert_fails(run("check_guarantee_selection", self.small, {path: mutated}),
                          f"{path} includes Rust source bytes 1 times and is not classed")
        gated = text + '\n#[cfg(test)]\nmod source_tests {\n    const SOURCE: &str = include_str!("registry.rs");\n}\n'
        self.assert_clean(run("check_guarantee_selection", self.small, {path: gated}))

    def test_removed_or_recounted_inclusion_fails(self) -> None:
        path = "crates/iroha_core_privacy/src/execution_proofs/kernel_export.rs"
        mutated = source(path).replace('include_bytes!("race.rs")', "RACE_SOURCE")
        self.assert_fails(run("check_guarantee_selection", self.small, {path: mutated}), f"{path} includes Rust source bytes")

    def test_site_shape_is_checked(self) -> None:
        inventory = copy.deepcopy(self.small)
        sites = {site["id"]: site for site in inventory["guarantee_selection"]["sites"]}
        sites["generic.native_uploaded_key"]["rejection_tests"] = []
        del sites["soracloud.typed_role_feature"]["open_defect"]
        sites["kaigi.policy_named_key"]["selector"] = "astrology"
        del sites["voting.election_keys"]["site"]
        sites["exact12.qualification_singleton"]["open_defect"] = {"what": "x"}
        del sites["axt.fee_sponsor_binding"]["chooses_guarantee"]
        inventory["guarantee_selection"]["source_inclusion_census"]["files"][0]["use"] = "decoration"
        inventory["guarantee_selection"]["source_inclusion_census"]["files"][1]["site"] = "no.such.site"
        errors = run("check_guarantee_selection", inventory)
        self.assert_fails(errors, "sites[generic.native_uploaded_key]: cite a rejection test or record an open defect")
        self.assert_fails(errors, "sites[soracloud.typed_role_feature]: a selector that can choose a guarantee is an open defect")
        self.assert_fails(errors, "sites[kaigi.policy_named_key]: selector must be one of")
        self.assert_fails(errors, "sites[voting.election_keys]: site (path and symbol) is required")
        self.assert_fails(errors, "sites[exact12.qualification_singleton]: open_defect needs owner_task and what")
        self.assert_fails(errors, "sites[axt.fee_sponsor_binding]: chooses_guarantee must say")
        self.assert_fails(errors, "use must be identity or export")
        self.assert_fails(errors, "an identity use names its site")

    def test_every_selector_kind_needs_a_site(self) -> None:
        inventory = copy.deepcopy(self.small)
        inventory["guarantee_selection"]["sites"] = [
            site for site in inventory["guarantee_selection"]["sites"] if site["selector"] != "catalog_membership"]
        self.assert_fails(run("check_guarantee_selection", inventory), "no site with selector `catalog_membership`")


class Digests(Base):
    @classmethod
    def setUpClass(cls) -> None:
        inventory = copy.deepcopy(INVENTORY)
        inventory["digests"]["products"] = [group for group in inventory["digests"]["products"] if group["product"] in ("verange", "orchard")]
        cls.small = inventory

    def test_small_baseline_is_clean(self) -> None:
        errors = [error for error in run("check_digests", self.small)]
        self.assert_clean(errors)

    def test_new_primitive_in_an_owner_file_fails(self) -> None:
        path = "crates/iroha_core_privacy/src/privacy_engines/verange.rs"
        mutated = "use sha3::Sha3_512;\n" + source(path)
        self.assert_fails(run("check_digests", self.small, {path: mutated}), "digests.products[verange]: hash-primitive census is")

    def test_primitive_added_in_test_code_is_not_counted(self) -> None:
        path = "crates/iroha_core_privacy/src/privacy_engines/verange.rs"
        mutated = source(path) + "\n#[cfg(test)]\nmod digest_tests {\n    use sha3::Sha3_512;\n}\n"
        self.assert_clean(run("check_digests", self.small, {path: mutated}))

    def test_shape_and_named_roles_are_checked(self) -> None:
        inventory = copy.deepcopy(self.small)
        inventory["digests"]["products"][0]["in_circuit"] = {}
        del inventory["digests"]["products"][1]["native"]
        inventory["digests"]["named_roles"] = [role for role in inventory["digests"]["named_roles"] if role["id"] != "mkhe_proof_hashes"]
        inventory["digests"]["named_roles"][0]["native"] = []
        errors = run("check_digests", inventory)
        self.assert_fails(errors, "in_circuit: an object here must give `none` with the reason")
        self.assert_fails(errors, "native and in_circuit are required")
        self.assert_fails(errors, "digests.named_roles: `mkhe_proof_hashes` is required")
        self.assert_fails(errors, "native digest evidence is required")


class Anchors(Base):
    def minimal(self, **nodes) -> dict:
        inventory = {"inventories": copy.deepcopy(INVENTORY["inventories"]), "routes": {"list": []}, "operations": [], "relations": []}
        inventory.update(nodes)
        return inventory

    def test_symbol_must_be_in_the_file_and_in_production_code(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs"
        good = self.minimal(x={"path": path, "symbol": "pub fn validate_execution_receipt_at("})
        self.assert_clean(run("check_anchors", good))
        self.assert_fails(run("check_anchors", self.minimal(x={"path": path, "symbol": "fn no_such_function("})), "is not in")
        self.assert_fails(run("check_anchors", self.minimal(x={"path": path, "symbol": "fn sample_proof_verifier()"})),
                          "is only in test code of")
        self.assert_fails(run("check_anchors", self.minimal(x={"path": "crates/no/such.rs", "symbol": "x"})), "crates/no/such.rs is missing")

    def test_a_reaches_link_may_be_a_test_helper(self) -> None:
        helper = {"path": PRIVACY_HANDLERS, "symbol": "fn valid_payment_instruction("}
        test = {"path": "crates/iroha_core/src/smartcontracts/isi/privacy_pgc_payment_tests.rs",
                "test": "verified_pgc_payment_replaces_complete_table_atomically_and_replay_rejects"}
        self.assert_clean(run("check_anchors", self.minimal(x={"tests": [dict(test, reaches=[helper])]})))
        self.assert_fails(run("check_anchors", self.minimal(x=helper)), "is only in test code of")
        gone = dict(helper, symbol="fn no_such_helper(")
        self.assert_fails(run("check_anchors", self.minimal(x={"tests": [dict(test, reaches=[gone])]})), "is not in")

    def test_symbol_survives_reformatting(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs"
        text = source(path)
        mark = "pub fn validate_execution_receipt_at("
        reformatted = text.replace(mark, "pub\n    fn   validate_execution_receipt_at(", 1)
        self.assert_clean(run("check_anchors", self.minimal(x={"path": path, "symbol": mark}), {path: reformatted}))

    def test_tests_must_exist_and_run_by_default(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs"
        name = "unavailable_execution_relation_rejects_a_valid_unrelated_native_proof"
        node = self.minimal(x={"path": path, "test": name})
        self.assert_clean(run("check_anchors", node))
        text = source(path)
        self.assert_fails(run("check_anchors", node, {path: text.replace(f"fn {name}(", f"fn renamed_{name}(")}), "not found")
        ignored = text.replace(f"    #[test]\n    fn {name}(", f"    #[test]\n    #[ignore = \"slow\"]\n    fn {name}(")
        self.assertNotEqual(ignored, text)
        self.assert_fails(run("check_anchors", node, {path: ignored}), "is #[ignore]d")
        untested = text.replace(f"    #[test]\n    fn {name}(", f"    fn {name}(")
        self.assert_fails(run("check_anchors", node, {path: untested}), "has no #[test] attribute")
        self.assert_fails(run("check_anchors", self.minimal(x={"path": path, "test": name, "ignored": True})),
                          "is recorded as #[ignore]d and is not")
        self.assert_clean(run("check_anchors", self.minimal(x={"path": path, "test": name, "ignored": True}), {path: ignored}))

    def test_tests_in_a_feature_gated_module_do_not_run_by_default(self) -> None:
        manifest = (
            '[package]\nname = "sample"\n\n[features]\n# default = ["evidence"]\ndefault = ["node"]\n'
            'node = ["shipped-feature", "dep:other"]\nshipped-feature = []\nevidence = [\n  "other/evidence",\n]\n\n'
            '[dependencies]\nother = { path = "../other", features = ["evidence"] }\n'
        )
        lib = (
            '//! Sample.\n/// Evidence.\n#[cfg(feature = "evidence")]\n#[allow(dead_code)]\npub mod evidence;\n'
            '#[cfg(feature = "shipped-feature")]\nmod shipped;\nmod plain;\n'
        )
        case = "#[test]\nfn sample_case() {}\n"
        files = {
            "crates/sample/Cargo.toml": manifest,
            "crates/sample/src/lib.rs": lib,
            "crates/sample/src/evidence/tests.rs": case,
            "crates/sample/src/shipped.rs": case,
            "crates/sample/src/plain.rs": case,
        }
        tree = C.Tree(C.ROOT, files)
        self.assertEqual(C.default_features(tree, "sample"), {"default", "node", "shipped-feature"})
        self.assertEqual(C.feature_gate(tree, "crates/sample/src/evidence/tests.rs"), "evidence")
        self.assertIsNone(C.feature_gate(tree, "crates/sample/src/shipped.rs"))
        self.assertIsNone(C.feature_gate(tree, "crates/sample/src/plain.rs"))
        self.assertIsNone(C.feature_gate(tree, "scripts/tests/sample.py"))
        gated = {"path": "crates/sample/src/evidence/tests.rs", "test": "sample_case"}
        self.assert_fails(run("check_anchors", self.minimal(x=gated), files), "is compiled only with feature `evidence`")
        marked = dict(gated, feature="evidence")
        self.assert_clean(run("check_anchors", self.minimal(x=marked), files))
        self.assertTrue(C.runs_by_default(gated))
        self.assertFalse(C.runs_by_default(marked))
        self.assertFalse(C.runs_by_default(dict(gated, ignored=True)))
        for path in ("crates/sample/src/shipped.rs", "crates/sample/src/plain.rs"):
            self.assert_clean(run("check_anchors", self.minimal(x={"path": path, "test": "sample_case"}), files))
            self.assert_fails(
                run("check_anchors", self.minimal(x={"path": path, "test": "sample_case", "feature": "evidence"}), files),
                "which does not gate its module")

    def test_the_feature_gate_recorded_in_the_tracked_inventory_is_the_one_in_the_tree(self) -> None:
        marked = [node for _, node in C.walk(INVENTORY) if "test" in node and node.get("feature")]
        self.assertTrue(marked)
        for node in marked:
            self.assertEqual(C.feature_gate(REAL, node["path"]), node["feature"], node)

    def test_macro_declared_tests_are_recognized(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/world.rs"
        good = self.minimal(x={"path": path, "test": "verify_proof_rejects_inline_verifying_key"})
        self.assert_clean(run("check_anchors", good))
        self.assert_fails(run("check_anchors", self.minimal(x={"path": path, "test": "verify_proof_accepts_inline_verifying_key"})), "not found")

    def test_cross_inventory_keys_tasks_routes_and_operations_resolve(self) -> None:
        nodes = self.minimal(
            a={"inventory": "fastpq", "key": "consumers/no-such-consumer"},
            b={"inventory": "nowhere", "key": "x"},
            c={"owner_tasks": ["Z.9"]},
            d={"owner_task": "Z.8"},
            e={"routes": ["no.such.route"]},
            f={"operations": ["no::SuchOperation"]},
            g={"relation": "no.such.relation"},
            h={"consumers": ["no::SuchConsumer"]},
            i={"operation": "no::SuchSingleOperation"},
        )
        errors = run("check_anchors", nodes)
        self.assert_fails(errors, "key `consumers/no-such-consumer` does not resolve in specs/fastpq/shared_backend_inventory.json")
        self.assert_fails(errors, "inventory `nowhere` is not declared")
        self.assert_fails(errors, "task Z.9 is not in")
        self.assert_fails(errors, "task Z.8 is not in")
        self.assert_fails(errors, "route no.such.route is not a listed route")
        self.assert_fails(errors, "operation no::SuchOperation is not a listed operation")
        self.assert_fails(errors, "relation no.such.relation is not a listed relation")
        self.assert_fails(errors, "consumer no::SuchConsumer is not a listed operation")
        self.assert_fails(errors, "operation no::SuchSingleOperation is not a listed operation")
        self.assert_clean(run("check_anchors", self.minimal(a={"inventory": "fastpq", "key": "consumers/axt"})))

    def test_missing_inventory_file_fails_unless_its_owner_is_still_open(self) -> None:
        inventory = self.minimal(a={"inventory": "fhe", "key": "current_state/bfv_backends_refused"})
        self.assert_fails(run("check_anchors", inventory, {"specs/fhe_ownership_inventory.json": None}),
                          "specs/fhe_ownership_inventory.json is missing")
        optional = self.minimal(a={"inventory": "primitive", "key": "digests/anything"})
        checker = C.Checker(optional, C.Tree(C.ROOT, {"specs/zk_primitive_workloads.json": None}), None)
        checker.check_anchors()
        self.assertEqual(checker.errors, [])
        self.assertTrue(any("owned by H.1" in note for note in checker.notes))
        present = C.Checker(optional, C.Tree(C.ROOT, {"specs/zk_primitive_workloads.json": '{"digests": []}'}), None)
        present.check_anchors()
        self.assertTrue(any("does not resolve" in error for error in present.errors))


class Requirements(Base):
    def test_ledger_mapping_and_inventory_agree(self) -> None:
        def drop(inventory: dict) -> None:
            inventory["requirements"]["requirements"] = [
                record for record in inventory["requirements"]["requirements"] if record["id"] != "REQ-061"]
            inventory["requirements"]["findings"].append({"id": "R6-1", "addressed_by": ["operations"]})
            inventory["requirements"]["requirements"][0]["addressed_by"] = ["no_such_section"]
            inventory["requirements"]["findings"][0]["addressed_by"] = []
            inventory["requirement_mapping"]["enforced_by"] = []
        errors = run("check_requirements", edited(drop))
        self.assert_fails(errors, "requirements.requirements: REQ-061 maps to F.1")
        self.assert_fails(errors, "requirements.findings: R6-1 does not map to F.1")
        self.assert_fails(errors, "`no_such_section` does not resolve in this inventory")
        self.assert_fails(errors, "addressed_by is required")
        self.assert_fails(errors, "requirement_mapping: cite the plan checker")

    def test_a_requirement_newly_mapped_to_this_task_fails(self) -> None:
        import json
        ledger = json.loads(source(C.LEDGER))
        record = next(record for record in ledger["requirements"] if "F.1" not in record["task_ids"])
        record["task_ids"].append("F.1")
        self.assert_fails(run("check_requirements", overrides={C.LEDGER: json.dumps(ledger)}),
                          f"requirements.requirements: {record['id']} maps to F.1")

    def test_the_cited_plan_checker_enforces_the_mapping(self) -> None:
        import json
        import runpy
        plan = runpy.run_path(str(C.ROOT / "scripts" / "check_zk_delivery_plan.py"))
        graph = json.loads(source(C.GRAPH))
        ledger = json.loads(source(C.LEDGER))
        task_ids = {task["id"] for task in graph["tasks"]}
        self.assertEqual(plan["check_reconciliation"](ledger, graph["reconciliation_baseline"], task_ids), [])
        ledger["requirements"][0]["task_ids"] = []
        errors = plan["check_reconciliation"](ledger, graph["reconciliation_baseline"], task_ids)
        self.assertTrue(any("task_ids must map to existing tasks" in error for error in errors), errors)

    def test_header_is_checked(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["schema"] = "v0"
            inventory["consumed_by"] = ["A.1"]
            del inventory["digests"]
        errors = run("check_header", edited(edit))
        self.assert_fails(errors, "schema must be")
        self.assert_fails(errors, "consumed_by must be the graph's dependents of F.1")
        self.assert_fails(errors, "missing section `digests`")
        checker = C.Checker(edited(edit), C.Tree(), None)
        self.assertTrue(any(error.startswith("missing section") for error in checker.check()))


class Readers(Base):
    def test_enum_variants(self) -> None:
        text = """
        pub enum Kind {
            /// one, with a comma
            #[norito(rename = "a{b}")]
            Alpha,
            Beta(Vec<(u8, u8)>),
            // Gamma,
            Delta { x: u8, y: [u8; 2] },
        }
        pub enum Other { One }
        """
        self.assertEqual(C.enum_variants(text, "Kind"), ["Alpha", "Beta", "Delta"])
        self.assertEqual(C.enum_variants(text, "Other"), ["One"])
        self.assertIsNone(C.enum_variants(text, "Missing"))

    def test_string_list_match_arms_and_fn_body(self) -> None:
        text = 'const NAMES: &[&str] = &[\n    "a/b", // note "x"\n    "c",\n];\nfn pick(self) -> T { match self { Self::A | Self::B => T::One, Self::C => { T::Two } Self::D => "label", } }'
        self.assertEqual(C.string_list(text, "NAMES"), ["a/b", "c"])
        self.assertIsNone(C.string_list(text, "OTHER"))
        arms = C.match_arms(C.fn_body(text, "pick"))
        self.assertEqual(arms, {"A": "T::One", "B": "T::One", "C": "T::Two", "D": "label"})
        self.assertIsNone(C.fn_body(text, "absent"))

    def test_production_text_drops_only_test_gated_items(self) -> None:
        text = (
            "struct S {\n    #[cfg(test)]\n    probe: u8,\n    real: u8,\n}\n"
            "#[cfg(test)]\nconst T: u8 = 1;\n"
            "fn kept() { let a = '{'; let b = \"}{\"; }\n"
            "#[cfg(all(test, feature = \"x\"))]\nmod tests {\n    fn gone() { let s = \"}\"; let c = '}'; /* } */ }\n}\n"
            "fn also_kept() {}\n"
            "#[cfg(test)]\nmod external;\n"
            "fn last() {}\n"
        )
        out = C.production_text(text)
        for kept in ("real: u8", "fn kept()", "fn also_kept()", "fn last()"):
            self.assertIn(kept, out)
        for gone in ("probe: u8", "const T", "fn gone()", "mod external"):
            self.assertNotIn(gone, out)
        self.assertEqual(C.production_text("fn plain() {}"), "fn plain() {}")

    def test_rust_item_end_skips_strings_chars_and_comments(self) -> None:
        text = 'fn f() { let a = "}"; let b = \'}\'; // }\n /* } */ let c = r#"}"#; } tail'
        self.assertEqual(text[C.rust_item_end(text, 0):], " tail")
        self.assertEqual(C.rust_item_end("const X: u8 = 1; rest", 0), len("const X: u8 = 1;"))

    def test_route_literal_and_scope(self) -> None:
        self.assertEqual(C.route_literal("/v1/zk/vk/register"), "/v1/zk/vk/register")
        self.assertEqual(C.route_literal("/v1/kaigi/calls/{call_id}/events"), "/v1/kaigi/calls/")
        self.assertEqual(C.route_literal("/v1/accounts/{account_id}/identifiers/claim-receipt"), "/identifiers/claim-receipt")
        self.assertIsNone(C.route_literal("/{a}/b"))
        routes = {"path_prefixes": ["/v1/zk/"]}
        self.assertTrue(C.route_in_scope(routes, "/v1/zk/roots"))
        self.assertFalse(C.route_in_scope(routes, "/v1/zkx"))

    def test_resolve_key_and_squash(self) -> None:
        document = {"a": [{"id": "x", "b": {"c": 1}}, {"name": "y"}, {"variant": "V"}], "list": ["p", "q"]}
        self.assertTrue(C.resolve_key(document, "a/x/b/c"))
        self.assertTrue(C.resolve_key(document, "a/y"))
        self.assertTrue(C.resolve_key(document, "a/V"))
        self.assertTrue(C.resolve_key(document, "list/q"))
        self.assertFalse(C.resolve_key(document, "a/z"))
        self.assertFalse(C.resolve_key(document, "a/x/b/c/d"))
        self.assertTrue(C.contains("fn  a(\n   b: u8)", "fn a( b: u8)"))
        self.assertFalse(C.contains("fn a()", "fn b()"))

    def test_syscall_and_builtin_readers(self) -> None:
        text = "pub const SYSCALL_A_B: u32 = 0x1F;\npub const SMARTCONTRACT_INSTRUCTION_TAG_X: u64 = 7;\n"
        self.assertEqual(C.syscall_constants(text), {"A_B": 31})
        self.assertEqual(C.instruction_tags(text), {"X": 7})
        builtins = "Self::A | Self::B => &[s::SYSCALL_ONE, s::SYSCALL_TWO],\nSelf::C => { &[s::SYSCALL_ONE] }\n// Self::D => &[s::SYSCALL_ONE],"
        self.assertEqual(C.builtin_syscalls(builtins), {"ONE": ["A", "B", "C"], "TWO": ["A", "B"]})

    def test_registry_reader_and_scope(self) -> None:
        registry = {"path": "r.rs", "entry_macros": ["built_in_wire_id"], "strip_prefixes": ["crate::isi::"],
                    "modules": {"a": {"scope": "full"}, "b": {"scope": "partial", "pattern": "Zk"}, "": {"scope": "out"}}}
        text = 'built_in_wire_id!(crate::isi::a::One => "id.one"),\nbuilt_in_wire_id!(b::ZkTwo => "id.two", register),\nbuilt_in_wire_id!(b::Three => "id.three"),\nbuilt_in_wire_id!(Top => "id.top"),\nbuilt_in_wire_id!(c::New => "id.new"),'
        entries = C.registry_entries(C.Tree(C.ROOT, {"r.rs": text}), registry)
        self.assertEqual([entry["type"] for entry in entries], ["a::One", "b::ZkTwo", "b::Three", "Top", "c::New"])
        self.assertEqual([C.module_scope(registry, entry) for entry in entries], ["in", "in", "out", "out", "unclassed"])

    def test_tsv_reader_and_tree_overrides(self) -> None:
        rows = C.tsv_rows("# comment\nroute_id\tmethod\tpath\nx.y\tGET\t/v1/x\n")
        self.assertEqual(rows, {"x.y": {"route_id": "x.y", "method": "GET", "path": "/v1/x"}})
        self.assertEqual(C.tsv_rows(None), {})
        tree = C.Tree(C.ROOT, {"scripts/new_file.py": "x", "scripts/check_zk_operation_inventory.py": None})
        self.assertEqual(tree.read("scripts/new_file.py"), "x")
        self.assertFalse(tree.exists("scripts/check_zk_operation_inventory.py"))
        files = tree.walk(["scripts"], (".py",))
        self.assertIn("scripts/new_file.py", files)
        self.assertNotIn("scripts/check_zk_operation_inventory.py", files)

    def test_propose_prints_skeletons_for_unlisted_entries(self) -> None:
        overrides = appended_registry('built_in_wire_id!(kaigi::RotateKaigiHost => "iroha.kaigi.rotate_host.v1"),')
        overrides[C.ROUTE_TSV] = source(C.ROUTE_TSV) + "zk.shield.apply\tPOST\t/v1/zk/shield\tpublic\tx\ty\tmutation\thttp\talways\ttrue\ttrue\ttrue\tfalse\n"
        lines = "\n".join(C.Checker(INVENTORY, C.Tree(C.ROOT, overrides), None).propose())
        self.assertIn('"type": "kaigi::RotateKaigiHost"', lines)
        self.assertIn('"wire_id": "iroha.kaigi.rotate_host.v1"', lines)
        self.assertIn('"id": "zk.shield.apply"', lines)
        self.assertEqual(C.Checker(INVENTORY, C.Tree(), None).propose(), [])


SAMPLE_RUST = """
//! Sample. fn in_a_comment() { verify_secret(); }
use x::Execute;
const NOTE: &str = "fn in_a_string() { verify_secret() }";
macro_rules! sample_test {
    ($name:ident $body:block) => {
        #[test]
        fn $name() $body
    };
}
pub fn verify_sample(proof: &[u8]) -> bool {
    check_bytes(proof)
}
fn check_bytes(proof: &[u8]) -> bool {
    let lifetime: &'static str = "}";
    let quote = '{';
    proof.len() > 1 && core_verify(proof)
}
fn twice(a: u8) -> u8 { a }
mod other { fn twice(a: u8) -> u8 { a + 1 } }
impl Execute for SubmitSample {
    fn execute(self, authority: &AccountId, st: &mut St) -> Result<(), Error> {
        self.execute_authorized(authority, st)
    }
}
impl SampleAuthorized for SubmitSample {
    fn execute_authorized(self, authority: &AccountId, st: &mut St) -> Result<(), Error> {
        if authority != &self.owner {
            return Err(unauthorized("only the owner"));
        }
        ensure_role(st, authority)?;
        st.world.account(authority)?;
        log(Wrapper::Signed(authority));
        apply(st, |inner| { record(inner); lineage(inner, authority, &self.owner) })?;
        verify_sample(&self.proof);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> SubmitSample { SubmitSample::default() }
    #[test]
    fn handler_accepts_a_sample() {
        let instruction = fixture();
        instruction.execute(&ALICE, &mut st()).unwrap();
    }
    #[test]
    fn direct_call() { assert!(verify_sample(&[1, 2])); }
    #[test]
    fn unrelated() { assert_eq!(twice(1), 1); }
    sample_test!(macro_written {
        assert!(verify_sample(&[3, 4]));
    });
}
"""
SAMPLE = "crates/sample/src/sample.rs"
SAMPLE_CORE = "crates/sample/src/core.rs"
SAMPLE_CORE_RUST = "pub fn core_verify(proof: &[u8]) -> bool { !proof.is_empty() }\n"


def sample_tree(**extra) -> "C.Tree":
    files = {SAMPLE: SAMPLE_RUST, SAMPLE_CORE: SAMPLE_CORE_RUST}
    files.update(extra)
    return C.Tree(C.ROOT, files)


class Reach(Base):
    """The textual reach engine on a small synthetic file."""

    def test_code_only_blanks_comments_and_literals_and_keeps_offsets(self) -> None:
        code = C.code_only(SAMPLE_RUST)
        self.assertEqual(len(code), len(SAMPLE_RUST))
        self.assertEqual(code.count("\n"), SAMPLE_RUST.count("\n"))
        self.assertNotIn("in_a_comment", code)
        self.assertNotIn("in_a_string", code)
        self.assertNotIn("only the owner", code)
        self.assertIn("fn check_bytes", code)
        self.assertIn("&'static str", code)

    def test_body_start_finds_the_item_brace_or_a_declaration(self) -> None:
        code = "fn a(x: [u8; 2]) -> Result<(), E> where T: Fn(u8) -> u8 { 1 } fn b(); fn c() {}"
        self.assertEqual(code[C.body_start(code, 0)], "{")
        self.assertEqual(C.body_start(code, 0), code.index("{"))
        self.assertIsNone(C.body_start(code, code.index("fn b")))
        self.assertIsNone(C.body_start("fn never", 0))

    def test_index_reads_functions_impls_and_macro_written_tests(self) -> None:
        index = C.rust_index(SAMPLE_RUST)
        self.assertIs(index, C.rust_index(SAMPLE_RUST))
        for name in ("verify_sample", "check_bytes", "execute", "execute_authorized", "handler_accepts_a_sample", "macro_written"):
            self.assertEqual(len(index.functions[name]), 1, name)
        self.assertEqual(len(index.functions["twice"]), 2)
        self.assertNotIn("in_a_comment", index.functions)
        self.assertNotIn("in_a_string", index.functions)
        self.assertEqual([(block["trait"], block["type"]) for block in index.impls],
                         [("Execute", "SubmitSample"), ("SampleAuthorized", "SubmitSample")])
        position = SAMPLE_RUST.index("ensure_role(st, authority)")
        self.assertEqual(index.enclosing(position), ("execute_authorized", "SubmitSample"))
        self.assertEqual(index.enclosing(SAMPLE_RUST.index("const NOTE")), (None, None))
        self.assertIsNotNone(index.item_span(SAMPLE_RUST.index("pub fn verify_sample")))
        self.assertIsNone(index.item_span(len(SAMPLE_RUST) - 1))

    def test_closure_follows_unique_functions_and_executed_handlers(self) -> None:
        index = C.rust_index(SAMPLE_RUST)
        direct = index.closure(index.functions["direct_call"])
        self.assertTrue(C.names(direct, "check_bytes"))
        self.assertTrue(C.names(direct, "core_verify"))
        self.assertFalse(C.names(index.closure(index.functions["direct_call"], depth=0), "check_bytes"))
        self.assertFalse(C.names(index.closure(index.functions["direct_call"], stop=frozenset({"verify_sample"})), "check_bytes"))
        handler = index.closure(index.functions["handler_accepts_a_sample"])
        self.assertTrue(C.names(handler, "execute_authorized"), "the type comes from the fixture, the call from the test")
        self.assertFalse(C.names(index.closure(index.functions["unrelated"]), "verify_sample"))
        self.assertTrue(C.names(index.closure(index.functions["macro_written"]), "check_bytes"))
        raw = index.closure(index.functions["execute_authorized"], raw=True)
        self.assertIn("only the owner", raw)
        self.assertNotIn("only the owner", index.closure(index.functions["execute_authorized"]))

    def test_symbol_position_names_and_verifier_name(self) -> None:
        self.assertEqual(C.symbol_position("fn  a(\n  b: u8)", "fn a( b: u8)"), 0)
        self.assertIsNone(C.symbol_position("fn a()", "fn b()"))
        self.assertIsNone(C.symbol_position("fn a()", "  "))
        self.assertTrue(C.names("x.verify_sample(y)", "verify_sample"))
        self.assertFalse(C.names("verify_sample_v2(y)", "verify_sample"))
        self.assertEqual(C.verifier_name({"symbol": "pub fn verify_for_relation("}), "verify_for_relation")
        self.assertEqual(C.verifier_name({"symbol": "verify_batch_encoded(&statement, proof)"}), "verify_batch_encoded")
        self.assertEqual(C.verifier_name({"symbol": "Some(X::Y)", "name": "verify_for_relation"}), "verify_for_relation")
        self.assertIsNone(C.verifier_name({"symbol": "no call here"}))

    def test_anchor_names_and_closures(self) -> None:
        tree = sample_tree()
        self.assertEqual(C.anchor_names(tree, {"path": SAMPLE, "symbol": "pub fn verify_sample("}), ["verify_sample"])
        self.assertEqual(C.anchor_names(tree, {"path": SAMPLE, "symbol": "impl Execute for SubmitSample"}), ["SubmitSample"])
        self.assertEqual(C.anchor_names(tree, {"path": SAMPLE, "symbol": "impl Execute for x::Generic<T> {"}), ["Generic"])
        self.assertEqual(C.anchor_names(tree, {"path": SAMPLE, "symbol": "ensure_role(st, authority)?;"}), ["SubmitSample"])
        self.assertEqual(C.anchor_names(tree, {"path": SAMPLE, "symbol": "proof.len() > 1"}), ["check_bytes"])
        self.assertEqual(C.anchor_names(tree, {"path": SAMPLE, "symbol": "no such text"}), [])
        self.assertEqual(C.anchor_names(tree, {"path": "crates/sample/src/gone.rs", "symbol": "x"}), [])
        whole = C.anchor_closure(tree, {"path": SAMPLE, "symbol": "impl Execute for SubmitSample"})
        self.assertTrue(C.names(whole, "ensure_role"), "an impl anchor stands for every impl block of the type")
        self.assertIsNone(C.anchor_closure(tree, {"path": SAMPLE, "symbol": "no such text"}))
        self.assertIsNone(C.anchor_closure(tree, {"path": "crates/sample/src/gone.rs", "symbol": "x"}))
        self.assertIsNone(C.test_closure(tree, {"path": SAMPLE, "test": "absent"}))
        self.assertIsNone(C.test_closure(tree, {"path": "crates/sample/src/gone.rs", "test": "x"}))

    def test_reach_through_the_file_and_through_named_links(self) -> None:
        tree = sample_tree()
        direct = {"path": SAMPLE, "test": "direct_call"}
        self.assertIsNone(C.reach(tree, direct, ["verify_sample"]))
        self.assertIn("does not name `core_verify_v2`", C.reach(tree, direct, ["core_verify_v2"]))
        self.assertIn("has no body", C.reach(tree, {"path": SAMPLE, "test": "absent"}, ["verify_sample"]))
        self.assertIn("does not name `verify_sample`", C.reach(tree, {"path": SAMPLE, "test": "unrelated"}, ["verify_sample"]))
        link = {"path": SAMPLE_CORE, "symbol": "pub fn core_verify("}
        self.assertIsNone(C.reach(tree, dict(direct, reaches=[link]), ["is_empty"]))
        self.assertIn("test unrelated does not name `core_verify`",
                      C.reach(tree, {"path": SAMPLE, "test": "unrelated", "reaches": [link]}, ["is_empty"]))
        self.assertIn("is not a function or impl", C.reach(tree, dict(direct, reaches=[{"path": SAMPLE_CORE, "symbol": "gone"}]), ["x"]))
        self.assertIsNone(C.reach(tree, direct, ["verify_sample"], also=["assert"]))
        self.assertIn("none of ['OtherRelation']", C.reach(tree, direct, ["verify_sample"], also=["OtherRelation"]))
        self.assertIsNone(C.reach(tree, {"path": SAMPLE, "test": "handler_accepts_a_sample"}, ["SubmitSample"]))

    def test_feature_gate_reads_the_inner_attribute_of_an_integration_test(self) -> None:
        manifest = '[package]\nname = "sample"\n\n[features]\ndefault = ["node"]\nnode = []\nzk-tests = []\n'
        gated = '//! Gated.\n#![cfg(all(\n    feature = "node",\n    feature = "zk-tests"\n))]\n#[test]\nfn case() {}\n'
        tree = C.Tree(C.ROOT, {"crates/sample/Cargo.toml": manifest, "crates/sample/tests/gated.rs": gated,
                               "crates/sample/tests/open.rs": '#![cfg(feature = "node")]\n#[test]\nfn case() {}\n'})
        self.assertEqual(C.feature_gate(tree, "crates/sample/tests/gated.rs"), "zk-tests")
        self.assertIsNone(C.feature_gate(tree, "crates/sample/tests/open.rs"))


class Authority(Base):
    REGISTRY = {
        "authority_token_pattern": r"\b(?:ensure_role|Can[A-Z][A-Za-z0-9]+)\b",
        "authority_comparison_pattern": r"[!=]=\s*[&*]?\s*authority(?![A-Za-z0-9_])|(?<![A-Za-z0-9_.])authority\s*[!=]=\s*&?",
        "authority_words": ["authority"],
        "authority_passthrough": [{"symbol": "account", "what": "lookup"}],
    }

    def test_argument_callees_walks_out_of_constructors_and_stops_at_statements(self) -> None:
        code = C.code_only(
            "fn f(authority: &Id) {\n"
            "    let authority = other(x);\n"
            "    ensure_role(st, authority)?;\n"
            "    st.world.account(authority)?;\n"
            "    log(Wrapper::Signed(authority));\n"
            "    note(format!(\"{authority}\"), 1);\n"
            "    apply(st, |inner| { record(inner); lineage(inner, authority, &owner) })?;\n"
            "    if (authority == &owner) { return; }\n"
            "    plain(\"authority\");\n"
            "    items[authority.index()].touch(first(&[authority]));\n"
            "    let copy = authority.clone();\n"
            "}\n"
        )
        self.assertEqual(C.argument_callees(code, ("authority",)), {"ensure_role", "account", "log", "lineage", "first"})
        self.assertEqual(C.argument_callees(code, ()), set())
        self.assertEqual(C.argument_callees("fn f() { check(authorization, 1); }", ("authority", "authorization")), {"check"})

    def test_authority_tokens_join_names_comparisons_and_receivers(self) -> None:
        tree = sample_tree()
        block = {"path": SAMPLE, "symbol": "impl Execute for SubmitSample", "body": ""}
        code = C.handler_scope(tree, block, "SubmitSample")
        raw = C.handler_scope(tree, block, "SubmitSample", raw=True)
        self.assertEqual(C.authority_tokens(code, raw, self.REGISTRY),
                         {"authority != &", "ensure_role", "execute_authorized", "log", "lineage"})
        permission = 'fn execute() { has(st, "CanManageSamples"); } // CanIgnoreThis'
        self.assertEqual(C.authority_tokens(C.code_only(permission), permission, self.REGISTRY), {"CanManageSamples"})
        self.assertIn("verify_sample", C.handler_scope(tree, block, "SubmitSample", depth=1))
        self.assertTrue(C.names(C.handler_scope(tree, block, "SubmitSample", depth=1), "check_bytes"))
        self.assertFalse(C.names(code, "check_bytes"))
        orphan = {"path": SAMPLE, "symbol": "impl Execute for Elsewhere", "body": "impl Execute for Elsewhere { /* x */ fn execute() {} }"}
        self.assertNotIn("/* x */", C.handler_scope(tree, orphan, "Elsewhere"))
        self.assertIn("/* x */", C.handler_scope(tree, orphan, "Elsewhere", raw=True))

    def test_a_check_removed_inside_a_delegate_fails(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/kaigi.rs"
        old = ('        if authority != template.host() {\n'
               '            return Err(unauthorized("only the host account may create a Kaigi"));\n'
               '        }')
        self.assert_fails(run("check_anchors", overrides=replaced(path, old, "")),
                          'operations[kaigi::CreateKaigi].authority')
        old = '        return Err(unauthorized("account is not associated with the Kaigi"));'
        errors = run("check_anchors", overrides=replaced(path, old, "        return Ok(());"))
        for identifier in ("kaigi::JoinKaigi", "kaigi::EndKaigi", "kaigi::RecordKaigiUsage"):
            self.assert_fails(errors, f"operations[{identifier}].authority")

    def test_a_host_only_check_removed_from_a_handler_fails(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/kaigi.rs"
        text = source(path)
        old = ('                if !accounts_share_active_lineage(stx, authority, &record.host)? {\n'
               '                    return Err(unauthorized("only the host may record usage for a Kaigi"));\n'
               '                }\n')
        self.assertIn(old, text)
        errors = run("check_registry", overrides={path: text.replace(old, "")})
        self.assert_fails(errors, "operations[kaigi::RecordKaigiUsage]: authority check `accounts_share_active_lineage` is not in the handler body")

    def test_a_new_function_that_receives_the_signer_fails(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/world.rs"
        text = source(path)
        head = "impl Execute for zk::PruneProofs {"
        start = text.index("{", text.index("fn execute", text.index(head)))
        mutated = text[: start + 1] + "\n        ensure_proof_pruner(authority, state_transaction)?;" + text[start + 1 :]
        self.assert_fails(run("check_registry", overrides={path: mutated}),
                          "operations[zk::PruneProofs]: the handler contains the authority check `ensure_proof_pruner`")
        compared = text[: start + 1] + "\n        if self.owner != *authority { return Err(denied()); }" + text[start + 1 :]
        self.assert_fails(run("check_registry", overrides={path: compared}),
                          "operations[zk::PruneProofs]: the handler contains the authority check `!= *authority`")

    def test_recorded_checks_of_the_reported_rows_are_listed(self) -> None:
        def symbols(identifier: str) -> set[str]:
            return {check["symbol"] for check in operation(INVENTORY, identifier)["authority"]}
        self.assertIn("!= *authority", symbols("governance::UpdatePlainConviction"))
        self.assertIn("!= *authority", symbols("governance::CastZkBallot"))
        for identifier in ("kaigi::RecordKaigiUsage", "kaigi::SetKaigiRelayManifest", "kaigi::ReportKaigiRelayHealth", "kaigi::EndKaigi"):
            self.assertIn("accounts_share_active_lineage", symbols(identifier), identifier)
        self.assertIn('return Err(unauthorized("only the host account may create a Kaigi"));', symbols("kaigi::CreateKaigi"))
        for item in INVENTORY["operations"]:
            for check in item.get("authority", []):
                if check.get("scope") == "file":
                    self.assertTrue(check.get("what"), (item["id"], check["symbol"]))

    def test_passthrough_and_scope_shape_are_checked(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["registry"]["authority_passthrough"].append({"symbol": "never_called"})
            operation(inventory, "kaigi::CreateKaigi")["authority"][-1].pop("what")
            operation(inventory, "kaigi::JoinKaigi")["authority"][0]["scope"] = "galaxy"
            inventory["registry"]["authority_passthrough"] = [
                item for item in inventory["registry"]["authority_passthrough"] if item["symbol"] != "account"]
        errors = run("check_registry", edited(edit))
        self.assert_fails(errors, "registry.authority_passthrough[never_called]: `what` must say why it is not a check")
        self.assert_fails(errors, "registry.authority_passthrough[never_called]: no listed handler passes the authority to it")
        self.assert_fails(errors, "outside the handler needs `what`")
        self.assert_fails(errors, "operations[kaigi::JoinKaigi]: authority scope must be handler or file")
        self.assert_fails(errors, "the handler contains the authority check `account`")


class HandlerTripwire(Base):
    def test_a_verifier_reached_through_a_helper_of_the_file_fails(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/vpn.rs"
        text = source(path)
        head = "impl Execute for SettleVpnLease {"
        start = text.index("{", text.index("fn execute", text.index(head)))
        mutated = (text[: start + 1] + "\n        check_lease(&self)?;" + text[start + 1 :]
                   + "\nfn check_lease(i: &SettleVpnLease) -> Result<(), Error> { verify_lease_proof(i) }\n")
        self.assert_fails(run("check_registry", overrides={path: mutated}),
                          "the handler of vpn::SettleVpnLease calls verify_lease_proof")

    def test_macro_generated_handler_files_are_listed_with_their_calls(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/sccp/mod.rs"
        self.assertEqual(C.macro_handler_files(REAL, ["crates/iroha_core/src/smartcontracts/isi/sccp"]), [path])
        self.assertEqual(C.macro_handler_files(REAL, ["crates/iroha_core/src/smartcontracts/isi/vpn.rs"]), [])
        mutated = source(path) + "\nfn admit(p: &P) -> bool { verify_sccp_zk_proof(p) }\n"
        self.assert_fails(run("check_registry", overrides={path: mutated}),
                          f"registry.tripwire.macro_generated: {path} calls ['verify_sccp_zk_proof'], recorded []")
        new = "crates/iroha_core/src/smartcontracts/isi/generated_handlers.rs"
        overrides = {new: "macro_rules! h { ($t:ty) => { impl Execute for $t { fn execute(self) {} } }; }\n"}
        self.assert_fails(run("check_registry", overrides=overrides),
                          f"registry.tripwire.macro_generated: {new} writes `impl Execute` for a macro variable")

        def edit(inventory: dict) -> None:
            inventory["registry"]["tripwire"]["macro_generated"].append({"path": "crates/iroha_core/src/smartcontracts/isi/vpn.rs", "calls": []})
        errors = run("check_registry", edited(edit))
        self.assert_fails(errors, "vpn.rs no longer generates handlers by macro")
        self.assert_fails(errors, "vpn.rs needs a reason")


class EntryPoints(Base):
    """A new verifier or validator call is a new admission route or belongs to a recorded one."""

    def test_census_counts_code_only_and_names_capturing_tokens(self) -> None:
        census = {
            "roots": ["crates/sample/src"], "exclude": [r"_tests\.rs$"],
            "out_of_scope_names": [{"pattern": "musubi", "reason": "x"}],
            "tokens": [
                {"id": "sample", "needle": "verify_sample", "pattern": r"\bverify_sample\s*\("},
                {"id": "restore", "pattern": r"(?<!fn )\b(validate_[a-z_]*proof[a-z_]*)\s*\(", "roots": ["crates/sample/src/restore.rs"]},
                {"id": "absent", "needle": "never_here", "pattern": r"never_here"},
            ],
        }
        restore = ("fn validate_proof_index() {}\nfn load() { validate_proof_index(); validate_proof_index(); validate_proof_tags();\n"
                   "    validate_musubi_proofs(); /* validate_proof_comment() */ let s = \"validate_proof_string()\"; }\n"
                   "#[cfg(test)]\nmod tests { fn t() { validate_proof_only_in_tests(); } }\n")
        tree = sample_tree(**{"crates/sample/src/restore.rs": restore, "crates/sample/src/sample_tests.rs": "fn x() { verify_sample(1); }"})
        self.assertEqual(C.entry_point_census(tree, census), [
            {"token": "restore", "name": "validate_proof_index", "path": "crates/sample/src/restore.rs", "count": 2},
            {"token": "restore", "name": "validate_proof_tags", "path": "crates/sample/src/restore.rs", "count": 1},
            {"token": "sample", "path": SAMPLE, "count": 2},
        ])

    def test_tracked_census_matches_and_every_row_is_classed(self) -> None:
        section = INVENTORY["admission_routes"]
        census = section["entry_point_census"]
        self.assertEqual(C.entry_point_census(REAL, census),
                         [{key: value for key, value in row.items() if key in ("token", "name", "path", "count")}
                          for row in census["occurrences"]])
        classes = set(C.ADMISSION_ROUTES) | set(census["other_classes"])
        self.assertTrue(all(row["route"] in classes for row in census["occurrences"]))
        self.assertGreater(len([row for row in census["occurrences"] if row["route"] == "restore"]), 15)

    def test_new_verifier_calls_in_five_route_classes_fail(self) -> None:
        additions = {
            "crates/iroha_core/src/queue.rs": "\nfn admit_early(e: &E, c: C) -> bool { verify_privacy_envelope_v1(e, c).is_ok() }\n",
            "crates/iroha_genesis/src/lib.rs": "\nfn genesis_verify(b: &str, p: &ProofBox) -> bool { iroha_core_zk::verify_backend(b, p, None) }\n",
            "crates/iroha_core/src/state/deserialize_core.rs": "\nfn reverify(w: &World) -> bool { validate_proof_records_at_restore(w) }\n",
            "crates/iroha_core/src/tx.rs": "\nfn pre(p: &ProofBox) -> bool { crate::zk::preverify_with_budget(p, None, &mut b(), 0).is_ok() }\n",
            "crates/iroha_torii/src/lib.rs": "\nasync fn handler_privacy_verify(e: E) -> bool { verify_privacy_envelope_v1(&e, ctx()).is_ok() }\n",
        }
        errors = run("check_admission_routes", overrides={path: source(path) + text for path, text in additions.items()})
        self.assert_fails(errors, "`exact12_dispatch` in crates/iroha_core/src/queue.rs occurs 1 times and is not classed")
        self.assert_fails(errors, "`generic_backend` in crates/iroha_genesis/src/lib.rs occurs 1 times and is not classed")
        self.assert_fails(errors, "`validate_proof_records_at_restore` in crates/iroha_core/src/state/deserialize_core.rs occurs 1 times and is not classed")
        self.assert_fails(errors, "`preverification` in crates/iroha_core/src/tx.rs occurs 1 times and is not classed")
        self.assert_fails(errors, "`exact12_dispatch` in crates/iroha_torii/src/lib.rs occurs 1 times and is not classed")

    def test_a_second_call_in_a_recorded_file_and_a_removed_restore_validator_fail(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/game.rs"
        errors = run("check_admission_routes",
                     overrides={path: source(path) + "\nfn again(p: &P) { crate::execution_proofs::verify_execution_proof_v1(p).ok(); }\n"})
        self.assert_fails(errors, f"`execution_proof` in {path} occurs 2 times, recorded 1")
        restore = "crates/iroha_core/src/state/deserialize_world.rs"
        errors = run("check_admission_routes",
                     overrides=replaced(restore, "    verifying_key_index::validate_verifying_key_index(&world)?;\n", ""))
        self.assert_fails(errors, f"`validate_verifying_key_index` in {restore} no longer occurs")

    def test_classes_sites_and_exclusions_are_checked(self) -> None:
        def edit(inventory: dict) -> None:
            section = inventory["admission_routes"]
            rows = {(row["token"], row.get("name", ""), row["path"]): row for row in section["entry_point_census"]["occurrences"]}
            rows[("execution_proof", "", "crates/iroha_core/src/smartcontracts/isi/game.rs")]["route"] = "telepathy"
            rows[("purpose_bound", "", "crates/iroha_core_zk/src/confidential_v2.rs")].pop("note")
            rows[("lane_privacy", "", "crates/iroha_core/src/queue.rs")]["excluded"] = "no_such_exclusion"
            section["restore"]["sites"] = [site for site in section["restore"]["sites"] if "validate_proof_tag_index" not in site["symbol"]]
            section["torii"]["sites"] = [site for site in section["torii"]["sites"] if not site["path"].endswith("zk_prover.rs")]
            section["excluded"].append({"id": "incomplete"})
            section["entry_point_census"]["tokens"].append({"id": "never", "pattern": r"never_called_anywhere_v9\("})
            section["entry_point_census"]["out_of_scope_names"].append({"pattern": "zzz"})
            section["entry_point_census"]["tokens"] = [
                token for token in section["entry_point_census"]["tokens"] if token["id"] != "timed_ovn_release"]
        errors = run("check_admission_routes", edited(edit))
        self.assert_fails(errors, "is not classed under a route class (route: telepathy)")
        self.assert_fails(errors, "crates/iroha_core_zk/src/confidential_v2.rs is classed `not_admission` and needs a note")
        self.assert_fails(errors, "crates/iroha_core/src/queue.rs names no entry of admission_routes.excluded")
        self.assert_fails(errors, "admission_routes.restore: `validate_proof_tag_index` in crates/iroha_core/src/state/deserialize_world.rs is classed here and no site of the class names it")
        self.assert_fails(errors, "admission_routes.torii: `generic_backend_guardrails` in crates/iroha_torii/src/zk_prover.rs is classed here and no site of the class names it")
        self.assert_fails(errors, "admission_routes.excluded[incomplete]: id, site and reason are required")
        self.assert_fails(errors, "tokens[never]: the token occurs nowhere")
        self.assert_fails(errors, "out_of_scope_names[zzz]: reason is required")
        self.assert_fails(errors, "the verifier `verify_final_release` of relation voting.parliament_timed_ovn has no token")

        def missing(inventory: dict) -> None:
            del inventory["admission_routes"]["entry_point_census"]
        self.assert_fails(run("check_admission_routes", edited(missing)), "admission_routes.entry_point_census is required")

    def test_restore_lists_the_validators_of_the_plan_products(self) -> None:
        symbols = " ".join(site["symbol"] for site in INVENTORY["admission_routes"]["restore"]["sites"])
        for name in ("validate_private_settlement_persisted_state_v1", "validate_privacy_persisted_state_v1",
                     "validate_privacy_public_reserve_dependencies_v1", "validate_proof_tag_index", "validate_verifying_key_index",
                     "validate_identifier_claims", "validate_soracloud_service_deployment_history", "proof_status_restore::rebuild"):
            self.assertIn(name, symbols)
        self.assertNotIn("read as stored", INVENTORY["admission_routes"]["restore"]["what"])

    def test_a_route_test_reaches_a_listed_site_or_says_what_it_covers(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["admission_routes"]["restore"]["tests"].append(
                {"path": "crates/iroha_core_zk/src/verification/tests.rs", "test": "backend_confusion_and_unknown_circuits_reject_before_crypto"})
        self.assert_fails(run("check_admission_routes", edited(edit)),
                          "admission_routes.restore: test backend_confusion_and_unknown_circuits_reject_before_crypto does not name")

    def test_lane_privacy_proofs_are_excluded_with_a_reason(self) -> None:
        excluded = {item["id"]: item for item in INVENTORY["admission_routes"]["excluded"]}
        self.assertIn("Merkle", excluded["lane_privacy_merkle_proofs"]["reason"])
        rows = [row for row in INVENTORY["admission_routes"]["entry_point_census"]["occurrences"] if row["token"] == "lane_privacy"]
        self.assertEqual({row["path"] for row in rows},
                         {"crates/iroha_core/src/interlane/mod.rs", "crates/iroha_core/src/queue.rs", "crates/iroha_core/src/tx.rs"})
        self.assertTrue(all(row["route"] == "excluded" for row in rows))


class PlainBallotAndRestoreGuards(Base):
    """Actual shared authority and restore guards stay independently anchored."""

    BALLOTS = ("governance::CastPlainBallot", "governance::UpdatePlainConviction")
    WORLD = "crates/iroha_core/src/smartcontracts/isi/world.rs"
    RESTORE_WORLD = "crates/iroha_core/src/state/deserialize_world.rs"
    RESTORE_CORE = "crates/iroha_core/src/state/deserialize_core.rs"

    def guarded_ballots(self) -> list[dict]:
        return [operation(INVENTORY, identifier) for identifier in self.BALLOTS]

    def guarded_restore(self) -> list[dict]:
        return [site for site in INVENTORY["admission_routes"]["restore"]["sites"] if "state_field" in site]

    def anchors(self, **nodes) -> dict:
        routes = [{"id": route} for item in nodes.get("operations", []) for route in item.get("routes", [])]
        return dict(inventories=INVENTORY["inventories"], routes={"list": routes}, **nodes)

    def removed_symbol(self, site: dict) -> dict:
        text = source(site["path"])
        pattern = re.compile(r"\s+".join(re.escape(part) for part in site["symbol"].split()))
        matches = list(pattern.finditer(text))
        self.assertEqual(len(matches), 1, site)
        match = matches[0]
        return {site["path"]: text[:match.start()] + text[match.end():]}

    def test_both_plain_ballots_name_exact_permission_citizen_and_shared_owner_guards(self) -> None:
        for op in self.guarded_ballots():
            guards = [item for item in op["authority"] if item.get("scope") == "file"]
            symbols = " ".join(item["symbol"] for item in guards)
            for name in ("CanSubmitGovernanceBallot", "ensure_exact_governance_ballot_permission",
                         "ensure_citizen_for_ballot", "if ballot.owner != *authority"):
                self.assertIn(name, symbols, op["id"])
            self.assertTrue(all(item.get("what") for item in guards))
        direct = operation(INVENTORY, "governance::UpdatePlainConviction")["authority"]
        self.assertTrue(any(item["symbol"] == "!= *authority" for item in direct))
        self.assertTrue(any('"owner must equal authority"' in item["symbol"] for item in direct))
        self.assert_clean(run("check_anchors", self.anchors(operations=self.guarded_ballots())))

    def test_removing_each_shared_plain_ballot_guard_is_detected_for_both_operations(self) -> None:
        guards = [item for item in self.guarded_ballots()[0]["authority"]
                  if item.get("scope") == "file" and item["symbol"] != "fn execute_plain_ballot_position("]
        self.assertEqual(len(guards), 4)
        for guard in guards:
            with self.subTest(guard=guard["symbol"]):
                errors = run("check_anchors", self.anchors(operations=self.guarded_ballots()),
                             overrides=self.removed_symbol(guard))
                for identifier in self.BALLOTS:
                    self.assert_fails(errors, f"operations[{identifier}].authority[")

    def test_restore_lists_all_twenty_two_axt_guards_and_committed_height_policy(self) -> None:
        guards = self.guarded_restore()
        self.assertEqual(Counter(site["state_field"] for site in guards), {
            "world.axt_handle_counters": 10, "world.axt_source_transfer_replay_ledger": 4,
            "world.axt_asset_incarnations": 3, "world.axt_replay_ledger": 3,
            "world.axt_handle_budget_ledger": 1, "world.axt_spend_nonce_ledger": 1,
            "world.privacy_consensus_policy": 1,
        })
        refs = INVENTORY["admission_routes"]["restore"]["references"]
        for site in guards:
            self.assertTrue(site["what"])
            self.assertIn({"inventory": "state", "key": "fields/" + site["state_field"]}, refs)
        self.assert_clean(run("check_anchors", self.anchors(sites=guards, references=refs)))

    def test_removing_each_original_restore_guard_is_detected(self) -> None:
        for guard in self.guarded_restore():
            with self.subTest(field=guard["state_field"], guard=guard["symbol"]):
                errors = run("check_anchors", self.anchors(sites=[guard]),
                             overrides=self.removed_symbol(guard))
                self.assert_fails(errors, "sites[0]:")

    def test_restore_guard_requires_original_state_reference_and_meaning(self) -> None:
        def edit(inventory: dict) -> None:
            restore = inventory["admission_routes"]["restore"]
            restore["references"] = [ref for ref in restore["references"]
                                     if ref["key"] != "fields/world.axt_handle_counters"]
            next(site for site in restore["sites"] if site.get("state_field") == "world.privacy_consensus_policy").pop("what")
        errors = run("check_admission_routes", edited(edit))
        self.assert_fails(errors, "world.axt_handle_counters needs its State inventory reference")
        self.assert_fails(errors, "world.privacy_consensus_policy needs `what`")

    def test_removed_key_and_committed_height_validations_change_the_census(self) -> None:
        for path, call, expected in (
            (self.RESTORE_WORLD, ".validate_for_key(key)", "occurs 2 times, recorded 3"),
            (self.RESTORE_CORE, ".validate_at_committed_height(committed_height)", "no longer occurs"),
        ):
            with self.subTest(call=call):
                errors = run("check_admission_routes", overrides=replaced(path, call, ".unchecked()"))
                self.assert_fails(errors, expected)

    def test_new_axt_or_key_or_height_restore_calls_require_classification(self) -> None:
        for call, expected in (
            ("validate_axt_replay_ledger(w)", "`validate_axt_replay_ledger`"),
            ("w.validate_for_key(key)", "occurs 4 times, recorded 3"),
            ("w.validate_at_committed_height(height)", "`validate_at_committed_height`"),
        ):
            with self.subTest(call=call):
                path = self.RESTORE_WORLD
                errors = run("check_admission_routes", overrides={path: source(path) +
                             "\nfn new_restore_guard(w: &World) { " + call + "; }\n"})
                self.assert_fails(errors, expected)


class AxtSplit(Base):
    """The refusals of AXT proofs and anchored spends are operations of their own."""

    def test_spend_and_proof_are_refused_operations_with_their_refusal_tests(self) -> None:
        spend = operation(INVENTORY, "axt.anchored_spend")
        self.assertEqual((spend["status"]["verification"], spend["status"]["state_effects"]), ("refused", "unreachable"))
        self.assertIn("AXT_UNANCHORED_REMOTE_SPEND_REJECTION", spend["refusal"]["symbol"])
        self.assertIn("signed_spends_are_rejected_before_fastpq_verification", [test["test"] for test in spend["tests"]])
        proof = operation(INVENTORY, "axt.ds_proof")
        self.assertEqual((proof["status"]["verification"], proof["status"]["state_effects"]), ("refused", "unreachable"))
        self.assertIn("standalone FASTPQ proof admission is unavailable", proof["refusal"]["symbol"])
        envelope = operation(INVENTORY, "axt.envelope")
        self.assertEqual(envelope["status"]["verification"], "not_applicable")
        self.assertNotIn("StageAnchoredSpend", envelope["kotodama"]["builtins"])
        self.assertNotIn("VerifyDsProof", envelope["kotodama"]["builtins"])

    def test_the_refusals_are_anchored_in_the_source(self) -> None:
        path = "crates/iroha_core/src/block.rs"
        old = "                .find(|envelope| !envelope.spends.is_empty())\n"
        self.assert_fails(run("check_anchors", overrides=replaced(path, old, "                .find(|_| false)\n")),
                          "operations[axt.anchored_spend].carrier.evidence")
        host = "crates/iroha_core/src/smartcontracts/ivm/host.rs"
        errors = run("check_anchors", overrides=replaced(
            host, "standalone FASTPQ proof admission is unavailable until AXT_VERIFY_DS_PROOF binds", "proof admitted when AXT_VERIFY_DS_PROOF binds"))
        self.assert_fails(errors, "operations[axt.ds_proof].refusal")

    def test_a_production_admission_mode_that_verifies_changes_the_census(self) -> None:
        host = "crates/iroha_core/src/smartcontracts/ivm/host.rs"
        mutated = source(host) + ("\nfn admit_anchored(e: &E, s: Option<u64>) -> bool {"
                                  " fastpq_prover::verify_axt_proof_envelope_with_outer_metadata(e, s).is_ok() }\n")
        self.assert_fails(run("check_admission_routes", overrides={host: mutated}),
                          f"`axt_fastpq` in {host} occurs 2 times, recorded 1")


class RouteLinks(Base):
    HEADER = Routes.HEADER

    def test_handlers_are_torii_functions(self) -> None:
        for route in INVENTORY["routes"]["list"]:
            self.assertRegex(route["handler"]["symbol"], r"\bfn \w+\(", route["id"])
            self.assertTrue(route["handler"]["path"].startswith("crates/iroha_torii/src/"), route["id"])

        def edit(inventory: dict) -> None:
            routes = {route["id"]: route for route in inventory["routes"]["list"]}
            routes["private_settlement.leg.upload"]["handler"] = routes["private_settlement.leg.upload"]["catalog_row"]
            routes["zk.roots.read"]["handler"] = {"path": "crates/iroha_torii/src/lib.rs", "symbol": "async fn handler_gone("}
        errors = run("check_routes", edited(edit))
        self.assert_fails(errors, "routes[private_settlement.leg.upload]: handler must be the Torii handler function")
        self.assert_fails(errors, "routes[zk.roots.read]: handler `async fn handler_gone(` has no body")

    def test_a_route_that_builds_an_instruction_is_linked_to_it(self) -> None:
        self.assertIn("application.soracloud_state_mutate_post", operation(INVENTORY, "soracloud::MutateSoracloudState")["routes"])
        self.assertIn("private_settlement.bundle.submit", operation(INVENTORY, "private_settlement::AbortAtomicPrivateSettlementV1")["routes"])

        def unlink(inventory: dict) -> None:
            operation(inventory, "soracloud::MutateSoracloudState")["routes"] = []
            operation(inventory, "private_settlement::AbortAtomicPrivateSettlementV1")["routes"] = []
            operation(inventory, "kaigi::JoinKaigi")["torii"] = ["crates/iroha_torii/src/lib.rs"]
        errors = run("check_routes", edited(unlink))
        self.assert_fails(errors, "operations[soracloud::MutateSoracloudState]: the handler of route application.soracloud_state_mutate_post names this instruction")
        self.assert_fails(errors, "operations[private_settlement::AbortAtomicPrivateSettlementV1]: the handler of route private_settlement.bundle.submit names this instruction")
        self.assert_fails(errors, "operations[kaigi::JoinKaigi]: Torii files naming the instruction are []")

    def test_an_instruction_torii_starts_to_build_needs_its_route(self) -> None:
        new = "crates/iroha_torii/src/new_privacy_draft.rs"
        overrides = {new: "pub(crate) async fn handle_privacy_draft() -> Box<dyn I> { Box::new(SubmitPrivacyProofV1::draft()) }\n"}
        errors = run("check_routes", overrides=overrides)
        self.assert_fails(errors, f"operations[privacy::SubmitPrivacyProofV1]: Torii files naming the instruction are ['{new}']")
        inventory = copy.deepcopy(INVENTORY)
        operation(inventory, "privacy::SubmitPrivacyProofV1")["torii"] = [new]
        self.assert_fails(run("check_routes", inventory, overrides),
                          f"operations[privacy::SubmitPrivacyProofV1]: Torii names this instruction in {new} and no listed route's handler does")
        operation(inventory, "privacy::SubmitPrivacyProofV1")["routes_note"] = "A draft helper no route calls."
        self.assert_clean([error for error in run("check_routes", inventory, overrides) if "SubmitPrivacyProofV1" in error])

    def test_builders_in_another_file_are_reached_through_handler_calls(self) -> None:
        def edit(inventory: dict) -> None:
            routes = {route["id"]: route for route in inventory["routes"]["list"]}
            routes["contracts.zk_vk_register_post"]["handler_calls"] = [
                {"path": "crates/iroha_torii/src/routing.rs", "symbol": "fn handle_post_vk_update("}]
        self.assert_fails(run("check_routes", edited(edit)),
                          "routes[contracts.zk_vk_register_post]: the handler does not call `handle_post_vk_update`")
        self.assertEqual(C.Checker(INVENTORY, REAL, None).instruction_names()["RegisterVerifyingKey"], "verifying_keys::RegisterVerifyingKey")
        builders = C.Checker(INVENTORY, REAL, None).torii_builders()
        self.assertEqual(builders["verifying_keys::RegisterVerifyingKey"], ["crates/iroha_torii/src/routing.rs"])

    def test_a_route_with_a_family_word_in_a_new_path_family_fails(self) -> None:
        tsv = source(C.ROUTE_TSV)
        extra = "wg.witness.assert\tPOST\t/v1/wg/witness-assertions\tpublic\ttorii_default\tpublic\tmutation\thttp\talways\ttrue\ttrue\ttrue\tfalse\n"
        self.assert_fails(run("check_routes", overrides={C.ROUTE_TSV: tsv + extra}),
                          "routes.tripwire: wg.witness.assert (POST /v1/wg/witness-assertions) of the tracked TSV has a family word")
        plain = "vpn.lease.read\tGET\t/v1/vpn/leases/{id}\tpublic\ttorii_default\tpublic\tread\thttp\talways\ttrue\ttrue\ttrue\tfalse\n"
        self.assert_clean(run("check_routes", overrides={C.ROUTE_TSV: tsv + plain}))

    def test_tripwire_exclusions_are_checked(self) -> None:
        def edit(inventory: dict) -> None:
            tripwire = inventory["routes"]["tripwire"]
            tripwire["out_of_scope_prefixes"].append({"prefix": "/v1/nowhere/"})
            tripwire["exclusions"].append({"id": "no.such.route"})
            tripwire["out_of_scope_prefixes"] = [item for item in tripwire["out_of_scope_prefixes"] if item["prefix"] != "/v1/sccp/"]
        errors = run("check_routes", edited(edit))
        self.assert_fails(errors, "out_of_scope_prefixes[/v1/nowhere/]: reason is required")
        self.assert_fails(errors, "out_of_scope_prefixes[/v1/nowhere/]: no route with a family word is under it")
        self.assert_fails(errors, "exclusions[no.such.route]: reason is required")
        self.assert_fails(errors, "exclusions[no.such.route]: not a row of")
        self.assert_fails(errors, "routes.tripwire: sccp.message.proof")


class Bridges(Base):
    def test_bridge_files_are_recorded_per_operation(self) -> None:
        referenced = [item for item in INVENTORY["operations"] if item.get("native_bridges")]
        self.assertGreaterEqual(len(referenced), 20)
        roots = tuple(INVENTORY["sdk"]["native_bridges"]["roots"])
        self.assertEqual(len(roots), 3)
        for item in referenced:
            for row in item["native_bridges"]:
                self.assertTrue(row["path"].startswith(roots), row["path"])

    def test_a_bridge_that_starts_or_stops_referencing_an_operation_fails(self) -> None:
        small = small_sdk(INVENTORY)
        self.assert_clean(run("check_sdk", small))
        new = "crates/iroha_js_codec/src/new_wg.rs"
        overrides = {new: "pub fn encode() -> &'static str { \"iroha.privacy.submit_proof.v1\" }\n"}
        self.assert_fails(run("check_sdk", small, overrides),
                          f"operations[privacy::SubmitPrivacyProofV1]: native_bridges: now referenced by ['{new}']")
        item = next(item for item in small["operations"] if item.get("native_bridges"))
        path = item["native_bridges"][0]["path"]
        self.assert_fails(run("check_sdk", small, {path: "// emptied\n"}),
                          f"operations[{item['id']}]: native_bridges: now referenced by [], no longer by ['{path}']")

        def no_roots(inventory: dict) -> None:
            inventory["sdk"]["native_bridges"]["roots"] = []
        self.assert_fails(run("check_sdk", edited(no_roots)), "sdk.native_bridges: roots with source files are required")


class SelectionEvidence(Base):
    def test_a_rejection_test_reaches_its_site(self) -> None:
        def binder(inventory: dict) -> None:
            site = next(site for site in inventory["guarantee_selection"]["sites"] if site["id"] == "axt.fee_sponsor_binding")
            site["rejection_tests"] = [{"path": "crates/fastpq_prover/src/axt_binding/tests.rs", "test": "bind_axt_batch_rejects_parameter_mismatch"}]
        errors = run("check_guarantee_selection", edited(binder))
        self.assert_fails(errors, "sites[axt.fee_sponsor_binding]: test bind_axt_batch_rejects_parameter_mismatch does not name `RegisterVerifiedFeeSponsorVaultAllocation`")
        self.assert_fails(errors, "sites[axt.fee_sponsor_binding]: test_evidence is `none`")
        site = next(site for site in INVENTORY["guarantee_selection"]["sites"] if site["id"] == "ivm.code_and_abi_hash")
        self.assertEqual(site["rejection_tests"][0]["test"], "overlay_rejects_ivm_proved_without_complete_execution_relation")
        self.assertIn("overlay_rejects_ivm_proved_without_complete_execution_relation",
                      [test["test"] for test in operation(INVENTORY, "ivm_proof.proved_invocation")["tests"]])

    def test_an_inline_key_in_a_handler_is_a_new_selector(self) -> None:
        path = "crates/iroha_core/src/smartcontracts/isi/kaigi/privacy.rs"
        old = "let configured = state.zk.kaigi_authorization_vk.clone();"
        overrides = replaced(path, old, old + " let inline_vk = proof.inline_verifying_key.clone();")
        self.assert_fails(run("check_guarantee_selection", overrides=overrides), f"`inline_key` occurs 2 times in {path}, recorded 0")

    def test_qualification_site_records_the_binary_chain_and_roster_conditions(self) -> None:
        site = next(site for site in INVENTORY["guarantee_selection"]["sites"] if site["id"] == "exact12.qualification_singleton")
        for word in ("ABI hash", "syscall-list digest", "chain id", "validator roster"):
            self.assertIn(word, site["what"])
        self.assertEqual(len(site["registration_conditions"]), 3)

    def test_constructed_profiles_are_asserted_by_a_default_test(self) -> None:
        profiles = INVENTORY["exact12"]["compiled_profiles"]
        self.assertEqual(profiles["constructed_test"]["test"], "only_governance_released_engines_have_compiled_profiles")
        path = profiles["constructed_test"]["path"]
        overrides = replaced(path, "            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,\n            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,",
                             "            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,")
        self.assert_fails(run("check_exact12", overrides=overrides),
                          "exact12[OrchardHalo2ActionsV1]: compiled_profile.state is `constructed`, but")

        def ignored(inventory: dict) -> None:
            inventory["exact12"]["compiled_profiles"]["constructed_test"]["ignored"] = True
        self.assert_fails(run("check_exact12", edited(ignored)), "constructed_test must cite a test that runs by default")

        def renamed(inventory: dict) -> None:
            protocol(inventory, "PqMaspStarkV1")["verifier"]["symbol"] = "fn verify_pq_masp_other_v1("
        self.assert_fails(run("check_exact12", edited(renamed)), "does not call the recorded verifier `verify_pq_masp_other_v1`")
        self.assertEqual(C.Checker(INVENTORY, REAL, None).dispatch_entries(),
                         ["verify_privacy_envelope_after_compiled_activation_v1", "verify_privacy_envelope_v1"])

    def test_a_relation_core_is_reached_from_its_verifier(self) -> None:
        def cut(inventory: dict) -> None:
            relation = next(item for item in inventory["relations"] if item["id"] == "native_pipa_r.kaigi_usage")
            relation["core"]["via"] = relation["core"]["via"][1:]
        self.assert_fails(run("check_products", edited(cut)),
                          "relations[native_pipa_r.kaigi_usage]: core: `verify_usage_commitment` does not name `verify_backend_with_timing_guardrails`")

        def no_words(inventory: dict) -> None:
            relation = next(item for item in inventory["relations"] if item["id"] == "native_pipa_r.kaigi_usage")
            del relation["test_words"]
        self.assert_fails(run("check_products", edited(no_words)), "core needs a function symbol, a verifier with a body and test_words")

    def test_digest_tokens_cover_the_primitives_of_the_finding(self) -> None:
        tokens = {token["id"]: token["pattern"] for token in INVENTORY["digests"]["primitive_tokens"]}
        import re as regex
        for identifier, sample in (("sha2_384", "Sha384::new()"), ("blake2s", "Blake2s256::digest(x)"),
                                   ("shake128", "Shake128::default()"), ("hkdf", "Hkdf::<Sha3_512>::new(None, k)")):
            self.assertRegex(sample, regex.compile(tokens[identifier]), identifier)
        race = next(group for group in INVENTORY["digests"]["products"] if group["product"] == "race")
        self.assertGreater(race["census"].get("sha2_384", 0), 0)
        outer = "crates/iroha_core_privacy/src/privacy_engines/privacy_outer_hash.rs"
        for product in ("zk_x509", "ivm_private_note", "pq_masp", "atomic_settlement"):
            group = next(group for group in INVENTORY["digests"]["products"] if group["product"] == product)
            self.assertIn(outer, group["owner_paths"])
            self.assertGreater(group["census"].get("sha3_384", 0), 0, product)
        self.assertRegex("core: Sha3_384Core,", regex.compile(tokens["sha3_384"]))


class Maintenance(Base):
    def test_dump_reproduces_the_tracked_file(self) -> None:
        self.assertEqual(C.dump(C.load()), source(C.INVENTORY))

    def test_dump_inlines_small_leaves_only(self) -> None:
        self.assertEqual(C._inline({"a": 1, "b": ["x", "y"]}), '{"a": 1, "b": ["x", "y"]}')
        self.assertEqual(C._inline(["a", 2, None]), '["a", 2, null]')
        self.assertIsNone(C._inline({"a": {"b": 1}}))
        self.assertIsNone(C._inline([{"a": 1}]))
        self.assertIsNone(C._inline({"a": "x" * 200}))
        self.assertEqual(C._inline("é"), '"é"')
        text = C.dump({"k": {"nested": {"deep": [1, 2]}}, "long": ["y" * 80, "z" * 80], "empty": [], "n": None})
        self.assertEqual(text, ('{\n "k": {\n  "nested": {"deep": [1, 2]}\n },\n "long": [\n  "' + "y" * 80 + '",\n  "' + "z" * 80
                                + '"\n ],\n "empty": [],\n "n": null\n}\n'))
        import json
        self.assertEqual(json.loads(text), {"k": {"nested": {"deep": [1, 2]}}, "long": ["y" * 80, "z" * 80], "empty": [], "n": None})
        out: list[str] = []
        C._dump([], 0, out)
        self.assertEqual(out, ["[]"])

    def test_write_inventory_writes_the_stable_text(self) -> None:
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "specs").mkdir()
            C.write_inventory({"schema": "x", "list": [1, 2]}, root)
            self.assertEqual((root / C.INVENTORY).read_text(encoding="utf-8"), '{"schema": "x", "list": [1, 2]}\n')
            self.assertEqual(C.load(root), {"schema": "x", "list": [1, 2]})

    def call_main(self, argv: list[str], errors: list[str], plan_code: int | None = None, load=None):
        from unittest import mock
        import subprocess
        out, err = io.StringIO(), io.StringIO()
        written: list[dict] = []
        patches = [
            mock.patch.object(C.Checker, "check", lambda self: list(errors)),
            mock.patch.object(C.Checker, "refresh", lambda self: ["operations[x].sdk"]),
            mock.patch.object(C, "write_inventory", lambda inventory: written.append(inventory)),
        ]
        if plan_code is not None:
            patches.append(mock.patch.object(
                C.subprocess, "run",
                lambda *args, **kwargs: subprocess.CompletedProcess(args, plan_code, stdout="first line\nplan says no\n")))
        if load is not None:
            patches.append(mock.patch.object(C, "load", load))
        for patch in patches:
            patch.start()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = C.main(argv)
        finally:
            for patch in patches:
                patch.stop()
        return code, out.getvalue(), err.getvalue(), written

    def test_main_exit_codes(self) -> None:
        code, out, err, written = self.call_main(["--no-compile"], [])
        self.assertEqual((code, written), (0, []))
        self.assertIn("93 operations (81 registered instructions)", out)
        code, out, err, _ = self.call_main(["--no-compile"], ["operations[x]: wrong", "routes[y]: wrong"])
        self.assertEqual(code, 1)
        self.assertIn("operations[x]: wrong", err)
        self.assertIn("zk_operation_inventory: 2 inconsistencies", err)
        self.assertEqual(out, "")

        def unreadable():
            raise OSError("no such file")
        code, out, err, _ = self.call_main(["--no-compile"], [], load=unreadable)
        self.assertEqual(code, 2)
        self.assertIn("cannot read specs/zk_operation_inventory.json", err)

    def test_main_with_plan_check_reports_the_plan_checker(self) -> None:
        code, out, err, _ = self.call_main(["--no-compile", "--with-plan-check"], [], plan_code=0)
        self.assertEqual(code, 0)
        code, out, err, _ = self.call_main(["--no-compile", "--with-plan-check"], [], plan_code=1)
        self.assertEqual(code, 1)
        self.assertIn("scripts/check_zk_delivery_plan.py failed: plan says no", err)

    def test_main_refresh_writes_once_and_propose_writes_nothing(self) -> None:
        code, out, err, written = self.call_main(["--no-compile", "--refresh"], [])
        self.assertEqual(code, 0)
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0]["schema"], C.SCHEMA)
        self.assertIn("refreshed operations[x].sdk", out)
        self.assertIn("refreshed 1 recorded facts", out)
        code, out, err, written = self.call_main(["--no-compile", "--propose"], ["ignored"])
        self.assertEqual((code, written), (0, []))
        self.assertIn("nothing to propose", out)

    def test_refresh_fills_the_new_mechanical_parts(self) -> None:
        inventory = copy.deepcopy(INVENTORY)
        operation(inventory, "kaigi::JoinKaigi")["native_bridges"] = []
        operation(inventory, "soracloud::MutateSoracloudState")["torii"] = []
        rows = inventory["admission_routes"]["entry_point_census"]["occurrences"]
        rows[0]["count"] += 1
        removed = rows.pop()
        changes = C.Checker(inventory, C.Tree(), None).refresh()
        self.assertIn("operations[kaigi::JoinKaigi].native_bridges", changes)
        self.assertIn("operations[soracloud::MutateSoracloudState].torii", changes)
        self.assertIn("admission_routes.entry_point_census.occurrences", changes)
        restored = inventory["admission_routes"]["entry_point_census"]["occurrences"][-1]
        self.assertIsNone(restored["route"], "a row the inventory did not class comes back unclassed")
        restored["route"] = removed["route"]
        for key in ("note", "excluded"):
            if key in removed:
                restored[key] = removed[key]
        self.assertEqual(inventory, INVENTORY)


ROLE_MODEL = "crates/iroha_data_model/src/privacy/action_role.rs"
DISPATCH_REGISTRY = "crates/iroha_core_privacy/src/privacy_dispatch.rs"
ACTION_DRIVER = "crates/iroha_core/src/bin/privacy_exact12_action_driver.rs"
PRIVACY_INSTRUCTIONS = "crates/iroha_data_model/src/isi/privacy.rs"
CORE_PRIVACY = "crates/iroha_core/src/privacy.rs"
PROOFS_MODEL = "crates/iroha_data_model/src/privacy/proofs.rs"
ENVELOPE_LITERAL = (
    "PrivacyProofEnvelopeV1 { wire_magic: Default::default(), catalog_commitment: Default::default(), "
    "protocol_id, proof_system_id, engine_id, parameter_id, parameter_digest, verifier_digest, "
    "statement_schema_digest, engine_manifest_digest, statement_digest, statement, proof }"
)


def role(inventory: dict, name: str) -> dict:
    return next(item for item in inventory["exact12"]["roles"]["list"] if item["role"] == name)


def appended(path: str, code: str) -> dict:
    """`path` with production `code` appended at the end of the file."""
    return {path: source(path) + "\n" + code + "\n"}


class Exact12Roles(Base):
    """The thirteen typed roles and the typed dispatch registry."""

    def test_tracked_roles_match_the_source(self) -> None:
        self.assert_clean(run("check_action_roles"))
        rows = INVENTORY["exact12"]["roles"]["list"]
        self.assertEqual(len(rows), 13)
        self.assertEqual(sum(1 for row in rows if row["protocol"] == "IrohaZkAmsV1"), 2)

    def test_the_four_facts_of_every_role_are_distinct_and_no_role_is_delivered(self) -> None:
        rows = INVENTORY["exact12"]["roles"]["list"]
        refused = [row["role"] for row in rows if row["verification"] == "refused"]
        self.assertEqual(refused, ["ZkAceAuthorization", "ZkAmsBatchAdmission", "ZkAmsProvisionAccount",
                                   "VegaCredentialPresentation", "ZkX509CertificatePresentation"])
        for row in rows:
            self.assertEqual(row["delivery"], "not_delivered", row["role"])
            self.assertTrue(row["missing"], row["role"])
            self.assertEqual(row["verification"] == "refused", "limitation" in row, row["role"])
            self.assertEqual(row["state_effects"] == "unreachable", row["verification"] == "refused", row["role"])
        self.assertEqual({row["state_effects"] for row in rows}, {"gated", "none", "unreachable"})
        verify_only = [row["role"] for row in rows if row["effect_class"] == "VerifyOnly"]
        self.assertEqual(verify_only, ["VeRangeRange", "VegaCredentialPresentation", "JindoBatchedEvaluation",
                                       "BootleLanternPresentation"])

    def test_fourteenth_role_and_reordered_roles_fail(self) -> None:
        overrides = replaced(ROLE_MODEL, "    /// PQ-MASP transition.\n    PqMaspTransition,\n}",
                             "    /// PQ-MASP transition.\n    PqMaspTransition,\n    /// New.\n    NewRole,\n}")
        self.assert_fails(run("check_action_roles", overrides=overrides), "PrivacyActionRoleV1 has variants")
        overrides = replaced(ROLE_MODEL, "        Self::ZkAceAuthorization,\n        Self::AnonymousPgcPayment,",
                             "        Self::AnonymousPgcPayment,\n        Self::ZkAceAuthorization,")
        self.assert_fails(run("check_action_roles", overrides=overrides), "the ALL list of the role enum differs")

    def test_changed_protocol_of_a_role_fails(self) -> None:
        overrides = replaced(ROLE_MODEL, "Self::VeRangeRange => PrivacyProtocolIdV1::VeRangeTransparentRangeV1,",
                             "Self::VeRangeRange => PrivacyProtocolIdV1::PqMaspStarkV1,")
        self.assert_fails(run("check_action_roles", overrides=overrides),
                          "exact12.roles[VeRangeRange]: protocol_id gives `PrivacyProtocolIdV1::PqMaspStarkV1`")

    def test_typed_registry_and_recorded_rows_are_compared_field_by_field(self) -> None:
        text = source(DISPATCH_REGISTRY)
        row = ("    row(\n        PrivacyActionRoleV1::ZkAceAuthorization,\n"
               "        unsupported(PrivacyRoleLimitationV1::ZkAceSoundnessDerivationIncomplete),\n"
               "        PrivacyRoleEffectClassV1::ZkAceAuthorization,\n    ),\n")
        self.assertIn(row, text)
        claimed = row.replace("unsupported(PrivacyRoleLimitationV1::ZkAceSoundnessDerivationIncomplete)", "IMPLEMENTED")
        errors = run("check_action_roles", overrides={DISPATCH_REGISTRY: text.replace(row, claimed)})
        self.assert_fails(errors, "exact12.roles[ZkAceAuthorization]: the typed registry gives verification `implemented`")
        self.assert_fails(errors, "exact12.roles[ZkAceAuthorization]: the typed registry gives limitation `None`")
        other_class = row.replace("PrivacyRoleEffectClassV1::ZkAceAuthorization", "PrivacyRoleEffectClassV1::VerifyOnly")
        self.assert_fails(run("check_action_roles", overrides={DISPATCH_REGISTRY: text.replace(row, other_class)}),
                          "exact12.roles[ZkAceAuthorization]: the typed registry gives effect_class `VerifyOnly`")
        self.assert_fails(run("check_action_roles", overrides={DISPATCH_REGISTRY: text.replace(row, "")}),
                          "exact12.roles.registry: PRIVACY_ROLE_DISPATCH_TABLE_V1 lists")

        def edit(inventory: dict) -> None:
            role(inventory, "OrchardActions")["verification"] = "refused"
            role(inventory, "VegaCredentialPresentation")["limitation"] = "NotALimitation"
            role(inventory, "FcmpTransfer")["effect_class"] = "NotAClass"
        errors = run("check_action_roles", edited(edit))
        self.assert_fails(errors, "exact12.roles[OrchardActions]: a refused role records its limitation")
        self.assert_fails(errors, "exact12.roles[OrchardActions]: the typed registry gives verification `implemented`")
        self.assert_fails(errors, "exact12.roles[VegaCredentialPresentation]: limitation `NotALimitation` is not a variant")
        self.assert_fails(errors, "exact12.roles[FcmpTransfer]: effect_class `NotAClass` is not a variant")

    def test_state_effects_follow_verification_effect_class_and_the_admission_gate(self) -> None:
        def edit(inventory: dict) -> None:
            role(inventory, "VeRangeRange")["state_effects"] = "gated"
            role(inventory, "OrchardActions")["state_effects"] = "implemented"
            role(inventory, "ZkAceAuthorization")["state_effects"] = "gated"
            role(inventory, "JindoBatchedEvaluation")["ledger_effect"] = "OrchardActions"
        errors = run("check_action_roles", edited(edit))
        self.assert_fails(errors, "exact12.roles[VeRangeRange]: state_effects must be `none`")
        self.assert_fails(errors, "exact12.roles[OrchardActions]: state_effects must be `gated`")
        self.assert_fails(errors, "exact12.roles[ZkAceAuthorization]: state_effects must be `unreachable`")
        self.assert_fails(errors, "exact12.roles[JindoBatchedEvaluation]: effect class `VerifyOnly` hands over ledger effect `None`")

        # When the handler stops calling the admission gate (P.5), applied roles are `implemented`.
        text = source(PRIVACY_HANDLERS)
        call = "let activation = *resolve_qualified_privacy_activation_v1("
        self.assertIn(call, text)
        ungated = {PRIVACY_HANDLERS: text.replace(call, "let activation = *resolve_registered_activation(")}
        errors = run("check_action_roles", overrides=ungated)
        self.assert_fails(errors, "the handler no longer calls the admission gate; remove `gate_site`")
        self.assert_fails(errors, "exact12.roles[OrchardActions]: state_effects must be `implemented`")
        self.assertFalse(any("VeRangeRange" in error for error in errors), errors)

        def without_gate(inventory: dict) -> None:
            del inventory["exact12"]["roles"]["gate_site"]
        self.assert_fails(run("check_action_roles", edited(without_gate)),
                          "the handler calls the admission gate; record it as `gate_site`")

    def test_delivery_needs_the_typed_registry_and_implemented_owner_tasks(self) -> None:
        def edit(inventory: dict) -> None:
            role(inventory, "JindoBatchedEvaluation")["delivery"] = "delivered"
            role(inventory, "PqMaspTransition")["delivery"] = "shipped"
            del role(inventory, "FcmpTransfer")["missing"]
        errors = run("check_action_roles", edited(edit))
        self.assert_fails(errors, "exact12.roles[JindoBatchedEvaluation]: delivery is `delivered` while P.12")
        self.assert_fails(errors, "exact12.roles: the typed registry constructs `Delivered` 0 time(s), 1 role(s) recorded")
        self.assert_fails(errors, "exact12.roles[PqMaspTransition]: delivery must be one of")
        self.assert_fails(errors, "exact12.roles[FcmpTransfer]: missing must say what the delivery lacks")
        overrides = replaced(DISPATCH_REGISTRY, "        delivery: PrivacyRoleDeliveryV1::NotDelivered,\n    }\n}",
                             "        delivery: PrivacyRoleDeliveryV1::Delivered,\n    }\n}")
        self.assert_fails(run("check_action_roles", overrides=overrides),
                          "exact12.roles: the typed registry constructs `Delivered` 1 time(s), 0 role(s) recorded")

    def test_roles_agree_with_their_protocol_rows_and_the_dispatch(self) -> None:
        def edit(inventory: dict) -> None:
            protocol(inventory, "VegaExistingCredentialZkV1")["status"]["verification"] = "implemented"
            protocol(inventory, "IrohaZkAmsV1")["ledger_effect"] = ["ZkAmsBatchAdmission"]
            role(inventory, "OrchardActions")["native_verifiers"] = [
                {"name": "verify_orchard_shortcut_v1", "engine_scope": "crates/iroha_core_privacy/src/privacy_engines/orchard.rs"}
            ]
            role(inventory, "PqMaspTransition")["protocol"] = "MoneroFcmpPlusPlusV1"
            inventory["exact12"]["roles"]["count"] = 12
            inventory["exact12"]["roles"]["registry"]["json_view_test"]["ignored"] = True
        errors = run("check_action_roles", edited(edit))
        self.assert_fails(errors, "exact12.roles: protocol VegaExistingCredentialZkV1 is recorded `implemented`")
        self.assert_fails(errors, "exact12.roles: protocol IrohaZkAmsV1 records ledger effects ['ZkAmsBatchAdmission']")
        self.assert_fails(errors, "exact12.roles[OrchardActions]: the dispatch `verify_privacy_envelope_after_compiled_activation_v1` "
                                  "does not reach native verifier `verify_orchard_shortcut_v1`")
        self.assert_fails(errors, "exact12.roles[PqMaspTransition]: protocol_id gives")
        self.assert_fails(errors, "exact12.roles: protocol PqMaspStarkV1 has no role")
        self.assert_fails(errors, "exact12.roles: count is 12, 13 roles listed")
        self.assert_fails(errors, "exact12.roles.registry.json_view_test: must cite a test that runs by default")

    def test_missing_sections_fail(self) -> None:
        def edit(inventory: dict) -> None:
            del inventory["exact12"]["roles"]
            del inventory["exact12"]["single_route"]
        inventory = edited(edit)
        self.assert_fails(run("check_action_roles", inventory), "exact12: `roles` is required")
        self.assert_fails(run("check_exact12_single_route", inventory), "exact12: `single_route` is required")


class Exact12SingleRoute(Base):
    """A second authoritative route for an Exact12 role fails the check."""

    METHOD = "check_exact12_single_route"

    def test_tracked_single_route_matches_the_source(self) -> None:
        self.assert_clean(run(self.METHOD))

    def test_second_envelope_assembler_fails_in_any_production_file(self) -> None:
        function = f"fn hand_assembled() -> PrivacyProofEnvelopeV1 {{\n    {ENVELOPE_LITERAL}\n}}"
        for path in ("crates/zk_ace_prover/src/lib.rs", "crates/iroha_core_privacy/src/privacy_engines/jindo.rs",
                     "python/iroha_python/iroha_python_rs/src/privacy_native_actions.rs", ACTION_DRIVER):
            errors = run(self.METHOD, overrides=appended(path, function))
            self.assert_fails(errors, f"exact12.single_route: {path}: `hand_assembled` assembles PrivacyProofEnvelopeV1 "
                                      "outside `bind_v1`")
        qualified = "fn qualified() { let _ = iroha_data_model::privacy::" + ENVELOPE_LITERAL + "; }"
        self.assert_fails(run(self.METHOD, overrides=appended(CORE_PRIVACY, qualified)),
                          f"{CORE_PRIVACY}: `qualified` assembles PrivacyProofEnvelopeV1 outside `bind_v1`")

    def test_test_gated_assemblies_and_signatures_are_not_assemblies(self) -> None:
        gated = (
            "#[cfg(test)]\nmod hand_assembled_tests {\n    fn fixture() -> PrivacyProofEnvelopeV1 {\n        "
            + ENVELOPE_LITERAL + "\n    }\n}\n"
            '#[cfg(any(test, feature = "test-utils"))]\nfn fixture_for_tests() -> PrivacyProofEnvelopeV1 {\n    '
            + ENVELOPE_LITERAL + "\n}\n"
            "fn passes_through(envelope: PrivacyProofEnvelopeV1) -> PrivacyProofEnvelopeV1 {\n    envelope\n}\n"
            "// PrivacyProofEnvelopeV1 { .. } in a comment\n"
            'const NAME: &str = "PrivacyProofEnvelopeV1 { .. }";\n'
        )
        self.assert_clean(run(self.METHOD, overrides=appended(CORE_PRIVACY, gated)))
        # A builder compiled into the release-evidence feature is production code of that build.
        feature_gated = ('#[cfg(any(test, feature = "privacy-release-evidence"))]\nfn evidence_builder() -> PrivacyProofEnvelopeV1 {\n    '
                         + ENVELOPE_LITERAL + "\n}\n")
        self.assert_fails(run(self.METHOD, overrides=appended(CORE_PRIVACY, feature_gated)),
                          "`evidence_builder` assembles PrivacyProofEnvelopeV1 outside `bind_v1`")

    def test_second_self_literal_and_missing_assembler_fail(self) -> None:
        second = ("impl PrivacyProofEnvelopeV1 {\n    /// Second assembler.\n    pub fn rebuilt(self) -> Self {\n"
                  "        Self { statement_digest: self.statement_digest, ..self }\n    }\n}")
        self.assert_fails(run(self.METHOD, overrides=appended(ROLE_MODEL, second)),
                          f"{ROLE_MODEL}: `rebuilt` assembles PrivacyProofEnvelopeV1 outside `bind_v1`")
        text = source(ROLE_MODEL)
        self.assertIn("        let envelope = Self {\n", text)
        moved = text.replace("        let envelope = Self {\n", "        let envelope = build_envelope! {\n", 1)
        self.assert_fails(run(self.METHOD, overrides={ROLE_MODEL: moved}),
                          "`bind_v1` of crates/iroha_data_model/src/privacy/action_role.rs must assemble "
                          "PrivacyProofEnvelopeV1 exactly once, found 0")

    def test_unrecorded_identity_assignment_fails_and_recorded_sites_are_exact(self) -> None:
        assignment = "fn relabel(envelope: &mut PrivacyProofEnvelopeV1) {\n    envelope.protocol_id = other();\n}"
        self.assert_fails(run(self.METHOD, overrides=appended(CORE_PRIVACY, assignment)),
                          f"{CORE_PRIVACY} assigns an envelope identity field 1 time(s), recorded 0")
        comparison = "fn same(envelope: &PrivacyProofEnvelopeV1) -> bool {\n    envelope.protocol_id == other()\n}"
        self.assert_clean(run(self.METHOD, overrides=appended(CORE_PRIVACY, comparison)))

        def edit(inventory: dict) -> None:
            sites = inventory["exact12"]["single_route"]["envelope"]["field_assignments"]
            sites[0]["count"] += 1
            del sites[1]["why"]
        errors = run(self.METHOD, edited(edit))
        self.assert_fails(errors, "crates/iroha_data_model/src/transaction/signed.rs assigns an envelope identity field 1 time(s), recorded 2")
        self.assert_fails(errors, "field_assignments[crates/iroha_core/src/privacy_release_evidence/zk_x509.rs] needs `why`")

    def test_second_instruction_that_carries_an_envelope_statement_or_proof_fails(self) -> None:
        for field in ("envelope: PrivacyProofEnvelopeV1", "proofs: Vec<crate::privacy::PrivacyProofV1>",
                      "statement: Option<PrivacyStatementV1>"):
            name = field.split(":")[0]
            struct = f"/// Second carrier.\npub struct SubmitSecondPrivacyProofV1 {{\n    /// Payload.\n    pub {field},\n}}"
            self.assert_fails(run(self.METHOD, overrides=appended(PRIVACY_INSTRUCTIONS, struct)),
                              f"{PRIVACY_INSTRUCTIONS}: `SubmitSecondPrivacyProofV1.{name}` carries an Exact12 envelope")
        other = "/// Unrelated.\npub struct RegisterSomethingV1 {\n    /// Payload.\n    pub activation: PrivacyProtocolActivationRecordV1,\n}"
        self.assert_clean(run(self.METHOD, overrides=appended(PRIVACY_INSTRUCTIONS, other)))
        overrides = replaced(PRIVACY_INSTRUCTIONS, "pub envelope: PrivacyProofEnvelopeV1,", "pub envelope: PrivacyEnvelopeBytesV1,")
        self.assert_fails(run(self.METHOD, overrides=overrides),
                          "SubmitPrivacyProofV1.envelope of crates/iroha_data_model/src/isi/privacy.rs does not carry")

    def test_second_handler_stage_or_dispatch_call_fails(self) -> None:
        cases = {
            "PreparedPrivacySubmissionV1::prepare": "fn second_entry() { let _ = PreparedPrivacySubmissionV1::prepare(a, b); }",
            "execute_after_admission": "fn second_entry(s: PreparedPrivacySubmissionV1) { let _ = s.execute_after_admission(a, b, c); }",
            "action_role_v1": "fn second_route(e: &PrivacyProofEnvelopeV1) { let _ = e.action_role_v1(); }",
            "verify_privacy_envelope_v1": "fn second_route() { let _ = verify_privacy_envelope_v1(a, b); }",
            "into_ledger": "fn second_executor(e: VerifiedPrivacyEffectsV1) { let _ = e.into_ledger(); }",
        }
        for call, code in cases.items():
            errors = run(self.METHOD, overrides=appended(PRIVACY_HANDLERS, code))
            self.assert_fails(errors, f"exact12.single_route: `{call}` is called 2 time(s) in production code of "
                                      f"{PRIVACY_HANDLERS}; the single path calls it once")
        text = source(PRIVACY_HANDLERS)
        call = "        let effects = verify_privacy_envelope_v1(\n"
        self.assertIn(call, text)
        self.assert_fails(run(self.METHOD, overrides={PRIVACY_HANDLERS: text.replace(call, "        let effects = verify_elsewhere_v1(\n")}),
                          "`verify_privacy_envelope_v1` is called 0 time(s)")
        moved = text.replace("        let role = self.envelope.action_role_v1().map_err(|error| {",
                             "        let role = resolve(&self.envelope).map_err(|error| {")
        moved += "\nfn resolve(e: &PrivacyProofEnvelopeV1) -> Result<PrivacyActionRoleV1, ()> { e.action_role_v1().map_err(|_| ()) }\n"
        self.assert_fails(run(self.METHOD, overrides={PRIVACY_HANDLERS: moved}),
                          "`action_role_v1` is no longer called inside `execute_after_admission`")

    def test_native_verifier_called_outside_its_engine_and_the_dispatch_fails(self) -> None:
        shortcut = "fn shortcut() { let _ = crate::privacy_engines::orchard::verify_orchard_bundle_v1(a, b, c); }"
        for path in (CORE_PRIVACY, PRIVACY_HANDLERS, ACTION_DRIVER, "crates/iroha_torii/src/lib.rs"):
            self.assert_fails(run(self.METHOD, overrides=appended(path, shortcut)),
                              f"exact12.single_route: role OrchardActions: native verifier `verify_orchard_bundle_v1` is called in {path}")
        # Inside the engine and in the recorded tooling the same call is not a route.
        self.assert_clean(run(self.METHOD, overrides=appended("crates/iroha_core_privacy/src/privacy_engines/orchard.rs", shortcut)))
        self.assert_clean(run(self.METHOD, overrides=appended("crates/iroha_core/src/privacy_release_evidence.rs", shortcut)))
        text = source(VERIFIER)
        self.assertIn("verify_orchard_bundle_v1(", text)
        without = text.replace("verify_orchard_bundle_v1(", "verify_orchard_bundle_elsewhere_v1(")
        self.assert_fails(run(self.METHOD, overrides={VERIFIER: without}),
                          f"role OrchardActions: {VERIFIER} no longer calls native verifier `verify_orchard_bundle_v1`")

        def edit(inventory: dict) -> None:
            role(inventory, "JindoBatchedEvaluation")["native_verifiers"][0]["engine_scope"] = "crates/iroha_core_privacy/src/privacy_engines/absent/"
            inventory["exact12"]["single_route"]["native_verifiers"]["non_admission_callers"].append(
                {"path": CORE_PRIVACY, "note": "stale"})
        errors = run(self.METHOD, edited(edit))
        self.assert_fails(errors, "role JindoBatchedEvaluation: engine_scope `crates/iroha_core_privacy/src/privacy_engines/absent/` holds no scanned file")
        self.assert_fails(errors, f"non_admission_callers[{CORE_PRIVACY}] calls no recorded native verifier")

    def test_pgc_bootstrap_proof_has_one_admission_caller(self) -> None:
        shortcut = "fn bootstrap_shortcut() { let _ = verify_bootstrap_encoded(a, b, c); }"
        self.assert_fails(run(self.METHOD, overrides=appended(CORE_PRIVACY, shortcut)),
                          "administrative operation privacy::BootstrapPrivacyPgcAccountsV1: native verifier "
                          f"`verify_bootstrap_encoded` is called in {CORE_PRIVACY}")
        text = source(PRIVACY_HANDLERS)
        self.assertEqual(text.count("verify_bootstrap_encoded("), 1)
        errors = run(self.METHOD, overrides={PRIVACY_HANDLERS: text.replace("verify_bootstrap_encoded(", "verify_bootstrap_elsewhere(")})
        self.assert_fails(errors, f"{PRIVACY_HANDLERS} no longer calls native verifier `verify_bootstrap_encoded`")
        self.assert_fails(errors, "its executor does not call `verify_bootstrap_encoded`")

        def edit(inventory: dict) -> None:
            inventory["exact12"]["single_route"]["administrative_proof_operations"][0]["id"] = "privacy::NotListedV1"
        self.assert_fails(run(self.METHOD, edited(edit)), "administrative operation privacy::NotListedV1: not a listed operation")

    def test_second_native_verifier_call_in_the_dispatch_file_fails(self) -> None:
        shortcut = "fn shortcut() { let _ = crate::privacy_engines::orchard::verify_orchard_bundle_v1(a, b, c); }"
        self.assert_fails(run(self.METHOD, overrides=appended(VERIFIER, shortcut)),
                          f"role OrchardActions: {VERIFIER} calls native verifier `verify_orchard_bundle_v1` "
                          "2 time(s); its one admission caller must call it exactly once")

    def test_second_pgc_bootstrap_call_in_the_handler_file_fails(self) -> None:
        shortcut = "fn bootstrap_shortcut() { let _ = verify_bootstrap_encoded(a, b, c); }"
        self.assert_fails(run(self.METHOD, overrides=appended(PRIVACY_HANDLERS, shortcut)),
                          f"administrative operation privacy::BootstrapPrivacyPgcAccountsV1: {PRIVACY_HANDLERS} "
                          "calls native verifier `verify_bootstrap_encoded` 2 time(s); "
                          "its one admission caller must call it exactly once")

    def test_second_effect_consumer_matcher_or_executor_arm_fails(self) -> None:
        consumer = "fn apply_elsewhere(e: VerifiedPrivacyEffectsV1) { let _ = e.into_ledger(); }"
        self.assert_fails(run(self.METHOD, overrides=appended(CORE_PRIVACY, consumer)),
                          f"{CORE_PRIVACY} consumes a verified effect (`into_ledger`) 1 time(s), recorded 0")
        matcher = "fn classify(l: &VerifiedPrivacyLedgerEffectsV1) -> bool { matches!(l, VerifiedPrivacyLedgerEffectsV1::None) }"
        self.assert_fails(run(self.METHOD, overrides=appended(CORE_PRIVACY, matcher)),
                          f"{CORE_PRIVACY} names a variant of the verified ledger effect and is not a recorded matcher")
        text = source(PRIVACY_HANDLERS)
        arm = "            VerifiedPrivacyLedgerEffectsV1::OrchardActions(effect) => {\n"
        self.assertEqual(text.count(arm), 1)
        doubled = text.replace(arm, "            VerifiedPrivacyLedgerEffectsV1::OrchardActions(effect) if false => {}\n" + arm.replace("=> {", "=> {"))
        doubled = doubled.replace("VerifiedPrivacyLedgerEffectsV1::OrchardActions(effect) if false => {}",
                                  "VerifiedPrivacyLedgerEffectsV1::OrchardActions(_) => {}")
        self.assert_fails(run(self.METHOD, overrides={PRIVACY_HANDLERS: doubled}),
                          "the handler has 2 executor arm(s) for effect `OrchardActions`")

        def edit(inventory: dict) -> None:
            effects = inventory["exact12"]["single_route"]["effects"]
            effects["ledger_consumers"][1]["use"] = "ledger_application"
            effects["matchers"].append({"path": CORE_PRIVACY, "use": "elsewhere"})
        errors = run(self.METHOD, edited(edit))
        self.assert_fails(errors, "exactly the handler applies a verified effect")
        self.assert_fails(errors, f"{CORE_PRIVACY} is a recorded matcher and names no variant")
        self.assert_fails(errors, f"matchers[{CORE_PRIVACY}].use must be one of")

    def test_action_driver_is_an_entry_with_typed_roles_and_no_verifier(self) -> None:
        text = source(ACTION_DRIVER)
        spec = "        operation: JINDO_OPERATION,\n        role: PrivacyActionRoleV1::JindoBatchedEvaluation,\n"
        self.assertIn(spec, text)
        other_role = text.replace(spec, "        operation: JINDO_OPERATION,\n        role: PrivacyActionRoleV1::VeRangeRange,\n")
        self.assert_fails(run(self.METHOD, overrides={ACTION_DRIVER: other_role}),
                          "exact12.single_route: OPERATION_SPECS_V1 of crates/iroha_core/src/bin/privacy_exact12_action_driver.rs is")
        for call in ("require_supported_privacy_action_role_v1", "require_canonical_role_submission_v1"):
            removed = text.replace(call + "(", call + "_removed(")
            self.assert_fails(run(self.METHOD, overrides={ACTION_DRIVER: removed}),
                              f"the action driver no longer calls `{call}`")
        own_verifier = "fn verify_here() { let _ = iroha_core_privacy::privacy_verifier::verify_privacy_envelope_v1(a, b); }"
        self.assert_fails(run(self.METHOD, overrides=appended(ACTION_DRIVER, own_verifier)),
                          "the action driver names `verify_privacy_envelope_v1`; it owns no verifier and no effect")

        def edit(inventory: dict) -> None:
            route = inventory["exact12"]["single_route"]
            route["driver_operations"][1]["role"] = "ZkAceAuthorization"
            role(inventory, "OrchardActions")["driver_operation"] = None
        errors = run(self.METHOD, edited(edit))
        self.assert_fails(errors, "driver operations build-zk-ace-action-v1 and build-anonymous-pgc-action-v1 name one role")
        self.assert_fails(errors, "role OrchardActions records driver operation `None`, the driver table gives `build-orchard-action-v1`")

        def unknown(inventory: dict) -> None:
            inventory["exact12"]["single_route"]["driver_operations"][0]["role"] = "NotARole"
        self.assert_fails(run(self.METHOD, edited(unknown)), "driver operation build-zk-ace-action-v1 names `NotARole`")

    def test_entries_record_their_tests_and_the_refusals_of_the_routes_that_are_not_entries(self) -> None:
        def edit(inventory: dict) -> None:
            entries = inventory["exact12"]["single_route"]["entries"]
            del entries[2]["refusals"]
            entries[0]["tests"] = []
            entries[1]["applicable"] = "yes"
            del entries[3]
        errors = run(self.METHOD, edited(edit))
        self.assert_fails(errors, "entries[generic_verification] is not an entry of the path and must record its refusals")
        self.assert_fails(errors, "entries[direct_instruction] needs tests")
        self.assert_fails(errors, "entries[action_driver].applicable must be true or false")
        self.assert_fails(errors, "entries must record `contract_or_proved_executable`")

    def test_retired_duplicates_stay_retired(self) -> None:
        old_branch = ('fn old_branch() -> Error {\n    invalid_privacy_parameter("Orchard protocol envelope carries a different '
                      'statement type")\n}')
        self.assert_fails(run(self.METHOD, overrides=appended(PRIVACY_HANDLERS, old_branch)),
                          "retired[handler_protocol_routing]: `protocol envelope carries a different statement type` is back")
        old_key = "fn old_key(s: &PreparedPrivacySubmissionV1) -> bool {\n    s.envelope.protocol_id == PrivacyProtocolIdV1::IrohaZkAmsV1\n}"
        text = source(PRIVACY_HANDLERS).replace("s.envelope", "self.envelope")
        self.assert_fails(run(self.METHOD, overrides={PRIVACY_HANDLERS: text + "\n" + old_key.replace("s.envelope", "self.envelope") + "\n"}),
                          "retired[handler_protocol_routing]: `self\\.envelope\\.protocol_id\\s*==` is back")
        matcher = "impl IrohaZkAmsProofV1 {\n    /// Old.\n    pub const fn matches_action(&self) -> bool { true }\n}"
        self.assert_fails(run(self.METHOD, overrides=appended(PROOFS_MODEL, matcher)),
                          "retired[zk_ams_action_proof_matcher]: `fn matches_action` is back")
        variant = "/// Old.\npub struct PrivacyEngineUnavailableFailureV1;"
        self.assert_fails(run(self.METHOD, overrides=appended(VERIFIER, variant)),
                          "retired[feature_conditional_engine_refusal]: `PrivacyEngineUnavailableFailureV1` is back")

        def edit(inventory: dict) -> None:
            del inventory["exact12"]["single_route"]["retired"][0]["equivalence"]
        self.assert_fails(run(self.METHOD, edited(edit)), "retired[builder_envelope_assemblies]: `equivalence` is required")

    def test_instruction_must_be_a_listed_operation(self) -> None:
        def edit(inventory: dict) -> None:
            inventory["exact12"]["single_route"]["instruction"]["type"] = "privacy::SubmitOtherV1"
        self.assert_fails(run(self.METHOD, edited(edit)), "instruction privacy::SubmitOtherV1 is not a listed operation")


class Exact12RouteReaders(Base):
    """The text readers behind the single-route check."""

    def test_drop_gated_items_removes_the_item_and_only_the_item(self) -> None:
        gate = r'#\[cfg\(any\(\s*test\s*,\s*feature\s*=\s*"test-utils"\s*\)\)\]'
        text = ('fn kept() {}\n#[cfg(any(test, feature = "test-utils"))]\npub fn dropped() { inner(); }\n'
                '#[cfg(any(test, feature = "test-utils"))]\n#[doc(hidden)]\npub mod fixtures {\n    fn also_dropped() {}\n}\n'
                "fn also_kept() {}\n")
        result = C.drop_gated_items(text, [gate])
        self.assertIn("fn kept()", result)
        self.assertIn("fn also_kept()", result)
        self.assertNotIn("dropped", result)
        self.assertEqual(C.drop_gated_items(text, []), text)
        other = '#[cfg(any(test, feature = "privacy-release-evidence"))]\nfn builder() {}\n'
        self.assertEqual(C.drop_gated_items(other, [gate]), other)

    def test_registry_rows_reads_every_row_or_nothing(self) -> None:
        rows = C.registry_rows(source(DISPATCH_REGISTRY), "PRIVACY_ROLE_DISPATCH_TABLE_V1")
        self.assertEqual(len(rows), 13)
        self.assertEqual(rows[0], {"role": "ZkAceAuthorization", "verification": "refused",
                                   "limitation": "ZkAceSoundnessDerivationIncomplete", "effect_class": "ZkAceAuthorization"})
        self.assertEqual(rows[2], {"role": "VeRangeRange", "verification": "implemented", "limitation": None,
                                   "effect_class": "VerifyOnly"})
        self.assertIsNone(C.registry_rows("const OTHER: [u8; 1] = [0];", "PRIVACY_ROLE_DISPATCH_TABLE_V1"))
        unknown = "const T: [R; 1] = [row(Role::A, maybe(), Class::B)];"
        self.assertEqual(C.registry_rows(unknown, "T"), [{"role": "A", "verification": None, "limitation": None, "effect_class": "B"}])
        self.assertIsNone(C.registry_rows("const T: [R; 1] = [row(Role::A, IMPLEMENTED)];", "T"))

    def test_driver_operations_resolve_their_constants(self) -> None:
        rows = C.driver_operations(source(ACTION_DRIVER), "OPERATION_SPECS_V1")
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows[0], {"name": "build-zk-ace-action-v1", "role": "ZkAceAuthorization"})
        self.assertEqual(rows, [{"name": item["name"], "role": item["role"]}
                                for item in INVENTORY["exact12"]["single_route"]["driver_operations"]])
        self.assertIsNone(C.driver_operations("fn main() {}", "OPERATION_SPECS_V1"))

    def test_struct_fields_of_types_reads_named_fields_only(self) -> None:
        code = ("pub struct A { pub envelope: PrivacyProofEnvelopeV1, pub other: u8 }\n"
                "struct B { proofs: Vec<PrivacyProofV1> }\n"
                "struct C { kept: PrivacyProofEnvelopeV1Digest }\n"
                "fn f(envelope: PrivacyProofEnvelopeV1) {}\n")
        self.assertEqual(C.struct_fields_of_types(code, ["PrivacyProofEnvelopeV1", "PrivacyProofV1"]),
                         [("A", "envelope", "PrivacyProofEnvelopeV1"), ("B", "proofs", "PrivacyProofV1")])

    def test_envelope_scanners_see_literals_self_literals_and_assignments(self) -> None:
        path = "crates/iroha_core/src/privacy_scan_sample.rs"
        text = (
            "fn literal() { let _ = Thing { a: 1 }; }\n"
            "impl Thing {\n    fn build() -> Self { Self { a: 1 } }\n    fn read(&self) -> u8 { self.a }\n}\n"
            "impl Clone for Thing { fn clone(&self) -> Self { Self { a: self.a } } }\n"
            "fn sig() -> Thing { make() }\n"
            "fn assign(envelope: &mut E) { envelope.protocol_id = x; envelope . statement_digest = y; let _ = envelope.engine_id == z; }\n"
        )
        tree = C.Tree(C.ROOT, {path: text})
        scan = C.RouteScan(tree, {"roots": ["crates/iroha_core/src/privacy_scan_sample.rs"], "exclude": [], "test_gates": []})
        self.assertEqual(scan.files, [path])
        self.assertEqual(C.envelope_assemblies(scan, "Thing"),
                         [{"path": path, "function": "literal", "kind": "literal"},
                          {"path": path, "function": "build", "kind": "self_literal"}])
        self.assertEqual(C.envelope_field_assignments(scan), {path: 2})
        self.assertEqual(scan.calls("make"), {path: 1})
        self.assertEqual(scan.calls("build"), {})
        self.assertEqual(scan.holding("no such needle"), [])

    def test_mentions_privacy_reads_the_path_the_override_and_the_file(self) -> None:
        tree = C.Tree(C.ROOT, {"crates/x/src/a.rs": "fn a() {}", "crates/x/src/b.rs": "use iroha_core_privacy::x;"})
        self.assertFalse(C.mentions_privacy(tree, "crates/x/src/a.rs"))
        self.assertTrue(C.mentions_privacy(tree, "crates/x/src/b.rs"))
        self.assertTrue(C.mentions_privacy(tree, "crates/x/src/privacy_thing.rs"))
        self.assertTrue(C.mentions_privacy(REAL, PRIVACY_HANDLERS))
        self.assertTrue(C.mentions_privacy(REAL, "crates/zk_ace_prover/src/lib.rs"))
        self.assertFalse(C.mentions_privacy(REAL, "crates/x/src/absent.rs"))
        self.assertFalse(C.mentions_privacy(REAL, "crates/iroha_version/src/lib.rs"))

    def test_handler_gate_is_read_from_the_impl_block(self) -> None:
        checker = C.Checker(INVENTORY, C.Tree())
        entry = INVENTORY["exact12"]["single_route"]["handler"]["entry"]
        self.assertTrue(checker.handler_is_gated(entry, "resolve_qualified_privacy_activation_v1"))
        self.assertFalse(checker.handler_is_gated(entry, "no_such_gate"))
        self.assertFalse(checker.handler_is_gated({"path": PRIVACY_HANDLERS, "symbol": "impl Execute for NoSuchInstructionV1"},
                                                  "resolve_qualified_privacy_activation_v1"))

    def test_a_cargo_target_with_required_features_gates_its_tests(self) -> None:
        self.assertEqual(C.target_required_feature(REAL, "iroha_core", "src/bin/privacy_exact12_action_driver.rs"),
                         "privacy-release-evidence")
        self.assertIsNone(C.target_required_feature(REAL, "iroha_core", "src/privacy.rs"))
        self.assertEqual(C.feature_gate(REAL, ACTION_DRIVER), "privacy-release-evidence")
        manifest = ('[features]\ndefault = ["on"]\non = []\noff = []\n\n[[bin]]\nname = "a"\npath = "src/bin/a.rs"\n'
                    'required-features = ["on"]\n\n[[bin]]\nname = "b"\npath = "src/bin/b.rs"\nrequired-features = ["on", "off"]\n\n'
                    '[[bin]]\nname = "c"\npath = "src/bin/c.rs"\n')
        tree = C.Tree(C.ROOT, {"crates/sample/Cargo.toml": manifest})
        self.assertIsNone(C.target_required_feature(tree, "sample", "src/bin/a.rs"))
        self.assertEqual(C.target_required_feature(tree, "sample", "src/bin/b.rs"), "off")
        self.assertIsNone(C.target_required_feature(tree, "sample", "src/bin/c.rs"))

        def edit(inventory: dict) -> None:
            test = inventory["exact12"]["single_route"]["entries"][1]["tests"][0]
            del test["feature"]
        errors = run("check_anchors", edited(edit))
        self.assert_fails(errors, 'is compiled only with feature `privacy-release-evidence`; record "feature": "privacy-release-evidence"')


if __name__ == "__main__":
    unittest.main()
