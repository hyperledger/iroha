"""Drift tests for the protocol economic invariant matrix checker.

Every mutation is applied in memory: the matrix is deep-copied and the tree is read
through `Tree(overrides=...)`. Nothing in the checkout is written.

Run with either of:
    python3 -m unittest scripts/tests/check_zk_economic_invariants_test.py
    python3 -m pytest -q scripts/tests/check_zk_economic_invariants_test.py
"""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "check_zk_economic_invariants.py"
_SPEC = importlib.util.spec_from_file_location("check_zk_economic_invariants", _PATH)
C = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = C
_SPEC.loader.exec_module(C)

MATRIX = C.load()
REAL = C.readers.Tree()
PRIVACY_MODEL = "crates/iroha_data_model/src/privacy.rs"
PROTOCOL_MODEL = "crates/iroha_data_model/src/privacy/protocol.rs"
STATEMENTS = "crates/iroha_data_model/src/privacy/statements.rs"
HANDLERS = "crates/iroha_core/src/smartcontracts/isi/privacy.rs"
ASSETS = "crates/iroha_core/src/smartcontracts/isi/asset.rs"
VERIFIER = "crates/iroha_core_privacy/src/privacy_verifier.rs"
PRIVACY_STATE = "crates/iroha_core_privacy/src/privacy_state.rs"
KAIGI = "crates/iroha_core/src/smartcontracts/isi/kaigi.rs"
WORLD_STATE = "crates/iroha_core/src/state.rs"
HARNESS_TESTS = "crates/iroha_core/src/smartcontracts/isi/asset/privacy_economic_invariant_tests.rs"
RESERVE_TESTS = "crates/iroha_core/src/smartcontracts/isi/asset/privacy_public_reserve_tests.rs"
INCLUDE = 'include!("asset/privacy_economic_invariant_tests.rs");'
PGC_ARM = "VerifiedPrivacyLedgerEffectsV1::AnonymousPgcPayment(effect) => {"
X509_ARM = "VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(effect) => {"
CUSTODY_MISMATCH = '"verified privacy pool bridge does not match governed reserve custody"'
# The funded-allowance owner repeats this refusal earlier in asset.rs; the cited bridge site is the
# one occurrence followed by `.into()` inside `execute_verified_privacy_pool_public_balance_transfer`.
BRIDGE_CUSTODY_MISMATCH = CUSTODY_MISMATCH + ".into()"


def source(path: str) -> str:
    text = REAL.read(path)
    assert text is not None, path
    return text


def replaced(path: str, old: str, new: str) -> dict:
    text = source(path)
    assert old in text, f"{old!r} is not in {path}"
    return {path: text.replace(old, new, 1)}


def inserted_after(path: str, anchor: str, addition: str) -> dict:
    return replaced(path, anchor, anchor + addition)


def document(path: str) -> dict:
    return json.loads(source(path))


def run(method: str | None = None, matrix: dict | None = None, overrides: dict | None = None, strict: bool = False) -> list[str]:
    checker = C.Checker(matrix if matrix is not None else MATRIX, C.readers.Tree(C.ROOT, overrides), strict_lines=strict)
    if method is None:
        return checker.check()
    getattr(checker, method)()
    return checker.errors


def edited(edit) -> dict:
    matrix = copy.deepcopy(MATRIX)
    edit(matrix)
    return matrix


def without_lines(node):
    """`node` without the advisory `line` of its anchors."""
    if isinstance(node, dict):
        return {key: without_lines(value) for key, value in node.items() if key != "line"}
    if isinstance(node, list):
        return [without_lines(value) for value in node]
    return node


def effect(matrix: dict, identifier: str) -> dict:
    return next(item for item in matrix["effects"] if item["id"] == identifier)


def protocol(matrix: dict, identifier: str) -> dict:
    return next(item for item in matrix["protocols"] if item["id"] == identifier)


def defect(matrix: dict, identifier: str) -> dict:
    return next(item for item in matrix["defects"] if item["id"] == identifier)


def invariant(matrix: dict, identifier: str, kind: str) -> dict:
    return next(item for item in effect(matrix, identifier)["invariants"] if item["kind"] == kind)


class Base(unittest.TestCase):
    def assert_fails(self, errors: list[str], fragment: str) -> None:
        self.assertTrue(any(fragment in error for error in errors), f"{fragment!r} not in {errors[:8]}")

    def assert_clean(self, errors: list[str]) -> None:
        self.assertEqual(errors, [])


class TrackedMatrix(Base):
    """The tracked file against the real tree."""

    def test_tracked_matrix_matches_the_source(self) -> None:
        self.assert_clean(run())

    def test_main_passes_and_show_lists_every_effect_and_defect(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(C.main([]), 0)
        self.assertIn("match the tree", out.getvalue())
        self.assertEqual(len(C.show(MATRIX)), len(MATRIX["effects"]))
        self.assertEqual(len(C.show_defects(MATRIX)), len(MATRIX["defects"]))

    def test_show_and_defects_options_print_one_line_per_record(self) -> None:
        for option, count in (("--show", len(MATRIX["effects"])), ("--defects", len(MATRIX["defects"]))):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(C.main([option]), 0)
            self.assertEqual(len(out.getvalue().splitlines()), count, option)

    def test_tracked_file_is_in_the_stable_text_form_refresh_writes(self) -> None:
        self.assertEqual(C.readers.dump(MATRIX), source(C.INVENTORY))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "specs").mkdir()
            C.write_inventory(MATRIX, root)
            self.assertEqual((root / C.INVENTORY).read_text(encoding="utf-8"), source(C.INVENTORY))
            self.assertEqual(C.load(root), MATRIX)

    def test_refresh_changes_nothing_but_advisory_lines(self) -> None:
        matrix = copy.deepcopy(MATRIX)
        changes = C.Checker(matrix, C.readers.Tree()).refresh()
        self.assertEqual([change for change in changes if ".line " not in change], [])
        self.assertEqual(without_lines(matrix), without_lines(MATRIX))

    def test_every_operation_of_the_operation_inventory_is_classified(self) -> None:
        operations = {item["id"] for item in document(C.OPERATIONS)["operations"]}
        self.assertEqual(set(MATRIX["operations"]), operations)
        bearing = [key for key, item in MATRIX["operations"].items() if item["value_bearing"]]
        self.assertTrue(bearing)
        for key in bearing:
            self.assertTrue(MATRIX["operations"][key]["effects"], key)

    def test_the_seven_effect_classes_are_all_used(self) -> None:
        used = {item["class"] for item in MATRIX["effects"]}
        self.assertEqual(used, set(C.EFFECT_CLASSES))

    def test_every_value_bearing_protocol_answers_the_lifecycle(self) -> None:
        for item in MATRIX["protocols"]:
            if not item["value_bearing"]:
                continue
            for key in C.LIFECYCLE_KEYS:
                self.assertIn(item["lifecycle"][key]["status"], C.ANSWER_STATUS, item["id"])
            for key in C.EXIT_KEYS:
                self.assertIn(item["lifecycle"]["exits"][key]["status"], C.ANSWER_STATUS, item["id"])

    def test_every_proof_authorized_effect_separates_the_three_failures(self) -> None:
        for item in MATRIX["effects"]:
            exposure = item["exposure_after_erroneous_acceptance"]
            self.assertEqual(sorted(key for key in exposure if key != "summary"), sorted(C.FAILURE_KINDS), item["id"])

    def test_no_bound_is_recorded_as_soundness(self) -> None:
        for item in MATRIX["effects"]:
            for record in item["invariants"]:
                self.assertNotRegex(record["statement"], r"(?i)sound", item["id"])
                if record["status"] in ("enforced", "enforced_by_absence"):
                    self.assertIn("proof_soundness", record["does_not_establish"], item["id"])
                    if record["kind"] in C.BOUNDING_KINDS:
                        self.assertIn("hidden_conservation", record["does_not_establish"], item["id"])

    def test_every_gap_has_an_owned_defect(self) -> None:
        defects = {item["id"]: item for item in MATRIX["defects"]}
        for item in MATRIX["effects"]:
            for record in item["invariants"]:
                if record["status"] == "not_enforced":
                    self.assertTrue(record["defects"], item["id"])
                    for identifier in record["defects"]:
                        self.assertTrue(defects[identifier]["owner"], identifier)

    def test_the_added_harness_tests_are_cited(self) -> None:
        added = {test["test"] for item in MATRIX["effects"] for test in item["mutation_tests"] if test["status"] == "added"}
        self.assertEqual(added, {
            "faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance",
            "faulty_verifier_pool_effect_cannot_reach_another_pool_asset_scope_or_account",
            "faulty_verifier_pool_deposit_moves_existing_units_and_never_mints",
            "faulty_verifier_general_bridge_moves_only_existing_source_units",
            "dropped_transaction_discards_a_faulty_pool_withdrawal",
            "faulty_verifier_fee_sponsor_cannot_rebind_a_lease_or_overlap_a_live_route",
            "faulty_verifier_fee_sponsor_capacity_is_exact_and_identical_replay_adds_no_lock",
            "faulty_verifier_fee_sponsor_failed_batch_discards_earlier_allocation",
            "faulty_verifier_fee_sponsor_respects_current_height_and_scheduled_revision",
        })


class Shape(Base):
    def test_schema_task_and_required_keys_are_checked(self) -> None:
        self.assert_fails(run("check_shape", edited(lambda m: m.update(schema="other"))), "schema is")
        self.assert_fails(run("check_shape", edited(lambda m: m.update(task="F.1"))), "task is")
        self.assert_fails(run("check_shape", edited(lambda m: m.pop("root_policy"))), "`root_policy` is missing")

    def test_vocabulary_is_closed(self) -> None:
        matrix = edited(lambda m: m["vocabulary"]["effect_class"].pop("inter_pool_movement"))
        self.assert_fails(run("check_shape", matrix), "vocabulary.effect_class must define exactly")
        matrix = edited(lambda m: m["vocabulary"]["failure_kind"].update(other="x"))
        self.assert_fails(run("check_shape", matrix), "vocabulary.failure_kind must define exactly")

    def test_consumers_are_tasks_of_the_graph(self) -> None:
        self.assert_fails(run("check_shape", edited(lambda m: m["consumed_by"].append("Z.9"))), "task `Z.9` is not in")

    def test_sources_name_the_sibling_inventories(self) -> None:
        matrix = edited(lambda m: m["sources"]["operation_inventory"].update(path="specs/other.json"))
        self.assert_fails(run("check_sources", matrix), "sources.operation_inventory.path must be")
        self.assert_fails(run("check_sources", overrides={C.OPERATIONS: "{}"}), "schema is None")


class Operations(Base):
    def test_unclassified_operation_fails(self) -> None:
        matrix = edited(lambda m: m["operations"].pop("kaigi::RecordKaigiUsage"))
        self.assert_fails(run("check_operations", matrix), "source has ['kaigi::RecordKaigiUsage'] unrecorded")

    def test_operation_added_to_the_operation_inventory_fails(self) -> None:
        operations = document(C.OPERATIONS)
        added = copy.deepcopy(next(item for item in operations["operations"] if item["id"] == "kaigi::RecordKaigiUsage"))
        added["id"] = "kaigi::PayKaigiUsage"
        operations["operations"].append(added)
        errors = run("check_operations", overrides={C.OPERATIONS: json.dumps(operations)})
        self.assert_fails(errors, "source has ['kaigi::PayKaigiUsage'] unrecorded")

    def test_stale_operation_fails(self) -> None:
        matrix = edited(lambda m: m["operations"].update({"gone::Operation": {"value_bearing": False, "reason": "administrative", "note": "x"}}))
        self.assert_fails(run("check_operations", matrix), "the matrix has ['gone::Operation'] stale")

    def test_value_bearing_operation_without_a_row_fails(self) -> None:
        matrix = edited(lambda m: m["operations"].update({"kaigi::RecordKaigiUsage": {"value_bearing": True, "effects": []}}))
        self.assert_fails(run("check_operations", matrix), "a value-bearing operation has no effect row")

    def test_removing_the_row_of_a_value_bearing_operation_fails(self) -> None:
        def edit(matrix: dict) -> None:
            matrix["effects"] = [item for item in matrix["effects"] if item["id"] != "race.game_settlement"]
        self.assert_fails(run("check_operations", edited(edit)), "operation game::SettleGameSessionV1: a value-bearing operation has no effect row")

    def test_recorded_rows_must_be_the_rows_that_name_the_operation(self) -> None:
        matrix = edited(lambda m: m["operations"]["game::SettleGameSessionV1"].update(effects=["orchard.unshield"]))
        self.assert_fails(run("check_operations", matrix), "differ from the rows that name it")

    def test_row_naming_an_operation_recorded_as_moving_no_value_fails(self) -> None:
        matrix = edited(lambda m: effect(m, "race.game_settlement").update(also_operations=["kaigi::RecordKaigiUsage"]))
        self.assert_fails(run("check_operations", matrix), "recorded as moving no value, yet rows")

    def test_handler_that_starts_naming_ledger_value_fails(self) -> None:
        overrides = inserted_after(KAIGI, "impl Execute for RecordKaigiUsage {",
                                   "\n    fn pay(amount: Quantity) { let _ = amount; }\n")
        errors = run("check_operations", overrides=overrides)
        self.assert_fails(errors, "operation kaigi::RecordKaigiUsage: its handler names the ledger-value identifiers ['Quantity']")

    def test_value_identifier_in_a_helper_of_the_handler_file_is_found(self) -> None:
        text = source(KAIGI)
        marker = "impl Execute for RecordKaigiUsage {"
        assert marker in text
        body_start = text.index("{", text.index(") -> Result<(), Error>", text.index(marker)))
        mutated = (text[: body_start + 1] + "\n        f3_test_helper_that_pays();\n" + text[body_start + 1 :]
                   + "\nfn f3_test_helper_that_pays() { let _ = Mint::asset_quantity; }\n")
        errors = run("check_operations", overrides={KAIGI: mutated})
        self.assert_fails(errors, "operation kaigi::RecordKaigiUsage: its handler names the ledger-value identifiers ['Mint']")

    def test_recorded_value_identifiers_need_a_note_and_must_be_exact(self) -> None:
        matrix = edited(lambda m: m["operations"]["kaigi::RecordKaigiUsage"].update(value_tokens=["Quantity"]))
        self.assert_fails(run("check_operations", matrix), "its handler names the ledger-value identifiers []")
        overrides = inserted_after(KAIGI, "impl Execute for RecordKaigiUsage {", "\n    fn pay(amount: Quantity) { let _ = amount; }\n")
        self.assert_fails(run("check_operations", matrix, overrides), "value_tokens need a `value_tokens_note`")

    def test_reason_is_closed_and_needs_a_note(self) -> None:
        matrix = edited(lambda m: m["operations"]["kaigi::RecordKaigiUsage"].update(reason="harmless"))
        self.assert_fails(run("check_operations", matrix), "reason must be one of")
        matrix = edited(lambda m: m["operations"]["kaigi::RecordKaigiUsage"].pop("note"))
        self.assert_fails(run("check_operations", matrix), "says why in `note`")

    def test_refused_operation_that_gains_effects_must_be_classified_again(self) -> None:
        operations = document(C.OPERATIONS)
        next(item for item in operations["operations"] if item["id"] == "ivm_proof.proved_invocation")["status"]["state_effects"] = "implemented"
        errors = run("check_operations", overrides={C.OPERATIONS: json.dumps(operations)})
        self.assert_fails(errors, "operation ivm_proof.proved_invocation: recorded as refused_no_value")

    def test_tripwire_needs_a_pattern(self) -> None:
        self.assert_fails(run("check_operations", edited(lambda m: m["tripwire"].update(pattern="("))), "not a regular expression")
        self.assert_fails(run("check_operations", edited(lambda m: m["tripwire"].update(helper_depth="2"))), "tripwire needs")


class Protocols(Base):
    def test_product_without_a_protocol_entry_fails(self) -> None:
        def edit(matrix: dict) -> None:
            matrix["protocols"] = [item for item in matrix["protocols"] if item["id"] != "kaigi"]
        self.assert_fails(run("check_protocols", edited(edit)), "source has ['kaigi'] unrecorded")

    def test_value_bearing_flag_follows_the_rows(self) -> None:
        self.assert_fails(run("check_protocols", edited(lambda m: protocol(m, "orchard").update(value_bearing=False))),
                          "protocol orchard: value_bearing is False with 4 effect rows")
        self.assert_fails(run("check_protocols", edited(lambda m: protocol(m, "kaigi").update(value_bearing=True))),
                          "protocol kaigi: value_bearing is True with 0 effect rows")

    def test_recorded_effects_are_the_rows_of_the_protocol(self) -> None:
        matrix = edited(lambda m: protocol(m, "orchard")["effects"].remove("orchard.unshield"))
        self.assert_fails(run("check_protocols", matrix), "differ from the rows of this protocol")

    def test_shared_operations_name_where_their_rows_are(self) -> None:
        matrix = edited(lambda m: protocol(m, "exact12_admission").pop("rows_recorded_under"))
        self.assert_fails(run("check_protocols", matrix), "record their rows here or name the protocols")
        matrix = edited(lambda m: protocol(m, "exact12_admission").update(rows_recorded_under=["kaigi"]))
        self.assert_fails(run("check_protocols", matrix), "is not a value-bearing protocol")

    def test_protocol_recorded_as_moving_no_value_says_why(self) -> None:
        self.assert_fails(run("check_protocols", edited(lambda m: protocol(m, "jindo").pop("why_no_value"))), "says why")

    def test_every_lifecycle_answer_is_required(self) -> None:
        for key in C.LIFECYCLE_KEYS:
            matrix = edited(lambda m, key=key: protocol(m, "orchard")["lifecycle"].pop(key))
            self.assert_fails(run("check_protocols", matrix), f"protocol orchard: lifecycle.{key}: needs `status`")
        for key in C.EXIT_KEYS:
            matrix = edited(lambda m, key=key: protocol(m, "atomic_settlement")["lifecycle"]["exits"].pop(key))
            self.assert_fails(run("check_protocols", matrix), f"protocol atomic_settlement: lifecycle.exits.{key}: needs `status`")

    def test_defined_answer_needs_an_existing_site(self) -> None:
        matrix = edited(lambda m: protocol(m, "orchard")["lifecycle"]["failure_atomicity"].pop("sites"))
        self.assert_fails(run("check_protocols", matrix), "a defined answer cites at least one site")
        matrix = edited(lambda m: protocol(m, "orchard")["lifecycle"]["failure_atomicity"]["sites"][0].update(symbol="fn gone("))
        self.assert_fails(run("check_protocols", matrix), "`fn gone(` is not in")

    def test_answer_that_is_not_defined_needs_an_open_defect(self) -> None:
        matrix = edited(lambda m: protocol(m, "orchard")["lifecycle"]["exits"]["policy_revocation"].pop("defects"))
        self.assert_fails(run("check_protocols", matrix), "an answer that is not defined cites an open defect")
        matrix = edited(lambda m: protocol(m, "orchard")["lifecycle"]["exits"]["correction"].update(defects=["D-UNKNOWN"]))
        self.assert_fails(run("check_protocols", matrix), "defect `D-UNKNOWN` is not recorded")

    def test_pool_and_owner_are_required(self) -> None:
        self.assert_fails(run("check_protocols", edited(lambda m: protocol(m, "fcmp")["pool"].update(boundary="open"))),
                          "pool.boundary must be one of")
        self.assert_fails(run("check_protocols", edited(lambda m: protocol(m, "fcmp")["pool"].pop("supply_source"))),
                          "pool.supply_source is missing")
        self.assert_fails(run("check_protocols", edited(lambda m: protocol(m, "fcmp").update(owner_tasks=["Z.9"]))),
                          "task `Z.9` is not in")


class ClosedLists(Base):
    def test_thirteenth_protocol_fails(self) -> None:
        overrides = replaced(PRIVACY_MODEL, '    #[norito(rename = "pq-masp-stark-v1")]\n    PqMaspStarkV1,\n}',
                             '    #[norito(rename = "pq-masp-stark-v1")]\n    PqMaspStarkV1,\n    /// New.\n    NewPoolV1,\n}')
        self.assert_fails(run("check_closed_lists", overrides=overrides), "closed_lists.exact12: source has ['NewPoolV1'] unrecorded")

    def test_new_ledger_effect_class_fails(self) -> None:
        overrides = replaced(VERIFIER, "pub enum VerifiedPrivacyLedgerEffectsV1 {",
                             "pub enum VerifiedPrivacyLedgerEffectsV1 {\n    /// New.\n    BridgeMint(u64),")
        self.assert_fails(run("check_closed_lists", overrides=overrides), "closed_lists.ledger_effects: source has ['BridgeMint'] unrecorded")

    def test_value_free_arm_that_starts_moving_value_fails(self) -> None:
        overrides = inserted_after(HANDLERS, X509_ARM, "\n                let _fee = Quantity::from(1_u32);")
        errors = run("check_closed_lists", overrides=overrides)
        self.assert_fails(errors, "closed_lists.ledger_effects.ZkX509Certificate: the arm names `Quantity`")

    def test_value_free_class_needs_its_forbidden_list_and_no_rows(self) -> None:
        def edit(matrix: dict) -> None:
            item = next(c for c in matrix["closed_lists"]["ledger_effects"]["classes"] if c["variant"] == "None")
            item.pop("forbidden")
            item["effects"] = ["orchard.unshield"]
        errors = run("check_closed_lists", edited(edit))
        self.assert_fails(errors, "lists the identifiers its arm must not name")
        self.assert_fails(errors, "a class recorded as moving no value has effect rows")

    def test_value_bearing_class_rows_belong_to_a_protocol_that_returns_it(self) -> None:
        def edit(matrix: dict) -> None:
            item = next(c for c in matrix["closed_lists"]["ledger_effects"]["classes"] if c["variant"] == "OrchardActions")
            item["effects"] = ["fcmp.transfer"]
        self.assert_fails(run("check_closed_lists", edited(edit)), "belongs to a protocol whose verifier does not return this class")

    def test_protocol_that_returns_a_value_class_cannot_be_recorded_as_value_free(self) -> None:
        matrix = edited(lambda m: protocol(m, "pq_masp").update(value_bearing=False))
        self.assert_fails(run("check_closed_lists", matrix), "protocol pq_masp returns a value-bearing class")

    def test_ledger_effects_of_a_protocol_follow_the_operation_inventory(self) -> None:
        matrix = edited(lambda m: protocol(m, "jindo").update(ledger_effects=["OrchardActions"]))
        self.assert_fails(run("check_closed_lists", matrix), "protocol jindo: ledger_effects")

    def test_new_proof_managed_transition_fails(self) -> None:
        overrides = replaced(VERIFIER, "pub enum VerifiedProofManagedPoolTransitionV1 {",
                             "pub enum VerifiedProofManagedPoolTransitionV1 {\n    /// New.\n    Bridge { amount: u64 },")
        self.assert_fails(run("check_closed_lists", overrides=overrides), "closed_lists.proof_managed_transitions: source has ['Bridge']")

    def test_protocol_added_to_the_reserve_list_fails(self) -> None:
        overrides = replaced(PRIVACY_STATE,
                             "    PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,\n];",
                             "    PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,\n    PrivacyProtocolIdV1::PqMaspStarkV1,\n];")
        errors = run("check_closed_lists", overrides=overrides)
        self.assert_fails(errors, "closed_lists.reserve_owners.protocol_list: source has ['PqMaspStarkV1'] unrecorded")
        self.assert_fails(errors, "the source lets")

    def test_new_reserve_owner_variant_fails(self) -> None:
        overrides = replaced(PRIVACY_STATE, "pub enum PrivacyPublicReserveOwnerV1 {",
                             "pub enum PrivacyPublicReserveOwnerV1 {\n    /// New.\n    PqMasp { namespace: PrivacyNamespaceV1 },")
        self.assert_fails(run("check_closed_lists", overrides=overrides), "closed_lists.reserve_owners: source has ['PqMasp'] unrecorded")

    def test_closed_pool_recorded_with_a_reserve_fails(self) -> None:
        matrix = edited(lambda m: protocol(m, "fcmp")["pool"].update(boundary="public_reserve"))
        self.assert_fails(run("check_closed_lists", matrix), "protocols with boundary public_reserve are")

    def test_root_role_and_its_management_are_checked(self) -> None:
        overrides = replaced(PROTOCOL_MODEL, "pub enum PrivacyRootRoleV1 {", "pub enum PrivacyRootRoleV1 {\n    /// New.\n    ReserveLedger,")
        self.assert_fails(run("check_closed_lists", overrides=overrides), "closed_lists.root_roles: source has ['ReserveLedger'] unrecorded")

        def edit(matrix: dict) -> None:
            role = next(r for r in matrix["closed_lists"]["root_roles"]["roles"] if r["variant"] == "OutputSet")
            role["management"] = "GovernanceManaged"
        self.assert_fails(run("check_closed_lists", edited(edit)), "closed_lists.root_roles.OutputSet: source management is ProofManaged")

    def test_root_role_protocols_follow_the_source(self) -> None:
        def edit(matrix: dict) -> None:
            role = next(r for r in matrix["closed_lists"]["root_roles"]["roles"] if r["variant"] == "NoteCommitmentAnchor")
            role["protocols"] = ["orchard"]
        self.assert_fails(run("check_closed_lists", edited(edit)),
                          "closed_lists.root_roles.NoteCommitmentAnchor: the source makes it a root of ['orchard', 'pq_masp']")

    def test_new_committed_pool_map_must_be_recorded(self) -> None:
        overrides = replaced(WORLD_STATE, "    pub(crate) zk_assets: Storage<AssetDefinitionId, ZkAssetState>,",
                             "    pub(crate) zk_assets: Storage<AssetDefinitionId, ZkAssetState>,\n"
                             "    pub(crate) bridge_pool_nullifiers: Storage<Hash, u64>,")
        self.assert_fails(run("check_closed_lists", overrides=overrides),
                          "closed_lists.pool_state: source has ['bridge_pool_nullifiers'] unrecorded")

    def test_pool_map_names_its_protocols_or_why_it_is_left_out(self) -> None:
        def field(matrix: dict, name: str) -> dict:
            return next(item for item in matrix["closed_lists"]["pool_state"]["fields"] if item["field"] == name)
        matrix = edited(lambda m: field(m, "kagemusha_wallet_ledger").pop("out_of_scope"))
        self.assert_fails(run("check_closed_lists", matrix), "names its `protocols`, or says why it is `out_of_scope`")
        matrix = edited(lambda m: field(m, "zk_assets").update(protocols=["nowhere"]))
        self.assert_fails(run("check_closed_lists", matrix), "closed_lists.pool_state.zk_assets: protocol `nowhere` is not recorded")
        matrix = edited(lambda m: m["closed_lists"]["pool_state"].update(struct="Gone"))
        self.assert_fails(run("check_closed_lists", matrix), "struct Gone is not in")

    def test_lifecycle_state_added_or_removed_fails(self) -> None:
        overrides = replaced(PROTOCOL_MODEL, "    Suspended(PrivacySuspendedLifecycleV1),", "    Frozen(PrivacySuspendedLifecycleV1),")
        errors = run("check_closed_lists", overrides=overrides)
        self.assert_fails(errors, "closed_lists.lifecycle_states: source has ['Frozen'] unrecorded, the matrix has ['Suspended'] stale")

    def test_state_that_admits_no_value_effect_is_a_recorded_switch(self) -> None:
        def edit(matrix: dict) -> None:
            found = matrix["root_policy"]["generic_suspension_switch"]["found"]
            matrix["root_policy"]["generic_suspension_switch"]["found"] = [item for item in found if item["state"] != "Suspended"]
        self.assert_fails(run("check_closed_lists", edited(edit)), "closed_lists.lifecycle_states.Suspended: a state that admits no value effect")

    def test_value_balance_direction_is_checked(self) -> None:
        overrides = replaced(STATEMENTS, "    /// Private value leaves the pool.\n    OutOfPool,",
                             "    /// Private value leaves the pool.\n    OutOfPool,\n    /// New.\n    AcrossPools,")
        self.assert_fails(run("check_closed_lists", overrides=overrides), "closed_lists.value_balance_directions: source has ['AcrossPools']")


class Effects(Base):
    def test_handler_must_equal_the_operation_inventory(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.pool_bootstrap")["handler"].update(symbol="impl Execute for Other"))
        self.assert_fails(run("check_effects", matrix), "effect orchard.pool_bootstrap: handler differs from the operation inventory")

    def test_removed_handler_fails(self) -> None:
        overrides = replaced(HANDLERS, "impl Execute for BootstrapPrivacyOrchardPoolV1 {", "impl Execute for BootstrapOrchardPool {")
        self.assert_fails(run("check_effects", overrides=overrides), "effect orchard.pool_bootstrap: handler: `impl Execute for BootstrapPrivacyOrchardPoolV1`")

    def test_effect_status_must_agree_with_the_operation_inventory(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.unshield").update(effect_status="implemented"))
        self.assert_fails(run("check_effects", matrix), "effect_status implemented contradicts the operation inventory, which records gated")
        matrix = edited(lambda m: effect(m, "confidential_assets.unshield").update(effect_status="gated"))
        self.assert_fails(run("check_effects", matrix), "contradicts the operation inventory, which records absent")

    def test_unreachable_under_a_gated_operation_needs_a_refused_profile(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.unshield").update(effect_status="unreachable", required_before_enabling="x"))
        self.assert_fails(run("check_effects", matrix), "unreachable needs a refused compiled profile")

    def test_absent_effect_has_no_handler_and_names_what_is_required(self) -> None:
        matrix = edited(lambda m: effect(m, "confidential_assets.shield").update(handler={"path": HANDLERS, "symbol": "fn x("}))
        self.assert_fails(run("check_effects", matrix), "an absent effect has no handler to cite")
        matrix = edited(lambda m: effect(m, "confidential_assets.shield").pop("required_before_enabling"))
        self.assert_fails(run("check_effects", matrix), "records `required_before_enabling`")
        matrix = edited(lambda m: effect(m, "confidential_assets.shield").update(defects=[]))
        self.assert_fails(run("check_effects", matrix), "cites the open defect of its owner")

    def test_class_summary_and_protocol_are_checked(self) -> None:
        self.assert_fails(run("check_effects", edited(lambda m: effect(m, "orchard.shield").update({"class": "mint"}))), "class must be one of")
        self.assert_fails(run("check_effects", edited(lambda m: effect(m, "orchard.shield").update(protocol="nowhere"))), "is not recorded")
        self.assert_fails(run("check_effects", edited(lambda m: effect(m, "orchard.shield").update(operation="nowhere"))), "is not in")
        self.assert_fails(run("check_effects", edited(lambda m: m["effects"].append(copy.deepcopy(effect(m, "orchard.shield"))))), "ids are unique")

    def test_private_issuance_names_who_may_issue(self) -> None:
        matrix = edited(lambda m: effect(m, "fcmp.pool_bootstrap")["authorized_issuance_source"].update(kind="none"))
        self.assert_fails(run("check_effects", matrix), "private issuance names who may issue")
        matrix = edited(lambda m: effect(m, "orchard.unshield").pop("authorized_issuance_source"))
        self.assert_fails(run("check_effects", matrix), "authorized_issuance_source needs")

    def test_reachable_effect_names_an_invariant(self) -> None:
        matrix = edited(lambda m: effect(m, "voting.plain_ballot_lock").update(invariants=[]))
        self.assert_fails(run("check_effects", matrix), "a reachable effect names at least one ledger invariant")

    def test_removed_enforcement_site_fails(self) -> None:
        assert source(ASSETS).count(BRIDGE_CUSTODY_MISMATCH) == 1
        overrides = replaced(ASSETS, BRIDGE_CUSTODY_MISMATCH, '"bridge refused".into()')
        errors = run("check_effects", overrides=overrides)
        self.assert_fails(errors, "effect orchard.unshield: invariant 1 (asset_namespace_isolation): `" + CUSTODY_MISMATCH)

    def test_enforcement_site_must_stay_inside_its_scope(self) -> None:
        text = source(ASSETS)
        assert CUSTODY_MISMATCH in text
        assert text.count(BRIDGE_CUSTODY_MISMATCH) == 1
        moved = text.replace(BRIDGE_CUSTODY_MISMATCH, '"bridge refused".into()', 1) + f"\nfn elsewhere() -> &'static str {{ {CUSTODY_MISMATCH} }}\n"
        errors = run("check_effects", overrides={ASSETS: moved})
        self.assert_fails(errors, "inside `pub(crate) fn execute_verified_privacy_pool_public_balance_transfer(`")

    def test_enforced_invariant_needs_a_site(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "exact_reserve_debit_before_equal_credit").pop("sites"))
        self.assert_fails(run("check_effects", matrix), "an enforced invariant cites its enforcement site")

    def test_closed_pool_that_starts_moving_assets_fails(self) -> None:
        overrides = inserted_after(HANDLERS, PGC_ARM, "\n                execute_verified_privacy_public_balance_transfer();")
        errors = run("check_effects", overrides=overrides)
        self.assert_fails(errors, "effect anonymous_pgc.payment: invariant 2 (no_transparent_boundary): `execute_verified_` appears in")

    def test_absence_needs_its_scope(self) -> None:
        matrix = edited(lambda m: invariant(m, "anonymous_pgc.payment", "no_transparent_boundary").pop("absence"))
        self.assert_fails(run("check_effects", matrix), "records its `absence` scope")
        matrix = edited(lambda m: invariant(m, "anonymous_pgc.payment", "no_transparent_boundary")["absence"].update(within="fn gone("))
        self.assert_fails(run("check_effects", matrix), "`fn gone(` opens no body")

    def test_invariant_that_is_not_enforced_needs_an_open_defect(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.shield", "bounded_custody").pop("defects"))
        self.assert_fails(run("check_effects", matrix), "an invariant that is not enforced cites an open defect with its owner")

    def test_not_applicable_says_why_and_kinds_are_closed(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.pool_bootstrap", "no_transparent_boundary").pop("why"))
        self.assert_fails(run("check_effects", matrix), "not_applicable says `why`")
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "bounded_custody").update(kind="cap"))
        self.assert_fails(run("check_effects", matrix), "kind must be one of")
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "bounded_custody").update(status="maybe"))
        self.assert_fails(run("check_effects", matrix), "status must be one of")


class NotSoundness(Base):
    """A reserve cap is never labelled proof soundness."""

    def test_enforced_invariant_lists_proof_soundness_as_not_established(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "asset_namespace_isolation").update(does_not_establish=[]))
        self.assert_fails(run("check_effects", matrix), "lists `proof_soundness` under does_not_establish")

    def test_reserve_bound_lists_hidden_conservation_as_not_established(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "exact_reserve_debit_before_equal_credit")
                        .update(does_not_establish=["proof_soundness"]))
        self.assert_fails(run("check_effects", matrix), "lists `hidden_conservation` under does_not_establish")
        matrix = edited(lambda m: invariant(m, "anonymous_pgc.payment", "fixed_public_supply").update(does_not_establish=["proof_soundness"]))
        self.assert_fails(run("check_effects", matrix), "lists `hidden_conservation` under does_not_establish")

    def test_unknown_non_claim_is_refused(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "asset_namespace_isolation")
                        .update(does_not_establish=["proof_soundness", "liveness"]))
        self.assert_fails(run("check_effects", matrix), "does_not_establish has unknown entries ['liveness']")

    def test_the_word_is_refused_in_statements_and_bounds(self) -> None:
        matrix = edited(lambda m: invariant(m, "orchard.unshield", "exact_reserve_debit_before_equal_credit")
                        .update(statement="The reserve cap gives proof soundness."))
        self.assert_fails(run("check_effects", matrix), "a ledger invariant is not described as soundness")
        matrix = edited(lambda m: effect(m, "orchard.unshield")["exposure_after_erroneous_acceptance"]["reserve_theft"]
                        .update(bound="Bounded by the soundness of the reserve."))
        self.assert_fails(run("check_effects", matrix), "exposure reserve_theft.bound is not described as soundness")

    def test_reserve_pool_admits_that_hidden_value_leaves_through_the_reserve(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.transfer")["exposure_after_erroneous_acceptance"]["reserve_theft"]
                        .update(possible="no"))
        self.assert_fails(run("check_effects", matrix), "reserve_theft must be `yes` with its bound")

    def test_closed_pool_has_no_reserve_and_records_its_missing_boundary(self) -> None:
        matrix = edited(lambda m: effect(m, "fcmp.transfer")["exposure_after_erroneous_acceptance"]["reserve_theft"].update(possible="yes"))
        self.assert_fails(run("check_effects", matrix), "a closed pool has no reserve to take from")

        def edit(matrix: dict) -> None:
            item = effect(matrix, "fcmp.transfer")
            item["invariants"] = [record for record in item["invariants"] if record["kind"] != "no_transparent_boundary"]
        self.assert_fails(run("check_effects", edited(edit)), "records the enforced invariant `no_transparent_boundary`")


class Exposure(Base):
    def test_the_three_failure_kinds_are_answered_separately(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.unshield")["exposure_after_erroneous_acceptance"].pop("transparent_minting"))
        self.assert_fails(run("check_effects", matrix), "answers exactly ['hidden_inflation', 'reserve_theft', 'transparent_minting']")
        matrix = edited(lambda m: effect(m, "orchard.unshield")["exposure_after_erroneous_acceptance"].update(inflation={"possible": "yes"}))
        self.assert_fails(run("check_effects", matrix), "answers exactly")

    def test_each_answer_needs_a_bound(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.unshield")["exposure_after_erroneous_acceptance"]["reserve_theft"].pop("bound"))
        self.assert_fails(run("check_effects", matrix), "exposure reserve_theft.bound says what limits it")
        matrix = edited(lambda m: effect(m, "orchard.unshield")["exposure_after_erroneous_acceptance"]["reserve_theft"].update(possible="maybe"))
        self.assert_fails(run("check_effects", matrix), "exposure reserve_theft.possible must be one of")
        matrix = edited(lambda m: effect(m, "orchard.unshield")["exposure_after_erroneous_acceptance"].pop("summary"))
        self.assert_fails(run("check_effects", matrix), "exposure needs a `summary`")

    def test_no_minting_needs_an_invariant_that_justifies_it(self) -> None:
        def edit(matrix: dict) -> None:
            item = effect(matrix, "zk_ace.transfer")
            item["effect_status"] = "gated"
            item["invariants"] = [record for record in item["invariants"] if record["kind"] != "existing_asset_movement"]
        self.assert_fails(self._exposure(edited(edit), "zk_ace.transfer"),
                          "`transparent_minting: no` needs an enforced invariant of kind")

    def _exposure(self, matrix: dict, identifier: str) -> list[str]:
        checker = C.Checker(matrix, C.readers.Tree())
        item = effect(matrix, identifier)
        checker.check_exposure(item, f"effect {identifier}", protocol(matrix, item["protocol"]), True)
        return checker.errors

    def test_effect_without_a_proof_says_who_authorizes_it(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.pool_bootstrap")["proof"].pop("why"))
        self.assert_fails(run("check_effects", matrix), "says who authorizes it under proof.why")
        matrix = edited(lambda m: effect(m, "orchard.pool_bootstrap")["exposure_after_erroneous_acceptance"]["reserve_theft"].update(possible="yes"))
        self.assert_fails(run("check_effects", matrix), "without a proof every exposure answer is not_applicable")
        matrix = edited(lambda m: effect(m, "orchard.pool_bootstrap").pop("proof"))
        self.assert_fails(run("check_effects", matrix), "proof.authorizes says whether a proof authorizes this effect")


class MutationTests(Base):
    def test_proof_authorized_effect_needs_a_verifier_fault_test_or_an_open_defect(self) -> None:
        def edit(matrix: dict) -> None:
            item = effect(matrix, "pq_masp.transfer")
            for test in item["mutation_tests"]:
                test.pop("verifier_fault", None)
        self.assert_fails(run("check_effects", edited(edit)), "effect pq_masp.transfer: a proof-authorized effect has a verifier-fault mutation test")

    def test_reachable_effect_needs_a_test_or_a_defect(self) -> None:
        matrix = edited(lambda m: effect(m, "voting.plain_ballot_lock").update(mutation_tests=[]))
        self.assert_fails(run("check_effects", matrix), "cites a mutation test or an open defect for the missing one")

    def test_missing_test_fails(self) -> None:
        overrides = replaced(HARNESS_TESTS, "fn faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance()",
                             "fn renamed_withdrawal_test()")
        errors = run("check_effects", overrides=overrides)
        self.assert_fails(errors, "test faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance not found")

    def test_ignored_test_fails(self) -> None:
        overrides = replaced(HARNESS_TESTS, "#[test]\nfn faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance()",
                             "#[test]\n#[ignore]\nfn faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance()")
        self.assert_fails(run("check_effects", overrides=overrides), "is #[ignore]d")

    def test_function_without_the_test_attribute_fails(self) -> None:
        overrides = replaced(HARNESS_TESTS, "#[test]\nfn faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance()",
                             "fn faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance()")
        self.assert_fails(run("check_effects", overrides=overrides), "has no #[test] attribute")

    def test_test_must_name_what_it_exercises(self) -> None:
        text = source(HARNESS_TESTS)
        gutted = text.replace("apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &withdrawal(", "skip(&mut transaction, &BOB_ID, &withdrawal(")
        self.assertNotEqual(text, gutted)
        errors = run("check_effects", overrides={HARNESS_TESTS: gutted})
        self.assert_fails(errors, "test faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance does not name `apply_faulty_verifier_pool_effect`")

    def test_asserted_rejection_text_must_be_in_the_test(self) -> None:
        overrides = replaced(HARNESS_TESTS, '"does not match governed reserve custody"', '"refused"')
        errors = run("check_effects", overrides=overrides)
        self.assert_fails(errors, "does not contain the rejection text `does not match governed reserve custody`")

    def test_asserted_rejection_text_must_be_at_an_enforcement_site(self) -> None:
        text = source(ASSETS).replace("does not match governed reserve custody", "is refused")
        errors = run("check_effects", overrides={ASSETS: text})
        self.assert_fails(errors, "is in no enforcement-site file of the effect")

    def test_feature_gate_of_a_cited_test_must_be_recorded(self) -> None:
        def edit(matrix: dict) -> None:
            effect(matrix, "voting.zk_ballot_lock")["mutation_tests"][0].pop("feature")
        self.assert_fails(run("check_effects", edited(edit)), "is gated by feature 'zk-tests', recorded None")

    def test_cited_test_needs_status_and_what_it_shows(self) -> None:
        matrix = edited(lambda m: effect(m, "orchard.unshield")["mutation_tests"][0].pop("shows"))
        self.assert_fails(run("check_effects", matrix), "must say what it `shows`")
        matrix = edited(lambda m: effect(m, "orchard.unshield")["mutation_tests"][0].update(status="planned"))
        self.assert_fails(run("check_effects", matrix), "needs `status` in")

    def test_harness_must_be_compiled(self) -> None:
        overrides = replaced(ASSETS, INCLUDE, "// include removed")
        self.assert_fails(run("check_effects", overrides=overrides), "so the harness is not compiled")

    def test_harness_must_be_test_only(self) -> None:
        text = source(ASSETS)
        self.assertIn(INCLUDE, text)
        production = text.replace(INCLUDE, "// moved", 1) + f"\nmod production_copy {{\n    {INCLUDE}\n}}\n"
        errors = run("check_effects", overrides={ASSETS: production})
        self.assert_fails(errors, "a verifier-fault harness must be test-only")

    def test_harness_symbol_must_exist(self) -> None:
        overrides = replaced(HARNESS_TESTS, "fn apply_faulty_verifier_pool_effect(", "fn apply_effect(")
        self.assert_fails(run("check_effects", overrides=overrides), "harness: `fn apply_faulty_verifier_pool_effect(` is not in")


class RootPolicy(Base):
    def test_required_answer_is_none_and_holds_is_false_while_a_switch_is_recorded(self) -> None:
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"].update(required="allowed"))
        self.assert_fails(run("check_root_policy", matrix), "required must be `none`")
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"].update(holds=True))
        self.assert_fails(run("check_root_policy", matrix), "holds must be false while a switch is recorded")
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"].update(found=[]))
        self.assert_fails(run("check_root_policy", matrix), "holds must be true when no switch is recorded")

    def test_switch_needs_site_effects_and_an_owned_defect(self) -> None:
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"]["found"][0].pop("defect"))
        self.assert_fails(run("check_root_policy", matrix), "a suspension switch is an open defect with an owner")
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"]["found"][0].pop("effect_on_exits"))
        self.assert_fails(run("check_root_policy", matrix), "`effect_on_exits` is missing")
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"]["found"][0]["site"].update(symbol="Gone(State),"))
        self.assert_fails(run("check_root_policy", matrix), "`Gone(State),` is not in")
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"]["found"][0].update(defect="D-POOL-NO-TURNSTILE-OR-CAP"))
        self.assert_fails(run("check_root_policy", matrix), "is not of kind suspension_switch")

    def test_cited_census_entry_must_exist_and_be_open(self) -> None:
        census = document(C.CENSUS)
        next(entry for entry in census["entries"] if entry["id"] == "privacy.activation")["status"] = "done"
        errors = run("check_root_policy", overrides={C.CENSUS: json.dumps(census)})
        self.assert_fails(errors, "census entry `privacy.activation` is done; the switch is recorded as open here")
        matrix = edited(lambda m: m["root_policy"]["generic_suspension_switch"]["found"][0].update(census="privacy.gone"))
        self.assert_fails(run("check_root_policy", matrix), "census entry `privacy.gone` is not in")

    def test_new_suspension_word_in_a_recorded_file_fails(self) -> None:
        overrides = inserted_after(HANDLERS, "impl Execute for PublishPrivacyRootV1 {", "\n    fn suspend_pool_roots() {}\n")
        errors = run("check_root_policy", overrides=overrides)
        self.assert_fails(errors, f"root_policy.suspension_census: {HANDLERS} has 1 suspension words and is not recorded")

    def test_census_count_drift_and_stale_file_fail(self) -> None:
        overrides = inserted_after(PROTOCOL_MODEL, "pub enum PrivacyRootRoleV1 {", "\n    /// New.\n    EmergencyHalt,")
        self.assert_fails(run("check_root_policy", overrides=overrides), f"{PROTOCOL_MODEL} has ")

        def edit(matrix: dict) -> None:
            matrix["root_policy"]["suspension_census"]["files"].append(
                {"path": HANDLERS, "count": 1, "class": "word_only", "note": "x"})
        self.assert_fails(run("check_root_policy", edited(edit)), f"{HANDLERS} is recorded and has no suspension word")

    def test_census_file_needs_class_note_and_defect(self) -> None:
        matrix = edited(lambda m: m["root_policy"]["suspension_census"]["files"][0].update({"class": "other"}))
        self.assert_fails(run("check_root_policy", matrix), "needs `class` in")
        matrix = edited(lambda m: m["root_policy"]["suspension_census"]["files"][0].pop("defects"))
        self.assert_fails(run("check_root_policy", matrix), "is a lifecycle switch and cites no defect")

    def test_publication_and_history_sites_are_checked(self) -> None:
        matrix = edited(lambda m: m["root_policy"]["publication"].update(sites=[]))
        self.assert_fails(run("check_root_policy", matrix), "root_policy.publication: cites at least one site")
        overrides = replaced("crates/iroha_data_model/src/privacy/policy.rs",
                             "pub const fn admission_retained_root_count(&self) -> u32 {", "pub const fn retained(&self) -> u32 {")
        self.assert_fails(run("check_root_policy", overrides=overrides), "root_policy.history: `pub const fn admission_retained_root_count")
        matrix = edited(lambda m: m["root_policy"]["history"].pop("statement"))
        self.assert_fails(run("check_root_policy", matrix), "root_policy.history: needs a `statement`")
        self.assert_fails(run("check_root_policy", edited(lambda m: m["root_policy"].pop("history"))), "`history` is missing")


class Defects(Base):
    def test_owner_is_a_task_of_the_graph_and_never_this_task(self) -> None:
        matrix = edited(lambda m: defect(m, "D-POOL-NO-TURNSTILE-OR-CAP").update(owner=["Z.9"]))
        self.assert_fails(run(None, matrix), "defect D-POOL-NO-TURNSTILE-OR-CAP: owner `Z.9` is not in")
        matrix = edited(lambda m: defect(m, "D-POOL-NO-TURNSTILE-OR-CAP").update(owner=["F.3"]))
        self.assert_fails(run(None, matrix), "the matrix records defects, it does not own their repair")
        matrix = edited(lambda m: defect(m, "D-POOL-NO-TURNSTILE-OR-CAP").update(owner=[]))
        self.assert_fails(run(None, matrix), "`owner` lists the tasks that close it")

    def test_defect_site_must_exist(self) -> None:
        matrix = edited(lambda m: defect(m, "D-IVM-GENESIS-NOTES-UNBACKED").update(symbol="fn gone("))
        self.assert_fails(run(None, matrix), "defect D-IVM-GENESIS-NOTES-UNBACKED: `fn gone(` is not in")

    def test_defect_shape_is_checked(self) -> None:
        matrix = edited(lambda m: defect(m, "D-IVM-GENESIS-NOTES-UNBACKED").update(kind="bug"))
        self.assert_fails(run(None, matrix), "kind must be one of")
        matrix = edited(lambda m: defect(m, "D-IVM-GENESIS-NOTES-UNBACKED").pop("required"))
        self.assert_fails(run(None, matrix), "`required` is missing")
        matrix = edited(lambda m: defect(m, "D-IVM-GENESIS-NOTES-UNBACKED").pop("line"))
        self.assert_fails(run(None, matrix), "records the `line` of its site")

    def test_unreferenced_defect_fails(self) -> None:
        def edit(matrix: dict) -> None:
            added = copy.deepcopy(defect(matrix, "D-POOL-NO-TURNSTILE-OR-CAP"))
            added["id"] = "D-ORPHAN"
            matrix["defects"].append(added)
        self.assert_fails(run(None, edited(edit)), "defect D-ORPHAN: nothing in the matrix references it")

    def test_stale_line_is_a_note_unless_strict(self) -> None:
        matrix = edited(lambda m: defect(m, "D-POOL-NO-TURNSTILE-OR-CAP").update(line=1))
        checker = C.Checker(matrix, C.readers.Tree())
        self.assertEqual(checker.check(), [])
        self.assertTrue(any("defect D-POOL-NO-TURNSTILE-OR-CAP: `line` 1 is stale" in note for note in checker.notes))
        self.assert_fails(run(None, matrix, strict=True), "defect D-POOL-NO-TURNSTILE-OR-CAP: `line` 1 is stale")

    def test_refresh_rewrites_a_stale_line(self) -> None:
        matrix = edited(lambda m: defect(m, "D-POOL-NO-TURNSTILE-OR-CAP").update(line=1))
        changes = C.Checker(matrix, C.readers.Tree()).refresh()
        self.assertTrue(any(change.startswith("defects[D-POOL-NO-TURNSTILE-OR-CAP].line 1 ->") for change in changes), changes)
        record = defect(matrix, "D-POOL-NO-TURNSTILE-OR-CAP")
        text = source(record["path"])
        self.assertIn(record["symbol"], text.splitlines()[record["line"] - 1])
        self.assert_clean(run(None, matrix, strict=True))


class Requirements(Base):
    def test_requirement_newly_mapped_to_the_task_must_be_addressed(self) -> None:
        ledger = document(C.LEDGER)
        other = next(item for item in ledger["requirements"] if "F.3" not in item["task_ids"])
        other["task_ids"].append("F.3")
        errors = run("check_requirements", overrides={C.LEDGER: json.dumps(ledger)})
        self.assert_fails(errors, f"source has ['{other['id']}'] unrecorded")

    def test_addressed_requirement_must_be_mapped_and_resolve(self) -> None:
        matrix = edited(lambda m: m["requirements"]["addressed"].append({"id": "REQ-001", "where": ["effects/orchard.unshield"]}))
        self.assert_fails(run("check_requirements", matrix), "the matrix has ['REQ-001'] stale")
        matrix = edited(lambda m: m["requirements"]["addressed"][0].update(where=["effects/nowhere"]))
        self.assert_fails(run("check_requirements", matrix), "`effects/nowhere` does not resolve in the matrix")
        matrix = edited(lambda m: m["requirements"]["addressed"][0].update(where=[]))
        self.assert_fails(run("check_requirements", matrix), "`where` lists the sections that address it")


class Summary(Base):
    def test_summary_is_recomputed(self) -> None:
        matrix = edited(lambda m: m["summary"].update(effects=1))
        self.assert_fails(run("check_summary", matrix), "summary differs from the recomputed counts")

    def test_summary_counts_what_the_matrix_holds(self) -> None:
        summary = MATRIX["summary"]
        self.assertEqual(summary["effects"], len(MATRIX["effects"]))
        self.assertEqual(summary["operations"], len(MATRIX["operations"]))
        self.assertEqual(sum(summary["effects_by_class"].values()), summary["effects"])
        self.assertEqual(sum(summary["effects_by_status"].values()), summary["effects"])
        self.assertEqual(summary["added_tests"], 9)
        self.assertEqual(summary["defects"], len(MATRIX["defects"]))


class Readers(Base):
    def test_arm_span_reads_a_block_arm_and_an_expression_arm(self) -> None:
        code = "match x { A::B(v) => { one(v); two() }, A::C => three(1, [2, 3]), A::D => four() }"
        start, end = C.arm_span(code, code.index("A::B"))
        self.assertEqual(code[start:end], "{ one(v); two() }")
        start, end = C.arm_span(code, code.index("A::C"))
        self.assertEqual(code[start:end], "three(1, [2, 3])")
        start, end = C.arm_span(code, code.index("A::D"))
        self.assertEqual(code[start:end].strip(), "four()")

    def test_block_span_reads_functions_impls_and_arms(self) -> None:
        text = "impl Execute for T {\n    fn execute(self) -> Result<(), E> { body() }\n}\nfn other(a: u8) -> u8 { match a { 1 => { one() } _ => two(), } }\n"
        span = C.block_span(text, "impl Execute for T {")
        self.assertIn("body()", text[span[0] : span[1]])
        self.assertNotIn("other", text[span[0] : span[1]])
        span = C.block_span(text, "fn other(")
        self.assertIn("two()", text[span[0] : span[1]])
        span = C.block_span(text, "1 => {")
        self.assertEqual(text[span[0] : span[1]], "{ one() }")
        self.assertIsNone(C.block_span(text, "fn missing("))

    def test_word_in_matches_identifiers_and_prefixes(self) -> None:
        self.assertTrue(C.word_in("let q = Quantity::from(1);", "Quantity"))
        self.assertFalse(C.word_in("let q = BigQuantityLike::new();", "Quantity"))
        self.assertTrue(C.word_in("execute_verified_privacy_public_balance_transfer(x)", "execute_verified_"))
        self.assertFalse(C.word_in("pre_execute_verified_thing(x)", "execute_verified_"))

    def test_absence_scopes_accepts_one_scope_or_a_list(self) -> None:
        self.assertEqual(C.absence_scopes({"absence": {"path": "a"}}), [{"path": "a"}])
        self.assertEqual(C.absence_scopes({"absence": [{"path": "a"}, {"path": "b"}]}), [{"path": "a"}, {"path": "b"}])
        self.assertEqual(C.absence_scopes({}), [])

    def test_line_of_counts_from_one(self) -> None:
        self.assertEqual(C.line_of("a\nb\nc", 0), 1)
        self.assertEqual(C.line_of("a\nb\nc", 4), 3)


if __name__ == "__main__":
    unittest.main()
