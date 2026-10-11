"""Drift tests for the unified resource contract checker."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from runpy import run_path

import pytest


CHECKER = run_path(
    str(Path(__file__).resolve().parents[1] / "check_zk_resource_contract.py")
)
ROOT = CHECKER["ROOT"]
CONTRACT = json.loads(CHECKER["CONTRACT"].read_text(encoding="utf-8"))
TASKS = CHECKER["load_tasks"](CHECKER["GRAPH"])
MIB = 1024 * 1024
GIB = 1024 * MIB


def problems(contract: dict, tasks: dict | None = None) -> list:
    return CHECKER["check"](ROOT, contract, TASKS if tasks is None else tasks)


def edited(edit) -> dict:
    contract = copy.deepcopy(CONTRACT)
    edit(contract)
    return contract


def bound(contract: dict, identifier: str) -> dict:
    return next(item for item in contract["bounds"] if item["id"] == identifier)


def relation(contract: dict, identifier: str) -> dict:
    return next(item for item in contract["relations"] if item["id"] == identifier)


def assert_fails(contract: dict, fragment: str, tasks: dict | None = None) -> None:
    found = problems(contract, tasks)
    assert any(fragment in problem for problem in found), found


def test_tracked_contract_matches_the_source() -> None:
    assert problems(CONTRACT) == []
    assert CHECKER["main"]([]) == 0


def test_contract_covers_every_group_stage_and_class() -> None:
    groups = {item["group"] for item in CONTRACT["bounds"]} | {
        item["group"] for item in CONTRACT["declared"]
    }
    assert groups == set(CHECKER["GROUPS"])
    stages = {
        site["stage"] for item in CONTRACT["bounds"] for site in item.get("enforcement", [])
    }
    assert stages == set(CHECKER["STAGES"])
    assert {item["class"] for item in CONTRACT["bounds"]} == set(CHECKER["CLASSES"])
    assert {item["source"] for item in CONTRACT["bounds"]} == set(CHECKER["SOURCES"])
    # Every bound names one owner symbol in one file.
    for item in CONTRACT["bounds"]:
        assert (ROOT / item["owner"]["path"]).is_file(), item["id"]


def test_fixed_x509_bounds_are_preserved_and_classed() -> None:
    expected = {
        "x509.max_proof_bytes": (9_437_184, "consensus"),
        "transaction.max_tx_bytes": (10_485_760, "consensus"),
        "x509.max_crl_age_seconds": (300, "consensus"),
        "x509.max_presentation_window_seconds": (300, "consensus"),
        "x509.prover_target_seconds": (300, "engineering_target"),
        "x509.prover_peak_rss_bytes": (12 * GIB, "local_defer"),
        "x509.prover_address_space_bytes": (32 * GIB, "local_defer"),
    }
    assert CHECKER["FIXED_BOUNDS"] == {key: value for key, (value, _) in expected.items()}
    for identifier, (value, klass) in expected.items():
        item = bound(CONTRACT, identifier)
        assert (item["value"], item["class"], item["fixed"]) == (value, klass, True)
    for identifier in CHECKER["FIXED_NON_VALIDITY"]:
        assert bound(CONTRACT, identifier)["validity"] is False
    # The validity bounds and the targets partition the fixed bounds.
    assert set(CHECKER["FIXED_VALIDITY"]) | set(CHECKER["FIXED_NON_VALIDITY"]) == set(expected)
    assert not set(CHECKER["FIXED_VALIDITY"]) & set(CHECKER["FIXED_NON_VALIDITY"])


def test_the_crl_age_is_a_validity_bound_and_the_prover_time_is_a_target() -> None:
    """Two fixed bounds have the value 300: one decides validity, the other never does."""
    age = bound(CONTRACT, "x509.max_crl_age_seconds")
    window = bound(CONTRACT, "x509.max_presentation_window_seconds")
    target = bound(CONTRACT, "x509.prover_target_seconds")
    assert age["value"] == window["value"] == target["value"] == 300
    assert age["owner"]["symbol"] == "ZK_X509_MAX_CRL_AGE_SECONDS_V1"
    assert target["owner"]["symbol"] == "ZK_X509_PROVER_TARGET_SECONDS_V1"
    assert window["refs"] == {"ZK_X509_MAX_CRL_AGE_SECONDS_V1": "x509.max_crl_age_seconds"}
    for item in (age, window):
        assert item["class"] == "consensus" and item["enforcement"] and item["tests"]
        assert {site["stage"] for site in item["enforcement"]} >= {"sdk", "follower"}
    assert target["class"] == "engineering_target" and "enforcement" not in target
    assert relation(CONTRACT, "x509_presentation_window_within_crl_age")["expect"]["today"] == "holds"

    for identifier in ("x509.max_crl_age_seconds", "x509.max_presentation_window_seconds"):

        def relaxed(contract: dict, identifier: str = identifier) -> None:
            bound(contract, identifier)["value"] = 600

        assert_fails(edited(relaxed), f"{identifier}: the delivery plan fixes 300")

        def demoted(contract: dict, identifier: str = identifier) -> None:
            item = bound(contract, identifier)
            item["class"] = "engineering_target"
            item["validity"] = False
            del item["enforcement"]

        assert_fails(edited(demoted), f"{identifier}: a fixed validity bound is classed consensus")

        def untested(contract: dict, identifier: str = identifier) -> None:
            del bound(contract, identifier)["tests"]

        assert_fails(edited(untested), f"{identifier}: a fixed validity bound is classed consensus")

        def removed(contract: dict, identifier: str = identifier) -> None:
            contract["bounds"] = [item for item in contract["bounds"] if item["id"] != identifier]
            contract["relations"] = [
                item for item in contract["relations"] if identifier not in item["expr"]
            ]

        assert_fails(edited(removed), f"{identifier}: the fixed bound is missing")


@pytest.mark.parametrize("identifier", sorted(CHECKER["FIXED_BOUNDS"]))
def test_relaxing_a_fixed_bound_fails(identifier: str) -> None:
    def relax(contract: dict) -> None:
        bound(contract, identifier)["value"] += 1

    assert_fails(edited(relax), f"{identifier}: the delivery plan fixes")

    def unfix(contract: dict) -> None:
        del bound(contract, identifier)["fixed"]

    assert_fails(edited(unfix), f"{identifier}: the bound is recorded `fixed: true`")


@pytest.mark.parametrize("identifier", CHECKER["FRAMED_BOUNDS"])
def test_measured_lengths_state_their_framing(identifier: str) -> None:
    assert bound(CONTRACT, identifier)["framing"]

    def silent(contract: dict) -> None:
        del bound(contract, identifier)["framing"]

    assert_fails(edited(silent), f"{identifier}: states in `framing`")


def test_time_and_memory_targets_can_never_be_consensus_validity() -> None:
    def promote(contract: dict) -> None:
        item = bound(contract, "x509.prover_target_seconds")
        item["class"] = "consensus"
        item["enforcement"] = [
            {"stage": "follower", "path": item["owner"]["path"], "contains": "300"}
        ]

    assert_fails(edited(promote), "is never consensus validity")

    def promote_memory(contract: dict) -> None:
        bound(contract, "x509.prover_peak_rss_bytes")["class"] = "consensus"

    assert_fails(edited(promote_memory), "is never consensus validity")

    def enforce(contract: dict) -> None:
        bound(contract, "x509.prover_target_seconds")["enforcement"] = [
            {"stage": "follower", "path": "specs/zk_resource_contract.json", "contains": "x"}
        ]

    assert_fails(edited(enforce), "an engineering target has no enforcement site")

    def validity(contract: dict) -> None:
        bound(contract, "x509.prover_target_seconds")["validity"] = True

    assert_fails(edited(validity), "an engineering target records `validity: false`")


def test_prover_limits_name_where_the_prover_applies_them() -> None:
    rss = bound(CONTRACT, "x509.prover_peak_rss_bytes")
    assert rss["on_exhaustion"] == "prover_failure" and rss["enforcement"] and rss["tests"]
    assert rss["observations"], "the RSS observation stays recorded as the engineering target"

    def unsited(contract: dict) -> None:
        del bound(contract, "x509.prover_peak_rss_bytes")["enforcement"]

    assert_fails(edited(unsited), "a prover-side limit names where the prover applies it")

    def drifted(contract: dict) -> None:
        bound(contract, "x509.prover_peak_rss_bytes")["observations"][0]["contains"] = "gone"

    assert_fails(edited(drifted), "no longer contains `gone`")


def test_committed_time_budgets_are_local_scheduling_limits() -> None:
    """REQ-117: consensus limits, local scheduling limits and targets are three things."""
    for identifier, on_exceed in (
        ("work_budget.exec_budget_ms", "retry"),
        ("work_budget.apply_budget_ms", "replan"),
    ):
        item = bound(CONTRACT, identifier)
        assert (item["class"], item["source"]) == ("local_schedule", "committed")
        assert item["on_exceed"] == on_exceed and item["validity"] is False
        assert item["enforcement"] and item["tests"]
    sites = {
        site["path"] for site in bound(CONTRACT, "work_budget.exec_budget_ms")["enforcement"]
    }
    assert "crates/iroha_core/src/sumeragi/executor.rs" in sites
    assert "crates/iroha_sumeragi/src/machine/propose.rs" in sites

    def target(contract: dict) -> None:
        bound(contract, "work_budget.exec_budget_ms")["class"] = "engineering_target"

    assert_fails(edited(target), "an engineering target has no enforcement site")

    def unsited(contract: dict) -> None:
        del bound(contract, "work_budget.exec_budget_ms")["enforcement"]

    assert_fails(edited(unsited), "a local scheduling limit names where it is applied")

    def rejecting(contract: dict) -> None:
        bound(contract, "work_budget.exec_budget_ms")["on_exceed"] = "reject"

    assert_fails(edited(rejecting), "records `on_exceed` as `retry` or `replan`")

    def validity(contract: dict) -> None:
        bound(contract, "work_budget.apply_budget_ms")["validity"] = True

    assert_fails(edited(validity), "a local scheduling limit records `validity: false`")

    def untested(contract: dict) -> None:
        del bound(contract, "work_budget.apply_budget_ms")["tests"]

    assert_fails(edited(untested), "a local scheduling limit names its tests")


def test_value_and_expression_drift_fail() -> None:
    def value(contract: dict) -> None:
        bound(contract, "block.max_block_bytes")["value"] = 16 * MIB

    assert_fails(edited(value), "block.max_block_bytes: `max_block_bytes` evaluates to 4194304")

    def expression(contract: dict) -> None:
        bound(contract, "transport.frame_overhead_bytes")["owner"]["expr"] = "64 * 1024"

    assert_fails(edited(expression), "transport.frame_overhead_bytes: `FRAME_OVERHEAD` in")

    def symbol(contract: dict) -> None:
        bound(contract, "transaction.max_tx_bytes")["owner"]["symbol"] = "max_tx_bytes_gone"

    assert_fails(edited(symbol), "`max_tx_bytes_gone` is not defined")

    def path(contract: dict) -> None:
        bound(contract, "transaction.max_tx_bytes")["owner"]["path"] = "crates/missing.rs"

    assert_fails(edited(path), "crates/missing.rs does not exist")


def test_a_failed_reference_fails_every_bound_derived_from_it() -> None:
    def wrong(contract: dict) -> None:
        bound(contract, "transport.max_committee_size")["value"] = 1

    found = problems(edited(wrong))
    assert any(problem.startswith("transport.max_committee_size:") for problem in found)
    assert any(
        "transport.frame_overhead_bytes: `refs` names transport.max_committee_size" in problem
        for problem in found
    )
    # The chain frame limit is derived from the frame overhead in turn.
    assert any("transport.chain_frame_limit_bytes: `refs` names" in problem for problem in found)

    def unknown(contract: dict) -> None:
        bound(contract, "transport.frame_overhead_bytes")["refs"]["MAX_COMMITTEE_SIZE"] = "no.such"

    assert_fails(edited(unknown), "which is not a bound")

    def missing(contract: dict) -> None:
        del bound(contract, "transport.frame_overhead_bytes")["refs"]["MAX_COMMITTEE_SIZE"]

    assert_fails(edited(missing), "has no entry in `refs`")


def test_enforcement_site_and_test_drift_fail() -> None:
    def site(contract: dict) -> None:
        bound(contract, "transaction.max_tx_bytes")["enforcement"][3]["contains"] = (
            "if tx_encoded_len >= max_tx_bytes {"
        )

    assert_fails(edited(site), "no longer contains `if tx_encoded_len >= max_tx_bytes {`")

    def stage(contract: dict) -> None:
        bound(contract, "transaction.max_tx_bytes")["enforcement"][0]["stage"] = "wallet"

    assert_fails(edited(stage), "unknown stage 'wallet'")

    def named(contract: dict) -> None:
        bound(contract, "block.max_block_bytes")["tests"][0]["name"] = "no_such_test"

    assert_fails(edited(named), "test `no_such_test` is not in")

    def stripped(contract: dict) -> None:
        del bound(contract, "block.max_block_bytes")["enforcement"]

    assert_fails(edited(stripped), "a consensus bound lists its enforcement sites")


def test_relation_expectations_are_evaluated_under_every_profile() -> None:
    today = relation(CONTRACT, "transaction_cap_fits_block_payload")
    assert today["expect"] == {"today": "violated", "x2_target": "holds"}
    feasible = relation(CONTRACT, "committed_payload_has_a_feasible_sync_setting")
    assert feasible["expect"] == {"today": "holds", "x2_target": "violated"}

    def flip_today(contract: dict) -> None:
        relation(contract, "transaction_cap_fits_block_payload")["expect"]["today"] = "holds"

    assert_fails(edited(flip_today), "violated under `today`; the contract records holds")

    def flip_target(contract: dict) -> None:
        relation(contract, "sync_response_serves_committed_payload")["expect"][
            "x2_target"
        ] = "holds"

    assert_fails(edited(flip_target), "violated under `x2_target`; the contract records holds")

    def ownerless(contract: dict) -> None:
        del relation(contract, "gossip_frame_carries_max_transaction")["open"]

    assert_fails(edited(ownerless), "is not a task of the delivery graph")

    def unknown(contract: dict) -> None:
        relation(contract, "block_payload_within_rs16_payload")["expr"] = (
            "block.max_block_bytes <= rs16.no_such_bound"
        )

    assert_fails(edited(unknown), "unknown or open bound `rs16.no_such_bound`")

    def not_boolean(contract: dict) -> None:
        relation(contract, "block_payload_within_rs16_payload")["expr"] = (
            "block.max_block_bytes + 1"
        )

    assert_fails(edited(not_boolean), "the expression is not a comparison")

    def profile(contract: dict) -> None:
        contract["profiles"]["x2_target"]["overrides"]["block.no_such"] = 1

    assert_fails(edited(profile), "profile x2_target: unknown bound `block.no_such`")


def test_relation_values_are_the_recorded_arithmetic() -> None:
    values = {item["id"]: item["value"] for item in CONTRACT["bounds"]}
    evaluate = CHECKER["evaluate_relation"]
    # Today: the 10 MiB cap plus the reserve does not fit the 4 MiB payload.
    assert values["transaction.max_tx_bytes"] + 65_536 == 10_551_296
    assert values["block.max_block_bytes"] == 4_194_304
    # The includable bound queue admission and the proposer share today.
    assert (
        evaluate(
            "min(transaction.max_tx_bytes, block.max_block_bytes - "
            "block.payload_transaction_reserve_bytes)",
            values,
            "test",
        )
        == 4_128_768
    )
    assert values["transport.frame_overhead_bytes"] == 264_224
    assert values["transport.chain_frame_limit_bytes"] == 17_041_440
    # A 16 MiB payload needs 17,305,664 bytes of frame for a sync response.
    target = {**values, "block.max_block_bytes": 16 * MIB}
    assert (
        evaluate(
            "block.max_block_bytes + 2 * transport.frame_overhead_bytes", target, "test"
        )
        == 17_305_664
    )
    assert values["transport.max_plaintext_frame_bytes"] == 17_825_792
    # The largest payload for which a feasible sync setting exists today.
    assert (
        evaluate(
            "transport.chain_frame_limit_bytes - 2 * transport.frame_overhead_bytes",
            values,
            "test",
        )
        == 16_512_992
    )
    assert evaluate("ceil_div(7, 2) == 4 and max(1, 2) == 2", values, "test") is True


def test_node_local_validity_bounds_are_defects_owned_by_a_task() -> None:
    defects = {
        item["id"]: item["defect"]["owner"]
        for item in CONTRACT["bounds"]
        if item["class"] == "consensus" and item["source"] == "node_local"
    }
    assert defects, "today's node-local validity bounds are recorded"
    assert set(defects.values()) == {"F.4"}
    assert "storage.config_da_ingest_quota_max_bytes_per_account" in defects
    assert "proof.config_private_settlement_max_proof_bytes" in defects
    # F.4 moved the ZK consensus-policy hash inventory (45 bounds) and the
    # execution limits of the pipeline (15 bounds) into committed State: they are
    # no longer node-local defects and name the committed policy. The ten
    # [nexus] bounds remain.
    assert len(defects) == 10
    pipeline_policy = [
        item
        for item in CONTRACT["bounds"]
        if item.get("catalog", {}).get("id") == "execution_policy_digest_v1"
    ]
    assert len(pipeline_policy) == 15
    for item in pipeline_policy:
        assert item["source"] == "committed" and "defect" not in item, item["id"]
        assert item["committed_as"].startswith("pipeline_validity_policy_v1 "), item["id"]
    zk_policy = [
        item
        for item in CONTRACT["bounds"]
        if item.get("catalog", {}).get("id") == "zk_consensus_policy_hash"
    ]
    assert len(zk_policy) == 45
    for item in zk_policy:
        assert item["source"] == "committed" and "defect" not in item, item["id"]
        assert item["committed_as"].startswith("zk_validity_policy_v1 "), item["id"]

    def undeclared(contract: dict) -> None:
        del bound(contract, "storage.config_da_ingest_quota_max_bytes_per_account")["defect"]

    assert_fails(edited(undeclared), "must be recorded as a defect with an owner task")

    def ownerless(contract: dict) -> None:
        bound(contract, "storage.config_da_ingest_quota_max_bytes_per_account")["defect"][
            "owner"
        ] = "Z.9"

    assert_fails(edited(ownerless), "owner `Z.9` is not a task of the delivery graph")

    def uncommitted(contract: dict) -> None:
        del bound(contract, "proof.config_pipa_r_max_proof_bytes")["committed_as"]

    assert_fails(edited(uncommitted), "a committed bound names `committed_as`")


def test_local_resources_defer_or_are_guarded_by_a_relation() -> None:
    for item in CONTRACT["bounds"]:
        if item["class"] != "local_defer":
            continue
        assert item["validity"] is False, item["id"]
        assert item["on_exhaustion"] in ("defer", "local_refusal", "prover_failure")
        if item["on_exhaustion"] == "defer":
            assert item["tests"], item["id"]
        if item["on_exhaustion"] == "local_refusal":
            assert relation(CONTRACT, item["guarded_by"]), item["id"]

    def untested(contract: dict) -> None:
        del bound(contract, "decoded_scratch.ivm_execution_pool_bytes")["tests"]

    assert_fails(edited(untested), "names the test of its deferral")

    def unguarded(contract: dict) -> None:
        bound(contract, "sync.local_sync_max_bytes")["guarded_by"] = "no_such_relation"

    assert_fails(edited(unguarded), "names its relation in `guarded_by`")

    def rejecting(contract: dict) -> None:
        bound(contract, "queue.capacity")["on_exhaustion"] = "reject"

    assert_fails(edited(rejecting), "records `on_exhaustion` as")

    def validity(contract: dict) -> None:
        del bound(contract, "queue.capacity")["validity"]

    assert_fails(edited(validity), "a local resource records `validity: false`")


def test_ram_lfe_budgets_are_derived_and_open_ones_carry_no_number() -> None:
    section = CONTRACT["ram_lfe"]
    by_id = {budget["id"]: budget for budget in section["budgets"]}
    open_ids = {item["id"] for item in section["open_inputs"]}
    assert by_id["ram_lfe.tape_bytes"]["value"] == 256 * 48
    assert by_id["ram_lfe.initial_state_stream_bytes"]["value"] == 32 * 32
    for budget in section["budgets"]:
        is_open = bool(set(budget["inputs"]) & open_ids)
        assert (budget["value"] is None) == is_open, budget["id"]
    assert all(item["value"] is None for item in section["open_inputs"])

    def invented(contract: dict) -> None:
        budget = next(
            item
            for item in contract["ram_lfe"]["budgets"]
            if item["id"] == "ram_lfe.execution_verification_gas"
        )
        budget["value"] = 1_000_000

    assert_fails(edited(invented), "so the value must be null; no number is invented")

    def stale(contract: dict) -> None:
        contract["ram_lfe"]["budgets"][0]["value"] = 1

    assert_fails(edited(stale), "every input is known and the formula gives 12288")

    def undeclared(contract: dict) -> None:
        contract["ram_lfe"]["budgets"][2]["inputs"].pop()

    assert_fails(edited(undeclared), "`inputs` must be exactly the ids the formula uses")

    def closed(contract: dict) -> None:
        contract["ram_lfe"]["open_inputs"][0]["value"] = 4_096

    assert_fails(edited(closed), "a known input is a bound, not an open input")

    def removed(contract: dict) -> None:
        del contract["ram_lfe"]

    assert_fails(edited(removed), "the contract derives the RAM-LFE budgets")


def test_open_items_are_reconciled_when_their_task_is_implemented() -> None:
    assert_fails(CONTRACT, "task X.2 is recorded implemented", {**TASKS, "X.2": "implemented"})
    assert_fails(CONTRACT, "task F.4 is recorded implemented", {**TASKS, "F.4": "implemented"})
    # I.1 implemented its declared design: nothing of it is open any more.
    assert problems(CONTRACT, {**TASKS, "I.1": "implemented"}) == []
    assert_fails(CONTRACT, "task C.3 is recorded implemented", {**TASKS, "C.3": "implemented"})
    # A status that is not `implemented` keeps the open items valid.
    assert problems(CONTRACT, {**TASKS, "X.2": "in_progress"}) == []


def test_declared_items_are_not_yet_implemented_and_state_their_requirements() -> None:
    owners = {item["id"]: item["open"]["owner"] for item in CONTRACT["declared"]}
    assert owners == {
        "transaction.structured_size_refusal": "S.1",
        "vm_handles.invocation_scoped_attachment_handles": "I.2",
        "work_budget.unified_deterministic_charge": "I.4",
        "block.maximum_proof_transport_profile": "X.2",
        "proof.product_proof_ceilings": "V.3",
    }
    relation_ids = {item["id"] for item in CONTRACT["relations"]}
    for item in CONTRACT["declared"]:
        assert item["status"] == "not_implemented"
        assert item["requires"] and item["today"]
        assert set(item["relations"]) <= relation_ids, item["id"]

    def implemented(contract: dict) -> None:
        contract["declared"][0]["status"] = "implemented"

    assert_fails(edited(implemented), "is a bound with an owner, not `declared`")

    def empty(contract: dict) -> None:
        contract["declared"][0]["requires"] = []

    assert_fails(edited(empty), "a declared item lists what it must satisfy")


def test_every_stage_names_its_tests_or_the_task_that_owns_the_gap() -> None:
    by_stage = {entry["stage"]: entry for entry in CONTRACT["stage_tests"]}
    assert set(by_stage) == set(CHECKER["STAGES"])
    for stage, entry in by_stage.items():
        assert entry["tests"] or entry["open"]["owner"] in TASKS, stage
    # The stages that cannot be exercised below a network say so and name their owner.
    assert by_stage["torii"]["open"]["owner"] == "V.2"
    assert by_stage["storage"]["open"]["owner"] == "V.2"
    assert {entry["id"] for entry in CONTRACT["behaviors"]} == set(CHECKER["BEHAVIORS"])

    def dropped(contract: dict) -> None:
        contract["stage_tests"] = [
            entry for entry in contract["stage_tests"] if entry["stage"] != "follower"
        ]

    assert_fails(edited(dropped), "stage_tests: stage `follower` is missing")

    def untested(contract: dict) -> None:
        entry = next(item for item in contract["stage_tests"] if item["stage"] == "proposer")
        entry["tests"] = []

    assert_fails(edited(untested), "names a test or the task that owns the gap")

    def renamed(contract: dict) -> None:
        entry = next(item for item in contract["stage_tests"] if item["stage"] == "vm")
        entry["tests"][0]["name"] = "no_such_vm_test"

    assert_fails(edited(renamed), "test `no_such_vm_test` is not in")

    def silent(contract: dict) -> None:
        contract["behaviors"] = [
            entry
            for entry in contract["behaviors"]
            if entry["id"] != "missing_local_resource_defers"
        ]

    assert_fails(edited(silent), "`missing_local_resource_defers` names the tests")


def test_schema_group_and_duplicate_checks() -> None:
    assert problems({**CONTRACT, "schema": "other"}) == [
        "schema is 'other', expected 'iroha.zk_resource_contract.v1'"
    ]

    def duplicate(contract: dict) -> None:
        contract["bounds"].append(copy.deepcopy(contract["bounds"][0]))

    assert_fails(edited(duplicate), "transaction.max_tx_bytes: duplicate bound id")

    def no_storage(contract: dict) -> None:
        contract["bounds"] = [item for item in contract["bounds"] if item["group"] != "storage"]

    assert_fails(edited(no_storage), "group `storage` has no bound or declared item")

    def no_torii(contract: dict) -> None:
        for item in contract["bounds"]:
            item["enforcement"] = [
                site for site in item.get("enforcement", []) if site["stage"] != "torii"
            ]

    assert_fails(edited(no_torii), "stage `torii` has no enforcement site")

    def unknown_class(contract: dict) -> None:
        bound(contract, "queue.capacity")["class"] = "soft"

    assert_fails(edited(unknown_class), "unknown class 'soft'")


def test_rust_expression_reader_and_evaluator(tmp_path: Path) -> None:
    source = """
    /// Owner.
    pub const BASE: usize = 4 * 1024; // four KiB
    pub const DERIVED: u64 =
        (BASE as u64 + crate::other::EXTRA as u64)
            * 2;
    pub mod first { pub const LIMIT: u32 = 1; }
    pub mod second {
        pub const LIMIT: NonZeroU64 = nonzero!(8_u64 * 2_u64.pow(10));
        pub const fn cap() -> NonZeroU32 {
            // a comment inside the body
            nonzero_ext::nonzero!(0x0010_0000_u32)
        }
        pub fn same() -> NonZeroU32 { cap() }
    }
    impl Default for Limits {
        fn default() -> Self {
            Self { small: 1 << 4, large: NonZeroUsize::new(4096).expect("non-zero") }
        }
    }
    fn policy(self) -> u64 { match self { Self::V1 => 64 * 1024, } }
    """
    extract = CHECKER["extract_expression"]
    evaluate = CHECKER["evaluate_rust"]

    def read(symbol: str, kind: str = "const", anchor: str | None = None) -> str:
        owner = {"path": "x.rs", "symbol": symbol, "kind": kind}
        if anchor:
            owner["anchor"] = anchor
        return extract(source, owner, symbol)

    assert read("BASE") == "4 * 1024"
    assert evaluate(read("BASE"), {}, {}, "t") == 4_096
    derived = read("DERIVED")
    assert derived == "(BASE as u64 + crate::other::EXTRA as u64) * 2"
    values = {"a.base": 4_096, "a.extra": 4}
    refs = {"BASE": "a.base", "crate::other::EXTRA": "a.extra"}
    assert evaluate(derived, refs, values, "t") == 8_200
    # An anchor selects the second of two equal names.
    assert evaluate(read("LIMIT"), {}, {}, "t") == 1
    assert evaluate(read("LIMIT", anchor="pub mod second {"), {}, {}, "t") == 8_192
    assert read("cap", "fn") == "nonzero_ext::nonzero!(0x0010_0000_u32)"
    assert evaluate(read("cap", "fn"), {}, {}, "t") == 1_048_576
    assert evaluate(read("same", "fn"), {"cap": "a.cap"}, {"a.cap": 7}, "t") == 7
    assert evaluate(read("small", "field", "impl Default for Limits"), {}, {}, "t") == 16
    assert evaluate(read("large", "field", "impl Default for Limits"), {}, {}, "t") == 4_096
    assert evaluate(read("Self::V1", "arm", "fn policy"), {}, {}, "t") == 65_536
    error = CHECKER["ContractError"]
    with pytest.raises(error, match="has no entry in `refs`"):
        evaluate(derived, {}, {}, "t")
    with pytest.raises(error, match="refers to unverified bound"):
        evaluate(derived, refs, {"a.base": 1}, "t")
    with pytest.raises(error, match="is not defined"):
        read("ABSENT")
    with pytest.raises(error, match="anchor"):
        read("LIMIT", anchor="pub mod third {")
    with pytest.raises(error, match="is not integer arithmetic"):
        evaluate("1 ^ 2", {}, {}, "t")
    # Only arithmetic and comparisons evaluate; nothing else is executed.
    with pytest.raises(error):
        CHECKER["safe_eval"]("__import__('os').getcwd()", "t")
    with pytest.raises(error):
        CHECKER["evaluate_relation"]("a.base.__class__ == 1", {"a.base": 1}, "t")


def test_checker_reads_a_source_tree_and_reports_drift_there(tmp_path: Path) -> None:
    (tmp_path / "a.rs").write_text(
        "pub const LIMIT: u64 = 4 * 1024;\nfn admit(len: u64) -> bool { len > LIMIT }\n"
        "#[test]\nfn limit_is_inclusive() {}\n",
        encoding="utf-8",
    )
    contract = {
        "bounds": [
            {
                "id": "queue.limit",
                "group": "queue",
                "what": "A limit.",
                "unit": "bytes",
                "value": 4_096,
                "source": "constant",
                "class": "consensus",
                "owner": {"path": "a.rs", "symbol": "LIMIT", "kind": "const", "expr": "4 * 1024"},
                "enforcement": [{"stage": "queue", "path": "a.rs", "contains": "len > LIMIT"}],
                "tests": [{"path": "a.rs", "name": "limit_is_inclusive"}],
            }
        ]
    }
    found: list = []
    assert CHECKER["verify_bounds"](tmp_path, contract, found) == {"queue.limit": 4_096}
    CHECKER["_check_sites"](tmp_path, contract["bounds"][0], "queue.limit", found)
    assert found == []
    # The owner changes its value: the same contract now fails.
    (tmp_path / "a.rs").write_text(
        "pub const LIMIT: u64 = 8 * 1024;\nfn admit(len: u64) -> bool { len >= LIMIT }\n",
        encoding="utf-8",
    )
    assert CHECKER["verify_bounds"](tmp_path, contract, found) == {}
    CHECKER["_check_sites"](tmp_path, contract["bounds"][0], "queue.limit", found)
    assert len(found) == 3
    assert "is now `8 * 1024`; the contract records `4 * 1024`" in found[0]
    assert "no longer contains `len > LIMIT`" in found[1]
    assert "test `limit_is_inclusive` is not in a.rs" in found[2]


def test_a_named_test_must_be_an_active_test(tmp_path: Path) -> None:
    """A named test that lost `#[test]` or gained `#[ignore]` no longer backs a bound."""
    problem = CHECKER["test_problem"]
    active = (
        "fn helper() {}\n\n/// Documented; with a semicolon.\n#[test]\n"
        "#[allow(clippy::too_many_lines)]\nfn limit_is_inclusive() {\n    helper();\n}\n"
    )
    assert problem(active, "a.rs", "limit_is_inclusive") is None
    assert problem(active.replace("#[test]", "#[tokio::test(flavor = \"current_thread\")]"),
                   "a.rs", "limit_is_inclusive") is None
    assert problem(active.replace("fn limit", "async fn limit"), "a.rs", "limit_is_inclusive") is None
    assert problem(active, "a.rs", "no_such") == "is not in"
    ignored = active.replace("#[test]", "#[test]\n#[ignore = \"slow\"]")
    assert problem(ignored, "a.rs", "limit_is_inclusive") == "is `#[ignore]`d in"
    assert problem(active.replace("#[test]", "#[ignore]\n#[test]"), "a.rs",
                   "limit_is_inclusive") == "is `#[ignore]`d in"
    conditional = active.replace("#[test]", "#[test]\n#[cfg_attr(not(feature = \"slow\"), ignore)]")
    assert problem(conditional, "a.rs", "limit_is_inclusive") == "is `#[ignore]`d in"
    plain = active.replace("#[test]\n", "")
    assert problem(plain, "a.rs", "limit_is_inclusive") == "has no `#[test]` attribute in"
    # The attribute of the previous test does not leak into the next function.
    neighbours = "#[test]\nfn first() {}\nfn second() {}\n"
    assert problem(neighbours, "a.rs", "first") is None
    assert problem(neighbours, "a.rs", "second") == "has no `#[test]` attribute in"
    # A helper named like the test in a comment or a call is not a definition.
    assert problem("// fn ghost() {}\nfn other() { ghost(); }\n", "a.rs", "ghost") is not None
    # A test generated by a `macro_rules!` of the same file whose arms carry `#[test]`.
    generated = (
        "macro_rules! state_test {\n    (sync $name:ident $($body:tt)*) => {\n        #[test]\n"
        "        fn $name() { $($body)* }\n    };\n}\n"
        "state_test! { sync fanout_rejects_one_over\n    let limit = 256;\n}\n"
    )
    assert problem(generated, "a.rs", "fanout_rejects_one_over", "state_test") is None
    assert problem(generated, "a.rs", "fanout_rejects_one_over") == "is not in"
    assert problem(generated, "a.rs", "absent", "state_test") == "is not in"
    assert "is not defined" in problem(generated, "a.rs", "fanout_rejects_one_over", "other_test")
    assert "generates no `#[test]`" in problem(
        generated.replace("#[test]\n", ""), "a.rs", "fanout_rejects_one_over", "state_test"
    )
    assert "`#[ignore]`d test" in problem(
        generated.replace("#[test]", "#[test]\n        #[ignore]"),
        "a.rs",
        "fanout_rejects_one_over",
        "state_test",
    )
    python = "import pytest\n\n\ndef test_limit() -> None:\n    pass\n"
    assert problem(python, "a.py", "test_limit") is None
    skipped = python.replace("def test_limit", "@pytest.mark.skip(reason='x')\ndef test_limit")
    assert problem(skipped, "a.py", "test_limit") == "is skipped in"
    assert problem(python, "a.py", "test_other") == "is not in"

    # Through the checker: the same record fails once the test is ignored or loses its attribute.
    record = {"tests": [{"path": "a.rs", "name": "limit_is_inclusive"}]}
    for source, expected in (
        (active, []),
        (ignored, ["x: test `limit_is_inclusive` is `#[ignore]`d in a.rs"]),
        (plain, ["x: test `limit_is_inclusive` has no `#[test]` attribute in a.rs"]),
    ):
        (tmp_path / "a.rs").write_text(source + f"// {len(source)}\n" * 2, encoding="utf-8")
        found: list = []
        CHECKER["_check_sites"](tmp_path, record, "x", found)
        assert found == expected

    # `#[cfg(any())]` is never true: the test is not compiled.
    compiled_out = active.replace("#[test]", "#[cfg(any())]\n#[test]")
    assert problem(compiled_out, "a.rs", "limit_is_inclusive") == (
        "is compiled out by `#[cfg(any())]` in"
    )
    # A generator defined in the file that includes the test file, and the `name { .. }` form.
    included = "world_test!(ballot_cap_rejects_one_over {\n    let cap = 1;\n});\n"
    definition = (
        "macro_rules! world_test {\n    ($name:ident $body:block) => {\n        #[test]\n"
        "        fn $name() $body\n    };\n}\ninclude!(\"world_tests.rs\");\n"
    )
    assert problem(included, "a.rs", "ballot_cap_rejects_one_over", "world_test", definition) is None
    assert "is not defined" in problem(included, "a.rs", "ballot_cap_rejects_one_over", "world_test")
    assert problem(included, "a.rs", "absent", "world_test", definition) == "is not in"

    # Every test the tracked contract names is an active test.
    def named_tests(node):
        if isinstance(node, dict):
            if set(node) >= {"path", "name"} and "contains" not in node:
                yield node
            for value in node.values():
                yield from named_tests(value)
        elif isinstance(node, list):
            for value in node:
                yield from named_tests(value)

    names = {(node["path"], node["name"]): node for node in named_tests(CONTRACT)}
    assert len(names) > 170
    for (path, name), node in sorted(names.items()):
        assert CHECKER["_named_test_problem"](ROOT, node, "x") is None, (path, name)
        assert not CHECKER["unreachable_test_file"](ROOT, path), path


def test_a_named_test_file_must_be_part_of_its_crate(tmp_path: Path) -> None:
    """A test in a file no `mod`, `include!`, `#[path]` or test target reaches never runs."""
    unreachable = CHECKER["unreachable_test_file"]
    crate = tmp_path / "crates" / "demo"
    (crate / "src" / "queue").mkdir(parents=True)
    (crate / "tests" / "grouped").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nautotests = false\n\n"
        "[[test]]\nname = \"group\"\npath = \"tests/grouped/group.rs\"\n",
        encoding="utf-8",
    )
    files = {
        "src/lib.rs": "mod queue;\n#[cfg(test)]\n#[path = \"../tests/in_lib.rs\"]\nmod in_lib;\n",
        "src/queue.rs": "mod limits;\n#[cfg(test)]\ninclude!(\"queue/included_tests.rs\");\n",
        "src/queue/limits.rs": "#[test]\nfn in_module() {}\n",
        "src/queue/included_tests.rs": "#[test]\nfn included() {}\n",
        "src/queue/orphan_tests.rs": "#[test]\nfn orphan() {}\n",
        "tests/in_lib.rs": "#[test]\nfn in_lib() {}\n",
        "tests/grouped/group.rs": "#[path = \"../grouped_case.rs\"]\nmod grouped_case;\n",
        "tests/grouped_case.rs": "#[test]\nfn grouped() {}\n",
        "tests/unlisted.rs": "#[test]\nfn unlisted() {}\n",
    }
    for name, text in files.items():
        (crate / name).write_text(text, encoding="utf-8")

    def judged(name: str) -> bool:
        CHECKER["_REACHABLE"].clear()
        CHECKER["_REFERENCES"].clear()
        return unreachable(tmp_path, f"crates/demo/{name}")

    for reached in (
        "src/lib.rs",
        "src/queue/limits.rs",
        "src/queue/included_tests.rs",
        "tests/in_lib.rs",
        "tests/grouped/group.rs",
        "tests/grouped_case.rs",
    ):
        assert not judged(reached), reached
    # No module names the file; `autotests = false` and no `[[test]]` entry.
    assert judged("src/queue/orphan_tests.rs")
    assert judged("tests/unlisted.rs")
    # A file outside every crate (a scratch source) and a Python test are not judged.
    (tmp_path / "loose.rs").write_text("#[test]\nfn loose() {}\n", encoding="utf-8")
    assert not unreachable(tmp_path, "loose.rs")
    assert not unreachable(tmp_path, "scripts/tests/x.py")

    # Through the checker.
    record = {"tests": [{"path": "crates/demo/src/queue/included_tests.rs", "name": "included"}]}
    found: list = []
    CHECKER["_REACHABLE"].clear()
    CHECKER["_check_sites"](tmp_path, record, "x", found)
    assert found == []
    # Removing the `include!` leaves the file on disk and the test out of the build.
    (crate / "src" / "queue.rs").write_text("mod limits;\n// tests removed\n", encoding="utf-8")
    CHECKER["_REACHABLE"].clear()
    CHECKER["_REFERENCES"].clear()
    CHECKER["_check_sites"](tmp_path, record, "x", found)
    assert len(found) == 1 and "which no `mod`, `include!`, `#[path]`" in found[0]
    # A reference that is itself compiled out does not count.
    (crate / "src" / "queue.rs").write_text(
        "mod limits;\n#[cfg(any())]\ninclude!(\"queue/included_tests.rs\");\n", encoding="utf-8"
    )
    CHECKER["_REACHABLE"].clear()
    CHECKER["_REFERENCES"].clear()
    assert unreachable(tmp_path, "crates/demo/src/queue/included_tests.rs")


def test_a_site_that_only_repeats_the_definition_is_rejected() -> None:
    definition_only = CHECKER["_definition_only"]
    owner = {"path": "a.rs", "symbol": "MAX_FRAME_BYTES", "kind": "const"}
    in_owner = lambda text: {"path": "a.rs", "contains": text}  # noqa: E731
    assert definition_only(in_owner("pub const MAX_FRAME_BYTES: usize = 4 * 1024;"), owner)
    assert definition_only(in_owner("MAX_FRAME_BYTES"), owner)
    assert definition_only({"path": "b.rs", "contains": "crate::a::MAX_FRAME_BYTES,"}, owner)
    assert not definition_only(in_owner("if len > MAX_FRAME_BYTES {"), owner)
    assert not definition_only({"path": "b.rs", "contains": "if len > MAX_FRAME_BYTES {"}, owner)
    default = {"path": "a.rs", "symbol": "max_tx_bytes", "kind": "fn"}
    assert definition_only({"path": "a.rs", "contains": "pub const fn max_tx_bytes() -> u64 {"}, default)
    field = {"path": "a.rs", "symbol": "max_bytes", "kind": "field"}
    assert definition_only({"path": "a.rs", "contains": "max_bytes: 1 << 30,"}, field)
    # The definition of any other constant is no comparison either: an alias, a derived
    # constant, with or without its semicolon, in any file and without an owner.
    for text in (
        "const MAX: usize = MAX_FRAME_BYTES;",
        "pub(crate) const STRICT_INIT_MAX_BLOCK_BYTES: u64 = MAX_FRAME_BYTES;",
        "const DEPTH: usize = MAX_FRAME_BYTES.ilog2() as usize",
        "pub const OUTPUT_START: u64 = Self::INPUT_START + Self::INPUT_SIZE;",
        "static LIMITS: DecodeLimits = DecodeLimits::new( MAX_FRAME_BYTES, MAX_FRAME_BYTES * 8, );",
    ):
        assert definition_only({"path": "b.rs", "contains": text}, owner), text
        assert definition_only({"path": "b.rs", "contains": text}), text
    # A function signature names where a check lives, not the check.
    for text in (
        "pub const fn check_signed_transaction_bytes(",
        "pub const fn from_parameters(parameters: SmartContractParameters) -> Self {",
        "pub fn ivm_execution_budget(&self) -> iroha_allocation::AllocationBudget {",
        "fn effective<T: Limits>(limits: &T) -> usize",
    ):
        assert definition_only({"path": "b.rs", "contains": text}, owner), text
    # A compile-time assertion compares; so do a statement after a constant, a function with
    # its body and the constant a trait implementation binds.
    for text in (
        "const _: () = assert!(MAX_FRAME_BYTES.is_power_of_two());",
        "const LIMIT: usize = MAX_FRAME_BYTES; if len > LIMIT {",
        "fn effective(limits: &Limits) -> usize { limits.max_len.min(MAX_FRAME_BYTES) }",
        "impl SharedDomain for FrameDomain { const MAX: usize = MAX_FRAME_BYTES; }",
    ):
        assert not definition_only({"path": "b.rs", "contains": text}, owner), text

    def defined(contract: dict) -> None:
        item = bound(contract, "block.max_evidence_frame_bytes")
        item["enforcement"] = [
            {
                "stage": "follower",
                "path": item["owner"]["path"],
                "contains": "pub const MAX_EVIDENCE_FRAME_BYTES: usize = 4 * 1024 * 1024;",
            }
        ]

    rejected = "is only a symbol, a definition or a function signature"
    assert_fails(edited(defined), rejected)

    def bare(contract: dict) -> None:
        item = bound(contract, "guest_memory.max_call_frame_bytes")
        item["enforcement"] = [
            {"stage": "vm", "path": item["owner"]["path"], "contains": "MAX_CALL_FRAME_BYTES_V1"}
        ]

    assert_fails(edited(bare), rejected)

    def alias(contract: dict) -> None:
        # The verifier's case: the zk-X509 proof ceiling backed by an alias definition.
        bound(contract, "x509.max_proof_bytes")["enforcement"] = [
            {
                "stage": "follower",
                "path": "crates/iroha_core_privacy/src/privacy_engines/mod.rs",
                "contains": "self::zk_x509::profile::ZK_X509_MAX_PROOF_BYTES_V1 as usize;",
            }
        ]

    assert problems(edited(alias)) == []  # an expression fragment is still text the file holds

    def alias_item(contract: dict) -> None:
        bound(contract, "rs16.max_availability_frame_bytes")["enforcement"] = [
            {
                "stage": "rs16",
                "path": "crates/iroha_sumeragi/src/availability/artifact.rs",
                "contains": "const MAX: usize = MAX_AVAILABILITY_FRAME_BYTES;",
            }
        ]

    assert_fails(edited(alias_item), rejected)

    def signature(contract: dict) -> None:
        # The rule covers every record with sites, not only bounds.
        declared = next(
            item for item in contract["declared"] if item["id"] == "transaction.structured_size_refusal"
        )
        declared["enforcement"][0]["path"] = "crates/iroha_data_model/src/proof.rs"
        declared["enforcement"][0]["contains"] = (
            "pub fn structural_error(&self) -> Option<(&'static str, &'static str)> {"
        )

    assert_fails(edited(signature), rejected)
    # No record of the tracked contract is backed by such a site.
    for item in CONTRACT["bounds"]:
        for site in item.get("enforcement", []):
            assert not definition_only(site, item["owner"]), (item["id"], site["contains"])
    # The zk-X509 proof ceiling names the encoder and the decoder comparison.
    sites = {site["contains"] for site in bound(CONTRACT, "x509.max_proof_bytes")["enforcement"]}
    assert "if encoded_length > ZK_X509_MAX_PROOF_BYTES_V1 as usize {" in sites
    assert "if encoded.len() > ZK_X509_MAX_PROOF_BYTES_V1 as usize {" in sites


def test_a_site_records_how_often_its_text_occurs(tmp_path: Path) -> None:
    """Removing one of two identical comparisons is drift."""
    twice = "fn a(len: usize) { if len > LIMIT {} }\nfn b(len: usize) { if len > LIMIT {} }\n"
    (tmp_path / "a.rs").write_text(twice, encoding="utf-8")
    site = {"stage": "queue", "path": "a.rs", "contains": "if len > LIMIT {", "count": 2}
    record = {"enforcement": [site]}
    found: list = []
    CHECKER["_check_sites"](tmp_path, record, "x", found)
    assert found == []
    once = twice.replace("fn b(len: usize) { if len > LIMIT {} }", "fn b(len: usize) {}")
    (tmp_path / "a.rs").write_text(once, encoding="utf-8")
    CHECKER["_check_sites"](tmp_path, record, "x", found)
    assert found == ["x: a.rs contains `if len > LIMIT {` 1 time(s); the contract records 2"]
    # A site without a count occurs exactly once; an explicit count of one is not written.
    found = []
    CHECKER["_check_sites"](tmp_path, {"enforcement": [{**site, "count": 1}]}, "x", found)
    assert len(found) == 1 and "a site that occurs once records none" in found[0]
    (tmp_path / "a.rs").write_text(twice, encoding="utf-8")
    plain = {"stage": "queue", "path": "a.rs", "contains": "if len > LIMIT {"}
    found = []
    CHECKER["_check_sites"](tmp_path, {"enforcement": [plain]}, "x", found)
    assert found == ["x: a.rs contains `if len > LIMIT {` 2 time(s); the contract records 1"]
    # `--refresh` rewrites the count of a site that is still present and reports it.
    notes: list = []
    found = []
    CHECKER["_check_sites"](tmp_path, {"enforcement": [plain]}, "x", found, None, True, notes)
    assert found == [] and plain["count"] == 2
    assert len(notes) == 1 and "now occurs 2 time(s), was 1" in notes[0]
    (tmp_path / "a.rs").write_text(once, encoding="utf-8")
    CHECKER["_check_sites"](tmp_path, {"enforcement": [plain]}, "x", found, None, True, notes)
    assert "count" not in plain and len(notes) == 2
    # A site that is gone is never refreshed away.
    (tmp_path / "a.rs").write_text("fn a() {}\n", encoding="utf-8")
    CHECKER["_check_sites"](tmp_path, {"enforcement": [plain]}, "x", found, None, True, notes)
    assert found == ["x: a.rs no longer contains `if len > LIMIT {`"]

    # The tracked contract: the verifier's case and the lane batch comparison.
    frame = next(
        site
        for site in bound(CONTRACT, "attachment.list_max_canonical_frame_bytes")["enforcement"]
        if site["contains"].startswith("if canonical_frame_len >")
    )
    assert frame["count"] == 2

    def miscounted(contract: dict) -> None:
        next(
            site
            for site in bound(contract, "attachment.list_max_canonical_frame_bytes")["enforcement"]
            if site["contains"].startswith("if canonical_frame_len >")
        )["count"] = 3

    assert_fails(edited(miscounted), "2 time(s); the contract records 3")
    lane = bound(CONTRACT, "block.lane_batch_framing_reserve_bytes")
    assert "if length <= max_bytes as usize {" in {site["contains"] for site in lane["enforcement"]}
    assert "build_trims_the_batch_to_the_lane_payload_limit" in {test["name"] for test in lane["tests"]}
    counted = [
        site
        for item in CONTRACT["bounds"]
        for site in item.get("enforcement", [])
        if "count" in site
    ]
    assert len(counted) >= 18 and all(site["count"] > 1 for site in counted)


def test_every_consensus_bound_names_a_test_or_the_owner_of_the_gap() -> None:
    consensus = [item for item in CONTRACT["bounds"] if item["class"] == "consensus"]
    pins = CHECKER["pin_tests"](CONTRACT)
    assert len(pins) == len(CONTRACT["pin_tests"]) >= 13

    def only_pins(item: dict) -> bool:
        tests = item.get("tests") or []
        return bool(tests) and all((test["path"], test["name"]) in pins for test in tests)

    tested = [item for item in consensus if item.get("tests") and not only_pins(item)]
    pinned = [item for item in consensus if only_pins(item)]
    gaps = {item["id"]: item["test_gap"]["owner"] for item in consensus if "test_gap" in item}
    assert set(gaps.values()) <= set(TASKS)
    # A bound with a test of its boundary records no gap; one without names the gap's owner.
    assert not [item["id"] for item in tested if "test_gap" in item]
    for item in consensus:
        if not item.get("tests"):
            assert item["id"] in gaps, item["id"]
    # A bound whose every test is a pin names the owner of the boundary test, is recorded
    # unenforced, or states why a pin is the right test.
    # F.4 wrote the boundary tests of five committed confidential and proof limits, of
    # the native PIPA-R proof caps and of the five AMX budget values, so those bounds left this group.
    assert len(pinned) >= 6
    for item in pinned:
        assert "test_gap" in item or "unenforced" in item or item.get("value_pin"), item["id"]
    assert {item["id"] for item in pinned if item.get("value_pin")} == {
        "block.core_default_max_block_bytes",
        "guest_memory.data_model_heap_max_bytes",
    }
    # The bounds the verifier found backed by a pin alone now name a boundary test or a gap.
    for identifier, name in (
        ("work_budget.fuel", "validate_ivm_max_cycles_exceeds_fuel_rejected"),
        ("work_budget.fuel", "validate_ivm_max_cycles_equal_to_fuel_is_admitted"),
        ("guest_memory.committed_heap_limit_bytes", "per_instance_heap_ceiling_cannot_be_bypassed_by_growth"),
        ("proof.config_pipa_r_max_proof_bytes", "guardrails_enforce_pipa_r_max_proof_bytes_for_open_verify_envelopes"),
        ("proof.config_ballot_history_cap", "direct_zk_ballot_rejects_a_full_corpus_without_pruning"),
        (
            "work_budget.config_confidential_registry_max_delta_per_block",
            "confidential_registry_delta_cap_limits_transitions",
        ),
        (
            "work_budget.config_confidential_max_nullifiers_per_tx",
            "nullifiers_per_transaction_accept_the_committed_limit_and_reject_one_more",
        ),
        (
            "work_budget.config_confidential_max_commitments_per_tx",
            "commitments_per_transaction_accept_the_committed_limit_and_reject_one_more",
        ),
        (
            "work_budget.config_confidential_max_verify_calls_per_block",
            "verify_calls_accept_the_committed_limits_and_reject_one_more",
        ),
        (
            "proof.config_confidential_max_proof_size_bytes",
            "proof_size_accepts_the_committed_limit_and_rejects_one_byte_more",
        ),
        (
            "proof.config_preverify_budget_bytes",
            "preverify_budget_and_size_accept_the_committed_limit_and_reject_one_byte_more",
        ),
        (
            "work_budget.config_query_max_fetch_size",
            "query_limits_from_pipeline_use_the_committed_max_fetch_at_and_above_the_limit",
        ),
        (
            "proof.config_pipa_r_max_envelope_bytes",
            "native_real_proofs_obey_relation_policy_caps_and_preverify",
        ),
        (
            "work_budget.config_amx_per_dataspace_budget_ms",
            "amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above",
        ),
        (
            "work_budget.config_amx_group_budget_ms",
            "amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above",
        ),
        (
            "work_budget.config_amx_per_instruction_ns",
            "amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above",
        ),
        (
            "work_budget.config_amx_per_memory_access_ns",
            "amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above",
        ),
        (
            "work_budget.config_amx_per_syscall_ns",
            "amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above",
        ),
    ):
        item = bound(CONTRACT, identifier)
        assert name in {test["name"] for test in item["tests"]}, identifier
        assert not only_pins(item) and "test_gap" not in item
    # No boundary-test gap of the ZK and pipeline policy families is owned by F.4 any more.
    assert "F.4" not in gaps.values()
    for identifier in ("transaction.max_instructions",):
        item = bound(CONTRACT, identifier)
        assert only_pins(item) and item["test_gap"]["owner"] in TASKS, identifier

    def unowned(contract: dict) -> None:
        del bound(contract, "transaction.max_instructions")["test_gap"]

    assert_fails(edited(unowned), "its tests only pin the value or a digest projection")

    def pin_claimed_as_boundary(contract: dict) -> None:
        # A pin test cannot be relabelled by dropping it from the list while a bound names it
        # as its only evidence: the list is checked both ways.
        contract["pin_tests"] = [
            test for test in contract["pin_tests"] if test["name"] != "t_req_defaults_match_spec"
        ] + [{"path": "scripts/tests/check_zk_resource_contract_test.py", "name": "absent", "pins": "value", "what": "x"}]

    assert_fails(edited(pin_claimed_as_boundary), "pin_tests absent: is not in")

    def unused_pin(contract: dict) -> None:
        contract["pin_tests"].append(
            {
                "path": "scripts/tests/check_zk_resource_contract_test.py",
                "name": "test_tracked_contract_matches_the_source",
                "pins": "value",
                "what": "x",
            }
        )

    assert_fails(edited(unused_pin), "no bound names this test")

    def gap_beside_a_boundary_test(contract: dict) -> None:
        bound(contract, "work_budget.fuel")["test_gap"] = {"owner": "I.4", "summary": "x"}

    assert_fails(
        edited(gap_beside_a_boundary_test),
        "work_budget.fuel: a bound with a test of its boundary records no `test_gap`",
    )

    def pin_reason_beside_a_boundary_test(contract: dict) -> None:
        bound(contract, "work_budget.fuel")["value_pin"] = "x"

    assert_fails(edited(pin_reason_beside_a_boundary_test), "`value_pin` is for a bound whose every test is a pin")

    def fixed_bound_backed_by_a_pin(contract: dict) -> None:
        bound(contract, "transaction.max_tx_bytes")["tests"] = [
            {
                "path": "crates/iroha_data_model/tests/resource_contract_v1.rs",
                "name": "committed_defaults_are_the_values_the_contract_records",
            }
        ]

    assert_fails(
        edited(fixed_bound_backed_by_a_pin),
        "transaction.max_tx_bytes: a fixed validity bound names a test of its boundary",
    )
    # The committed output budget is backed by tests of that budget, not of the overlay cap.
    for identifier in ("queued_effects.max_output_items", "queued_effects.max_output_bytes"):
        names = {entry["name"] for entry in bound(CONTRACT, identifier)["tests"]}
        assert "committed_output_budget_accepts_the_exact_limit_and_refuses_one_over" in names
        assert not any(name.startswith("plain_instruction_group_checks") for name in names)
    overlay = {
        entry["name"]
        for entry in bound(CONTRACT, "queued_effects.config_overlay_max_instructions")["tests"]
    }
    assert "plain_instruction_group_checks_exact_count_before_first_effect" in overlay
    # The zk-X509 proof ceiling names tests of the engine constant.
    engine = {entry["path"] for entry in bound(CONTRACT, "x509.max_proof_bytes")["tests"]}
    assert any("privacy_engines/zk_x509/" in path for path in engine)

    def untested(contract: dict) -> None:
        del bound(contract, "transaction.max_signatures")["tests"]

    assert_fails(edited(untested), "transaction.max_signatures: a consensus bound names a test")

    def both(contract: dict) -> None:
        bound(contract, "transaction.max_signatures")["test_gap"] = {
            "owner": "V.3",
            "summary": "x",
        }

    assert_fails(edited(both), "a bound with a test of its boundary records no `test_gap`")

    def ownerless(contract: dict) -> None:
        item = bound(contract, "transaction.max_signatures")
        del item["tests"]
        item["test_gap"] = {"owner": "Z.9", "summary": "x"}

    assert_fails(edited(ownerless), "test_gap: owner `Z.9` is not a task")
    gap = next(iter(gaps))
    assert_fails(
        CONTRACT,
        f"{gap}: test_gap: task {gaps[gap]} is recorded implemented",
        {**TASKS, gaps[gap]: "implemented"},
    )


def test_a_value_bound_into_state_but_compared_nowhere_is_recorded_unenforced() -> None:
    unenforced = {item["id"] for item in CONTRACT["bounds"] if "unenforced" in item}
    assert unenforced == {
        "queued_effects.config_overlay_chunk_instructions",
        "proof.config_confidential_max_public_inputs",
        "proof.config_confidential_registry_max_vk_entries",
        "proof.config_confidential_registry_max_params_entries",
        "proof.config_private_settlement_max_proof_bytes",
        "proof.config_private_settlement_max_capsule_bytes",
        "storage.config_private_settlement_sidecar_max_records",
        "storage.config_private_settlement_sidecar_max_total_bytes",
    }
    for identifier in unenforced:
        item = bound(CONTRACT, identifier)
        assert "enforcement" not in item and item["unenforced"]["owner"] == "F.4"
    # The settlement leg limits are compared by Torii's service only: an observation, never
    # an enforcement site of a state transition.
    proof = bound(CONTRACT, "proof.config_private_settlement_max_proof_bytes")
    assert proof["value"] == 8 * MIB and len(proof["observations"]) == 2
    assert all("iroha_torii" in entry["path"] for entry in proof["observations"])

    def sited(contract: dict) -> None:
        item = bound(contract, "proof.config_confidential_max_public_inputs")
        item["enforcement"] = bound(contract, "proof.config_pipa_r_max_proof_bytes")["enforcement"]

    assert_fails(edited(sited), "a bound with enforcement sites is not `unenforced`")

    def observation_gone(contract: dict) -> None:
        bound(contract, "proof.config_private_settlement_max_proof_bytes")["observations"][0][
            "contains"
        ] = "|| request.payload.proof.len() as u64 > config.no_such_limit.get()"

    assert_fails(edited(observation_gone), "private_settlement.rs no longer contains")


def test_every_limit_in_an_owner_file_is_listed_or_excluded() -> None:
    """The inventory cannot silently omit a limit an owner file or directory defines."""
    section = CONTRACT["completeness"]
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    # A bound of another crate is scanned in the source the compared code imports it from.
    scanned = {scope["path"] for scope in CHECKER["import_scopes"](ROOT, scopes)}
    for item in CONTRACT["bounds"]:
        if item["owner"]["kind"] == "const":
            assert item["owner"]["path"] in scanned, item["id"]
    for group in section["excluded"]:
        holders = group["files"] if "files" in group else [group]
        assert group["reason"] and all(holder["path"] and holder["symbols"] for holder in holders)
    # The bounds the first inventory missed are listed.
    for identifier, symbol in (
        ("attachment.list_max_canonical_frame_bytes", "PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1"),
        ("attachment.list_max_attachments", "PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1"),
        ("decoded_scratch.config_ivm_max_decoded_bytes", "IVM_MAX_DECODED_BYTES"),
        ("work_budget.block_gas_limit_default", "DEFAULT_GAS_LIMIT_PER_BLOCK"),
        ("work_budget.fastpq_bootstrap_network_inputs", "BOOTSTRAP_NETWORK_INPUTS"),
        # Found by the directory scan of the second repair.
        ("block.max_evidence_admissions_per_block", "MAX_EVIDENCE_ADMISSIONS_PER_BLOCK"),
        ("block.max_evidence_admission_bytes", "MAX_EVIDENCE_ADMISSION_BYTES"),
        ("block.authenticated_proofs_max_block_wire_bytes", "AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1"),
        ("sync.max_proposal_bytes", "MAX_PROPOSAL_BYTES"),
        ("decoded_scratch.max_private_input_record_bytes", "MAX_PRIVATE_INPUT_RECORD_BYTES_V1"),
        ("decoded_scratch.max_private_inputs", "MAX_PRIVATE_INPUTS_V1"),
        ("decoded_scratch.max_private_input_transport_bytes", "MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1"),
        ("work_budget.max_contract_call_depth", "MAX_CONTRACT_CALL_DEPTH"),
        ("transport.p2p_max_encrypted_frame_bytes", "MAX_ENCRYPTED_FRAME_BYTES"),
    ):
        assert bound(CONTRACT, identifier)["owner"]["symbol"] == symbol
    for field in ("max_outputs", "max_total_output_bytes", "max_time_invocations"):
        assert bound(CONTRACT, f"block.execution_output_{field}")["source"] == "committed"
    assert bound(CONTRACT, "block.max_time_trigger_invocations")["value"] == 512
    assert bound(CONTRACT, "block.max_evidence_admissions_per_block")["value"] == 8
    assert bound(CONTRACT, "sync.max_proposal_bytes")["value"] == 64 * MIB
    assert bound(CONTRACT, "block.authenticated_proofs_max_block_wire_bytes")["value"] == 32 * MIB
    # The executed block wire may exceed what the block-proof carrier serves: recorded open.
    carrier = relation(CONTRACT, "authenticated_block_proofs_carry_an_executed_block")
    assert carrier["expect"] == {"today": "violated", "x2_target": "violated"}
    assert carrier["open"]["owner"] in TASKS

    # The crates on the path are scanned whole, so a new file there is scanned too.
    trees = {scope["tree"] for scope in section["scopes"] if "tree" in scope}
    assert trees == {
        "crates/iroha_data_model/src",
        "crates/iroha_torii/src",
        "crates/iroha_core/src",
        "crates/iroha_core_zk/src",
        "crates/ivm_abi/src",
        "crates/ivm/src",
        "crates/iroha_sumeragi/src",
        "crates/iroha_p2p/src",
    }
    assert len(scopes) > 2000
    for path in (
        "crates/iroha_core/src/sumeragi/evidence.rs",
        "crates/iroha_core/src/sumeragi/certified_chain.rs",
        "crates/iroha_data_model/src/block/proofs.rs",
        "crates/ivm_abi/src/private_input.rs",
        "crates/ivm/src/limits.rs",
        "crates/iroha_p2p/src/peer.rs",
        "crates/iroha_core/src/tx.rs",
    ):
        assert path in scanned, path
    # Test, fixture and simulator sources are not production limits. A source whose name
    # looks like one is scanned only when its crate compiles it outside test builds: a
    # file included as text at module scope, or a fixture module the library declares.
    named_like_tests = [path for path in scanned if "/tests/" in path or path.endswith("_tests.rs")]
    assert named_like_tests
    assert all(CHECKER["compiled_outside_tests"](ROOT, path) for path in named_like_tests)
    assert "crates/iroha_sumeragi/src/machine/tests/safety.rs" not in scanned
    assert "crates/iroha_data_model/src/nexus/private_settlement/tests.rs" not in scanned
    assert "crates/ivm/src/prebuilt_fixtures.rs" in scanned
    assert not [path for path in scanned if path.startswith("crates/iroha_sumeragi/src/sim/")]
    nexus = [
        scope
        for scope in section["scopes"]
        if scope.get("module") == ["pub mod nexus {"]
    ]
    assert len(nexus) == 1 and nexus[0]["path"].endswith("parameters/defaults.rs")

    def unlisted(contract: dict) -> None:
        contract["bounds"] = [
            item for item in contract["bounds"] if item["id"] != "attachment.list_max_attachments"
        ]
        contract["relations"] = [
            item for item in contract["relations"] if "list_max_attachments" not in item["expr"]
        ]

    assert_fails(
        edited(unlisted),
        "`PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1` is neither a listed bound nor excluded",
    )

    def unlisted_default(contract: dict) -> None:
        contract["bounds"] = [
            item for item in contract["bounds"] if item["id"] != "transaction.max_signatures"
        ]

    assert_fails(edited(unlisted_default), "`max_signatures` is neither a listed bound nor excluded")

    def symbols_of(group: dict) -> list:
        holders = group["files"] if "files" in group else [group]
        return [symbol for holder in holders for symbol in holder["symbols"]]

    def unexcluded(contract: dict) -> None:
        group = next(
            item for item in contract["completeness"]["excluded"] if "MAX_DA_STRIPE_WIDTH" in symbols_of(item)
        )
        group["symbols"].remove("MAX_DA_STRIPE_WIDTH")

    assert_fails(edited(unexcluded), "`MAX_DA_STRIPE_WIDTH` is neither a listed bound nor excluded")

    def unexcluded_in_a_tree(contract: dict) -> None:
        # A limit in a file that owns no listed bound: found through the directory scope.
        for group in contract["completeness"]["excluded"]:
            for holder in group.get("files", []):
                if "MAX_QUEUE_SCAN" in holder["symbols"]:
                    holder["symbols"].remove("MAX_QUEUE_SCAN")
            if "MAX_QUEUE_SCAN" in group.get("symbols", []):
                group["symbols"].remove("MAX_QUEUE_SCAN")

    assert_fails(
        edited(unexcluded_in_a_tree),
        "completeness crates/iroha_core/src/sumeragi/payload.rs: `MAX_QUEUE_SCAN` is neither",
    )

    def nexus_default_unlisted(contract: dict) -> None:
        # The verifier's case: the settlement carrier default was in no scope.
        identifier = "transaction.config_private_settlement_max_carrier_bytes"
        contract["bounds"] = [item for item in contract["bounds"] if item["id"] != identifier]
        contract["relations"] = [item for item in contract["relations"] if identifier not in item["expr"]]
        catalog = next(item for item in contract["catalogs"] if item["id"] == "nexus_consensus_policy_v1")
        del catalog["fields"]["atomic_private_settlement.max_carrier_bytes"]
        catalog["excluded"][0]["fields"].append("atomic_private_settlement.max_carrier_bytes")

    assert_fails(
        edited(nexus_default_unlisted),
        "`pub mod nexus {`: `MAX_CARRIER_BYTES` is neither a listed bound nor excluded",
    )

    def stale(contract: dict) -> None:
        contract["completeness"]["excluded"][0]["symbols"].append("NO_SUCH_LIMIT")

    assert_fails(edited(stale), "the exclusion of `NO_SUCH_LIMIT`")

    def unreasoned(contract: dict) -> None:
        contract["completeness"]["excluded"][0]["reason"] = ""

    assert_fails(edited(unreasoned), "an exclusion states its reason")

    def both(contract: dict) -> None:
        contract["completeness"]["excluded"].append(
            {
                "path": "crates/iroha_data_model/src/proof.rs",
                "reason": "x",
                "symbols": ["PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1"],
            }
        )

    assert_fails(edited(both), "is both listed and excluded")

    def unscanned(contract: dict) -> None:
        # The file scope of the proof model and the crate tree that would still cover it.
        contract["completeness"]["scopes"] = [
            scope
            for scope in contract["completeness"]["scopes"]
            if scope.get("path") != "crates/iroha_data_model/src/proof.rs"
            and scope.get("tree") != "crates/iroha_data_model/src"
        ]
        contract["completeness"]["excluded"] = [
            group
            for group in contract["completeness"]["excluded"]
            if group.get("path") != "crates/iroha_data_model/src/proof.rs"
        ]

    assert_fails(edited(unscanned), "is outside every completeness scope")

    def tree_removed(contract: dict) -> None:
        contract["completeness"]["scopes"] = [
            scope for scope in contract["completeness"]["scopes"] if scope.get("tree") != "crates/ivm_abi/src"
        ]

    assert_fails(edited(tree_removed), "matches no scanned limit")

    def unexplained_skip(contract: dict) -> None:
        tree = next(
            scope for scope in contract["completeness"]["scopes"] if scope.get("tree") == "crates/iroha_sumeragi/src"
        )
        tree["skip"][0]["why"] = ""

    assert_fails(edited(unexplained_skip), "a skipped path states `why`")

    def cites_nothing(contract: dict) -> None:
        contract["completeness"]["excluded"][0]["reason"] += " See guest_memory.abi_heap_bytes."

    assert_fails(edited(cites_nothing), "the text cites `guest_memory.abi_heap_bytes`, which is not a bound")

    def removed(contract: dict) -> None:
        del contract["completeness"]

    assert_fails(edited(removed), "the contract lists the owner files it scans")


def test_proof_envelope_finality_and_contract_code_limits_are_listed() -> None:
    """The limits an evidence review found enforced on the path and absent from the contract."""
    section = CONTRACT["completeness"]
    scanned = {scope["path"] for scope in CHECKER["expand_scopes"](ROOT, section, [])}
    for identifier, path, symbol, value, kind in (
        ("proof.zk1_max_section_bytes", "crates/iroha_core_zk/src/lib.rs", "MAX_PROOF_LEN", 8 * MIB, "consensus"),
        (
            "proof.open_verify_default_max_proof_bytes",
            "crates/iroha_data_model/src/zk.rs",
            "OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES",
            64 * MIB,
            "consensus",
        ),
        ("proof.stark_fri_max_envelope_bytes", "crates/iroha_core_zk/src/stark.rs", "MAX_ENVELOPE_BYTES", MIB, "consensus"),
        (
            "block.finality_proof_max_block_bytes",
            "crates/iroha_data_model/src/sumeragi_finality.rs",
            "MAX_FINALITY_BLOCK_BYTES",
            32 * MIB,
            "local_defer",
        ),
        (
            "storage.contract_code_default_max_bytes",
            "crates/iroha_core/src/smartcontracts/isi/world.rs",
            "DEFAULT_MAX_CONTRACT_CODE_BYTES",
            16 * MIB,
            "consensus",
        ),
        (
            "storage.contract_code_portable_max_bytes",
            "crates/iroha_core/src/smartcontracts/isi/world.rs",
            "MAX_PORTABLE_CONTRACT_CODE_BYTES",
            2**31 - 1,
            "consensus",
        ),
    ):
        item = bound(CONTRACT, identifier)
        assert item["owner"]["path"] == path and item["owner"]["symbol"] == symbol, identifier
        assert item["value"] == value and item["class"] == kind, identifier
        assert item["enforcement"], identifier
        assert path in scanned, identifier
    # Every one that decides validity names a test of its comparison.
    for identifier in (
        "proof.zk1_max_section_bytes",
        "proof.open_verify_default_max_proof_bytes",
        "proof.stark_fri_max_envelope_bytes",
        "storage.contract_code_default_max_bytes",
        "storage.contract_code_portable_max_bytes",
    ):
        item = bound(CONTRACT, identifier)
        assert item["tests"] and "test_gap" not in item and item["test_note"], identifier
    assert bound(CONTRACT, "storage.contract_code_default_max_bytes")["source"] == "committed"

    # Native proof admission has its own hard ceiling; the retired ZK1 envelope is absent.
    native_relation = relation(CONTRACT, "native_proof_cap_fits_verifier_ceiling")
    assert native_relation["expr"] == "proof.config_pipa_r_max_envelope_bytes <= proof.native_max_proof_bytes"
    assert native_relation["expect"] == {"today": "holds"}
    assert bound(CONTRACT, "proof.native_max_proof_bytes")["test_gap"]["owner"] == "V.2"
    assert not any("zk1" in item["id"] for item in CONTRACT["bounds"] + CONTRACT["relations"])
    # The finality-proof reader is a local refusal guarded by its own open relation.
    reader = bound(CONTRACT, "block.finality_proof_max_block_bytes")
    assert reader["validity"] is False and reader["on_exhaustion"] == "local_refusal"
    assert reader["guarded_by"] == "finality_proofs_carry_an_executed_block"
    finality = relation(CONTRACT, reader["guarded_by"])
    assert finality["expect"] == {"today": "violated", "x2_target": "violated"}
    assert finality["open"]["owner"] in TASKS
    for identifier in (
        "native_proof_cap_fits_verifier_ceiling",
        "open_verify_default_above_transaction_cap",
        "stark_config_caps_within_the_verifier_ceiling",
        "default_contract_code_cap_is_portable",
        "contract_code_cap_admits_a_program_image",
    ):
        assert relation(CONTRACT, identifier)["expect"]["today"] == "holds", identifier

    # The proof crate is scanned whole: its KAGEMUSHA product directories are no longer
    # skipped, and every limit in them is excluded symbol by symbol under that product.
    tree = next(scope for scope in section["scopes"] if scope.get("tree") == "crates/iroha_core_zk/src")
    assert "skip" not in tree
    product = [
        "crates/iroha_core_zk/src/kagemusha_v1_recursion/",
        "crates/iroha_core_zk/src/kagemusha_v1_state/",
        "crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/",
    ]
    for prefix in product:
        assert [path for path in scanned if path.startswith(prefix)], prefix
    product_group = next(
        group
        for group in section["excluded"]
        if "files" in group and any(holder["path"].startswith(product[0]) for holder in group["files"])
    )
    assert product_group["reason"].startswith("The KAGEMUSHA offline-cash product")
    in_product = [
        symbol
        for holder in product_group["files"]
        if any(holder["path"].startswith(prefix) for prefix in product)
        for symbol in holder["symbols"]
    ]
    assert len(in_product) == 96
    for path in (
        "crates/iroha_core_zk/src/lib.rs",
        "crates/iroha_core_zk/src/stark.rs",
        "crates/iroha_core_zk/src/verification.rs",
        "crates/iroha_core_zk/src/confidential_v2.rs",
        "crates/iroha_core_zk/src/kagemusha_sender_wire.rs",
    ):
        assert path in scanned, path

    # Each new bound is held by the scan: removing it leaves an unclassified limit.
    for identifier, symbol in (
        ("proof.zk1_max_section_bytes", "MAX_PROOF_LEN"),
        ("proof.open_verify_default_max_proof_bytes", "OPEN_VERIFY_DEFAULT_MAX_PROOF_BYTES"),
        ("proof.stark_fri_max_envelope_bytes", "MAX_ENVELOPE_BYTES"),
        ("block.finality_proof_max_block_bytes", "MAX_FINALITY_BLOCK_BYTES"),
        ("storage.contract_code_default_max_bytes", "DEFAULT_MAX_CONTRACT_CODE_BYTES"),
        ("storage.contract_code_portable_max_bytes", "MAX_PORTABLE_CONTRACT_CODE_BYTES"),
    ):

        def unlisted(contract: dict, identifier: str = identifier) -> None:
            contract["bounds"] = [item for item in contract["bounds"] if item["id"] != identifier]
            contract["relations"] = [
                item for item in contract["relations"] if identifier not in item["expr"]
            ]

        assert_fails(edited(unlisted), f"`{symbol}` is neither a listed bound nor excluded")

    def scope_removed(contract: dict) -> None:
        contract["completeness"]["scopes"] = [
            scope
            for scope in contract["completeness"]["scopes"]
            if scope.get("tree") != "crates/iroha_core_zk/src"
        ]

    assert_fails(edited(scope_removed), "proof.zk1_max_section_bytes: its owner in")

    def ceiling_claimed_to_fit(contract: dict) -> None:
        relation(contract, "zk1_section_holds_a_ceiling_proof")["expect"]["today"] = "holds"

    assert_fails(edited(ceiling_claimed_to_fit), "violated under `today`; the contract records holds")

    def unguarded(contract: dict) -> None:
        del bound(contract, "block.finality_proof_max_block_bytes")["guarded_by"]

    assert_fails(edited(unguarded), "a locally refusing bound names its relation in `guarded_by`")

    def site_gone(contract: dict) -> None:
        bound(contract, "proof.zk1_max_section_bytes")["enforcement"][0]["contains"] = "if len > NO_SUCH_LIMIT {"

    assert_fails(edited(site_gone), "no longer contains `if len > NO_SUCH_LIMIT {`")


def test_completeness_scan_reads_constants_and_defaults(tmp_path: Path) -> None:
    source = """
    pub const MAX_FRAME_BYTES: usize = 4;
    const RESERVE: u32 = 2;
    pub const NAME: &str = "x";
    pub mod queue {
        pub const CAPACITY: usize = 8;
        pub mod nested { pub const MAX_DEPTH: u8 = 3; }
    }
    pub mod torii {
        pub const MAX_CONNECTIONS: usize = 1;
        pub const PROOF_MAX_BODY_BYTES: u64 = 9;
    }
    pub mod transaction {
        pub const fn max_tx_bytes() -> u64 { 10 }
        pub fn max_signatures() -> u64 { 16 }
        fn private() -> u64 { 1 }
        pub fn with_argument(x: u64) -> u64 { x }
    }
    #[cfg(test)]
    mod tests {
        const MAX_IN_TEST: usize = 1;
    }
    #[cfg(test)]
    /// Documented test module with a further attribute.
    #[allow(clippy::too_many_lines)]
    pub mod more_tests {
        const TEST_GAS_LIMIT: u64 = 1;
    }
    #[cfg(all(test, feature = "sim"))]
    mod sim_tests {
        const MAX_IN_SIM: usize = 1;
    }
    pub const OVERHEAD_AFTER_TESTS: usize = 5;
    """
    symbols = CHECKER["scope_symbols"]
    assert symbols(source, {"kind": "const"}, "t") == [
        "MAX_FRAME_BYTES",
        "RESERVE",
        "CAPACITY",
        "MAX_DEPTH",
        "MAX_CONNECTIONS",
        "PROOF_MAX_BODY_BYTES",
        "OVERHEAD_AFTER_TESTS",
    ]
    assert symbols(source, {"kind": "const", "module": ["pub mod queue {"]}, "t") == [
        "CAPACITY",
        "MAX_DEPTH",
    ]
    assert symbols(
        source, {"kind": "const", "module": ["pub mod queue {", "pub mod nested {"]}, "t"
    ) == ["MAX_DEPTH"]
    narrowed = {"kind": "const", "module": ["pub mod torii {"], "matching": "BODY_BYTES", "why": "x"}
    assert symbols(source, narrowed, "t") == ["PROOF_MAX_BODY_BYTES"]
    assert symbols(
        source, {"kind": "default_fn", "module": ["pub mod transaction {"]}, "t"
    ) == ["max_tx_bytes", "max_signatures"]
    error = CHECKER["ContractError"]
    with pytest.raises(error, match="states `why`"):
        symbols(source, {"kind": "const", "matching": "BODY"}, "t")
    with pytest.raises(error, match="is not in the file"):
        symbols(source, {"kind": "const", "module": ["pub mod absent {"]}, "t")
    with pytest.raises(error, match="unknown scope kind"):
        symbols(source, {"kind": "static"}, "t")

    # A new limit in a scanned file fails until it is listed or excluded.
    (tmp_path / "a.rs").write_text(
        "pub const MAX_A: u64 = 4;\nfn admit(len: u64) -> bool { len > MAX_A }\n", encoding="utf-8"
    )
    contract = {
        "bounds": [
            {"id": "queue.a", "owner": {"path": "a.rs", "symbol": "MAX_A", "kind": "const"}}
        ],
        "completeness": {"scopes": [{"path": "a.rs", "kind": "const"}], "excluded": []},
    }
    found: list = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []
    (tmp_path / "a.rs").write_text(
        "pub const MAX_A: u64 = 4;\npub const MAX_B: u64 = 8;\n", encoding="utf-8"
    )
    unlisted: list = []
    CHECKER["check_completeness"](tmp_path, contract, found, False, None, unlisted)
    assert found == ["completeness a.rs: `MAX_B` is neither a listed bound nor excluded with a reason"]
    assert [(scope["path"], symbol) for scope, symbol in unlisted] == [("a.rs", "MAX_B")]
    contract["completeness"]["excluded"] = [{"path": "a.rs", "reason": "derived", "symbols": ["MAX_B"]}]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    # An exclusion pins the defining expression of its limit; `--refresh` records it.
    assert found == [
        "completeness a.rs: the exclusion of `MAX_B` records no defining expression in `exprs`; "
        "run --refresh"
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found, True, [])
    assert found == []
    assert contract["completeness"]["excluded"][0]["exprs"] == {"MAX_B": "8"}
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []


def test_a_directory_scope_scans_every_production_source_below_it(tmp_path: Path) -> None:
    """A new file in a scanned directory is scanned; test and skipped sources are not."""
    tree = tmp_path / "crates" / "demo" / "src"
    for name, text in {
        "lib.rs": "pub const MAX_A: u64 = 4;\n",
        "wire/frame.rs": "pub const MAX_FRAME: u64 = 8;\npub const WIDTH: u64 = 2;\n",
        "wire/frame_tests.rs": "const MAX_IN_TEST_FILE: u64 = 1;\n",
        "wire/tests/cases.rs": "const MAX_IN_TEST_DIR: u64 = 1;\n",
        "wire/release_fixture.rs": "const MAX_FIXTURE: u64 = 1;\n",
        "sim/driver.rs": "const INGRESS_CAP: u64 = 1;\n",
        "tests.rs": "const MAX_ROOT_TESTS: u64 = 1;\n",
    }.items():
        file = tree / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
    scope = {
        "tree": "crates/demo/src",
        "kind": "const",
        "skip": [{"path": "crates/demo/src/sim", "why": "a simulator"}],
    }
    contract = {
        "bounds": [
            {"id": "queue.a", "owner": {"path": "crates/demo/src/lib.rs", "symbol": "MAX_A", "kind": "const"}}
        ],
        "completeness": {"scopes": [scope], "excluded": []},
    }
    expanded = CHECKER["expand_scopes"](tmp_path, contract["completeness"], [])
    assert [item["path"] for item in expanded] == [
        "crates/demo/src/lib.rs",
        "crates/demo/src/wire/frame.rs",
    ]
    found: list = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == [
        "completeness crates/demo/src/wire/frame.rs: `MAX_FRAME` is neither a listed bound "
        "nor excluded with a reason"
    ]
    # One reason may cover several files; every symbol is still named.
    contract["completeness"]["excluded"] = [
        {
            "reason": "wire geometry",
            "files": [
                {
                    "path": "crates/demo/src/wire/frame.rs",
                    "symbols": ["MAX_FRAME"],
                    "exprs": {"MAX_FRAME": "8"},
                }
            ],
        }
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []
    # A file added later is scanned without touching the contract.
    (tree / "wire" / "sync.rs").write_text("pub const SYNC_LIMIT: u64 = 3;\n", encoding="utf-8")
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == [
        "completeness crates/demo/src/wire/sync.rs: `SYNC_LIMIT` is neither a listed bound "
        "nor excluded with a reason"
    ]
    (tree / "wire" / "sync.rs").unlink()
    # A stale exclusion fails; `--refresh` removes it and reports it.
    contract["completeness"]["excluded"][0]["files"].append(
        {"path": "crates/demo/src/wire/frame.rs", "symbols": ["GONE_LIMIT"], "exprs": {"GONE_LIMIT": "1"}}
    )
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert len(found) == 1 and "the exclusion of `GONE_LIMIT`" in found[0]
    found, notes = [], []
    CHECKER["check_completeness"](tmp_path, contract, found, True, notes)
    assert found == [] and len(notes) == 1 and notes[0].endswith("matches no scanned limit; removed")
    assert contract["completeness"]["excluded"] == [
        {
            "reason": "wire geometry",
            "files": [
                {
                    "path": "crates/demo/src/wire/frame.rs",
                    "symbols": ["MAX_FRAME"],
                    "exprs": {"MAX_FRAME": "8"},
                }
            ],
        }
    ]
    # Malformed tree scopes are reported.
    for broken, fragment in (
        ({"tree": "crates/absent", "kind": "const"}, "the directory does not exist"),
        ({"tree": "crates/demo/src", "kind": "default_fn"}, "a tree scope scans constants"),
        (
            {"tree": "crates/demo/src", "kind": "const", "skip": [{"path": "crates/other", "why": "x"}]},
            "is not below the tree",
        ),
    ):
        found = []
        CHECKER["expand_scopes"](tmp_path, {"scopes": [broken]}, found)
        assert len(found) == 1 and fragment in found[0], found


def test_node_local_validity_limits_are_checked_against_the_typed_catalogs() -> None:
    """The contract's node-local list is a view of the node-configuration catalogs the code owns.

    The ZK consensus-policy hash inventory (`zk_validity_policy_v1`) and the
    execution limits of the execution-policy catalog (`pipeline_validity_policy_v1`)
    are committed State since F.4; their catalogs are still read from the same
    functions.
    """
    catalogs = {catalog["id"]: catalog for catalog in CONTRACT["catalogs"]}
    assert set(catalogs) == set(CHECKER["REQUIRED_CATALOGS"])
    local = ("nexus_consensus_policy_v1",)
    assert {name for name, catalog in catalogs.items() if catalog["source"] == "node_local"} == set(local)
    assert catalogs["zk_consensus_policy_hash"]["source"] == "committed"
    assert catalogs["execution_policy_digest_v1"]["source"] == "committed"
    listed = {
        identifier for name in local for identifier in catalogs[name]["fields"].values()
    }
    node_local = {
        item["id"]
        for item in CONTRACT["bounds"]
        if item["class"] == "consensus" and item["source"] == "node_local"
    }
    assert listed == node_local, "every node-local validity bound is a catalog field"
    assert len(node_local) == 10
    for identifier in node_local:
        assert bound(CONTRACT, identifier)["defect"]["owner"] == "F.4"
    pipeline = catalogs["execution_policy_digest_v1"]["fields"]
    for field in (
        "pipeline.ivm_max_decoded_instructions",
        "pipeline.ivm_max_decoded_bytes",
        "pipeline.overlay_max_instructions",
        "pipeline.overlay_max_bytes",
        "pipeline.quarantine_tx_max_cycles",
        "pipeline.quarantine_max_txs_per_block",
    ):
        assert field in pipeline
    zk = catalogs["zk_consensus_policy_hash"]["fields"]
    for field in (
        "pipa_r.max_envelope_bytes",
        "pipa_r.max_proof_bytes",
        "max_verify_batch",
        "sccp.max_proofs_per_transaction",
        "sccp.max_proofs_per_block",
        "sccp.max_proof_bytes_per_transaction",
        "max_nullifiers_per_tx",
        "gas.per_proof_byte",
    ):
        assert field in zk
    # The view covers each catalog exactly: listed, excluded and digest fields are the
    # source's field list.
    for catalog in catalogs.values():
        source = (ROOT / catalog["path"]).read_text(encoding="utf-8")
        observed = CHECKER["catalog_fields"](source, catalog, "t")
        excluded = [field for group in catalog["excluded"] for field in group["fields"]]
        recorded = list(catalog["fields"]) + excluded + list(catalog.get("digests", {}))
        assert sorted(observed) == sorted(recorded)
        assert all(group["reason"] for group in catalog["excluded"])
    assert len(catalogs["execution_policy_digest_v1"]["fields"]) == 15
    assert len(catalogs["zk_consensus_policy_hash"]["fields"]) == 45
    assert len(catalogs["nexus_consensus_policy_v1"]["fields"]) == 10
    # The execution-policy digest binds 164 fields: ten committee sizes come from a loop.
    execution_source = (ROOT / catalogs["execution_policy_digest_v1"]["path"]).read_text(encoding="utf-8")
    execution_fields = CHECKER["catalog_fields"](execution_source, catalogs["execution_policy_digest_v1"], "t")
    assert len(execution_fields) == 164
    assert "governance.fma_committee_size" in execution_fields
    # The Nexus digest is not a catalog of identities only: it is the third catalog.
    assert catalogs["execution_policy_digest_v1"]["digests"] == {
        "nexus.policy_digest": "nexus_consensus_policy_v1",
        "zk.policy_digest": "zk_consensus_policy_hash",
    }
    nexus = catalogs["nexus_consensus_policy_v1"]
    assert nexus["struct"] == "NexusConsensusPolicyPreimageV1"
    assert nexus["function"] == "nexus_consensus_policy_preimage_with_runtime_policies"
    for field, identifier in (
        ("atomic_private_settlement.max_participants", "transaction.config_private_settlement_max_participants"),
        ("atomic_private_settlement.max_carrier_bytes", "transaction.config_private_settlement_max_carrier_bytes"),
        ("atomic_private_settlement.max_proof_bytes", "proof.config_private_settlement_max_proof_bytes"),
        ("atomic_private_settlement.max_capsule_bytes", "proof.config_private_settlement_max_capsule_bytes"),
        ("atomic_private_settlement.sidecar_max_records", "storage.config_private_settlement_sidecar_max_records"),
        ("uploaded_models.max_plaintext_bytes_per_model", "storage.config_uploaded_model_max_plaintext_bytes"),
        ("da.ingest_quota_max_bytes_per_account", "storage.config_da_ingest_quota_max_bytes_per_account"),
    ):
        assert nexus["fields"][field] == identifier
    carrier = bound(CONTRACT, "transaction.config_private_settlement_max_carrier_bytes")
    assert carrier["value"] == 4 * MIB and carrier["defect"]["owner"] == "F.4"
    assert {site["stage"] for site in carrier["enforcement"]} >= {"follower"}
    # The carrier limit is above today's includable transaction bound: recorded, with an owner.
    includable = relation(CONTRACT, "private_settlement_carrier_within_includable_transaction")
    assert includable["expect"] == {"today": "violated", "x2_target": "holds"}
    assert includable["open"]["owner"] == "X.2"

    def unlisted(contract: dict) -> None:
        del contract["catalogs"][0]["fields"]["pipeline.ivm_max_decoded_bytes"]

    assert_fails(
        edited(unlisted),
        "field `pipeline.ivm_max_decoded_bytes` of `execution_policy_digest_v1` is neither "
        "listed as a bound nor excluded",
    )

    def unexcluded(contract: dict) -> None:
        contract["catalogs"][1]["excluded"][0]["fields"].pop()

    assert_fails(edited(unexcluded), "of `compute_zk_consensus_policy_hash` is neither listed")

    def loop_field_unexcluded(contract: dict) -> None:
        for group in contract["catalogs"][0]["excluded"]:
            if "governance.mpc_committee_size" in group["fields"]:
                group["fields"].remove("governance.mpc_committee_size")

    assert_fails(
        edited(loop_field_unexcluded),
        "field `governance.mpc_committee_size` of `execution_policy_digest_v1` is neither",
    )

    def nexus_field_unlisted(contract: dict) -> None:
        catalog = next(item for item in contract["catalogs"] if item["id"] == "nexus_consensus_policy_v1")
        for group in catalog["excluded"]:
            if "da.sample_size_max" in group["fields"]:
                group["fields"].remove("da.sample_size_max")

    assert_fails(
        edited(nexus_field_unlisted),
        "field `da.sample_size_max` of `nexus_consensus_policy_preimage_with_runtime_policies` is neither",
    )

    def invented(contract: dict) -> None:
        contract["catalogs"][1]["excluded"][0]["fields"].append("pipa_r.no_such_limit")

    assert_fails(edited(invented), "`pipa_r.no_such_limit` is not a field of")

    def twice(contract: dict) -> None:
        contract["catalogs"][0]["excluded"][0]["fields"].append("pipeline.overlay_max_bytes")

    assert_fails(edited(twice), "`pipeline.overlay_max_bytes` is recorded twice")

    def unlinked(contract: dict) -> None:
        del bound(contract, "decoded_scratch.config_ivm_max_decoded_bytes")["catalog"]

    assert_fails(edited(unlinked), "records `catalog` as execution_policy_digest_v1")

    def committed(contract: dict) -> None:
        item = bound(contract, "proof.config_pipa_r_max_envelope_bytes")
        item["source"] = "constant"
        del item["committed_as"]

    assert_fails(edited(committed), "a field of zk_consensus_policy_hash has source `committed`")

    def local_class(contract: dict) -> None:
        item = bound(contract, "storage.config_da_ingest_quota_max_bytes_per_account")
        item["class"] = "local_defer"

    assert_fails(edited(local_class), "the bound is classed consensus with its defect")

    def nexus_without_defect(contract: dict) -> None:
        del bound(contract, "storage.config_da_ingest_quota_max_count_per_account")["defect"]

    assert_fails(
        edited(nexus_without_defect),
        "storage.config_da_ingest_quota_max_count_per_account: a validity-affecting bound read "
        "from node-local configuration must be recorded as a defect",
    )

    def unreasoned(contract: dict) -> None:
        contract["catalogs"][0]["excluded"][0]["reason"] = ""

    assert_fails(edited(unreasoned), "an exclusion states its reason")

    def dropped(contract: dict) -> None:
        contract["catalogs"] = [
            item for item in contract["catalogs"] if item["id"] != "zk_consensus_policy_hash"
        ]

    assert_fails(edited(dropped), "catalogs: `zk_consensus_policy_hash` is checked against the source")
    assert_fails(
        edited(dropped),
        "`zk.policy_digest` is recorded as the digest of `zk_consensus_policy_hash`, which is "
        "not another catalog",
    )

    def nexus_dropped(contract: dict) -> None:
        # The first repair's state: the Nexus digest dismissed with a reason instead of checked.
        contract["catalogs"] = [
            item for item in contract["catalogs"] if item["id"] != "nexus_consensus_policy_v1"
        ]
        execution = contract["catalogs"][0]
        del execution["digests"]["nexus.policy_digest"]
        execution["excluded"].append(
            {"reason": "holds identities, not resource bounds", "fields": ["nexus.policy_digest"]}
        )
        for item in contract["bounds"]:
            if item.get("catalog", {}).get("id") == "nexus_consensus_policy_v1":
                del item["catalog"]

    assert_fails(edited(nexus_dropped), "catalogs: `nexus_consensus_policy_v1` is checked against the source")

    def stray(contract: dict) -> None:
        bound(contract, "queue.capacity")["catalog"] = {
            "id": "zk_consensus_policy_hash",
            "field": "max_verify_batch",
        }

    assert_fails(edited(stray), "queue.capacity: its `catalog` entry is not a field of that catalog")


def test_committed_policy_structs_are_catalogs_of_their_fields() -> None:
    """A field added to a committed policy struct is a bound the contract must list."""
    catalogs = {catalog["id"]: catalog for catalog in CONTRACT["catalogs"]}
    output = catalogs["execution_output_policy_v1"]
    fastpq = catalogs["fastpq_source_policy_v1"]
    assert output["source"] == fastpq["source"] == "committed"
    assert len(output["fields"]) == 7 and len(fastpq["fields"]) == 20
    assert output["excluded"] == fastpq["excluded"] == []
    assert fastpq["fields"]["mandatory.per_obligation.max_deltas"] == "work_budget.fastpq_mandatory_max_deltas"
    assert fastpq["fields"]["max_native_maintenance_invocations"] == (
        "work_budget.fastpq_native_maintenance_invocations"
    )
    for catalog in (output, fastpq):
        for identifier in catalog["fields"].values():
            assert bound(CONTRACT, identifier)["source"] == "committed"

    def field_unlisted(contract: dict) -> None:
        catalog = next(item for item in contract["catalogs"] if item["id"] == "execution_output_policy_v1")
        del catalog["fields"]["max_time_triggers"]
        del bound(contract, "block.execution_output_max_time_triggers")["catalog"]

    assert_fails(
        edited(field_unlisted),
        "field `max_time_triggers` of `ExecutionOutputPolicyV1` is neither listed",
    )

    def node_local(contract: dict) -> None:
        bound(contract, "work_budget.fastpq_block_max_deltas")["source"] = "constant"

    assert_fails(edited(node_local), "a field of fastpq_source_policy_v1 has source `committed`")


def test_catalog_field_reader(tmp_path: Path) -> None:
    source = """
    pub fn execution_policy_digest_v1(pipeline: &Pipeline) -> [u8; 32] {
        let mut policy = Fields::default();
        policy.push("pipeline.dynamic_prepass", &pipeline.dynamic_prepass);
        policy.push(
            "pipeline.overlay_max_bytes",
            &pipeline.overlay_max_bytes,
        );
        // policy.push("pipeline.commented_out", &0);
        for (name, size) in [
            (
                "governance.rules_committee_size",
                governance.rules_committee_size,
            ),
            ("governance.review_panel_size", governance.review_panel_size),
        ] {
            policy.push(name, &usize_field(size));
        }
        policy.finish()
    }

    pub fn compute_zk_consensus_policy_hash(zk: &Zk) -> [u8; 32] {
        let mut h = Sha256::new();
        zk_policy_put_bytes(&mut h, b"iroha:zk:consensus-policy:v1");
        zk_policy_put_u32(&mut h, "max_verify_batch", zk.max_verify_batch);
        zk_policy_put_usize(
            &mut h,
            "pipa_r.max_proof_bytes",
            zk.pipa_r.max_proof_bytes,
        );
        h.finalize().into()
    }
    """
    fields = CHECKER["catalog_fields"]
    push = {"function": "execution_policy_digest_v1", "field_form": "policy_push", "path": "a.rs"}
    assert fields(source, push, "t") == [
        "pipeline.dynamic_prepass",
        "pipeline.overlay_max_bytes",
        "governance.rules_committee_size",
        "governance.review_panel_size",
    ]
    put = {"function": "compute_zk_consensus_policy_hash", "field_form": "zk_policy_put", "path": "a.rs"}
    assert fields(source, put, "t") == ["max_verify_batch", "pipa_r.max_proof_bytes"]
    error = CHECKER["ContractError"]
    with pytest.raises(error, match="is not in a.rs"):
        fields(source, {**push, "function": "absent"}, "t")
    with pytest.raises(error, match="unknown field form"):
        fields(source, {**push, "field_form": "macro"}, "t")
    # A field added to the loop's table is read like any other.
    grown = source.replace(
        '("governance.review_panel_size", governance.review_panel_size),',
        '("governance.review_panel_size", governance.review_panel_size),\n'
        '            ("governance.new_committee_size", governance.new_committee_size),',
    )
    assert fields(grown, push, "t")[-1] == "governance.new_committee_size"
    # A field whose name the reader cannot read fails instead of being skipped.
    for unreadable in (
        source.replace('policy.push("pipeline.dynamic_prepass",', "policy.push(PREPASS_FIELD,"),
        source.replace("policy.push(name, &usize_field(size));", "policy.push(other, &usize_field(size));"),
        source.replace('"governance.review_panel_size", governance.review_panel_size', "REVIEW, 3"),
        source.replace("] {\n            policy.push(name", "] { }\n        {\n            policy.push(name"),
    ):
        with pytest.raises(error, match="binds a field whose name the checker cannot read"):
            fields(unreadable, push, "t")
    with pytest.raises(error, match="`zk_policy_put_u32\\(` call binds a field whose name"):
        fields(source.replace('"max_verify_batch"', "MAX_BATCH_FIELD"), put, "t")

    # A typed preimage struct: nested structs contribute their fields below the field's name.
    structs = """
    #[derive(Encode)]
    struct PreimageV1 {
        version: u8,
        /// Routing identities.
        routing: RoutingV1,
        rules: Vec<RuleV1>,
        settlement: SettlementV1,
        sponsors: Vec<(u64, ProgramId)>,
        digest: Option<[u8; 32]>,
        delay: DurationV1,
    }
    #[derive(Encode)]
    struct RoutingV1 { default_lane: u32 }
    struct RuleV1 { lane: u32, account: Option<String> }
    struct SettlementV1 {
        pub max_participants: u16,
        pub(crate) max_carrier_bytes: u64,
    }
    struct DurationV1 { seconds: u64, nanoseconds: u32 }
    pub fn preimage(config: &Config) -> Vec<u8> {
        let value = PreimageV1 { version: 1, routing: RoutingV1 { default_lane: 0 } };
        value.encode()
    }
    pub fn unrelated() -> u8 { 0 }
    """
    tree = {"struct": "PreimageV1", "function": "preimage", "field_form": "struct_tree", "path": "a.rs"}
    assert fields(structs, tree, "t") == [
        "version",
        "routing.default_lane",
        "rules.lane",
        "rules.account",
        "settlement.max_participants",
        "settlement.max_carrier_bytes",
        "sponsors",
        "digest",
        "delay.seconds",
        "delay.nanoseconds",
    ]
    assert CHECKER["struct_field_tree"](structs, "SettlementV1", "t") == [
        "max_participants",
        "max_carrier_bytes",
    ]
    with pytest.raises(error, match="struct `AbsentV1` is not defined"):
        fields(structs, {"struct": "AbsentV1", "field_form": "struct_tree", "path": "a.rs"}, "t")
    with pytest.raises(error, match="`unrelated` no longer builds `PreimageV1`"):
        fields(structs, {**tree, "function": "unrelated"}, "t")
    with pytest.raises(error, match="missing struct"):
        fields(structs, {"field_form": "struct_tree", "path": "a.rs"}, "t")

    # A field added to the function fails the view until it is listed or excluded.
    (tmp_path / "a.rs").write_text(
        "pub const MAX_K: u32 = 16;\nfn admit(k: u32) -> bool { k > MAX_K }\n" + source + structs,
        encoding="utf-8",
    )
    contract = {
        "bounds": [
            {
                "id": "proof.k",
                "source": "node_local",
                "class": "consensus",
                "catalog": {"id": "zk_consensus_policy_hash", "field": "max_verify_batch"},
            },
            {
                "id": "transaction.carrier",
                "source": "node_local",
                "class": "consensus",
                "catalog": {"id": "nexus_consensus_policy_v1", "field": "settlement.max_carrier_bytes"},
            },
        ],
        "catalogs": [
            {
                **put,
                "id": "zk_consensus_policy_hash",
                "source": "node_local",
                "what": "x",
                "fields": {"max_verify_batch": "proof.k"},
                "excluded": [],
            },
            {
                **tree,
                "id": "nexus_consensus_policy_v1",
                "source": "node_local",
                "what": "x",
                "fields": {"settlement.max_carrier_bytes": "transaction.carrier"},
                "excluded": [
                    {
                        "reason": "identities and windows",
                        "fields": [
                            "version", "routing.default_lane", "rules.lane", "rules.account",
                            "sponsors", "digest", "delay.seconds", "delay.nanoseconds",
                        ],
                    }
                ],
            },
        ],
    }
    found: list = []
    unlisted: list = []
    CHECKER["check_catalogs"](tmp_path, contract, TASKS, found, unlisted)
    assert found == [
        "catalog zk_consensus_policy_hash: field `pipa_r.max_proof_bytes` of "
        "`compute_zk_consensus_policy_hash` is neither listed as a bound nor excluded with a reason",
        "catalog nexus_consensus_policy_v1: field `settlement.max_participants` of `preimage` "
        "is neither listed as a bound nor excluded with a reason",
        "catalogs: `execution_policy_digest_v1` is checked against the source",
        "catalogs: `execution_output_policy_v1` is checked against the source",
        "catalogs: `fastpq_source_policy_v1` is checked against the source",
    ]
    assert [(catalog["id"], field) for catalog, field in unlisted] == [
        ("zk_consensus_policy_hash", "pipa_r.max_proof_bytes"),
        ("nexus_consensus_policy_v1", "settlement.max_participants"),
    ]


def test_derived_bounds_are_recomputed_and_join_the_relations() -> None:
    derived = {item["id"]: item for item in CONTRACT["derived"]}
    effective = derived["block.effective_max_own_transactions"]
    assert effective["value"] == 11
    assert bound(CONTRACT, "block.max_transactions")["value"] == 512
    assert "not the largest number" in bound(CONTRACT, "block.max_transactions")["what"]
    assert any(
        site["contains"] == ".min(fastpq_inputs)" for site in effective["enforcement"]
    )
    assert relation(CONTRACT, "fastpq_network_inputs_within_transaction_ceiling")["expect"] == {
        "today": "holds",
        "x2_target": "holds",
    }

    def stale(contract: dict) -> None:
        contract["derived"][0]["value"] = 512

    assert_fails(edited(stale), "the formula gives 11; the contract records 512")

    def unsited(contract: dict) -> None:
        contract["derived"][0]["enforcement"] = []

    assert_fails(edited(unsited), "names its enforcement sites and tests")

    def site(contract: dict) -> None:
        contract["derived"][0]["enforcement"][0]["contains"] = ".min(no_such_cap)"

    assert_fails(edited(site), "no longer contains `.min(no_such_cap)`")

    def clash(contract: dict) -> None:
        contract["derived"][0]["id"] = "block.max_transactions"

    assert_fails(edited(clash), "the id is already a bound")


def test_signed_attachment_bounds_hold_a_ceiling_proof() -> None:
    """I.1: a ceiling-sized proof is one signed attachment occurrence within the transaction cap."""
    ceiling = bound(CONTRACT, "x509.max_proof_bytes")["value"]
    occurrence = bound(CONTRACT, "attachment.occurrence_max_bytes")
    frame = bound(CONTRACT, "attachment.signed_frame_max_bytes")
    assert (occurrence["value"], occurrence["class"]) == (ceiling, "consensus")
    assert (frame["value"], frame["class"]) == (ceiling + 64 * 1024, "consensus")
    assert frame["value"] <= bound(CONTRACT, "transaction.max_tx_bytes")["value"]
    assert bound(CONTRACT, "attachment.max_occurrences")["value"] == 16
    assert bound(CONTRACT, "attachment.max_actions")["value"] == 16
    carried = relation(CONTRACT, "attachment_list_frame_holds_a_ceiling_proof")
    assert carried["expect"] == {"today": "holds", "x2_target": "holds"}
    assert "open" not in carried and carried["tests"]
    # The design is implemented: bounds with owners, no declared item.
    assert all(item["id"] != "attachment.signed_inline_occurrences" for item in CONTRACT["declared"])
    for identifier in (
        "attachment.occurrence_max_bytes",
        "attachment.max_occurrences",
        "attachment.max_actions",
        "attachment.signed_frame_max_bytes",
        "attachment.invocation_max_call_path_depth",
        "attachment.operation_max_wire_id_bytes",
    ):
        item = bound(CONTRACT, identifier)
        assert item["owner"]["path"].endswith("transaction/signed_attachments.rs"), identifier
        assert item["tests"] and "test_gap" not in item, identifier
        assert {site["stage"] for site in item["enforcement"]} >= {"sdk", "queue"}, identifier

    def shrunk(contract: dict) -> None:
        relation(contract, "attachment_list_frame_holds_a_ceiling_proof")["expect"]["today"] = "violated"

    assert_fails(edited(shrunk), "holds under `today`; the contract records violated")

    def two_ceilings(contract: dict) -> None:
        relation(contract, "attachment_frame_is_one_ceiling_occurrence_plus_allowance")["expr"] = (
            "attachment.signed_frame_max_bytes - attachment.occurrence_max_bytes == 9437184"
        )

    assert_fails(edited(two_ceilings), "violated under `today`; the contract records holds")


def test_proof_attachment_list_is_a_local_bound_outside_the_signed_transaction() -> None:
    """The former transaction field remains the prover API body and SDK staging list."""
    frame = bound(CONTRACT, "attachment.list_max_canonical_frame_bytes")
    count = bound(CONTRACT, "attachment.list_max_attachments")
    assert (frame["value"], count["value"]) == (8 * MIB, 16)
    for item in (frame, count):
        assert (item["class"], item["validity"], item["on_exhaustion"]) == (
            "local_defer",
            False,
            "local_refusal",
        )
        assert relation(CONTRACT, item["guarded_by"])["expect"]["today"] == "holds"
        assert all(site["path"] != "crates/iroha_core/src/tx.rs" for site in item["enforcement"])
    assert frame["value"] < bound(CONTRACT, "attachment.signed_frame_max_bytes")["value"]

    def unguarded(contract: dict) -> None:
        del bound(contract, "attachment.list_max_canonical_frame_bytes")["guarded_by"]

    assert_fails(edited(unguarded), "a locally refusing bound names its relation in `guarded_by`")


def test_ram_lfe_budgets_cover_the_full_workload() -> None:
    section = CONTRACT["ram_lfe"]
    components = {budget["component"] for budget in section["budgets"]}
    assert components == set(CHECKER["WORKLOAD_COMPONENTS"])
    used = set()
    for budget in section["budgets"]:
        used.update(budget["inputs"])
    assert {item["id"] for item in section["open_inputs"]} <= used
    shapes = {item["id"] for item in CONTRACT["bounds"] if item["id"].startswith("ram_lfe.shape_")}
    assert len(shapes) == 10 and shapes <= used
    by_id = {budget["id"]: budget for budget in section["budgets"]}
    # The parts the first derivation missed have a formula, and no invented number.
    for identifier, component in (
        ("ram_lfe.key_registration_transaction_bytes", "key_registration"),
        ("ram_lfe.wellformedness_verification_gas", "verification"),
        ("ram_lfe.opening_verification_gas", "opening"),
        ("ram_lfe.threshold_opening_transaction_bytes", "threshold_opening"),
        ("ram_lfe.threshold_opening_verification_gas", "threshold_opening"),
        ("ram_lfe.validator_request_scratch_bytes", "validator_scratch"),
        ("ram_lfe.validator_receipt_scratch_bytes", "validator_scratch"),
        ("ram_lfe.affine_evaluation_work_units", "class_affine"),
        ("ram_lfe.bounded_evaluation_work_units", "class_bounded"),
        ("ram_lfe.refresh_evaluation_work_units", "class_refresh"),
    ):
        assert by_id[identifier]["component"] == component
        assert by_id[identifier]["value"] is None
    assert "ram_lfe.evaluation_key_bytes" in by_id["ram_lfe.key_registration_transaction_bytes"]["inputs"]
    assert by_id["ram_lfe.bounded_multiplicative_depth"]["value"] == 16
    assert by_id["ram_lfe.refresh_multiplicative_depth"]["value"] == 16 * 65
    assert by_id["ram_lfe.cleartext_trace_scalars"]["value"] == 257 * 36
    assert relation(CONTRACT, "ram_lfe_leakage_bits_are_the_output_space")["expect"]["today"] == "holds"
    assert 2**512 < 257**64 < 2**513

    def unused_input(contract: dict) -> None:
        contract["ram_lfe"]["budgets"] = [
            budget
            for budget in contract["ram_lfe"]["budgets"]
            if "ram_lfe.evaluation_key_bytes" not in budget["inputs"]
        ]

    assert_fails(
        edited(unused_input),
        "ram_lfe input ram_lfe.evaluation_key_bytes: an open input is used by a budget formula",
    )

    def unused_shape(contract: dict) -> None:
        contract["ram_lfe"]["budgets"] = [
            budget
            for budget in contract["ram_lfe"]["budgets"]
            if "ram_lfe.shape_bounded_max_rank" not in budget["inputs"]
        ]

    assert_fails(
        edited(unused_shape),
        "ram_lfe.shape_bounded_max_rank: a RAM-LFE shape bound is used by a budget formula",
    )

    def no_threshold(contract: dict) -> None:
        contract["ram_lfe"]["budgets"] = [
            budget
            for budget in contract["ram_lfe"]["budgets"]
            if budget["component"] != "threshold_opening"
        ]

    assert_fails(edited(no_threshold), "the workload component `threshold_opening` has a budget")

    def unlabelled(contract: dict) -> None:
        del contract["ram_lfe"]["budgets"][0]["component"]

    assert_fails(edited(unlabelled), "names its workload `component`")


def test_behaviors_name_tests_at_every_required_stage() -> None:
    behaviors = {entry["id"]: entry for entry in CONTRACT["behaviors"]}
    for identifier, stages in CHECKER["BEHAVIOR_STAGES"].items():
        reached = {entry["stage"] for entry in behaviors[identifier]["tests"]}
        assert set(stages) <= reached, identifier
    malformed = behaviors["malformed_carried_evidence_rejects_deterministically"]
    names = {entry["name"] for entry in malformed["tests"]}
    # Evidence carried by a transaction, at admission and in block validation.
    assert "malformed_proof_attachments_rejected_at_transaction_admission" in names
    assert "attachment_list_bounds_accept_the_limit_and_reject_one_over" in names
    assert "privacy_proof_ceiling_accepts_the_limit_and_rejects_one_over" in names
    deferral = {entry["name"] for entry in behaviors["missing_local_resource_defers"]["tests"]}
    assert "deferred_includable_assessment_defers_queue_admission_without_custody" in deferral

    def consensus_only(contract: dict) -> None:
        entry = next(
            item
            for item in contract["behaviors"]
            if item["id"] == "malformed_carried_evidence_rejects_deterministically"
        )
        entry["tests"] = [item for item in entry["tests"] if item["stage"] == "follower"]

    assert_fails(edited(consensus_only), "names a test at the `queue` stage")

    def no_queue_deferral(contract: dict) -> None:
        entry = next(
            item for item in contract["behaviors"] if item["id"] == "missing_local_resource_defers"
        )
        entry["tests"] = [item for item in entry["tests"] if item["stage"] != "queue"]

    assert_fails(edited(no_queue_deferral), "`missing_local_resource_defers` names a test at the `queue` stage")


def test_refresh_rewrites_values_and_expressions_and_keeps_classifications(tmp_path: Path) -> None:
    (tmp_path / "a.rs").write_text(
        "pub const LIMIT: u64 = 8 * 1024;\npub const DOUBLE: u64 = LIMIT * 2;\n"
        "fn admit(len: u64) -> bool { len > LIMIT || len > DOUBLE }\n"
        "#[test]\nfn limit_is_inclusive() {}\n",
        encoding="utf-8",
    )
    owner = lambda symbol: {"path": "a.rs", "symbol": symbol, "kind": "const"}  # noqa: E731
    contract = {
        "bounds": [
            {
                "id": "queue.limit",
                "group": "queue",
                "what": "A limit.",
                "unit": "bytes",
                "value": 4_096,
                "source": "constant",
                "class": "consensus",
                "owner": {**owner("LIMIT"), "expr": "4 * 1024"},
                "enforcement": [{"stage": "queue", "path": "a.rs", "contains": "len > LIMIT"}],
                "tests": [{"path": "a.rs", "name": "limit_is_inclusive"}],
            },
            {
                "id": "queue.double",
                "group": "queue",
                "what": "Twice the limit.",
                "unit": "bytes",
                "source": "constant",
                "class": "consensus",
                "owner": owner("DOUBLE"),
                "refs": {"LIMIT": "queue.limit"},
            },
        ]
    }
    before = copy.deepcopy(contract)
    found: list = []
    values = CHECKER["verify_bounds"](tmp_path, contract, found, True)
    assert found == [] and values == {"queue.limit": 8_192, "queue.double": 16_384}
    assert contract["bounds"][0]["owner"]["expr"] == "8 * 1024"
    assert contract["bounds"][0]["value"] == 8_192
    assert contract["bounds"][1]["owner"]["expr"] == "LIMIT * 2"
    assert contract["bounds"][1]["value"] == 16_384
    # Nothing but the expression and the value changed.
    for refreshed, original in zip(contract["bounds"], before["bounds"]):
        for key in original:
            if key not in ("value", "owner"):
                assert refreshed[key] == original[key]
        assert refreshed["owner"]["symbol"] == original["owner"]["symbol"]
    # The refreshed contract verifies; the stale one did not.
    assert CHECKER["verify_bounds"](tmp_path, contract, found) == values and found == []
    stale: list = []
    CHECKER["verify_bounds"](tmp_path, before, stale)
    assert stale and "is now `8 * 1024`" in stale[0]
    # Derived bounds and closed budgets are recomputed by the same refresh.
    stale_tracked = copy.deepcopy(CONTRACT)
    stale_tracked["derived"][0]["value"] = 512
    stale_tracked["ram_lfe"]["budgets"][0]["value"] = 1
    stale_problems = CHECKER["check"](ROOT, copy.deepcopy(stale_tracked), TASKS)
    assert any("the formula gives 11; the contract records 512" in item for item in stale_problems)
    assert any("the formula gives 12288; the contract records 1" in item for item in stale_problems)
    assert CHECKER["check"](ROOT, stale_tracked, TASKS, True) == []
    assert CHECKER["render"](stale_tracked) == CHECKER["render"](CONTRACT)
    # Refreshing the tracked contract changes nothing and leaves it valid.
    tracked = copy.deepcopy(CONTRACT)
    assert CHECKER["check"](ROOT, tracked, TASKS, True) == []
    assert CHECKER["render"](tracked) == CHECKER["render"](CONTRACT)
    assert CHECKER["render"](CONTRACT) == CHECKER["CONTRACT"].read_text(encoding="utf-8")


def test_refresh_reports_what_it_changes_and_never_adds_a_classification() -> None:
    """`--refresh` rewrites counts and drops stale exclusions, and says so."""
    stale = copy.deepcopy(CONTRACT)
    frame = next(
        site
        for site in bound(stale, "attachment.list_max_canonical_frame_bytes")["enforcement"]
        if site["contains"].startswith("if canonical_frame_len >")
    )
    del frame["count"]
    stale["completeness"]["excluded"][0]["symbols"].append("NO_SUCH_LIMIT")
    assert len(CHECKER["check"](ROOT, copy.deepcopy(stale), TASKS)) == 2
    notes: list = []
    assert CHECKER["check"](ROOT, stale, TASKS, True, notes) == []
    assert len(notes) == 2
    assert any("now occurs 2 time(s), was 1" in note for note in notes)
    assert any("`NO_SUCH_LIMIT`" in note and note.endswith("removed") for note in notes)
    assert CHECKER["render"](stale) == CHECKER["render"](CONTRACT)
    # Refresh classifies nothing: an unlisted limit and a gone site still fail after it.
    unlisted = copy.deepcopy(CONTRACT)
    unlisted["bounds"] = [
        item for item in unlisted["bounds"] if item["id"] != "work_budget.max_contract_call_depth"
    ]
    bound(unlisted, "sync.max_proposal_bytes")["enforcement"][0]["contains"] = "|| no_such_comparison"
    remaining = CHECKER["check"](ROOT, unlisted, TASKS, True, [])
    assert any("`MAX_CONTRACT_CALL_DEPTH` is neither a listed bound nor excluded" in item for item in remaining)
    assert any("no longer contains `|| no_such_comparison`" in item for item in remaining)


def test_propose_suggests_entries_and_writes_nothing(tmp_path: Path, capsys) -> None:
    """`--propose` prints a skeleton with candidate sites and tests for an unlisted limit."""
    crate = tmp_path / "crates" / "demo"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname = \"demo\"\n", encoding="utf-8")
    (crate / "src" / "lib.rs").write_text(
        "pub mod limits {\n    /// Largest frame.\n    pub const MAX_FRAME_BYTES: usize = 4 * 1024;\n}\n"
        "pub const DOUBLE_LIMIT: usize = limits::MAX_FRAME_BYTES * 2;\n"
        "pub fn admit(len: usize) -> bool {\n    if len > limits::MAX_FRAME_BYTES {\n        return false;\n    }\n"
        "    true\n}\n"
        "pub fn again(len: usize) -> bool {\n    if len > limits::MAX_FRAME_BYTES {\n        return false;\n    }\n"
        "    true\n}\n"
        "#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn frame_limit_is_inclusive() {\n"
        "        assert!(admit(limits::MAX_FRAME_BYTES));\n    }\n    #[test]\n    #[ignore]\n"
        "    fn slow_frame_case() {\n        assert!(!admit(limits::MAX_FRAME_BYTES + 1));\n    }\n"
        "    #[test]\n    fn unrelated() {}\n}\n",
        encoding="utf-8",
    )
    scope = {"path": "crates/demo/src/lib.rs", "kind": "const", "module": ["pub mod limits {"]}
    entry = CHECKER["propose_entry"](tmp_path, scope, "MAX_FRAME_BYTES", {}, [])
    assert entry["owner"] == {
        "path": "crates/demo/src/lib.rs",
        "symbol": "MAX_FRAME_BYTES",
        "kind": "const",
        "anchor": ["pub mod limits {"],
        "expr": "4 * 1024",
    }
    assert entry["value"] == 4096 and entry["source"] == "constant"
    # The comparison is proposed with its occurrence count; the definition that only
    # multiplies the constant, the ignored test and the unrelated test are not.
    assert entry["candidate_sites"] == [
        {
            "stage": "<stage>",
            "path": "crates/demo/src/lib.rs",
            "contains": "if len > limits::MAX_FRAME_BYTES {",
            "count": 2,
        }
    ]
    assert entry["candidate_tests"] == [
        {"path": "crates/demo/src/lib.rs", "name": "frame_limit_is_inclusive"}
    ]
    # An expression that names another constant is not guessed.
    derived = CHECKER["propose_entry"](
        tmp_path, {"path": "crates/demo/src/lib.rs", "kind": "const"}, "DOUBLE_LIMIT", {}, []
    )
    assert derived["value"] is None and "add `refs`" in derived["value_note"]
    # A further word finds the sites of a configuration field read through another name.
    worded = CHECKER["propose_entry"](
        tmp_path, {"path": "crates/demo/src/lib.rs", "kind": "const"}, "DOUBLE_LIMIT", {}, [], ("admit",)
    )
    assert {test["name"] for test in worded["candidate_tests"]} == {"frame_limit_is_inclusive"}

    # On the tracked contract there is nothing to propose, and nothing is written.
    before = CHECKER["CONTRACT"].read_text(encoding="utf-8")
    assert CHECKER["propose"](ROOT, copy.deepcopy(CONTRACT), TASKS, []) == []
    assert CHECKER["main"](["--propose"]) == 0
    assert "nothing to propose" in capsys.readouterr().out
    assert CHECKER["CONTRACT"].read_text(encoding="utf-8") == before
    # An unlisted limit, an unrecorded catalog field, a stale exclusion and a gone site are
    # each reported with what to do.
    drifted = copy.deepcopy(CONTRACT)
    drifted["bounds"] = [
        item for item in drifted["bounds"] if item["id"] != "work_budget.max_contract_call_depth"
    ]
    nexus = next(item for item in drifted["catalogs"] if item["id"] == "nexus_consensus_policy_v1")
    nexus["excluded"][0]["fields"].remove("version")
    drifted["completeness"]["excluded"][0]["symbols"].append("NO_SUCH_LIMIT")
    bound(drifted, "sync.max_proposal_bytes")["enforcement"][0]["contains"] = (
        "|| header.payload_len as usize >= MAX_PROPOSAL_BYTES"
    )
    lines = CHECKER["propose"](ROOT, drifted, TASKS, [])
    text = "\n".join(lines)
    assert "# unlisted limit `MAX_CONTRACT_CALL_DEPTH` in crates/ivm/src/limits.rs" in text
    assert '"contains": "if self.len() >= MAX_CONTRACT_CALL_DEPTH {"' in text
    assert "protected_depth_limit_retains_full_lifo_stack_on_refusal_and_reuses_popped_slot" in text
    assert "# catalog nexus_consensus_policy_v1: field `version` is not recorded" in text
    assert "# --refresh would change: completeness: the exclusion of `NO_SUCH_LIMIT`" in text
    assert "# sync.max_proposal_bytes: site `|| header.payload_len as usize >= MAX_PROPOSAL_BYTES` is gone" in text
    assert "#   closest: || header.payload_len as usize > MAX_PROPOSAL_BYTES" in text
    # The proposal did not edit the contract it was given.
    assert "NO_SUCH_LIMIT" in drifted["completeness"]["excluded"][0]["symbols"]
    one = CHECKER["propose"](ROOT, CONTRACT, TASKS, [], "crates/ivm/src/limits.rs:MAX_CONTRACT_CALL_DEPTH")
    assert len(one) == 1 and json.loads(one[0])["value"] == 1024


def test_text_that_cites_a_bound_cites_one_that_exists() -> None:
    cited = CHECKER["_CITED_ID"]
    assert cited.findall("bounded by guest_memory.heap_max_bytes and rs16.* (see queue.rs)") == [
        "guest_memory.heap_max_bytes",
        "queue.rs",
    ]
    assert cited.findall("crates/iroha_core/src/queue.rs and transaction.max_tx_bytes()") == []

    def renamed(contract: dict) -> None:
        # A bound renamed without its reasons: every text that cited it is reported once.
        bound(contract, "block.payload_transaction_reserve_bytes")["id"] = "block.payload_reserve_bytes"
        for item in contract["relations"]:
            item["expr"] = item["expr"].replace(
                "block.payload_transaction_reserve_bytes", "block.payload_reserve_bytes"
            )

    found = problems(edited(renamed))
    assert any(
        "the text cites `block.payload_transaction_reserve_bytes`, which is not a bound" in item
        for item in found
    ), found

    def miscited(contract: dict) -> None:
        bound(contract, "work_budget.fuel")["test_note"] += " See work_budget.gas_limit_total."

    assert_fails(edited(miscited), "bounds/test_note: the text cites `work_budget.gas_limit_total`")


def test_lane_route_statements_state_that_there_is_no_rescue_above_the_global_budget() -> None:
    """The includable bound holds for the route at admission; it is not a promise of inclusion."""
    agreement = CONTRACT["stage_decisions"]["agreement"]
    assert "nothing admitted is unincludable" not in agreement
    assert "only its lane's proposer can carry it" in agreement
    assert "stays queued until it expires" in agreement
    system = (ROOT / "crates/iroha_data_model/src/parameter/system.rs").read_text(encoding="utf-8")
    payload = (ROOT / "crates/iroha_core/src/sumeragi/payload.rs").read_text(encoding="utf-8")
    assert "rescues it when the lane stalls" not in system
    assert "never left waiting" not in system
    assert "The bound is not a promise of inclusion." in system
    assert "with the\n/// global chain as its rescue" not in payload
    lanes = (ROOT / "specs/sumeragi_lanes.md").read_text(encoding="utf-8")
    assert "such a\ntransaction is never rescued" in lanes
    proposer = next(entry for entry in CONTRACT["stage_tests"] if entry["stage"] == "proposer")
    assert "global_rescue_carries_a_stalled_lane_transaction_only_within_the_global_budget" in {
        test["name"] for test in proposer["tests"]
    }
    assert "if next > max_bytes {" in {site["contains"] for site in proposer["enforcement"]}


PATH_CRATES = (
    "crates/iroha_data_model/src",
    "crates/iroha_torii/src",
    "crates/iroha_core/src",
    "crates/iroha_core_zk/src",
)
# The limits the F.2 evidence review found enforced on the path and outside every scope,
# and the generic path limits found while the four crates were enumerated.
NAMED_PATH_LIMITS = (
    (
        "proof.private_settlement_max_proof_bytes",
        "crates/iroha_data_model/src/nexus/private_settlement.rs",
        "PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1",
        8 * MIB,
    ),
    (
        "proof.sccp_source_proof_max_bytes",
        "crates/iroha_data_model/src/sccp/inbound.rs",
        "SCCP_SOURCE_PROOF_MAX_BYTES_V1",
        8 * MIB,
    ),
    (
        "proof.axt_proof_blob_max_payload_bytes",
        "crates/iroha_data_model/src/nexus/axt.rs",
        "MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES",
        2 * MIB,
    ),
    (
        "transaction.torii_app_api_payload_max_bytes",
        "crates/iroha_torii/src/routing.rs",
        "MAX_TRANSACTION_PAYLOAD_BYTES",
        16 * MIB,
    ),
    (
        "block.parent_service_commit_qc_max_bytes",
        "crates/iroha_data_model/src/consensus.rs",
        "PARENT_SERVICE_COMMIT_QC_MAX_BYTES",
        512 * 1024,
    ),
    (
        "transaction.metadata_value_default_max_bytes",
        "crates/iroha_core/src/smartcontracts/limits.rs",
        "DEFAULT_JSON_LIMIT",
        MIB,
    ),
    (
        "transaction.instruction_payload_default_max_bytes",
        "crates/iroha_core/src/smartcontracts/isi/triggers/mod.rs",
        "DEFAULT_MAX",
        MIB,
    ),
)


def _with_override(path: str, text: str, contract: dict | None = None) -> list:
    """Every problem of the tracked contract when `path` reads as `text` (in memory only)."""
    CHECKER["_OVERRIDES"][path] = text
    try:
        found: list = []
        contract = CONTRACT if contract is None else contract
        CHECKER["verify_bounds"](ROOT, contract, found)
        CHECKER["check_completeness"](ROOT, contract, found)
        return found
    finally:
        del CHECKER["_OVERRIDES"][path]


def test_the_crates_on_the_path_are_scanned_whole() -> None:
    """Data model, Torii, node and proof crate: every limit is a bound or a pinned exclusion."""
    section = CONTRACT["completeness"]
    trees = {scope["tree"]: scope for scope in section["scopes"] if "tree" in scope}
    for crate in PATH_CRATES:
        assert crate in trees and "skip" not in trees[crate], crate
        # No narrower tree of the same crate remains beside it.
        assert not [tree for tree in trees if tree.startswith(crate + "/")], crate
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    scanned = {scope["path"] for scope in scopes}
    for crate in PATH_CRATES:
        files = [path for path in scanned if path.startswith(crate + "/")]
        assert len(files) > 100, (crate, len(files))
    # The limits the evidence review named are listed bounds with their owner in a scope.
    for identifier, path, symbol, value in NAMED_PATH_LIMITS:
        item = bound(CONTRACT, identifier)
        assert (item["owner"]["path"], item["owner"]["symbol"]) == (path, symbol), identifier
        assert item["value"] == value and item["enforcement"], identifier
        assert path in scanned, identifier
        assert item.get("tests") or item.get("test_gap") or item["class"] == "local_defer", identifier
    # Every scanned limit of the four crates is listed or excluded, and every exclusion
    # pins the defining expression of its limit.
    listed = {
        (item["owner"]["path"], item["owner"]["symbol"])
        for item in CONTRACT["bounds"]
        if item["owner"]["kind"] in ("const", "fn")
    }
    pinned: dict = {}
    for group in section["excluded"]:
        assert group["reason"], group
        for holder in group["files"] if "files" in group else [group]:
            assert set(holder["exprs"]) == set(holder["symbols"]), holder["path"]
            for symbol in holder["symbols"]:
                pinned[(holder["path"], tuple(holder.get("module") or ()), symbol)] = holder["exprs"][symbol]
    counted = {crate: 0 for crate in PATH_CRATES}
    for scope in scopes:
        crate = next((crate for crate in PATH_CRATES if scope["path"].startswith(crate + "/")), None)
        if crate is None:
            continue
        source = CHECKER["_read"](ROOT, scope["path"], "test")
        for symbol in CHECKER["scope_symbols"](source, scope, "test"):
            counted[crate] += 1
            key = (scope["path"], tuple(scope.get("module") or ()), symbol)
            assert (scope["path"], symbol) in listed or key in pinned, key
            if key in pinned:
                assert pinned[key] == CHECKER["scope_expression"](source, scope, symbol, "test"), key
    # The enumeration is whole crates, not a sample: hundreds of limits each.
    assert counted["crates/iroha_data_model/src"] > 600
    assert counted["crates/iroha_torii/src"] > 400
    assert counted["crates/iroha_core/src"] > 300
    assert counted["crates/iroha_core_zk/src"] > 120
    # Removing a named bound leaves its limit unclassified; removing a crate tree fails.
    for identifier, path, symbol, _ in NAMED_PATH_LIMITS:

        def unlisted(contract: dict, identifier: str = identifier) -> None:
            contract["bounds"] = [item for item in contract["bounds"] if item["id"] != identifier]
            contract["relations"] = [
                item for item in contract["relations"] if identifier not in item["expr"]
            ]

        assert_fails(edited(unlisted), f"completeness {path}: `{symbol}` is neither a listed bound nor excluded")
    for crate in PATH_CRATES:

        def narrowed(contract: dict, crate: str = crate) -> None:
            contract["completeness"]["scopes"] = [
                scope for scope in contract["completeness"]["scopes"] if scope.get("tree") != crate
            ]

        assert_fails(edited(narrowed), "matches no scanned limit")


def test_changing_a_path_limit_in_memory_fails_the_checker() -> None:
    """A named limit set to another value is reported: as a bound, by value and expression."""
    for identifier, path, symbol, _ in NAMED_PATH_LIMITS:
        scope = {"path": path, "kind": "const"}
        source = CHECKER["_read"](ROOT, path, "test")
        changed = CHECKER["mutate_limit"](source, scope, symbol, "test")
        assert changed is not None and changed != source, identifier
        found = _with_override(path, changed)
        assert any(found_item.startswith(f"{identifier}: `{symbol}` in {path} is now `1`") for found_item in found), (
            identifier,
            found,
        )
    # The four limits the review set to 1 by hand, exactly as it did.
    for path, old, new, fragment in (
        (
            "crates/iroha_data_model/src/nexus/private_settlement.rs",
            "pub const PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1: usize = 8 * 1024 * 1024;",
            "pub const PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1: usize = 1;",
            "proof.private_settlement_max_proof_bytes: `PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1`",
        ),
        (
            "crates/iroha_data_model/src/sccp/inbound.rs",
            "pub const SCCP_SOURCE_PROOF_MAX_BYTES_V1: usize = 8 * 1024 * 1024;",
            "pub const SCCP_SOURCE_PROOF_MAX_BYTES_V1: usize = 1;",
            "proof.sccp_source_proof_max_bytes: `SCCP_SOURCE_PROOF_MAX_BYTES_V1`",
        ),
        (
            "crates/iroha_data_model/src/nexus/axt.rs",
            "pub const MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;",
            "pub const MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES: usize = 1;",
            "proof.axt_proof_blob_max_payload_bytes: `MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES`",
        ),
        (
            "crates/iroha_torii/src/routing.rs",
            "const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;",
            "const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 1;",
            "transaction.torii_app_api_payload_max_bytes: `MAX_TRANSACTION_PAYLOAD_BYTES`",
        ),
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(old) == 1, path
        found = _with_override(path, source.replace(old, new))
        assert any(fragment in item for item in found), (path, found)
        # Lowering the transaction-facing ones also breaks a relation in the full check.
    lowered = CHECKER["_read"](ROOT, "crates/iroha_torii/src/routing.rs", "test").replace(
        "const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;",
        "const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;",
    )
    CHECKER["_OVERRIDES"]["crates/iroha_torii/src/routing.rs"] = lowered
    try:
        refreshed = copy.deepcopy(CONTRACT)
        found = CHECKER["check"](ROOT, refreshed, TASKS, True, [])
    finally:
        del CHECKER["_OVERRIDES"]["crates/iroha_torii/src/routing.rs"]
    assert any(
        "relation torii_app_api_payload_carries_max_transaction: violated under `today`" in item
        for item in found
    ), found
    # Removing a recorded comparison of a named limit is site drift.
    path = "crates/iroha_data_model/src/nexus/axt.rs"
    source = CHECKER["_read"](ROOT, path, "test")
    comparison = "if proof.payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES"
    assert source.count(comparison) == 1
    CHECKER["_OVERRIDES"][path] = source.replace(comparison, "if false")
    try:
        found = CHECKER["check"](ROOT, copy.deepcopy(CONTRACT), TASKS)
    finally:
        del CHECKER["_OVERRIDES"][path]
    assert any(f"{path} no longer contains `{comparison}`" in item for item in found), found


def test_an_excluded_limit_pins_its_defining_expression() -> None:
    """An exclusion is written for a value: a changed value is reviewed again."""
    for path, symbol, group_word in (
        ("crates/iroha_data_model/src/musubi.rs", "MUSUBI_MAX_CAR_BYTES_V1", "MUSUBI"),
        ("crates/iroha_torii/src/webhook.rs", "WEBHOOK_REGISTRY_MAX_ENTRIES", "Torii"),
        ("crates/iroha_core/src/kura.rs", "STRICT_INIT_MAX_BLOCK_BYTES", "Kura"),
        (
            "crates/iroha_core_zk/src/kagemusha_v1_recursion/mod.rs",
            None,
            "KAGEMUSHA",
        ),
        ("crates/iroha_data_model/src/execution_proofs.rs", "EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1", "execution-proof"),
    ):
        if symbol is None:
            # Any limit of the product directory the proof crate used to skip.
            path, symbol = next(
                (holder["path"], holder["symbols"][0])
                for group in CONTRACT["completeness"]["excluded"]
                for holder in group.get("files", [])
                if holder["path"].startswith("crates/iroha_core_zk/src/kagemusha_v1_recursion/")
            )
        scope = next(
            scope
            for scope in CHECKER["expand_scopes"](ROOT, CONTRACT["completeness"], [])
            if scope["path"] == path
        )
        source = CHECKER["_read"](ROOT, path, "test")
        holder, reason = next(
            (holder, group["reason"])
            for group in CONTRACT["completeness"]["excluded"]
            for holder in (group["files"] if "files" in group else [group])
            if holder["path"] == path and symbol in holder["symbols"]
        )
        assert group_word in reason, (symbol, reason)
        recorded = holder["exprs"][symbol]
        assert recorded == CHECKER["scope_expression"](source, scope, symbol, "test")
        changed = CHECKER["mutate_limit"](source, scope, symbol, "test")
        found = _with_override(path, changed)
        assert found == [
            f"completeness {path}: the excluded limit `{symbol}` is now `1`; the contract records "
            f"`{recorded}`. Review the reason of its exclusion, then run --refresh"
        ], found
        # `--refresh` records the new expression and says so; it never drops the exclusion.
        refreshed = copy.deepcopy(CONTRACT)
        CHECKER["_OVERRIDES"][path] = changed
        try:
            found, notes = [], []
            CHECKER["check_completeness"](ROOT, refreshed, found, True, notes)
        finally:
            del CHECKER["_OVERRIDES"][path]
        assert found == [] and len(notes) == 1, (found, notes)
        assert notes[0].endswith(f"was `{recorded}`; confirm its exclusion still holds")
        updated = next(
            holder
            for group in refreshed["completeness"]["excluded"]
            for holder in (group["files"] if "files" in group else [group])
            if holder["path"] == path and symbol in holder["symbols"]
        )
        assert updated["exprs"][symbol] == "1"

    def unpinned(contract: dict) -> None:
        del contract["completeness"]["excluded"][0]["exprs"]

    assert_fails(edited(unpinned), "records no defining expression in `exprs`; run --refresh")

    def stray(contract: dict) -> None:
        contract["completeness"]["excluded"][0]["exprs"]["NOT_EXCLUDED"] = "1"

    assert_fails(edited(stray), "`exprs` records `NOT_EXCLUDED`, which the group does not exclude")


def test_mutation_sweep_changes_every_limit_of_a_scope_and_reports_survivors() -> None:
    """`--mutate`: each limit is changed in memory, one at a time; an unnoticed change is named."""
    prefixes = (
        "crates/iroha_data_model/src/nexus/private_settlement.rs",
        "crates/iroha_data_model/src/sccp/",
        "crates/iroha_data_model/src/nexus/axt.rs",
        "crates/iroha_core/src/torii_proxy.rs",
        "crates/iroha_core/src/smartcontracts/limits.rs",
        "crates/iroha_core_zk/src/stark.rs",
        "crates/iroha_torii/src/zk1.rs",
    )
    changed, survivors, constant_only = CHECKER["mutation_sweep"](ROOT, CONTRACT, prefixes)
    assert changed >= 70 and survivors == [] and constant_only == [], (changed, survivors, constant_only)
    # Nothing was left overridden and nothing was written.
    assert CHECKER["_OVERRIDES"] == {}
    assert json.loads(CHECKER["CONTRACT"].read_text(encoding="utf-8")) == CONTRACT
    # A contract that no longer pins a limit lets its change through, and the sweep says so.
    weakened = copy.deepcopy(CONTRACT)
    weakened["bounds"] = [
        item for item in weakened["bounds"] if item["id"] != "proof.sccp_source_proof_max_bytes"
    ]
    weakened["relations"] = [
        item for item in weakened["relations"] if "proof.sccp_source_proof_max_bytes" not in item["expr"]
    ]
    with pytest.raises(CHECKER["ContractError"], match="starts from a contract that matches the source"):
        CHECKER["mutation_sweep"](ROOT, weakened, ("crates/iroha_data_model/src/sccp/inbound.rs",))
    original = CHECKER["check_completeness"]

    def blind(root, contract, problems, *args, **kwargs):
        before = len(problems)
        original(root, contract, problems, *args, **kwargs)
        problems[before:] = [item for item in problems[before:] if "`SCCP_HISTORY_MAX_SIZE_V1`" not in item]

    CHECKER["mutation_sweep"].__globals__["check_completeness"] = blind
    try:
        changed, survivors, _ = CHECKER["mutation_sweep"](
            ROOT, CONTRACT, ("crates/iroha_data_model/src/sccp/attestation.rs",)
        )
    finally:
        CHECKER["mutation_sweep"].__globals__["check_completeness"] = original
    # The file holds one named limit and two recorded literal comparisons; only the change
    # of the limit the blinded check hides goes unnoticed.
    assert changed == 3 and survivors == ["crates/iroha_data_model/src/sccp/attestation.rs: SCCP_HISTORY_MAX_SIZE_V1"]


def test_definition_reader_and_limit_mutation(tmp_path: Path) -> None:
    """Expressions are read whole: array types, blocks, literals, statics and trait constants."""
    source = (
        "pub const MAX_A: usize = 4 * 1024;\n"
        "const TAG_LIMIT: [u8; 4] = *b\"a;b}\";\n"
        "pub(crate) const BLOCK_BUDGET: u64 = { let x = 2; x * 3 };\n"
        "pub static MAX_STATIC: u32 = 7; // a limit written as a static\n"
        "static CAP_REJECTS: AtomicU64 = AtomicU64::new(0);\n"
        "static BUDGET: std::sync::OnceLock<Budget> = std::sync::OnceLock::new();\n"
        "pub const DELIMITER_LIMIT: char = ';';\n"
        "trait Bounded { const MAX_LEN: usize; }\n"
        "impl Bounded for A { const MAX_LEN: usize = 9; }\n"
        "mod inner { pub const MAX_A: usize = 5; }\n"
        "#[cfg(test)]\nmod tests { const MAX_IN_TESTS: usize = 1; }\n"
    )
    spans = CHECKER["definition_spans"]
    norm = CHECKER["normalize"]
    assert [norm(source[a:b]) for a, b in spans(source, "MAX_A")] == ["4 * 1024", "5"]
    assert [norm(source[a:b]) for a, b in spans(source, "TAG_LIMIT")] == ['*b"a;b}"']
    assert [norm(source[a:b]) for a, b in spans(source, "BLOCK_BUDGET")] == ["{ let x = 2; x * 3 }"]
    assert [norm(source[a:b]) for a, b in spans(source, "MAX_STATIC")] == ["7"]
    assert [norm(source[a:b]) for a, b in spans(source, "DELIMITER_LIMIT")] == ["';'"]
    assert [norm(source[a:b]) for a, b in spans(source, "MAX_LEN")] == ["", "9"]
    assert spans(source, "NO_SUCH") == []
    scope = {"path": "a.rs", "kind": "const"}
    # State-holding statics are not limits; an immutable static is. Inline tests are not scanned.
    assert CHECKER["scope_symbols"](source, scope, "x") == [
        "MAX_A",
        "TAG_LIMIT",
        "BLOCK_BUDGET",
        "MAX_STATIC",
        "DELIMITER_LIMIT",
        "MAX_LEN",
    ]
    expression = CHECKER["scope_expression"]
    assert expression(source, scope, "MAX_A", "x") == "4 * 1024 | 5"
    assert expression(source, scope, "MAX_LEN", "x") == " | 9"
    assert expression(source, scope, "MAX_STATIC", "x") == "7"
    mutate = CHECKER["mutate_limit"]
    changed = mutate(source, scope, "MAX_A", "x")
    assert "pub const MAX_A: usize = 1;" in changed and "pub const MAX_A: usize = 1; }" in changed
    assert mutate("const MAX_ONE: u8 = 1;\n", scope, "MAX_ONE", "x") == "const MAX_ONE: u8 = 2;\n"
    assert mutate("trait T { const MAX_LEN: usize; }\n", scope, "MAX_LEN", "x") is None
    # A module scope reads and changes only the definition inside its module.
    modules = "pub mod a {\n    pub const MAX_X: u8 = 3;\n}\npub mod b {\n    pub const MAX_X: u8 = 4;\n}\n"
    in_b = {"path": "m.rs", "kind": "const", "module": ["pub mod b {"]}
    assert expression(modules, in_b, "MAX_X", "x") == "4"
    assert mutate(modules, in_b, "MAX_X", "x") == modules.replace("= 4;", "= 1;")
    defaults = "pub mod t {\n    pub const fn max_tx() -> u64 {\n        10\n    }\n}\n"
    default_scope = {"path": "d.rs", "kind": "default_fn", "module": ["pub mod t {"]}
    assert expression(defaults, default_scope, "max_tx", "x") == "10"
    assert "".join(mutate(defaults, default_scope, "max_tx", "x").split()) == "".join(
        defaults.replace("10", "1").split()
    )

    # A second definition of a listed name in the same scope is not classified by its bound.
    (tmp_path / "a.rs").write_text("pub const MAX_A: u64 = 4;\n", encoding="utf-8")
    contract = {
        "bounds": [{"id": "queue.a", "owner": {"path": "a.rs", "symbol": "MAX_A", "kind": "const"}}],
        "completeness": {"scopes": [{"path": "a.rs", "kind": "const"}], "excluded": []},
    }
    found: list = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []
    (tmp_path / "a.rs").write_text(
        "pub const MAX_A: u64 = 4;\nmod da { pub const MAX_A: u64 = 1; }\n", encoding="utf-8"
    )
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == [
        "completeness a.rs: `MAX_A` is defined 2 times in the scope and 1 bound(s) list it; "
        "anchor a bound at each definition"
    ]
    # A limit written as an immutable static is scanned; a counter is not.
    (tmp_path / "a.rs").write_text(
        "pub const MAX_A: u64 = 4;\nstatic MAX_B: usize = 8;\nstatic CAP_HITS: AtomicU64 = AtomicU64::new(0);\n",
        encoding="utf-8",
    )
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == ["completeness a.rs: `MAX_B` is neither a listed bound nor excluded with a reason"]


def _feature_crate(tmp_path: Path, manifest: str, files: dict) -> None:
    crate = tmp_path / "crates" / "demo"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text(manifest, encoding="utf-8")
    for name, text in files.items():
        file = crate / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")


def test_feature_gated_tests_record_the_features_that_compile_them(tmp_path: Path) -> None:
    """A test behind a Cargo feature names it; a feature the crate does not have never runs."""
    requirement = CHECKER["_cfg_requirement"]
    assert requirement('feature = "zk-tests"') == {"zk-tests"}
    assert requirement('all(test, feature = "a", feature = "b")') == {"a", "b"}
    assert requirement('any(test, feature = "a")') == set()
    assert requirement('any(feature = "a", all(feature = "b", feature = "c"))') == {"a|b+c"}
    assert requirement('not(feature = "a")') == set() and requirement("test") == set()
    # Every gate among the attributes of an item counts, an inner `#![cfg(..)]` too.
    gates = CHECKER["cfg_predicates"]('#[cfg(all(test, feature = "x"))]\n#![cfg(feature = "y")]')
    assert gates == ['all(test, feature = "x")', 'feature = "y"']
    assert set().union(*(requirement(gate) for gate in gates)) == {"x", "y"}

    # The tracked contract: the gates of the tests the evidence review could not run.
    def recorded(identifier: str, name: str) -> list:
        return next(test for test in bound(CONTRACT, identifier)["tests"] if test["name"] == name).get(
            "features", []
        )

    assert recorded("proof.stark_fri_max_envelope_bytes", "stark_verifier_limits_cannot_relax_canonical_structure_caps") == [
        "zk-stark"
    ]
    gated = {
        (test["path"], test["name"]): test["features"]
        for item in CONTRACT["bounds"]
        for test in item.get("tests", [])
        if "features" in test
    }
    assert gated[("crates/iroha_core/tests/zk_roots_get_cap.rs", "zk_roots_get_respects_cap_and_max")] == [
        "zk-tests",
    ]
    assert gated[("crates/iroha_core/tests/zk_proof_retention.rs", "manual_prune_instruction_applies_new_cap")] == [
        "zk-tests"
    ]
    # The two verifier tests run again on a fixture of a production circuit and are named
    # beside the boundary tests F.4 wrote against the committed policy.
    assert gated[("crates/iroha_core/tests/zk_verify.rs", "verifyproof_rejects_when_exceeding_size_cap")] == [
        "zk-preverify",
        "zk-tests",
    ]
    assert gated[("crates/iroha_core/tests/zk_verify.rs", "verifyproof_rejects_when_block_cap_hit")] == [
        "zk-preverify",
        "zk-tests",
    ]
    for identifier in (
        "proof.config_confidential_max_proof_size_bytes",
        "work_budget.config_confidential_max_verify_calls_per_block",
    ):
        assert "test_gap" not in bound(CONTRACT, identifier), identifier
        assert any(
            test["path"] == "crates/iroha_core/src/zk_validity_policy_boundary_tests.rs"
            for test in bound(CONTRACT, identifier)["tests"]
        ), identifier
    assert gated[(
        "crates/iroha_core/src/zk_validity_policy_boundary_tests.rs",
        "preverify_budget_and_size_accept_the_committed_limit_and_reject_one_byte_more",
    )] == ["zk-preverify"]
    assert gated[("crates/iroha_core/tests/bridge_proofs.rs", "bridge_range_length_cap_enforced")] == [
        "iroha-core-tests"
    ]
    assert gated[("crates/iroha_core/tests/zk_ledger_scaffold.rs", "zk_roots_are_bounded_in_world_state")] == [
        "zk-tests",
    ]
    # Every recorded list is what the source says, and an ungated test records none.
    for (path, name), features in gated.items():
        assert CHECKER["test_features"](ROOT, {"path": path, "name": name}, "test") == features, name
    plain = {"path": "crates/iroha_data_model/src/sccp/inbound.rs", "name": "source_proof_bounds_hold_at_every_boundary"}
    assert CHECKER["test_features"](ROOT, plain, "test") == []

    def forgotten(contract: dict) -> None:
        test = bound(contract, "proof.stark_fri_max_envelope_bytes")["tests"][0]
        del test["features"]

    assert_fails(
        edited(forgotten),
        "is compiled with features ['zk-stark']; the contract records none in `features`",
    )

    def wrong(contract: dict) -> None:
        bound(contract, "proof.stark_fri_max_envelope_bytes")["tests"][0]["features"] = ["zk-tests"]

    assert_fails(edited(wrong), "the contract records ['zk-tests'] in `features`")

    def invented(contract: dict) -> None:
        bound(contract, "proof.sccp_source_proof_max_bytes")["tests"][0]["features"] = ["zk-tests"]

    assert_fails(edited(invented), "is compiled with features []; the contract records ['zk-tests']")

    # The commands that run every named test are derived from the same records.
    commands = CHECKER["test_commands"](ROOT, CONTRACT)
    assert any(
        command.startswith(
            "cargo test --locked -p iroha_core_zk --features zk-stark --lib -- "
        )
        and "stark_verifier_limits_cannot_relax_canonical_structure_caps" in command
        for command in commands
    ), commands
    assert any(
        command.startswith(
            "cargo test --locked -p iroha_core --features zk-tests --test iroha_core_group_05 -- "
        )
        for command in commands
    )
    assert any(
        command.startswith("cargo test --locked -p iroha_data_model --lib -- ")
        and "source_proof_bounds_hold_at_every_boundary" in command
        for command in commands
    )

    # A source tree of its own: every gate on the way from the test to its target counts.
    manifest = (
        '[package]\nname = "demo"\nautotests = false\n\n[features]\ndefault = []\nheavy = ["fixtures"]\nfixtures = []\n'
        'slow = []\n\n[[test]]\nname = "grouped"\npath = "tests/grouped/main.rs"\n'
        'required-features = ["fixtures"]\n'
    )
    _feature_crate(
        tmp_path,
        manifest,
        {
            "src/lib.rs": (
                '#[cfg(all(test, feature = "heavy"))]\ninclude!("included_tests.rs");\n'
                '#[cfg(feature = "slow")]\nmod gated;\nmod open;\n'
                '#[cfg(feature = "absent")]\nmod never;\n'
            ),
            "src/included_tests.rs": "#[test]\nfn included() {}\n",
            "src/gated.rs": '#[test]\nfn in_gated() {}\n#[cfg(feature = "heavy")]\n#[test]\nfn doubly() {}\n',
            "src/open.rs": "#[test]\nfn in_open() {}\n",
            "src/never.rs": "#[test]\nfn unreachable() {}\n",
            "tests/grouped/main.rs": '#[path = "../cases.rs"]\nmod cases;\n',
            "tests/cases.rs": '#![cfg(feature = "slow")]\n#[test]\nfn grouped_case() {}\n',
        },
    )
    features = CHECKER["test_features"]

    def of(path: str, name: str) -> list:
        return features(tmp_path, {"path": f"crates/demo/{path}", "name": name}, "t")

    assert of("src/included_tests.rs", "included") == ["heavy"]
    assert of("src/gated.rs", "in_gated") == ["slow"]
    assert of("src/gated.rs", "doubly") == ["heavy", "slow"]
    assert of("src/open.rs", "in_open") == []
    # `heavy` enables `fixtures`, so only the smallest set is recorded.
    assert of("tests/cases.rs", "grouped_case") == ["fixtures", "slow"]
    with pytest.raises(CHECKER["ContractError"], match="feature `absent`, which is not a feature of its crate"):
        of("src/never.rs", "unreachable")
    record = {
        "enforcement": [],
        "tests": [{"path": "crates/demo/src/gated.rs", "name": "in_gated"}],
    }
    found: list = []
    CHECKER["_check_sites"](tmp_path, record, "demo", found)
    assert len(found) == 1 and "is compiled with features ['slow']" in found[0]
    found, notes = [], []
    CHECKER["_check_sites"](tmp_path, record, "demo", found, None, True, notes)
    assert found == [] and record["tests"][0]["features"] == ["slow"] and len(notes) == 1
    CHECKER["_check_sites"](tmp_path, record, "demo", found)
    assert found == []
    record["tests"][0] = {"path": "crates/demo/src/never.rs", "name": "unreachable"}
    CHECKER["_check_sites"](tmp_path, record, "demo", found)
    assert len(found) == 1 and "it never runs" in found[0]
    assert CHECKER["test_commands"](tmp_path, {"x": {"tests": [
        {"path": "crates/demo/tests/cases.rs", "name": "grouped_case", "features": ["fixtures", "slow"]},
        {"path": "crates/demo/src/open.rs", "name": "in_open"},
    ]}}) == [
        "cargo test --locked -p demo --lib -- in_open",
        "cargo test --locked -p demo --features fixtures,slow --test grouped -- grouped_case",
    ]


def test_a_zk_policy_committed_as_names_a_field_the_policy_defines(tmp_path: Path) -> None:
    """`committed_as` of a ZK validity policy bound is resolved against the struct."""
    fields = CHECKER["zk_validity_policy_fields"](
        (ROOT / CHECKER["ZK_VALIDITY_POLICY_SOURCE"]).read_text(encoding="utf-8")
    )
    assert sorted(fields) == ["confidential", "gas", "pipa_r", "proofs", "sccp", "stark"]
    assert sum(len(names) for names in fields.values()) == 58
    assert "max_nullifiers_per_tx" in fields["confidential"]
    named = [
        item for item in CONTRACT["bounds"]
        if str(item.get("committed_as", "")).startswith("zk_validity_policy_v1")
    ]
    assert len(named) == 45
    found: list = []
    CHECKER["check_zk_policy_committed_as"](ROOT, CONTRACT, found)
    assert found == []
    # A renamed or misspelled field, and a free-form text, are reported.
    for text, fragment in (
        ("zk_validity_policy_v1 (ZkValidityPolicyV1.confidential.max_nullifier_per_tx), x", "does not define"),
        ("zk_validity_policy_v1 (ZkValidityPolicyV1.missing.max_k), x", "does not define"),
        ("zk_validity_policy_v1, the confidential limits", "must start with"),
    ):
        broken = copy.deepcopy(CONTRACT)
        bound(broken, "work_budget.config_confidential_max_nullifiers_per_tx")["committed_as"] = text
        found = []
        CHECKER["check_zk_policy_committed_as"](ROOT, broken, found)
        assert len(found) == 1 and fragment in found[0], found


def test_a_pipeline_policy_committed_as_names_a_field_the_policy_defines() -> None:
    """`committed_as` of a pipeline validity policy bound is resolved against the struct."""
    fields = CHECKER["pipeline_validity_policy_fields"](
        (ROOT / CHECKER["PIPELINE_VALIDITY_POLICY_SOURCE"]).read_text(encoding="utf-8")
    )
    assert len(fields) == 16 and len(set(fields)) == 16
    assert "overlay_max_instructions" in fields and "dynamic_prepass" in fields
    named = [
        item for item in CONTRACT["bounds"]
        if str(item.get("committed_as", "")).startswith("pipeline_validity_policy_v1")
    ]
    # The fifteen execution limits of the execution-policy catalog; none keeps
    # a node-local source or its defect.
    assert len(named) == 15
    assert all(item["source"] == "committed" and "defect" not in item for item in named)
    catalog = next(
        item for item in CONTRACT["catalogs"] if item["id"] == "execution_policy_digest_v1"
    )
    assert sorted(catalog["fields"].values()) == sorted(item["id"] for item in named)
    assert sorted(field.split(".", 1)[1] for field in catalog["fields"]) == sorted(
        set(fields) - {"dynamic_prepass"}
    )
    found: list = []
    CHECKER["check_pipeline_policy_committed_as"](ROOT, CONTRACT, found)
    assert found == []
    # A renamed or misspelled field, and a free-form text, are reported.
    for text, fragment in (
        ("pipeline_validity_policy_v1 (PipelineValidityPolicyV1.overlay_max_instruction), x", "does not define"),
        ("pipeline_validity_policy_v1, the overlay limits", "must start with"),
    ):
        broken = copy.deepcopy(CONTRACT)
        bound(broken, "queued_effects.config_overlay_max_instructions")["committed_as"] = text
        found = []
        CHECKER["check_pipeline_policy_committed_as"](ROOT, broken, found)
        assert len(found) == 1 and fragment in found[0], found


# ---------------------------------------------------------------------------
# Feature gates on enclosing blocks, text-keyed caches and in-memory overrides
# ---------------------------------------------------------------------------


def _demo_crate(tmp_path: Path, files: dict, features: str = 'zk-tests = []\nhalo2-dev-tests = []\n') -> None:
    """A scratch crate `crates/demo` with the given `src` files and `[features]` table."""
    crate = tmp_path / "crates" / "demo"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text(
        f'[package]\nname = "demo"\nversion = "0.0.0"\n\n[features]\n{features}', encoding="utf-8"
    )
    for name, text in files.items():
        file = crate / "src" / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")


def test_a_feature_gate_on_an_enclosing_module_is_read(tmp_path: Path) -> None:
    """The usual gate of a Rust test is on the inline module around it, not on the test."""
    lib = (
        "pub const TEXT: &str = \"}{ #[cfg(any())] mod fake {\"; // a brace { in a comment\n"
        "pub const BRACE: char = '{';\n"
        "#[cfg(test)]\nmod plain {\n    #[test]\n    fn plain_test() {}\n}\n"
        "#[cfg(all(test, feature = \"zk-tests\", feature = \"halo2-dev-tests\"))]\n"
        "mod gated {\n    #[test]\n    fn gated_test() {}\n"
        "    mod inner {\n        #[test]\n        fn nested_test() {}\n    }\n}\n"
        "#[cfg(all(test, feature = \"halo2-dev-tests\"))]\nmod one {\n    #[test]\n    fn one_feature_test() {}\n}\n"
        "#[cfg(all(test, feature = \"never\"))]\nmod never {\n    #[test]\n    fn never_test() {}\n}\n"
        "#[cfg(any())]\nmod out {\n    #[test]\n    fn compiled_out_test() {}\n}\n"
        "#[cfg(feature = \"zk-tests\")]\nmod outer {\n    #[cfg(test)]\n    mod deep {\n"
        "        #[test]\n        #[cfg(feature = \"halo2-dev-tests\")]\n        fn deep_test() {}\n    }\n"
        "    mod child;\n}\n"
        "#[cfg(any())]\nmod dead {\n    mod buried;\n}\n"
    )
    _demo_crate(
        tmp_path,
        {
            "lib.rs": lib,
            "outer/child.rs": "#[test]\nfn child_test() {}\n",
            "dead/buried.rs": "#[test]\nfn buried_test() {}\n",
        },
    )
    path = "crates/demo/src/lib.rs"

    def features(name: str, file: str = path) -> list:
        return CHECKER["test_features"](tmp_path, {"path": file, "name": name}, "test")

    assert features("plain_test") == []
    assert features("gated_test") == ["halo2-dev-tests", "zk-tests"]
    # Every enclosing block counts: a module inside a gated module, and a gate on the
    # test itself beside one on a module two levels up.
    assert features("nested_test") == ["halo2-dev-tests", "zk-tests"]
    assert features("one_feature_test") == ["halo2-dev-tests"]
    assert features("deep_test") == ["halo2-dev-tests", "zk-tests"]
    # A file declared inside a gated inline module inherits the gate of that module.
    assert features("child_test", "crates/demo/src/outer/child.rs") == ["zk-tests"]
    with pytest.raises(
        CHECKER["ContractError"],
        match="compiled only with feature `never`, which is not a feature of its crate: it never runs",
    ):
        features("never_test")
    problem = CHECKER["test_problem"]
    assert problem(lib, path, "compiled_out_test") == "is inside a block compiled out by `#[cfg(any())]` in"
    assert problem(lib, path, "gated_test") is None and problem(lib, path, "plain_test") is None
    # A declaration inside a module that is never compiled does not reach its file.
    assert CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/dead/buried.rs")
    assert not CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/outer/child.rs")
    # The headers the gates are read from: outermost first, braces in literals ignored.
    heads = CHECKER["enclosing_heads"](lib, lib.index("fn nested_test"))
    assert [" ".join(head.split()) for head in heads] == [
        '#[cfg(all(test, feature = "zk-tests", feature = "halo2-dev-tests"))] mod gated',
        "mod inner",
    ]
    assert CHECKER["enclosing_heads"](lib, lib.index("pub const BRACE")) == []
    # The check reports each form through the contract record.
    record = {"tests": [{"path": path, "name": "gated_test"}]}
    found: list = []
    CHECKER["_check_sites"](tmp_path, record, "demo", found)
    assert found == [
        "demo: test `gated_test` in crates/demo/src/lib.rs is compiled with features "
        "['halo2-dev-tests', 'zk-tests']; the contract records none in `features`"
    ]
    record["tests"][0]["features"] = ["halo2-dev-tests", "zk-tests"]
    found = []
    CHECKER["_check_sites"](tmp_path, record, "demo", found)
    assert found == []
    for name, fragment in (
        ("never_test", "is compiled only with feature `never`"),
        ("compiled_out_test", "is inside a block compiled out by `#[cfg(any())]`"),
    ):
        found = []
        CHECKER["_check_sites"](tmp_path, {"tests": [{"path": path, "name": name}]}, "demo", found)
        assert len(found) == 1 and fragment in found[0], found


def test_a_module_gate_on_a_tracked_boundary_test_is_reported() -> None:
    """The case the review reproduced: the ZK1 boundary tests behind a gate on their module."""
    path = "crates/iroha_core_zk/src/lib.rs"
    source = CHECKER["_read"](ROOT, path, "test")
    plain = "#[cfg(test)]\n    mod section_bound_tests {"
    assert source.count(plain) >= 1
    test = {
        "path": path,
        "name": "zk1_section_of_exactly_the_bound_is_read_and_one_byte_more_is_refused",
    }
    assert CHECKER["test_features"](ROOT, test, "test") == []
    for gate, expected in (
        ('#[cfg(all(test, feature = "zk-tests", feature = "halo2-dev-tests"))]', ["halo2-dev-tests", "zk-tests"]),
        ('#[cfg(all(test, feature = "halo2-dev-tests"))]', ["halo2-dev-tests"]),
    ):
        CHECKER["_OVERRIDES"][path] = source.replace(plain, gate + "\n    mod section_bound_tests {")
        try:
            assert CHECKER["test_features"](ROOT, test, "test") == expected
            found: list = []
            CHECKER["_check_sites"](ROOT, {"tests": [dict(test)]}, "bound", found)
        finally:
            del CHECKER["_OVERRIDES"][path]
        assert len(found) == 1 and f"is compiled with features {expected}" in found[0], found
    for gate, fragment in (
        ('#[cfg(all(test, feature = "never"))]', "feature `never`, which is not a feature of its crate"),
        ("#[cfg(any())]", "is inside a block compiled out by `#[cfg(any())]`"),
    ):
        CHECKER["_OVERRIDES"][path] = source.replace(plain, gate + "\n    mod section_bound_tests {")
        try:
            found = []
            CHECKER["_check_sites"](ROOT, {"tests": [dict(test)]}, "bound", found)
        finally:
            del CHECKER["_OVERRIDES"][path]
        assert len(found) == 1 and fragment in found[0], found
    # Nothing stays cached from the overridden texts.
    assert CHECKER["test_features"](ROOT, test, "test") == []


def test_a_file_gate_is_read_through_an_in_memory_override(tmp_path: Path) -> None:
    """A text that stands in for a file is what the feature chain reads, at every level."""
    _demo_crate(
        tmp_path,
        {
            "lib.rs": "mod suite;\n",
            "suite.rs": "#[test]\nfn suite_test() {}\n",
        },
    )
    test = {"path": "crates/demo/src/suite.rs", "name": "suite_test"}
    assert CHECKER["test_features"](tmp_path, test, "test") == []
    overrides = CHECKER["_OVERRIDES"]
    # A gate on the file itself.
    overrides["crates/demo/src/suite.rs"] = '#![cfg(feature = "zk-tests")]\n#[test]\nfn suite_test() {}\n'
    try:
        assert CHECKER["test_features"](tmp_path, test, "test") == ["zk-tests"]
    finally:
        del overrides["crates/demo/src/suite.rs"]
    # A gate on the declaration in another file.
    overrides["crates/demo/src/lib.rs"] = '#[cfg(feature = "halo2-dev-tests")]\nmod suite;\n'
    try:
        assert CHECKER["test_features"](tmp_path, test, "test") == ["halo2-dev-tests"]
        assert not CHECKER["compiled_only_in_tests"](tmp_path, "crates/demo/src/suite.rs")
    finally:
        del overrides["crates/demo/src/lib.rs"]
    overrides["crates/demo/src/lib.rs"] = "#[cfg(test)]\nmod suite;\n"
    try:
        assert CHECKER["compiled_only_in_tests"](tmp_path, "crates/demo/src/suite.rs")
    finally:
        del overrides["crates/demo/src/lib.rs"]
    assert CHECKER["test_features"](tmp_path, test, "test") == []
    assert not CHECKER["compiled_only_in_tests"](tmp_path, "crates/demo/src/suite.rs")
    assert overrides == {}


def test_text_caches_are_keyed_by_the_text() -> None:
    """Two texts never share a cached result, whatever their length and hash."""
    memo = CHECKER["_TextMemo"](4)
    assert memo.get("aa", "key", lambda: 1) == 1
    assert memo.get("aa", "key", lambda: 2) == 1
    assert memo.get("ab", "key", lambda: 2) == 2
    assert memo.get("aa", "other", lambda: 3) == 3
    derived = memo.derive("aa", "copy", lambda: "aa-derived")
    assert derived == "aa-derived" and memo.get(derived, "key", lambda: 4) == 4
    memo.forget("aa")
    assert memo.get("aa", "key", lambda: 5) == 5
    assert memo.get("aa-derived", "key", lambda: 6) == 6
    assert memo.get("ab", "key", lambda: 7) == 2
    for index in range(16):
        memo.get(f"text {index}", "key", lambda: index)
    assert len(memo) <= 4
    # The readers of the checker: equal length, different text, different answer.
    one = "pub const MAX_ALPHA: u64 = 1;\n"
    two = "pub const MAX_GAMMA: u64 = 2;\n"
    assert len(one) == len(two)
    scope = {"kind": "const"}
    assert CHECKER["scope_symbols"](one, scope, "test") == ["MAX_ALPHA"]
    assert CHECKER["scope_symbols"](two, scope, "test") == ["MAX_GAMMA"]
    assert CHECKER["scope_expression"](one, scope, "MAX_ALPHA", "test") == "1"
    assert CHECKER["scope_expression"](two, scope, "MAX_GAMMA", "test") == "2"
    assert CHECKER["definition_spans"](one, "MAX_GAMMA") == []
    first = "#[test]\nfn alpha() {}\n"
    second = "#[test]\nfn gamma() {}\n"
    assert CHECKER["test_problem"](first, "a.rs", "alpha") is None
    assert CHECKER["test_problem"](second, "a.rs", "alpha") == "is not in"
    # No cache of the module is keyed by a length and a hash any more.
    script = Path(CHECKER["__file__"]).read_text(encoding="utf-8")
    assert "hash(source)" not in script and "hash(text)" not in script


def test_code_and_comment_masks_keep_offsets() -> None:
    """Comments and literals are blanked in place, so a position means the same in both texts."""
    source = (
        'let a = "x{y"; // c {\n'
        "let b = '{'; let c: &'static str = r#\"q\"{\"#; /* { \n } */ let d = b'\\n';\n"
        'let url = "https://example.test/{}"; fn f<\'a>(x: &\'a u8) { }\n'
    )
    mask = CHECKER["code_mask"](source)
    assert len(mask) == len(source) and mask.count("\n") == source.count("\n")
    assert mask.count("{") == 1 and mask.count("}") == 1
    assert "'static" in mask and "<'a>" in mask and "https" not in mask
    comments = CHECKER["comment_mask"](source)
    assert len(comments) == len(source)
    # A string that holds `//` stays whole; only the comments are gone.
    assert '"https://example.test/{}"' in comments and "// c {" not in comments
    assert "/* {" not in comments and "'{'" in comments


# ---------------------------------------------------------------------------
# Limits that their name does not mark: compared constants, limit functions, literals
# ---------------------------------------------------------------------------


def test_the_comparison_scan_reads_what_the_code_compares() -> None:
    """Constants, limit-named functions and literals are found by their use, not their name."""
    source = (
        "pub const COMMITMENT_BYTES: usize = 512;\n"
        "const WIDTH: u64 = 4;\n"
        "const LABEL: &str = \"x > 99\";\n"
        "static SLOTS: u32 = 8;\n"
        "pub const fn max_shadow_proof_bytes() -> usize { 9 }\n"
        "fn shadow_budget() -> core::num::NonZeroU64 { core::num::NonZeroU64::MIN }\n"
        "fn helper() -> usize { 3 }\n"
        "fn max_with_argument(x: usize) -> usize { x }\n"
        "fn generic<\n    const S_LEN: usize,\n    const N: usize,\n>(x: usize) -> bool {\n    S_LEN <= 1_024 && x > N\n}\n"
        "fn f(raw: &[u8], n: u64, v: Vec<u8>, y: f64) -> bool {\n"
        "    if raw.len() > 4 * 1024 * 1024 || n >= WIDTH {\n        return false;\n    }\n"
        "    if request\n        .transfers\n        .len()\n        > 1000\n    {\n        return false;\n    }\n"
        "    let a = v.len() as u64 > 4096; // z > 77\n"
        "    let b = 8 < n;\n"
        "    let c = (1..=31).contains(&n) && n < 2 * n && n > 0 && n >= 1;\n"
        "    let d = n.min(16 * 1024).max(1).clamp(2, u64::from(SLOTS));\n"
        "    let e = raw.len() > COMMITMENT_BYTES && n >> 8 > 3 && y < 0.5;\n"
        "    let g: Vec<AssignedBits<16, F>> = Vec::with_capacity(64);\n"
        "    let h = raw.iter().take(1 << 5).count() == SLOTS as usize && n == 7;\n"
        "    a && b\n}\n"
        "#[cfg(test)]\nmod tests {\n    const HIDDEN: usize = 5;\n"
        "    fn t(x: usize) -> bool {\n        x > 123_456 && x > HIDDEN\n    }\n}\n"
    )
    scan = CHECKER["comparison_scan"](source)
    # A const generic parameter is no item; a string constant is no integer.
    assert scan["integers"] == ("COMMITMENT_BYTES", "WIDTH", "SLOTS")
    # Every upper-case name of a comparison is a use; one that names no integer item (a
    # const generic parameter) is dropped when uses are attributed to the items of a crate.
    assert scan["uses"] == {"COMMITMENT_BYTES", "WIDTH", "SLOTS", "S_LEN", "N"}
    assert sorted(scan["functions"]) == ["max_shadow_proof_bytes", "shadow_budget"]
    sites = CHECKER["literal_sites"](source, 2)
    assert {text: [value for _, _, value in spans] for text, spans in sites.items()} == {
        "S_LEN <= 1_024": [1024],
        "raw.len() > 4 * 1024 * 1024": [4 * MIB],
        "request .transfers .len() > 1000": [1000],
        "v.len() as u64 > 4096": [4096],
        "8 < n": [8],
        "(1..=31).contains(&n)": [31],
        # A literal that is only a part of an operand: the site is the whole comparison.
        "n < 2 * n": [2],
        "n.min(16 * 1024)": [16 * 1024],
        "n.min(16 * 1024).max(1).clamp(2, u64::from(SLOTS))": [2],
        # The text of a site pins every literal it holds: the shift beside the 3.
        "8 > 3": [8, 3],
        "raw.iter().take(1 << 5)": [32],
    }
    # Arithmetic in front of the compared run is part of the operand; a capped receiver
    # never starts at an operator.
    arithmetic = (
        "fn g(offset: usize, first: usize, i: usize) -> bool {\n"
        "    let cut = i * 7..(i * 7 + 7).min(32);\n"
        "    first + offset - 1 < 32\n}\n"
    )
    assert sorted(CHECKER["literal_sites"](arithmetic, 2)) == [
        "7..(i * 7 + 7).min(32)",
        "first + offset - 1 < 32",
    ]
    # The literal spans are offsets in the source, so one literal can be changed alone.
    start, end, value = sites["raw.len() > 4 * 1024 * 1024"][0]
    assert source[start:end] == "4 * 1024 * 1024" and value == 4 * MIB
    # A higher minimum drops the small ones; nothing below 2 is ever a site.
    assert sorted(CHECKER["literal_sites"](source, 1000)) == [
        "S_LEN <= 1_024",
        "n.min(16 * 1024)",
        "raw.len() > 4 * 1024 * 1024",
        "request .transfers .len() > 1000",
        "v.len() as u64 > 4096",
    ]
    value_of = CHECKER["literal_value"]
    assert value_of("4 * 1024 * 1024") == 4 * MIB and value_of("1 << 20") == MIB
    assert value_of("0x40_usize") == 64 and value_of("0b1000") == 8 and value_of("1_000u64") == 1000
    assert value_of("2 * n") is None and value_of("MAX") is None and value_of("0.5") is None
    assert CHECKER["function_body_spans"](source, "max_shadow_proof_bytes") != []
    body = CHECKER["function_body_spans"](source, "max_shadow_proof_bytes")[0]
    assert source[body[0] : body[1]].strip() == "9"
    assert CHECKER["function_body_spans"](source, "max_with_argument") == []


def _compared_demo(tmp_path: Path) -> dict:
    _demo_crate(
        tmp_path,
        {
            "lib.rs": (
                "pub const COMMITMENT_BYTES: usize = 512;\n"
                "pub const WIDTH: usize = 4;\n"
                "pub const MAX_NAMED: usize = 7;\n"
                "pub const fn max_shadow_proof_bytes() -> usize {\n    1\n}\n"
                "pub fn check(value: &[u8]) -> bool {\n    value.len() > 4096 && value.len() > MAX_NAMED\n}\n"
                "pub mod other;\npub mod lane_fixture;\n"
                "#[cfg(test)]\nmod reference;\n#[cfg(test)]\nmod frame_tests;\n"
            ),
            "other.rs": (
                "use crate::COMMITMENT_BYTES;\n"
                "pub fn fits(value: &[u8]) -> bool {\n    value.len() <= COMMITMENT_BYTES\n}\n"
            ),
            # A production file whose name looks like a fixture: the crate compiles it.
            "lane_fixture.rs": "pub const MAX_SHADOW_BODY_BYTES: usize = 1;\n",
            # A test-only module whose name does not say so: scanned by name only.
            "reference.rs": (
                "pub const HIDDEN: usize = 3;\npub const MAX_IN_REFERENCE: usize = 2;\n"
                "pub fn g(x: usize) -> bool {\n    x > HIDDEN && x > 99\n}\n"
            ),
            "frame_tests.rs": "const MAX_IN_TEST_FILE: usize = 1;\nfn h(x: usize) -> bool {\n    x > 55\n}\n",
        },
    )
    return {
        "bounds": [
            {
                "id": "queue.named",
                "owner": {"path": "crates/demo/src/lib.rs", "symbol": "MAX_NAMED", "kind": "const"},
                "enforcement": [],
            }
        ],
        "completeness": {
            "scopes": [{"tree": "crates/demo/src", "kind": "const", "comparisons": True}],
            "excluded": [],
            "literals": {"why": "0 and 1 test presence", "minimum": 2, "groups": []},
        },
    }


def test_a_comparisons_scope_requires_every_compared_limit_and_literal(tmp_path: Path) -> None:
    """Each limit the code compares is listed or excluded; each literal is owned or recorded."""
    contract = _compared_demo(tmp_path)
    section = contract["completeness"]
    scopes = CHECKER["expand_scopes"](tmp_path, section, [])
    assert [(scope["path"].rsplit("/", 1)[-1], scope.get("comparisons", False)) for scope in scopes] == [
        ("lane_fixture.rs", True),
        ("lib.rs", True),
        ("other.rs", True),
        ("reference.rs", False),
    ]
    assert CHECKER["compiled_outside_tests"](tmp_path, "crates/demo/src/lane_fixture.rs")
    assert not CHECKER["compiled_outside_tests"](tmp_path, "crates/demo/src/frame_tests.rs")
    assert CHECKER["compiled_only_in_tests"](tmp_path, "crates/demo/src/reference.rs")
    assert CHECKER["compared_symbols"](tmp_path, scopes) == {
        "crates/demo/src/lane_fixture.rs": [],
        "crates/demo/src/lib.rs": ["COMMITMENT_BYTES", "max_shadow_proof_bytes"],
        "crates/demo/src/other.rs": [],
    }
    found: list = []
    unlisted: list = []
    CHECKER["check_completeness"](tmp_path, contract, found, False, None, unlisted)
    assert found == [
        "completeness crates/demo/src/lane_fixture.rs: `MAX_SHADOW_BODY_BYTES` is neither a listed bound "
        "nor excluded with a reason",
        "completeness crates/demo/src/lib.rs: `COMMITMENT_BYTES` is neither a listed bound nor excluded "
        "with a reason",
        "completeness crates/demo/src/lib.rs: `max_shadow_proof_bytes` is neither a listed bound nor "
        "excluded with a reason",
        "completeness crates/demo/src/reference.rs: `MAX_IN_REFERENCE` is neither a listed bound nor "
        "excluded with a reason",
        "completeness literals in crates/demo/src/lib.rs: the literal comparison `value.len() > 4096` "
        "(1 time(s)) is neither a site of a listed bound nor recorded with a reason",
    ]
    assert unlisted[-1] == ("crates/demo/src/lib.rs", "value.len() > 4096", 1)
    section["excluded"] = [
        {
            "reason": "demo shapes",
            "files": [
                {
                    "path": "crates/demo/src/lane_fixture.rs",
                    "symbols": ["MAX_SHADOW_BODY_BYTES"],
                    "exprs": {"MAX_SHADOW_BODY_BYTES": "1"},
                },
                {
                    "path": "crates/demo/src/lib.rs",
                    "symbols": ["COMMITMENT_BYTES", "max_shadow_proof_bytes"],
                    "exprs": {"COMMITMENT_BYTES": "512", "max_shadow_proof_bytes": "1"},
                },
                {
                    "path": "crates/demo/src/reference.rs",
                    "symbols": ["MAX_IN_REFERENCE"],
                    "exprs": {"MAX_IN_REFERENCE": "2"},
                },
            ],
        }
    ]
    section["literals"]["groups"] = [
        {
            "reason": "a demo shape",
            "files": [{"path": "crates/demo/src/lib.rs", "sites": {"value.len() > 4096": 1}}],
        }
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []

    def problems_with(path: str, old: str, new: str) -> list:
        file = tmp_path / path
        text = file.read_text(encoding="utf-8")
        assert text.count(old) == 1, old
        CHECKER["_OVERRIDES"][path] = text.replace(old, new)
        try:
            out: list = []
            CHECKER["check_completeness"](tmp_path, contract, out)
            return out
        finally:
            del CHECKER["_OVERRIDES"][path]

    lib = "crates/demo/src/lib.rs"
    # A compared constant and a limit function are pinned like a named limit.
    assert problems_with(lib, "COMMITMENT_BYTES: usize = 512;", "COMMITMENT_BYTES: usize = 1;") == [
        f"completeness {lib}: the excluded limit `COMMITMENT_BYTES` is now `1`; the contract records "
        "`512`. Review the reason of its exclusion, then run --refresh"
    ]
    assert problems_with(lib, "usize {\n    1\n}", "usize {\n    2\n}") == [
        f"completeness {lib}: the excluded limit `max_shadow_proof_bytes` is now `2`; the contract "
        "records `1`. Review the reason of its exclusion, then run --refresh"
    ]
    # A changed literal is a recorded text that is gone and a new one that is not recorded.
    assert problems_with(lib, "value.len() > 4096", "value.len() > 1024") == [
        f"completeness literals in {lib}: the literal comparison `value.len() > 1024` (1 time(s)) is "
        "neither a site of a listed bound nor recorded with a reason",
        f"completeness literals in {lib}: `value.len() > 4096` matches no literal comparison",
    ]
    # A literal lowered below the minimum is still a recorded comparison that is gone.
    assert problems_with(lib, "value.len() > 4096", "value.len() > 1") == [
        f"completeness literals in {lib}: `value.len() > 4096` matches no literal comparison"
    ]
    # A second copy of a recorded comparison changes its count.
    assert problems_with(lib, "pub mod other;", "pub fn again(value: &[u8]) -> bool {\n    value.len() > 4096\n}\npub mod other;") == [
        f"completeness literals in {lib}: `value.len() > 4096` occurs 2 time(s) outside the sites of "
        "listed bounds; the contract records 1"
    ]
    # New limits of each kind in a file that was clean.
    other = "crates/demo/src/other.rs"
    found = problems_with(
        other,
        "use crate::COMMITMENT_BYTES;\n",
        "use crate::COMMITMENT_BYTES;\n"
        "pub const SHADOW_PROOF_BYTES: usize = 1;\n"
        "pub fn shadow(b: &[u8]) -> bool {\n    b.len() > SHADOW_PROOF_BYTES || b.len() > 4096\n}\n"
        "pub fn shadow_limit() -> u32 {\n    7\n}\n",
    )
    assert found == [
        f"completeness {other}: `SHADOW_PROOF_BYTES` is neither a listed bound nor excluded with a reason",
        f"completeness {other}: `shadow_limit` is neither a listed bound nor excluded with a reason",
        f"completeness literals in {other}: the literal comparison `b.len() > 4096` (1 time(s)) is neither a "
        "site of a listed bound nor recorded with a reason",
    ]
    # A constant that stops being compared is an exclusion that matches nothing.
    found = problems_with(other, "value.len() <= COMMITMENT_BYTES", "value.is_empty()")
    assert found == [
        f"completeness: the exclusion of `COMMITMENT_BYTES` in {lib} matches no scanned limit"
    ]

    # A literal inside an enforcement site of a listed bound is owned by that bound.
    owned = copy.deepcopy(contract)
    owned["bounds"][0]["enforcement"] = [
        {"stage": "queue", "path": lib, "contains": "value.len() > 4096 && value.len() > MAX_NAMED"}
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, owned, found)
    assert found == [
        f"completeness literals in {lib}: `value.len() > 4096` is a site of a listed bound and recorded here too"
    ]
    owned["completeness"]["literals"]["groups"] = []
    found = []
    CHECKER["check_completeness"](tmp_path, owned, found)
    assert found == []

    # Malformed records and `--refresh`.
    broken = copy.deepcopy(contract)
    broken["completeness"]["literals"]["groups"][0]["files"].append(
        {"path": "crates/demo/src/other.rs", "sites": {"gone.len() > 9": 1}}
    )
    found = []
    CHECKER["check_completeness"](tmp_path, broken, found)
    assert found == [f"completeness literals in {other}: `gone.len() > 9` matches no literal comparison"]
    found, notes = [], []
    CHECKER["check_completeness"](tmp_path, broken, found, True, notes)
    assert found == [] and notes == [
        f"completeness literals in {other}: `gone.len() > 9` matches no literal comparison; removed"
    ]
    assert broken["completeness"]["literals"] == contract["completeness"]["literals"]
    for edit, fragment in (
        (lambda item: item["literals"].update(minimum=1), "`minimum` is an integer of 2 or more"),
        (lambda item: item["literals"].pop("why"), "`minimum` is an integer of 2 or more"),
        (lambda item: item.pop("literals"), "`literals` records the literal comparisons that no bound owns"),
        (lambda item: item["literals"]["groups"][0].pop("reason"), "a group states its reason"),
        (
            lambda item: item["literals"]["groups"][0]["files"].append(
                {"path": "crates/demo/src/reference.rs", "sites": {"x > 99": 1}}
            ),
            "the file is not in a `comparisons` scope",
        ),
        (lambda item: item["scopes"][0].update(comparisons="yes"), "`comparisons` is `true` or absent"),
    ):
        broken = copy.deepcopy(contract)
        edit(broken["completeness"])
        found = []
        if "comparisons" in fragment:
            CHECKER["expand_scopes"](tmp_path, broken["completeness"], found)
        CHECKER["check_completeness"](tmp_path, broken, found)
        assert any(fragment in item for item in found), (fragment, found)
    # Without `comparisons` the scope is read by name only, and `literals` has no file.
    by_name = copy.deepcopy(contract)
    del by_name["completeness"]["scopes"][0]["comparisons"]
    found = []
    CHECKER["check_completeness"](tmp_path, by_name, found)
    assert found == [
        f"completeness: the exclusion of `COMMITMENT_BYTES` in {lib} matches no scanned limit",
        f"completeness: the exclusion of `max_shadow_proof_bytes` in {lib} matches no scanned limit",
        "completeness literals: no scope sets `comparisons`",
    ]
    assert CHECKER["_OVERRIDES"] == {}


def test_the_mutation_sweep_changes_compared_limits_and_literals(tmp_path: Path) -> None:
    """`--mutate` changes every limit a comparison scope holds and every recorded literal."""
    contract = _compared_demo(tmp_path)
    section = contract["completeness"]
    section["excluded"] = [
        {
            "reason": "demo shapes",
            "files": [
                {
                    "path": "crates/demo/src/lane_fixture.rs",
                    "symbols": ["MAX_SHADOW_BODY_BYTES"],
                    "exprs": {"MAX_SHADOW_BODY_BYTES": "1"},
                },
                {
                    "path": "crates/demo/src/lib.rs",
                    "symbols": ["COMMITMENT_BYTES", "max_shadow_proof_bytes"],
                    "exprs": {"COMMITMENT_BYTES": "512", "max_shadow_proof_bytes": "1"},
                },
                {
                    "path": "crates/demo/src/reference.rs",
                    "symbols": ["MAX_IN_REFERENCE"],
                    "exprs": {"MAX_IN_REFERENCE": "2"},
                },
            ],
        }
    ]
    section["literals"]["groups"] = [
        {"reason": "a demo shape", "files": [{"path": "crates/demo/src/lib.rs", "sites": {"value.len() > 4096": 1}}]}
    ]
    contract["bounds"][0].update(value=7, group="queue", what="x", unit="count", source="constant", **{"class": "consensus"})
    contract["bounds"][0]["owner"]["expr"] = "7"
    changed, survivors, constant_only = CHECKER["mutation_sweep"](tmp_path, contract)
    # One literal and five limits: MAX_NAMED, MAX_SHADOW_BODY_BYTES, COMMITMENT_BYTES,
    # max_shadow_proof_bytes and MAX_IN_REFERENCE.
    assert (changed, survivors, constant_only) == (6, [], [])
    # A sweep that does not look at literals lets the literal change through and says so.
    original = CHECKER["check_literals"]
    CHECKER["mutation_sweep"].__globals__["check_literals"] = lambda *args, **kwargs: None
    try:
        changed, survivors, _ = CHECKER["mutation_sweep"](tmp_path, contract)
    finally:
        CHECKER["mutation_sweep"].__globals__["check_literals"] = original
    assert changed == 6 and survivors == ["crates/demo/src/lib.rs: literal `value.len() > 4096`"]
    assert CHECKER["_OVERRIDES"] == {}


def test_changing_a_compared_limit_or_a_literal_in_memory_fails_the_checker() -> None:
    """The changes the review left unnoticed: limits that their name does not mark."""
    section = CONTRACT["completeness"]
    trees = {scope["tree"]: scope for scope in section["scopes"] if "tree" in scope}
    for crate in PATH_CRATES:
        assert trees[crate].get("comparisons") is True, crate
    assert section["literals"]["minimum"] == 2 and section["literals"]["why"]
    for path, old, new, fragment in (
        (
            "crates/iroha_data_model/src/sumeragi_finality/native_lanes.rs",
            "const COMMITMENT_BYTES: usize = 512;",
            "const COMMITMENT_BYTES: usize = 1;",
            "the excluded limit `COMMITMENT_BYTES` is now `1`; the contract records `512`",
        ),
        (
            "crates/iroha_core_zk/src/stark.rs",
            "pub const STARK_FRI_CONSENSUS_MIN_QUERIES: u16 = 64;",
            "pub const STARK_FRI_CONSENSUS_MIN_QUERIES: u16 = 1;",
            "the excluded limit `STARK_FRI_CONSENSUS_MIN_QUERIES` is now `1`; the contract records `64`",
        ),
        (
            "crates/iroha_data_model/src/kagemusha/kagemusha_ordinary_node_mint_v1.rs",
            "raw.len() > 4 * 1024 * 1024",
            "raw.len() > 1",
            "`raw.len() > 4 * 1024 * 1024` matches no literal comparison",
        ),
        (
            "crates/iroha_core/src/smartcontracts/isi/game.rs",
            "self.manifest.max_input_bytes > 4096",
            "self.manifest.max_input_bytes > 1",
            "`self.manifest.max_input_bytes > 4096` matches no literal comparison",
        ),
        (
            "crates/iroha_torii/src/routing.rs",
            "nonce_bytes.len() > 32",
            "nonce_bytes.len() > 33",
            "the literal comparison `nonce_bytes.len() > 33` (1 time(s)) is neither a site of a listed bound",
        ),
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(old) >= 1, (path, old)
        found = _with_override(path, source.replace(old, new, 1))
        assert any(fragment in item for item in found), (path, found)
    # The retail-fee request ceiling is written across lines; its text is the normalized one.
    path = "crates/iroha_core/src/retail_fee.rs"
    source = CHECKER["_read"](ROOT, path, "test")
    sites = CHECKER["literal_sites"](source, 2)
    text = next(text for text in sites if text.endswith(".len() > 1000") and "transfers" in text)
    start, end, value = sites[text][0]
    assert value == 1000
    found = _with_override(path, source[:start] + "1" + source[end:])
    assert any(f"`{text}` matches no literal comparison" in item for item in found), found
    # A new limit of each kind in each of the four crates, added in memory.
    for crate, path in (
        ("crates/iroha_data_model/src", "crates/iroha_data_model/src/consensus.rs"),
        ("crates/iroha_torii/src", "crates/iroha_torii/src/limits.rs"),
        ("crates/iroha_core/src", "crates/iroha_core/src/queue.rs"),
        ("crates/iroha_core_zk/src", "crates/iroha_core_zk/src/stark.rs"),
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        added = (
            "\npub const SHADOW_PROOF_BYTES: usize = 1;\n"
            "pub const fn max_shadow_proof_bytes() -> usize {\n    1\n}\n"
            "pub fn shadow_admits(bytes: &[u8]) -> bool {\n"
            "    bytes.len() <= SHADOW_PROOF_BYTES || bytes.len() > 40_961\n}\n"
        )
        found = _with_override(path, source + added)
        for fragment in (
            f"completeness {path}: `SHADOW_PROOF_BYTES` is neither a listed bound nor excluded",
            f"completeness {path}: `max_shadow_proof_bytes` is neither a listed bound nor excluded",
            f"completeness literals in {path}: the literal comparison `bytes.len() > 40_961`",
        ):
            assert any(fragment in item for item in found), (crate, fragment, found)
    # The result-table ceiling of an IVM execution statement is the named return-word
    # bound of an entrypoint, no literal of its own.
    statement = CHECKER["_read"](ROOT, "crates/iroha_data_model/src/proof/ivm_execution_statement.rs", "test")
    assert "initialized_word_count > 8_192" not in statement
    assert "> crate::smart_contract::entrypoint::MAX_ENTRYPOINT_RETURN_WORDS" in statement
    assert CHECKER["_OVERRIDES"] == {}


def test_every_compared_limit_and_literal_of_the_path_crates_is_classified() -> None:
    """The enumeration by use is whole, like the one by name: nothing is left unrecorded."""
    section = CONTRACT["completeness"]
    # With the sources that only an import of the compared code brings in.
    scopes = CHECKER["import_scopes"](ROOT, CHECKER["expand_scopes"](ROOT, section, []))
    compared = CHECKER["compared_symbols"](ROOT, scopes)
    listed = {
        (item["owner"]["path"], item["owner"]["symbol"])
        for item in CONTRACT["bounds"]
        if item["owner"]["kind"] in ("const", "fn")
    }
    pinned = {
        (holder["path"], symbol): holder["exprs"][symbol]
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        if not holder.get("module")
        for symbol in holder["symbols"]
    }
    # A default of a committed-parameter module is classified by the scope of that module.
    in_modules = {
        (holder["path"], symbol)
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        if holder.get("module")
        for symbol in holder["symbols"]
    }
    by_use = 0
    for path, symbols in compared.items():
        scope = next(scope for scope in scopes if scope["path"] == path and not scope.get("module"))
        source = CHECKER["_read"](ROOT, path, "test")
        for symbol in symbols:
            by_use += 1
            key = (path, symbol)
            assert key in listed or key in pinned or key in in_modules, key
            if (path, symbol) in pinned:
                assert pinned[(path, symbol)] == CHECKER["scope_expression"](source, scope, symbol, "test")
    assert by_use > 150, by_use
    recorded = {
        (holder["path"], text): count
        for group in section["literals"]["groups"]
        for holder in group["files"]
        for text, count in holder["sites"].items()
    }
    owned: dict = {}
    for item in CONTRACT["bounds"]:
        for site in item.get("enforcement", []):
            owned.setdefault(site["path"], []).append(CHECKER["normalize"](site["contains"]))
    paths = CHECKER["literal_scopes"](scopes)
    assert len(paths) > 1500 and all(any(path.startswith(crate + "/") for crate in PATH_CRATES) for path in paths)
    seen = 0
    for path in paths:
        source = CHECKER["_read"](ROOT, path, "test")
        for text, spans in CHECKER["literal_sites"](source, section["literals"]["minimum"]).items():
            seen += len(spans)
            assert (path, text) in recorded or any(
                CHECKER["_held_whole"](site, text) for site in owned.get(path, ())
            ), (path, text)
    assert seen > 600, seen
    # Every group says why, and no two groups record the same site.
    assert all(group["reason"] and group["files"] for group in section["literals"]["groups"])
    assert len(recorded) == sum(
        len(holder["sites"]) for group in section["literals"]["groups"] for holder in group["files"]
    )


def test_a_lazy_static_of_a_plain_value_is_a_limit() -> None:
    """A limit written as `LazyLock<usize>` is scanned; a lazy lock, cell or atomic is state."""
    source = (
        "static MAX_LAZY: LazyLock<usize> = LazyLock::new(|| 4096);\n"
        "static CAP_STATE: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));\n"
        "static LIMIT_ONCE: OnceLock<usize> = OnceLock::new();\n"
        "pub static MAX_PLAIN: u32 = 7;\n"
        "static BUDGET_LOCKED: once_cell::sync::Lazy<std::sync::RwLock<u8>> =\n"
        "    once_cell::sync::Lazy::new(Default::default);\n"
        "static BUDGET_VALUE: once_cell::sync::Lazy<u64> = once_cell::sync::Lazy::new(|| 9);\n"
        "static CAP_REJECTS: AtomicU64 = AtomicU64::new(0);\n"
    )
    scope = {"kind": "const"}
    assert CHECKER["scope_symbols"](source, scope, "test") == ["MAX_LAZY", "MAX_PLAIN", "BUDGET_VALUE"]
    assert CHECKER["scope_expression"](source, scope, "MAX_LAZY", "test") == "LazyLock::new(|| 4096)"
    changed = CHECKER["mutate_limit"](source, scope, "MAX_LAZY", "test")
    assert "static MAX_LAZY: LazyLock<usize> = 1;" in changed
    # No such limit exists in the tracked tree today; one that appears must be classified.
    path = "crates/iroha_core/src/queue.rs"
    queue = CHECKER["_read"](ROOT, path, "test")
    found = _with_override(
        path, queue + "\nstatic MAX_SHADOW_QUEUE_BYTES: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| 1);\n"
    )
    assert found == [
        f"completeness {path}: `MAX_SHADOW_QUEUE_BYTES` is neither a listed bound nor excluded with a reason"
    ], found


def _terms_demo(tmp_path: Path) -> dict:
    _demo_crate(
        tmp_path,
        {
            "lib.rs": (
                "pub mod frame;\npub mod wire;\n"
                "pub const HEADER_BYTES: usize = 8;\n"
                "pub const PART: usize = 16;\n"
                "pub const BODY_BYTES: usize = PART * 4;\n"
                "pub const UNUSED_WIDTH: usize = 3;\n"
                "pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + BODY_BYTES + Header::SIZE;\n"
                "pub struct Header;\n"
                "impl Header {\n"
                "    pub const SIZE: usize = 2;\n"
                "    pub const MAX_ROWS: usize = Self::ROW_WIDTH * 2;\n"
                "    pub const ROW_WIDTH: usize = 5;\n"
                "}\n"
            ),
            "frame.rs": (
                "pub const TRAILER_BYTES: usize = 4;\n"
                "pub fn frame_limit() -> usize {\n    crate::HEADER_BYTES + TRAILER_BYTES\n}\n"
            ),
            # A file that defines an item of the name refers to its own item.
            "wire.rs": (
                "const PART: u8 = 1;\n"
                "pub const MAX_WIRE: usize = PART as usize + crate::frame::TRAILER_BYTES;\n"
            ),
        },
    )
    return {
        "bounds": [
            {
                "id": "queue.header",
                "group": "queue",
                "what": "x",
                "unit": "bytes",
                "value": 8,
                "source": "constant",
                "class": "consensus",
                "owner": {
                    "path": "crates/demo/src/lib.rs",
                    "symbol": "HEADER_BYTES",
                    "kind": "const",
                    "expr": "8",
                },
                "enforcement": [],
            }
        ],
        "completeness": {
            "scopes": [{"tree": "crates/demo/src", "kind": "const", "comparisons": True}],
            "excluded": [],
            "literals": {"why": "0 and 1 test presence", "minimum": 2, "groups": []},
        },
    }


def test_a_term_of_a_scanned_limit_is_scanned_and_names_its_limit(tmp_path: Path) -> None:
    """A constant the expression of a scanned limit names is pinned, with the limits it is part of."""
    contract = _terms_demo(tmp_path)
    section = contract["completeness"]
    lib, frame, wire = (f"crates/demo/src/{name}.rs" for name in ("lib", "frame", "wire"))
    assert CHECKER["referenced_constants"](
        "HEADER + crate::frame::TRAILER_BYTES * Self::ROW_WIDTH + Header::SIZE + u64::MAX"
        " + u32::BITS as usize + core::mem::size_of::<WORD>() + CALL(1) + Mac!{} + Kind::A { x: 1 }"
        ' + "IN A STRING".len() + b\'X\' as usize /* IN_A_COMMENT */'
    ) == {"HEADER", "TRAILER_BYTES", "ROW_WIDTH", "WORD"}
    scopes = CHECKER["expand_scopes"](tmp_path, section, [])
    # Nothing is compared: every symbol but the limit function is found as a term. An
    # associated constant named through its type (`Header::SIZE`) and a constant no
    # limit names (`UNUSED_WIDTH`) are not followed.
    assert CHECKER["compared_symbols"](tmp_path, scopes) == {
        frame: ["frame_limit", "TRAILER_BYTES"],
        lib: ["HEADER_BYTES", "BODY_BYTES", "ROW_WIDTH", "PART"],
        wire: ["PART"],
    }
    terms = CHECKER["limit_terms"](tmp_path, scopes)
    assert terms == {
        frame: {"TRAILER_BYTES": [f"{frame}: frame_limit", f"{wire}: MAX_WIRE"]},
        lib: {
            "HEADER_BYTES": [f"{frame}: frame_limit", f"{lib}: MAX_FRAME_BYTES"],
            "BODY_BYTES": [f"{lib}: MAX_FRAME_BYTES"],
            "ROW_WIDTH": [f"{lib}: MAX_ROWS"],
            # `PART` of wire.rs is another item: MAX_WIRE does not name this one.
            "PART": [f"{lib}: BODY_BYTES"],
        },
        wire: {"PART": [f"{wire}: MAX_WIRE"]},
    }
    found: list = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == [
        f"completeness {frame}: `{symbol}` is neither a listed bound nor excluded with a reason"
        for symbol in ("frame_limit", "TRAILER_BYTES")
    ] + [
        f"completeness {lib}: `{symbol}` is neither a listed bound nor excluded with a reason"
        for symbol in ("MAX_FRAME_BYTES", "MAX_ROWS", "BODY_BYTES", "ROW_WIDTH", "PART")
    ] + [
        f"completeness {wire}: `{symbol}` is neither a listed bound nor excluded with a reason"
        for symbol in ("MAX_WIRE", "PART")
    ]
    # Excluded without `term_of`: each term says which limits it is part of. The listed
    # bound HEADER_BYTES is a term too and needs none; nor do the limits found by name.
    section["excluded"] = [
        {
            "reason": "demo limits and their terms",
            "files": [
                {
                    "path": frame,
                    "symbols": ["frame_limit", "TRAILER_BYTES"],
                    "exprs": {"frame_limit": "crate::HEADER_BYTES + TRAILER_BYTES", "TRAILER_BYTES": "4"},
                },
                {
                    "path": lib,
                    "symbols": ["MAX_FRAME_BYTES", "MAX_ROWS", "BODY_BYTES", "ROW_WIDTH", "PART"],
                    "exprs": {
                        "MAX_FRAME_BYTES": "HEADER_BYTES + BODY_BYTES + Header::SIZE",
                        "MAX_ROWS": "Self::ROW_WIDTH * 2",
                        "BODY_BYTES": "PART * 4",
                        "ROW_WIDTH": "5",
                        "PART": "16",
                    },
                },
                {
                    "path": wire,
                    "symbols": ["MAX_WIRE", "PART"],
                    "exprs": {"MAX_WIRE": "PART as usize + crate::frame::TRAILER_BYTES", "PART": "1"},
                },
            ],
        }
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == [
        f"completeness {frame}: `TRAILER_BYTES` is excluded as a term of {frame}: frame_limit, "
        f"{wire}: MAX_WIRE and records no `term_of`; run --refresh",
        f"completeness {lib}: `BODY_BYTES` is excluded as a term of {lib}: MAX_FRAME_BYTES and records "
        "no `term_of`; run --refresh",
        f"completeness {lib}: `ROW_WIDTH` is excluded as a term of {lib}: MAX_ROWS and records no "
        "`term_of`; run --refresh",
        f"completeness {lib}: `PART` is excluded as a term of {lib}: BODY_BYTES and records no "
        "`term_of`; run --refresh",
        f"completeness {wire}: `PART` is excluded as a term of {wire}: MAX_WIRE and records no "
        "`term_of`; run --refresh",
    ]
    # `--refresh` writes the lists; a first recording is no change to report.
    found, notes = [], []
    CHECKER["check_completeness"](tmp_path, contract, found, True, notes)
    assert found == [] and notes == []
    holders = {holder["path"]: holder for holder in section["excluded"][0]["files"]}
    assert holders[frame]["term_of"] == terms[frame]
    assert holders[lib]["term_of"] == {name: terms[lib][name] for name in ("BODY_BYTES", "ROW_WIDTH", "PART")}
    assert holders[wire]["term_of"] == terms[wire]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []

    def problems_with(path: str, old: str, new: str, refresh: bool = False, target: dict | None = None) -> tuple:
        text = (tmp_path / path).read_text(encoding="utf-8")
        assert text.count(old) == 1, old
        CHECKER["_OVERRIDES"][path] = text.replace(old, new)
        try:
            out, notes = [], []
            CHECKER["check_completeness"](tmp_path, contract if target is None else target, out, refresh, notes)
            return out, notes
        finally:
            del CHECKER["_OVERRIDES"][path]

    # A changed term is a changed pinned expression: the limit it is part of changed.
    assert problems_with(lib, "PART: usize = 16;", "PART: usize = 1;")[0] == [
        f"completeness {lib}: the excluded limit `PART` is now `1`; the contract records `16`. Review "
        "the reason of its exclusion, then run --refresh"
    ]
    # A term that the code starts to compare is a limit of its own: its record says so.
    compared = "pub fn fits(n: usize) -> bool {\n    n <= BODY_BYTES\n}\npub struct Header;\n"
    assert problems_with(lib, "pub struct Header;\n", compared)[0] == [
        f"completeness {lib}: `BODY_BYTES` records `term_of`, but it is a limit by its own name or by a "
        "comparison of its own; classify it as one, then run --refresh"
    ]
    refreshed = copy.deepcopy(contract)
    found, notes = problems_with(lib, "pub struct Header;\n", compared, True, refreshed)
    assert found == [] and notes == [
        f"completeness {lib}: `BODY_BYTES` is a limit of its own now, no term; `term_of` removed, "
        "confirm the reason of its exclusion"
    ]
    assert "BODY_BYTES" not in refreshed["completeness"]["excluded"][0]["files"][1]["term_of"]
    # Another limit that names a term changes what the term is part of.
    added = "pub const MAX_OTHER_ROWS: usize = ROW_WIDTH;\npub struct Header;\n"
    assert problems_with(lib, "pub struct Header;\n", added)[0] == [
        f"completeness {lib}: `MAX_OTHER_ROWS` is neither a listed bound nor excluded with a reason",
        f"completeness {lib}: the term `ROW_WIDTH` is part of {lib}: MAX_OTHER_ROWS, {lib}: MAX_ROWS; "
        f"the contract records {lib}: MAX_ROWS. Review the reason of its exclusion, then run --refresh",
    ]
    refreshed = copy.deepcopy(contract)
    found, notes = problems_with(lib, "pub struct Header;\n", added, True, refreshed)
    assert notes == [
        f"completeness {lib}: the term `ROW_WIDTH` is now part of {lib}: MAX_OTHER_ROWS, {lib}: MAX_ROWS, "
        f"was {lib}: MAX_ROWS; confirm its exclusion still holds"
    ]
    # A limit that no longer names its terms leaves exclusions that match nothing.
    found, _ = problems_with(lib, "HEADER_BYTES + BODY_BYTES + Header::SIZE", "HEADER_BYTES + Header::SIZE")
    assert found == [
        f"completeness {lib}: the excluded limit `MAX_FRAME_BYTES` is now `HEADER_BYTES + Header::SIZE`; "
        "the contract records `HEADER_BYTES + BODY_BYTES + Header::SIZE`. Review the reason of its "
        "exclusion, then run --refresh",
        f"completeness: the exclusion of `BODY_BYTES` in {lib} matches no scanned limit",
        f"completeness: the exclusion of `PART` in {lib} matches no scanned limit",
    ]
    # A new term is unclassified until it is excluded or listed.
    found, _ = problems_with(
        frame, "pub const TRAILER_BYTES: usize = 4;\n", "pub const TRAILER_BYTES: usize = CRC_BYTES * 2;\nconst CRC_BYTES: usize = 2;\n"
    )
    assert found == [
        f"completeness {frame}: the excluded limit `TRAILER_BYTES` is now `CRC_BYTES * 2`; the contract "
        "records `4`. Review the reason of its exclusion, then run --refresh",
        f"completeness {frame}: `CRC_BYTES` is neither a listed bound nor excluded with a reason",
    ]
    # `term_of` on a limit found by name, and for a symbol the holder does not exclude.
    broken = copy.deepcopy(contract)
    broken["completeness"]["excluded"][0]["files"][1]["term_of"]["MAX_ROWS"] = [f"{lib}: MAX_FRAME_BYTES"]
    broken["completeness"]["excluded"][0]["files"][2]["term_of"]["NOT_EXCLUDED"] = [f"{wire}: MAX_WIRE"]
    found = []
    CHECKER["check_completeness"](tmp_path, broken, found)
    assert found == [
        f"completeness exclusion in {wire}: `term_of` records `NOT_EXCLUDED`, which the group does not exclude",
        f"completeness {lib}: `MAX_ROWS` records `term_of`, but it is a limit by its own name or by a "
        "comparison of its own; classify it as one, then run --refresh",
    ]
    found, notes = [], []
    CHECKER["check_completeness"](tmp_path, broken, found, True, notes)
    assert found == [] and broken == contract
    # The sweep changes every term like every other limit: nine limits, none unnoticed.
    changed, survivors, constant_only = CHECKER["mutation_sweep"](tmp_path, contract)
    assert (changed, survivors, constant_only) == (10, [], []), (changed, survivors, constant_only)
    # A chain of terms longer than the reader follows fails loudly instead of ending early.
    original = CHECKER["_compared"].__globals__["_TERM_ROUNDS"]
    CHECKER["_compared"].__globals__["_TERM_ROUNDS"] = 1
    try:
        found = []
        CHECKER["check_completeness"](tmp_path, contract, found)
    finally:
        CHECKER["_compared"].__globals__["_TERM_ROUNDS"] = original
    assert found == ["completeness: a chain of terms is longer than 1 constants; raise `_TERM_ROUNDS`"]
    assert CHECKER["_OVERRIDES"] == {}


def test_every_term_of_the_path_crates_is_pinned_with_the_limits_it_is_part_of() -> None:
    """Terms of the four crates: each is classified, names its limits, and a change is reported."""
    section = CONTRACT["completeness"]
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    terms = CHECKER["limit_terms"](ROOT, scopes)
    listed = {
        (item["owner"]["path"], item["owner"]["symbol"])
        for item in CONTRACT["bounds"]
        if item["owner"]["kind"] in ("const", "fn")
    }
    holders = {
        (holder["path"], symbol): (holder, group["reason"])
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        if not holder.get("module")
        for symbol in holder["symbols"]
    }
    in_modules = {
        (holder["path"], symbol)
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        if holder.get("module")
        for symbol in holder["symbols"]
    }
    recorded = {
        (holder["path"], symbol): part_of
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        for symbol, part_of in holder.get("term_of", {}).items()
    }
    named: dict = {}
    # A term may lie in a source of another crate: one the compared code imports from.
    imported = CHECKER["imported_constants"](ROOT, scopes)
    for scope in CHECKER["import_scopes"](ROOT, scopes):
        if not scope.get("module"):
            named[scope["path"]] = (
                set()
                if scope.get("imported")
                else set(
                    CHECKER["scope_symbols"](
                        CHECKER["_read"](ROOT, scope["path"], "test"), scope, "test"
                    )
                )
            )
    excluded_terms = {}
    outside = 0
    for path, by_term in terms.items():
        if not any(path.startswith(crate + "/") for crate in PATH_CRATES):
            assert set(by_term) <= set(imported[path]), path
            outside += len(by_term)
        for term, part_of in by_term.items():
            assert part_of, (path, term)
            if term in named[path]:
                # A scope with its own `matching` pattern already scans it by name.
                continue
            key = (path, term)
            if key in in_modules and key not in holders:
                # A scope of a module of the file classifies it and pins its expression.
                continue
            assert key in listed or key in holders, key
            if key in holders:
                excluded_terms[key] = part_of
            # Every limit a term is part of is classified itself.
            for label in part_of:
                user, _, symbol = label.partition(": ")
                assert (user, symbol) in listed or (user, symbol) in holders or (user, symbol) in in_modules, label
    # The contract records exactly these lists, and only for terms.
    assert recorded == excluded_terms
    assert len(excluded_terms) >= 40, len(excluded_terms)
    # Terms are followed into the other crates of the workspace.
    assert outside >= 30, outside
    assert terms["crates/iroha_primitives/src/json.rs"]["MAX_JSON_BYTES"] == [
        "crates/iroha_core/src/compliance/mod.rs: LANE_COMPLIANCE_POLICY_MAX_FIELD_BYTES",
        "crates/iroha_data_model/src/nexus/runtime_catalog.rs: MAX_NEXUS_RUNTIME_CATALOG_BYTES",
    ]
    assert bound(CONTRACT, "transaction.json_document_max_bytes")["owner"]["symbol"] == "MAX_JSON_BYTES"
    # The reason of a term's group says what a term is; no other group holds one.
    for key in excluded_terms:
        assert holders[key][1].startswith("Terms of excluded limits"), key
    # The cases a reviewer would try: a term of a product limit, of a limit function, of a
    # limit of another crate and of another term.
    for path, old, new, symbol in (
        (
            "crates/iroha_data_model/src/soranet/vpn.rs",
            "const VPN_HEADER_LEN: usize = 42;",
            "const VPN_HEADER_LEN: usize = 1;",
            "VPN_HEADER_LEN",
        ),
        (
            "crates/iroha_core/src/smartcontracts/isi/query/canonical_topk.rs",
            "CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES: u64 = 1024;",
            "CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES: u64 = 1;",
            "CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES",
        ),
        (
            "crates/iroha_core/src/privacy_release_evidence.rs",
            "PRIVACY_RELEASE_CASE_COUNT_V1: usize = 4;",
            "PRIVACY_RELEASE_CASE_COUNT_V1: usize = 1;",
            "PRIVACY_RELEASE_CASE_COUNT_V1",
        ),
        (
            "crates/iroha_core_zk/src/confidential_v2.rs",
            "CONFIDENTIAL_TRANSFER_V2_IPA_K: u32 = 13;",
            "CONFIDENTIAL_TRANSFER_V2_IPA_K: u32 = 1;",
            "CONFIDENTIAL_TRANSFER_V2_IPA_K",
        ),
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(old) == 1, (path, old)
        assert (path, symbol) in excluded_terms, symbol
        found = _with_override(path, source.replace(old, new))
        assert any(f"the excluded limit `{symbol}` is now `1`" in item for item in found), (symbol, found)
    # A new term in each of the four crates, added in memory.
    for path in (
        "crates/iroha_data_model/src/consensus.rs",
        "crates/iroha_torii/src/limits.rs",
        "crates/iroha_core/src/queue.rs",
        "crates/iroha_core_zk/src/stark.rs",
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        added = (
            "\npub const MAX_SHADOW_FRAME_BYTES: usize = SHADOW_PREFIX_BYTES + 1;\n"
            "const SHADOW_PREFIX_BYTES: usize = 7;\n"
        )
        found = _with_override(path, source + added)
        for symbol in ("MAX_SHADOW_FRAME_BYTES", "SHADOW_PREFIX_BYTES"):
            fragment = f"completeness {path}: `{symbol}` is neither a listed bound nor excluded"
            assert any(fragment in item for item in found), (path, symbol, found)
    # `--propose` says what an unlisted term is part of.
    CHECKER["_OVERRIDES"][path] = source + added
    try:
        lines = CHECKER["propose"](ROOT, copy.deepcopy(CONTRACT), TASKS, [])
    finally:
        del CHECKER["_OVERRIDES"][path]
    text = "\n".join(lines)
    assert f"# unlisted limit `SHADOW_PREFIX_BYTES` in {path}: list it or exclude it" in text
    assert (
        f"#   it is a term of {path}: MAX_SHADOW_FRAME_BYTES: an exclusion records that list as "
        "`term_of` (--refresh writes it)"
    ) in text
    assert text.count("it is a term of") == 1, text
    assert CHECKER["_OVERRIDES"] == {}


# ---------------------------------------------------------------------------
# Literals at any indentation, literals that are a part of what is compared,
# test modules and gates in every form they are written
# ---------------------------------------------------------------------------


def _recorded_literal_sites(contract: dict | None = None) -> dict:
    """`(path, text) -> count` of every literal comparison the contract records."""
    section = (CONTRACT if contract is None else contract)["completeness"]
    return {
        (holder["path"], text): count
        for group in section["literals"]["groups"]
        for holder in group["files"]
        for text, count in holder["sites"].items()
    }


def test_a_literal_at_the_end_of_a_line_is_read_at_any_indentation() -> None:
    """The line after a literal may be indented by any depth, and a literal may end the text."""
    sites = CHECKER["literal_sites"]
    for indent in (0, 4, 8, 16, 20, 21, 22, 23, 24, 28, 32, 40, 64):
        pad = " " * indent
        for joiner in ("||", "&&"):
            source = (
                "fn f(token: &[u8], other: bool) -> bool {\n"
                f"{pad}token.is_empty()\n{pad}    {joiner} token.len() > 64 * 1024\n"
                f"{pad}    {joiner} other\n}}\n"
            )
            assert sorted(sites(source, 2)) == ["token.len() > 64 * 1024"], (indent, joiner)
        # The literal in front of the operator, first on a deeply indented line.
        source = f"fn g(n: usize, other: bool) -> bool {{\n{pad}other\n{pad}    && 63 < n\n}}\n"
        assert sorted(sites(source, 2)) == ["63 < n"], indent
        # What the next line adds continues the operand: the literal is a part of it.
        source = f"fn h(n: usize, m: usize) -> bool {{\n{pad}n > 64\n{pad}    + m\n}}\n"
        assert sorted(sites(source, 2)) == ["n > 64 + m"], indent
        # A single `&` or `|` continues it as well; `&&` and `||` end it.
        source = f"fn i(n: usize, m: usize) -> bool {{\n{pad}n > 64\n{pad}    | m\n}}\n"
        assert sorted(sites(source, 2)) == ["n > 64 | m"], indent
    assert sorted(sites("const fn k(n: usize) -> bool { n > 63", 2)) == ["n > 63"]
    assert sorted(sites("const K: bool = 63 < N", 2)) == ["63 < N"]

    # The two comparisons of the tracked tree that this layout hid are recorded.
    recorded = _recorded_literal_sites()
    hidden = (
        (
            "crates/iroha_data_model/src/kagemusha/kagemusha_ordinary_enrollment_http_v1.rs",
            "token.len() > 64 * 1024",
            "token.len() > 1024 * 1024 * 1024",
        ),
        (
            "crates/iroha_torii/src/sorafs/delegated_routing.rs",
            "label.len() > 63",
            "label.len() > 6300",
        ),
    )
    for path, text, changed in hidden:
        assert recorded[(path, text)] == 1, (path, text)
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(text) == 1, (path, text)
        # In the source the next line is indented 24 columns or more.
        after = source[source.index(text) + len(text) :]
        assert len(after) - len(after.lstrip(" \n")) >= 25, path
        found = _with_override(path, source.replace(text, changed))
        assert any(f"`{text}` matches no literal comparison" in item for item in found), found
        assert any(f"the literal comparison `{changed}`" in item for item in found), found
    # A new comparison written this way is reported in each of the four crates.
    for path in (
        "crates/iroha_data_model/src/consensus.rs",
        "crates/iroha_torii/src/limits.rs",
        "crates/iroha_core/src/queue.rs",
        "crates/iroha_core_zk/src/stark.rs",
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        for indent in (8, 20, 24, 28, 32):
            pad = " " * indent
            added = (
                "\npub fn shadow_token_is_refused(token: &[u8], other: bool) -> bool {\n"
                f"{pad}token.is_empty()\n{pad}    || token.len() > 65_537\n{pad}    || other\n}}\n"
            )
            found = _with_override(path, source + added)
            assert any(
                f"completeness literals in {path}: the literal comparison `token.len() > 65_537`" in item
                for item in found
            ), (path, indent, found)
    assert CHECKER["_OVERRIDES"] == {}


_PART_LITERAL_SOURCE = (
    "const MAX: usize = 4096;\n"
    "fn f(len: usize, original: &[u8], height: u64, expires: u64, timeout: Duration, items: &[u8], x: usize) -> bool {\n"
    "    if original.len() > MAX + 1024 || len > 2 * MAX {\n        return false;\n    }\n"
    "    if items.len() / 2 >= MAX || expires > height.saturating_add(1_000_000) {\n        return false;\n    }\n"
    "    let a = timeout > Duration::from_secs(5 * 60);\n"
    "    let b = x < (1 << 12);\n"
    "    let c = 2.max(len / 4);\n"
    "    let d = core::cmp::min(MAX, len - 8);\n"
    "    let e = std::cmp::max(len, 64);\n"
    "    let g = (len / 2).min(MAX);\n"
    "    let h = items.iter().take(len + 8).count();\n"
    "    let i = (2..=MAX).contains(&len);\n"
    "    let j = fields[7].len() > MAX;\n"
    "    let k = len.min(MAX / 2).max(16);\n"
    "    let l = pair.0 > pair.1 && y > 0.5 && z < 1e9 && w > 2f64;\n"
    "    let m = x.len() / 4 > 1;\n"
    "    let n = match len {\n        v => v * 3 > x,\n    };\n"
    "    let o = items.iter().filter(|v| **v as usize * 2 > len).count() > x + 5;\n"
    "    let table: BTreeMap<\n        Key,\n        Value,\n    > = scan(world, 64)?;\n"
    "    let p = seed[..8].len() > x && min(len, 32) > 0;\n"
    "    let q = some_very_long_receiver_expression_name.iter().map(|value| value.len() * 3).sum::<usize>().min(MAX);\n"
    "    let r = some_very_long_receiver_expression_name.iter().map(|value| value.len() + 1).sum::<usize>().min(77);\n"
    "    a\n}\n"
    "fn min(a: usize, b: usize) -> usize {\n    a\n}\n"
)


def test_a_literal_that_is_part_of_a_compared_operand_is_a_site() -> None:
    """`MAX + 1024`, `2 * MAX`, `len / 2 >= MAX`: the literal moves the limit and is pinned."""
    source = _PART_LITERAL_SOURCE
    sites = CHECKER["literal_sites"](source, 2)
    assert {text: [value for _, _, value in spans] for text, spans in sites.items()} == {
        # An addend, a factor, a divisor and the argument of a call in a compared operand.
        "original.len() > MAX + 1024": [1024],
        "len > 2 * MAX": [2],
        "items.len() / 2 >= MAX": [2],
        "expires > height.saturating_add(1_000_000)": [1_000_000],
        "timeout > Duration::from_secs(5 * 60)": [5, 60],
        # A parenthesised literal is a part: its integers of 2 or more are pinned.
        "x < (1 << 12)": [12],
        # A literal receiver, the function form and a literal in a compared receiver.
        "2.max(len / 4)": [2, 4],
        "core::cmp::min(MAX, len - 8)": [8],
        "std::cmp::max(len, 64)": [64],
        "(len / 2).min(MAX)": [2],
        "min(len, 32)": [32],
        # A part of an argument of `.take` and the start of a tested range.
        "items.iter().take(len + 8)": [8],
        "(2..=MAX).contains(&len)": [2],
        # An index inside a comparison, and a range end inside one.
        "fields[7].len() > MAX": [7],
        "seed[..8].len() > x": [8],
        # A site that holds another literal in its text pins it too.
        "len.min(MAX / 2).max(16)": [2, 16],
        # A whole operand below the minimum hides no part of the other operand.
        "x.len() / 4 > 1": [4],
        # After the `=>` of a match arm; the head of a closure is no part of the text.
        "v * 3 > x": [3],
        "**v as usize * 2 > len": [2],
        "items.iter().filter(|v| **v as usize * 2 > len).count() > x + 5": [5],
        # A long compared receiver joins the text only when it holds a literal.
        "some_very_long_receiver_expression_name.iter().map(|value| value.len() * 3).sum::<usize>().min(MAX)": [3],
        ".min(77)": [77],
    }
    # No float, tuple field or generic bracket is a literal site, and `fn min(..)` is no call.
    assert not any("pair" in text or "scan(world" in text or "fn min" in text for text in sites)
    # One comparison is one occurrence, however many literals it holds.
    occurrences = CHECKER["literal_occurrences"](source, 2)
    assert set(occurrences) == set(sites) and set(occurrences.values()) == {1}
    assert len(sites["timeout > Duration::from_secs(5 * 60)"]) == 2
    # Every span is the literal itself, so each can be changed alone.
    for text, spans in sites.items():
        for start, end, value in spans:
            assert CHECKER["literal_value"](source[start:end]) == value, text
    # The minimum decides for parts as for whole operands.
    assert {text: [value for _, _, value in spans] for text, spans in CHECKER["literal_sites"](source, 1000).items()} == {
        "original.len() > MAX + 1024": [1024],
        "expires > height.saturating_add(1_000_000)": [1_000_000],
    }
    assert "x.len() / 4 > 1" not in CHECKER["literal_sites"](source, 5)
    scan = CHECKER["comparison_scan"](source)
    # A constant given to `min` or `max` called as a function is compared.
    assert scan["uses"] == {"MAX"}
    assert CHECKER["comparison_scan"]("fn f(x: usize) -> usize {\n    core::cmp::min(SHADOW_BYTES, x)\n}\n")["uses"] == {
        "SHADOW_BYTES"
    }
    # A constant of a single letter is a constant: its use in a comparison is read.
    single = CHECKER["comparison_scan"](
        "const Q: usize = 9;\nfn f<T: Ord, const N: usize>(n: usize) -> bool {\n    n > Q && n < N\n}\n"
    )
    assert single["integers"] == ("Q",) and single["uses"] == {"Q", "N"}
    assert CHECKER["referenced_constants"]("3 * Q + u64::MAX as usize") == {"Q"}
    # A limit function may return its integer in an `Option` or as the value of a `Result`.
    functions = CHECKER["comparison_scan"](
        "fn shadow_reserve() -> Option<u64> {\n    None\n}\n"
        "fn shadow_cap() -> Result<usize, Error> {\n    Ok(1)\n}\n"
        "fn shadow_limit() -> std::io::Result<u32> {\n    Ok(1)\n}\n"
        "fn limits() -> Limits {\n    Limits::default()\n}\n"
        "fn capacity_error() -> Error {\n    Error\n}\n"
        "fn budget_text() -> Option<String> {\n    None\n}\n"
    )["functions"]
    assert sorted(functions) == ["shadow_cap", "shadow_limit", "shadow_reserve"]
    # The clause of a comparison: both operands whole, nothing that only stands in front.
    mask = "    return if a + 2 > b { 1 } else { 0 };"
    operator = mask.index(">")
    left, right = CHECKER["_compared_clause"](mask, operator, operator + 1)
    assert mask[left:right] == "a + 2 > b"
    mask = "    Vec<\n        Key,\n    > = scan(2);"
    operator = mask.index(">")
    assert CHECKER["_compared_clause"](mask, operator, operator + 1)[0] == operator
    # An operand longer than the window is cut at a blank, never inside a name or a literal.
    window = CHECKER["_CLAUSE_WINDOW"]
    mask = "x > " + "a + " * (window // 4) + "123456 + b"
    left, right = CHECKER["_compared_clause"](mask, 2, 3)
    assert mask[left:right].endswith((" a", " +")) and right - 3 <= window


def test_a_part_literal_is_recorded_and_changed_by_the_sweep(tmp_path: Path) -> None:
    """A comparisons scope requires the whole comparison of a part literal, and `--mutate` raises each."""
    _demo_crate(
        tmp_path,
        {
            "lib.rs": (
                "pub const MAX_NAMED: usize = 7;\n"
                "pub fn check(value: &[u8], wait: Duration) -> bool {\n"
                "    value.len() > MAX_NAMED + 1024 && value.len() / 2 >= MAX_NAMED\n"
                "        && wait > Duration::from_secs(5 * 60)\n}\n"
                "pub fn shadow_reserve() -> Option<u64> {\n    Some(3)\n}\n"
            ),
        },
    )
    lib = "crates/demo/src/lib.rs"
    contract = {
        "bounds": [
            {
                "id": "queue.named",
                "value": 7,
                "group": "queue",
                "what": "x",
                "unit": "count",
                "source": "constant",
                "class": "consensus",
                "owner": {"path": lib, "symbol": "MAX_NAMED", "kind": "const", "expr": "7"},
                "enforcement": [],
            }
        ],
        "completeness": {
            "scopes": [{"tree": "crates/demo/src", "kind": "const", "comparisons": True}],
            "excluded": [],
            "literals": {"why": "0 and 1 test presence", "minimum": 2, "groups": []},
        },
    }
    found: list = []
    unlisted: list = []
    CHECKER["check_completeness"](tmp_path, contract, found, False, None, unlisted)
    assert found == [
        f"completeness {lib}: `shadow_reserve` is neither a listed bound nor excluded with a reason",
        f"completeness literals in {lib}: the literal comparison `value.len() > MAX_NAMED + 1024` "
        "(1 time(s)) is neither a site of a listed bound nor recorded with a reason",
        f"completeness literals in {lib}: the literal comparison `value.len() / 2 >= MAX_NAMED` "
        "(1 time(s)) is neither a site of a listed bound nor recorded with a reason",
        f"completeness literals in {lib}: the literal comparison `wait > Duration::from_secs(5 * 60)` "
        "(1 time(s)) is neither a site of a listed bound nor recorded with a reason",
    ]
    contract["completeness"]["excluded"] = [
        {"reason": "a demo", "files": [{"path": lib, "symbols": ["shadow_reserve"], "exprs": {"shadow_reserve": "Some(3)"}}]}
    ]
    contract["completeness"]["literals"]["groups"] = [
        {
            "reason": "demo shapes",
            "files": [{"path": lib, "sites": {item[1]: item[2] for item in unlisted if len(item) == 3}}],
        }
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []
    # A comparison inside an enforcement site of the bound is owned once, with both its literals.
    owned = copy.deepcopy(contract)
    owned["bounds"][0]["enforcement"] = [
        {"stage": "queue", "path": lib, "contains": "&& wait > Duration::from_secs(5 * 60)"}
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, owned, found)
    assert found == [
        f"completeness literals in {lib}: `wait > Duration::from_secs(5 * 60)` is a site of a listed bound "
        "and recorded here too"
    ]
    # Each literal of each comparison is raised by one: 1024, 2, 5 and 60, then the two limits.
    changed, survivors, constant_only = CHECKER["mutation_sweep"](tmp_path, contract)
    assert (changed, survivors, constant_only) == (6, [], [])
    source = (tmp_path / lib).read_text(encoding="utf-8")
    for old, new, gone in (
        ("MAX_NAMED + 1024", "MAX_NAMED + 2048", "value.len() > MAX_NAMED + 1024"),
        ("value.len() / 2", "value.len() / 3", "value.len() / 2 >= MAX_NAMED"),
        ("from_secs(5 * 60)", "from_secs(5 * 61)", "wait > Duration::from_secs(5 * 60)"),
        ("Some(3)", "Some(4)", "the excluded limit `shadow_reserve` is now `Some(4)`"),
    ):
        CHECKER["_OVERRIDES"][lib] = source.replace(old, new)
        try:
            found = []
            CHECKER["check_completeness"](tmp_path, contract, found)
        finally:
            del CHECKER["_OVERRIDES"][lib]
        assert any(gone in item for item in found), (old, found)
    assert CHECKER["_OVERRIDES"] == {}


def test_changing_a_part_literal_in_memory_fails_the_checker() -> None:
    """The changes the second review left unnoticed: a literal beside a named limit."""
    recorded = _recorded_literal_sites()
    for path, text, old, new in (
        (
            "crates/iroha_data_model/src/kagemusha/kagemusha_app_enrollment_possession_v1.rs",
            "original.len() > KAGEMUSHA_APP_ENROLLMENT_POSSESSION_MAX_BYTES_V1 + 1024",
            "original.len() > KAGEMUSHA_APP_ENROLLMENT_POSSESSION_MAX_BYTES_V1 + 1024",
            "original.len() > KAGEMUSHA_APP_ENROLLMENT_POSSESSION_MAX_BYTES_V1 + 1025",
        ),
        (
            "crates/iroha_data_model/src/kagemusha/kagemusha_ordinary_node_mint_v1.rs",
            "payload_bytes > KAGEMUSHA_ORDINARY_NODE_MINT_SUBMISSION_MAX_BYTES_V1 - 64 * 1024",
            "MAX_BYTES_V1 - 64 * 1024",
            "MAX_BYTES_V1 - 65 * 1024",
        ),
        (
            "crates/iroha_data_model/src/musubi.rs",
            "account.len() > 2 * MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1",
            "account.len() > 2 * MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1",
            "account.len() > 3 * MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1",
        ),
        (
            "crates/iroha_core/src/state.rs",
            "encoded_hex.len() > MAX_AUTOSCALE_COMMITTEE_BYTES.saturating_mul(2)",
            "MAX_AUTOSCALE_COMMITTEE_BYTES.saturating_mul(2)",
            "MAX_AUTOSCALE_COMMITTEE_BYTES.saturating_mul(3)",
        ),
        (
            "crates/iroha_core/src/smartcontracts/ivm/host.rs",
            "instructions.len() / 2 >= MAX_NFTS_PER_CALL",
            "instructions.len() / 2 >= MAX_NFTS_PER_CALL",
            "instructions.len() / 3 >= MAX_NFTS_PER_CALL",
        ),
        (
            "crates/iroha_core/src/smartcontracts/isi/nft_market.rs",
            "self.expires_at_height > height.saturating_add(1_000_000)",
            "height.saturating_add(1_000_000)",
            "height.saturating_add(1_000_001)",
        ),
        (
            "crates/iroha_torii/src/sorafs/gateway/compliance.rs",
            "self.fetch_limits.connect_timeout > Duration::from_secs(30)",
            "connect_timeout > Duration::from_secs(30)",
            "connect_timeout > Duration::from_secs(31)",
        ),
        (
            "crates/iroha_torii/src/collections/engine.rs",
            "2.max(candidate.len() / 4)",
            "2.max(candidate.len() / 4)",
            "3.max(candidate.len() / 4)",
        ),
        (
            "crates/iroha_core_zk/src/kagemusha_v1_state/ordinary_native_clock.rs",
            "original.len() > MAX_FRAME / 4",
            "original.len() > MAX_FRAME / 4",
            "original.len() > MAX_FRAME / 5",
        ),
        (
            "crates/iroha_core_zk/src/pasta_sha256_table8.rs",
            "TABLE8_COMPRESSION_ROWS_ESTIMATE_UNMEASURED < (1 << 12)",
            "UNMEASURED < (1 << 12)",
            "UNMEASURED < (1 << 13)",
        ),
    ):
        assert recorded[(path, text)] >= 1, (path, text)
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(old) >= 1, (path, old)
        found = _with_override(path, source.replace(old, new, 1))
        assert any(f"`{text}`" in item for item in found), (path, found)
    # A function-form cap names a constant that is compared, and a limit function may
    # return an `Option`: both are classified in the tracked tree and pinned.
    for path, old, new, fragment in (
        (
            "crates/iroha_data_model/src/zk.rs",
            "pub const ZK_ACE_PACKED_LIMB_BYTES: usize = 7;",
            "pub const ZK_ACE_PACKED_LIMB_BYTES: usize = 8;",
            "the excluded limit `ZK_ACE_PACKED_LIMB_BYTES` is now `8`; the contract records `7`",
        ),
        (
            "crates/iroha_torii/src/torii_fanout_decode_helpers.rs",
            "const QUERY_FANOUT_CANDIDATE_IDENTITY_REPRESENTATIONS: usize = 3;",
            "const QUERY_FANOUT_CANDIDATE_IDENTITY_REPRESENTATIONS: usize = 4;",
            "the excluded limit `QUERY_FANOUT_CANDIDATE_IDENTITY_REPRESENTATIONS` is now `4`",
        ),
        (
            "crates/iroha_torii/src/limits.rs",
            "if soft == libc::RLIM_INFINITY || soft == 0 {",
            "if soft == libc::RLIM_INFINITY {",
            "the excluded limit `nofile_soft_limit` is now",
        ),
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(old) == 1, (path, old)
        found = _with_override(path, source.replace(old, new))
        assert any(fragment in item for item in found), (path, found)
    # New comparisons of each part form, in each of the four crates.
    for path in (
        "crates/iroha_data_model/src/consensus.rs",
        "crates/iroha_torii/src/limits.rs",
        "crates/iroha_core/src/queue.rs",
        "crates/iroha_core_zk/src/stark.rs",
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        added = (
            "\nconst SHADOW_ROWS: usize = 3;\nconst Q: usize = 5;\n"
            "pub fn shadow_admits(bytes: &[u8], wait: core::time::Duration, rows: usize) -> bool {\n"
            "    bytes.len() <= rows + 40_961\n"
            "        && rows > Q\n"
            "        && bytes.len() / 3 >= rows\n"
            "        && wait > core::time::Duration::from_secs(40_963)\n"
            "        && core::cmp::min(SHADOW_ROWS, rows) > 0\n"
            "        && rows.saturating_mul(40_965).min(bytes.len()) > 0\n}\n"
            "pub fn shadow_reserve_bytes() -> Option<usize> {\n    None\n}\n"
        )
        found = _with_override(path, source + added)
        for fragment in (
            f"completeness {path}: `SHADOW_ROWS` is neither a listed bound nor excluded",
            f"completeness {path}: `Q` is neither a listed bound nor excluded",
            f"completeness {path}: `shadow_reserve_bytes` is neither a listed bound nor excluded",
            f"completeness literals in {path}: the literal comparison `bytes.len() <= rows + 40_961`",
            f"completeness literals in {path}: the literal comparison `bytes.len() / 3 >= rows`",
            f"completeness literals in {path}: the literal comparison `wait > core::time::Duration::from_secs(40_963)`",
            f"completeness literals in {path}: the literal comparison `rows.saturating_mul(40_965).min(bytes.len())`",
        ):
            assert any(fragment in item for item in found), (path, fragment, found)
    assert CHECKER["_OVERRIDES"] == {}


def test_every_literal_of_a_compared_clause_in_the_path_crates_is_pinned() -> None:
    """An enumeration of its own: no integer of 2 or more in a compared clause is outside every site."""
    section = CONTRACT["completeness"]
    minimum = section["literals"]["minimum"]
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    paths = CHECKER["literal_scopes"](scopes)
    relational = re.compile(r"(?<=\s)(?:<=|>=|<|>)(?=\s)")
    integer = re.compile(
        r"(?<![A-Za-z0-9_])(?:0x[0-9a-fA-F_]+|[0-9][0-9_]*)(?:_?[ui](?:8|16|32|64|128|size))?(?![A-Za-z0-9_])"
    )
    comparisons = literals = occurrences = 0
    window = CHECKER["_CLAUSE_WINDOW"]
    cut: list = []
    for path in paths:
        source = CHECKER["_read"](ROOT, path, "test")
        sites = CHECKER["literal_sites"](source, minimum)
        occurrences += sum(CHECKER["literal_occurrences"](source, minimum).values())
        pinned = sorted((start, end) for spans in sites.values() for start, end, _ in spans)
        mask = CHECKER["production_mask"](source)
        for match in relational.finditer(mask):
            left = CHECKER["_clause_start"](mask, match.start())
            right = CHECKER["_clause_end"](mask, match.end())
            if not mask[left : match.start()].strip():
                continue  # the `>` that closes a generic list on a line of its own
            comparisons += 1
            if match.start() - left >= window or right - match.end() >= window:
                # Longer than the clause window: only the bracket of a generic list is.
                cut.append((path, source.count("\n", 0, match.start()) + 1))
                assert not any(
                    (CHECKER["literal_value"](literal.group(0)) or 0) >= minimum
                    for literal in integer.finditer(mask, left, right)
                ), cut[-1]
            for literal in integer.finditer(mask, left, right):
                text = literal.group(0)
                before = mask[max(0, literal.start() - 2) : literal.start()]
                after = mask[literal.end() : literal.end() + 2]
                if (before.endswith(".") and not before.endswith("..")) or (
                    after[:1] == "." and after[1:2].isdigit()
                ):
                    continue  # a tuple field or a float
                value = CHECKER["literal_value"](text)
                if value is None or value < minimum:
                    continue
                literals += 1
                position = literal.start()
                assert any(start <= position < end for start, end in pinned), (
                    path,
                    source.count("\n", 0, position) + 1,
                    " ".join(source[left:right].split()),
                )
    assert comparisons > 10_000 and literals > 700, (comparisons, literals)
    # No comparison is longer than the window on a side: nothing is read in part.
    assert len(cut) <= 4, cut
    # What the contract records and what bounds own add up to every occurrence.
    recorded = _recorded_literal_sites()
    assert sum(recorded.values()) <= occurrences
    assert sum(recorded.values()) == CHECKER["_recorded_literals"](CONTRACT)


def test_an_inline_test_module_is_read_by_its_gate() -> None:
    """A test module is one whose gate holds only in test builds, however the gate is written."""
    source = (
        "pub const MAX_PRODUCTION: usize = 1;\n"
        "#[cfg(all(feature = \"telemetry\", test))]\n#[allow(clippy::float_cmp)]\nmod reversed {\n"
        "    const MAX_REVERSED: usize = 2;\n    fn t(x: usize) -> bool {\n        x > 111\n    }\n}\n"
        "#[cfg(all(\n    test,\n    feature = \"x\"\n))]\nmod spread {\n    const MAX_SPREAD: usize = 3;\n"
        "    fn t(x: usize) -> bool {\n        x > 222 && '{' != '}'\n    }\n}\n"
        "/// Documented.\n#[cfg(test)]\n// a comment; with a semicolon and a brace }\n/// More.\n"
        "pub(crate) mod plain {\n    const MAX_PLAIN: usize = 4;\n    const BRACE: char = '{';\n"
        "    const RAW: &str = r#\"\"}\"#;\n}\n"
        "#[cfg(any(test, feature = \"y\"))]\nmod shared {\n    pub const MAX_SHARED: usize = 5;\n"
        "    pub fn t(x: usize) -> bool {\n        x > 333\n    }\n}\n"
        "#[cfg(not(test))]\nmod production_only {\n    pub const MAX_NOT_TEST: usize = 6;\n}\n"
        "mod outer {\n    #[cfg(test)]\n    mod nested {\n        const MAX_NESTED: usize = 7;\n    }\n"
        "    pub const MAX_OUTER: usize = 8;\n}\n"
        "pub const MAX_AFTER: usize = 9;\n"
        "pub fn after(x: usize) -> bool {\n    x > 444\n}\n"
    )
    modules = CHECKER["inline_test_modules"](source)
    assert [source[opening - 12 : opening + 1].split()[-2] for _, opening in modules] == [
        "reversed",
        "spread",
        "plain",
        "nested",
    ]
    # The block of a module starts at its attributes.
    assert source[modules[0][0] :].startswith('#[cfg(all(feature = "telemetry", test))]')
    assert source[modules[1][0] :].startswith("#[cfg(all(\n")
    assert source[modules[2][0] :].startswith("/// Documented.")
    # A module that a non-test build compiles too is production code: `any(test, ..)`, `not(test)`.
    assert CHECKER["scope_symbols"](source, {"kind": "const"}, "test") == [
        "MAX_PRODUCTION",
        "MAX_SHARED",
        "MAX_NOT_TEST",
        "MAX_OUTER",
        "MAX_AFTER",
    ]
    # A brace in a character literal or a raw string of the tests does not move the end of
    # their module: what follows it is still read.
    assert sorted(CHECKER["literal_sites"](source, 2)) == ["x > 333", "x > 444"]
    stripped = CHECKER["_without_inline_tests"](source)
    assert "MAX_AFTER" in stripped and "MAX_PLAIN" not in stripped and "MAX_NESTED" not in stripped
    assert "MAX_OUTER" in stripped and "x > 222" not in stripped
    # The tracked tree: the three modules whose gate names the feature first are test code,
    # and what follows a test module with braces in its literals is production code.
    telemetry = CHECKER["_read"](ROOT, "crates/iroha_core/src/telemetry.rs", "test")
    assert '#[cfg(all(feature = "telemetry", test))]' in telemetry
    assert not any("baseline_high_post" in text for text in CHECKER["literal_sites"](telemetry, 2))
    routing_path = "crates/iroha_torii/src/routing.rs"
    routing = CHECKER["_read"](ROOT, routing_path, "test")
    assert routing.count('#[cfg(all(feature = "app_api", test))]\nmod ') == 2
    symbols = CHECKER["scope_symbols"](routing, {"kind": "const"}, "test")
    for symbol in ("MAX_TRANSACTION_PAYLOAD_BYTES", "DEFAULT_CONTRACT_ARGUMENT_GAS_LIMIT"):
        assert symbol in symbols, symbol
    stripped = CHECKER["_without_inline_tests"](routing)
    assert "mod app_api_transaction_signing_tests" not in stripped
    assert "mod asset_transfer_request_tests" not in stripped
    # Every inline test module of every scanned source ends where its code mask says.
    scopes = CHECKER["expand_scopes"](ROOT, CONTRACT["completeness"], [])
    modules = 0
    for path in sorted({scope["path"] for scope in scopes}):
        text = CHECKER["_read"](ROOT, path, "test")
        found = CHECKER["inline_test_modules"](text)
        if not found:
            continue
        mask = CHECKER["source_mask"](text)
        stripped = CHECKER["_without_inline_tests"](text)
        removed = 0
        position = 0
        for start, opening in found:
            if start < position:
                continue
            end = CHECKER["_mask_block_end"](mask, opening)
            end = len(text) if end < 0 else end
            removed += end - start
            position = end
            modules += 1
        assert len(stripped) == len(text) - removed, path
    assert modules > 1500, modules


def test_a_gate_that_never_holds_is_read_at_any_depth(tmp_path: Path) -> None:
    """`any()`, `not(test)` and a feature the command turns off compile a test out."""
    node = CHECKER["_cfg_node"]
    value = CHECKER["_cfg_value"]
    assert node('all(test, any(), not(feature = "a"), target_os = "none")') == (
        "all",
        [("test",), ("any", []), ("not", ("feature", "a")), ("other", 'target_os = "none"')],
    )
    # A boolean literal is the empty group it equals: `false` never holds, `true` always does.
    assert node("all(test, false, not(true))") == (
        "all",
        [("test",), ("any", []), ("not", ("all", []))],
    )
    # In a test build, with features unknown.
    for predicate, expected in (
        ("test", True),
        ("any()", False),
        ("all()", True),
        ("not(all())", False),
        ("not(test)", False),
        ("all(test, any())", False),
        ("any(not(test), all(test, any()))", False),
        ("false", False),
        ("true", True),
        ("not(true)", False),
        ("all(test, false)", False),
        ("all(test, not(true))", False),
        ("any(not(test), false)", False),
        ("any(test, false)", True),
        ("all(test, true)", True),
        ("not(false)", True),
        ("all(test, not(any()))", True),
        ('all(test, target_os = "none")', None),
        ('all(test, feature = "a")', None),
        ('any(test, feature = "a")', True),
        ("unix", None),
    ):
        assert value(node(predicate), True) is expected, predicate
    # In a build that is not known to be a test build, `not(test)` decides nothing.
    assert value(node("not(test)"), None) is None
    assert value(node("all(test, any())"), None) is False
    # With the features of a command.
    assert value(node('not(feature = "std")'), True, {"std"}) is False
    assert value(node('not(feature = "std")'), True, set()) is True
    assert value(node('all(test, feature = "a", not(feature = "b"))'), True, {"a"}) is True
    assert value(node('any(feature = "a", feature = "b")'), True, set(), frozenset({"a", "b"})) is None
    never = CHECKER["cfg_never"]
    assert never("#[cfg(any())]") == "any()" and never("#[cfg(any())]", True) == "any()"
    assert never("#[cfg(not(test))]") is None and never("#[cfg(not(test))]", True) == "not(test)"
    assert never("#[cfg( all( test,\n any( ) ) )]") == "all( test, any( ) )"
    assert never('#[cfg(all(test, feature = "x"))]\n#[cfg(test)]', True) is None
    assert never("#[cfg_attr(test, cfg(any()))]", True) == "any(not(test), any())"
    assert never("#[cfg_attr(test, cfg(any()))]") is None
    assert never("#[cfg(false)]") == "false" and never("#[cfg(false)]", True) == "false"
    assert never("#[cfg(all(test, false))]") == "all(test, false)"
    assert never("#[cfg(all(test, not(true)))]") == "all(test, not(true))"
    assert never("#[cfg( all( test,\n not( true ) ) )]", True) == "all( test, not( true ) )"
    assert never("#![cfg(false)]") == "false"
    assert never("#[cfg_attr(test, cfg(false))]", True) == "any(not(test), false)"
    assert never("#[cfg_attr(test, cfg(false))]") is None
    assert never("#[cfg(true)]", True) is None and never("#[cfg(all(test, true))]", True) is None
    assert never("#[cfg(any(test, false))]", True) is None
    # The words in another place are no gate: a feature of that name, a value of the code.
    assert never('#[cfg(feature = "false")]', True) is None
    assert never("#[derive(Debug)]\nconst ON: bool = false;", True) is None
    constant = CHECKER["CFG_CONSTANT"]
    assert constant.search("#[cfg(false)]") and constant.search("#[cfg_attr(test, cfg(not(true)))]")
    assert constant.search("let on = false; if cfg!(test) { true } else { on }") is None
    # A `cfg` that `cfg_attr` applies is a gate where its condition holds.
    predicates = CHECKER["cfg_predicates"]
    assert predicates('#[cfg(test)]\n#[cfg_attr(test, cfg(feature = "x"))]\n#![cfg(unix)]') == [
        "test",
        'any(not(test), feature = "x")',
        "unix",
    ]
    assert predicates('#[cfg_attr(test, allow(dead_code), cfg(feature = "x"), cfg(feature = "y"))]') == [
        'any(not(test), feature = "x")',
        'any(not(test), feature = "y")',
    ]
    assert predicates('#[cfg_attr(feature = "a", cfg_attr(test, cfg(feature = "x")))]') == [
        'any(not(feature = "a"), any(not(test), feature = "x"))'
    ]
    assert predicates("#[cfg_attr(test, allow(dead_code))]\n#[derive(Debug)]") == []
    requirement = CHECKER["_cfg_requirement"]
    assert requirement('any(not(test), feature = "x")') == {"x"}
    assert requirement('any(any(), feature = "x", feature = "y")') == {"x|y"}
    assert requirement('any(test, feature = "x")') == set()
    assert [requirement(gate) for gate in predicates('#[cfg_attr(test, cfg(feature = "x"))]')] == [{"x"}]

    lib = (
        "#[cfg(all(test, any()))]\nmod never_all {\n    #[test]\n    fn never_all_test() {}\n}\n"
        "#[cfg(not(test))]\nmod not_test {\n    #[test]\n    fn not_test_test() {}\n}\n"
        "#[cfg(test)]\nmod tests {\n    #[test]\n    #[cfg(not(test))]\n    fn own_gate_test() {}\n"
        "    #[test]\n    fn plain_test() {}\n}\n"
        "#[cfg(all(test, not(feature = \"std\")))]\nmod without_default {\n    #[test]\n    fn without_default_test() {}\n}\n"
        "#[cfg(all(test, not(feature = \"slow\")))]\nmod without_optional {\n    #[test]\n    fn without_optional_test() {}\n}\n"
        "#[cfg(all(test, feature = \"heavy\", not(feature = \"slow\")))]\nmod contradiction {\n"
        "    #[test]\n    fn contradiction_test() {}\n}\n"
        "#[cfg(all(test, target_os = \"none\"))]\nmod other_target {\n    #[test]\n    fn other_target_test() {}\n}\n"
        "#[cfg(test)]\n#[cfg_attr(test, cfg(feature = \"slow\"))]\nmod through_attr {\n"
        "    #[test]\n    fn through_attr_test() {}\n}\n"
        "#[cfg(false)]\nmod false_gate {\n    #[test]\n    fn false_gate_test() {}\n}\n"
        "#[cfg(all(test, false))]\nmod false_part {\n    #[test]\n    fn false_part_test() {}\n}\n"
        "#[cfg(all(test, not(true)))]\nmod not_true {\n    #[test]\n    fn not_true_test() {}\n}\n"
        "#[cfg(all(test, true))]\nmod true_gate {\n    #[test]\n    fn true_gate_test() {}\n}\n"
        "#[cfg(test)]\nmod more_tests {\n    #[test]\n    #[cfg(false)]\n    fn own_false_test() {}\n}\n"
        "#[cfg(test)]\n#[cfg_attr(test, cfg(false))]\nmod false_through_attr {\n"
        "    #[test]\n    fn false_through_attr_test() {}\n}\n"
        "#[cfg(not(test))]\nmod production;\n"
        "#[cfg(all(test, any()))]\nmod dead;\n"
        "#[cfg(false)]\nmod off;\n"
        "mod open;\n"
        "#[cfg(not(test))]\ninclude!(\"included.rs\");\n"
    )
    _demo_crate(
        tmp_path,
        {
            "lib.rs": lib,
            "production.rs": "pub const MAX_IN_PRODUCTION: usize = 1;\n#[test]\nfn production_file_test() {}\n",
            "dead.rs": "#[test]\nfn dead_file_test() {}\n",
            "off.rs": "#[test]\nfn off_file_test() {}\n",
            "open.rs": "#[test]\nfn open_file_test() {}\n",
            "included.rs": "#[test]\nfn included_file_test() {}\n",
        },
        'default = ["std"]\nstd = []\nslow = []\nheavy = ["slow"]\n',
    )
    path = "crates/demo/src/lib.rs"
    problem = CHECKER["test_problem"]
    assert problem(lib, path, "never_all_test") == "is inside a block compiled out by `#[cfg(all(test, any()))]` in"
    assert problem(lib, path, "not_test_test") == "is inside a block compiled out by `#[cfg(not(test))]` in"
    assert problem(lib, path, "own_gate_test") == "is compiled out by `#[cfg(not(test))]` in"
    assert problem(lib, path, "plain_test") is None
    assert problem(lib, path, "false_gate_test") == "is inside a block compiled out by `#[cfg(false)]` in"
    assert problem(lib, path, "false_part_test") == (
        "is inside a block compiled out by `#[cfg(all(test, false))]` in"
    )
    assert problem(lib, path, "not_true_test") == (
        "is inside a block compiled out by `#[cfg(all(test, not(true)))]` in"
    )
    assert problem(lib, path, "own_false_test") == "is compiled out by `#[cfg(false)]` in"
    assert problem(lib, path, "false_through_attr_test") == (
        "is inside a block compiled out by `#[cfg(any(not(test), false))]` in"
    )
    assert problem(lib, path, "true_gate_test") is None

    def features(name: str, file: str = path) -> list:
        return CHECKER["test_features"](tmp_path, {"path": file, "name": name}, "test")

    assert features("plain_test") == []
    # `std` is a default feature: the command that runs the tests turns it on.
    with pytest.raises(
        CHECKER["ContractError"],
        match=r"without_default_test` in crates/demo/src/lib.rs is behind "
        r"`#\[cfg\(all\(test, not\(feature = \"std\"\)\)\)\]`, which is false with the default features "
        r"and \[\]: it never runs",
    ):
        features("without_default_test")
    # `slow` is off unless a recorded feature turns it on.
    assert features("without_optional_test") == []
    with pytest.raises(CHECKER["ContractError"], match=r"which is false with the default features and \['heavy'\]"):
        features("contradiction_test")
    # A predicate this checker does not judge leaves the test as compiled.
    assert features("other_target_test") == []
    assert features("through_attr_test") == ["slow"]
    # A file that only a non-test build declares holds no test that runs, and is production code.
    assert CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/production.rs")
    assert CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/dead.rs")
    assert CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/off.rs")
    assert not CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/open.rs")
    for file, name in (("production.rs", "production_file_test"), ("included.rs", "included_file_test")):
        with pytest.raises(
            CHECKER["ContractError"],
            match="which no declaration that a test build compiles joins to a target of its crate",
        ):
            features(name, f"crates/demo/src/{file}")
    # An `include!` behind `not(test)` is a reference, so the file is part of the crate;
    # no test build compiles it, and the record of its test says so.
    assert not CHECKER["unreachable_test_file"](tmp_path, "crates/demo/src/included.rs")
    found = []
    CHECKER["_check_sites"](
        tmp_path, {"tests": [{"path": "crates/demo/src/included.rs", "name": "included_file_test"}]}, "demo", found
    )
    assert len(found) == 1 and "no declaration that a test build compiles" in found[0], found
    assert CHECKER["compiled_outside_tests"](tmp_path, "crates/demo/src/production.rs")
    assert not CHECKER["compiled_only_in_tests"](tmp_path, "crates/demo/src/production.rs")
    # Each form is reported through the contract record.
    for name, fragment in (
        ("never_all_test", "is inside a block compiled out by `#[cfg(all(test, any()))]`"),
        ("not_test_test", "is inside a block compiled out by `#[cfg(not(test))]`"),
        ("own_gate_test", "is compiled out by `#[cfg(not(test))]`"),
        ("false_gate_test", "is inside a block compiled out by `#[cfg(false)]`"),
        ("false_part_test", "is inside a block compiled out by `#[cfg(all(test, false))]`"),
        ("not_true_test", "is inside a block compiled out by `#[cfg(all(test, not(true)))]`"),
        ("own_false_test", "is compiled out by `#[cfg(false)]`"),
        ("false_through_attr_test", "is inside a block compiled out by `#[cfg(any(not(test), false))]`"),
        ("without_default_test", "it never runs"),
        ("contradiction_test", "it never runs"),
        ("through_attr_test", "is compiled with features ['slow']; the contract records none"),
    ):
        found: list = []
        CHECKER["_check_sites"](tmp_path, {"tests": [{"path": path, "name": name}]}, "demo", found)
        assert len(found) == 1 and fragment in found[0], (name, found)
    for name in ("plain_test", "without_optional_test", "other_target_test", "true_gate_test"):
        found = []
        CHECKER["_check_sites"](tmp_path, {"tests": [{"path": path, "name": name}]}, "demo", found)
        assert found == [], (name, found)
    found = []
    CHECKER["_check_sites"](
        tmp_path, {"tests": [{"path": "crates/demo/src/production.rs", "name": "production_file_test"}]}, "demo", found
    )
    assert len(found) == 1 and "which no `mod`, `include!`, `#[path]` or test target of its crate reaches" in found[0]


def test_a_gate_that_never_holds_on_a_tracked_boundary_test_is_reported() -> None:
    """The gates the second review put on the module of a tracked boundary test."""
    path = "crates/iroha_data_model/src/sumeragi_finality.rs"
    source = CHECKER["_read"](ROOT, path, "test")
    plain = "#[cfg(test)]\nmod block_bound_tests {"
    assert source.count(plain) == 1
    test = {
        "path": path,
        "name": "finality_proof_block_of_exactly_the_bound_is_read_and_one_byte_more_is_refused",
    }
    assert CHECKER["test_features"](ROOT, test, "test") == []
    # `application-model` is a default feature of the data model; `std` is no feature of it.
    for gate, fragment in (
        ("#[cfg(all(test, any()))]", "is inside a block compiled out by `#[cfg(all(test, any()))]`"),
        ("#[cfg(not(test))]", "is inside a block compiled out by `#[cfg(not(test))]`"),
        # A boolean literal (stable since Rust 1.88): the plain way to write a gate that never holds.
        ("#[cfg(false)]", "is inside a block compiled out by `#[cfg(false)]`"),
        ("#[cfg(all(test, false))]", "is inside a block compiled out by `#[cfg(all(test, false))]`"),
        (
            "#[cfg(all(test, not(true)))]",
            "is inside a block compiled out by `#[cfg(all(test, not(true)))]`",
        ),
        (
            "#[cfg(test)]\n#[cfg_attr(test, cfg(false))]",
            "is inside a block compiled out by `#[cfg(any(not(test), false))]`",
        ),
        (
            '#[cfg(test)]\n#[cfg_attr(test, cfg(feature = "transparent_api"))]',
            "is compiled with features ['transparent_api']; the contract records none",
        ),
        (
            '#[cfg(all(test, not(feature = "application-model")))]',
            "which is false with the default features and []: it never runs",
        ),
        (
            '#[cfg(all(test, feature = "transparent_api", not(feature = "application-model")))]',
            "which is false with the default features and ['transparent_api']: it never runs",
        ),
    ):
        CHECKER["_OVERRIDES"][path] = source.replace(plain, gate + "\nmod block_bound_tests {")
        try:
            found: list = []
            CHECKER["_check_sites"](ROOT, {"tests": [dict(test)]}, "bound", found)
        finally:
            del CHECKER["_OVERRIDES"][path]
        assert len(found) == 1 and fragment in found[0], (gate, found)
    # Not judged, as the documentation says: another target, and a feature the crate lacks
    # under `not` (always off, so the test is compiled).
    # `true` holds everywhere, so a gate with it changes nothing.
    for gate in (
        '#[cfg(all(test, target_os = "none"))]',
        '#[cfg(all(test, not(feature = "std")))]',
        "#[cfg(all(test, true))]",
        "#[cfg(any(test, false))]",
    ):
        CHECKER["_OVERRIDES"][path] = source.replace(plain, gate + "\nmod block_bound_tests {")
        try:
            found = []
            CHECKER["_check_sites"](ROOT, {"tests": [dict(test)]}, "bound", found)
        finally:
            del CHECKER["_OVERRIDES"][path]
        assert found == [], (gate, found)
    # The same literal on the test itself.
    own = "    #[test]\n    fn " + test["name"] + "("
    assert source.count(own) == 1
    CHECKER["_OVERRIDES"][path] = source.replace(own, own.replace("#[test]\n", "#[test]\n    #[cfg(false)]\n"))
    try:
        found = []
        CHECKER["_check_sites"](ROOT, {"tests": [dict(test)]}, "bound", found)
    finally:
        del CHECKER["_OVERRIDES"][path]
    assert len(found) == 1 and "is compiled out by `#[cfg(false)]`" in found[0], found
    assert CHECKER["test_features"](ROOT, test, "test") == []
    assert CHECKER["_OVERRIDES"] == {}


_RECEIVER_SOURCE = (
    "const ROWS: usize = 9;\nconst UNIT: usize = 3;\nconst SCALE: u64 = 5;\nconst WIDTH: usize = 7;\n"
    "const FACTOR: usize = 2;\nconst CUT: usize = 4;\nconst HEAD: usize = 6;\nconst FLOOR: usize = 8;\n"
    "const OFFSET: usize = 10;\nconst LOW: usize = 12;\nconst HIGH: usize = 13;\nconst PEAK: usize = 14;\n"
    "const BASE: usize = 15;\nconst TOP: usize = 16;\nconst EDGE: usize = 17;\nconst BAR: usize = 18;\n"
    "const SKIPPED: usize = 19;\nconst ARM: usize = 20;\n"
    "impl Table {\n    const SLOTS: usize = 11;\n"
    "    fn names(&self, n: usize, k: usize, cap: usize, wide: u64) -> usize {\n"
    "        let a = ROWS.min(n);\n"
    "        let b = (UNIT * k).max(n);\n"
    "        let c = u64::from(SCALE).min(wide);\n"
    "        let d = n.saturating_mul(WIDTH).min(cap);\n"
    "        let e = Self::SLOTS.clamp(1, n);\n"
    "        let f = FACTOR\n            .saturating_mul(k)\n            .saturating_add(1)\n            .min(n);\n"
    "        let g = (n..cap).contains(&HEAD);\n"
    "        let h = [FLOOR, n].into_iter().max();\n"
    "        let i = (0..CUT).take(n).count() + buffer(SKIPPED).truncate(n);\n"
    "        let j = OFFSET + n.min(cap);\n"
    "        let l = n.lt(&LOW) || HIGH.ge(&n);\n"
    "        let m = core::cmp::Ord::max(n, PEAK) + Ord::clamp(n, BASE, TOP);\n"
    "        let o = <usize as Ord>::max(n, EDGE) > 0 && PartialOrd::lt(&n, &BAR);\n"
    "        let p = match k {\n            ARM => 4096,\n            _ => 8192,\n        }\n        .min(cap);\n"
    "        a\n    }\n"
    "    fn literals(&self, n: usize, k: usize, cap: usize, wide: u64, delta: u64, current: u64) -> usize {\n"
    "        let a = delta\n            .saturating_mul(10_000)\n            .saturating_div(current)\n            .min(u64::from(u16::MAX));\n"
    "        let b = self\n            .rows\n            .capacity()\n            .checked_mul(2)\n            .unwrap_or(self.maximum)\n"
    "            .max(1)\n            .min(self.maximum);\n"
    "        let c = block_time\n            .saturating_mul(3)\n            .clamp(low, high);\n"
    "        let d = n\n            .saturating_mul(12)\n            .saturating_add(k)\n            .clamp(low, high);\n"
    "        let e = items.iter().skip(40).take(n).count();\n"
    "        let f = 41 + n.min(cap);\n"
    "        let g = \"a b\".len().min(4) + '{'.len_utf8().max(cap);\n"
    "        let h = [n, 64].into_iter().max();\n"
    "        let i = n.lt(&4096) || 42.ge(&n) || n.le(&1);\n"
    "        let j = core::cmp::Ord::max(n, 4097) + u32::clamp(k, 2, 4098) as usize;\n"
    "        let l = <u64 as Ord>::max(wide, 77) > 0 && PartialOrd::lt(&n, &512);\n"
    "        let m = Duration::max(wait, Duration::from_secs(43));\n"
    "        let o = retry_after.as_millis().saturating_add(999) / 1_000;\n"
    "        a as usize\n    }\n}\n"
    "fn clamp(value: usize, low: usize, high: usize) -> usize {\n    value.max(low + 44)\n}\n"
    "fn lt(a: usize) -> bool {\n    a > 45\n}\n"
)


def test_the_receiver_of_a_cap_is_read_whole() -> None:
    """`a.min(b)` compares `a` too: the whole method chain in front of the call, on any number of lines."""
    source = _RECEIVER_SOURCE
    scan = CHECKER["comparison_scan"](source)
    # A constant is compared as the receiver of `.min`, `.max` or `.clamp`: alone, inside a
    # receiver expression, converted, behind `Self::`, at the head of a chain broken across
    # lines, and as the receiver of `.max()` over a list. So is the value a range tests,
    # either side of a comparison method, and an argument of a function behind any path.
    # `MAX` is the `u16::MAX` of a cap; it names no item of the file.
    assert scan["uses"] == {
        "ROWS", "UNIT", "SCALE", "WIDTH", "SLOTS", "FACTOR", "HEAD", "FLOOR",
        "LOW", "HIGH", "PEAK", "BASE", "TOP", "EDGE", "BAR", "MAX",
    }  # fmt: skip
    # Not compared: the collection `.take` and `.truncate` cut, arithmetic in front of the
    # head of a receiver, and what a block yields (all three are declared residuals).
    assert not {"CUT", "SKIPPED", "OFFSET", "ARM"} & scan["uses"]
    assert set(scan["integers"]) - scan["uses"] == {"CUT", "SKIPPED", "OFFSET", "ARM"}
    sites = CHECKER["literal_sites"](source, 2)
    assert {text: [value for _, _, value in spans] for text, spans in sites.items()} == {
        # A literal in a chain element above the capping call: the text is the whole chain.
        "delta .saturating_mul(10_000) .saturating_div(current) .min(u64::from(u16::MAX))": [10_000],
        # The inner cap holds the literal; the outer one adds no second site for it.
        "self .rows .capacity() .checked_mul(2) .unwrap_or(self.maximum) .max(1)": [2],
        # The receiver of `.clamp` is compared with both ends: in the last element and above it.
        ".saturating_mul(3) .clamp(low, high)": [3],
        "n .saturating_mul(12) .saturating_add(k) .clamp(low, high)": [12],
        # A head the mask blanked (a string literal) ends the chain where it stood.
        ".len().min(4)": [4],
        # `.max()` over a list compares its elements.
        "[n, 64].into_iter().max()": [64],
        # A comparison written as a method, and one with a literal receiver.
        "n.lt(&4096)": [4096],
        "42.ge(&n)": [42],
        # The function forms behind any path.
        "core::cmp::Ord::max(n, 4097)": [4097],
        "u32::clamp(k, 2, 4098)": [2, 4098],
        "<u64 as Ord>::max(wide, 77)": [77],
        "PartialOrd::lt(&n, &512)": [512],
        "Duration::max(wait, Duration::from_secs(43))": [43],
        # A function named like a cap is no call where it is defined; its body is read.
        "value.max(low + 44)": [44],
        "a > 45": [45],
    }
    # No site: a skipped prefix of what `.take` cuts, an addend in front of a receiver, a
    # quotient nothing compares, a comparison with 1 and the arms of a block.
    values = {value for spans in sites.values() for _, _, value in spans}
    assert not {40, 41, 999, 1_000, 8192} & values
    assert [text for text, spans in sites.items() if any(value == 4096 for _, _, value in spans)] == [
        "n.lt(&4096)"
    ]
    occurrences = CHECKER["literal_occurrences"](source, 2)
    assert set(occurrences) == set(sites) and set(occurrences.values()) == {1}
    for text, spans in sites.items():
        for start, end, value in spans:
            assert CHECKER["literal_value"](source[start:end]) == value, text

    # The walk itself, on masks written out.
    start = CHECKER["_receiver_start"]

    def receiver(mask: str, call: str = ".min(") -> str:
        end = mask.rindex(call)
        return mask[start(mask, end) : end]

    assert receiver("let a = ROWS.min(n);") == "ROWS"
    assert receiver("let a = base + (ROWS * k).min(n);") == "(ROWS * k)"
    assert receiver("let a = x\n    .saturating_mul(3)\n    .saturating_add(1)\n    .min(n);") == (
        "x\n    .saturating_mul(3)\n    .saturating_add(1)\n    "
    )
    assert receiver("foo(a, b.len()\n        .min(c))") == "b.len()\n        "
    assert receiver("let v = u64::try_from(\n    a + ROWS,\n)\n.unwrap_or(1)\n.min(2);") == (
        "u64::try_from(\n    a + ROWS,\n)\n.unwrap_or(1)\n"
    )
    assert receiver("call(value?\n    .rows()?\n    .min(4))") == "value?\n    .rows()?\n    "
    # Arithmetic, a cast, a keyword and a closure head in front of the head are no part of it.
    assert receiver("let a = 40 + n.min(cap);") == "n"
    assert receiver("return n.min(cap);") == "n"
    assert receiver("items.iter().map(|v| v.len().min(cap))") == "v.len()"
    # A blanked string or character literal as the head: the chain ends at its first method.
    assert receiver("let a =      .len().min(4);") == ".len()"
    assert receiver("let a = b\n    +        .len()\n    .min(4);") == ".len()\n    "
    # A block as the head is not followed, and nothing in front of a separator is.
    assert receiver("let a = match k {\n    _ => 8192,\n}\n.min(cap);") == ""
    assert receiver("(a, .min(c))") == ""
    # Twenty elements, one a line: no bound on the length of a chain.
    long_chain = "head" + "".join(f"\n    .step({index})" for index in range(20)) + "\n    .min(cap)"
    assert receiver(long_chain) == long_chain[: long_chain.rindex(".min(")]
    run = CHECKER["_run_start"]
    assert run("a + b.c(d, e)  ", 15) == (4, 13) and run("x, ", 3) == (2, 2)


def test_a_site_of_a_bound_owns_only_the_comparison_it_holds_whole(tmp_path: Path) -> None:
    """A shorter comparison that is a part of the text of an enforcement site is not owned by it."""
    held = CHECKER["_held_whole"]
    site = "if frame.len() > MAX.saturating_add(128) || o.len() > 1280 {"
    assert held(site, "frame.len() > MAX.saturating_add(128)") == 1
    # A longer name, a longer number and a method chain that runs on are other comparisons.
    assert held(site, "e.len() > MAX.saturating_add(128)") == 0
    assert held(site, "o.len() > 128") == 0
    assert held(site, "len() > 1280") == 0
    assert held(site, "o.len() > 1280") == 1
    assert held("a.min(64) + b.min(64)", ".min(64)") == 2
    assert held("x > 12", "x > 12") == 1 and held("x > 12", "y > 12") == 0
    _demo_crate(
        tmp_path,
        {
            "lib.rs": (
                "pub const MAX_NAMED: usize = 7;\n"
                "pub fn check(frame: &[u8], o: &[u8]) -> bool {\n"
                "    frame.len() > MAX_NAMED.saturating_add(1280)\n}\n"
                "pub fn other(len: usize) -> bool {\n    len > MAX_NAMED.saturating_add(128)\n}\n"
            ),
        },
    )
    lib = "crates/demo/src/lib.rs"
    contract = {
        "bounds": [
            {
                "id": "queue.named",
                "owner": {"path": lib, "symbol": "MAX_NAMED", "kind": "const"},
                "enforcement": [
                    {"stage": "queue", "path": lib, "contains": "frame.len() > MAX_NAMED.saturating_add(1280)"}
                ],
            }
        ],
        "completeness": {
            "scopes": [{"tree": "crates/demo/src", "kind": "const", "comparisons": True}],
            "excluded": [],
            "literals": {"why": "0 and 1 test presence", "minimum": 2, "groups": []},
        },
    }
    found: list = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    # The site owns its own comparison. `len > MAX_NAMED.saturating_add(128)` is a part of
    # the site's text as a string and is another comparison: it needs its own record.
    assert found == [
        f"completeness literals in {lib}: the literal comparison `len > MAX_NAMED.saturating_add(128)` "
        "(1 time(s)) is neither a site of a listed bound nor recorded with a reason"
    ]


_RECEIVER_CONSTANTS = (
    ("crates/iroha_core/src/smartcontracts/isi/tx.rs", "TRANSACTION_HISTORY_BYTES_PER_WORK_UNIT"),
    ("crates/iroha_core/src/compliance/mod.rs", "LANE_COMPLIANCE_POLICY_DECODE_ALLOCATION_MULTIPLIER"),
    ("crates/iroha_core/src/compliance/mod.rs", "LANE_COMPLIANCE_POLICY_DECODE_FIXED_ALLOCATION_BYTES"),
    ("crates/iroha_data_model/src/sorafs/final_promotion_authority.rs", "FINAL_PROMOTION_RESERVATION_MS_V1"),
    ("crates/iroha_core/src/query/stream_token_authority.rs", "STREAM_TOKEN_NATIVE_RESERVATION_MS_V1"),
    ("crates/iroha_data_model/src/sorafs/topology_authority.rs", "TOPOLOGY_RESERVATION_MS_V1"),
    ("crates/iroha_core/src/kura.rs", "SIZE_OF_BLOCK_HASH"),
    ("crates/iroha_core/src/state/telemetry_status.rs", "STATUS_CLASSIFICATION_BLOCKS"),
    (
        "crates/iroha_core_zk/src/kagemusha_v1_recursion/artifact_resource_preflight.rs",
        "PASTA_PROCESSED_SCALAR_BYTES",
    ),
    ("crates/iroha_core_zk/src/pasta_sha256.rs", "SHA256_ROWS_PER_BLOCK_V1"),
    ("crates/iroha_core_zk/src/pasta_sha256.rs", "SHA256_ROWS_PER_JOB_V1"),
    ("crates/iroha_core_zk/src/pasta_sha256.rs", "SHA256_ROWS_PER_EXTRA_SNAPSHOT_V1"),
    ("crates/iroha_torii/src/zk_prover.rs", "ATTACHMENT_DISCOVERY_BYTES_PER_LOCATION"),
    ("crates/iroha_torii/src/zk_prover.rs", "ATTACHMENT_DISCOVERY_WORK_PER_LOCATION"),
    ("crates/iroha_torii/src/sorafs/api/stream_token_body.rs", "RESPONSE_CHUNK_BYTES"),
    ("crates/iroha_torii/src/sorafs/gateway/feed_transport.rs", "READ_BUFFER_BYTES"),
    ("crates/iroha_torii/src/torii_fanout_decode_helpers.rs", "QUERY_INGRESS_PHASE_UNITS"),
    ("crates/iroha_torii/src/limits.rs", "MIN_BUCKETS_PER_SHARD"),
    ("crates/iroha_torii/src/lib_pipeline_handlers.rs", "TRIGGER_COMPLETION_DEFAULT_SCAN_BLOCKS"),
    ("crates/iroha_torii/src/routing.rs", "DEFAULT_TRADER_CANDLE_BUCKET_MS"),
    ("crates/iroha_torii/src/da/ingest.rs", "BYTES_PER_GIB"),
    ("crates/iroha_torii/src/da/ingest.rs", "SECS_PER_MONTH"),
)
_RECEIVER_LITERALS = (
    (
        "crates/iroha_data_model/src/compute/mod.rs",
        "delta .saturating_mul(10_000) .saturating_div(current) .min(u64::from(u16::MAX))",
        ".saturating_mul(10_000)\n        .saturating_div(current)",
        ".saturating_mul(10_001)\n        .saturating_div(current)",
    ),
    (
        "crates/iroha_torii/src/sorafs/api.rs",
        "u64::try_from(retry_after.as_millis().saturating_add(999) / 1_000) .unwrap_or(u64::MAX) .max(1)",
        "retry_after.as_millis().saturating_add(999) / 1_000",
        "retry_after.as_millis().saturating_add(999) / 1_001",
    ),
    (
        "crates/iroha_core/src/state/authority_registry/leaf/paired/staging.rs",
        "self .rows .capacity() .checked_mul(2) .unwrap_or(self.maximum) .max(1)",
        ".checked_mul(2)",
        ".checked_mul(3)",
    ),
    (
        "crates/iroha_core/src/queue.rs",
        ".saturating_mul(3) .clamp( QUEUE_PRESSURE_MIN_AGE_BUDGET_MS, QUEUE_PRESSURE_MAX_AGE_BUDGET_MS, )",
        ".saturating_mul(3)\n            .clamp(",
        ".saturating_mul(4)\n            .clamp(",
    ),
    (
        "crates/iroha_torii/src/sorafs/blinded.rs",
        ".saturating_mul(16) .clamp(MIN_RESOLVER_BLOOM_BITS_V1, MAX_RESOLVER_BLOOM_BITS_V1)",
        ".saturating_mul(16)\n            .clamp(MIN_RESOLVER_BLOOM_BITS_V1",
        ".saturating_mul(17)\n            .clamp(MIN_RESOLVER_BLOOM_BITS_V1",
    ),
    (
        "crates/iroha_torii/src/routing.rs",
        "(finite_top_sum(top_sums[2]) / total_f64).clamp(0.0, 1.0)",
        "(finite_top_sum(top_sums[2]) / total_f64).clamp(0.0, 1.0)",
        "(finite_top_sum(top_sums[3]) / total_f64).clamp(0.0, 1.0)",
    ),
)


def test_changing_a_compared_receiver_in_memory_fails_the_checker() -> None:
    """The changes the third review left unnoticed: a constant or a literal in the receiver of a cap."""
    section = CONTRACT["completeness"]
    pinned = {
        (holder["path"], symbol): (holder["exprs"][symbol], holder.get("term_of", {}).get(symbol))
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        if not holder.get("module")
        for symbol in holder["symbols"]
    }
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    compared = CHECKER["compared_symbols"](ROOT, scopes)
    terms = CHECKER["limit_terms"](ROOT, scopes)
    for path, symbol in _RECEIVER_CONSTANTS:
        # Each is found by its use and classified as a limit of its own, not as a term.
        assert symbol in compared[path], (path, symbol)
        assert symbol not in terms.get(path, {}), (path, symbol)
        assert (path, symbol) in pinned and pinned[(path, symbol)][1] is None, (path, symbol)
        source = CHECKER["_read"](ROOT, path, "test")
        definition = re.compile(rf"(\bconst {symbol}: [a-z0-9]+ = )([^;]+);")
        assert len(definition.findall(source)) == 1, (path, symbol)
        found = _with_override(path, definition.sub(r"\g<1>7_777;", source))
        fragment = f"the excluded limit `{symbol}` is now `7_777`; the contract records `{pinned[(path, symbol)][0]}`"
        assert any(fragment in item for item in found), (path, symbol, found)
    recorded = _recorded_literal_sites()
    for path, text, old, new in _RECEIVER_LITERALS:
        assert recorded[(path, text)] == 1, (path, text)
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(old) == 1, (path, old)
        found = _with_override(path, source.replace(old, new))
        assert any(f"`{text}` matches no literal comparison" in item for item in found), (path, found)
        assert any("is neither a site of a listed bound nor recorded" in item for item in found), (path, found)
    # New code of each form, in each of the four crates.
    for path in (
        "crates/iroha_data_model/src/consensus.rs",
        "crates/iroha_torii/src/limits.rs",
        "crates/iroha_core/src/queue.rs",
        "crates/iroha_core_zk/src/stark.rs",
    ):
        source = CHECKER["_read"](ROOT, path, "test")
        added = (
            "\nconst SHADOW_A: usize = 3;\nconst SHADOW_B: usize = 3;\nconst SHADOW_C: u64 = 3;\n"
            "const SHADOW_D: usize = 3;\nconst SHADOW_E: usize = 3;\nconst SHADOW_F: usize = 3;\n"
            "const SHADOW_G: usize = 3;\nconst SHADOW_H: usize = 3;\nconst SHADOW_I: usize = 3;\n"
            "const SHADOW_J: usize = 3;\nconst SHADOW_K: usize = 3;\n"
            "struct ShadowTable;\nimpl ShadowTable {\n    const SHADOW_SLOTS: usize = 3;\n"
            "    fn shadow_names(n: usize, k: usize, cap: usize, wide: u64) -> usize {\n"
            "        let a = SHADOW_A.min(n);\n"
            "        let b = (SHADOW_B * k).max(n);\n"
            "        let c = u64::from(SHADOW_C).min(wide);\n"
            "        let d = n.saturating_mul(SHADOW_D).min(cap);\n"
            "        let e = Self::SHADOW_SLOTS.clamp(1, n);\n"
            "        let f = SHADOW_E\n            .saturating_mul(k)\n            .saturating_add(1)\n            .min(n);\n"
            "        let g = (n..cap).contains(&SHADOW_F);\n"
            "        let h = n.lt(&SHADOW_G) || SHADOW_H.ge(&n);\n"
            "        let i = core::cmp::Ord::max(n, SHADOW_I) + usize::clamp(n, SHADOW_J, cap);\n"
            "        let j = PartialOrd::le(&n, &SHADOW_K);\n"
            "        a\n    }\n"
            "    fn shadow_literals(n: usize, k: usize, cap: usize, wide: u64) -> usize {\n"
            "        let a = wide\n            .saturating_mul(40_961)\n            .saturating_div(3)\n            .min(u64::MAX);\n"
            "        let b = n\n            .saturating_mul(40_963)\n            .saturating_add(k)\n            .clamp(k, cap);\n"
            "        let c = n.lt(&40_965) || k.ge(&cap.saturating_mul(40_967));\n"
            "        let d = core::cmp::Ord::max(n, 40_969) + usize::clamp(n, 2, 40_971);\n"
            "        let e = <u64 as Ord>::min(wide, 40_973) > 0 && PartialOrd::gt(&n, &40_975);\n"
            "        let f = [n, 40_977].into_iter().max();\n"
            "        a as usize\n    }\n}\n"
        )
        found = _with_override(path, source + added)
        for symbol in (
            "SHADOW_A", "SHADOW_B", "SHADOW_C", "SHADOW_D", "SHADOW_SLOTS", "SHADOW_E", "SHADOW_F",
            "SHADOW_G", "SHADOW_H", "SHADOW_I", "SHADOW_J", "SHADOW_K",
        ):  # fmt: skip
            fragment = f"completeness {path}: `{symbol}` is neither a listed bound nor excluded"
            assert any(fragment in item for item in found), (path, symbol, found)
        for text in (
            "wide .saturating_mul(40_961) .saturating_div(3) .min(u64::MAX)",
            "n .saturating_mul(40_963) .saturating_add(k) .clamp(k, cap)",
            "n.lt(&40_965)",
            "k.ge(&cap.saturating_mul(40_967))",
            "core::cmp::Ord::max(n, 40_969)",
            "usize::clamp(n, 2, 40_971)",
            "<u64 as Ord>::min(wide, 40_973)",
            "PartialOrd::gt(&n, &40_975)",
            "[n, 40_977].into_iter().max()",
        ):
            fragment = f"completeness literals in {path}: the literal comparison `{text}`"
            assert any(fragment in item for item in found), (path, text, found)
    assert CHECKER["_OVERRIDES"] == {}


def test_every_receiver_of_a_cap_in_the_path_crates_is_read() -> None:
    """An enumeration of its own: no constant or literal in the receiver of a cap is outside the scan."""
    section = CONTRACT["completeness"]
    minimum = section["literals"]["minimum"]
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    paths = CHECKER["literal_scopes"](scopes)
    # Tokens of the code mask: a name, a number, a path or range separator, any other sign.
    token = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9][0-9A-Za-z_]*|::|\.\.=?|[^\s]")
    constant = re.compile(r"[A-Z][A-Z0-9_]*")
    compared = ("min", "max", "clamp", "lt", "le", "gt", "ge")
    scans = {path: CHECKER["comparison_scan"](CHECKER["_read"](ROOT, path, "test")) for path in paths}
    integers = {name for scan in scans.values() for name in scan["integers"]}
    calls = receivers = broken = names = literals = 0
    for path in paths:
        source = CHECKER["_read"](ROOT, path, "test")
        mask = CHECKER["production_mask"](source)
        tokens = [(match.group(0), match.start()) for match in token.finditer(mask)]
        sites = CHECKER["literal_sites"](source, minimum)
        pinned = sorted((start, end) for spans in sites.values() for start, end, _ in spans)
        uses = scans[path]["uses"]
        for index in range(2, len(tokens) - 1):
            if tokens[index][0] not in compared or tokens[index - 1][0] != "." or tokens[index + 1][0] != "(":
                continue
            calls += 1
            # The receiver, walked back token by token: names, numbers, `.`, `::`, `?` and
            # bracketed groups, across any line break. It ends at an operator, a separator
            # or a brace.
            low = index - 1
            while low > 0:
                text = tokens[low - 1][0]
                if text in (")", "]"):
                    depth = 0
                    while low > 0:
                        low -= 1
                        if tokens[low][0] in (")", "]"):
                            depth += 1
                        elif tokens[low][0] in ("(", "["):
                            depth -= 1
                            if depth == 0:
                                break
                    continue
                if text[0].isalnum() or text[0] == "_" or text in (".", "::", "?"):
                    low -= 1
                    continue
                break
            if low == index - 1:
                continue
            receivers += 1
            if "\n" in mask[tokens[low][1] : tokens[index - 1][1]]:
                broken += 1
            where = (path, source.count("\n", 0, tokens[index][1]) + 1)
            for position in range(low, index - 1):
                text, start = tokens[position]
                following = tokens[position + 1][0]
                if constant.fullmatch(text) and following not in ("::", "(", "!", "{"):
                    if text in integers:
                        names += 1
                        assert text in uses, (where, text)
                elif text[0].isdigit():
                    before = tokens[position - 1][0] if position else ""
                    if before == "." or (following == "." and tokens[position + 2][0][:1].isdigit()):
                        continue  # a tuple field or a float
                    value = CHECKER["literal_value"](text)
                    if value is None or value < minimum:
                        continue
                    literals += 1
                    assert any(first <= start < last for first, last in pinned), (where, text)
    assert calls > 1000 and receivers > 1000 and broken > 250, (calls, receivers, broken)
    assert names > 100 and literals > 40, (names, literals)
    # Every integer constant that stands in such a receiver is classified.
    listed = {
        (item["owner"]["path"], item["owner"]["symbol"])
        for item in CONTRACT["bounds"]
        if item["owner"]["kind"] in ("const", "fn")
    }
    excluded = {
        (holder["path"], symbol)
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        for symbol in holder["symbols"]
    }
    by_use = CHECKER["compared_symbols"](ROOT, scopes)
    for path, symbol in _RECEIVER_CONSTANTS:
        assert symbol in by_use[path] and (path, symbol) in excluded | listed, (path, symbol)


def _imports_demo(tmp_path: Path) -> dict:
    """A scratch workspace: one compared crate and the crates around it.

    `user` is compared. It depends on `shape` (which depends on `deep`) and, under
    another key, on the package `renamed`; `stranger` is a member nobody depends on.
    """
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = [\n    "crates/*",\n]\n', encoding="utf-8")
    crates = {
        "user": (
            '[package]\nname = "user"\nversion = "0.0.0"\n\n[dependencies]\n'
            'shape = { path = "../shape" }\n'
            'other = { package = "renamed",\n    path = "../renamed_dir" }\n\n'
            '[dev-dependencies]\nstranger = { path = "../stranger" }\n',
            {
                "lib.rs": (
                    "use shape::{FRAME_ROWS, Shape, wire::MAX_WIRE_BYTES as WIRE_CAP};\n"
                    "pub const MAX_USER_ROWS: usize = shape::BASE_ROWS * 2;\n"
                    "pub fn fits(n: usize) -> bool {\n"
                    "    n <= FRAME_ROWS\n"
                    "        && n < WIRE_CAP\n"
                    "        && n > Shape::SIZE\n"
                    "        && n < other::RENAMED_ROWS\n"
                    "        && n < DEEP_ROWS\n"
                    "        && n < HIDDEN_ROWS\n"
                    "        && n < UNRELATED_ROWS\n"
                    "        && n < TEST_ONLY_ROWS\n"
                    "        && n < u64::MAX as usize\n"
                    "}\n"
                ),
            },
        ),
        "shape": (
            '[package]\nname = "shape"\nversion = "0.0.0"\n\n[dependencies.deep]\npath = "../deep"\n',
            {
                "lib.rs": (
                    "pub mod wire;\n#[cfg(test)]\nmod checks;\n"
                    "pub const FRAME_ROWS: usize = PART * 4;\n"
                    "const PART: usize = 8;\n"
                    "pub const BASE_ROWS: usize = 10;\n"
                    "pub(crate) const HIDDEN_ROWS: usize = 3;\n"
                    "pub struct Shape;\nimpl Shape {\n    pub const SIZE: usize = 2;\n}\n"
                    "#[cfg(test)]\nmod tests {\n    pub const UNRELATED_ROWS: usize = 1;\n}\n"
                ),
                "wire.rs": "pub const MAX_WIRE_BYTES: usize = deep::DEPTH_BOUND + 1;\n",
                # Compiled only in test builds: no production constant.
                "checks.rs": "pub const TEST_ONLY_ROWS: usize = 9;\n",
                # The root of a binary target: no other crate names its items.
                "main.rs": "pub const TEST_ONLY_ROWS: usize = 9;\nfn main() {}\n",
            },
        ),
        "deep": (
            '[package]\nname = "deep"\nversion = "0.0.0"\n',
            {"lib.rs": "pub const DEPTH_BOUND: usize = 5;\npub const DEEP_ROWS: usize = 11;\n"},
        ),
        "renamed_dir": (
            '[package]\nname = "renamed"\nversion = "0.0.0"\n',
            {"lib.rs": "pub const RENAMED_ROWS: usize = 6;\n"},
        ),
        "stranger": (
            '[package]\nname = "stranger"\nversion = "0.0.0"\n',
            {"lib.rs": "pub const UNRELATED_ROWS: usize = 7;\npub const FRAME_ROWS: usize = 99;\n"},
        ),
    }
    for name, (manifest, files) in crates.items():
        crate = tmp_path / "crates" / name
        (crate / "src").mkdir(parents=True, exist_ok=True)
        (crate / "Cargo.toml").write_text(manifest, encoding="utf-8")
        for file, text in files.items():
            (crate / "src" / file).write_text(text, encoding="utf-8")
    return {
        "bounds": [],
        "completeness": {
            "scopes": [{"tree": "crates/user/src", "kind": "const", "comparisons": True}],
            "excluded": [],
            "literals": {"why": "0 and 1 test presence", "minimum": 2, "groups": []},
        },
    }


def test_a_compared_constant_of_another_crate_is_classified(tmp_path: Path) -> None:
    """A constant the compared code imports is scanned where another crate defines it."""
    assert CHECKER["plain_names"](
        "n <= FRAME_ROWS && n < shape::wire::MAX_WIRE_BYTES && n > Header::SIZE "
        "&& n < u64::MAX && n < Self::ROWS && n < <T as Shape>::LIMIT && n < crate::a::B_C"
    ) == {"FRAME_ROWS", "MAX_WIRE_BYTES", "B_C", "T"}
    assert CHECKER["manifest_dependencies"](
        '[package]\nname = "x"\n[dependencies]\na = "1"\nb = { workspace = true }\n'
        'c-d = { package = "real_c", path = "../c" }\ne = { version = "1",\n  features = ["x",\n   "y"] }\n'
        "f.workspace = true\n[target.'cfg(unix)'.dependencies]\ng = { path = \"../g\" }\n"
        '[dev-dependencies]\nh = "1"\n[dependencies.i]\npackage = "real_i"\n[build-dependencies]\nj = "1"\n'
    ) == {"a": "a", "b": "b", "c-d": "real_c", "e": "e", "f": "f", "g": "g", "i": "real_i"}
    contract = _imports_demo(tmp_path)
    section = contract["completeness"]
    shape, wire, deep, renamed = (
        f"crates/{name}/src/{file}.rs"
        for name, file in (("shape", "lib"), ("shape", "wire"), ("deep", "lib"), ("renamed_dir", "lib"))
    )
    scopes = CHECKER["expand_scopes"](tmp_path, section, [])
    assert [scope["path"] for scope in scopes] == ["crates/user/src/lib.rs"]
    # By dependency, directly or through another crate, under the package a key renames,
    # and under the name a `use` of the comparing file gives the constant (`WIRE_CAP`).
    # `BASE_ROWS` is compared nowhere: the expression of a limit of the compared crate
    # names it.
    # Not: an associated constant (`Shape::SIZE`, `u64::MAX`), a restricted item
    # (`pub(crate)`), an item of a test module or of a test-only file, the root of a
    # binary, and a member the crate does not depend on outside its tests.
    user = "crates/user/src/lib.rs"
    imported = {
        shape: ["FRAME_ROWS", "PART", "BASE_ROWS"],
        wire: ["MAX_WIRE_BYTES"],
        deep: ["DEPTH_BOUND", "DEEP_ROWS"],
        renamed: ["RENAMED_ROWS"],
    }
    assert CHECKER["imported_constants"](tmp_path, scopes) == imported
    assert CHECKER["compared_symbols"](tmp_path, scopes) == {user: [], **imported}
    # A term of an imported constant is resolved from its own source: in its file, else
    # in its crate, else in the crates that crate depends on.
    assert CHECKER["limit_terms"](tmp_path, scopes) == {
        shape: {"PART": [f"{shape}: FRAME_ROWS"], "BASE_ROWS": [f"{user}: MAX_USER_ROWS"]},
        deep: {"DEPTH_BOUND": [f"{wire}: MAX_WIRE_BYTES"]},
    }
    extended = CHECKER["import_scopes"](tmp_path, scopes)
    assert [(scope["path"], scope.get("imported")) for scope in extended[1:]] == [
        (path, True) for path in sorted(imported)
    ]
    assert CHECKER["import_scopes"](tmp_path, extended) == extended
    found: list = []
    unlisted: list = []
    CHECKER["check_completeness"](tmp_path, contract, found, False, None, unlisted)
    unclassified = [(user, "MAX_USER_ROWS")] + [
        (path, symbol) for path, symbols in imported.items() for symbol in symbols
    ]
    assert sorted(found) == sorted(
        f"completeness {path}: `{symbol}` is neither a listed bound nor excluded with a reason"
        for path, symbol in unclassified
    )
    assert sorted((scope["path"], symbol) for scope, symbol in unlisted) == sorted(unclassified)
    # Classified: one as a bound, the others excluded; --refresh pins the expressions.
    contract["bounds"] = [
        {
            "id": "queue.renamed_rows",
            "group": "queue",
            "what": "x",
            "unit": "count",
            "value": 6,
            "source": "constant",
            "class": "consensus",
            "owner": {"path": renamed, "symbol": "RENAMED_ROWS", "kind": "const", "expr": "6"},
            "enforcement": [],
        }
    ]
    section["excluded"] = [
        {
            "reason": "demo imports",
            "files": [
                {"path": user, "symbols": ["MAX_USER_ROWS"]},
                {"path": shape, "symbols": ["FRAME_ROWS", "PART", "BASE_ROWS"]},
                {"path": wire, "symbols": ["MAX_WIRE_BYTES"]},
                {"path": deep, "symbols": ["DEPTH_BOUND", "DEEP_ROWS"]},
            ],
        }
    ]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found, True, [])
    assert found == []
    holders = {holder["path"]: holder for holder in section["excluded"][0]["files"]}
    assert holders[shape]["exprs"] == {"FRAME_ROWS": "PART * 4", "PART": "8", "BASE_ROWS": "10"}
    assert holders[shape]["term_of"] == {
        "PART": [f"{shape}: FRAME_ROWS"],
        "BASE_ROWS": [f"{user}: MAX_USER_ROWS"],
    }
    assert holders[user]["exprs"] == {"MAX_USER_ROWS": "shape::BASE_ROWS * 2"}
    assert holders[wire]["exprs"] == {"MAX_WIRE_BYTES": "deep::DEPTH_BOUND + 1"}
    assert holders[deep]["term_of"] == {"DEPTH_BOUND": [f"{wire}: MAX_WIRE_BYTES"]}
    assert "term_of" not in holders[wire]
    found = []
    CHECKER["check_completeness"](tmp_path, contract, found)
    assert found == []
    # A changed value of an imported constant is a changed pinned expression.
    for path, symbol, text, changed in (
        (deep, "DEPTH_BOUND", "usize = 5;", "usize = 6;"),
        (deep, "DEEP_ROWS", "usize = 11;", "usize = 12;"),
        (shape, "PART", "usize = 8;", "usize = 9;"),
        (shape, "BASE_ROWS", "usize = 10;", "usize = 11;"),
        (wire, "MAX_WIRE_BYTES", "+ 1;", "+ 2;"),
    ):
        source = (tmp_path / path).read_text(encoding="utf-8")
        CHECKER["_OVERRIDES"][path] = source.replace(text, changed)
        try:
            found = []
            CHECKER["check_completeness"](tmp_path, contract, found)
        finally:
            del CHECKER["_OVERRIDES"][path]
        assert len(found) == 1 and f"the excluded limit `{symbol}` is now" in found[0], found
    # A listed bound of another crate reports its changed value.
    CHECKER["_OVERRIDES"][renamed] = "pub const RENAMED_ROWS: usize = 60;\n"
    try:
        found = []
        CHECKER["verify_bounds"](tmp_path, contract, found)
    finally:
        del CHECKER["_OVERRIDES"][renamed]
    assert len(found) == 1 and "queue.renamed_rows" in found[0] and "`RENAMED_ROWS`" in found[0], found
    # The sweep changes every imported constant and each change is reported.
    changed, survivors, constant_only = CHECKER["mutation_sweep"](
        tmp_path, contract, ("crates/shape/", "crates/deep/", "crates/renamed_dir/")
    )
    assert (changed, survivors, constant_only) == (7, [], []), (changed, survivors, constant_only)
    # An imported scope scans the imported constants only: a bound on another constant
    # of the file still needs a scope of its own.
    stray = copy.deepcopy(contract)
    stray["bounds"].append(
        {"id": "queue.hidden", "owner": {"path": shape, "symbol": "HIDDEN_ROWS", "kind": "const"}, "enforcement": []}
    )
    found = []
    CHECKER["check_completeness"](tmp_path, stray, found)
    assert found == [f"queue.hidden: its owner in {shape} is outside every completeness scope"]
    # A new definition in a crate the compared crate depends on is found in memory too.
    CHECKER["_OVERRIDES"][deep] = (
        "pub const DEPTH_BOUND: usize = 5;\npub const DEEP_ROWS: usize = 11;\n"
        "pub const UNRELATED_ROWS: usize = 4;\n"
    )
    try:
        found = []
        CHECKER["check_completeness"](tmp_path, contract, found)
    finally:
        del CHECKER["_OVERRIDES"][deep]
    assert found == [
        f"completeness {deep}: `UNRELATED_ROWS` is neither a listed bound nor excluded with a reason"
    ]
    # Without the dependency nothing of that crate is read.
    manifest = tmp_path / "crates" / "user" / "Cargo.toml"
    manifest.write_text('[package]\nname = "user"\nversion = "0.0.0"\n', encoding="utf-8")
    assert CHECKER["imported_constants"](tmp_path, CHECKER["expand_scopes"](tmp_path, section, [])) == {}
    assert CHECKER["_OVERRIDES"] == {}


def test_every_constant_the_path_crates_import_is_classified() -> None:
    """The enumeration starts from the names the scan reads, wherever they are defined."""
    section = CONTRACT["completeness"]
    scopes = CHECKER["expand_scopes"](ROOT, section, [])
    imported = CHECKER["imported_constants"](ROOT, scopes)
    compared = set(CHECKER["literal_scopes"](scopes))
    assert imported and not set(imported) & compared
    listed = {
        (item["owner"]["path"], item["owner"]["symbol"])
        for item in CONTRACT["bounds"]
        if item["owner"]["kind"] == "const"
    }
    excluded = {
        (holder["path"], symbol)
        for group in section["excluded"]
        for holder in (group["files"] if "files" in group else [group])
        for symbol in holder["symbols"]
    }
    count = 0
    for path, symbols in imported.items():
        for symbol in symbols:
            count += 1
            assert (path, symbol) in listed or (path, symbol) in excluded, (path, symbol)
    crates = {"/".join(path.split("/")[:2]) for path in imported}
    assert count >= 100 and len(crates) >= 15, (count, sorted(crates))
    # An independent reading: every `pub` integer constant of another crate whose name a
    # compared source writes plainly, taken from the scan's own `plain` names and found by
    # a walk of the dependency crates that uses no code of the resolver.
    workspace = CHECKER["_workspace"](ROOT)
    plain: dict = {}
    for path in compared:
        scan = CHECKER["comparison_scan"](CHECKER["_read"](ROOT, path, "test"))
        plain.setdefault("/".join(path.split("/")[:2]), set()).update(scan["plain"] - scan["items"])
    definition = re.compile(
        r"^[ \t]*pub[ \t]+(?:const|static)[ \t]+([A-Z][A-Z0-9_]*)[ \t]*:[ \t]*(?:[ui](?:8|16|32|64|128|size))\b",
        re.MULTILINE,
    )
    expected = set()
    for crate, names in plain.items():
        for member in workspace.closure(crate):
            for file in sorted((ROOT / member / "src").rglob("*.rs")):
                relative = file.relative_to(ROOT).as_posix()
                inner = relative[len(member) + len("/src/") :]
                if relative in compared or inner == "main.rs" or inner.startswith("bin/"):
                    continue
                text = file.read_text(encoding="utf-8")
                for name in set(definition.findall(text)) & names:
                    expected.add((relative, name))
    found = {(path, symbol) for path, symbols in imported.items() for symbol in symbols}
    # The walk reads raw text: a definition inside a test module or a test-only file is
    # no production constant and is the only thing it may see beyond the resolver.
    for path, symbol in expected - found:
        source = CHECKER["_read"](ROOT, path, "test")
        assert (
            symbol not in CHECKER["comparison_scan"](source)["public"]
            or CHECKER["compiled_only_in_tests"](ROOT, path)
            or (CHECKER["TEST_FILE"].search(path.split("/src/", 1)[1]) and not CHECKER["compiled_outside_tests"](ROOT, path))
        ), (path, symbol)
    assert len(expected & found) >= 90, len(expected & found)
    # The model crate's name ceiling is a listed bound; a product ceiling is an exclusion.
    assert bound(CONTRACT, "transaction.name_max_bytes")["owner"]["path"] == "crates/iroha_model_base/src/name.rs"
    assert ("crates/sorafs_manifest/src/token.rs", "STREAM_TOKEN_MAX_STREAMS_V1") in excluded


def test_changing_an_imported_constant_in_memory_fails_the_checker() -> None:
    """A constant another crate defines is pinned: its change is reported by name."""
    cases = (
        ("crates/iroha_model_base/src/name.rs", "MAX_NAME_BYTES: usize = 255;", "MAX_NAME_BYTES: usize = 256;", "transaction.name_max_bytes"),
        ("crates/sorafs_manifest/src/token.rs", "STREAM_TOKEN_MAX_STREAMS_V1: u16 = 1_024;", "STREAM_TOKEN_MAX_STREAMS_V1: u16 = 1_025;", "`STREAM_TOKEN_MAX_STREAMS_V1`"),
        ("crates/iroha_crypto/src/merkle_map/ordered_range.rs", "MAX_NORITO_TREE_ENTRIES: usize = 65_536;", "MAX_NORITO_TREE_ENTRIES: usize = 1;", "`MAX_NORITO_TREE_ENTRIES`"),
        ("crates/iroha_sccp/src/v1/constants.rs", "MAX_ROSTER_MEMBERS: usize = 31;", "MAX_ROSTER_MEMBERS: usize = 32;", "`MAX_ROSTER_MEMBERS`"),
        ("crates/iroha_torii_shared/src/da/queries.rs", "DA_QUERY_REQUEST_MAX_BYTES: usize = 64 * 1024;", "DA_QUERY_REQUEST_MAX_BYTES: usize = 65 * 1024;", "`DA_QUERY_REQUEST_MAX_BYTES`"),
        # A term of an imported constant moves its value.
        ("crates/iroha_primitives/src/numeric.rs", "MAX_MANTISSA_BITS: usize = 512;", "MAX_MANTISSA_BITS: usize = 1024;", "`MAX_MANTISSA_BITS`"),
    )
    for path, text, changed, fragment in cases:
        source = CHECKER["_read"](ROOT, path, "test")
        assert source.count(text) == 1, (path, text)
        found = _with_override(path, source.replace(text, changed))
        assert found and all(fragment in problem for problem in found), (path, found)
    # A new public constant of a dependency that the compared code already names.
    path = "crates/iroha_sccp/src/v1/constants.rs"
    source = CHECKER["_read"](ROOT, path, "test")
    found = _with_override(path, source.replace("MAX_ROSTER_MEMBERS", "MAX_ROSTER_SEATS"))
    assert any("`MAX_ROSTER_MEMBERS` in crates/iroha_sccp/src/v1/constants.rs matches no scanned limit" in problem for problem in found), found
    changed, survivors, constant_only = CHECKER["mutation_sweep"](
        ROOT,
        CONTRACT,
        ("crates/iroha_sccp/", "crates/iroha_model_base/", "crates/iroha_primitives/", "crates/sorafs_manifest/src/signer/"),
    )
    assert changed >= 18 and survivors == [] and constant_only == [], (changed, survivors, constant_only)
    assert CHECKER["_OVERRIDES"] == {}


def test_open_ram_lfe_inputs_record_what_the_candidates_project() -> None:
    """C.3's projections stand beside its open inputs; none of them is the input's value."""
    source = "specs/fhe_bgv_cost_summary.json"
    summary = json.loads((ROOT / source).read_text(encoding="utf-8"))["resource_contract_inputs"]
    assert len(summary) == 3
    owned = [item for item in CONTRACT["ram_lfe"]["open_inputs"] if item["owner"] == "C.3"]
    assert sorted(item["id"] for item in owned) == [
        "ram_lfe.ciphertext_bytes",
        "ram_lfe.evaluation_key_bytes",
        "ram_lfe.input_ciphertexts",
        "ram_lfe.multiplication_work_units",
        "ram_lfe.output_ciphertexts",
        "ram_lfe.plain_operation_work_units",
    ]
    for item in owned:
        # No profile is selected: the input stays open and its budgets carry no number.
        assert item["value"] is None
        assert item["candidates"] == {
            "source": source,
            "values": {profile: entries[item["id"]]["value"] for profile, entries in sorted(summary.items())},
        }
    plain = next(item for item in owned if item["id"] == "ram_lfe.plain_operation_work_units")
    assert "(an input load)" in plain["summary"] and "plaintext multiplication" not in plain["summary"]
    assert plain["candidates"]["values"]["bgv.f257.n16.q22x50.p2x60"] == 1_795_227_648
    for budget in CONTRACT["ram_lfe"]["budgets"]:
        if any(name in budget["inputs"] for name in (item["id"] for item in owned)):
            assert budget["value"] is None, budget["id"]

    def drifted(contract: dict) -> None:
        item = next(i for i in contract["ram_lfe"]["open_inputs"] if i["id"] == "ram_lfe.ciphertext_bytes")
        item["candidates"]["values"]["bgv.f257.n16.q22x50.p2x60"] += 1

    assert_fails(
        edited(drifted),
        "ram_lfe input ram_lfe.ciphertext_bytes: the candidate values differ from "
        "`resource_contract_inputs` of specs/fhe_bgv_cost_summary.json",
    )

    def dropped(contract: dict) -> None:
        item = next(i for i in contract["ram_lfe"]["open_inputs"] if i["id"] == "ram_lfe.ciphertext_bytes")
        del item["candidates"]["values"]["bgv.f257.n14.q6x50.p2x60"]

    assert_fails(edited(dropped), "ram_lfe input ram_lfe.ciphertext_bytes: the candidate values differ")

    def selected(contract: dict) -> None:
        item = next(i for i in contract["ram_lfe"]["open_inputs"] if i["id"] == "ram_lfe.ciphertext_bytes")
        item["value"] = item["candidates"]["values"]["bgv.f257.n16.q22x50.p2x60"]

    assert_fails(edited(selected), "ram_lfe input ram_lfe.ciphertext_bytes: a known input is a bound, not an open input")

    def elsewhere(contract: dict) -> None:
        item = next(i for i in contract["ram_lfe"]["open_inputs"] if i["id"] == "ram_lfe.ciphertext_bytes")
        item["candidates"]["source"] = "specs/zk_delivery_graph.json"

    assert_fails(edited(elsewhere), "specs/zk_delivery_graph.json records no `resource_contract_inputs`")

    def unprojected(contract: dict) -> None:
        item = next(i for i in contract["ram_lfe"]["open_inputs"] if i["id"] == "ram_lfe.refresh_work_units")
        item["candidates"] = {"source": source, "values": {}}

    assert_fails(edited(unprojected), "ram_lfe input ram_lfe.refresh_work_units: no candidate of")
    # --refresh rewrites the record from the summary and adds no value.
    stale = edited(drifted)
    notes: list = []
    assert CHECKER["check"](ROOT, stale, TASKS, True, notes) == []
    assert stale["ram_lfe"] == CONTRACT["ram_lfe"]
