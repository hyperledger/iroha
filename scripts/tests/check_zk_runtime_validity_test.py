"""Drift tests for the runtime-validity census checker (task F.4)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from runpy import run_path

import pytest


CHECKER = run_path(
    str(Path(__file__).resolve().parents[1] / "check_zk_runtime_validity.py")
)
ROOT = CHECKER["ROOT"]
CENSUS = json.loads((ROOT / CHECKER["DEFAULT_CENSUS"]).read_text(encoding="utf-8"))
CONTRACT = json.loads((ROOT / CHECKER["RESOURCE_CONTRACT"]).read_text(encoding="utf-8"))
GRAPH = json.loads((ROOT / CHECKER["DELIVERY_GRAPH"]).read_text(encoding="utf-8"))
Scan = CHECKER["Scan"]
CensusChecker = CHECKER["CensusChecker"]
CENSUS_SITES = [row for item in CENSUS["entries"] for row in item.get("sites", [])]


@pytest.fixture(scope="module")
def tree_scan():
    """One scan of the real tree, shared by the tests that only edit the census."""
    return Scan(ROOT)


def problems(scan, census, contract=CONTRACT, graph=GRAPH) -> list:
    return CensusChecker(scan, census, contract, graph).run()


def edited(edit) -> dict:
    census = copy.deepcopy(CENSUS)
    edit(census)
    return census


def entry(census: dict, identifier: str) -> dict:
    return next(item for item in census["entries"] if item["id"] == identifier)


def assert_fails(scan, census: dict, fragment: str, **inputs) -> None:
    found = problems(scan, census, **inputs)
    assert any(fragment in problem for problem in found), found[:5]


# ---------------------------------------------------------------------------
# The tracked census against the real tree
# ---------------------------------------------------------------------------

def test_tracked_census_matches_the_source(tree_scan) -> None:
    assert problems(tree_scan, CENSUS) == []


def test_census_covers_every_gate_kind_and_names_only_plan_tasks() -> None:
    kinds = {item["kind"] for item in CENSUS["entries"]}
    assert kinds == set(CHECKER["KINDS"])
    tasks = {task["id"] for task in GRAPH["tasks"]}
    owners = {item["owner"] for item in CENSUS["entries"] if item["owner"] is not None}
    assert owners <= tasks
    assert "F.4" in owners and "P.5" in owners
    # Every entry says what it gates and what decides instead.
    for item in CENSUS["entries"]:
        assert item["gates"].strip() and item["decided_by"].strip(), item["id"]
        assert (ROOT / item["path"]).is_file(), item["id"]


def test_done_entries_hold_evidence_and_f4_open_entries_say_why() -> None:
    done = [item for item in CENSUS["entries"] if item["status"] == "done"]
    assert {item["id"] for item in done} >= {"cfg.zk.validity_policy", "env.zk.config_aliases"}
    for item in done:
        assert item.get("tests") or item.get("removed"), item["id"]
    for item in CENSUS["entries"]:
        if item["status"] == "open" and item["owner"] == "F.4":
            assert item.get("open_reason"), item["id"]
        if item["status"] in ("not_a_gate", "out_of_plan"):
            assert item["owner"] is None and item.get("note"), item["id"]


def test_backend_switch_census_tracks_canonical_pipa_r_readers(tree_scan) -> None:
    """A backend rename cannot hide retained switches or revive retired readers."""
    expected = {
        key: count for key, count in tree_scan.rows.items()
        if key[1:] == ("config_switch", "enabled")
        and key[0] != "crates/irohad/src/main.rs"
    }
    recorded = {
        tuple(row[:3]): row[3]
        for identifier in ("cfg.zk.validity_policy", "switch.zk.backend_enabled")
        for row in entry(CENSUS, identifier)["sites"]
        if row[1] == "config_switch"
    }
    assert recorded == expected
    backend = entry(CENSUS, "switch.zk.backend_enabled")
    assert backend["status"] == "open"
    assert "pipa_r.enabled" in backend["gates"]
    assert any(anchor["path"] == "crates/iroha_core_zk/src/lib.rs"
               for anchor in backend["anchors"])


def test_pipeline_fee_census_tracks_retained_readers(tree_scan) -> None:
    """Fee projection migration keeps every retained read visible in the census."""
    expected = {key: count for key, count in tree_scan.rows.items()
                if key[1] == "node_policy_read" and key[2].startswith("pipeline.gas")}
    row = entry(CENSUS, "cfg.pipeline.gas_identity")
    assert {tuple(site[:3]): site[3] for site in row["sites"]} == expected
    assert row["status"] == "open"
    assert "compile errors" in row["open_reason"]
    # Same-named fields in the coupled parameter owner remain explicitly classified.
    key = ("crates/iroha_core/src/pipeline_gas_policy.rs", "pipeline_settings_write", "<expression>")
    writes = entry(CENSUS, "cfg.pipeline.settings_writes")
    assert tree_scan.rows[key] == 2
    assert [*key, 2] in writes["sites"]
    assert "StateParameters.pipeline" in writes["decided_by"]


def test_every_node_configuration_catalog_field_is_assigned_once() -> None:
    recorded = CHECKER["contract_catalog_fields"](CONTRACT)
    assert set(recorded) == set(CHECKER["CONFIG_CATALOGS"])
    for catalog in CENSUS["config_catalogs"]:
        assigned = [field for group in catalog["groups"] for field in group["fields"]]
        assert sorted(assigned) == sorted(recorded[catalog["catalog"]]), catalog["catalog"]
    # The whole ZK consensus-policy hash inventory is the committed policy.
    zk = next(item for item in CENSUS["config_catalogs"] if item["catalog"] == "zk_consensus_policy_hash")
    assert [group["entry"] for group in zk["groups"]] == ["cfg.zk.validity_policy"]


# ---------------------------------------------------------------------------
# Drift of the census document
# ---------------------------------------------------------------------------

def test_a_removed_site_row_is_an_unlisted_gate(tree_scan) -> None:
    def drop(census):
        target = next(item for item in census["entries"] if item["sites"])
        target["sites"].pop()
    assert_fails(tree_scan, edited(drop), "unlisted site:")


def test_a_site_that_no_longer_exists_fails(tree_scan) -> None:
    def add(census):
        entry(census, "gate.privacy.activation_registry")["sites"].append(
            ["crates/iroha_core/src/privacy.rs", "qualification", "reviewer", 3]
        )
    assert_fails(tree_scan, edited(add), "is gone; remove the row")


def test_a_changed_occurrence_count_fails(tree_scan) -> None:
    def bump(census):
        target = next(item for item in census["entries"] if item["sites"])
        target["sites"][0][3] += 1
    assert_fails(tree_scan, edited(bump), "the census records")


def test_a_site_attributed_twice_fails(tree_scan) -> None:
    def duplicate(census):
        with_sites = [item for item in census["entries"] if item["sites"]]
        with_sites[1]["sites"].append(list(with_sites[0]["sites"][0]))
    assert_fails(tree_scan, edited(duplicate), "attributed to both")


def test_unknown_owner_kind_and_status_fail(tree_scan) -> None:
    assert_fails(
        tree_scan,
        edited(lambda census: entry(census, "gate.privacy.activation_registry").update(owner="Z.9")),
        "is not a task of",
    )
    assert_fails(
        tree_scan,
        edited(lambda census: entry(census, "gate.privacy.activation_registry").update(kind="lifecycle")),
        "unknown kind",
    )
    assert_fails(
        tree_scan,
        edited(lambda census: entry(census, "gate.privacy.activation_registry").update(status="closed")),
        "unknown status",
    )


def test_the_pipeline_limits_are_recorded_as_committed(tree_scan) -> None:
    census = json.loads((ROOT / "specs" / "zk_runtime_validity_census.json").read_text(encoding="utf-8"))
    for ident in ("cfg.pipeline.bounds", "cfg.pipeline.dynamic_prepass"):
        row = entry(census, ident)
        assert row["status"] == "done" and row["owner"] == "F.4", ident
        assert row["tests"], ident
        assert "pipeline_validity_policy_v1" in row["decided_by"], ident
    # Fee source migration is present; certified-history integration remains open.
    assert entry(census, "cfg.pipeline.gas_identity")["status"] == "open"

    # A `done` entry that loses its tests is refused.
    def untested(census):
        entry(census, "cfg.pipeline.bounds").pop("tests")

    assert_fails(tree_scan, edited(untested), "cfg.pipeline.bounds")


def test_an_open_f4_entry_without_a_reason_fails(tree_scan) -> None:
    def strip(census):
        entry(census, "cfg.nexus.bounds").pop("open_reason")
    assert_fails(tree_scan, edited(strip), "states why it is not changed now")


def test_a_done_entry_needs_a_real_test_or_a_removed_construct(tree_scan) -> None:
    def strip(census):
        target = entry(census, "env.zk.config_aliases")
        target.pop("tests")
        target.pop("removed")
    assert_fails(tree_scan, edited(strip), "names a test or a removed construct")

    def rename(census):
        entry(census, "cfg.zk.validity_policy")["tests"][0]["name"] = "no_such_test"
    assert_fails(tree_scan, edited(rename), "is not an active test")


def test_a_missing_anchor_or_symbol_fails(tree_scan) -> None:
    assert_fails(
        tree_scan,
        edited(lambda census: entry(census, "gate.privacy.activation_registry").update(symbol="no_such_symbol")),
        "does not occur in",
    )

    def move(census):
        entry(census, "gate.privacy.activation_registry")["anchors"][0]["contains"] = "no such text"
    assert_fails(tree_scan, edited(move), "occurs 0 time(s)")


def test_an_unassigned_or_unknown_catalog_field_fails(tree_scan) -> None:
    def drop(census):
        census["config_catalogs"][0]["groups"][0]["fields"].pop()
    assert_fails(tree_scan, edited(drop), "is not assigned to an entry")

    def invent(census):
        census["config_catalogs"][0]["groups"][0]["fields"].append("pipeline.invented_limit")
    assert_fails(tree_scan, edited(invent), "is not a field of the catalog")


def test_a_new_catalog_field_in_the_resource_contract_fails(tree_scan) -> None:
    contract = copy.deepcopy(CONTRACT)
    catalog = next(item for item in contract["catalogs"] if item["id"] == "zk_consensus_policy_hash")
    catalog["excluded"][0]["fields"].append("halo2.new_switch")
    assert_fails(tree_scan, CENSUS, "field 'halo2.new_switch' is not assigned", contract=contract)


def test_feature_classification_is_complete_and_counted(tree_scan) -> None:
    def drop(census):
        census["features"]["iroha_core"].pop("zk-stark")
    assert_fails(tree_scan, edited(drop), "feature iroha_core/zk-stark: not classified")

    def bump(census):
        census["features"]["iroha_core"]["zk-stark"]["cfg_sites"] += 1
    assert_fails(tree_scan, edited(bump), "conditional-compilation site(s)")

    def invent(census):
        census["features"]["iroha_core"]["zk-invented"] = {"class": "validity_gate", "entry": "feature.zk_stark", "cfg_sites": 0}
    assert_fails(tree_scan, edited(invent), "classified but neither declared nor used")


def test_the_detector_table_cannot_be_narrowed_in_the_census(tree_scan) -> None:
    def narrow(census):
        census["scan"]["detectors"]["env_read"]["pattern"] = "never"
    assert_fails(tree_scan, edited(narrow), "scan.detectors differs")

    def forget(census):
        census["scan"]["rust_crates"].remove("iroha_core_zk")
    assert_fails(tree_scan, edited(forget), "scan.rust_crates differs")


def test_summary_is_recomputed(tree_scan) -> None:
    def lie(census):
        census["summary"]["by_status"]["open"] = 0
    assert_fails(tree_scan, edited(lie), "summary must be")


def test_render_is_stable() -> None:
    text = (ROOT / CHECKER["DEFAULT_CENSUS"]).read_text(encoding="utf-8")
    assert CHECKER["render"](CENSUS) == text


# ---------------------------------------------------------------------------
# Drift of the source (synthetic trees)
# ---------------------------------------------------------------------------

def write(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def rows(root: Path) -> dict:
    return dict(Scan(root).rows)


def test_scan_finds_each_kind_of_gate_in_production_code(tmp_path: Path) -> None:
    write(tmp_path, "crates/iroha_core/src/zk_gate.rs", """
        pub fn gate(cfg: &Zk, chain: &str) -> bool {
            let from_env = std::env::var("IROHA_ZK_OVERRIDE").is_ok();
            let build = option_env!("IROHA_GIT_COMMIT_HASH");
            let started = std::time::Instant::now();
            #[cfg(feature = "zk-stark")]
            let stark = cfg.stark.enabled;
            let ready = privacy_readiness_certificate(chain);
            let active = PrivacyLifecycle::Active == privacy_protocol_activation(chain);
            let catalog = exact12_capability_manifest_v1();
            let source_digest = proof_source_digest();
            if is_production_proof_chain(chain) { return verify_timeout_ms() > started.elapsed().as_millis(); }
            Err(ProofUnavailable)
        }
    """)
    found = rows(tmp_path)
    path = "crates/iroha_core/src/zk_gate.rs"
    assert found[(path, "env_read", "IROHA_ZK_OVERRIDE")] == 1
    assert found[(path, "env_read", "IROHA_GIT_COMMIT_HASH")] == 1
    assert found[(path, "wall_clock", "instant")] == 1
    assert found[(path, "wall_clock", "elapsed")] == 1
    assert found[(path, "config_switch", "enabled")] == 1
    assert found[(path, "qualification", "readiness")] == 1
    assert found[(path, "activation", "activation")] == 1
    assert found[(path, "activation", "lifecycle")] == 1
    assert found[(path, "global_manifest", "exact12")] == 1
    assert found[(path, "digest_identity", "source")] == 2
    assert found[(path, "chain_condition", "production")] == 1
    assert found[(path, "time_budget", "timeout")] == 1
    assert found[(path, "unavailable", "unavailable")] == 1
    assert Scan(tmp_path).feature_rows[(path, "zk-stark")] == 1


def test_scan_tracks_pipa_r_switches_and_family_identifiers(tmp_path: Path) -> None:
    path = "crates/iroha_core/src/native_pipa_r.rs"
    write(tmp_path, path, """
        pub fn verify(cfg: &Zk) -> bool {
            let direct = cfg.pipa_r.enabled;
            let nested = zk_config().pipa_r.enabled;
            let active = privacy_activation();
            direct && nested && active
        }
    """)
    outside = "crates/iroha_core/src/executor.rs"
    write(tmp_path, outside, """
        pub fn execute() -> bool { pipa_r_activation() }
    """)
    found = rows(tmp_path)
    assert found[(path, "config_switch", "enabled")] == 2
    assert found[(path, "activation", "activation")] == 1
    assert found[(outside, "activation", "activation")] == 1


def test_scan_ignores_comments_strings_and_test_code(tmp_path: Path) -> None:
    write(tmp_path, "crates/iroha_core/src/zk_quiet.rs", """
        // std::env::var("IN_A_COMMENT") and privacy_readiness in a comment
        /* nested /* std::env::var("NESTED") */ still a comment */
        pub const TEXT: &str = "privacy_qualification_record and Instant::now in a string";
        pub const RAW: &str = r#"exact12_capability_manifest "quoted" "#;
        #[cfg(test)]
        mod tests {
            #[test]
            fn reads_environment() { let _ = std::env::var("ONLY_IN_TESTS"); }
        }
        #[cfg(test)]
        fn test_only_helper() { let _ = std::env::var("ONLY_IN_A_TEST_HELPER"); }
        pub fn production() -> u32 { 7 }
    """)
    write(tmp_path, "crates/iroha_core/src/zk_quiet_tests.rs",
          'fn f() { let _ = std::env::var("IN_A_TEST_FILE"); }')
    write(tmp_path, "crates/iroha_core/src/zk_decl.rs", "#[cfg(test)]\nmod probe;\npub fn f() {}\n")
    write(tmp_path, "crates/iroha_core/src/zk_decl/probe.rs",
          'fn f() { let _ = std::env::var("IN_A_TEST_ONLY_MODULE"); }')
    assert rows(tmp_path) == {}


def test_a_family_detector_counts_family_identifiers_in_shared_files(tmp_path: Path) -> None:
    # A shared file: only identifiers that are themselves on the proof path count.
    write(tmp_path, "crates/iroha_core/src/state.rs", """
        pub fn f() {
            let lane_activation_height = 1;
            let privacy_exact12_qualification = 2;
            let provider_qualification = 3;
        }
    """)
    found = rows(tmp_path)
    path = "crates/iroha_core/src/state.rs"
    assert found == {
        (path, "qualification", "qualification"): 1,
        (path, "global_manifest", "exact12"): 1,
    }


def test_a_new_gate_in_the_real_layout_is_reported_as_unlisted(tmp_path: Path) -> None:
    # A census that lists nothing, a tree with one new gate: the check names it.
    write(tmp_path, "crates/iroha_core_zk/src/lib.rs",
          'pub fn verify() -> bool { std::env::var("ZK_SKIP_VERIFY").is_err() }')
    census = copy.deepcopy(CENSUS)
    census["entries"] = []
    census["config_catalogs"] = []
    census["features"] = {}
    found = CensusChecker(Scan(tmp_path), census, {"catalogs": []}, GRAPH).run()
    assert any(
        "unlisted site: crates/iroha_core_zk/src/lib.rs detector env_read token 'ZK_SKIP_VERIFY'" in problem
        for problem in found
    ), found[:5]


def unlisted(root: Path) -> list:
    """Problems of a census that lists nothing, checked against the tree at `root`."""
    census = copy.deepcopy(CENSUS)
    census["entries"] = []
    census["config_catalogs"] = []
    census["features"] = {}
    return CensusChecker(Scan(root), census, {"catalogs": []}, GRAPH).run()


def assert_unlisted(root: Path, path: str, detector: str, token: str) -> None:
    found = unlisted(root)
    wanted = f"unlisted site: {path} detector {detector} token {token!r}"
    assert any(wanted in problem for problem in found), found[:8]


def test_scan_separates_local_resource_version_and_height_deadline_names(tmp_path: Path) -> None:
    path = "crates/iroha_core_zk/src/outcomes.rs"
    write(tmp_path, path, """
        pub enum Error {
            RandomnessUnavailable, EntropyUnavailable, LocalAllocationUnavailable,
            ProofAllocationUnavailable, UnsupportedPlatform, UnavailableIssuanceRngV1,
            UnsupportedProofVersion, UnsupportedVersion,
            EngineUnavailable, ProtocolUnavailable, UnsupportedDegree, Suspended,
        }
        pub fn windows(opening_deadline_height: u64, deadline_ms: u64, verify_timeout: u64) {}
    """)
    found = rows(tmp_path)
    assert found[(path, "unavailable", "local_resource")] == 6
    assert found[(path, "unavailable", "version_check")] == 2
    assert found[(path, "unavailable", "unavailable")] == 2
    assert found[(path, "unavailable", "unsupported")] == 1
    assert found[(path, "unavailable", "suspended")] == 1
    assert found[(path, "time_budget", "height_deadline")] == 1
    assert found[(path, "time_budget", "deadline")] == 1
    assert found[(path, "time_budget", "timeout")] == 1


def test_digest_detector_matches_whole_words_only(tmp_path: Path) -> None:
    path = "crates/iroha_core_zk/src/digests.rs"
    write(tmp_path, path, """
        pub fn f(resource_shape: u8, commit_hash: u8, commit_digest: u8) {}
        pub struct TlePartialReleaseShareV1;
        pub fn g(source_digest: u8, tested_binary_digest: u8, rustc_commit_hash: u8,
                 catalog_hash: u8, release_digest: u8) {}
    """)
    found = rows(tmp_path)
    assert {key[2]: count for key, count in found.items() if key[1] == "digest_identity"} == {
        "source": 1, "binary": 1, "build": 1, "catalog": 1, "release": 1,
    }


def test_genesis_tools_handshake_and_cli_crates_are_scanned(tmp_path: Path) -> None:
    # The crates a validity gate could hide in outside Core: each is in scope.
    cases = {
        "crates/iroha_p2p/src/lib.rs": "CONFIDENTIAL_SKIP_PROOFS",
        "crates/iroha_kagami/src/genesis/sign.rs": "ZK_GENESIS_SKIP_VK",
        "crates/iroha_deploy/src/localnet.rs": "ZK_LOCALNET_ASSUME_VALID",
        "crates/iroha_test_network/src/lib.rs": "ZK_TEST_NETWORK_BYPASS",
        "crates/iroha_cli/src/zk.rs": "ZK_CLI_FORCE",
        "crates/iroha_torii_shared/src/lib.rs": "ZK_SHARED_FORCE",
        "crates/connect_norito_bridge/src/lib.rs": "ZK_BRIDGE_FORCE",
        "crates/iroha_js_host/src/lib.rs": "ZK_JS_FORCE",
        "crates/iroha_plonk/src/lib.rs": "ZK_PLONK_FORCE",
    }
    for path, name in cases.items():
        write(tmp_path, path, f'pub fn gate() -> bool {{ std::env::var("{name}").is_ok() }}')
    found = unlisted(tmp_path)
    for path, name in cases.items():
        wanted = f"unlisted site: {path} detector env_read token {name!r}"
        assert any(wanted in problem for problem in found), (path, found[:4])
    assert set(CENSUS["scan"]["rust_crates"]) >= {path.split("/")[1] for path in cases}


def test_installing_or_writing_zk_settings_in_production_is_detected(tmp_path: Path) -> None:
    # Any spelling of a complete install, and any write to a `zk` settings field.
    path = "crates/irohad/src/main.rs"
    write(tmp_path, path, """
        fn start(state: &mut State, c: &Config) {
            let z = &c.zk;
            state.set_zk(z.clone()).unwrap();
            state.zk = z.clone();
            state.zk.max_proof_size_bytes = 1;
            c.zk.halo2.max_k = 3;
            if state.zk == other.zk {}
        }
    """)
    found = rows(tmp_path)
    assert found[(path, "zk_settings_install", "set_zk")] == 1
    assert found[(path, "zk_settings_write", "<expression>")] == 1
    assert found[(path, "zk_settings_write", "max_proof_size_bytes")] == 1
    assert found[(path, "zk_settings_write", "halo2")] == 1
    assert_unlisted(tmp_path, path, "zk_settings_install", "set_zk")
    # The tracked tree has no production install of a complete settings value.
    assert not [
        row for row in CENSUS_SITES if row[1] == "zk_settings_install"
    ], "State::set_zk is test-only; a production call site is a defect"


def test_a_read_of_an_uncommitted_node_policy_field_is_detected(tmp_path: Path) -> None:
    write(tmp_path, CHECKER["RESOURCE_CONTRACT"], json.dumps(CONTRACT))
    path = "crates/iroha_core/src/new_reader.rs"
    write(tmp_path, path, """
        impl StateBlock<'_> {
            fn skew(&self) -> u64 { self.nexus.axt.max_clock_skew_ms }
            fn fetch(&self) -> u64 { self.pipeline.query_max_fetch_size }
            fn key(&self, view: &StateView) -> Key { view.gov().vk_ballot.clone() }
            fn group(&self) -> Axt { self.nexus.axt.clone() }
            fn local(&self) -> usize { self.pipeline.workers }
        }
    """)
    found = rows(tmp_path)
    assert found[(path, "node_policy_read", "axt.max_clock_skew_ms")] == 1
    assert found[(path, "node_policy_read", "pipeline.query_max_fetch_size")] == 1
    assert found[(path, "node_policy_read", "governance.vk_ballot")] == 1
    assert found[(path, "node_policy_read", "axt.*")] == 1
    assert not [key for key in found if key[2].startswith("pipeline.workers")]
    assert_unlisted(tmp_path, path, "node_policy_read", "axt.max_clock_skew_ms")
    # Every such read of the tracked tree belongs to the entry that owns its field.
    owners = {
        row[2]: item["id"] for item in CENSUS["entries"] for row in item.get("sites", [])
        if row[1] == "node_policy_read"
    }
    assert owners["axt.slot_length_ms"] == "cfg.nexus.axt_windows"
    assert owners["pipeline.ivm_max_cycles_upper_bound"] == "cfg.pipeline.bounds"
    assert owners["governance.voting_asset_id"] == "cfg.governance"
    assert owners["crypto.allowed_signing"] == "cfg.crypto.algorithms"


def test_fraud_reads_use_the_exact_committed_catalog_owner(tmp_path: Path) -> None:
    """The State spelling cannot hide policy reads or turn transport into validity."""
    write(tmp_path, CHECKER["RESOURCE_CONTRACT"], json.dumps(CONTRACT))
    path = "crates/iroha_core/src/new_reader.rs"
    write(tmp_path, path, """
        fn read(state: &State) {
            let _ = state.fraud_monitoring.policy.enabled;
            let _ = state.fraud_monitoring.policy.attesters;
            let _ = state.fraud_monitoring.service_endpoints;
            let _ = state.fraud_monitoring.connect_timeout;
            let _ = state.fraud_monitoring.request_timeout;
            let _ = state.fraud_monitoring.missing_assessment_grace;
        }
    """)
    found = rows(tmp_path)
    policy_reads = {key: count for key, count in found.items()
                    if key[1] == "node_policy_read"}
    assert policy_reads == {(path, "node_policy_read", "fraud.policy"): 2}
    assert_unlisted(tmp_path, path, "node_policy_read", "fraud.policy")
    policy = entry(CENSUS, "cfg.fraud.committed_policy")
    assert policy["status"] == "done" and policy["owner"] == "F.4"
    assert policy["decided_by"].startswith("The exact FraudAdmissionPolicyV1")
    assert "freezes its predecessor" in policy["decided_by"]
    assert "did not demonstrate two admitted validators" in policy["note"]
    assert any(anchor["contains"] == 'policy.push("fraud.policy", &fraud_monitoring.policy);'
               for anchor in policy["anchors"])
    # This split must preserve the independently unfinished Oracle authority.
    assert entry(CENSUS, "cfg.oracle")["status"] == "open"


def test_the_handshake_switches_are_detected_in_the_p2p_crate(tmp_path: Path) -> None:
    path = "crates/iroha_p2p/src/peer.rs"
    write(tmp_path, path, """
        fn enforce(caps: &Caps, assume_valid: bool, verifier_backend: &str) -> bool {
            assume_valid != caps.assume_valid || verifier_backend != caps.verifier_backend
        }
    """)
    found = rows(tmp_path)
    assert found[(path, "handshake_switch", "assume_valid")] == 3
    assert found[(path, "handshake_switch", "verifier_backend")] == 3
    switches = entry(CENSUS, "cfg.confidential.node_switches")
    assert {row[0] for row in switches["sites"] if row[1] == "handshake_switch"} >= {
        "crates/iroha_p2p/src/peer.rs", "crates/irohad/src/main.rs",
    }
    assert any(
        anchor["contains"].startswith("verifier_backend: config.confidential.verifier_backend")
        for anchor in switches["anchors"]
    )


def test_clock_and_review_gates_in_core_validation_files_are_detected(tmp_path: Path) -> None:
    # Files that validate every transaction, although their paths are not on the proof path.
    write(tmp_path, "crates/iroha_core/src/queue.rs", """
        fn admit(started: std::time::Instant, budget: Duration) -> Result<(), Error> {
            if started.elapsed() > budget { return Err(Error::Expired); }
            Ok(())
        }
    """)
    write(tmp_path, "crates/iroha_core/src/tx.rs", """
        fn validate(tx: &Tx) -> bool { tx.reviewer_approved && tx.audit_certificate.is_some() }
    """)
    # The same names outside those files and outside the proof path are not scanned.
    write(tmp_path, "crates/iroha_core/src/telemetry.rs",
          "fn f(s: std::time::Instant) -> u128 { s.elapsed().as_millis() }")
    found = rows(tmp_path)
    assert found == {
        ("crates/iroha_core/src/queue.rs", "core_wall_clock", "elapsed"): 1,
        ("crates/iroha_core/src/tx.rs", "core_review_gate", "reviewer"): 2,
    }
    assert_unlisted(tmp_path, "crates/iroha_core/src/queue.rs", "core_wall_clock", "elapsed")
    assert_unlisted(tmp_path, "crates/iroha_core/src/tx.rs", "core_review_gate", "reviewer")
    # A chain-identity condition written with a literal network name.
    write(tmp_path, "crates/iroha_core_zk/src/chain_gate.rs",
          'pub fn gate(chain: &str) -> bool { chain == "minamoto" || chain != "sora-testnet" }')
    assert_unlisted(tmp_path, "crates/iroha_core_zk/src/chain_gate.rs", "chain_literal", "minamoto")
    assert_unlisted(tmp_path, "crates/iroha_core_zk/src/chain_gate.rs", "chain_literal", "sora-testnet")
    assert entry(CENSUS, "chain.network_name_literals")["status"] == "not_a_gate"
    # The tracked tree: the clock readings are pinned, and no review gate exists there.
    # Every reading was read in repair round 3: phase and lock timings, one
    # telemetry duration, one directory stamp and the admission network time.
    timing = entry(CENSUS, "wall.core.execution_timing")
    assert timing["status"] == "not_a_gate" and timing["attribution"] == "read" and timing["sites"]
    assert not [row for row in CENSUS_SITES if row[1] == "core_review_gate"]


def test_installing_or_writing_pipeline_settings_in_production_is_detected(tmp_path: Path) -> None:
    # The pipeline settings are State-owned like the ZK ones: a complete install
    # and any write to a `pipeline` settings field are rows of the scan.
    path = "crates/irohad/src/main.rs"
    write(tmp_path, path, """
        fn start(state: &mut State, config: &Config) {
            state.set_pipeline(config.pipeline.clone());
            state.pipeline = config.pipeline.clone();
            state.pipeline.overlay_max_bytes = 1;
            state.pipeline.gas.units_per_gas = rates;
            if state.pipeline == other.pipeline {}
            let limit = state.pipeline.overlay_max_bytes;
        }
    """)
    found = rows(tmp_path)
    assert found[(path, "pipeline_settings_install", "set_pipeline")] == 1
    assert found[(path, "pipeline_settings_write", "<expression>")] == 1
    assert found[(path, "pipeline_settings_write", "overlay_max_bytes")] == 1
    assert found[(path, "pipeline_settings_write", "gas")] == 1
    assert_unlisted(tmp_path, path, "pipeline_settings_install", "set_pipeline")
    assert_unlisted(tmp_path, path, "pipeline_settings_write", "<expression>")
    # Whole-value writes belong to the private runtime installer and the
    # validated committed-policy cache; the latter never reads node settings.
    assert not [row for row in CENSUS_SITES if row[1] == "pipeline_settings_install"]
    writes = {(row[0], row[2]) for row in CENSUS_SITES if row[1] == "pipeline_settings_write"}
    assert ("crates/iroha_core/src/state/runtime_configuration.rs", "<expression>") in writes
    assert {token for _, token in writes} <= {
        "<expression>", "gas", "parallel_apply", "parallel_overlay", "ready_queue_heap", "workers",
    }, writes
    assert {path for path, token in writes if token == "<expression>"} == {
        "crates/iroha_core/src/state/runtime_configuration.rs",
        "crates/iroha_core/src/pipeline_gas_policy.rs",
    }


def test_a_test_module_renamed_with_a_path_attribute_is_not_scanned(tmp_path: Path) -> None:
    write(tmp_path, "crates/iroha_core/src/block.rs", """
        pub(crate) mod valid {
            #[cfg(test)]
            #[path = "admission_batching.rs"]
            mod admission_batching_tests;
        }
        #[cfg(test)]
        #[path = "fixtures/helpers.rs"]
        mod helper_fixtures;
    """)
    gate = 'pub fn gate() -> bool { std::env::var("ZK_TEST_ONLY_GATE").is_ok() }'
    write(tmp_path, "crates/iroha_core/src/block/valid/admission_batching.rs", gate)
    write(tmp_path, "crates/iroha_core/src/fixtures/helpers.rs", gate)
    write(tmp_path, "crates/iroha_core/src/fixtures/helpers/deeper.rs", gate)
    # A production file with the same name elsewhere is still scanned.
    write(tmp_path, "crates/iroha_core/src/queue/admission_batching.rs", gate)
    found = rows(tmp_path)
    assert [key[0] for key in found if key[1] == "env_read"] == [
        "crates/iroha_core/src/queue/admission_batching.rs"
    ]


def test_qualified_names_builder_verbs_and_expired_deadlines_are_not_gates(tmp_path: Path) -> None:
    path = "crates/iroha_core_zk/src/names.rs"
    write(tmp_path, path, """
        pub fn parse_fully_qualified(name: &str) {}
        pub struct FullyQualifiedName;
        pub fn build_sha256_word_circuit_v1() {}
        pub fn build_sha_word_stark_base_v1() {}
        pub enum Failure { RegistrationDeadlineExpired, OpeningDeadlineExpired }
        pub fn real(qualification_digest: u8, build_sha256: u8, rustc_commit_hash: u8,
                    deadline_ms: u64) {}
    """)
    found = rows(tmp_path)
    assert {key[2]: count for key, count in found.items() if key[1] == "qualification"} == {
        "qualification": 1,
    }
    assert {key[2]: count for key, count in found.items() if key[1] == "digest_identity"} == {
        "build": 2,
    }
    assert {key[2]: count for key, count in found.items() if key[1] == "time_budget"} == {
        "deadline_outcome": 2, "deadline": 1,
    }


def test_entries_read_in_repair_round_two_state_what_the_code_does() -> None:
    by_id = {item["id"]: item for item in CENSUS["entries"]}
    # Names that only looked like a gate have no entry or a not_a_gate one.
    assert "kaigi.qualification" not in by_id
    assert "voting.time_budget" not in by_id
    for identifier in ("voting.deadline_outcome", "voting.unavailable", "voting.dkg_qualified_set",
                       "fhe_arithmetic.unavailable", "axt.unavailable", "axt.digest_identity",
                       "kaigi.unavailable", "verange.unavailable", "soracloud.digest_identity",
                       "zk_x509.time_budget"):
        assert by_id[identifier]["status"] == "not_a_gate", identifier
        assert by_id[identifier]["owner"] is None, identifier
        assert by_id[identifier]["attribution"] == "read", identifier
    # The entropy failure of a prover is a local resource, not an unfinished operation.
    for identifier in ("orchard", "fcmp", "pq_masp", "private_note", "private_settlement"):
        assert f"{identifier}.unavailable" not in by_id, identifier
        assert by_id[f"{identifier}.local_resource"]["status"] == "local_resource"
    # Real gates stay open with their owner and the fact that was read.
    assert by_id["voting.qualification"]["status"] == "open"
    assert "release-audit reviewer" in by_id["voting.qualification"]["note"]
    assert by_id["ivm_proof.qualification"]["status"] == "open"
    assert by_id["zk_x509.digest_identity"]["status"] == "open"
    assert "build_sha256_word_circuit_v1" != by_id["zk_x509.digest_identity"]["symbol"]
    # The process-wide verification gas schedule is gone.
    gas = by_id["gas.process_wide_schedule"]
    assert gas["status"] == "done"
    assert any("static ZK_GAS_BASE_VERIFY" in item["contains"] for item in gas["removed"])


def test_local_resource_and_reclassified_entries_state_what_the_code_does() -> None:
    statuses = {item["id"]: item["status"] for item in CENSUS["entries"]}
    # Local allocation and entropy failures are not unfinished operations.
    for identifier in ("axt.local_resource", "orchard.local_resource", "zk_ace.local_resource",
                       "confidential.local_resource", "fhe_arithmetic.local_resource"):
        assert statuses[identifier] == "local_resource", identifier
    assert statuses["pgc.version_check"] == "not_a_gate"
    assert statuses["voting.height_deadline"] == "not_a_gate"
    # ABI syscalls, AIR frame roles and write ordering are ordinary protocol code.
    for identifier in ("ivm.activation", "ivm_proof.activation", "fastpq.activation",
                       "wall.zk_lane.enqueue_timeout"):
        assert statuses[identifier] == "not_a_gate", identifier
    axt = entry(CENSUS, "axt.local_resource")
    assert {test["name"] for test in axt["tests"]} >= {
        "local_fastpq_allocation_refusal_defers_without_axt_reject_reason",
    }
    assert "local_resource" in CENSUS["statuses"]
    assert "does not see" in CENSUS["what"]


def test_sdk_sources_are_scanned_per_file_and_class(tmp_path: Path) -> None:
    write(tmp_path, "IrohaSwift/Sources/IrohaSwift/Privacy.swift",
          "func available() -> Bool { capabilityManifest.qualification != nil && exact12.readiness }")
    write(tmp_path, "IrohaSwift/Sources/IrohaSwift/Plain.swift", "func plain() -> Bool { true }")
    path = "IrohaSwift/Sources/IrohaSwift/Privacy.swift"
    assert rows(tmp_path) == {
        (path, "sdk_availability", "capability_manifest"): 1,
        (path, "sdk_availability", "qualification"): 1,
        (path, "sdk_availability", "exact12"): 1,
        (path, "sdk_availability", "readiness"): 1,
    }


def test_mutable_borrow_or_overwrite_of_settings_is_detected(tmp_path: Path) -> None:
    # The settings fields of `State` are private; inside the State modules a
    # mutable borrow, `mem::replace`, `mem::swap`, `clone_from` or a compound
    # assignment still reaches them, and each is a row of the scan.
    path = "crates/iroha_core/src/state/runtime_configuration.rs"
    write(tmp_path, path, """
        fn overwrite(state: &mut State, p: Pipeline, mut z: Zk) {
            core::mem::replace(&mut state.pipeline, p.clone());
            core::mem::swap(&mut state.zk, &mut z);
            state.pipeline.clone_from(&p);
            state.zk.clone_from(&z);
            let borrowed = &mut state.pipeline;
            state.pipeline.amx_group_budget_ms += 1;
            let read = &state.pipeline;
            let equal = state.zk.gas.proof_base == 1;
        }
    """)
    found = rows(tmp_path)
    assert found[(path, "settings_mut_borrow", "pipeline")] == 3
    assert found[(path, "settings_mut_borrow", "zk")] == 2
    assert found[(path, "pipeline_settings_write", "amx_group_budget_ms")] == 1
    assert not [key for key in found if key[1] == "zk_settings_write"]
    assert_unlisted(tmp_path, path, "settings_mut_borrow", "pipeline")
    assert_unlisted(tmp_path, path, "pipeline_settings_write", "amx_group_budget_ms")
    # The tracked tree has one mutable borrow: the frozen settings copy of a
    # block handed to its transaction, a field of `StateBlock`.
    assert [row[:3] for row in CENSUS_SITES if row[1] == "settings_mut_borrow"] == [
        ["crates/iroha_core/src/state.rs", "settings_mut_borrow", "zk"],
    ]
    state = (ROOT / "crates/iroha_core/src/state.rs").read_text(encoding="utf-8")
    assert "block_zk: &mut fields.zk," in state
    # The State-owned fields are private and have read accessors.
    assert "\n    zk: iroha_config::parameters::actual::Zk,\n    /// Governance configuration" in state
    assert "\n    pipeline: iroha_config::parameters::actual::Pipeline,\n    /// Shared pipeline" in state
    assert "pub const fn installed_zk(&self)" in state
    assert "pub const fn installed_pipeline(&self)" in state


def test_default_schedule_or_settings_in_production_is_detected(tmp_path: Path) -> None:
    # A meter, a host or a quote that is given the protocol default instead of
    # the schedule frozen in its block or view is a defect; every production
    # use of a default schedule or settings value is a row.
    path = "crates/iroha_core/src/tx.rs"
    write(tmp_path, path, """
        fn meter(instructions: &[InstructionBox], host: &mut CoreHost) -> u64 {
            host.set_zk_config(&Zk::default());
            let limits = actual::Pipeline::default();
            let gas = ConfidentialGas::default();
            crate::gas::meter_instructions(instructions, &crate::gas::DEFAULT_ZK_GAS)
        }
        #[cfg(test)]
        mod tests {
            fn fixture() { let _ = crate::gas::DEFAULT_ZK_GAS; let _ = Zk::default(); }
        }
    """)
    found = rows(tmp_path)
    assert found[(path, "default_validity_settings", "DEFAULT_ZK_GAS")] == 1
    assert found[(path, "default_validity_settings", "Zk::default")] == 1
    assert found[(path, "default_validity_settings", "Pipeline::default")] == 1
    assert found[(path, "default_validity_settings", "ConfidentialGas::default")] == 1
    assert_unlisted(tmp_path, path, "default_validity_settings", "DEFAULT_ZK_GAS")
    assert_unlisted(tmp_path, path, "default_validity_settings", "Zk::default")
    # The tracked tree: the definition, the three host constructors (replaced
    # by `set_zk_config` for every State-backed host) and genesis staging.
    sites = {(row[0], row[2]): row[3] for row in CENSUS_SITES if row[1] == "default_validity_settings"}
    assert sites == {
        ("crates/iroha_core/src/gas.rs", "DEFAULT_ZK_GAS"): 1,
        ("crates/iroha_core/src/smartcontracts/ivm/host.rs", "DEFAULT_ZK_GAS"): 3,
        ("crates/iroha_deploy/src/genesis/staging.rs", "Pipeline::default"): 1,
    }
    guard = entry(CENSUS, "gas.default_schedule_sites")
    assert guard["status"] == "done"
    assert {test["name"] for test in guard["tests"]} >= {
        "queue_admission_prices_a_proof_instruction_with_the_committed_gas_schedule",
        "fee_quote_prices_a_proof_instruction_with_the_committed_gas_schedule",
    }


def test_revocation_enums_and_true_constants_are_derived_from_the_source(tmp_path: Path) -> None:
    path = "crates/iroha_data_model/src/privacy/credentials.rs"
    write(tmp_path, path, """
        pub enum IssuerRecordLifecycleV1 { Active, Revoked }
        pub enum PolicyVersionLifecycleV1 { Active, Superseded, Revoked }
        pub enum ProtocolLifecycleV1 { Proposed(Height), Active, Suspended, Retired }
        pub const TAIL_LIFECYCLE_CONTRACT_IMPLEMENTED_V2: bool = true;
        pub const ENGINE_ACTIVATION_READY_V1: bool = false;
        fn check(record: &Record) -> bool {
            record.lifecycle == IssuerRecordLifecycleV1::Active
                && version.lifecycle == PolicyVersionLifecycleV1::Active
                && matches!(protocol, ProtocolLifecycleV1::Active)
                && TAIL_LIFECYCLE_CONTRACT_IMPLEMENTED_V2
                && ENGINE_ACTIVATION_READY_V1
        }
    """)
    scan = Scan(tmp_path, [path])
    assert scan.revocation_enums == {"IssuerRecordLifecycleV1", "PolicyVersionLifecycleV1"}
    assert scan.true_constants == {"TAIL_LIFECYCLE_CONTRACT_IMPLEMENTED_V2"}
    found = dict(scan.rows)
    # The two revocation enums: a definition and a use each.
    assert found[(path, "activation", "revocation_state")] == 4
    # The constant that is `true`: a definition and a use.
    assert found[(path, "activation", "constant_true")] == 2
    # The activation lifecycle, the field `lifecycle` and the `false` constant stay gate names.
    assert found[(path, "activation", "lifecycle")] == 2 + 2
    assert found[(path, "activation", "activation")] == 2
    assert found[(path, "unfinished_constant", "false")] == 1
    # A variant added to a revocation enum, or a constant set to false, changes the class.
    source = (tmp_path / path).read_text(encoding="utf-8")
    (tmp_path / path).write_text(
        source.replace("{ Active, Revoked }", "{ Pending, Active, Revoked }")
        .replace("IMPLEMENTED_V2: bool = true", "IMPLEMENTED_V2: bool = false"),
        encoding="utf-8",
    )
    changed = Scan(tmp_path, [path])
    assert changed.revocation_enums == {"PolicyVersionLifecycleV1"}
    assert changed.true_constants == set()
    assert changed.rows[(path, "activation", "revocation_state")] == 2
    assert (path, "activation", "constant_true") not in changed.rows
    assert changed.rows[(path, "unfinished_constant", "false")] == 2


def test_the_census_lists_the_source_derived_classes(tree_scan) -> None:
    assert CENSUS["scan"]["revocation_enums"] == sorted(tree_scan.revocation_enums)
    assert "PrivacyZkAcePolicyLifecycleV1" in CENSUS["scan"]["revocation_enums"]
    assert "PrivacyProtocolLifecycleV1" not in CENSUS["scan"]["revocation_enums"]
    assert_fails(
        tree_scan,
        edited(lambda census: census["scan"]["revocation_enums"].append("PrivacyProtocolLifecycleV1")),
        "scan.revocation_enums must be",
    )
    assert_fails(
        tree_scan,
        edited(lambda census: census["scan"]["true_constants"].clear()),
        "scan.true_constants must be",
    )


def test_every_gate_or_unfinished_entry_was_read_site_by_site() -> None:
    by_id = {item["id"]: item for item in CENSUS["entries"]}
    unread = [item["id"] for item in CENSUS["entries"]
              if item["attribution"] == "path_rule" and item["status"] in ("open", "unsupported")]
    assert unread == []
    # Revocation of a committed record is not an activation gate.
    assert "zk_ace.activation" not in by_id
    assert by_id["zk_ace.revocation_state"]["status"] == "not_a_gate"
    assert by_id["vega.revocation_state"]["status"] == "not_a_gate"
    assert "PrivacyProtocolLifecycleV1" in by_id["vega.activation"]["note"]
    # A constant that is `true` gates nothing; one that is `false` is unfinished work.
    assert "zk_ams.activation" not in by_id
    assert by_id["zk_ams.constant_true"]["status"] == "not_a_gate"
    assert by_id["zk_ams.unfinished_constant"]["status"] == "unsupported"
    assert by_id["zk_ace.unfinished_constant"]["owner"] == "P.15"
    # Trace-recorder deferrals of the IVM are a local resource; trap names are not a gate.
    ivm_local = {(row[0], row[2]) for row in by_id["ivm.local_resource"]["sites"]}
    assert ("crates/ivm/src/zk/runtime_trace.rs", "unavailable") in ivm_local
    assert by_id["ivm.unavailable"]["status"] == "not_a_gate"
    assert {row[0] for row in by_id["ivm.unavailable"]["sites"]} == {
        "crates/ivm/src/proof_coverage/traps.rs"
    }
    # Mixed entries say which names are a gate and which are revocation or validation.
    assert "withdrawal" in by_id["confidential.activation"]["note"]
    assert by_id["voting.activation"]["status"] == "not_a_gate"
    assert by_id["wall.core.execution_timing"]["status"] == "not_a_gate"
    assert by_id["wall.core.execution_timing"]["attribution"] == "read"
    # SDK rows are split by what the file and the class name.
    for sdk in ("swift", "csharp", "javascript", "python", "kotlin"):
        assert by_id[f"sdk_{sdk}.exact12_capability"]["status"] == "open", sdk
        # Retired release DTOs are not retained as fictitious SDK source owners.
        assert f"sdk_{sdk}.kagemusha_release" not in by_id, sdk
        assert by_id[f"sdk_{sdk}.names"]["status"] == "not_a_gate", sdk
        assert f"sdk_{sdk}.sdk_availability" not in by_id
    # `fault_injection` compiles a test helper and is not a gate.
    assert "feature.fault_injection" not in by_id
    assert CENSUS["features"]["iroha_data_model"]["fault_injection"]["class"] == "development_or_test"


def test_native_owner_reconciliation_preserves_unfinished_relations() -> None:
    """New native source names must not turn unfinished functionality into completion."""
    registration = entry(CENSUS, "sccp.qualification")
    assert registration["status"] == "out_of_plan"
    assert registration["symbol"] == "fn register_route("
    assert "It still refuses missing Parliament and reconciliation launch authority" in registration["note"]
    assert "a valid pin or deployment shape is not permission to register" in registration["note"]
    assert ("parliament_binding_ballot_available and sccp_reconciliation_available remain false; "
            "no launch qualification is claimed") in registration["note"]
    # Available native checks do not authorize the remaining launch relations: the
    # entry holds only readiness and qualification projections, never a register path.
    assert registration["sites"]
    assert all(site[1] == "qualification" and site[2] in ("readiness", "qualification")
               for site in registration["sites"])
    assert all(site[0] != registration["path"] for site in registration["sites"])
    governance = (ROOT / registration["path"]).read_text(encoding="utf-8")
    assert "registration::validate_available(state_transaction, register)?;" in governance
    assert ("super::parliament_iface::parliament_binding_ballot_available(),\n"
            "        sccp_reconciliation_available(),") in governance
    assert "gates.0 && gates.1" in governance
    assert 'Err(refuse(\n            "RegisterRoute launch/reconciliation authority is unavailable",' in governance
    assert "pub const fn sccp_reconciliation_available() -> bool {\n    false\n}" in governance
    registration_source = (ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/governance/registration.rs").read_text(encoding="utf-8")
    assert '"EVM address differs from the exact locked CREATE2 deployment"' in registration_source
    assert "stx.block_unix_timestamp_ms(),\n        params.committee_heartbeat_ms," in registration_source
    assert "pin.until_ms != pinned_deadline_ms" in registration_source
    parliament = (ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/parliament_iface.rs").read_text(encoding="utf-8")
    assert "pub const fn parliament_binding_ballot_available() -> bool {\n    false\n}" in parliament
    unavailable = entry(CENSUS, "sccp.unavailable")
    assert unavailable["status"] == "out_of_plan"
    assert "Missing or inconsistent original source/rotation custody remains unavailable, not authenticated absence" in unavailable["note"]
    assert ("The block hook now calls generation/anchor pruning, which preserves pending forgery "
            "penalties and retained generation boundaries") in unavailable["note"]
    assert "This inventory does not qualify complete SCCP delivery" in unavailable["note"]
    hook = (ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs").read_text(encoding="utf-8")
    assert "super::pruning::prune(&mut stx)" in hook
    torii = (ROOT / unavailable["path"]).read_text(encoding="utf-8")
    assert "HistoryProducerOwner::from_admission(&admission)?" in torii
    assert "read::with_state_view(&state, control," in torii
    assert '(StatusCode::REQUEST_TIMEOUT, "request_timeout")' in torii
    assert '(StatusCode::SERVICE_UNAVAILABLE, "sccp_capacity")' in torii
    assert '_ => (StatusCode::SERVICE_UNAVAILABLE, "sccp_unavailable")' in torii
    assert 'SccpNativeReadError::Pruned(_) => (StatusCode::GONE, "sccp_pruned")' in torii
    native = (ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/read/native.rs").read_text(encoding="utf-8")
    assert "pub fn control_proof(" in native and "pub fn message_proof(" in native
    assert "let view = state.try_view_once()?;" in native
    controls = entry(CENSUS, "sccp.native_read_controls")
    assert controls["status"] == "not_a_gate" and controls["attribution"] == "read"
    assert "not an invalid-evidence verdict" in controls["note"]
    assert "deadline_ms copied from and compared against the committed message record" in controls["note"]
    assert "Instant::now() >= control.deadline" in native
    execution = (ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/forgery/execution.rs").read_text(encoding="utf-8")
    assert "VerificationControl::Synchronous," in execution
    assert "stx.arm_local_storage_refusal(local);" in execution
    pin_shape = entry(CENSUS, "sccp.committee_pin_shape")
    assert pin_shape["status"] == "not_a_gate" and pin_shape["symbol"] == "ZeroPinCoordinate"
    assert "Shape validation does not authenticate a committee" in pin_shape["note"]
    features = entry(CENSUS, "feature.zk_halo2_family")
    assert features["status"] == "open"
    assert features["symbol"] == "zk-ipa-native = []"
    assert "semantic parity" in features["open_reason"]
    assert CENSUS["features"]["iroha_core"]["zk-preverify"]["class"] == "validity_gate"
    assert "zk-halo2" not in CENSUS["features"]["iroha_core"]


def test_current_sccp_incomplete_entries_reject_stale_anchors_and_false_completion(tree_scan) -> None:
    """Current source evidence must survive detector-name retirement without becoming done."""
    stale = edited(lambda census: entry(census, "sccp.qualification").update(
        symbol="fn route_registration_readiness()"))
    assert_fails(tree_scan, stale, "symbol 'fn route_registration_readiness()' does not occur")
    absent = edited(lambda census: entry(census, "sccp.unavailable")["anchors"][0].update(
        path="crates/iroha_core/src/smartcontracts/isi/sccp/read/absent_control.rs"))
    assert_fails(tree_scan, absent, "absent_control.rs")
    for identifier in ("sccp.qualification", "sccp.unavailable"):
        done = edited(lambda census: entry(census, identifier).update(status="done"))
        assert_fails(tree_scan, done, f"entry {identifier}: a done entry names a test or a removed construct")


def test_source_lookup_and_phone_key_checks_have_distinct_authorities() -> None:
    """Lookup hints and deterministic input rejection are not qualification gates."""
    lookup = entry(CENSUS, "plonk.source_lookup")
    assert lookup["status"] == "not_a_gate"
    assert "from_artifact_v2_cancellable" in lookup["note"]
    assert len(lookup["sites"]) == 5
    key_check = entry(CENSUS, "ram_lfe.phone_key_algorithm")
    assert key_check["status"] == "not_a_gate"
    assert key_check["sites"] == [["crates/iroha_crypto/src/ram_lfe/phone_control.rs",
                                     "unavailable", "unsupported", 3]]
    assert ["crates/iroha_crypto/src/ram_lfe/phone_control.rs",
            "unavailable", "local_resource", 2] in entry(CENSUS, "ram_lfe.local_resource")["sites"]


def test_compiled_source_profiles_are_a_kagemusha_only_digest_gate() -> None:
    """A compiled built-in profile is a binary-digest admission, never a strict lookup hint.

    It is recorded out of plan only while KAGEMUSHA is its sole production caller; a caller
    of the delivery plan makes it open F.4 work, so this test fails until the census is
    read again.
    """
    builtin = entry(CENSUS, "plonk.builtin_source_profile")
    assert builtin["kind"] == "digest" and builtin["status"] == "out_of_plan"
    assert "becomes open F.4 work" in builtin["note"]
    rows = {(site[0], site[1], site[2]) for site in builtin["sites"]}
    assert rows == {
        ("crates/iroha_plonk/src/keys/keygen/builtin.rs", "digest_identity", "source"),
        ("crates/iroha_plonk/src/keys/keygen/builtin.rs", "unavailable", "unsupported"),
        ("crates/iroha_plonk/src/keys/keygen/builtin/generated.rs", "digest_identity", "source"),
    }
    lookup = {site[0] for site in entry(CENSUS, "plonk.source_lookup")["sites"]}
    assert not {row[0] for row in rows} & lookup
    api = ("BuiltinSourceProfileV1", "BuiltinSourceMemberV1", "builtin_source_identity_v1")
    callers = set()
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith("crates/iroha_plonk/") or CHECKER["TEST_PATH"].search(
            relative.split("/src/", 1)[1]
        ):
            continue
        if any(name in path.read_text(encoding="utf-8", errors="replace") for name in api):
            callers.add(relative)
    assert callers, "the compiled profile API has no caller; reread the entry"
    assert all("kagemusha" in caller for caller in callers), sorted(callers)


def test_slash_reads_of_the_node_local_staking_projection_stay_open() -> None:
    """The slash path compares node-local staking fields: an open F.4 dependence."""
    nexus = entry(CENSUS, "cfg.nexus.policy")
    assert nexus["status"] == "open" and nexus["owner"] == "F.4"
    staking = "crates/iroha_core/src/smartcontracts/isi/staking.rs"
    rows = {site[2] for site in nexus["sites"] if site[0] == staking and site[1] == "node_policy_read"}
    assert {"staking.max_slash_bps", "staking.max_stake_shares_per_validator",
            "staking.slash_sink_account_id"} <= rows
    source = (ROOT / staking).read_text(encoding="utf-8")
    assert "let max_slash_bps = state_transaction.nexus.staking.max_slash_bps;" in source
    assert "slash_within_limit(amount, &slashable_exposure, max_slash_bps)?" in source


def test_refresh_rewrites_counts_only(tmp_path: Path) -> None:
    write(tmp_path, "crates/iroha_core/src/zk_gate.rs",
          'pub fn f() { let _ = (std::env::var("A_GATE"), std::env::var("A_GATE")); }')
    census = {
        "entries": [{"id": "e", "sites": [["crates/iroha_core/src/zk_gate.rs", "env_read", "A_GATE", 1],
                                         ["crates/iroha_core/src/gone.rs", "env_read", "GONE", 1]]}],
        "features": {},
    }
    changes = CHECKER["refresh_counts"](Scan(tmp_path), census)
    assert changes == ["e: crates/iroha_core/src/zk_gate.rs env_read A_GATE 1 -> 2"]
    assert census["entries"][0]["sites"][0][3] == 2
    # A row that is gone is left for a maintainer to reconcile.
    assert census["entries"][0]["sites"][1] == ["crates/iroha_core/src/gone.rs", "env_read", "GONE", 1]


def test_cli_reports_drift_with_a_nonzero_status(tmp_path: Path, capsys) -> None:
    write(tmp_path, "crates/iroha_core_zk/src/lib.rs",
          'pub fn verify() -> bool { std::env::var("ZK_SKIP_VERIFY").is_err() }')
    census = copy.deepcopy(CENSUS)
    census["entries"] = []
    census["config_catalogs"] = []
    census["features"] = {}
    write(tmp_path, CHECKER["DEFAULT_CENSUS"], json.dumps(census))
    write(tmp_path, CHECKER["RESOURCE_CONTRACT"], json.dumps({"catalogs": []}))
    write(tmp_path, CHECKER["DELIVERY_GRAPH"], json.dumps(GRAPH))
    assert CHECKER["main"](["--root", str(tmp_path)]) == 1
    assert "unlisted site" in capsys.readouterr().err
    assert CHECKER["main"](["--root", str(tmp_path), "--propose"]) == 0
    assert '"ZK_SKIP_VERIFY"' in capsys.readouterr().out
