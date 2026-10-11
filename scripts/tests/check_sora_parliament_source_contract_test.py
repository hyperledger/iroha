"""Mutation coverage for constructor-authenticated Parliament source boundaries."""

from __future__ import annotations

import ast
import inspect
import re
import subprocess
import sys

import pytest

from scripts.formal import check_sora_parliament_source_contract as guard


OPAQUE_OWNERS = (
    (
        "crates/iroha_core/src/tle_release.rs",
        "AuthorizedTleReleaseContextV1",
        "/// Authorize a TLE release from one point-in-time committed state view.",
        "opaque release authorization",
        guard.require_opaque_release_authorizations,
    ),
    (
        "crates/iroha_core_timed_ovn/src/tle.rs",
        "ValidatedTleReleaseProjectionV1",
        "/// Closed failures while validating a public authenticated-broker projection.",
        "validated broker projection",
        guard.require_opaque_release_projection,
    ),
    (
        "crates/iroha_core/src/tle_release/casting.rs",
        "AuthorizedTimedOvnCastingContextV1",
        "/// Authorize and replay-validate one public timed-OVN casting context.",
        "opaque casting authorization",
        guard.require_opaque_casting_authorization,
    ),
)


@pytest.mark.parametrize("owner", OPAQUE_OWNERS, ids=lambda owner: owner[1])
def test_opaque_authorization_source_baseline(owner: tuple) -> None:
    """The actual production owner passes before any mutation is considered."""
    path, _, _, _, check = owner
    check(guard.read(path))


@pytest.mark.parametrize("owner", OPAQUE_OWNERS, ids=lambda owner: owner[1])
@pytest.mark.parametrize("trait", ("SerializePayload", "DeserializePayload"))
@pytest.mark.parametrize("implementation", ("derive", "manual"))
def test_opaque_authorizations_reject_payload_codecs(
    owner: tuple, trait: str, implementation: str
) -> None:
    """Neither a derive attribute nor an impl may make authorized state decodable."""
    path, name, end, label, check = owner
    source = guard.read(path)
    check(source)
    if implementation == "derive":
        declaration = f"pub struct {name} {{"
        assert source.count(declaration) == 1
        mutated = source.replace(
            declaration, f"#[derive(norito::{trait})]\n{declaration}", 1
        )
    else:
        assert source.count(end) == 1
        lifetime = "<'_>" if trait == "DeserializePayload" else ""
        mutated = source.replace(
            end, f"impl norito::{trait}{lifetime} for {name} {{}}\n\n{end}", 1
        )
    assert mutated != source
    with pytest.raises(RuntimeError, match=re.escape(f"{path}: {label} exposes {trait!r}")):
        check(mutated)


def test_opaque_checks_are_connected_to_production_entrypoint() -> None:
    """The production check invokes both independently tested authorization gates."""
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name)]
    assert calls.count("require_opaque_release_authorizations") == 1
    assert calls.count("require_opaque_release_projection") == 1
    assert calls.count("require_opaque_casting_authorization") == 1


TYPES_PATH = "crates/iroha_data_model/src/governance/types.rs"
WORLD_PATH = "crates/iroha_core/src/smartcontracts/isi/world.rs"
ENDORSEMENT_ORDER = """!public_finding
                    .endorsing_assignments
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])"""


def test_complete_source_contract_baseline() -> None:
    """Exercise every production binding so drift outside the focused gates is visible."""
    assert guard.main() == 0


BEACON_CORE_PATH = "crates/iroha_core/src/beacon.rs"
STATE_TESTS_PATH = "crates/iroha_core/src/state/tests.rs"
PULSE_FIXTURE_PATHS = (
    BEACON_CORE_PATH,
    "crates/iroha_core/src/beacon/tests.rs",
    STATE_TESTS_PATH,
    guard.BEACON_PRODUCER_PATH,
    guard.BEACON_PRODUCER_TESTS_PATH,
    guard.BEACON_EXECUTION_TESTS_PATH,
)


def _pulse_fixture_sources() -> dict[str, str]:
    return {path: guard.read(path) for path in PULSE_FIXTURE_PATHS}


def _check_pulse_fixtures(sources: dict[str, str]) -> None:
    guard.require_beacon_parliament_pulse_fixtures(
        *(sources[path] for path in PULSE_FIXTURE_PATHS)
    )


def test_beacon_parliament_fixture_module_is_connected_to_production_guard() -> None:
    """The full checker follows the compiled modules, admission and both consumers."""
    _check_pulse_fixtures(_pulse_fixture_sources())
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_beacon_parliament_pulse_fixtures") == 1


BEACON_TEST_MODULE = "#[cfg(test)]\npub(crate) mod tests;"
PRODUCER_TEST_MODULE = "#[cfg(test)]\nmod tests;"
EXECUTION_TEST_MODULE = '#[path = "execution_tests.rs"]\nmod execution_tests;'


@pytest.mark.parametrize("path,anchor,replacement", (
    (BEACON_CORE_PATH, BEACON_TEST_MODULE, ""),
    (BEACON_CORE_PATH, BEACON_TEST_MODULE, "#[cfg(any())]\npub(crate) mod tests;"),
    (BEACON_CORE_PATH, BEACON_TEST_MODULE,
     '#[path = "disconnected.rs"]\n#[cfg(test)]\npub(crate) mod tests;'),
    (BEACON_CORE_PATH, BEACON_TEST_MODULE, "#[cfg(test)]\npub(crate) mod other_tests;"),
    (guard.BEACON_PRODUCER_PATH, PRODUCER_TEST_MODULE, ""),
    (guard.BEACON_PRODUCER_PATH, PRODUCER_TEST_MODULE, "#[cfg(any())]\nmod tests;"),
    (guard.BEACON_PRODUCER_TESTS_PATH, EXECUTION_TEST_MODULE, ""),
    (guard.BEACON_PRODUCER_TESTS_PATH, EXECUTION_TEST_MODULE,
     '#[path = "disconnected.rs"]\nmod execution_tests;'),
))
def test_beacon_parliament_fixture_module_cannot_be_disconnected(
    path: str, anchor: str, replacement: str,
) -> None:
    """Intact fixture text is insufficient when its compiled owner is removed."""
    sources = _pulse_fixture_sources()
    assert sources[path].count(anchor) == 1
    sources[path] = sources[path].replace(anchor, replacement, 1) + "\n/* " + anchor + " */\n"
    with pytest.raises(RuntimeError, match="original test module"):
        _check_pulse_fixtures(sources)


INDEX_ADMISSION_TEST = "fn parliament_required_beacon_slot_index_tracks_lifecycle_and_removal()"


@pytest.mark.parametrize("path,declaration,original,replacement", (
    (guard.BEACON_PRODUCER_TESTS_PATH,
     "fn all_seats_drive_real_shares_once_and_followers_use_only_transported_pulse()",
     "Err(NativeBeaconError::AwaitingShares { height: 9 })", "Err(NativeBeaconError::Context)"),
    (guard.BEACON_PRODUCER_TESTS_PATH,
     "fn all_seats_drive_real_shares_once_and_followers_use_only_transported_pulse()",
     "control::verify_result(&witness, None).is_err()", "true"),
    (guard.BEACON_PRODUCER_TESTS_PATH,
     "fn native_active_session_from_a_foreign_real_committee_refuses_before_signing()",
     "Err(NativeBeaconError::Source(_))", "Ok(None)"),
    (guard.BEACON_PRODUCER_TESTS_PATH,
     "fn native_active_session_from_a_foreign_real_committee_refuses_before_signing()",
     "count.load(Ordering::SeqCst) == 0", "true"),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn transported_pulse_executes_once_and_cold_replay_reproduces_the_certified_result()",
     'expect("cold executor reproduces the original certified pulse writes")', "unwrap()"),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn transported_pulse_executes_once_and_cold_replay_reproduces_the_certified_result()",
     'expect("completed publication is idempotent")', "unwrap()"),
    (STATE_TESTS_PATH, INDEX_ADMISSION_TEST,
     ".put_parliament_attempt(attempt.clone())", ".unchecked_parliament_attempt(attempt.clone())"),
    (STATE_TESTS_PATH, INDEX_ADMISSION_TEST,
     'expect("persist the live sortition request")', "unwrap()"),
    (STATE_TESTS_PATH, INDEX_ADMISSION_TEST,
     "crate::beacon::tests::pending_batched_sortition_attempt(", "other_pending_attempt("),
    (STATE_TESTS_PATH, INDEX_ADMISSION_TEST,
     ".fail_body_election_no_roster(", ".retain_live_request("),
    (guard.BEACON_PRODUCER_TESTS_PATH, "fn fixture() -> Fixture {",
     "(BeaconSessionId::for_network_v1(&chain.network_id()), 9)",
     "(BeaconSessionId::for_network_v1(&chain.network_id()), 10)"),
    (guard.BEACON_PRODUCER_TESTS_PATH, "fn fixture() -> Fixture {",
     ".put_parliament_attempt(attempt)", ".unchecked_parliament_attempt(attempt)"),
    (guard.BEACON_PRODUCER_TESTS_PATH, "fn fixture() -> Fixture {",
     "crate::beacon::tests::pending_batched_sortition_attempt(", "other_pending_attempt("),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn same_predecessor(fixture: &Fixture, demand: bool) -> CertifiedTestChain {",
     ".put_parliament_attempt(attempt)", ".unchecked_parliament_attempt(attempt)"),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn same_predecessor(fixture: &Fixture, demand: bool) -> CertifiedTestChain {",
     "crate::beacon::tests::pending_batched_sortition_attempt(", "other_pending_attempt("),
    (guard.BEACON_PRODUCER_TESTS_PATH,
     "fn wrong_source_sender_and_proof_never_change_the_owned_round()",
     ".parliament_unavailable_beacon_pulse_slots", ".global_beacon_pulse_slots"),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn transported_pulse_executes_once_and_cold_replay_reproduces_the_certified_result()",
     "invalid(&mut worker, &replay, &missing);", "let _ = &missing;"),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn native_pulse_refusals_preserve_the_exact_predecessor_and_require_actual_work()",
     "let unrequested = same_predecessor(&fixture, false);",
     "let unrequested = same_predecessor(&fixture, true);"),
    (guard.BEACON_EXECUTION_TESTS_PATH,
     "fn same_predecessor(fixture: &Fixture, demand: bool) -> CertifiedTestChain {",
     "if demand {", "if true {"),
))
def test_beacon_parliament_fixture_admission_cannot_be_moved_to_disconnected_text(
    path: str, declaration: str, original: str, replacement: str,
) -> None:
    """Each actual fixture retains its own admission, demand and refusal assertion."""
    sources = _pulse_fixture_sources()
    body = guard.rust_item(sources[path], declaration, path)
    assert original in body
    changed = sources[path].replace(body, body.replace(original, replacement), 1)
    sources[path] = changed + "\n/* " + original + " */\n"
    with pytest.raises(RuntimeError, match=re.escape(path)):
        _check_pulse_fixtures(sources)


def test_encrypted_beacon_dkg_source_baseline() -> None:
    """The current public model and reducer require signed private edges."""
    guard.require_encrypted_beacon_dkg_source(
        guard.read("crates/iroha_data_model/src/consensus.rs"),
        guard.read("crates/iroha_core/src/beacon.rs"),
    )


@pytest.mark.parametrize("old,new", (
    ("snapshot.record(),", "foreign.record(),"),
    ("&self.budget,", "&foreign_budget,"),
    ("self.finalized = Some(finalized);", "self.finalized = None;"),
    ("return Err(GlobalThresholdBeaconError::IncompleteDkgEdges.into());", "return Ok(existing);"),
))
def test_encrypted_beacon_dkg_finalization_retains_original_owner(old: str, new: str) -> None:
    """Finalization cannot substitute its source, funding, owner or all-edge rejection."""
    model = guard.read("crates/iroha_data_model/src/consensus.rs")
    path = "crates/iroha_core/src/beacon.rs"
    core = guard.read(path)
    body = guard.section(
        core, "    /// Finalize only after every frozen dealer/recipient edge is accepted.",
        "\n}\n\nfn validate_dkg_session(", path,
    )
    assert body.count(old) == 1
    changed = core.replace(body, body.replace(old, new, 1), 1)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_encrypted_beacon_dkg_source(model, changed + "\n/* " + old + " */\n")


@pytest.mark.parametrize("old,new", (
    ("budget.try_reserve_bytes(demand.total_bytes()?)?", "foreign.try_reserve_bytes(demand.total_bytes()?)?"),
    ("Construction::with_demand(demand, budget, &mut reservation)?", "Construction::with_demand(demand, foreign, &mut reservation)?"),
    ("construction.edges(source.encrypted_shares.iter())?", "construction.edges(foreign.encrypted_shares.iter())?"),
    ("construction.acceptances(source.share_acceptances.iter())?", "construction.acceptances(foreign.share_acceptances.iter())?"),
    ("finalized_at_height: height,", "finalized_at_height: 0,"),
    ("if construction.reservation.remaining_bytes() != 0", "if false"),
))
def test_encrypted_beacon_dkg_retained_constructor_cannot_lose_custody(
    monkeypatch: pytest.MonkeyPatch, old: str, new: str,
) -> None:
    """The connected constructor keeps exact nested rows and its original reservation."""
    path = guard.BEACON_DKG_OWNER_PATH
    original_read = guard.read
    source = original_read(path)
    body = guard.rust_item(source, "pub(in crate::beacon) fn retain_finalized_dkg(", path)
    assert body.count(old) == 1
    changed = source.replace(body, body.replace(old, new, 1), 1)
    monkeypatch.setattr(guard, "read", lambda requested: changed + "\n/* " + old + " */\n"
                        if requested == path else original_read(requested))
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_encrypted_beacon_dkg_source(
            original_read("crates/iroha_data_model/src/consensus.rs"),
            original_read("crates/iroha_core/src/beacon.rs"),
        )


@pytest.mark.parametrize(
    "original,replacement",
    (
        ("pub mlkem768_public_key: Vec<u8>,", "pub legacy_key: Vec<u8>,"),
        ("pub encrypted_share: Vec<u8>,", "pub revealed_share: Vec<u8>,"),
        ("pub share_acceptances: Vec<GlobalThresholdBeaconDkgShareAcceptanceV1>,",
         "pub complaint_responses: Vec<GlobalThresholdBeaconDkgShareAcceptanceV1>,"),
    ),
)
def test_encrypted_beacon_dkg_rejects_retired_public_layout(
    original: str, replacement: str
) -> None:
    """No legacy key, plaintext share or complaint-response alias is admitted."""
    model = guard.read("crates/iroha_data_model/src/consensus.rs")
    core = guard.read("crates/iroha_core/src/beacon.rs")
    assert original in model
    with pytest.raises(RuntimeError, match="retired public DKG layout|exact signed encrypted DKG fields"):
        guard.require_encrypted_beacon_dkg_source(
            model.replace(original, replacement, 1), core
        )


@pytest.mark.parametrize(
    "original,replacement",
    (
        ("|| self.encrypted_shares.len() != all_edges",
         "&& self.encrypted_shares.len() != all_edges"),
        ("|| self.share_acceptances.len() != all_edges",
         "&& self.share_acceptances.len() != all_edges"),
        ("|| transcript.share_acceptances.len() != all_edges",
         "&& transcript.share_acceptances.len() != all_edges"),
    ),
)
def test_encrypted_beacon_dkg_rejects_partial_finalization(
    original: str, replacement: str
) -> None:
    """Neither public finalization nor readback can accept incomplete edges."""
    model = guard.read("crates/iroha_data_model/src/consensus.rs")
    core = guard.read("crates/iroha_core/src/beacon.rs")
    assert original in core
    with pytest.raises(RuntimeError, match="missing modeled source binding"):
        guard.require_encrypted_beacon_dkg_source(
            model, core.replace(original, replacement, 1)
        )


@pytest.mark.parametrize("declaration,old,new", (
    ("shape", "validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier)?;", ""),
    ("shape", "validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier)?;",
     "validation::DkgSnapshotRef::from(transcript).validate_with_verifier(other)?;"),
    ("shape", "validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier)?;",
     "let _ = validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier);"),
    ("geometry", "|| transcript.encrypted_shares.len() != all_edges",
     "&& transcript.encrypted_shares.len() != all_edges"),
    ("geometry", "return Err(GlobalThresholdBeaconError::IncompleteDkgEdges);", "return Ok(());"),
    ("shape", ") != transcript.event_hash", ") != record.transcript_hash"),
    ("shape", "validate_adaptive_dkg_geometry(record)?;", ""),
    ("shape", "validate_adaptive_dkg_geometry(record)?;", "validate_adaptive_dkg_geometry(foreign)?;"),
    ("geometry", ".eq(1..=session.committee_size)", ".eq(1..session.committee_size)"),
))
def test_encrypted_beacon_dkg_retains_original_admission_and_event_commitment(
    declaration: str, old: str, new: str,
) -> None:
    """Readback retains the caller's resource refusal and complete signed edge commitment."""
    model = guard.read("crates/iroha_data_model/src/consensus.rs")
    core = guard.read(BEACON_CORE_PATH)
    guard.require_encrypted_beacon_dkg_source(model, core)
    name = ("fn validate_adaptive_dkg_geometry(" if declaration == "geometry" else
            "fn validate_adaptive_dkg_shape<V: validation::DkgSignatureVerifier>(")
    body = guard.rust_item(core, name, BEACON_CORE_PATH)
    assert body.count(old) == 1
    changed = core.replace(body, body.replace(old, new, 1), 1)
    assert changed != core
    with pytest.raises(RuntimeError, match=re.escape(BEACON_CORE_PATH)):
        guard.require_encrypted_beacon_dkg_source(model, changed + "\n/* " + old + " */\n")


RUNTIME_DEPS_PATH = "crates/irohad/src/main/runtime_deps.rs"
EXPIRED_READINESS_TEST = (
    "fn threshold_signer_startup_readiness_skips_expired_history_and_rejects_mismatch() {"
)


def test_threshold_signer_readiness_source_baseline_and_entrypoint() -> None:
    """The current active and retained custody checks remain connected to the full guard."""
    guard.require_threshold_signer_startup_readiness(guard.read(RUNTIME_DEPS_PATH))
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_threshold_signer_startup_readiness") == 1


@pytest.mark.parametrize("declaration,old,new", (
    (EXPIRED_READINESS_TEST, "threshold_signer_readiness_fixture_v1(14)",
     "threshold_signer_readiness_fixture_v1(13)"),
    (EXPIRED_READINESS_TEST, "fixture.active_key_session_id,", "fixture.retained_key_session_id,"),
    (EXPIRED_READINESS_TEST, "fixture.active_participant_index,", "fixture.retained_participant_index,"),
    (EXPIRED_READINESS_TEST, "vec![(", "vec![(fixture.retained_key_session_id, 2), ("),
    (EXPIRED_READINESS_TEST, "exact_signer.sign_calls.load(Ordering::Acquire), 0",
     "exact_signer.sign_calls.load(Ordering::Acquire), 1"),
    (EXPIRED_READINESS_TEST, "mismatched_signer.sign_calls.load(Ordering::Acquire), 0",
     "mismatched_signer.sign_calls.load(Ordering::Acquire), 1"),
    (EXPIRED_READINESS_TEST, "CapabilityMode::MismatchedSeat", "CapabilityMode::Exact"),
    ("fn threshold_signer_startup_readiness_scans_active_and_deadline_retained_frozen_rosters() {",
     "fixture.retained_participant_index,", "fixture.active_participant_index,"),
    ("fn threshold_signer_startup_readiness_scans_active_and_deadline_retained_frozen_rosters() {",
     "expected.sort_unstable();", ""),
    ("fn require_parliament_tle_capability_for_local_seat_v1(",
     ".attest_partial_release_capability(session, participant_index)",
     ".sign_partial_release(context)"),
))
def test_threshold_signer_readiness_rejects_lost_exact_custody_controls(
    declaration: str, old: str, new: str,
) -> None:
    """Expiry, exact seat, mismatch and no-signing assertions cannot move to unrelated text."""
    source = guard.read(RUNTIME_DEPS_PATH)
    guard.require_threshold_signer_startup_readiness(source)
    body = guard.rust_item(source, declaration, RUNTIME_DEPS_PATH)
    assert old in body
    changed = source.replace(body, body.replace(old, new), 1)
    assert changed != source
    with pytest.raises(RuntimeError, match=re.escape(RUNTIME_DEPS_PATH)):
        guard.require_threshold_signer_startup_readiness(changed + "\n/* " + old + " */\n")


def test_threshold_signer_readiness_allows_historical_id_in_a_negative_assertion() -> None:
    """An unrelated owner or explicit inequality is not an expired-session expected call."""
    source = guard.read(RUNTIME_DEPS_PATH)
    body = guard.rust_item(source, EXPIRED_READINESS_TEST, RUNTIME_DEPS_PATH)
    negative = "\n        assert_ne!(fixture.active_key_session_id, fixture.retained_key_session_id);\n"
    changed = source.replace(body, body[:-1] + negative + "}", 1)
    assert changed != source
    guard.require_threshold_signer_startup_readiness(changed)


FEE_BOUNDARY_PATHS = ('crates/iroha_core/src/validation_fee.rs', 'crates/iroha_core/src/deferred_authority.rs', 'crates/iroha_core/src/retail_fee.rs', 'crates/iroha_core/src/smartcontracts/isi/asset.rs', 'crates/iroha_core/src/tx.rs', 'crates/iroha_core/src/lib.rs')


def _fee_boundary_sources() -> dict[str, str]:
    return {path: guard.read(path) for path in FEE_BOUNDARY_PATHS}


def _check_fee_boundary(sources: dict[str, str]) -> None:
    guard.require_signed_deferred_authority_and_native_fees(
        *(sources[path] for path in FEE_BOUNDARY_PATHS)
    )


def test_signed_staking_fee_boundary_baseline() -> None:
    """Signed staking authority and native payment fees keep their distinct owners."""
    _check_fee_boundary(_fee_boundary_sources())


@pytest.mark.parametrize(
    "path,original,replacement",
    (
        (
            "crates/iroha_core/src/validation_fee.rs",
            "crate::deferred_authority::reject_opaque_deferred_authority(groups, stx)",
            "crate::deferred_authority::unchecked_opaque_operations(groups, stx)",
        ),
        (
            "crates/iroha_core/src/deferred_authority.rs",
            "monetary_staking_wire_id(instruction)",
            "None::<&'static str>",
        ),
        (
            "crates/iroha_core/src/deferred_authority.rs",
            "Executable::IvmProved(proved)",
            "Executable::IvmProved(_)\n                if false",
        ),
        (
            "crates/iroha_core/src/deferred_authority.rs",
            "        BondPublicLaneStake,\n        FinalizePublicLaneUnbond,\n        SlashPublicLaneValidator,",
            "        BondPublicLaneStake,\n        NonMonetaryWithdrawal,\n        SlashPublicLaneValidator,",
        ),
        (
            "crates/iroha_core/src/smartcontracts/isi/asset.rs",
            "retail_payment: source_policy == NumericAssetTransferSourcePolicy::User",
            "retail_payment: false",
        ),
        (
            "crates/iroha_core/src/retail_fee.rs",
            "source.definition() != &policy.ds_asset_id", "false",
        ),
    ),
)
def test_signed_staking_fee_boundary_rejects_omitted_guards(
    path: str, original: str, replacement: str
) -> None:
    """Policy absence, nested overlays and actual payment assets cannot mask a leg."""
    sources = _fee_boundary_sources()
    assert original in sources[path]
    sources[path] = sources[path].replace(original, replacement, 1)
    with pytest.raises(RuntimeError, match="missing modeled source binding"):
        _check_fee_boundary(sources)


def test_proved_trigger_registration_cannot_downgrade_to_plain_ivm() -> None:
    """A proof-carrying trigger must fail before its bytecode is registered."""
    source = guard.read("crates/iroha_core/src/smartcontracts/isi/triggers/set.rs")
    guard.require_proved_trigger_rejection(source)
    missing_rejection = source.replace(
        "Executable::IvmProved(_) => return Err(Error::ProofBackedTriggerUnavailable)",
        "Executable::IvmProved(_) => unreachable!()",
        1,
    )
    with pytest.raises(RuntimeError, match=r"missing modeled source binding\(s\)"):
        guard.require_proved_trigger_rejection(missing_rejection)
    with pytest.raises(RuntimeError, match="downgraded to plain bytecode"):
        guard.require_proved_trigger_rejection(source + "\nlet bytes = proved.bytecode;\n")


def test_source_contract_cli_help() -> None:
    """The read-only command documents its prerequisites without checking sources."""
    result = subprocess.run(
        [sys.executable, guard.__file__, "--help"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "read-only" in result.stdout
    assert "no third-party dependencies" in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize(
    "order",
    (
        "!public_finding.endorsing_assignments.windows(2).all(|pair| pair[0] < pair[1])",
        "!public_finding\n\t.endorsing_assignments\n\t.windows(2)"
        "\n\t.all(|pair| pair[0] < pair[1])",
        "! public_finding . endorsing_assignments . windows ( 2 )"
        " . all ( | pair | pair [ 0 ] < pair [ 1 ] )",
    ),
)
def test_endorsement_order_accepts_rust_whitespace_changes(order: str) -> None:
    """Line wrapping and indentation do not alter strict supporter ordering."""
    source = guard.read(TYPES_PATH)
    guard.require_public_finding_endorsement_order(source)
    assert source.count(ENDORSEMENT_ORDER) == 1
    guard.require_public_finding_endorsement_order(source.replace(ENDORSEMENT_ORDER, order))


@pytest.mark.parametrize(
    "order",
    (
        ENDORSEMENT_ORDER.replace("<", "<="),
        ENDORSEMENT_ORDER.replace("<", ">"),
        ENDORSEMENT_ORDER.replace("windows(2)", "windows(3)"),
        ENDORSEMENT_ORDER.removeprefix("!"),
        ENDORSEMENT_ORDER.replace("pair[0] < pair[1]", "true"),
        "false",
    ),
)
def test_endorsement_order_rejects_weakened_certificate_guard(order: str) -> None:
    """Duplicates, reversed comparisons and removed checks cannot satisfy the contract."""
    source = guard.read(TYPES_PATH)
    guard.require_public_finding_endorsement_order(source)
    assert source.count(ENDORSEMENT_ORDER) == 1
    mutated = source.replace(ENDORSEMENT_ORDER, order)
    # An intact snippet elsewhere cannot stand in for certificate validation.
    mutated += "\n/* " + ENDORSEMENT_ORDER + " */\n"
    with pytest.raises(RuntimeError, match="certificate validation must reject supporters"):
        guard.require_public_finding_endorsement_order(mutated)


@pytest.mark.parametrize(
    "removed,replacement",
    (
        ("entry.request.request_height != current_height", "false"),
        ("ensure_parliament_logical_beacon_v1(", "unchecked_logical_beacon("),
        ("entry.request.target_seats != configured_target", "false"),
        (
            "ParliamentDecisionModeV1::HiddenBindingBallot",
            "ParliamentDecisionModeV1::PublicFinding",
        ),
        (
            "if !crate::governance::parliament::hidden_ballot_population",
            "if crate::governance::parliament::hidden_ballot_population",
        ),
        ("expected_candidates.len()", "0"),
        ("&& hidden_body_requested", "|| hidden_body_requested"),
        (".record_hidden_sortition_capacity_failure_batch(", ".register_sortition_request_batch("),
        (".register_sortition_request_batch(", ".record_hidden_sortition_capacity_failure_batch("),
        (
            "ParliamentNoResultKindV1::SortitionRetriesExhausted",
            "ParliamentNoResultKindV1::RandomnessRedrawBudgetExhausted",
        ),
    ),
)
def test_sortition_registration_rejects_missing_shared_guards(
    removed: str, replacement: str
) -> None:
    """Both registration paths retain the helper's height, authority and capacity checks."""
    source = guard.read_rust_with_includes(WORLD_PATH)
    guard.require_sortition_registration_guards(source)
    helper = guard.section(
        source,
        "    fn apply_parliament_sortition_request_batch_v1(",
        "    fn ensure_parliament_logical_beacon_v1(",
        WORLD_PATH,
    )
    assert helper.count(removed) == 1
    mutated = source.replace(helper, helper.replace(removed, replacement))
    with pytest.raises(RuntimeError, match=WORLD_PATH):
        guard.require_sortition_registration_guards(mutated)


@pytest.mark.parametrize("initial", (False, True))
@pytest.mark.parametrize("bypass", (False, True))
def test_sortition_registration_rejects_disconnected_admission(
    initial: bool, bypass: bool
) -> None:
    """An unused correct helper cannot authenticate a transition or substituted candidates."""
    source = guard.read_rust_with_includes(WORLD_PATH)
    guard.require_sortition_registration_guards(source)
    start, end, candidates = (
        (
            "gov::ParliamentLifecycleTransitionV1::RegisterInitialSortition => {",
            "gov::ParliamentLifecycleTransitionV1::RegisterSortitionRequest(payload) => {",
            "candidates,",
        )
        if initial
        else (
            "gov::ParliamentLifecycleTransitionV1::RegisterSortitionRequest(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(payload) => {",
            "expected_candidates,",
        )
    )
    branch = guard.section(source, start, end, WORLD_PATH)
    removed = "apply_parliament_sortition_request_batch_v1(" if bypass else candidates
    replacement = "unchecked_sortition_registration(" if bypass else "Vec::new(),"
    assert branch.count(removed) == 1
    mutated = source.replace(branch, branch.replace(removed, replacement))
    with pytest.raises(RuntimeError, match="must use shared sortition admission"):
        guard.require_sortition_registration_guards(mutated)


@pytest.mark.parametrize("path", (TYPES_PATH, WORLD_PATH))
def test_production_checker_enforces_repaired_guards(
    path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run actual negative source mutations through the complete production entrypoint."""
    original_read = guard.read
    source = original_read(path)
    if path == TYPES_PATH:
        assert source.count(ENDORSEMENT_ORDER) == 1
        mutated = source.replace(ENDORSEMENT_ORDER, ENDORSEMENT_ORDER.replace("<", "<="))
        message = "certificate validation must reject supporters"
    else:
        original_call = "no_result_kind = apply_parliament_sortition_request_batch_v1("
        assert original_call in source
        mutated = source.replace(
            original_call, "no_result_kind = unchecked_sortition_registration(", 1
        )
        message = "must use shared sortition admission"
    monkeypatch.setattr(
        guard, "read", lambda relative: mutated if relative == path else original_read(relative)
    )
    with pytest.raises(RuntimeError, match=message):
        guard.main()


STATE_PATH = "crates/iroha_core/src/state.rs"
PUBLICATION_PATH = "crates/iroha_core/src/state/publication.rs"
EXPIRY_CALL = (
    "Self::apply_block_start_private_settlement_expiry(&mut sb, now_h)\n"
    "            .map_err(StateBlockStartError::Storage)?;"
)
ENACTMENT_CALL = "Self::apply_block_start_parliament_enactments(&mut sb, now_h)?;"


def test_block_start_phase_helpers_preserve_original_order_and_custody() -> None:
    """The extracted production phases use the same original block before execution."""
    guard.require_block_start_enactment_phases(guard.read(STATE_PATH))
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_block_start_enactment_phases") == 1


@pytest.mark.parametrize("original,replacement", (
    ("            world_cut_capture: None,", "            world_cut_capture: Some(foreign_capture),"),
    ("                    drop(self.world_cut_capture.take());", "                    // lost original World-cut capture retirement"),
    ("                    mv::BlockRetirement::release_writers(self);", "                    drop(self.world_cut_capture.take()); mv::BlockRetirement::release_writers(self);"),
), ids=("foreign-world-cut-capture", "lost-world-cut-capture-retirement", "world-cut-refund-before-writer-release"))
def test_shared_start_construction_retains_world_cut_capture_retirement(original: str, replacement: str) -> None:
    """The new journal capture remains empty at construction and retires after original writers."""
    source = guard.read(STATE_PATH)
    guard.require_block_start_construction(source)
    assert source.count(original) == 1
    changed = source.replace(original, replacement, 1) + "\n/* " + original + " */\n"
    assert changed != source
    with pytest.raises(RuntimeError, match="original armed State owner"):
        guard.require_block_start_construction(changed)


CONSTRUCTION_PATH = "crates/iroha_core/src/state/state_block_construction.rs"


@pytest.mark.parametrize("target,original,replacement", (
    ("state", "construct_acquired_block(acquired, curr_block, Box::new)",
     "construct_acquired_block(other, curr_block, Box::new)"),
    ("state", "construct_acquired_block(acquired, curr_block, Box::new)",
     "construct_acquired_block(acquired, other_header, Box::new)"),
    ("state", "construct_acquired_block(acquired, curr_block, Box::new)",
     "construct_acquired_block(acquired, curr_block, discard_original)"),
    ("state", '#[path = "state/state_block_construction.rs"]',
     '#[path = "state/other_construction.rs"]'),
    ("helper", "let mut original = Some(acquired);", "let mut original = Some(other);"),
    ("helper", "finish_state_block_construction(|| {", "finish_state_block_construction(move || {"),
    ("fields", "                world,", "                world: World::default().block(),"),
    ("fields", "transactions: storage_transactions::TransactionsBlockField::new(transactions),",
     "transactions: storage_transactions::TransactionsBlockField::new(other_transactions),"),
    ("fields", "_da_rewind_releases: da_rewind_releases,",
     "_da_rewind_releases: foreign_releases,"),
    ("fields", "native_execution_tip: block_field::BlockField::new(native_execution_tip),",
     "native_execution_tip: block_field::BlockField::new(other_tip),"),
    ("fields", "_curr_block: curr_block,", "_curr_block: other_header,"),
    ("fields", "start_of_block_effects_applied: false,", "start_of_block_effects_applied: true,"),
    ("fields", "pending_parliament_telemetry_events\n                    .take()",
     "other_parliament_events\n                    .take()"),
    ("helper", "let block = StateBlock::from_fields(StateBlockFields {",
     "let block = StateBlockFields {"),
    ("helper", 'finish.take().expect("original State finish continuation")(block)',
     'finish.take().expect("original State finish continuation")(other_block)'),
    ("helper", "    finish()\n}", "    unreachable!()\n}"),
    ("state", "            fields: Some(fields),", "            fields: None,"),
    ("state", "        mv::BlockRetirement::release_writers(self);", "        // discarded original writers"),
), ids=(
    "foreign-acquisition", "foreign-header", "substitute-continuation", "foreign-helper-module",
    "substitute-held-owner", "move-owned-finish", "substitute-world", "substitute-membership",
    "substitute-da-rewind-releases", "substitute-native-tip", "substitute-carrier-header", "premature-start-flag", "substitute-parliament-buffer",
    "unarmed-final-handoff", "discard-final-original", "disconnected-outlined-finish",
    "empty-executing-owner", "lost-executing-retirement",
))
def test_shared_start_construction_retains_exact_original_owner(
    target: str, original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defining helper, original fields and armed continuation must all join."""
    source = guard.read(STATE_PATH)
    helper = guard.read(CONSTRUCTION_PATH)
    guard.require_block_start_enactment_phases(source)
    text = source if target == "state" else helper
    if target == "fields":
        fields = guard.section(text, "let block = StateBlock::from_fields(StateBlockFields {",
                               'finish.take().expect("original State finish continuation")(block)',
                               CONSTRUCTION_PATH)
        assert fields.count(original) == 1
        mutated = text.replace(fields, fields.replace(original, replacement, 1), 1)
    else:
        assert text.count(original) == 1
        mutated = text.replace(original, replacement, 1)
    # A disconnected intact spelling in a comment is not an original owner.
    mutated += "\n/* " + original + " */\n"
    if target == "state":
        source = mutated
    else:
        original_read = guard.read
        monkeypatch.setattr(guard, "read", lambda path:
                            mutated if path == CONSTRUCTION_PATH else original_read(path))
    with pytest.raises(RuntimeError, match="start (construction|phases)"):
        guard.require_block_start_enactment_phases(source)


@pytest.mark.parametrize("mutation", (
    "missing_expiry", "missing_enactment", "duplicate", "swapped",
    "wrong_height", "conditional", "late_before_flag", "late_after_execution",
))
def test_block_start_phase_calls_reject_disconnected_or_late_owners(mutation: str) -> None:
    """Valid Rust statement changes cannot disconnect helpers or defer them until after execution."""
    source = guard.read(STATE_PATH)
    guard.require_block_start_enactment_phases(source)
    if mutation == "missing_expiry":
        mutated = source.replace(EXPIRY_CALL, "", 1)
    elif mutation == "missing_enactment":
        mutated = source.replace(ENACTMENT_CALL, "", 1)
    elif mutation == "duplicate":
        mutated = source.replace(ENACTMENT_CALL, ENACTMENT_CALL * 2, 1)
    elif mutation == "swapped":
        mutated = source.replace(EXPIRY_CALL, "PHASE_SWAP", 1).replace(
            ENACTMENT_CALL, EXPIRY_CALL, 1).replace("PHASE_SWAP", ENACTMENT_CALL, 1)
    elif mutation == "wrong_height":
        mutated = source.replace(ENACTMENT_CALL, ENACTMENT_CALL.replace("now_h)", "now_h + 1)"), 1)
    elif mutation == "conditional":
        mutated = source.replace(ENACTMENT_CALL, "if false { " + ENACTMENT_CALL + " }", 1)
    else:
        anchor = ("        sb.start_of_block_effects_applied = true;" if mutation == "late_before_flag"
                  else "\n        let result = after_start(&mut sb, continuation).map_err(StateBlockStartError::Stage)?;")
        assert source.count(anchor) == 1
        mutated = source.replace(ENACTMENT_CALL, "", 1).replace(anchor, anchor + "\n        " + ENACTMENT_CALL, 1)
    assert mutated != source
    with pytest.raises(RuntimeError, match="start phases"):
        guard.require_block_start_enactment_phases(mutated)


@pytest.mark.parametrize("original,replacement", (
    ("barrier.manifest.expiry_height < now_h", "barrier.manifest.expiry_height <= now_h"),
    ("let mut expiry = sb.try_transaction()?;", "let mut expiry = sb.try_transaction().unwrap();"),
    ("expiry.apply();", "drop(expiry);"),
    ("*enact_at_height < now_h", "*enact_at_height > now_h"),
    (".get(&now_h)", ".get(&(now_h + 1))"),
    ("drop(enactment);", "enactment.apply();"),
    ("let mut enactment = sb.try_transaction()?;", "let mut enactment = sb.try_transaction().unwrap();"),
    ("let mut failure = sb.try_transaction()?;", "let mut failure = sb.try_transaction().unwrap();"),
    ("failure.apply();", "drop(failure);"),
    ("let due_parliament_certificates = sb", "let _ = sb.world.parliament_attempts.iter();\n        let due_parliament_certificates = sb"),
))
def test_block_start_phase_bodies_reject_changed_height_or_rollback(
    original: str, replacement: str,
) -> None:
    """Both helpers retain exact due selection, actual rollback, and terminal recording."""
    source = guard.read(STATE_PATH)
    guard.require_block_start_enactment_phases(source)
    helpers = guard.section(source,
        "    /// Release expired private locks inside their original block transaction.",
        "    /// Apply scheduled world transitions within their shared transaction.", STATE_PATH)
    assert original in helpers
    mutated = source.replace(helpers, helpers.replace(original, replacement))
    with pytest.raises(RuntimeError, match=STATE_PATH):
        guard.require_block_start_enactment_phases(mutated)



@pytest.mark.parametrize("original,replacement", (
    ("self.acquire_canonical_runtime_block(false)?", "self.acquire_canonical_runtime_block(false).unwrap()"),
    ("self.acquire_canonical_runtime_block(false)?", "self.acquire_canonical_runtime_block(true)?"),
    ("before_start(&mut sb).map_err(StateBlockStartError::Stage)?", "before_start(&mut sb).unwrap()"),
    (EXPIRY_CALL, "Self::apply_block_start_private_settlement_expiry(&mut sb, now_h).unwrap();"),
    (ENACTMENT_CALL, "Self::apply_block_start_parliament_enactments(&mut sb, now_h).unwrap();"),
    ("\n        let result = after_start(&mut sb, continuation).map_err(StateBlockStartError::Stage)?", "\n        let result = after_start(&mut sb, continuation).unwrap()"),
    ("\n            let result = after_start(&mut sb, continuation).map_err(StateBlockStartError::Stage)?", "\n            let result = after_start(&mut sb, continuation).unwrap()"),
))
def test_block_start_admission_and_stage_refusals_remain_typed(
    original: str, replacement: str,
) -> None:
    """Local history admission precedes original effects; callback errors retain their class."""
    source = guard.read(STATE_PATH)
    guard.require_block_start_enactment_phases(source)
    constructor = guard.section(source,
        "    fn block_with_owned_start_stages<'state, E: std::fmt::Debug, T, R>(",
        "    /// Release expired private locks inside their original block transaction.", STATE_PATH)
    assert constructor.count(original) == 1
    mutated = source.replace(constructor, constructor.replace(original, replacement, 1), 1)
    with pytest.raises(RuntimeError, match="start phases"):
        guard.require_block_start_enactment_phases(mutated)


def test_production_checker_requires_the_extracted_start_phase_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A disconnected intact helper fails the real full checker entrypoint."""
    original_read = guard.read
    source = original_read(STATE_PATH)
    mutated = source.replace(ENACTMENT_CALL, "", 1)
    monkeypatch.setattr(guard, "read", lambda path: mutated if path == STATE_PATH else original_read(path))
    with pytest.raises(RuntimeError, match="start phases"):
        guard.main()



def test_parliament_direct_event_return_preserves_projection_before_drain() -> None:
    """The committed carrier's original preparation still owns the sole event drain."""
    guard.require_parliament_event_capture(guard.read(STATE_PATH))
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_parliament_event_capture") == 1


EVENT_PREPARATION = "    fn prepare_carrier_publication_events("
EVENT_CARRIER = "    fn apply_without_execution_inner("
EVENT_PRODUCTION = "    pub(crate) fn apply_without_execution_with_sumeragi_commit("


@pytest.mark.parametrize("declaration,original,replacement", (
    (EVENT_PRODUCTION, "authorization.map(|()| events)", "Ok(events)"),
    (EVENT_CARRIER, "Err(error) => return (Vec::new(), Err(error)),",
     "Err(error) => Vec::new(),"),
))
@pytest.mark.parametrize("decoy", ("", "/* {original} */", 'let _ = "{original}";'))
def test_carrier_events_keep_original_authorization_and_preparation_refusals(
    declaration: str, original: str, replacement: str, decoy: str,
) -> None:
    """Only live propagation in the original carrier can authorize its events."""
    source = guard.read(STATE_PATH)
    body = guard.rust_item(source, declaration, STATE_PATH)
    assert body.count(original) == 1
    changed = body.replace(original, decoy.format(original=original) + replacement, 1)
    with pytest.raises(RuntimeError, match=STATE_PATH):
        guard.require_parliament_event_capture(source.replace(body, changed, 1))


@pytest.mark.parametrize("mutation", (
    "early_drain", "substituted_return", "missing_projection", "foreign_carrier",
    "disconnected_preparation", "caller_drain",
))
def test_parliament_event_capture_rejects_early_drain_or_lost_projection(mutation: str) -> None:
    """No second drain, replacement result, foreign carrier or omitted projection is accepted."""
    source = guard.read(STATE_PATH)
    guard.require_parliament_event_capture(source)
    if mutation in ("disconnected_preparation", "caller_drain"):
        capture = guard.rust_item(source, EVENT_CARRIER, STATE_PATH)
        if mutation == "disconnected_preparation":
            changed = capture.replace(
                "self.prepare_carrier_publication_events(block.as_ref().header())",
                "Ok(self.world.take_external_events())", 1)
        else:
            changed = capture.replace(
                "        (events, Ok(()))",
                "        let _ = self.world.take_external_events();\n        (events, Ok(()))", 1)
    else:
        capture = guard.rust_item(source, EVENT_PREPARATION, STATE_PATH)
        if mutation == "early_drain":
            changed = capture.replace(
                "let parliament_transitions = self",
                "let _ = self.world.take_external_events();\n"
                "            let parliament_transitions = self", 1)
        elif mutation == "substituted_return":
            changed = capture.replace(
                "Ok(self.world.take_external_events())", "Ok(Vec::new())", 1)
        elif mutation == "missing_projection":
            changed = capture.replace(
                ".extend(parliament_transitions);", ".extend(Vec::new());", 1)
        else:
            changed = capture.replace("if header != self._curr_block {", "if false {", 1)
    assert changed != capture
    with pytest.raises(RuntimeError, match=STATE_PATH):
        guard.require_parliament_event_capture(source.replace(capture, changed, 1))


def test_prepared_parliament_commit_publication_baseline_and_entrypoint() -> None:
    """The actual prepared commit path and production checker share the same gate."""
    guard.require_parliament_commit_publication(guard.read(STATE_PATH))
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_parliament_commit_publication") == 1


def _replace_propagated_refusal(commit: str, call: str, anchor: str) -> str:
    """Unwrap the first propagated refusal after one call, whatever its layout."""
    start = commit.index(call)
    refusal = commit.index(anchor, commit.index("TransactionsBlockError::ExecutionDeferred(reason)", start))
    return commit[:refusal] + anchor.replace("?", ".unwrap()") + commit[refusal + len(anchor):]


@pytest.mark.parametrize("mutation", (
    "world_refusal", "world_validation_refusal", "foreign_world_effects", "shadowed_world_effects", "geometry_refusal", "world_drop", "hash_drop", "swapped_commits",
    "writer_removed", "generation_removed", "writer_early_drop", "conditional_world",
    "conditional_transitions", "transitions_after_snapshot",
    "replay_prevalidation", "authenticated_replay", "transitions_outside_replay_guard",
    "gauges_inside_replay_guard",
    "duplicate_publisher", "early_telemetry", "missing_cfg",
    "hash_prepare_refusal", "commit_lock_early_drop", "commit_lock_after_prepare",
    "state_commit_unlock_before_publication", "effect_owner_declared_after_commit_lock",
    "world_validation_removed", "world_validation_after_snapshot",
))
def test_prepared_commit_rejects_refusal_publication_or_replay_regressions(
    mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete statements cannot bypass refusal, publish early or recount historical replay."""
    state = guard.read(STATE_PATH)
    guard.require_parliament_commit_publication(state)
    commit = guard.read(PUBLICATION_PATH)
    telemetry_start = commit.index('        #[cfg(feature = "telemetry")]\n        {\n',
                                   commit.index("pending_public_lane_slash_observability.iter()"))
    telemetry_end = commit.index("        // Run the retained persistence plan", telemetry_start)
    telemetry = commit[telemetry_start:telemetry_end]
    transition = (
        "state_ref\n                        .telemetry\n"
        "                        .record_committed_parliament_transition(transition, no_result_kind);"
    )
    changed = commit
    if mutation == "world_refusal":
        changed = _replace_propagated_refusal(
            commit, "world_commit::PreparedWorldCommit::prepare_overlay_mutations(", "})?")
    elif mutation == "world_validation_refusal":
        changed = _replace_propagated_refusal(
            commit, "world_commit::PreparedWorldCommit::validate_prepared_overlay(", "})?;")
    elif mutation == "foreign_world_effects":
        original = "*world_effects = Some(effects);"
        assert commit.count(original) == 1
        changed = commit.replace(original,
                                 "/* " + original + " */ *world_effects = Some(other_effects);", 1)
    elif mutation == "shadowed_world_effects":
        original = "*world_effects = Some(effects);"
        assert commit.count(original) == 1
        changed = commit.replace(original,
                                 "let effects = replacement_effects;\n            " + original, 1)
    elif mutation == "geometry_refusal":
        geometry = guard.section(commit, "if let Err(err) = geometry_result {",
                                 "autoscale_start.elapsed()", STATE_PATH)
        assert geometry.count("return Err(TransactionsBlockError::from(err));") == 1
        changed = commit.replace(geometry,
                                 geometry.replace("return Err(TransactionsBlockError::from(err));", "", 1), 1)
    elif mutation == "hash_prepare_refusal":
        anchor = guard.section(commit, "            block_hashes\n                .try_prepare_publication()",
                               "            world\n                .try_prepare_frozen_publication()", PUBLICATION_PATH)
        anchor = "            block_hashes\n                .try_prepare_publication()" + anchor
        assert commit.count(anchor) == 1
        changed = commit.replace(anchor, "block_hashes.try_prepare_publication().unwrap();", 1)
    elif mutation == "commit_lock_early_drop":
        changed = commit.replace("        drop(_state_commit_lock);", "", 1).replace(
            "            world.publish_prepared();",
            "            drop(_state_commit_lock);\n            world.publish_prepared();", 1)
    elif mutation == "commit_lock_after_prepare":
        changed = commit.replace("        let _state_commit_lock = commit_fence.lock();", "", 1).replace(
            "            *tiered_snapshot = Some(tiered_publication::PreparedTieredSnapshot::prepare(",
            "        let _state_commit_lock = commit_fence.lock();\n"
            "            *tiered_snapshot = Some(tiered_publication::PreparedTieredSnapshot::prepare(", 1)
    elif mutation == "state_commit_unlock_before_publication":
        changed = commit.replace("        drop(_state_commit_lock);", "", 1).replace(
            "            transactions.publish_prepared();",
            "            drop(_state_commit_lock);\n            transactions.publish_prepared();", 1)
    elif mutation == "effect_owner_declared_after_commit_lock":
        owner = "effect_cleanup: effect_publication::StateEffectLocks::new(state),"
        fence = "commit_fence: state.state_commit_lock.defer_notifications(),"
        changed = commit.replace(owner, "", 1).replace(fence, fence + "\n            " + owner, 1)
    elif mutation in ("world_validation_removed", "world_validation_after_snapshot"):
        start = "        world_commit::PreparedWorldCommit::validate_prepared_overlay("
        end = "        if tiered_snapshot.is_none() {"
        validation = start + guard.section(commit, start, end, PUBLICATION_PATH)
        changed = commit.replace(validation, "", 1)
        if mutation == "world_validation_after_snapshot":
            changed = changed.replace("        if !*effects_captured {",
                                      validation + "        if !*effects_captured {", 1)
    elif mutation == "world_drop":
        changed = commit.replace("world.publish_prepared();", "drop(world);", 1)
    elif mutation == "hash_drop":
        changed = commit.replace("block_hashes.publish_prepared();", "drop(block_hashes);", 1)
    elif mutation == "swapped_commits":
        changed = commit.replace("world.publish_prepared();", "SWAP_COMMIT", 1).replace(
            "block_hashes.publish_prepared();", "world.publish_prepared();", 1).replace(
                "SWAP_COMMIT", "block_hashes.publish_prepared();", 1)
    elif mutation in ("writer_removed", "generation_removed", "writer_early_drop", "conditional_world"):
        publication = guard.section(commit, "        let autoscale_storage_hold =",
                                    "        if let Some(post) = lifecycle_post_publication.as_mut()", STATE_PATH)
        if mutation == "writer_removed":
            replacement = publication.replace("let _state_write_lock = write_fence.lock();", "", 1)
        elif mutation == "generation_removed":
            replacement = publication.replace("let _view_generation = publication_notice.begin();", "", 1)
        elif mutation == "writer_early_drop":
            replacement = publication.replace("transactions.publish_prepared();",
                "drop(_state_write_lock);\n            transactions.publish_prepared();", 1)
        else:
            replacement = publication.replace("world.publish_prepared();",
                                              "if false { world.publish_prepared(); }", 1)
        changed = commit.replace(publication, replacement, 1)
    elif mutation == "replay_prevalidation":
        old = "let telemetry_origin = this\n            .committed_telemetry_origin()\n            .map_err(|_| TransactionsBlockError::WorldCommitPreparation)?;"
        assert commit.count(old) == 1
        changed = commit.replace(old,
                                "let telemetry_origin = crate::sumeragi::executor::CommitTelemetryOrigin::Forward;", 1)
    elif mutation == "authenticated_replay":
        old = "if telemetry_origin == crate::sumeragi::executor::CommitTelemetryOrigin::Forward {"
        assert telemetry.count(old) == 1
        changed = commit.replace(telemetry, telemetry.replace(old, "if true {", 1), 1)
    elif mutation == "transitions_outside_replay_guard":
        declaration = "            if telemetry_origin == crate::sumeragi::executor::CommitTelemetryOrigin::Forward {"
        original = guard.rust_item(telemetry, declaration, PUBLICATION_PATH)
        assert original.endswith("}")
        moved = original.removeprefix(declaration).removesuffix("}")
        changed = commit.replace(telemetry, telemetry.replace(original, moved, 1), 1)
    elif mutation == "gauges_inside_replay_guard":
        boundary = "                }\n            }\n            if let Some(counts)"
        assert telemetry.count(boundary) == 1
        citizen = guard.rust_item(telemetry, "            if let Some(citizens_total)", PUBLICATION_PATH)
        moved = telemetry.replace(boundary, "                }\n            if let Some(counts)", 1)
        moved = moved.replace(citizen, citizen + "\n            }", 1)
        changed = commit.replace(telemetry, moved, 1)
    elif mutation in ("conditional_transitions", "missing_cfg", "duplicate_publisher"):
        assert telemetry.count(transition) == 1
        old, new = {
            "conditional_transitions": (transition, "if false {\n" + transition + "\n}"),
            "missing_cfg": ('#[cfg(feature = "telemetry")]', ""),
            "duplicate_publisher": (transition, transition + "\n" + transition),
        }[mutation]
        changed = commit.replace(telemetry, telemetry.replace(old, new, 1), 1)
    elif mutation == "transitions_after_snapshot":
        changed = commit.replace(telemetry, "", 1).replace(
            "        drop(_state_commit_lock);", telemetry + "        drop(_state_commit_lock);", 1)
    else:
        changed = commit.replace(telemetry, "", 1).replace(
            "        let _state_commit_lock = commit_fence.lock();", telemetry + "        let _state_commit_lock = commit_fence.lock();", 1)
    assert changed != commit
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda path:
                        changed if path == PUBLICATION_PATH else original_read(path))
    with pytest.raises(RuntimeError, match=PUBLICATION_PATH):
        guard.require_parliament_commit_publication(state)


@pytest.mark.parametrize("original,replacement", (
    ("        self.try_publish_inner()\n    }", "        self.try_publish_inner().discard()\n    }"),
    ("self.try_publish_inner().into_result()", "Ok(())"),
    (".unwrap_or_else(|| StatePublication::new(self.state_ref))",
     ".unwrap_or_else(|| StatePublication::new(other_state))"),
    ("if original.published {", "if false {"),
    ("self.attempt_original_publication(&mut original)",
     "self.attempt_original_publication(&mut replacement)"),
    ("self.recover_original_publication_fields();", ""),
    ("self.retire_original_publication_notices();", ""),
    ("self.publication = Some(original);\n        if terminal {",
     "self.publication = None;\n        if terminal {"),
    ("*published = true;", "*published = false;"),
))
def test_retained_publication_rejects_substituted_or_repeated_owners(
    original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both entrypoints reuse the exact original owner and publish its metrics once."""
    state = guard.read(STATE_PATH)
    guard.require_parliament_commit_publication(state)
    publication = guard.read(PUBLICATION_PATH)
    assert publication.count(original) == 1
    changed = publication.replace(original, replacement, 1)
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda path:
                        changed if path == PUBLICATION_PATH else original_read(path))
    with pytest.raises(RuntimeError, match=PUBLICATION_PATH):
        guard.require_parliament_commit_publication(state)


@pytest.mark.parametrize("original,replacement", (
    ("mod publication;", "mod other_publication;"),
    ("publication: Option<publication::StatePublication<'state>>",
     "publication: Option<OtherPublication<'state>>"),
))
def test_state_binds_its_retained_publication_module(original: str, replacement: str) -> None:
    """A correct detached module cannot stand in for the actual State publisher."""
    source = guard.read(STATE_PATH)
    assert source.count(original) == 1
    with pytest.raises(RuntimeError, match=STATE_PATH):
        guard.require_parliament_commit_publication(source.replace(original, replacement, 1))


@pytest.mark.parametrize("original,replacement", (
    ("let sccp_header = sb._curr_block;", "let sccp_header = foreign_header;"),
    ("crate::smartcontracts::isi::sccp::hook::apply_block_start(&mut sb, &sccp_header)",
     "crate::smartcontracts::isi::sccp::hook::apply_block_start(&mut other, &sccp_header)"),
    ("crate::smartcontracts::isi::sccp::hook::apply_block_start(&mut sb, &sccp_header)\n"
     "            .map_err(StateBlockStartError::Storage)?;", ""),
))
def test_sccp_heartbeat_keeps_the_original_ordered_start_owner(
    original: str, replacement: str,
) -> None:
    """The required SCCP heartbeat cannot be omitted or use a different State/header."""
    source = guard.read(STATE_PATH)
    assert source.count(original) == 1
    with pytest.raises(RuntimeError, match="start phases"):
        guard.require_block_start_enactment_phases(source.replace(original, replacement, 1))


@pytest.mark.parametrize("path,original,replacement", (
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "instance: source.instance(),", "instance: foreign.instance(),"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "height: source.height(),", "height: foreign.height(),"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "block_hash: source.block_hash(),", "block_hash: foreign.block_hash(),"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "epoch: **epoch,", "epoch: *foreign_epoch,"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "params: *params,", "params: foreign_params,"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "committee_digest: committee_digest(committee),", "committee_digest: foreign_digest,"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "writer.write_all(iroha_sumeragi::preimage::TAG_COMMITTEE)?;", "writer.write_all(b\"foreign domain\")?;"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "u32::try_from(committee.n())", "u32::try_from(0)"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "u16::try_from(bytes.len())", "u16::try_from(0)"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "if let Err(error) = self.retire_completed_replay(block, qc)",
     "if let Err(error) = self.retire_completed_replay(other_block, qc)"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "if let PublicationError::RecoveryRequired(reason) = &error",
     "if let PublicationError::Retryable(reason) = &error"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "self.recovery = Some(reason.clone());", "self.recovery = None;"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "return Err(error);", "return Ok(());"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     ".prepare_with_origin(block, qc, CommitTelemetryOrigin::HistoricalReplay)",
     ".prepare_with_origin(block, qc, CommitTelemetryOrigin::Forward)"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "live.telemetry_origin != Some(CommitTelemetryOrigin::HistoricalReplay)", "false"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "self.source != ReplaySource::capture(block.source())", "false"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "self.payload != Hash::new(block.payload().as_slice())", "false"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "self.qc != qc", "false"),
    ("crates/iroha_core/src/sumeragi/executor/replay.rs",
     "preparation::encoding_failure(&error)",
     "PublicationError::Retryable(error.to_string())"),
    ("crates/iroha_core/src/sumeragi/executor.rs",
     "mod replay;", "#[cfg(test)]\nmod replay;"),
    ("crates/iroha_core/src/sumeragi/executor.rs",
     "self.call(|reply| Request::Replay(block.clone(), commit_qc.clone(), reply))",
     "self.call(|reply| Request::Commit(block.clone(), commit_qc.clone(), reply))"),
    ("crates/iroha_core/src/sumeragi/executor.rs",
     "let _ = reply.send(self.replay(&block, &qc));",
     "let _ = reply.send(self.commit(&block, &qc));"),
    ("crates/iroha_core/src/sumeragi/executor.rs",
     "pending.matches(block, qc) && pending.telemetry_origin == origin",
     "pending.matches(block, qc)"),
    ("crates/iroha_core/src/sumeragi/executor.rs",
     "|original| original != origin", "|original| false"),
    ("crates/iroha_core/src/sumeragi/executor.rs",
     '.expect("original prepared telemetry origin")',
     ".unwrap_or(CommitTelemetryOrigin::Forward)"),
    ("crates/iroha_core/src/sumeragi/startup.rs",
     "Some(_) => super::executor::CommitTelemetryOrigin::HistoricalReplay",
     "Some(_) => super::executor::CommitTelemetryOrigin::Forward"),
    ("crates/iroha_core/src/state/output_seal.rs",
     "finalized.authorized.native_execution.telemetry_origin()",
     "crate::sumeragi::executor::CommitTelemetryOrigin::Forward"),
))
def test_parliament_replay_origin_retains_actual_authenticated_execution(
    path: str, original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replay classification cannot be manufactured, overwritten, or detached from finality."""
    state = guard.read(STATE_PATH)
    guard.require_parliament_commit_publication(state)
    source = guard.read(path)
    assert original in source
    changed = source.replace(original, replacement)
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda target:
                        changed if target == path else original_read(target))
    with pytest.raises(RuntimeError, match=path):
        guard.require_parliament_commit_publication(state)


@pytest.mark.parametrize("original,replacement", (
    ("-> Result<(), PublicationError>", "-> Result<(), String>"),
    ("require_body_admission(block, &self.execution_budget)?;", ""),
    ("require_qc_witness_admission(commit_qc, &self.execution_budget)?;", ""),
    ("require_body_admission(block, &self.execution_budget)?;",
     "require_body_admission(block, &self.execution_budget).map_err(|error| error.to_string())?;"),
    ("require_qc_witness_admission(commit_qc, &self.execution_budget)?;",
     "require_qc_witness_admission(commit_qc, &self.execution_budget).map_err(|error| error.to_string())?;"),
    (".unwrap_or_else(|| Err(control::stopped()))",
     ".unwrap_or_else(|| Err(control::stopped())).map_err(|error| error.to_string())"),
    (".unwrap_or_else(|| Err(control::stopped()))", ".unwrap_or(Ok(()))"),
))
def test_replay_dispatch_preserves_typed_admission_and_channel_refusal(
    original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both original admissions precede a serialized, unprojected publication result."""
    path = "crates/iroha_core/src/sumeragi/executor.rs"
    state = guard.read(STATE_PATH)
    guard.require_parliament_commit_publication(state)
    source = guard.read(path)
    replay = guard.rust_item(source, "    pub fn replay(", path)
    assert replay.count(original) == 1
    changed = source.replace(replay, replay.replace(original, replacement, 1), 1)
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda target:
                        changed if target == path else original_read(target))
    with pytest.raises(RuntimeError, match=path):
        guard.require_parliament_commit_publication(state)


BEACON_SOURCE_PATHS = (guard.EPOCH_BEACON_PATH, guard.BEACON_PRODUCER_PATH)


def _beacon_sources() -> dict[str, str]:
    return {path: guard.read(path) for path in BEACON_SOURCE_PATHS}


def test_indexed_beacon_requirement_gates_native_admission_and_production() -> None:
    """One committed demand gates follower admission, activation and witness building."""
    guard.require_parliament_beacon_requirement(*_beacon_sources().values())
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_parliament_beacon_requirement") == 1


@pytest.mark.parametrize("path,old,new", (
    (guard.EPOCH_BEACON_PATH,
     "record.session.adaptive_dkg.session.authority_generation != current.authority.generation",
     "false"),
    (guard.EPOCH_BEACON_PATH, "pulse: Some(pulse),", "pulse: None,"),
    (guard.BEACON_PRODUCER_PATH,
     "let parent = state.native_execution_tip().ok_or_else(|| {",
     "let parent = other.native_execution_tip().ok_or_else(|| {"),
    (guard.BEACON_PRODUCER_PATH,
     "if parent.core_hash() != context.parent_hash || parent.result() != context.parent_result",
     "if false"),
    (guard.BEACON_PRODUCER_PATH, "block_hash: parent.iroha_hash(),", "block_hash: other.iroha_hash(),"),
    (guard.BEACON_PRODUCER_PATH,
     "state.block_hashes().last() == Some(&parent.iroha_hash())", "true"),
    (guard.BEACON_PRODUCER_PATH, "parent.height() != applied.0", "false"),
    (guard.BEACON_PRODUCER_PATH, "|| !journal_matches", "|| false"),
    (guard.BEACON_PRODUCER_PATH,
     "let parent = self.parent_source(state, context, applied)?;",
     "let parent = self.parent_source(other, context, applied)?;"),
    (guard.BEACON_PRODUCER_PATH,
     "let parent = self.parent_source(state, context, applied)?;",
     "let parent = self.parent_source(state, context, applied).unwrap();"),
    (guard.EPOCH_BEACON_PATH, "(current.mode == ConsensusMode::Npos\n",
     "(current.mode != ConsensusMode::Npos\n"),
    (guard.EPOCH_BEACON_PATH, "height.checked_add(1) == Some(current.authorization.last_height))",
     "height.checked_add(2) == Some(current.authorization.last_height))"),
    (guard.EPOCH_BEACON_PATH, "Some(current.authorization.last_height))\n        ||",
     "Some(current.authorization.last_height))\n        &&"),
    (guard.EPOCH_BEACON_PATH, ".get(&(BeaconSessionId::for_network_v1(&current.network_id), height))",
     ".get(&(BeaconSessionId::for_network_v1(&current.network_id), height + 1))"),
    (guard.EPOCH_BEACON_PATH, "            .is_some_and(|attempts| !attempts.is_empty()))\n}",
     "            .is_some_and(|attempts| attempts.is_empty()))\n}"),
    (guard.EPOCH_BEACON_PATH, "let demanded = required(scope, world, current, height)?;",
     "let demanded = false;"),
    (guard.EPOCH_BEACON_PATH, "        return if demanded {", "        return if false {"),
    (guard.EPOCH_BEACON_PATH,
     '    if !demanded {\n        return Err("native beacon control witness was not requested".into());\n    }\n',
     ""),
    (guard.EPOCH_BEACON_PATH, "    validate_pending_slot(world, current, height)?;\n", ""),
    (guard.EPOCH_BEACON_PATH,
     "authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, peers)",
     "authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, foreign_peers)"),
    (guard.EPOCH_BEACON_PATH,
     ".parliament_unavailable_beacon_pulse_slots()\n        .get(&slot)\n"
     "        .is_some_and(|attempts| !attempts.is_empty())",
     ".parliament_unavailable_beacon_pulse_slots()\n        .get(&slot)\n"
     "        .is_some_and(|attempts| attempts.is_empty())"),
    (guard.BEACON_PRODUCER_PATH,
     "let active = if required {",
     "let active = if true {"),
    (guard.BEACON_PRODUCER_PATH,
     "            super::validate_pending_slot(state.world(), current, context.height)\n"
     "                .map_err(NativeBeaconError::Source)?;\n", ""),
    (guard.BEACON_PRODUCER_PATH,
     "        if self.prepared.as_ref() == Some(context) {\n            return Ok(());\n        }\n", ""),
    (guard.BEACON_PRODUCER_PATH, "        self.active = active;\n", "        self.active = None;\n"),
    (guard.BEACON_PRODUCER_PATH,
     "            Some(active) => Some(active.finalized.ok_or(NativeBeaconError::AwaitingShares {\n"
     "                height: context.height,\n            })?),",
     "            Some(active) => active.finalized,"),
    (guard.BEACON_PRODUCER_PATH,
     "        if self.prepared.as_ref() != Some(&source) {\n"
     "            return Err(NativeBeaconError::Context);\n        }\n", ""),
    (guard.BEACON_PRODUCER_PATH, "        let active = if required {",
     "        let _ = attempt.requires_beacon_pulse_at(slot);\n        let active = if required {"),
))
def test_beacon_requirement_rejects_lost_demand_or_unauthenticated_activation(
    path: str, old: str, new: str,
) -> None:
    """Demand, admission refusals, activation and missing-pulse refusal cannot be bypassed."""
    sources = _beacon_sources()
    guard.require_parliament_beacon_requirement(*sources.values())
    assert sources[path].count(old) == 1
    sources[path] = sources[path].replace(old, new, 1)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_parliament_beacon_requirement(*sources.values())


@pytest.mark.parametrize("path,old,new", (
    (guard.EPOCH_BEACON_PATH, "scope.validate().map_err(|error| error.to_string())?;", ""),
    (guard.EPOCH_BEACON_PATH, "if matches!(scope, SumeragiRootScope::Global)", "if true"),
    (guard.EPOCH_BEACON_PATH, "current.mode != ConsensusMode::Permissioned", "false"),
    (guard.EPOCH_BEACON_PATH,
     "        || current.authorization.beacon != BeaconEpochBindingV1::Bootstrap", "        || false"),
    (guard.EPOCH_BEACON_PATH,
     "            .parliament_required_beacon_pulse_slots()\n"
     "            .iter()\n            .next()\n            .is_some()", "            false"),
    (guard.EPOCH_BEACON_PATH, "world.active_global_beacon_key_session().is_some()", "false"),
    (guard.EPOCH_BEACON_PATH, "        || world.global_beacon_pulses().iter().next().is_some()", "        || false"),
    (guard.EPOCH_BEACON_PATH, "if !owns_global_control(scope, world, current)?", "if false"),
    (guard.EPOCH_BEACON_PATH, "(1, None) if supplied.is_none() => {}", "(1, None) => {}"),
    (guard.EPOCH_BEACON_PATH, "context.validate().map_err(str::to_owned)?;", ""),
    (guard.EPOCH_BEACON_PATH, "context.epoch != current.authorization.epoch", "false"),
    (guard.EPOCH_BEACON_PATH, "context.epoch_context_id != current.context_id()?", "false"),
    (guard.EPOCH_BEACON_PATH, "height < current.authorization.first_height", "false"),
    (guard.EPOCH_BEACON_PATH, "height > current.authorization.last_height", "false"),
    (guard.EPOCH_BEACON_PATH, "u64::try_from(hashes.hash_count())", "u64::try_from(other.hash_count())"),
    (guard.EPOCH_BEACON_PATH, "pulse.network_id != current.network_id", "false"),
    (guard.EPOCH_BEACON_PATH, "pulse.height != height", "false"),
    (guard.EPOCH_BEACON_PATH,
     "pulse.round != crate::beacon::GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1", "false"),
    (guard.EPOCH_BEACON_PATH, ".hash_at(index)", ".hash_at(0)"),
    (guard.BEACON_PRODUCER_PATH,
     "crate::sumeragi::lanes::routing::committed_root_scope(state.world())",
     "Some(SumeragiRootScope::Global)"),
    (guard.BEACON_PRODUCER_PATH,
     "let required = super::required(root_scope, state.world(), current, context.height)",
     "let required = super::required(SumeragiRootScope::Global, state.world(), current, context.height)"),
    (guard.BEACON_PRODUCER_PATH,
     "                NativeBeaconError::Source(\"native control requires immutable root scope\".into())",
     "                NativeBeaconError::Context"),
))
def test_beacon_requirement_preserves_authenticated_root_scope_and_parent_cut(
    path: str, old: str, new: str,
) -> None:
    """Private control custody, native context and exact parent source cannot be substituted."""
    sources = _beacon_sources()
    guard.require_parliament_beacon_requirement(*sources.values())
    assert sources[path].count(old) == 1
    sources[path] = sources[path].replace(old, new, 1)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_parliament_beacon_requirement(*sources.values())


def test_beacon_requirement_checks_root_before_reusing_prepared_context() -> None:
    """A cached reducer cannot bypass immutable scope selection or its error propagation."""
    sources = _beacon_sources()
    producer = sources[guard.BEACON_PRODUCER_PATH]
    guard.require_parliament_beacon_requirement(*sources.values())
    early_return = "        if self.prepared.as_ref() == Some(context) {\n            return Ok(());\n        }\n"
    scope_start = "        let root_scope = crate::sumeragi::lanes::routing::committed_root_scope(state.world())"
    assert producer.count(early_return) == producer.count(scope_start) == 1
    moved = producer.replace(early_return, "").replace(scope_start, early_return + scope_start)
    sources[guard.BEACON_PRODUCER_PATH] = moved
    with pytest.raises(RuntimeError, match=re.escape(guard.BEACON_PRODUCER_PATH)):
        guard.require_parliament_beacon_requirement(*sources.values())


def test_beacon_requirement_checks_original_parent_before_committed_demand() -> None:
    """Neither schedule selection nor a cached round may precede current tip authentication."""
    sources = _beacon_sources()
    producer = sources[guard.BEACON_PRODUCER_PATH]
    guard.require_parliament_beacon_requirement(*sources.values())
    admission = "        let parent = self.parent_source(state, context, applied)?;\n"
    cached = "        if self.prepared.as_ref() == Some(context) {"
    assert producer.count(admission) == producer.count(cached) == 1
    moved = producer.replace(admission, "").replace(cached, admission + cached, 1)
    sources[guard.BEACON_PRODUCER_PATH] = moved
    assert moved != producer
    with pytest.raises(RuntimeError, match=re.escape(guard.BEACON_PRODUCER_PATH)):
        guard.require_parliament_beacon_requirement(*sources.values())


BLOCK_PATH = "crates/iroha_core/src/block.rs"
PULSE_APPLICATION_PATHS = (BLOCK_PATH, guard.NATIVE_HEADER_SOURCE_PATH, guard.SCHEDULE_EXECUTION_PATH)


def _pulse_application_sources() -> dict[str, str]:
    return {path: guard.read(path) for path in PULSE_APPLICATION_PATHS}


def test_native_beacon_pulse_application_baseline_and_entrypoint() -> None:
    """The header witness is the sole pulse owner and is applied once after admission."""
    guard.require_native_beacon_pulse_application(*_pulse_application_sources().values())
    body = ast.parse(inspect.getsource(guard.main))
    calls = [node.func.id for node in ast.walk(body)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_native_beacon_pulse_application") == 1


@pytest.mark.parametrize("path,old,new", (
    (guard.SCHEDULE_EXECUTION_PATH, "source.header() != self._curr_block", "false"),
    (guard.SCHEDULE_EXECUTION_PATH,
     "authenticate_successor_context(self, &self._curr_block, expected)?;", ""),
    (guard.SCHEDULE_EXECUTION_PATH, ".insert(value.pulse_id, value);", ".insert(value.pulse_id, other);"),
    (guard.SCHEDULE_EXECUTION_PATH, "                value.height,", "                value.height + 1,"),
    (guard.SCHEDULE_EXECUTION_PATH, ".insert(slot, value.pulse_id);", ".insert(slot, other.pulse_id);"),
    (guard.SCHEDULE_EXECUTION_PATH,
     "self.sumeragi_schedule = ScheduleStep::Requested { captured, pulse };\n        Ok(())", "Ok(())"),
    (BLOCK_PATH,
     "            if block.global_beacon_pulse().is_some()\n"
     "                || block.header().global_beacon_pulse_hash().is_some()\n",
     "            if block.header().global_beacon_pulse_hash().is_some()\n"),
    (BLOCK_PATH,
     "            Self::validate_sumeragi_consensus_effects(block)?;\n"
     "            state\n                .block_with_recorded_pristine_carrier_stage(",
     "            state\n                .block_with_recorded_pristine_carrier_stage("),
    (BLOCK_PATH, "                                    profile.sumeragi_pulse(),\n",
     "                                    None,\n"),
    (BLOCK_PATH, '    include!("block/native_header_source.rs");',
     '    // include!("block/native_header_source.rs");'),
    (guard.NATIVE_HEADER_SOURCE_PATH,
     "crate::sumeragi::epoch_beacon::control::decode(&native_header.control_witness)",
     "crate::sumeragi::epoch_beacon::control::decode(&ControlWitness::empty())"),
    (guard.SCHEDULE_EXECUTION_PATH,
     "                &epoch,\n                height,\n                supplied_pulse,",
     "                &epoch,\n                height,\n                None,"),
    (guard.SCHEDULE_EXECUTION_PATH,
     "                current,\n                height,\n                supplied_pulse,",
     "                current,\n                height,\n                None,"),
    (guard.SCHEDULE_EXECUTION_PATH, "let current = &schedule.ready(height)?.epoch;",
     "let current = &schedule.ready(height + 1)?.epoch;"),
    (guard.SCHEDULE_EXECUTION_PATH,
     "if let (Some(value), Some(link)) = (pulse.pulse(), pulse.link()) {",
     "if let (Some(value), Some(link)) = (supplied_pulse, pulse.link()) {"),
    (guard.SCHEDULE_EXECUTION_PATH,
     "                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, link);\n", ";\n"),
))
def test_native_beacon_pulse_application_rejects_second_owner_or_unverified_write(
    path: str, old: str, new: str,
) -> None:
    """No payload pulse, skipped admission, foreign epoch or unverified write is accepted."""
    sources = _pulse_application_sources()
    owner = (
        guard.rust_item(sources[path], "    pub(crate) fn request_sumeragi_schedule(", path)
        if path == guard.SCHEDULE_EXECUTION_PATH else sources[path]
    )
    assert owner.count(old) == 1
    sources[path] = sources[path].replace(owner, owner.replace(old, new, 1), 1)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_native_beacon_pulse_application(*sources.values())


STORAGE_PATH = "crates/mv/src/storage.rs"


def _storage_iterator_implementation(source: str, owner: str) -> tuple[int, int]:
    """Select the concrete owner, so another implementation cannot be a decoy."""
    marker = f"StorageReadOnly<K, V> for {owner}<'_, K, V, M>"
    assert source.count(marker) == 1
    start = source.rfind("impl<", 0, source.index(marker))
    opening = source.index("{", source.index(marker))
    depth = 1
    for end in range(opening + 1, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if depth == 0:
            return start, end + 1
    raise AssertionError("missing concrete implementation end")


def test_borrowed_storage_iterators_accept_current_complete_owner_families() -> None:
    """All three owners retain lifetime, mode charge, reverse order and exact length."""
    guard.require_storage_borrowed_iterators(guard.read(STORAGE_PATH))


@pytest.mark.parametrize("mutation", (
    "iter_forward_only", "iter_inexact", "range_forward_only",
    "range_owner_lifetime", "iter_static_items", "range_sized_query",
))
def test_borrowed_storage_iterator_trait_rejects_weakened_contract(mutation: str) -> None:
    source = guard.read(STORAGE_PATH)
    start = source.index("pub trait StorageReadOnly")
    end = source.index("mod view {", start)
    trait = source[start:end]
    if mutation == "range_sized_query":
        range_start = trait.index("fn range<Q>")
        changed = trait[:range_start] + trait[range_start:].replace(
            "Q: Ord + ?Sized;", "Q: Ord + Sized;", 1
        )
    else:
        family = "RangeIter" if mutation.startswith("range_") else "Iter"
        match = re.search(rf"type {family}<'a>.*?;", trait, re.S)
        assert match
        declaration = match.group()
        if mutation.endswith("forward_only"):
            replacement = declaration.replace("DoubleEndedIterator", "Iterator")
        elif mutation == "iter_inexact":
            replacement = declaration.replace(" + ExactSizeIterator", "")
        elif mutation == "range_owner_lifetime":
            replacement = re.sub(r"\s+where\s+Self: 'a", "", declaration)
        else:
            replacement = declaration.replace("&'a", "&'static")
        changed = trait[:match.start()] + replacement + trait[match.end():]
    assert changed != trait
    mutated = source[:start] + changed + source[end:] + "\n/* " + trait + " */\n"
    with pytest.raises(RuntimeError, match="borrowed iterator trait contract changed"):
        guard.require_storage_borrowed_iterators(mutated)


@pytest.mark.parametrize("owner", ("View", "Block", "Transaction"))
@pytest.mark.parametrize("family", ("Iter", "RangeIter"))
@pytest.mark.parametrize("mutation", ("erase_charge", "remove_owner_lifetime", "boxed_delegate"))
def test_borrowed_storage_iterators_reject_family_and_allocation_escape(
    owner: str, family: str, mutation: str,
) -> None:
    source = guard.read(STORAGE_PATH)
    start, end = _storage_iterator_implementation(source, owner)
    implementation = source[start:end]
    if mutation == "boxed_delegate":
        receiver = {"View": "txn", "Block": "self.writers.as_ref().blocks", "Transaction": "self.current()"}[owner]
        call = f"{receiver}.iter()" if family == "Iter" else f"{receiver}.range(bounds)"
        assert implementation.count(call) == 1
        changed = implementation.replace(call, f"Box::new({call})", 1)
        message = f"{owner} borrowed iterator must use its original native owner"
    else:
        match = re.search(rf"type {family}<'a>.*?;", implementation, re.S)
        assert match
        declaration = match.group()
        replacement = (declaration.replace("M::Charge", "Untracked")
                       if mutation == "erase_charge"
                       else re.sub(r"\s+where\s+Self: 'a", "", declaration))
        changed = implementation[:match.start()] + replacement + implementation[match.end():]
        message = f"{owner} borrowed iterator family changed"
    assert changed != implementation
    mutated = source[:start] + changed + source[end:] + "\n/* " + implementation + " */\n"
    with pytest.raises(RuntimeError, match=re.escape(message)):
        guard.require_storage_borrowed_iterators(mutated)


@pytest.mark.parametrize("owner", ("View", "Block", "Transaction"))
def test_borrowed_storage_iterators_reject_other_generation_or_order(owner: str) -> None:
    source = guard.read(STORAGE_PATH)
    start, end = _storage_iterator_implementation(source, owner)
    implementation = source[start:end]
    call = {"View": "snapshot.range(bounds)", "Block": "self.writers.as_ref().blocks.range(bounds)",
            "Transaction": "self.current().range(bounds)"}[owner]
    assert implementation.count(call) == 1
    changed = implementation.replace(call, f"{call}.rev()", 1)
    with pytest.raises(RuntimeError, match=f"{owner} borrowed iterator must use its original native owner"):
        guard.require_storage_borrowed_iterators(source[:start] + changed + source[end:])


def test_borrowed_storage_iterator_gate_is_connected_to_main() -> None:
    calls = [node.func.id for node in ast.walk(ast.parse(inspect.getsource(guard.main)))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("require_storage_borrowed_iterators") == 1


@pytest.mark.parametrize("old,new", (
    ("iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(source)",
     "iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(other)"),
    ("crate::execution_attempt::genesis_read_attempt_error(error, |error| {\n"
     "                        ScheduleError::Epoch(error.to_string())\n"
     "                    })",
     "ScheduleError::Epoch(error.to_string()).into()"),
    ("crate::sumeragi::lanes::routing::committed_root_scope(&self.world)",
     "Some(SumeragiRootScope::Global)"),
    ("                ScheduleError::Epoch(\"native control requires immutable root scope\".into())",
     "                ScheduleError::Malformed"),
    ("                root_scope,\n                &self.world,",
     "                SumeragiRootScope::Global,\n                &self.world,"),
))
def test_native_beacon_application_requires_signed_or_committed_original_root(
    old: str, new: str,
) -> None:
    """Genesis and successors supply authenticated root ownership to both capture branches."""
    sources = _pulse_application_sources()
    guard.require_native_beacon_pulse_application(*sources.values())
    expected_count = 2 if old.startswith("                root_scope,") else 1
    assert sources[guard.SCHEDULE_EXECUTION_PATH].count(old) == expected_count
    sources[guard.SCHEDULE_EXECUTION_PATH] = sources[guard.SCHEDULE_EXECUTION_PATH].replace(old, new)
    with pytest.raises(RuntimeError, match=re.escape(guard.SCHEDULE_EXECUTION_PATH)):
        guard.require_native_beacon_pulse_application(*sources.values())


@pytest.mark.parametrize("path,declaration,original,replacement", (('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'depth > MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH', 'false'), ('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'reject_opaque_committee_operation(instruction, index)?;', 'let _ = instruction;'), ('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'resolve(&approval)', 'None'), ('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'if visited.insert(identity)', 'if false'), ('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'proposal.instructions.iter(),', '&[], '), ('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'proved.overlay.iter(),', '&[], '), ('crates/iroha_core/src/deferred_authority.rs', "fn reject_opaque_committee_operations_with<'a, F>(", 'std::slice::from_ref(instruction),', '&[], '), ('crates/iroha_core/src/validation_fee.rs', 'pub(crate) fn enforce_validation_fee_admission(', 'active_policy(state_transaction)?', 'None::<()>'), ('crates/iroha_core/src/validation_fee.rs', 'pub(crate) fn enforce_validation_fee_admission(', 'crate::retail_fee::admit(tx, state_transaction)?;', 'let _ = tx;'), ('crates/iroha_core/src/validation_fee.rs', 'fn reject_ivm_proved_completed_axt_effects(', 'OpaqueIvmProvedAxtEffects', 'OpaqueAcceptedEffects'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn admit(', 'RETAIL_FEE_ASSESSMENT_METADATA_KEY', 'UNAUTHENTICATED_ASSESSMENT_KEY'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn admit(', 'Some(*tx.hash().as_ref())', 'Some([0; 32])'), ('crates/iroha_core/src/retail_fee.rs', 'fn bind_assessment(', 'now >= assessment.expires_at_ms', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'fn bind_assessment(', 'if stx.world.retail_fee_assessment.is_some()', 'if false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn admit_deferred(', 'if reviewed.replace(assessment).is_some()', 'if false'), ('crates/iroha_core/src/retail_fee.rs', 'fn decode_assessment_marker(', 'log.msg.len() > 4096', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'fn decode_assessment_marker(', 'norito::decode_canonical(&bytes)', 'norito::decode_from_bytes(&bytes)'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn execute_assessment_marker(', 'stx.multisig_deferred_execution_stack.is_empty()', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn execute_assessment_marker(', '!stx.world.retail_fee_assessment_marker_pending', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn execute_assessment_marker(', 'stx.world.retail_fee_assessment.as_ref() != Some(&assessment)', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn execute_assessment_marker(', 'stx.world.retail_fee_assessment_marker_pending = false;', 'stx.world.retail_fee_assessment_marker_pending = true;'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn record_payment(', 'if stx.world.retail_fee_assessment.is_none()', 'if false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn record_payment(', 'approved_amount == amount', 'true'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'if stx.world.retail_fee_assessment_marker_pending', 'if false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'if !stx.world.retail_fee_exempt_payments.is_empty()', 'if false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'observed.iter().any(|(id, _)| id != source)', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'from.checked_sub(assessment.fee_minor)', 'Some(from)'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'source_transaction_hash: Some(source_transaction_hash)', 'source_transaction_hash: Some([0; 32])'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment: Some(assessment.clone())', 'assessment: None'), ('crates/iroha_core/src/tx.rs', 'pub(crate) fn validate_stateful_admission(', 'crate::validation_fee::enforce_validation_fee_admission(tx, state_transaction)', 'Ok::<(), ExecutionAttemptError<TransactionRejectionReason>>(())'), ('crates/iroha_core/src/tx.rs', 'pub(crate) fn execute_accepted_transaction_in_overlay(', 'crate::retail_fee::finalize(state_transaction)?;', 'let _ = state_transaction;'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.retail_enrolled != expected.retail_enrolled', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.account_id != expected.account_id', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.billing_month_start_ms != expected.billing_month_start_ms', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.policy_revision != expected.policy_revision', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.payments_used_before != expected.payments_used_before', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.qualifying_payments != expected.qualifying_payments', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.fee_minor != expected.fee_minor', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.state_commitment != expected.state_commitment', 'false'), ('crates/iroha_core/src/retail_fee.rs', 'pub(crate) fn finalize(', 'assessment.intent_hash != expected.intent_hash', 'false')))
def test_native_fee_boundary_rejects_changed_live_authority_or_assessment(
    path: str, declaration: str, original: str, replacement: str,
) -> None:
    """An intact spelling in a detached comment cannot replace the actual owner."""
    sources = _fee_boundary_sources()
    _check_fee_boundary(sources)
    body = guard.rust_item(sources[path], declaration, path)
    assert body.count(original) == 1
    sources[path] = sources[path].replace(body, body.replace(original, replacement, 1), 1)
    sources[path] += "\n/* " + original + " */\n"
    with pytest.raises(RuntimeError):
        _check_fee_boundary(sources)


@pytest.mark.parametrize("method", ("fn apply(", "fn apply_after_batch_preflight("))
def test_native_fee_boundary_requires_each_common_asset_payment_hook(method: str) -> None:
    sources = _fee_boundary_sources()
    path = FEE_BOUNDARY_PATHS[3]
    outer = guard.rust_item(sources[path], "impl PreparedNumericTransferPlan {", path)
    body = guard.rust_item(outer, method, path)
    original = "crate::retail_fee::record_payment("
    assert body.count(original) == 1
    changed = outer.replace(body, body.replace(original, "crate::retail_fee::ignore_payment(", 1), 1)
    sources[path] = sources[path].replace(outer, changed, 1) + "\n/* " + original + " */\n"
    with pytest.raises(RuntimeError):
        _check_fee_boundary(sources)


@pytest.mark.parametrize("module", ("deferred_authority", "retail_fee", "validation_fee", "tx"))
def test_native_fee_boundary_requires_unconditional_registered_owners(module: str) -> None:
    sources = _fee_boundary_sources()
    path = FEE_BOUNDARY_PATHS[5]
    prefix = "pub(crate)" if module == "deferred_authority" else "pub"
    declaration = prefix + " mod " + module + ";"
    assert sources[path].count(declaration) == 1
    sources[path] = sources[path].replace(declaration, "#[cfg(any())]\n" + declaration, 1)
    with pytest.raises(RuntimeError, match="must be unconditional"):
        _check_fee_boundary(sources)


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "before_runtime", "after_sequence"))
def test_native_fee_boundary_finalizes_once_after_runtime_and_triggers_before_sequence(mutation: str) -> None:
    sources = _fee_boundary_sources()
    path = FEE_BOUNDARY_PATHS[4]
    body = guard.rust_item(sources[path], "pub(crate) fn execute_accepted_transaction_in_overlay(", path)
    call = "crate::retail_fee::finalize(state_transaction)?;"
    assert body.count(call) == 1
    if mutation == "missing":
        changed = body.replace(call, "", 1)
    elif mutation == "duplicate":
        changed = body.replace(call, call + call, 1)
    elif mutation == "before_runtime":
        runtime = "Self::validate_transaction_with_runtime_executor(tx.clone(), state_transaction, ivm_cache)?;"
        assert body.count(runtime) == 1
        changed = body.replace(call, "", 1).replace(runtime, call + runtime, 1)
    else:
        sequence = ".insert(authority.clone(), seq);"
        assert body.count(sequence) == 1
        changed = body.replace(call, "", 1).replace(sequence, sequence + call, 1)
    sources[path] = sources[path].replace(body, changed, 1) + "\n/* " + call + " */\n"
    with pytest.raises(RuntimeError):
        _check_fee_boundary(sources)


@pytest.mark.parametrize("original,replacement", (
    ("curr_block, None, before_start, after_start", "other_header, None, before_start, after_start"),
    ("curr_block, None, before_start, after_start", "curr_block, Some(other_carrier), before_start, after_start"),
    ("curr_block, None, before_start, after_start", "curr_block, None, replacement, after_start"),
))
def test_block_start_carrier_delegate_preserves_original_callers(original: str, replacement: str) -> None:
    """The ordinary caller delegates once with its original header and continuations."""
    source = guard.read(STATE_PATH)
    guard.require_block_start_enactment_phases(source)
    assert source.count(original) == 1
    changed = source.replace(original, replacement, 1)
    with pytest.raises(RuntimeError, match="start phases"):
        guard.require_block_start_enactment_phases(changed)



@pytest.mark.parametrize("replacement", (
    "StateBlockStartError::Storage(reason)",
    "StateBlockStartError::Stage(reason)",
))
def test_block_start_due_execution_keeps_original_local_deferral(replacement: str) -> None:
    """Due effect and failure-recorder resource refusals retain their local class."""
    source = guard.read(STATE_PATH)
    guard.require_block_start_enactment_phases(source)
    declaration = "    fn apply_block_start_parliament_enactments<E: std::fmt::Debug>("
    due = guard.rust_item(source, declaration, STATE_PATH)
    original = "StateBlockStartError::ExecutionDeferred(reason)"
    assert due.count(original) == 2
    changed = source.replace(due, due.replace(original, replacement, 1), 1)
    with pytest.raises(RuntimeError, match="start phases"):
        guard.require_block_start_enactment_phases(changed)



@pytest.mark.parametrize("original,replacement", (
    ("validate_prepared_overlay(", "unchecked_prepared_overlay("),
    ("validate_prepared_overlay(\n            world,",
     "validate_prepared_overlay(\n            foreign_world,"),
    ("validate_prepared_overlay(\n            world,\n            &state_ref.ivm_execution_budget(),",
     "validate_prepared_overlay(\n            world,\n            &foreign_budget,"),
))
def test_prepared_commit_world_validation_uses_original_overlay_and_budget(
    original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publication validates its retained World with the original finite allocation budget."""
    state = guard.read(STATE_PATH)
    guard.require_parliament_commit_publication(state)
    publication = guard.read(PUBLICATION_PATH)
    assert publication.count(original) == 1
    changed = publication.replace(original, replacement, 1)
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda path:
                        changed if path == PUBLICATION_PATH else original_read(path))
    with pytest.raises(RuntimeError, match=PUBLICATION_PATH):
        guard.require_parliament_commit_publication(state)


@pytest.mark.parametrize("path,declaration,original,replacement", (
    (FEE_BOUNDARY_PATHS[0], "pub(crate) fn enforce_opaque_deferred_instruction_groups(",
     "transaction_attempt_rejection(stx, error)", "discard_original_authority_refusal(stx, error)"),
    (FEE_BOUNDARY_PATHS[0], "fn transaction_attempt_rejection(",
     "state.defer_execution(reason)", "reject_local_capacity(reason)"),
    (FEE_BOUNDARY_PATHS[1], "pub(crate) fn reject_opaque_deferred_authority(",
     ".flat_map(|instructions| instructions.iter())", ".flat_map(|_| [].iter())"),
    (FEE_BOUNDARY_PATHS[1], "pub(crate) fn reject_opaque_deferred_authority(",
     "error.map_rejection(TransactionRejectionReason::Validation)",
     "Attempt::Rejected(TransactionRejectionReason::Validation(error))"),
    (FEE_BOUNDARY_PATHS[1], "pub(crate) fn reject_opaque_instruction_authority<'a>(",
     "live_proposal_instructions_for_approval(state_transaction, approve)", "Ok(None)"),
    (FEE_BOUNDARY_PATHS[1], "pub(crate) fn reject_opaque_instruction_authority<'a>(",
     "error.map_rejection(|error|", "Attempt::Rejected(|error|"),
    (FEE_BOUNDARY_PATHS[1], "fn reject_opaque_committee_operations_with<'a, F>(",
     "Attempt::Deferred(reason) => return Err(Attempt::Deferred(reason))",
     "Attempt::Deferred(_) => None"),
    (FEE_BOUNDARY_PATHS[1], "fn reject_opaque_committee_operations_with<'a, F>(",
     "error.map_rejection(|error|", "Attempt::Rejected(|error|"),
    (FEE_BOUNDARY_PATHS[1], "fn reject_opaque_committee_operations_with<'a, F>(",
     "instructions.iter(),", "[].iter(),"),
))
def test_signed_staking_authority_retains_original_deferred_live_reads(
    path: str, declaration: str, original: str, replacement: str,
) -> None:
    """Every actual instruction is checked and only completed errors are reclassified."""
    sources = _fee_boundary_sources()
    _check_fee_boundary(sources)
    body = guard.rust_item(sources[path], declaration, path)
    assert original in body
    sources[path] = sources[path].replace(body, body.replace(original, replacement, 1), 1)
    sources[path] += "\n/* " + original + " */\n"
    with pytest.raises(RuntimeError):
        _check_fee_boundary(sources)


def test_signed_staking_authority_precedes_optional_fee_policy_resolution() -> None:
    """Moving the real guard behind optional policy lookup must not pass by spelling."""
    sources = _fee_boundary_sources()
    _check_fee_boundary(sources)
    path = FEE_BOUNDARY_PATHS[0]
    body = guard.rust_item(sources[path], "pub(crate) fn enforce_opaque_deferred_instruction_groups(", path)
    guard_call = ("crate::deferred_authority::reject_opaque_deferred_authority(groups, stx)\n"
                  "        .map_err(|error| transaction_attempt_rejection(stx, error))?;")
    policy_call = ("let registry = validated_policy_registry(stx)\n"
                   "        .map_err(|error| transaction_attempt_rejection(stx, error))?;")
    assert body.count(guard_call) == body.count(policy_call) == 1
    reordered = body.replace(guard_call, "", 1).replace(policy_call, policy_call + guard_call, 1)
    sources[path] = sources[path].replace(body, reordered, 1)
    with pytest.raises(RuntimeError):
        _check_fee_boundary(sources)


@pytest.mark.parametrize("old,new", (
    ("let peers = current.committee.iter().map(|seat| &seat.validator);",
     "let peers = foreign.committee.iter().map(|seat| &seat.validator);"),
    ("let peers = current.committee.iter().map(|seat| &seat.validator);",
     "let peers = current.committee.iter().rev().map(|seat| &seat.validator);"),
    ("network_id: current.network_id,", "network_id: record.session.network_id,"),
    ("network_id: current.network_id,\n        session_id: pulse.session_id,",
     "network_id: current.network_id,\n        session_id: record.session.session_id,"),
    ("        roster_hash,", "        roster_hash: record.session.roster_hash,"),
    ("transcript_hash: record.session.transcript_hash,", "transcript_hash: foreign.transcript_hash,"),
    ("let session = &record.session;", "let session = &foreign.session;"),
    ("session\n        .check_binding(&binding)\n        .map_err(|error| error.to_string())?;", ""),
    (".check_binding(&binding)", ".check_binding(&foreign_binding)"),
    ("        &session,\n        &pulse,", "        &foreign_session,\n        &pulse,"),
))
def test_beacon_capture_requires_original_borrowed_roster_and_current_seal(old: str, new: str) -> None:
    """A sealed graph still needs every current external identity before proof verification."""
    sources = _beacon_sources()
    guard.require_parliament_beacon_requirement(*sources.values())
    path = guard.EPOCH_BEACON_PATH
    body = guard.rust_item(sources[path], "pub(crate) fn capture(", path)
    assert body.count(old) == 1
    sources[path] = sources[path].replace(body, body.replace(old, new, 1), 1)
    sources[path] += "\n/* " + old + " */\n"
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_parliament_beacon_requirement(*sources.values())


@pytest.mark.parametrize("path,declaration,old,new", (
    (guard.BEACON_ROSTER_PATH, "pub(crate) fn authenticated_global_threshold_beacon_roster_hash_iter_v1<",
     "let count = roster.len();", "let count = usize::from(session.committee_size);"),
    (guard.BEACON_ROSTER_PATH, "pub(crate) fn authenticated_global_threshold_beacon_roster_hash_iter_v1<",
     "session.roster_hash != roster_hash", "false"),
    (guard.BEACON_ROSTER_PATH, "pub(crate) fn authenticated_global_threshold_beacon_roster_hash_iter_v1<",
     "usize::from(session.committee_size) != count", "false"),
    (guard.BEACON_ROSTER_PATH, "pub(crate) fn authenticated_global_threshold_beacon_roster_hash_iter_v1<",
     "global_threshold_beacon_roster_hash_iter_v1(roster)", "global_threshold_beacon_roster_hash_iter_v1(foreign)"),
    (guard.BEACON_ROSTER_PATH, "pub fn global_threshold_beacon_roster_hash_iter_v1<",
     "validation::RosterIter(roster)", "validation::RosterIter(roster.rev())"),
    (guard.BEACON_ROSTER_CODEC_PATH, "impl<'a, I> norito::core::SerializePayload for RosterIter<I>",
     "writer, self.0.clone()", "writer, self.0.clone().skip(1)"),
    (guard.BEACON_SEALED_SESSION_PATH, "    pub fn check_binding(",
     "validate_binding(self.record(), expected)", "Ok(())"),
    (guard.BEACON_SEALED_SESSION_PATH, "    pub fn check_binding(",
     "validate_binding(self.record(), expected)", "validate_binding(foreign.record(), expected)"),
    (guard.BEACON_SEALED_SESSION_PATH, "fn validate_binding(",
     "source.network_id != expected.network_id", "false"),
    (guard.BEACON_SEALED_SESSION_PATH, "fn validate_binding(",
     "source.session_id != expected.session_id", "false"),
    (guard.BEACON_SEALED_SESSION_PATH, "fn validate_binding(",
     "source.roster_hash != expected.roster_hash", "false"),
    (guard.BEACON_SEALED_SESSION_PATH, "fn validate_binding(",
     "source.transcript_hash != expected.transcript_hash", "false"),
))
def test_borrowed_beacon_helpers_preserve_exact_source_cardinality_and_binding(
    path: str, declaration: str, old: str, new: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither iterator cardinality/bytes nor the immutable graph recheck can be bypassed."""
    guard.require_borrowed_beacon_roster_and_sealed_binding()
    source = guard.read(path)
    body = guard.rust_item(source, declaration, path)
    assert body.count(old) == 1
    changed = source.replace(body, body.replace(old, new, 1), 1) + "\n/* " + old + " */\n"
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda target: changed if target == path else original_read(target))
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_borrowed_beacon_roster_and_sealed_binding()


@pytest.mark.parametrize("old,new", (
    ("let target_roster = preparation.committee.iter().map(|seat| &seat.validator);",
     "let target_roster = foreign.committee.iter().map(|seat| &seat.validator);"),
    ("let target_roster = preparation.committee.iter().map(|seat| &seat.validator);",
     "let target_roster = preparation.committee.iter().rev().map(|seat| &seat.validator);"),
    ("authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, target_roster)",
     "authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, foreign_roster)"),
))
def test_beacon_finalization_uses_complete_original_frozen_roster(old: str, new: str) -> None:
    """The target binding must come from the complete ordered authenticated preparation."""
    path = "crates/iroha_core/src/state/validator_committee.rs"
    source = guard.read(path)
    guard.require_beacon_finalization_roster(source)
    assert source.count(old) == 1
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_beacon_finalization_roster(source.replace(old, new, 1))

@pytest.mark.parametrize("original,replacement", (
    ("epoch: **epoch,", "epoch: EpochConfig::default(),"),
    ("params: *params,", "params: ChainParams::default(),"),
    ("committee_digest: committee_digest(committee),", "committee_digest: Hash::new([]),"),
    ("instance: source.instance(),", "instance: [0; 32],"),
    ("height: source.height(),", "height: 1,"),
    ("block_hash: source.block_hash(),", "block_hash: [0; 32],"),
    ("writer.write_all(iroha_sumeragi::preimage::TAG_COMMITTEE)?;", ""),
    ("&u32::try_from(committee.n())", "&u32::try_from(1_usize)"),
    ("for key in committee.members() {", "for key in committee.members().take(1) {"),
    ("&u16::try_from(bytes.len())", "&u16::try_from(1_usize)"),
    ("writer.write_all(bytes)?;", "writer.write_all(&[])?;"),
))
def test_completed_replay_compact_source_rejects_every_identity_substitution(
    original: str, replacement: str,
) -> None:
    """Graph retirement cannot omit configuration or any canonical committee byte."""
    source = guard.read("crates/iroha_core/src/sumeragi/executor/replay.rs")
    guard.require_completed_replay_source(source)
    assert source.count(original) == 1
    with pytest.raises(RuntimeError, match="complete"):
        guard.require_completed_replay_source(source.replace(original, replacement, 1))


@pytest.mark.parametrize("original,replacement", (
    ("if let PublicationError::RecoveryRequired(reason) = &error {", "if let reason = &error {"),
    ("            return Err(error);", "            return Err(PublicationError::Retryable(error.to_string()));"),
    ("source: ReplaySource::capture(&live.source),", "source: ReplaySource::capture(block.source()),"),
))
def test_replay_retirement_preserves_typed_original_refusal_and_published_source(
    original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retirement pressure stays typed; only its actual published owner supplies the receipt."""
    path = "crates/iroha_core/src/sumeragi/executor/replay.rs"
    state = guard.read(STATE_PATH)
    guard.require_parliament_commit_publication(state)
    source = guard.read(path)
    assert source.count(original) == 1
    changed = source.replace(original, replacement, 1)
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda target:
                        changed if target == path else original_read(target))
    with pytest.raises(RuntimeError, match=path):
        guard.require_parliament_commit_publication(state)


@pytest.mark.parametrize("original,replacement", (
    ("_da_rewind_releases: da_rewind_releases,", "_da_rewind_releases: replacement_releases,"),
    ("_read_releases: StateViewReleases::new(self),", "_read_releases: StateViewReleases::new(other),"),
))
def test_start_construction_keeps_original_da_and_state_reader_release_owners(
    original: str, replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outlined construction retains both original release owners before the armed handoff."""
    path = CONSTRUCTION_PATH
    state = guard.read(STATE_PATH)
    guard.require_block_start_construction(state)
    source = guard.read(path)
    assert source.count(original) == 1
    changed = source.replace(original, replacement, 1)
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda target:
                        changed if target == path else original_read(target))
    with pytest.raises(RuntimeError, match="original writers"):
        guard.require_block_start_construction(state)
