"""Frontend trace ownership, exact growth, source guards and finite domains."""

import importlib.util
from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("arena_frontend", SCRIPTS / "parliament_ballot_arena_frontend.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def inspect(events):
    """Independent lifetime checker; retain old/new overlap and peak count."""
    live = {}
    peak = 0
    for event in events:
        if event["op"] == "alloc":
            assert event["id"] not in live
            assert type(event["size"]) is int and event["size"] > 0
            live[event["id"]] = {"size": event["size"], "align": event["align"]}
            peak = max(peak, len(live))
        else:
            assert event["op"] == "free"
            assert event["id"] in live
            del live[event["id"]]
    return live, peak


def test_raw_vec_growth_has_exact_non_power_capacity_and_overlap():
    trace = M.frame_trace(b"T", (60,))
    assert trace["length"] == 69
    assert [(e["op"], e.get("size")) for e in trace["events"]] == [
        ("alloc", 8), ("alloc", 16), ("free", None), ("alloc", 69), ("free", None)]
    live, peak = inspect(trace["events"])
    assert live == trace["retained"] == {"frame.2": {"size": 69, "align": 1}}
    assert peak == 2


def test_frame_parts_match_independent_registration_fixture():
    path = M.ROOT / "crates/iroha_parliament_ballot_proof/tests/fixtures/reg_fast.txt"
    values = {k: bytes.fromhex(v) for line in path.read_text().splitlines()
              if " = " in line and not line.startswith("#") for k, v in [line.split(" = ")]}
    names = ("enc_body_context", "enc_network_id", "enc_authority", "enc_assignment_id",
             "enc_governance_attempt_id", "enc_election_attempt_id", "enc_body_role")
    lengths = tuple(len(values[n]) for n in names)
    trace = M.frame_trace(b"PARL/MU/REG/v1", (*lengths, 64, 128, 64))
    assert trace["length"] == len(values["F_REG"]) == 502
    assert M.canonical_record_bytes("candidate", "registration", lengths) == 160728


@pytest.mark.parametrize("row", ["candidate", "comparator"])
@pytest.mark.parametrize("role,seats", [("registration", 3), ("vote", 3), ("vote", 500), ("vote", 1000)])
def test_ordinary_prefix_retains_only_caller_owned_values(row, role, seats):
    trace = M.frontend_trace(row, role, seats=seats)
    live, peak = inspect(trace["prefix"])
    assert live == trace["retained"]
    assert len(live) == (8 if role == "registration" else 3)
    assert peak <= (12 if role == "registration" else 6)
    assert inspect(trace["prefix"] + trace["suffix"])[0] == {}
    assert trace["suffix"][-1] == {"op": "free", "id": "frontend.record"}
    assert not any("mu" in name for name in live)  # mu is an inline [u8;64].


def test_zero_length_registration_allocates_no_empty_vectors():
    trace = M.frontend_trace("candidate", "registration", registration_lengths=(0,) * 7)
    assert set(trace["retained"]) == {"frontend.record"}
    assert not any("registration." in e["id"] for e in trace["prefix"])


@pytest.mark.parametrize("role", ["registration", "vote"])
def test_every_ordinary_rejection_class_cleans_up_and_has_no_backend(role):
    stops = M.COMMON_STOPS + (M.REG_STOPS if role == "registration" else M.VOTE_STOPS)
    for stop in stops:
        trace = M.frontend_trace("candidate", role, stop=stop, record_bytes=M.MAX_INPUT_BYTES)
        assert not trace["reaches_backend"]
        assert not trace["suffix"] and not trace["retained"]
        assert inspect(trace["prefix"])[0] == {}
        assert not any("profile_verify" in e["id"] for e in trace["prefix"])


def test_partial_context_and_completed_context_have_different_drop_orders():
    partial = M.frontend_trace("candidate", "registration", stop="registration_field_4")
    complete = M.frontend_trace("candidate", "registration", stop="registration_fixed")
    statement = M.frontend_trace("candidate", "registration", stop="registration_digest")
    def fields(trace):
        return [e["id"].rsplit(".", 1)[1] for e in trace["prefix"]
                if e["op"] == "free" and ".registration." in e["id"]]
    assert fields(partial) == ["assignment", "authority", "network", "body"]
    assert fields(complete) == ["network", "authority", "assignment", "governance", "election", "role", "body"]
    assert fields(statement) == list(M.REG_FIELDS)


def test_read_failure_skips_profiles_and_preallocation_refusal_is_empty():
    assert M.frontend_trace("candidate", "vote", stop="admission", record_bytes=1 << 40)["prefix"] == []
    trace = M.frontend_trace("candidate", "vote", stop="read", record_bytes=65)
    assert trace["prefix"] == [
        {"op": "alloc", "id": "frontend.record", "size": 65, "align": 1,
         "source": "workspace.rs:execute bounded vec![0;length]"},
        {"op": "free", "id": "frontend.record"}]
    assert M.frontend_trace("candidate", "vote", stop="read", record_bytes=0)["prefix"] == []


def test_profile_and_slice_lifetimes_follow_cold_source_order():
    trace = M.frontend_trace("candidate", "vote", seats=17)
    events = trace["prefix"]
    ids = [e["id"] for e in events]
    field_free = next(i for i, e in enumerate(events) if e == {"op": "free", "id": "frontend.field_slices"})
    assert field_free < ids.index("frontend.list_digest_verify")
    assert ids.index("frontend.list_digest_verify") < next(i for i, s in enumerate(ids) if "profile_verify" in s)
    assert ids.index("frontend.authorization_concat") < ids.index("frontend.public_list")
    assert ids.index("frontend.public_list") < ids.index("frontend.frame_concat")


def test_all_vote_sizes_use_exact_list_lengths_and_complete_cleanup():
    for seats in range(3, 1001):
        trace = M.frontend_trace("candidate", "vote", seats=seats)
        assert trace["retained"]["frontend.vote.list"]["size"] == 128 * seats
        assert trace["record_bytes"] == 233596 + 128 * seats
        assert inspect(trace["prefix"] + trace["suffix"])[0] == {}


def test_retained_classes_partition_all_lengths_but_do_not_claim_transient_equivalence():
    for maximum in M.REG_CAPS:
        classes = M.buddy_length_classes(maximum)
        assert [n for lo, hi in classes for n in range(lo, hi + 1)] == list(range(maximum + 1))
        for lo, hi in classes:
            if lo:
                assert max(64, 1 << (lo - 1).bit_length()) == max(64, 1 << (hi - 1).bit_length())
    classes = list(M.registration_retained_classes())
    assert len(classes) == 32768
    assert len({c["representative_lengths"] for c in classes}) == 32768
    assert all(c["equivalence"] == "retained registration buddy orders only" for c in classes)
    assert not M.parameter_domain()["all_frontend_transient_classes_enumerated"]


def test_universal_frontend_bounds_check_profile_premise(monkeypatch):
    bound = M.frontend_bounds()
    assert bound["maximum_live_objects_including_input"] == 12
    assert bound["maximum_other_rounded_block"] == 262144
    assert not bound["allocator_spatial_success_proved_here"]
    monkeypatch.setattr(M, "_profile_trace", lambda *_: [
        {"op": "alloc", "id": "big", "size": 131073, "align": 1, "source": "changed"},
        {"op": "free", "id": "big"}])
    with pytest.raises(ValueError, match="premise changed"):
        M.frontend_bounds()


def test_source_guard_detects_changed_input(tmp_path):
    assert M.source_inventory()["sha256"] == M.REVIEWED_SOURCE_SHA256
    for name in M.FRONT_SOURCE_PATHS:
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((M.ROOT / name).read_bytes())
    changed = tmp_path / M.FRONT_SOURCE_PATHS[0]
    changed.write_bytes(changed.read_bytes() + b"\n// drift\n")
    with pytest.raises(ValueError, match="source changed"):
        M.source_inventory(tmp_path)


@pytest.mark.parametrize("kwargs", [
    {"record_bytes": M.MAX_INPUT_BYTES + 1}, {"record_bytes": 0},
    {"seats": 2}, {"seats": 1001}, {"seats": 3.5},
    {"stop": "registration_digest"}, {"stop": "invented"}, {"prefix": ""}])
def test_invalid_or_impossible_normal_shapes_are_rejected(kwargs):
    with pytest.raises(ValueError):
        M.frontend_trace("candidate", "vote", **kwargs)


def test_invalid_frame_and_registration_lengths_are_rejected():
    for fields in ((-1,), (1 << 32,), (1.0,)):
        with pytest.raises(ValueError):
            M.frame_parts(b"T", fields)
    for lengths in ((0,), (4097, 0, 0, 0, 0, 0, 0), (0, 257, 0, 0, 0, 0, 0)):
        with pytest.raises(ValueError):
            M.frontend_trace("candidate", "registration", registration_lengths=lengths)
