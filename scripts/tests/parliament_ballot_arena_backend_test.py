"""Independent shape, allocation-order and finite-loop checks for arena traces."""

import importlib.util
import itertools
from pathlib import Path
import re

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_arena_backend.py"
SPEC = importlib.util.spec_from_file_location("arena_backend", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def walk(events, live=None):
    """Check naming/lifetimes without substituting for the root buddy checker."""
    live = {} if live is None else live
    observed = []
    for event in events:
        if event["op"] == "alloc":
            assert event["id"] not in live
            assert event["size"] > 0
            live[event["id"]] = (event["size"], event["align"])
        elif event["op"] == "free":
            assert event["id"] in live
            del live[event["id"]]
        else:
            assert event["op"] == "repeat_restoring"
            assert 0 <= event["min"] <= event["max"]
            before = live.copy()
            observed.extend(walk(event["body"], live))
            assert live == before
        observed.append(live.copy())
    return observed


def test_small_vector_schedule_preserves_allocate_before_free_and_capacity():
    events, name, capacity = MODULE.vec_trace((1, 7, 1, 20), "small", "test")
    assert [(e["op"], e.get("size")) for e in events] == [
        ("alloc", 8), ("alloc", 16), ("free", None), ("alloc", 32), ("free", None)]
    assert name == "small.3" and capacity == 32
    assert max(sum(n for n, _ in state.values()) for state in walk(events)) == 48
    exact, live, capacity = MODULE.vec_trace((2, 30), "words", "test", element_bytes=8, align=8, initial=5)
    assert [e["size"] for e in exact if e["op"] == "alloc"] == [40, 80, 296]
    assert live == "words.2" and capacity == 37
    assert MODULE.vec_trace((0, 0), "empty", "test") == ([], None, 0)


def test_vector_schedule_rejects_invalid_inputs():
    for kwargs in ({"initial": -1}, {"element_bytes": 0}):
        with pytest.raises(ValueError):
            MODULE.vec_trace((1,), "x", "test", **kwargs)
    with pytest.raises(ValueError):
        MODULE.vec_trace((-1,), "x", "test")
    for size, align in ((0, 1), (1, 3), (True, 1)):
        with pytest.raises(ValueError):
            MODULE._alloc("x", size, align, "test")
    with pytest.raises(ValueError):
        MODULE._provider_repeat("x", 2, 1, False, "test", "test")


@pytest.mark.parametrize("row,suffix,expected_bytes", [("candidate", "f", 84304), ("comparator", "s", 83704)])
def test_profile_exact_collection_matches_generated_table_lengths(row, suffix, expected_bytes):
    path = MODULE.ROOT / MODULE.ZKP / f"crt/generated/faest_256{suffix}_tables.rs"
    source = path.read_text()
    names = ("TREE_MODULI", "M_TREE", "F", "G", "W_TREE", "W_GATE", "W_CRT")
    lengths = [int(re.search(rf"pub static {name}: \[u(?:16|64); (\d+)\]", source)[1]) for name in names]
    expected = 8 * (5 + sum(lengths))
    assert expected == expected_bytes
    events = MODULE.profile_trace(row)
    request = next(event for event in events if event["id"] == "profile.crt.bytes")
    assert request["op"] == "alloc" and request["size"] == expected
    states = walk(events)
    assert states[-1] == {}
    assert max(map(len, states)) == 4
    assert max(event.get("size", 0) for event in events) < 131072
    at_collect = next(i for i, e in enumerate(events) if e == request)
    assert len(states[at_collect]) == 2  # exact bytes coexist with final words
    assert events[at_collect + 1]["op"] == "free"
    assert events[at_collect + 1]["id"].startswith("profile.crt.words")


def test_profile_descriptor_growth_matches_independent_serialization():
    tag = b"PARL/DESC/v1"
    fields = [bytes(n) for n in (16, 9, 12, 64, 16, 129)]
    parts = [len(tag).to_bytes(2, "little"), tag, len(fields).to_bytes(2, "little")]
    for field in fields:
        parts.extend((len(field).to_bytes(4, "little"), field))
    assert len(b"".join(parts)) == 286
    length = cap = 0
    requests = []
    for part in parts:
        if len(part) > cap - length:
            cap = max(8, cap * 2, length + len(part))
            requests.append(cap)
        length += len(part)
    trace = MODULE.profile_trace("candidate")
    assert [e["size"] for e in trace if e["op"] == "alloc" and ".frame." in e["id"]] == requests
    assert trace[-3]["id"] == "profile.descriptor.dimensions"
    assert trace[-2]["id"] == "profile.descriptor.parameters"
    assert trace[-1]["id"].startswith("profile.descriptor.frame.")


@pytest.mark.parametrize("row,tau,leaves,width_reg,width_vote", [
    ("candidate", 33, 6400, 4490, 6698), ("comparator", 22, 61440, 4495, 6703)])
def test_dimensions_and_provider_loop_counts(row, tau, leaves, width_reg, width_vote):
    d = MODULE.dimensions(row)
    assert d["tau"] == tau and d["leaves"] == leaves
    assert d["width"] == width_reg
    assert MODULE.dimensions(row, "vote")["width"] == width_vote
    trace = MODULE.backend_trace(row, "vote")
    repeats = [e for e in trace if e["op"] == "repeat_restoring"]
    assert len(repeats) == tau + 2
    assert sum(e["min"] for e in repeats) == 2 * (leaves - tau)
    assert sum(e["max"] for e in repeats) == 3 * leaves - 2 * tau - 1
    for event in repeats:
        assert event["body"][0]["size"] == 960
        assert event["body"][0]["align"] == 8
        assert walk(event["body"])[-1] == {}


def test_internal_node_interval_contains_every_small_tree_hidden_pattern():
    # Independently mark complete-tree ancestors for every nonempty leaf subset.
    # Loop guard can vary with the challenge; each selected internal node emits
    # one isolated provider lifetime. Its count is always within [0,L-1].
    for leaves in (2, 4, 8):
        counts = set()
        for pattern in itertools.product((False, True), repeat=leaves):
            if not any(pattern):
                continue
            marks = [False] * (2 * leaves - 1)
            marks[leaves - 1:] = pattern
            for parent in range(leaves - 2, -1, -1):
                marks[parent] = marks[2 * parent + 1] or marks[2 * parent + 2]
            counts.add(sum(not marks[i] for i in range(leaves - 1)))
        assert min(counts) == 0
        assert max(counts) <= leaves - 1


@pytest.mark.parametrize("row", MODULE.ROWS)
@pytest.mark.parametrize("role", MODULE.WITNESS_BITS)
@pytest.mark.parametrize("accel", (False, True))
def test_all_role_traces_balance_and_acceleration_changes_only_alignment(row, role, accel):
    trace = MODULE.backend_trace(row, role, 1000, accel, prefix="owned")
    assert walk(trace)[-1] == {}
    assert all(event["id"].startswith("owned.") for event in trace)
    for event in trace:
        if event["op"] == "repeat_restoring":
            assert event["body"][0]["align"] == (16 if accel else 8)
    other = MODULE.backend_trace(row, role, 1000, not accel, prefix="owned")
    for one, two in zip(trace, other, strict=True):
        if one["op"] == "repeat_restoring":
            one["body"][0]["align"] = two["body"][0]["align"]
        assert one == two


def test_vote_size_only_changes_products_and_every_admitted_size_is_finite():
    baseline = MODULE.backend_trace("candidate", "vote", 3)
    for seats in range(3, 1001):
        trace = MODULE.backend_trace("candidate", "vote", seats)
        changed = [(one, two) for one, two in zip(baseline, trace, strict=True) if one != two]
        if seats == 3:
            assert changed == []
        else:
            assert len(changed) == 1
            assert changed[0][1]["id"] == "backend.relation.products"
            assert changed[0][1]["size"] == 40 * seats
    for row, role, seats, accel in (("unknown", "vote", 3, False), ("candidate", "bad", 3, False),
                                   ("candidate", "vote", 2, False), ("candidate", "vote", 1001, False),
                                   ("candidate", "vote", 3, 1)):
        with pytest.raises(ValueError):
            MODULE.backend_trace(row, role, seats, accel)


def test_critical_order_and_drop_lifetimes_are_preserved():
    trace = MODULE.backend_trace("candidate", "vote", 1000)
    position = {(e["op"], e["id"]): i for i, e in enumerate(trace)}
    assert position["alloc", "backend.lifted"] < position["free", "backend.columns"] < position["alloc", "backend.q"]
    assert position["free", "backend.mask.gate"] < position["free", "backend.mask.tree"] < position["alloc", "backend.lifted"]
    assert position["alloc", "backend.commitment"] < position["free", "backend.bavc.offsets"]
    assert position["alloc", "backend.bavc.offsets"] < position["alloc", "backend.bavc.hidden"] < position["free", "backend.bavc.keys"]
    assert position["alloc", "backend.coefficients.1"] < position["free", "backend.coefficients.0"]
    scratch_frees = [e["id"].rsplit(".", 1)[1] for e in trace if e["op"] == "free" and ".relation." in e["id"]]
    assert scratch_frees == ["state", "theta", "parity", "column", "source", "products"]
    assert [e["id"] for e in trace[-5:]] == [f"backend.{n}" for n in ("commitment", "hidden", "delta", "q", "q_masks")]


def test_source_pin_checks_current_reviewed_code_and_refuses_missing_scope(tmp_path):
    inventory = MODULE.source_inventory()
    assert inventory["aggregate_sha256"] == MODULE.REVIEWED_SOURCE_SHA256
    assert len(inventory["files"]) == 75
    with pytest.raises(ValueError, match="source drift"):
        MODULE.source_inventory(tmp_path)


def test_rustdoc_extraction_omits_line_numbers_but_preserves_code():
    parser = MODULE._RustdocCode()
    parser.feed('<pre><code><a href="#1">1</a><span>let a = 2 &lt; 3;</span>\n<a href="#2">2</a>x</code></pre>')
    assert "".join(parser.parts) == "let a = 2 < 3;\nx"
    pins = MODULE.RUST_SOURCE_SHA256
    assert {"alloc/slice.rs", "core/slice/iter.rs", "core/iter/adapters/flatten.rs", "core/alloc/global.rs"} <= pins.keys()
    assert all(len(value) == 64 for value in pins.values())


def test_metadata_does_not_promote_source_model_to_runtime_certificate():
    assumptions = MODULE.trace_assumptions()
    assert assumptions["complete_certificate"] is False
    assert assumptions["layouts"]["Key_Gf256"] == [40, 8]
    assert assumptions["layouts"]["Tree"] == [24, 8]
    assert "not Rust ABI promises" in assumptions["layout_obligation"]
