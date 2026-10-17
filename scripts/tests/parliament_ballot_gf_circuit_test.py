"""Check disjoint polynomial product-XOR kernels against independent arithmetic.

These finite tests cover the emitted component circuits, not a source-to-circuit
compiler, whole-simulator construction, primitive assumption, or qualification.
The reference uses polynomial long division; it does not reuse reduction columns.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import random
import sys

import pytest

HERE = Path(__file__).resolve()
ROOT = next(parent for parent in HERE.parents
            if (parent / "Cargo.toml").is_file() and (parent / "docs/validation").is_dir())
HELPER = HERE.parents[1] / "parliament_ballot_gf_circuit.py"
SPEC = importlib.util.spec_from_file_location("gf_circuit_under_test", HELPER)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)

# Constants derived independently from the three polynomial interfaces; the
# elementary convention is one CX and five elementary gates per Toffoli.
ROWS = {
    "gf256_mul": (256, 256, 256, (10, 5, 2, 0), 131072, 1298, 656658, 511, 1279),
    "gf256_mul_u64": (256, 64, 256, (10, 5, 2, 0), 32768, 508, 164348, 319, 895),
    "gf256_mul_tripled": (256, 768, 768, (19, 17, 4, 0), 393216, 1788, 1967868, 1023, 2815),
}
FLAGS = {
    "actual_simulator_execution", "complete_resource_vector", "whole_program_quantum_gate_bound",
    "compiled_memory_or_allocator_bound", "physical_workspace_qualified", "actual_input_collision_bridge",
    "primitive_advantage_assumed", "independent_cryptographic_review", "profile_qualified", "production_gate_changed",
}


def polynomial_product(left, right):
    """Schoolbook carryless product with no reduction or ordinary carries."""
    result, degree = 0, 0
    while right:
        if right & 1:
            result ^= left << degree
        right >>= 1
        degree += 1
    return result


def polynomial_remainder(value, degree, taps):
    """Cancel highest monomials by long division, independent of the emitter."""
    divisor = (1 << degree) + sum(1 << tap for tap in taps)
    while value.bit_length() > degree:
        value ^= divisor << (value.bit_length() - degree - 1)
    return value


def reference(g, left, right):
    return polynomial_remainder(polynomial_product(left, right), g.n, g.taps)


def packed_state(wires, cases):
    """Each host integer bit denotes a separate classical basis assignment."""
    state = [0] * (1 + max(itertools.chain.from_iterable(wires.values())))
    for lane, case in enumerate(cases):
        for name, value in zip(("a", "b", "z", "work"), case, strict=True):
            for bit, wire in enumerate(wires[name]):
                state[wire] |= ((value >> bit) & 1) << lane
    return state


def interpret(state, gates):
    """Own phase-free CX/CCX interpreter; return independently observed counts."""
    seen = Counter()
    for gate in gates:
        operation, *wires = gate
        assert operation in {"CX", "CCX"}
        assert len(wires) == (2 if operation == "CX" else 3)
        assert len(set(wires)) == len(wires)
        assert all(type(wire) is int and 0 <= wire < len(state) for wire in wires)
        if operation == "CX":
            state[wires[1]] ^= state[wires[0]]
        else:
            state[wires[2]] ^= state[wires[0]] & state[wires[1]]
        seen[operation] += 1
    return seen


def expected_clean(g, cases):
    return [(a, b, z ^ reference(g, a, b), 0) for a, b, z, work in cases if work == 0]


def check_resources(g, observed):
    counts = M.resources(g)
    assert counts["X"] == 0
    assert counts["CNOT"] == observed["CX"]
    assert counts["Toffoli"] == observed["CCX"]
    assert counts["elementary_one_two_qubit_gates"] == observed["CX"] + 5 * observed["CCX"]
    assert counts["sequential_elementary_depth_upper_bound"] == counts["elementary_one_two_qubit_gates"]
    assert counts["base_oracle_calls"] == 0
    assert counts["clean_work_bits"] == g.p + g.q - 1
    assert counts["source_and_output_bits"] == g.p + g.q + g.n
    assert counts["total_interface_bits"] == 2 * (g.p + g.q) + g.n - 1


@pytest.mark.parametrize("args", [
    (1, 1, 2, (1, 0)), (2, 2, 2, (0,)), (2, 3, 3, (1, 0)),
    (3, 2, 4, (3, 0)), (3, 3, 3, (2, 1, 0)), (4, 2, 4, (1, 0)),
])
def test_every_small_clean_basis_and_arbitrary_output_matches_long_division(args):
    g = M.Geometry(*args)
    cases = [(a, b, z, 0) for a in range(1 << g.p) for b in range(1 << g.q) for z in range(1 << g.n)]
    wires, gates = M.layout(g), list(M.emit(g))
    state = packed_state(wires, cases)
    original = state.copy()
    seen = interpret(state, gates)
    assert state == packed_state(wires, expected_clean(g, cases))
    check_resources(g, seen)
    # Reverse the actual gate sequence, then also check this XOR map's own
    # involution. Both comparisons include every input/output/work wire.
    interpret(state, reversed(gates))
    assert state == original
    interpret(state, gates)
    interpret(state, gates)
    assert state == original


@pytest.mark.parametrize("name", tuple(ROWS))
def test_actual_width_streamed_gates_cover_limb_edges_random_values_and_cleanup(name):
    p, q, n, taps, ccx, cx, elementary, work, total = ROWS[name]
    g = M.geometry(name)
    assert (g.p, g.q, g.n, g.taps) == (p, q, n, taps)
    rng = random.Random(0x20261014 + q)
    cases = [(0, 0, 0, 0), (0, (1 << q) - 1, (1 << n) - 1, 0),
             ((1 << p) - 1, 0, rng.getrandbits(n), 0),
             ((1 << p) - 1, (1 << q) - 1, (1 << n) - 1, 0),
             (1, 1, rng.getrandbits(n), 0), (1 << (p - 1), 1 << (q - 1), 0, 0)]
    # Both sides of every source 64-bit limb boundary, at every actual width.
    left_bits = sorted({0, p - 1, *(bit for boundary in range(64, p, 64) for bit in (boundary - 1, boundary))})
    right_bits = sorted({0, q - 1, *(bit for boundary in range(64, q, 64) for bit in (boundary - 1, boundary))})
    cases += [(1 << bit, 1 << (q - 1), rng.getrandbits(n), 0) for bit in left_bits]
    cases += [(1 << (p - 1), 1 << bit, rng.getrandbits(n), 0) for bit in right_bits]
    cases += [(rng.getrandbits(p), rng.getrandbits(q), rng.getrandbits(n), 0) for _ in range(20)]
    cases += [(equal, equal, rng.getrandbits(n), 0) for equal in (0, 1, (1 << min(p, q)) - 1, rng.getrandbits(min(p, q)))]
    wires = M.layout(g)
    state = packed_state(wires, cases)
    seen = interpret(state, M.emit(g))
    assert state == packed_state(wires, expected_clean(g, cases))
    assert seen == {"CCX": ccx, "CX": cx}
    check_resources(g, seen)
    result = M.resources(g)
    assert (result["elementary_one_two_qubit_gates"], result["clean_work_bits"], result["total_interface_bits"]) == (elementary, work, total)


@pytest.mark.parametrize("name", tuple(ROWS))
def test_each_actual_reduction_column_is_independent_monomial_long_division(name):
    g = M.geometry(name)
    columns = tuple(polynomial_remainder(1 << degree, g.n, g.taps) for degree in range(g.p + g.q - 1))
    assert M.reduction_columns(g) == columns
    assert M.resources(g)["CNOT"] == sum(value.bit_count() for value in columns)


@pytest.mark.parametrize("name", tuple(ROWS))
def test_pinned_source_style_u64_reduction_agrees_on_every_reachable_monomial(name):
    """Static Python transcription of reduce_limbs, not a Rust execution.

    Compare its whole finite polynomial basis against independent long division
    and the emitter. Native word buffers contain one extra leading coefficient
    which is always zero for these operand widths; no native memory bound follows.
    """
    g = M.geometry(name)
    limbs, native_words = g.n // 64, (g.p + g.q) // 64
    assert native_words == {"gf256_mul": 8, "gf256_mul_u64": 5, "gf256_mul_tripled": 16}[name]
    mask = (1 << 64) - 1
    columns = M.reduction_columns(g)
    for degree in range(g.p + g.q - 1):
        words = [0] * native_words
        words[degree // 64] = 1 << (degree % 64)
        for high in range(native_words - 1, limbs - 1, -1):
            word = words[high]
            words[high] = 0
            for tap in g.taps:
                words[high - limbs] ^= (word << tap) & mask
                if tap:
                    words[high - limbs + 1] ^= word >> (64 - tap)
        assert words[limbs:] == [0] * (native_words - limbs)
        reduced = sum(word << (64 * index) for index, word in enumerate(words[:limbs]))
        assert reduced == polynomial_remainder(1 << degree, g.n, g.taps) == columns[degree]


def test_tripled_highest_monomial_is_gf768_reduction_not_three_gf256_products():
    g = M.geometry("gf256_mul_tripled")
    left, right = 1 << 255, 1 << 767
    correct = sum(1 << degree for degree in (273, 271, 258, 254))
    assert reference(g, left, right) == correct
    blockwise = 0
    for block in range(3):
        value = (right >> (256 * block)) & ((1 << 256) - 1)
        blockwise |= polynomial_remainder(polynomial_product(left, value), 256, (10, 5, 2, 0)) << (256 * block)
    assert blockwise != correct
    # Widening is the coefficient-preserving inclusion; it is not generally
    # multiplicative between the two quotient rings.
    assert reference(M.geometry("gf256_mul"), 1 << 255, 2) != reference(g, 1 << 255, 2)


def test_little_endian_scalar_is_a_polynomial_not_integer_multiplication():
    scalar = int.from_bytes(bytes.fromhex("0100000000000080"), "little")
    assert scalar == (1 << 63) | 1
    g = M.geometry("gf256_mul_u64")
    assert reference(g, 3, 3) == 5
    assert reference(g, 3, scalar) == (3 << 63) ^ 3
    assert reference(g, 3, 3) != (3 * 3)


def test_gate_stages_show_bilinear_parity_and_exact_reverse_uncompute():
    g = M.Geometry(3, 3, 3, (1, 0))
    wires = M.layout(g)
    gates = list(M.emit(g))
    forward, middle, reverse = gates[:9], gates[9:-9], gates[-9:]
    assert all(gate[0] == "CCX" for gate in forward)
    assert all(gate[0] == "CX" for gate in middle)
    assert reverse == forward[::-1]
    cases = [(3, 3, 6, 0), (7, 7, 1, 0)]
    state = packed_state(wires, cases)
    interpret(state, forward)
    expected = [(a, b, z, polynomial_product(a, b)) for a, b, z, _ in cases]
    assert state == packed_state(wires, expected)
    # Both a0*b1 and a1*b0 hit degree one and cancel (XOR, not OR).
    assert polynomial_product(3, 3) == 5
    interpret(state, middle)
    assert state == packed_state(wires, [(a, b, z ^ reference(g, a, b), polynomial_product(a, b)) for a, b, z, _ in cases])
    interpret(state, reverse)
    assert state == packed_state(wires, expected_clean(g, cases))


@pytest.mark.parametrize("mutation", ("missing_uncompute", "missing_output_xor", "wrong_control", "wrong_tap"))
def test_substantive_circuit_mutations_are_detected_by_full_state_reference(mutation):
    g = M.Geometry(3, 3, 3, (1, 0))
    wires, gates = M.layout(g), list(M.emit(g))
    cases = [(a, b, 5, 0) for a in range(8) for b in range(8)]
    if mutation == "missing_uncompute":
        gates = gates[:-g.p * g.q]
    elif mutation == "missing_output_xor":
        del gates[g.p * g.q]
    elif mutation == "wrong_control":
        operation, first, second, target = gates[1]
        gates[1] = (operation, first, wires["b"][0], target)
    else:
        gates = list(M.emit(M.Geometry(3, 3, 3, (2, 0))))
    state = packed_state(wires, cases)
    interpret(state, gates)
    assert state != packed_state(wires, expected_clean(g, cases))


def test_dirty_work_is_restored_but_does_not_satisfy_clean_interface():
    g = M.Geometry(2, 2, 2, (1, 0))
    wires, gates = M.layout(g), list(M.emit(g))
    cases = [(0, 0, 0, 1)]
    state = packed_state(wires, cases)
    interpret(state, gates)
    assert state == packed_state(wires, [(0, 0, 1, 1)])
    assert state != packed_state(wires, [(0, 0, 0, 0)])
    interpret(state, reversed(gates))
    assert state == packed_state(wires, cases)


def test_complete_tiny_basis_permutation_and_entangled_external_reference():
    g = M.Geometry(1, 1, 2, (1, 0))
    wires, gates = M.layout(g), list(M.emit(g))
    # Entire five-wire interface, including dirty work: elementary reversible
    # gates must induce a bijection. This is a finite permutation control.
    basis = list(itertools.product(range(2), range(2), range(4), range(2)))
    state = packed_state(wires, basis)
    original = state.copy()
    interpret(state, gates)
    images = [sum(((bits >> lane) & 1) << wire for wire, bits in enumerate(state)) for lane in range(len(basis))]
    assert len(set(images)) == len(basis)
    interpret(state, reversed(gates))
    assert state == original
    # Formal amplitudes on distinct joint basis labels, with an untouched
    # external reference bit. The phase-free permutation preserves amplitudes;
    # input reduced states need not remain unchanged after z is entangled.
    amplitudes = [1, 1j, -1, -1j]
    cases = [(0, 0, 1, 0), (1, 0, 2, 0), (0, 1, 3, 0), (1, 1, 0, 0)]
    state = packed_state(wires, cases)
    reference_wire = len(state)
    state.append(0b1010)
    expected = packed_state(wires, expected_clean(g, cases)) + [0b1010]
    interpret(state, gates)
    def joint_terms(values):
        return {sum(((bits >> lane) & 1) << wire for wire, bits in enumerate(values)): amplitude
                for lane, amplitude in enumerate(amplitudes)}
    assert joint_terms(state) == joint_terms(expected)
    assert state[reference_wire] == 0b1010


def test_sparse_disjoint_layout_preserves_unused_wires():
    g = M.Geometry(3, 2, 3, (1, 0))
    wires = {name: tuple(3 * wire + 2 for wire in region) for name, region in M.layout(g).items()}
    cases = [(7, 3, 5, 0), (2, 1, 6, 0)]
    state = packed_state(wires, cases)
    used = set(itertools.chain.from_iterable(wires.values()))
    unused = set(range(len(state))) - used
    for wire in unused:
        state[wire] = 3
    expected = packed_state(wires, expected_clean(g, cases))
    for wire in unused:
        expected[wire] = 3
    interpret(state, M.emit(g, wires))
    assert state == expected


def test_emitter_snapshots_mutable_layout_after_validation_before_first_yield():
    g = M.Geometry(3, 2, 3, (1, 0))
    wires = {name: list(region) for name, region in M.layout(g).items()}
    expected = list(M.emit(g))
    stream = M.emit(g, wires)
    first = next(stream)
    for region in wires.values():
        region[:] = [0] * len(region)
    wires["a"] = []
    assert [first, *stream] == expected


@pytest.mark.parametrize("left,right", list(itertools.combinations(("a", "b", "z", "work"), 2)))
def test_every_pair_of_aliasing_regions_refuses_before_any_gate(left, right):
    g = M.Geometry(3, 2, 3, (1, 0))
    wires = {name: list(region) for name, region in M.layout(g).items()}
    wires[right][0] = wires[left][0]
    with pytest.raises(ValueError, match="overlap"):
        next(M.emit(g, wires))


@pytest.mark.parametrize("change", ("duplicate", "missing", "extra", "wrong_width", "wrong_type", "bool", "negative", "float", "large"))
def test_malformed_layout_refuses_before_any_gate(change):
    g = M.Geometry(3, 2, 3, (1, 0))
    wires = {name: list(region) for name, region in M.layout(g).items()}
    if change == "duplicate":
        wires["a"][1] = wires["a"][0]
    elif change == "missing":
        del wires["work"]
    elif change == "extra":
        wires["external"] = []
    elif change == "wrong_width":
        wires["b"].append(100)
    elif change == "wrong_type":
        wires["z"] = set(wires["z"])
    else:
        wires["a"][0] = {"bool": True, "negative": -1, "float": 0.0, "large": 1 << 63}[change]
    with pytest.raises(ValueError):
        next(M.emit(g, wires))


@pytest.mark.parametrize("args", [
    (True, 2, 3, (1, 0)), (2, False, 3, (1, 0)), (2, 2, True, (0,)),
    (0, 1, 3, (0,)), (1, 0, 3, (0,)), (-1, 1, 3, (0,)),
    (4, 2, 3, (0,)), (2, 4, 3, (0,)), (1, 1, 1, (0,)), (1, 1, 769, (0,)),
    (2.0, 2, 3, (0,)), (2, "2", 3, (0,)), (2, 2, 3.0, (0,)),
    (2, 2, 3, []), (2, 2, 3, [1, 0]), (2, 2, 3, ()), (2, 2, 3, (1,)),
    (2, 2, 3, (0, 0)), (2, 2, 3, (-1, 0)), (2, 2, 3, (3, 0)),
    (2, 2, 3, (True, 0)), (2, 2, 3, (1.0, 0)),
])
def test_malformed_geometry_refuses(args):
    with pytest.raises(ValueError):
        M.Geometry(*args)


def test_geometry_is_frozen_and_tap_order_does_not_change_polynomial():
    first, second = M.Geometry(3, 3, 3, (1, 0)), M.Geometry(3, 3, 3, (0, 1))
    assert first.modulus == second.modulus == 11
    assert M.reduction_columns(first) == M.reduction_columns(second)
    assert list(M.emit(first)) == list(M.emit(second))
    with pytest.raises(FrozenInstanceError):
        first.p = 2


@pytest.mark.parametrize("name", ("unknown", "GF256_MUL", None, 1, True, []))
def test_unknown_kernel_refuses(name):
    with pytest.raises(ValueError):
        M.geometry(name)


@pytest.mark.parametrize("function", ("layout", "reduction_columns", "resources", "emit"))
def test_geometry_consumers_refuse_unvalidated_objects(function):
    with pytest.raises(ValueError):
        value = getattr(M, function)({"p": 3, "q": 3, "n": 3, "taps": (1, 0)})
        if function == "emit":
            next(value)


def assert_false_flags(value):
    assert set(M.FALSE_FLAGS) == FLAGS
    assert all(value[name] is False for name in FLAGS)


def test_report_authenticates_exact_four_sources_and_keeps_all_exclusions():
    result = M.report(ROOT)
    independent = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in M.PINS}
    assert result["source_sha256_before"] == result["source_sha256_after"] == independent == M.PINS
    assert result["selected_source_count"] == 4
    assert result["schema"] == "parliament-gf-circuit-v1"
    assert result["verdict"] == "PASS_UNDER_STATED_PREMISES"
    assert result["checked_component_construction"] is True
    assert set(result["kernels"]) == set(ROWS)
    assert_false_flags(result)
    assert len(result["exclusions"]) == 6
    exclusions = " ".join(result["exclusions"])
    for phrase in ("not a complete compiler/dependency", "aliased registers are not", "entanglement", "whole-program history/cleanup", "No source operation-count multiplication", "qualification remain open"):
        assert phrase in exclusions


@pytest.mark.parametrize("relative", tuple(M.PINS))
def test_each_selected_input_byte_drift_is_refused(relative, monkeypatch):
    original = Path.read_bytes
    def changed(path):
        data = original(path)
        return data + b"\nchanged input\n" if path == ROOT / relative else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="selected source/evidence changed"):
        M.report(ROOT)


def test_late_source_drift_is_refused_instead_of_repinning(monkeypatch):
    original, reads = M.digest, Counter()
    def changed(path):
        reads[path] += 1
        value = original(path)
        return "0" * 64 if path == ROOT / M.FIELD and reads[path] == 2 else value
    monkeypatch.setattr(M, "digest", changed)
    with pytest.raises(ValueError, match="selected source/evidence changed"):
        M.report(ROOT)
    assert reads[ROOT / M.FIELD] == 2


@pytest.mark.parametrize("change", ("before", "after", "checked", "qualified", "complete", "missing", "invalid_json"))
def test_prior_accounting_semantics_do_not_transfer_qualification(change, monkeypatch):
    original = Path.read_text
    previous = json.loads(original(ROOT / M.ACCOUNTING))
    if change in ("before", "after"):
        previous[f"source_sha256_{change}"][M.FIELD] = "f" * 64
    elif change == "checked":
        previous["checked_logical_accounting"] = False
    elif change == "qualified":
        previous["profile_qualified"] = True
    elif change == "complete":
        previous["complete_resource_vector"] = True
    elif change == "missing":
        del previous["source_sha256_before"]
    # Deliberately bypass only the read-text value while keeping byte hashes
    # real: this isolates semantic guards, not an allowed input substitution.
    def changed(path, *args, **kwargs):
        if path == ROOT / M.ACCOUNTING:
            return "{" if change == "invalid_json" else json.dumps(previous)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", changed)
    with pytest.raises((ValueError, KeyError)):
        M.report(ROOT)


@pytest.mark.parametrize("before,after", [
    ("Gf256, limbs = 4", "Gf256, limbs = 3"),
    ("Gf768, limbs = 12", "Gf768, limbs = 8"),
    ("taps = [10, 5, 2, 0]", "taps = [10, 5, 1, 0]"),
    ("taps = [19, 17, 4, 0]", "taps = [19, 17, 3, 0]"),
    ("    Gf256,\n    Gf768,", "    Gf256,\n    Gf512,"),
    ("Gf256, limbs = 4, taps = [10, 5, 2, 0]", ""),
])
def test_source_geometry_correspondence_refuses_changed_choices(before, after):
    source = (ROOT / M.FIELD).read_text()
    assert source.count(before) == 1
    with pytest.raises(ValueError):
        M.source_geometry(source.replace(before, after, 1))


def test_duplicate_source_geometry_refuses_even_when_values_match():
    source = (ROOT / M.FIELD).read_text()
    with pytest.raises(ValueError, match="duplicate"):
        M.source_geometry(source + "\nGf256, limbs = 4, taps = [10, 5, 2, 0]\n")


@pytest.mark.parametrize("require_qualified,exit_code", [(False, 0), (True, 2)])
def test_cli_normal_and_qualification_refusal_write_same_scoped_result(tmp_path, require_qualified, exit_code):
    destination = tmp_path / "result.json"
    args = ["--root", str(ROOT), "--out", str(destination)]
    if require_qualified:
        args.append("--require-qualified")
    assert M.main(args) == exit_code
    result = json.loads(destination.read_text())
    assert result["verdict"] == "PASS_UNDER_STATED_PREMISES"
    assert result["checked_component_construction"] is True
    assert_false_flags(result)


@pytest.mark.parametrize("require_qualified", (False, True))
def test_cli_missing_inputs_write_unknown_with_all_gates_false(tmp_path, require_qualified):
    destination = tmp_path / "unknown.json"
    args = ["--root", str(tmp_path / "absent"), "--out", str(destination)]
    if require_qualified:
        args.append("--require-qualified")
    assert M.main(args) == 1
    result = json.loads(destination.read_text())
    assert result["verdict"] == "UNKNOWN"
    assert result["checked_component_construction"] is False
    assert result["error"]
    assert_false_flags(result)


def test_cli_refuses_overwriting_existing_evidence_before_reading_sources(tmp_path, monkeypatch):
    destination = tmp_path / "preserved.json"
    destination.write_bytes(b"original evidence\n")
    def must_not_run(_):
        pytest.fail("existing output must be rejected before report generation")
    monkeypatch.setattr(M, "report", must_not_run)
    with pytest.raises(SystemExit) as error:
        M.main(["--root", str(ROOT), "--out", str(destination)])
    assert error.value.code == 2
    assert destination.read_bytes() == b"original evidence\n"
