"""Independently check historical OpaqueField ARM64 paths and refusal controls.

The fixtures are immutable repository captures, not newly built executables.
These checks establish no callee, allocator, current-build or qualification bound.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

import pytest

HERE = Path(__file__).resolve()
ROOT = next(parent for parent in HERE.parents
            if (parent / "Cargo.toml").is_file() and (parent / "docs/validation").is_dir())
HELPER = HERE.parents[1] / "parliament_ballot_opaque_field_bound.py"
SPEC = importlib.util.spec_from_file_location("opaque_field_under_test", HELPER)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
CAPTURE = ROOT / "docs/validation/parliament_ballot_current_candidate/stack"
START = {"portable": 0x100013B28, "accel": 0x100013B2C}
SPAN = 0x9C
U64_MAX = 2**64 - 1


@lru_cache(maxsize=2)
def captured_text(mode):
    return (CAPTURE / mode / "disassembly.txt").read_text()


def independent_body(mode):
    """Read the fixed instruction interval without the helper's parser."""
    instructions = {}
    for line in captured_text(mode).splitlines():
        found = re.match(r"^([0-9a-f]+):\s+([a-z.]+)\s*(.*)$", line)
        if found:
            address = int(found[1], 16)
            if START[mode] <= address < START[mode] + SPAN:
                operands = found[3].split("<", 1)[0].split(";", 1)[0].strip()
                instructions[address] = (found[2], operands)
    return instructions


def ordinary_path_offsets(mode):
    """Enumerate this finite captured CFG, retaining a final call's fallthrough."""
    body = independent_body(mode)
    paths = []
    pending = [(START[mode], ())]
    while pending:
        address, prefix = pending.pop()
        if address == START[mode] + SPAN:
            paths.append((tuple(node-START[mode] for node in prefix), "outside_body"))
            continue
        assert address in body and address not in prefix
        opcode, operands = body[address]
        visited = (*prefix, address)
        if opcode == "ret":
            paths.append((tuple(node-START[mode] for node in visited), "return"))
        elif opcode in ("b", "b.ls", "cbz"):
            target = int(operands.split(",")[-1].strip(), 16)
            pending.append((target, visited))
            if opcode != "b":
                pending.append((address+4, visited))
        else:
            pending.append((address+4, visited))
    return paths


@pytest.mark.parametrize("mode", ("portable", "accel"))
def test_parser_and_independent_cfg_identify_all_four_actual_paths(mode):
    start = START[mode]
    body = M.parse_body(captured_text(mode), start, start+SPAN)
    assert body == independent_body(mode)
    assert list(sorted(body)) == list(range(start, start+SPAN, 4))
    assert len(body) == 39
    paths = ordinary_path_offsets(mode)
    assert len(paths) == 4
    call_kinds = {0x40: "shim", 0x4C: "alloc", 0x6C: "memcpy", 0x98: "handle_error"}
    signatures = {(len(path), terminal, tuple(call_kinds[offset] for offset in path if offset in call_kinds))
                  for path, terminal in paths}
    assert signatures == {
        (20, "return", ()),
        (23, "return", ("memcpy",)),
        (29, "return", ("shim", "alloc", "memcpy")),
        (18, "outside_body", ("shim", "alloc", "handle_error")),
    }


@pytest.mark.parametrize("mode", ("portable", "accel"))
def test_symbolic_profiles_cover_full_unsigned_length_partition_and_exact_local_counts(mode):
    result = M.analyze_body(independent_body(mode), mode)
    profiles = result["profiles"]
    assert set(profiles) == {"oversize", "empty", "allocated", "allocation_failure"}
    expected = {"oversize": ([257, U64_MAX], 20, [], "error"),
                "empty": ([0, 0], 23, ["memcpy"], "success"),
                "allocated": ([1, 256], 29, ["shim", "alloc", "memcpy"], "success"),
                "allocation_failure": ([1, 256], 18, ["shim", "alloc", "handle_error"], "unknown_frontier")}
    for name, (interval, local, kinds, outcome) in expected.items():
        profile = profiles[name]
        assert profile["length_interval"] == interval
        assert profile["local_instructions"] == local
        assert [call["kind"] for call in profile["calls"]] == kinds
        assert profile["outcome"] == outcome
    assert result["maximum_local_instructions"] == 29
    assert result["frame_bytes"] == 48
    assert result["own_stack_including_red_zone_bytes"] == 176
    assert result["unknown_terms"]


# Every replacement changes an actual control or data obligation. analyze_body
# must reject from its interpreter/contract, without relying on a body hash pin.
MUTATIONS = [
    (0x18, "cmp", "x1, #0xff", "exclusive acceptance at 256"),
    (0x18, "cmp", "x1, #0x101", "permits 257-byte allocation"),
    (0x18, "cmp", "w1, #0x100", "truncates unsigned slice length"),
    (0x18, "cmp", "x0, #0x100", "guards pointer instead of length"),
    (0x1C, "b.lt", "@0x38", "signed guard"),
    (0x1C, "b.lo", "@0x38", "drops equality boundary"),
    (0x1C, "b.hi", "@0x38", "inverts length guard"),
    (0x1C, "b", "@0x38", "bypasses length guard"),
    (0x1C, "b.ls", "@0x40", "skips source and zero preparation"),
    (0x14, "mov", "x20, x0", "writes output to slice pointer"),
    (0x10, "mov", "x19, x0", "loses slice length"),
    (0x10, "mov", "w19, w1", "truncates saved full-width actual length"),
    (0x20, "mov", "w8, #0x0", "changes error discriminant"),
    (0x28, "mov", "w8, #0xff", "changes reported bound"),
    (0x30, "mov", "w8, #0x0", "returns success on oversize"),
    (0x34, "b", "@0x38", "error falls into allocation"),
    (0x38, "mov", "x21, x1", "copies from length as pointer"),
    (0x3C, "cbz", "x0, @0x5c", "zero check tests pointer"),
    (0x3C, "cbnz", "x19, @0x5c", "inverts empty branch"),
    (0x3C, "cbz", "x19, @0x78", "empty branch skips vector output"),
    (0x44, "mov", "x0, x21", "allocator size is source pointer"),
    (0x44, "mov", "x0, x1", "allocator size uses shim-clobbered register"),
    (0x44, "mov", "x0, #0x101", "allocator request exceeds cap"),
    (0x48, "mov", "w1, #0x2", "allocator alignment differs"),
    (0x50, "cbnz", "x0, @0x90", "inverts allocation failure"),
    (0x50, "cbz", "x19, @0x90", "tests length after allocation"),
    (0x50, "cbz", "x0, @0x60", "null result becomes copy destination"),
    (0x54, "mov", "x22, x21", "loses allocated pointer ownership"),
    (0x5C, "mov", "w22, #0x0", "empty dangling pointer null"),
    (0x60, "mov", "x0, x21", "copy aliases original input"),
    (0x64, "mov", "x1, x22", "copy source is new allocation"),
    (0x68, "mov", "x2, #0x101", "copy size exceeds cap"),
    (0x68, "mov", "x2, x0", "copy size is pointer"),
    (0x70, "mov", "x8, #0x1", "successful vector tagged error"),
    (0x74, "stp", "x22, x19, [x20, #0x8]", "capacity and pointer exchanged"),
    (0x78, "str", "x21, [x20, #0x18]", "stores pointer as length or actual"),
    (0x7C, "str", "x19, [x20]", "stores length as result discriminant"),
    (0x00, "stp", "x22, x21, [sp, #-0x20]!", "frame too small"),
    (0x04, "stp", "x20, x19, [sp, #0x20]", "saved registers overlap"),
    (0x80, "ldp", "x29, x30, [sp, #0x10]", "return address restored incorrectly"),
    (0x84, "ldp", "x19, x20, [sp, #0x10]", "saved register order exchanged"),
    (0x88, "ldp", "x22, x21, [sp], #0x20", "stack not restored"),
    (0x8C, "ret", "x19", "unexpected return register"),
    (0x90, "mov", "w0, #0x2", "failure alignment changed"),
    (0x94, "mov", "x1, x21", "failure size lost"),
    (0x98, "ret", "", "erases unknown frontier"),
    (0x98, "b", "@0x8c", "cleans no frame before return"),
    (0x98, "brk", "#0x1", "relabels callee continuation as trap"),
    (0x58, "b", "@0x38", "cycle has no finite bound"),
    (0x58, "b", "@0x9c", "ordinary body escape"),
    (0x58, "blr", "x22", "unresolved indirect call"),
]


@pytest.mark.parametrize("mode", ("portable", "accel"))
@pytest.mark.parametrize("offset,opcode,operands,reason", MUTATIONS, ids=[item[3] for item in MUTATIONS])
def test_actual_constructor_semantic_mutations_refuse(mode, offset, opcode, operands, reason):
    body = independent_body(mode)
    operands = re.sub(r"@0x([0-9a-f]+)", lambda match: hex(START[mode] + int(match[1], 16)), operands)
    body[START[mode] + offset] = (opcode, operands)
    with pytest.raises(ValueError):
        M.analyze_body(body, mode)


@pytest.mark.parametrize("mode", ("portable", "accel"))
@pytest.mark.parametrize("offset", (0x40, 0x4C, 0x6C, 0x98))
def test_each_resolved_call_identity_is_required(mode, offset):
    body = independent_body(mode)
    body[START[mode]+offset] = ("bl", "0x100000000")
    with pytest.raises(ValueError):
        M.analyze_body(body, mode)


@pytest.mark.parametrize("mode", ("portable", "accel"))
def test_missing_added_or_misaligned_body_instructions_refuse(mode):
    original = independent_body(mode)
    for address, operation in ((START[mode]+0x18, None),
                               (START[mode]+SPAN, ("ret", "")),
                               (START[mode]+1, ("nop", ""))):
        body = copy.deepcopy(original)
        if operation is None:
            del body[address]
        else:
            body[address] = operation
        with pytest.raises(ValueError):
            M.analyze_body(body, mode)


@pytest.mark.parametrize("mode", ("portable", "accel"))
def test_harmless_branch_change_derives_shorter_count_without_hash_short_circuit(mode):
    original = M.analyze_body(independent_body(mode), mode)
    body = independent_body(mode)
    # x22 was just set from x0; x0 still holds the same allocation pointer.
    # Skipping the redundant restore preserves semantics only on this path.
    body[START[mode]+0x58] = ("b", hex(START[mode]+0x64))
    changed = M.analyze_body(body, mode)
    assert changed["profiles"]["allocated"]["local_instructions"] == 28
    assert changed["maximum_local_instructions"] == 28
    for name, before in original["profiles"].items():
        after = changed["profiles"][name]
        for field in ("length_interval", "outcome", "calls", "output_stores"):
            assert after[field] == before[field]
        if name != "allocated":
            assert after["local_instructions"] == before["local_instructions"]


@pytest.mark.parametrize("mode", ("portable", "accel"))
def test_each_profile_binds_arguments_result_ownership_and_unknown_fallthrough(mode):
    result = M.analyze_body(independent_body(mode), mode)
    profiles = result["profiles"]
    expected_arguments = {
        "oversize": [],
        "empty": [[1, "input", "length"]],
        "allocated": [[], ["length", 1], ["allocated", "input", "length"]],
        "allocation_failure": [[], ["length", 1], [1, "length"]],
    }
    for name, profile in profiles.items():
        assert [call["arguments"] for call in profile["calls"]] == expected_arguments[name]
        assert all(call["frame_depth_bytes"] == 48 for call in profile["calls"])
        assert all(call["length_interval"] == profile["length_interval"] for call in profile["calls"])
        assert profile["maximum_frame_bytes"] == 48
        assert profile["local_instructions"] == len(profile["path"])
        assert len(set(profile["path"])) == len(profile["path"])
    stores = lambda name: {(s["offset"], s["bytes"]): s["value"] for s in profiles[name]["output_stores"]}
    assert stores("oversize") == {(0, 8): 1, (8, 2): 8, (16, 8): 256, (24, 8): "length"}
    assert stores("empty") == {(0, 8): 0, (8, 8): "length", (16, 8): 1, (24, 8): "length"}
    assert stores("allocated") == {(0, 8): 0, (8, 8): "length", (16, 8): "allocated", (24, 8): "length"}
    failure = profiles["allocation_failure"]
    assert stores("allocation_failure") == {}
    assert failure["hypothetical_return_continuation"] == hex(START[mode]+SPAN)
    assert failure["path"][-1] == hex(START[mode]+SPAN-4)
    assert result["cfg"][hex(START[mode]+SPAN-4)] == []
    assert "allocation-error work and continuation" in result["unknown_terms"]
    assert result["no_complete_constructor_cost_bound"] is True
    paths = {(tuple(int(pc, 16)-START[mode] for pc in profile["path"]),
              "outside_body" if profile["outcome"] == "unknown_frontier" else "return")
             for profile in profiles.values()}
    assert paths == set(ordinary_path_offsets(mode))


def test_instruction_parser_presentation_and_malformed_ranges():
    start = START["portable"]
    lines = [f"{address:x}:\t{op}\t{operand} ; inert annotation"
             for address, (op, operand) in independent_body("portable").items()]
    text = "\n".join(lines)
    assert M.parse_body(text, start, start+SPAN) == independent_body("portable")
    for changed in (text+"\n"+lines[0], "\n".join(lines[1:]),
                    text.replace(f"{start:x}:", f"{start+1:x}:", 1)):
        with pytest.raises(ValueError):
            M.parse_body(changed, start, start+SPAN)
    for a, b in ((True, start+SPAN), (start, False), (start, start), (start+4, start),
                 (str(start), start+SPAN), (start, start+0.5)):
        with pytest.raises(ValueError):
            M.parse_body(text, a, b)
    for operand in ("x0", "0x123, x0", "0x123 trailing", "-0x4", "256"):
        with pytest.raises(ValueError):
            M.branch(operand)
    assert M.branch("0x123") == 0x123
    with pytest.raises(ValueError):
        M.analyze_body(independent_body("portable"), "other")


def small_macho():
    """Make a minimal ARM64 image with a known file/VM address displacement."""
    base, position = 0x100001000, 0x100
    payload = bytes(range(64))
    header = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 1, 152, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", base, 64, position, 64, 5, 5, 1, 0)
    section = struct.pack("<16s16sQQ8I", b"__text", b"__TEXT", base, 64, position, 2, 0, 0, 0, 0, 0, 0)
    prefix = header+segment+section
    return prefix+bytes(position-len(prefix))+payload, base, payload


def test_native_byte_extraction_uses_section_mapping_and_refuses_bad_images():
    binary, base, payload = small_macho()
    assert M.text_bytes(binary, base+8, 12) == payload[8:20]
    assert M.text_bytes(binary, base, 64) == payload
    assert M.text_bytes(binary, base+64, 0) == b""
    for address, length in ((base-4, 4), (base+60, 8), (base, -1)):
        with pytest.raises(ValueError):
            M.text_bytes(binary, address, length)
    malformed = [b"", binary[:31], binary[:100], binary[:-1]]
    for offset, value in ((0, 0), (4, 7), (12, 1), (16, 2), (20, 0),
                          (36, 8), (36, 153), (32+64, 2)):
        changed = bytearray(binary)
        struct.pack_into("<I", changed, offset, value)
        malformed.append(bytes(changed))
    for changed in malformed:
        with pytest.raises(ValueError):
            M.text_bytes(changed, base, 4)


@pytest.fixture(scope="module")
def authenticated_report():
    return M.report(ROOT)


def test_retained_image_source_and_correspondence_hash_bridge_stays_historical(authenticated_report):
    result = authenticated_report
    assert result["verdict"] == "PASS_UNDER_STATED_PREMISES"
    assert result["input_sha256"] == result["input_after_sha256"]
    for name, expected in result["input_sha256"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected
    assert "no existing analyzer rerun" in result["correspondence_scope"]
    original_source = ROOT / "docs/validation/parliament_ballot_frontend_bound/analysis/source/src/framing.rs.template"
    source_hash = "784c28ba9a115cb2775d78f7147fdcbd1fac5835affd1ef9938a7f1a2c2fc0a0"
    assert result["input_sha256"][str(original_source)] == source_hash
    source_name = str(ROOT / "crates/iroha_parliament_ballot_proof/src/framing.rs")
    assert result["historical_build_inputs"][source_name]["sha256"] == source_hash
    text = original_source.read_text()
    assert "pub const OPAQUE_FIELD_MAX_BYTES: usize = 256;" in text
    item = text.split("impl OpaqueField {", 1)[1].split("/// The bytes.", 1)[0]
    assert item.index("if bytes.len() > OPAQUE_FIELD_MAX_BYTES") < item.index("Ok(Self(bytes.to_vec()))")
    expected_images = {
        "portable": ("3f658228a903c50c9a549baedd0b822e14fca03f654659720cb434b83d9bb9dc",
                     "7701d2617eeb092fbd27ad23bdfeb9803aa7283d9386d52f660e1f1ee25a88ca"),
        "accel": ("40219e559636f092c3b4197f6e65eb1ab083f25444fcafd2b635221b4f7e18e7",
                  "a6a18284b5f0d90cf75cf0ff7f011a9d08c8334d10d6f0be6f6983f2eeb9e844"),
    }
    for mode, (image_hash, body_hash) in expected_images.items():
        actual = result["modes"][mode]
        assert actual["binary_sha256"] == image_hash
        assert actual["body_sha256"] == body_hash
        assert actual["source_sha256"] == source_hash
        assert (actual["body_start"], actual["body_end"]) == (hex(START[mode]), hex(START[mode]+SPAN))
    lock = str(ROOT / "Cargo.lock")
    archived = ROOT / "docs/validation/parliament_ballot_current_candidate/build-v2/generated-source/root-Cargo.lock.template.template"
    old = "2e12f608e4819adab3e5ab49ba66bdb5005a1c3c1c4830a8298b02e12056200e"
    assert result["historical_build_inputs"][lock] == {"sha256": old, "resolved_path": str(archived)}
    assert result["input_sha256"][str(archived)] == old
    live = hashlib.sha256(Path(lock).read_bytes()).hexdigest()
    if live != old:
        assert result["observed_build_input_drift"][lock] == {
            "captured": old, "observed": live, "original_resolved_path": str(archived)}
    else:
        assert lock not in result["observed_build_input_drift"]
    for flag in ("applies_to_current_checkout", "complete_constructor_cost_certificate",
                 "complete_workspace_certificate", "complete_native_cost_certificate",
                 "physical_cost_calibrated", "profile_qualified", "production_gate_changed"):
        assert result[flag] is False


@pytest.mark.parametrize("relative", (
    "docs/validation/parliament_ballot_current_candidate/SHA256SUMS",
    "docs/validation/parliament_ballot_current_correspondence/SHA256SUMS",
    "docs/validation/parliament_ballot_current_correspondence/analysis/report.json",
    "docs/validation/parliament_ballot_frontend_bound/analysis/source/src/framing.rs.template",
    "docs/validation/parliament_ballot_current_candidate/build-v2/generated-source/root-Cargo.lock.template.template",
    "docs/validation/parliament_ballot_current_candidate/stack/portable/disassembly.txt",
    "docs/validation/parliament_ballot_current_candidate/stack/accel/disassembly.txt",
    "docs/validation/parliament_ballot_current_candidate/stack/portable/stubs.txt",
    "docs/validation/parliament_ballot_current_candidate/stack/accel/stubs.txt",
))
def test_retained_source_and_artifact_drift_refuses(monkeypatch, relative):
    original = M.digest
    target = (ROOT / relative).resolve()
    monkeypatch.setattr(M, "digest", lambda path: "0"*64 if Path(path).resolve() == target else original(path))
    with pytest.raises(ValueError, match="retained identity changed"):
        M.report(ROOT)


def test_mid_analysis_evidence_change_refuses(monkeypatch):
    original = M.digest
    target = ROOT / "docs/validation/parliament_ballot_current_candidate/SHA256SUMS"
    reads = 0
    def changed(path):
        nonlocal reads
        value = original(path)
        if Path(path).resolve() == target:
            reads += 1
            if reads > 1:
                return "0"*64
        return value
    monkeypatch.setattr(M, "digest", changed)
    with pytest.raises(ValueError, match="changed during analysis"):
        M.report(ROOT)
    assert reads == 2


@pytest.mark.parametrize("mode", ("portable", "accel"))
def test_original_binary_identity_change_refuses(monkeypatch, mode):
    build = json.loads((ROOT / "docs/validation/parliament_ballot_current_candidate/build-v2/build-receipt.json").read_text())
    target = Path(build["binaries"][mode]["path"]).resolve()
    original = M.digest
    monkeypatch.setattr(M, "digest", lambda path: "0"*64 if Path(path).resolve() == target else original(path))
    with pytest.raises(ValueError, match="retained identity changed"):
        M.report(ROOT)


def test_live_lock_observation_cannot_replace_original_build_identity(monkeypatch):
    target = (ROOT / "Cargo.lock").resolve()
    original = M.digest
    monkeypatch.setattr(M, "digest", lambda path: "0"*64 if Path(path).resolve() == target else original(path))
    result = M.report(ROOT)
    old = "2e12f608e4819adab3e5ab49ba66bdb5005a1c3c1c4830a8298b02e12056200e"
    assert result["historical_build_inputs"][str(target)]["sha256"] == old
    assert result["observed_build_input_drift"][str(target)]["observed"] == "0"*64
    assert result["observed_build_input_drift"][str(target)]["captured"] == old
    assert str(target) not in result["input_sha256"]
    assert result["applies_to_current_checkout"] is False
    assert result["profile_qualified"] is False


def test_cli_qualification_refusal_unknown_and_exclusive_output(tmp_path, monkeypatch, authenticated_report):
    monkeypatch.setattr(M, "report", lambda root: copy.deepcopy(authenticated_report))
    output = tmp_path / "qualified.json"
    args = ["--root", str(ROOT), "--out", str(output)]
    assert M.main(args+["--require-qualified"]) == 2
    before = output.read_bytes()
    assert json.loads(before)["profile_qualified"] is False
    with pytest.raises(SystemExit) as failure:
        M.main(args)
    assert failure.value.code == 2
    assert output.read_bytes() == before
    def refuse(root):
        raise ValueError("mutated evidence")
    monkeypatch.setattr(M, "report", refuse)
    refused = tmp_path / "unknown.json"
    assert M.main(["--root", str(ROOT), "--out", str(refused)]) == 1
    record = json.loads(refused.read_text())
    assert record["verdict"] == "UNKNOWN" and record["error"] == "mutated evidence"
    for flag in ("applies_to_current_checkout", "complete_constructor_cost_certificate",
                 "complete_workspace_certificate", "complete_native_cost_certificate",
                 "physical_cost_calibrated", "profile_qualified", "production_gate_changed"):
        assert record[flag] is False
