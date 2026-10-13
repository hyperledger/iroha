"""Synthetic Mach-O bytes and altered instruction paths for target-catalog checks."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_indirect_targets.py"
SPEC = importlib.util.spec_from_file_location("ballot_indirect_targets", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE = 0x100000000


def macho():
    """Make one independently encoded little-endian Mach-O constant section."""
    data = bytearray(1024)
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x100000C, 0, 2, 1, 152, 0, 0)
    struct.pack_into("<II16sQQQQiiII", data, 32, 0x19, 152, b"__DATA_CONST", BASE, 4096,
                     0, 1024, 3, 3, 1, 0x10)
    struct.pack_into("<16s16sQQ8I", data, 104, b"__const", b"__DATA_CONST", BASE + 512,
                     128, 512, 3, 0, 0, 0, 0, 0, 0)
    for index, size in enumerate([704, 832, 960]):
        struct.pack_into("<4Q", data, 512 + 32 * index, 0x2000 + index * 16, size, 8, 0x3000 + index * 16)
    return data


def constructor():
    """Three constant branches converge without clobbering the vtable register."""
    instructions, names = {}, {}
    for i, bits in enumerate([128, 192, 256]):
        address = 0x1000 + i * 16
        instructions.update({address: ("adrp", f"x8, {BASE:#x} <page>"),
                             address + 4: ("add", f"x8, x8, #{512 + 32 * i:#x}"),
                             address + 8: ("mov", f"w9, #{i}"),
                             address + 12: ("b", "0x1030 <shared>")})
        names[0x2000 + i * 16] = f"core::ptr::drop_in_place<aes::soft::Aes{bits}>::h"
        names[0x3000 + i * 16] = f"<aes::soft::Aes{bits} as Encryptor>::encrypt::h"
    instructions[0x1030] = "stp", "x20, x8, [x19, #0x8]"
    instructions[0x1034] = "ret", ""
    functions = [{"address": "0x1000", "end": "0x1038", "name": "iroha_zkp_vole::prg::Prg::new_portable::h"}]
    rebases = {BASE + 512 + 32 * i + slot for i in range(3) for slot in [0, 24]}
    return instructions, names, functions, rebases


def test_raw_macho_table_words_are_not_inferred_from_symbol_names():
    data = macho()
    descriptors = MODULE.sections(data)
    raw, offset = MODULE.read_constant(data, descriptors, BASE + 544, 32)
    assert offset == 544
    assert raw == struct.pack("<4Q", 0x2010, 832, 8, 0x3010)
    tables = MODULE.catalog_tables(data, *constructor())
    assert [t["level_bits"] for t in tables] == [128, 192, 256]
    assert [t["table_address"] for t in tables] == [hex(BASE + x) for x in [512, 544, 576]]
    assert tables[2]["drop_address"] == "0x2020"
    assert tables[2]["encrypt_address"] == "0x3020"
    assert tables[2]["store_path"][-1]["instruction"] == "stp x20, x8, [x19, #0x8]"


@pytest.mark.parametrize("offset,value", [(0, 0), (4, 7), (8, 2), (16, 1000), (20, 10000),
                                          (32, 0x80000034), (36, 7), (36, 160)])
def test_invalid_or_unsupported_macho_headers_fail_closed(offset, value):
    data = macho()
    struct.pack_into("<I", data, offset, value)
    with pytest.raises(ValueError):
        MODULE.sections(data)


def test_truncated_headers_and_unconsumed_commands_are_rejected():
    with pytest.raises(ValueError):
        MODULE.sections(b"short")
    data = macho()
    struct.pack_into("<I", data, 16, 0)
    with pytest.raises(ValueError, match="unconsumed"):
        MODULE.sections(data)
    data = macho()
    struct.pack_into("<Q", data, 136, BASE - 1)
    with pytest.raises(ValueError, match="section outside"):
        MODULE.sections(data)


@pytest.mark.parametrize("field,value", [("segment", "__DATA"), ("section_flags", 1),
                                         ("segment_flags", 0), ("offset", 999), ("segment_filesize", 520)])
def test_constant_reads_require_exact_file_backed_readonly_mapping(field, value):
    data = macho()
    descriptors = MODULE.sections(data)
    descriptors[0][field] = value
    with pytest.raises(ValueError):
        MODULE.read_constant(data, descriptors, BASE + 512, 32)


def test_constant_boundary_and_ambiguous_sections_are_rejected():
    data = macho()
    descriptors = MODULE.sections(data)
    for address in [BASE + 500, BASE + 620]:
        with pytest.raises(ValueError):
            MODULE.read_constant(data, descriptors, address, 32)
    with pytest.raises(ValueError):
        MODULE.read_constant(data, descriptors * 2, BASE + 512, 32)


def test_rebases_parser_does_not_treat_scalar_or_other_segment_lines_as_pointers():
    text = """Rebase table:
__DATA_CONST __const 0x100000200 pointer
__DATA_CONST __const 0x100000218 pointer
__DATA_CONST __const 0x100000208 text abs32
__DATA __const 0x100000220 pointer
"""
    assert MODULE.parse_rebases(text) == {BASE + 512, BASE + 536}


@pytest.mark.parametrize("mutation", ["missing_rebase", "scalar_rebased", "unknown_target", "wrong_drop",
                                      "extra_method", "missing_table", "bad_size", "pointer_clobber"])
def test_catalog_refuses_incomplete_or_mismatched_table_evidence(mutation):
    data = macho()
    instructions, names, functions, rebases = constructor()
    if mutation == "missing_rebase":
        rebases.remove(BASE + 512)
    elif mutation == "scalar_rebased":
        rebases.add(BASE + 520)
    elif mutation == "unknown_target":
        struct.pack_into("<Q", data, 512, 0x9000)
    elif mutation == "wrong_drop":
        names[0x2000] = "drop_in_place<Aes256>"
    elif mutation == "extra_method":
        names[0x9000] = "<Other as Encryptor>::encrypt::h"
    elif mutation == "missing_table":
        instructions[0x1020] = "mov", "x8, #0"
    elif mutation == "bad_size":
        struct.pack_into("<Q", data, 520, 960)
    elif mutation == "pointer_clobber":
        instructions[0x1008] = "mov", "x8, #0"
    with pytest.raises(ValueError):
        MODULE.catalog_tables(data, instructions, names, functions, rebases)


def test_constructor_pointer_loop_is_not_assigned_an_arbitrary_bound():
    instructions, _, _, _ = constructor()
    instructions[0x1008] = "b", "0x1008 <loop>"
    with pytest.raises(ValueError, match="looped"):
        MODULE.pointer_store(instructions, 0x1008, 0x1000, 0x1038)


def drop_site():
    """Independent destructor slot, null guard, and metadata load sequence."""
    instructions = {0x1000: ("ldp", "x19, x20, [x0]"), 0x1004: ("ldr", "x8, [x20]"),
                    0x1008: ("cbz", "x8, 0x1014 <skip>"), 0x100c: ("mov", "x0, x19"),
                    0x1010: ("blr", "x8"), 0x1014: ("ldr", "x1, [x20, #0x8]"),
                    0x1018: ("cbz", "x1, 0x1020 <skip>"), 0x101c: ("ldr", "x2, [x20, #0x10]"),
                    0x1020: ("ret", "")}
    site = {"address": "0x1010", "function": "Prg drop", "kind": "indirect_call", "caller_depth_bytes": 32}
    function = {"address": "0x1000", "end": "0x1024", "name": "Prg drop"}
    return site, instructions, function


def test_drop_and_encrypt_slots_use_different_target_sets():
    tables = MODULE.catalog_tables(macho(), *constructor())
    result = MODULE.catalog_site(*drop_site(), tables)
    assert result["slot_offset_bytes"] == 0
    assert [t["address"] for t in result["conditional_targets"]] == ["0x2000", "0x2010", "0x2020"]
    site = {"address": "0x1018", "function": "Prg::fill::h", "kind": "indirect_call", "caller_depth_bytes": 288}
    instructions = {0x1000: ("ldp", "x9, x8, [x0]"), 0x1004: ("ldr", "x8, [x8, #0x18]"),
                    0x1008: ("stp", "x8, x9, [sp, #0x10]"), 0x100c: ("mov", "x0, x9"),
                    0x1010: ("ldp", "x8, x0, [sp, #0x10]"), 0x1014: ("mov", "x2, x23"),
                    0x1018: ("blr", "x8"), 0x101c: ("ret", "")}
    function = {"address": "0x1000", "end": "0x1020", "name": "Prg::fill::h"}
    result = MODULE.catalog_site(site, instructions, function, tables)
    assert result["slot_offset_bytes"] == 24
    assert [t["address"] for t in result["conditional_targets"]] == ["0x3000", "0x3010", "0x3020"]
    instructions[0x1014] = "mov", "x8, x0"
    with pytest.raises(ValueError, match="pre-call"):
        MODULE.catalog_site(site, instructions, function, tables)
    instructions[0x1014] = "mov", "x2, x23"
    instructions[0x1004] = "ldr", "x8, [x8, #0x20]"
    with pytest.raises(ValueError, match="encrypt"):
        MODULE.catalog_site(site, instructions, function, tables)


@pytest.mark.parametrize("address,changed", [(0x1010, ("blr", "x9")), (0x1004, ("ldr", "x8, [x20, #8]")),
                                            (0x1008, ("cbz", "x8, 0x1018")), (0x101c, ("ret", "")),
                                            (0x100c, ("mov", "x8, x0"))])
def test_changed_destructor_load_or_guard_is_not_resolved(address, changed):
    site, instructions, function = drop_site()
    instructions[address] = changed
    with pytest.raises(ValueError):
        MODULE.catalog_site(site, instructions, function, MODULE.catalog_tables(macho(), *constructor()))


def test_slot_windows_cannot_cross_the_owning_function_boundary():
    tables = MODULE.catalog_tables(macho(), *constructor())
    site, instructions, function = drop_site()
    function["address"] = "0x1004"
    with pytest.raises(ValueError, match="pre-call"):
        MODULE.catalog_site(site, instructions, function, tables)
    site = {"address": "0x1010", "function": "Prg::fill::h", "kind": "indirect_call", "caller_depth_bytes": 288}
    instructions = {0x1000: ("nop", ""), 0x1004: ("nop", ""),
                    0x1008: ("ldp", "x8, x0, [sp, #0x10]"), 0x100c: ("mov", "x2, x23"),
                    0x1010: ("blr", "x8"), 0x1014: ("nop", ""),
                    0x1018: ("ldp", "x9, x8, [x0]"), 0x101c: ("ldr", "x8, [x8, #0x18]"),
                    0x1020: ("stp", "x8, x9, [sp, #0x10]")}
    function = {"address": "0x1000", "end": "0x1020", "name": "Prg::fill::h"}
    with pytest.raises(ValueError, match="encrypt"):
        MODULE.catalog_site(site, instructions, function, tables)


def test_frozen_analyzer_uses_checked_source_bytes_and_rejects_drift(tmp_path):
    directory = tmp_path / MODULE.BASE
    directory.mkdir(parents=True)
    template = directory / "parliament_ballot_stack_audit.py.template"
    data = b"VALUE = 73\n"
    template.write_bytes(data)
    (directory / "receipt.json").write_text(json.dumps({"source_after": {"scripts/parliament_ballot_stack_audit.py": hashlib.sha256(data).hexdigest()}}))
    assert MODULE.load_analyzer(tmp_path).VALUE == 73
    template.write_bytes(b"VALUE = 99\n")
    with pytest.raises(ValueError, match="changed"):
        MODULE.load_analyzer(tmp_path)


def test_existing_output_is_never_overwritten(tmp_path):
    old = tmp_path / "catalog.json"
    old.write_text("prior successful evidence\n")
    with pytest.raises(FileExistsError):
        MODULE.run(MODULE.ROOT, tmp_path)
    assert old.read_text() == "prior successful evidence\n"


def test_conditional_graph_expansion_preserves_old_graph_and_other_gaps():
    analyzer = MODULE.load_analyzer(MODULE.ROOT)
    function = {"address": "0x1000", "name": "root", "calls": [], "frame_errors": [],
                "local_frame_plus_red_zone_bytes": 160,
                "gaps": [{"address": "0x1004", "kind": "indirect_call", "detail": "x8", "caller_depth_bytes": 32},
                         {"address": "0x1008", "kind": "native_edge", "detail": "_unknown", "caller_depth_bytes": 32}]}
    leaf = {"address": "0x2000", "name": "leaf", "calls": [], "frame_errors": [], "gaps": [], "local_frame_plus_red_zone_bytes": 192}
    report = {"functions": [function, leaf], "roots": [{"address": "0x1000"}]}
    snapshot = copy.deepcopy(report)
    sites = [{"address": "0x1004", "function": "root", "caller_depth_bytes": 32,
              "conditional_targets": [{"address": "0x2000"}]}]
    result = MODULE.rerun_regions(analyzer, report, sites)[0]
    assert report == snapshot
    assert result["resolved_region_stack_bytes"] == 224
    assert result["frontier_kind_counts"] == {"native_edge": 1}
    assert result["complete_stack_bound_bytes"] is None
    sites[0]["conditional_targets"][0]["address"] = "0x9999"
    with pytest.raises(ValueError, match="absent"):
        MODULE.rerun_regions(analyzer, report, sites)
