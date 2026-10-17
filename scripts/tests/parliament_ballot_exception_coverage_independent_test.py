"""Independent byte fixtures for the narrow Rust/Mach-O exception diagnostic.

Expected LSDA actions follow installed Rust 1.93.1, not generic C++ matching.
These tests execute Python parsers only and never execute retained workers.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import sys

import pytest

STAGE = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("exception_coverage_independent", STAGE / "scripts/parliament_ballot_exception_coverage.py")
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
BASE = 0x100000000
OWNER = BASE + 0x1000


def uleb(value):
    """Produce small independent unsigned fixture encodings."""
    assert value >= 0
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def sleb(value):
    """Produce signed fixture encodings without the helper decoder."""
    out = bytearray()
    while True:
        part = value & 127
        value >>= 7
        done = value == 0 and not part & 64 or value == -1 and part & 64
        out.append(part if done else part | 128)
        if done:
            return bytes(out)


def lsda(rows, actions=b"", type_count=None):
    """Construct omitted-LPStart tables, optional backward four-byte type slots."""
    table = b"".join(uleb(value) for row in rows for value in row)
    tail = b"\x01" + uleb(len(table)) + table + actions
    if type_count is None:
        return b"\xff\xff" + tail
    tail += b"\0" * (4 * type_count)
    return b"\xff\x9b" + uleb(len(tail)) + tail


@pytest.mark.parametrize("index,action", [(0, "cleanup"), (1, "catch"), (2, "catch"), (-1, "filter"), (-65, "filter")])
@pytest.mark.parametrize("padding", [b"", b"\0\0"])
def test_first_signed_action_index_and_one_based_offset(index, action, padding):
    raw = lsda([(0x20, 4, 0x80, 1 + len(padding))], padding + sleb(index) + b"\0", max(index, 0))
    parsed = M.parse_lsda(raw, OWNER, OWNER + 0x100)
    assert parsed["rows"] == [{"start": OWNER + 0x20, "end": OWNER + 0x24,
                               "landing_pad": OWNER + 0x80, "action_offset": 1 + len(padding),
                               "rust_action": action}]
    assert parsed["action_records"][0]["type_index"] == index
    assert parsed["type_targets_resolved"] is False


@pytest.mark.parametrize("first,expected", [(0, "cleanup"), (-1, "filter")])
def test_structural_chain_to_catch_does_not_change_rust_first_action(first, expected):
    # The link starts at action byte1; +1 points to the second record at byte2.
    raw = lsda([(0x20, 4, 0x80, 1)], sleb(first) + b"\x01\x01\0", 1)
    parsed = M.parse_lsda(raw, OWNER, OWNER + 0x100)
    assert parsed["rows"][0]["rust_action"] == expected
    records = parsed["action_records"]
    assert len(records) == 2 and [r["type_index"] for r in records] == [first, 1]
    assert records[0]["next_offset"] == records[1]["offset"]
    assert records[0]["next_offset"] == records[0]["offset"] + 2


def test_shared_action_record_is_not_duplicated_or_reclassified():
    parsed = M.parse_lsda(lsda([(0, 4, 0x80, 1), (8, 4, 0x84, 1)], b"\x7f\0"), OWNER, OWNER + 0x100)
    assert len(parsed["action_records"]) == 1
    assert [row["rust_action"] for row in parsed["rows"]] == ["filter", "filter"]


def test_missing_row_zero_landing_and_cleanup_are_distinct():
    parsed = M.parse_lsda(lsda([(0x20, 4, 0, 0), (0x28, 4, 0x80, 0)]), OWNER, OWNER + 0x100)
    assert parsed["missing_ip_rust_action"] == "terminate"
    assert M.call_action(None, OWNER + 0x20) == "none"
    assert M.call_action(parsed, OWNER + 0x20) == "none"
    assert M.call_action(parsed, OWNER + 0x24) == "terminate"
    assert M.call_action(parsed, OWNER + 0x28) == "cleanup"
    assert M.call_action(parsed, OWNER + 0x2C) == "terminate"


def test_ip_minus_one_uses_last_byte_of_call_not_return_or_first_byte():
    # Deliberately unaligned LSDA interval isolates byte P+3. Call intervals are
    # byte ranges; this synthetic fixture separates all three lookup mistakes.
    parsed = M.parse_lsda(lsda([(0x23, 1, 0x80, 0)]), OWNER, OWNER + 0x100)
    assert M.call_action(parsed, OWNER + 0x20) == "cleanup"
    assert M.call_action(parsed, OWNER + 0x20, ip_before_instruction=True) == "terminate"
    assert M.call_action(parsed, OWNER + 0x23, ip_before_instruction=True) == "cleanup"
    assert M.call_action(parsed, OWNER + 0x24, ip_before_instruction=True) == "terminate"


@pytest.mark.parametrize("raw", [
    b"", b"\xff", b"\xff\xff", b"\xff\xff\x01", b"\xff\xff\x01\x80",
    b"\xff\xff\x01\x04\x01\x01",  # truncated declared call table
    b"\xff\xff\x01\x03\x01\x01\x01",  # incomplete row
    b"\xff\xff\x01\x80\x00",  # redundant table-length LEB
    b"\xff\xff\x01" + b"\xff" * 10 + b"\x01",  # overflow
    b"\xff\x9b\x7f\x01\0",  # type base outside span
    b"\xff\x9b\0\x01\x04\0\x04\x08\0",  # call table beyond type base
    lsda([(0, 4, 0x80, 1)]),  # missing action record
    lsda([(0, 4, 0x80, 1)], b"\0"),  # missing action displacement
    lsda([(0, 4, 0x80, 1)], b"\0\x7f"),  # cycle to same action
    lsda([(0, 4, 0x80, 1)], b"\0\x7e"),  # backwards before action table
    lsda([(0, 4, 0x80, 1)], b"\x01\0"),  # catch without type slots
    lsda([(0, 4, 0x80, 1)], b"\x02\0", 1),  # insufficient type slots
    lsda([(0, 4, 0, 1)], b"\0\0"),  # unsupported action without pad
])
def test_truncated_ambiguous_or_unimplemented_lsda_refuses(raw):
    with pytest.raises(ValueError):
        M.parse_lsda(raw, OWNER, OWNER + 0x100)


@pytest.mark.parametrize("position,value", [(0, 0), (0, 0x1B), (1, 0), (1, 1), (2, 0), (2, 2), (2, 0x11), (2, 0xFF)])
def test_unimplemented_pointer_and_call_site_encodings_refuse(position, value):
    raw = bytearray(lsda([(0, 4, 0x80, 0)]))
    raw[position] = value
    with pytest.raises(ValueError):
        M.parse_lsda(bytes(raw), OWNER, OWNER + 0x100)


@pytest.mark.parametrize("rows", [
    [(0, 0, 0x80, 0)], [(0xFC, 5, 0x80, 0)], [(0x100, 4, 0x80, 0)],
    [(0, 4, 0x100, 0)], [(0, 4, 0x81, 0)],
    [(8, 4, 0x80, 0), (0, 4, 0x80, 0)],
    [(0, 8, 0x80, 0), (4, 4, 0x80, 0)],
])
def test_invalid_call_intervals_or_landing_addresses_refuse(rows):
    with pytest.raises(ValueError):
        M.parse_lsda(lsda(rows), OWNER, OWNER + 0x100)


def compact_fixture(compressed=False, has_lsda=True):
    """Independent regular/compressed tables with explicit byte-level offsets."""
    raw = bytearray(160)
    struct.pack_into("<7I", raw, 0, 1, 28, 2, 36, 1, 40, 2)
    first_encoding = 0x54000000 if has_lsda else 0x04000000
    struct.pack_into("<IIi", raw, 28, first_encoding, 0x02000000, 0x4000)
    struct.pack_into("<III", raw, 40, 0x1000, 80, 64)
    struct.pack_into("<III", raw, 52, 0x1100, 0, 72 if has_lsda else 64)
    if has_lsda:
        struct.pack_into("<II", raw, 64, 0x1000, 0x3000)
    if compressed:
        struct.pack_into("<IHHHH", raw, 80, 3, 12, 2, 20, 1)
        struct.pack_into("<III", raw, 92, 0, (2 << 24) | 0x80, 0x04000001)
    else:
        struct.pack_into("<IHHIIII", raw, 80, 2, 8, 2, 0x1000, first_encoding, 0x1080, 0x02000000)
    image = {"base": BASE, "sections": {
        ("__TEXT", "__unwind_info"): {"address": BASE + 0x2000, "offset": 0, "size": len(raw)},
        ("__TEXT", "__text"): {"address": OWNER, "offset": 0, "size": 0x100},
        ("__TEXT", "__eh_frame"): {"address": BASE + 0x5000, "offset": 0, "size": 0x100},
    }, "function_starts": [OWNER, OWNER + 0x40, OWNER + 0x80]}
    return raw, image


@pytest.mark.parametrize("compressed", [False, True])
def test_compact_regular_and_compressed_address_bases(compressed):
    data, image = compact_fixture(compressed)
    parsed = M.parse_unwind(bytes(data), image)
    assert [(row["start"], row["end"]) for row in parsed["entries"]] == [(OWNER, OWNER + 0x80), (OWNER + 0x80, OWNER + 0x100)]
    assert parsed["descriptors"] == {OWNER: BASE + 0x3000}
    assert parsed["personalities"] == [BASE + 0x4000]  # pointer slot, not routine
    assert parsed["entries"][0]["encoding"] == 0x54000000
    assert parsed["entries"][1]["encoding"] == (0x04000001 if compressed else 0x02000000)
    assert parsed["dwarf_fde_cfi_verified"] is False


def test_folded_no_lsda_ranges_do_not_replace_function_inventory():
    data, image = compact_fixture(has_lsda=False)
    parsed = M.parse_unwind(bytes(data), image)
    assert len(parsed["entries"]) == 2 and len(image["function_starts"]) == 3
    assert parsed["entries"][0]["start"] < OWNER + 0x40 < parsed["entries"][0]["end"]
    assert parsed["descriptors"] == {}


def test_personality_array_is_signed_image_relative_slot_address():
    data, image = compact_fixture()
    struct.pack_into("<i", data, 36, -32)
    assert M.parse_unwind(bytes(data), image)["personalities"] == [BASE - 32]


def test_dwarf_fallback_stays_unresolved_even_without_compact_personality():
    data, image = compact_fixture(has_lsda=False)
    struct.pack_into("<I", data, 92, 0x03000008)
    row = M.parse_unwind(bytes(data), image)["entries"][0]
    assert row["mode"] == "dwarf_fallback" and row["personality_index"] == 0
    assert row["encoding"] & 0xFFFFFF == 8
    del image["sections"][("__TEXT", "__eh_frame")]
    with pytest.raises(ValueError):
        M.parse_unwind(bytes(data), image)


@pytest.mark.parametrize("offset,fmt,value", [
    (0, "I", 2), (8, "I", 257), (16, "I", 4), (24, "I", 1),
    (56, "I", 80), (64, "I", 0x1004), (80, "I", 9),
    (84, "H", 4), (86, "H", 512), (92, "I", 0x14000000),
    (92, "I", 0x64000000), (92, "I", 0xD4000000), (100, "I", 0x05000000),
    (96, "I", 0x1000), (96, "I", 0x1100),
])
def test_corrupt_regular_unwind_metadata_refuses(offset, fmt, value):
    data, image = compact_fixture()
    struct.pack_into("<" + fmt, data, offset, value)
    with pytest.raises(ValueError):
        M.parse_unwind(bytes(data), image)


@pytest.mark.parametrize("offset,fmt,value", [(96, "I", (3 << 24) | 0x80), (88, "H", 4), (86, "H", 1022), (96, "I", 0)])
def test_corrupt_compressed_metadata_refuses(offset, fmt, value):
    data, image = compact_fixture(compressed=True)
    struct.pack_into("<" + fmt, data, offset, value)
    with pytest.raises(ValueError):
        M.parse_unwind(bytes(data), image)


def test_all_owner_landing_pads_seed_without_a_reached_protected_bl():
    instructions = {
        0x100: ("ret", ""), 0x110: ("bl", "0x200"),
        0x114: ("bl", "0x300"), 0x118: ("ret", ""),
        0x200: ("bl", "0x304"), 0x204: ("ret", ""),
    }
    functions = {0x100: {"end": 0x120, "name": "owner"}, 0x200: {"end": 0x208, "name": "cleanup_child"}}
    table = M.parse_lsda(lsda([(4, 4, 0x10, 0), (8, 4, 0x14, 0)]), 0x100, 0x120)
    args = (instructions, functions, {0x300: "_Unwind_Resume", 0x304: "__rust_alloc"}, {0x100: table}, [0x100])
    ordinary = M.coverage_graph(*args, seed_landing_pads=False)
    augmented = M.coverage_graph(*args, seed_landing_pads=True)
    assert ordinary["reachable_instructions"] == [0x100]
    assert augmented["reachable_instructions"] == [0x100, 0x110, 0x114, 0x118, 0x200, 0x204]
    assert augmented["landing_pad_seeds"] == [[0x100, 0x110], [0x100, 0x114]]
    assert augmented["native_symbols"] == {"_Unwind_Resume": 1, "__rust_alloc": 1}
    # Even an unwind runtime call keeps its ordinary continuation; a symbol is
    # not a proof of divergence. Exceptional register/SP entry remains unknown.
    assert [0x114, 0x118, "call_continuation"] in augmented["edges"]
    assert augmented["landing_pad_register_state_known"] is False
    assert augmented["complete_exception_semantics"] is False


def test_unmapped_landing_pad_cannot_disappear_from_coverage():
    table = M.parse_lsda(lsda([(0, 4, 0x10, 0)]), 0x100, 0x120)
    with pytest.raises(ValueError):
        M.coverage_graph({0x100: ("ret", "")}, {0x100: {"end": 0x120, "name": "owner"}}, {}, {0x100: table}, [0x100])


EH_ADDRESS = BASE + 0x8000
SLOT_ADDRESS = BASE + 0x4000
LSDA_ADDRESS = BASE + 0x3000


def eh_fixture(personality=True, lsda_address=LSDA_ADDRESS, cfi=b"\xff\x2f"):
    """Assemble one CIE/FDE using raw field-relative offsets independently."""
    augmentation = b"zPLR\0" if personality else b"zR\0"
    body = bytearray(b"\0" * 4 + b"\x01" + augmentation + b"\x01\x78\x1e")
    positions = {"cie_version": 8, "cie_augmentation": 9, "cie_aug_length": 4 + len(body)}
    body += b"\x07" if personality else b"\x01"
    if personality:
        body += b"\x9b"
        positions["personality"] = 4 + len(body)
        body += struct.pack("<i", SLOT_ADDRESS - (EH_ADDRESS + 4 + len(body)))
        positions["L"] = 4 + len(body)
        body += b"\x10"
    positions["R"] = 4 + len(body)
    body += b"\x10" + cfi
    body += b"\0" * (-len(body) % 4)
    cie = struct.pack("<I", len(body)) + body
    fde_offset = len(cie)
    fde = bytearray(struct.pack("<I", fde_offset + 4))
    positions.update(fde=fde_offset, cie_pointer=fde_offset + 4, pc_begin=fde_offset + 8, pc_range=fde_offset + 16, fde_aug_length=fde_offset + 24)
    fde += struct.pack("<qQ", OWNER - (EH_ADDRESS + fde_offset + 8), 0x80)
    fde += b"\x08" if personality else b"\0"
    if personality:
        positions["lsda"] = fde_offset + 4 + len(fde)
        relative = 0 if lsda_address is None else lsda_address - (EH_ADDRESS + positions["lsda"])
        fde += struct.pack("<q", relative)
    fde += cfi
    fde += b"\0" * (-len(fde) % 4)
    return bytearray(cie + struct.pack("<I", len(fde)) + fde + b"\0" * 4), positions


@pytest.mark.parametrize("personality", [False, True])
@pytest.mark.parametrize("cfi", [b"\0", b"\xff\x2f\xff\xff"])
def test_fde_field_relative_bases_range_scalar_and_uninterpreted_cfi(personality, cfi):
    raw, positions = eh_fixture(personality, cfi=cfi)
    parsed = M.parse_eh_frame(bytes(raw), EH_ADDRESS)
    assert list(parsed["cies"]) == [0] and list(parsed["fdes"]) == [positions["fde"]]
    cie, = parsed["cies"].values()
    fde, = parsed["fdes"].values()
    assert (fde["cie_offset"], fde["start"], fde["end"]) == (0, OWNER, OWNER + 0x80)
    assert cie["augmentation"] == ("zPLR" if personality else "zR")
    assert fde["lsda"] == (LSDA_ADDRESS if personality else None)
    assert fde["personality_slot"] == (SLOT_ADDRESS if personality else None)
    for record in (cie, fde):
        assert raw[record["cfi_start"]:record["cfi_end"]].startswith(cfi)
        assert hashlib.sha256(raw[record["cfi_start"]:record["cfi_end"]]).hexdigest() == record["cfi_sha256"]
    assert parsed["cfi_instructions_interpreted"] is False


def test_fde_zero_encoded_lsda_is_none_before_pc_relative_addition():
    raw, positions = eh_fixture(lsda_address=None)
    assert struct.unpack_from("<q", raw, positions["lsda"])[0] == 0
    fde, = M.parse_eh_frame(bytes(raw), EH_ADDRESS)["fdes"].values()
    assert fde["lsda"] is None and fde["personality_slot"] == SLOT_ADDRESS


@pytest.mark.parametrize("label,fmt,value", [
    ("cie_version", "B", 3), ("cie_augmentation", "B", ord("x")),
    ("cie_aug_length", "B", 6), ("cie_aug_length", "B", 8),
    ("R", "B", 0x1B), ("L", "B", 0x1B),
    ("cie_pointer", "I", 4), ("cie_pointer", "I", 0xFFFFFFFF),
    ("pc_range", "Q", 0), ("pc_range", "Q", 0xFFFFFFFFFFFFFFFF),
    ("fde_aug_length", "B", 7), ("fde_aug_length", "B", 9),
])
def test_unimplemented_or_malformed_cie_fde_header_refuses(label, fmt, value):
    raw, positions = eh_fixture()
    struct.pack_into("<" + fmt, raw, positions[label], value)
    with pytest.raises(ValueError):
        M.parse_eh_frame(bytes(raw), EH_ADDRESS)


@pytest.mark.parametrize("value", [0x1B, 0x10, 0xFF])
def test_personality_encoding_cannot_silently_lose_indirection_or_width(value):
    raw, positions = eh_fixture()
    raw[positions["personality"] - 1] = value
    with pytest.raises(ValueError):
        M.parse_eh_frame(bytes(raw), EH_ADDRESS)


@pytest.mark.parametrize("change", ["dwarf64", "short_record", "unaligned_length", "truncated", "nonzero_after_terminator"])
def test_eh_frame_record_extent_errors_refuse(change):
    raw, positions = eh_fixture()
    if change == "dwarf64": struct.pack_into("<I", raw, 0, 0xFFFFFFFF)
    elif change == "short_record": struct.pack_into("<I", raw, 0, 3)
    elif change == "unaligned_length": struct.pack_into("<I", raw, 0, 5)
    elif change == "truncated": raw = raw[:-8]
    else: raw += b"\x01"
    with pytest.raises(ValueError):
        M.parse_eh_frame(bytes(raw), EH_ADDRESS)


def resolver_fixture():
    raw, positions = eh_fixture()
    parsed = M.parse_eh_frame(bytes(raw), EH_ADDRESS)
    compact = {"entries": [{"start": OWNER, "end": OWNER + 0x100,
                            "mode": "dwarf_fallback", "encoding": 0x03000000 | positions["fde"],
                            "personality_index": 0, "lsda": LSDA_ADDRESS}],
               "descriptors": {OWNER: LSDA_ADDRESS}, "personalities": [SLOT_ADDRESS]}
    image = {"sections": {
        ("__TEXT", "__gcc_except_tab"): {"address": LSDA_ADDRESS, "size": 0x100, "zerofill": False},
        ("__DATA_CONST", "__got"): {"address": SLOT_ADDRESS, "size": 8, "zerofill": False},
    }}
    functions = {OWNER: {"end": OWNER + 0x100, "name": "owner"}}
    return compact, parsed, image, functions


def test_fde_mapping_restores_cie_personality_when_compact_index_is_zero():
    result = M.resolve_unwind(*resolver_fixture())
    row, = result["mappings"]
    assert row["source"] == "fde_augmentation" and row["start"] == OWNER
    assert row["end"] == OWNER + 0x80 and row["compact_end"] == OWNER + 0x100
    assert row["personality_slot"] == SLOT_ADDRESS and row["lsda"] == LSDA_ADDRESS
    assert result["loaded_personality_targets_authenticated"] is False
    assert result["cfi_instructions_interpreted"] is False


@pytest.mark.parametrize("change", ["hint_into_record", "hint_to_cie", "start", "fde_end", "function_end", "lsda", "personality", "unreadable_slot", "zerofill_slot", "outside_lsda", "orphan_fde", "duplicate_hint"])
def test_inconsistent_compact_fde_mapping_refuses(change):
    compact, parsed, image, functions = resolver_fixture()
    row = compact["entries"][0]
    fde, = parsed["fdes"].values()
    if change == "hint_into_record": row["encoding"] += 4
    elif change == "hint_to_cie": row["encoding"] = 0x03000000
    elif change == "start": row["start"] += 4
    elif change == "fde_end": fde["end"] = OWNER + 0x104
    elif change == "function_end": functions[OWNER]["end"] = OWNER + 0x7C
    elif change == "lsda": row["lsda"] += 4
    elif change == "personality": row["personality_index"] = 1; compact["personalities"][0] += 8
    elif change == "unreadable_slot": image["sections"][("__DATA_CONST", "__got")]["size"] = 7
    elif change == "zerofill_slot": image["sections"][("__DATA_CONST", "__got")]["zerofill"] = True
    elif change == "outside_lsda": image["sections"][("__TEXT", "__gcc_except_tab")]["address"] += 4
    elif change == "orphan_fde": parsed["fdes"][999] = dict(fde)
    else: compact["entries"].append(dict(row))
    with pytest.raises(ValueError):
        M.resolve_unwind(compact, parsed, image, functions)


def test_eh_frame_section_virtual_extent_cannot_cross_address_space():
    raw, _ = eh_fixture()
    with pytest.raises(ValueError):
        M.parse_eh_frame(bytes(raw), (1 << 64) - 16)
