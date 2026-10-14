#!/usr/bin/env python3
"""Conservative exception-table and cleanup coverage of retained ARM64 images.

This static diagnostic never runs a worker. It parses selected compact-unwind
and LSDA bytes, then seeds every listed landing pad of each reached owner. It
does not interpret DWARF CFI, restore landing-pad registers, prove native unwind
semantics, or produce any complete resource or production qualification bound.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import struct

INVENTORY_SHA256 = "578292d845726e3149b8da68f3350efd9e9739816744e1b664e165475361929e"
FDE_INVENTORY_SHA256 = "36e4aa2a8cc83c6650cf22089fe8d74dc743c114bc506c8860a3f66363a5a587"
FALSE_FLAGS = dict(complete_exception_semantics=False, dwarf_fde_cfi_verified=False,
                   complete_native_cost_certificate=False, complete_stack_certificate=False,
                   complete_workspace_certificate=False, physical_cost_calibrated=False,
                   applies_to_current_checkout=False, profile_qualified=False,
                   production_gate_changed=False, worker_executed=False)
STRAIGHT = set("""add addp adds addv adr adrp aese aesimc aesmc and ands asr bfi bfxil bic bics bif
bsl cas casa casab casal casalb casb casl ccmn ccmp cinc clz cmeq cmgt cmhi cmn
cmp cneg cnt csel cset csetm csinc csinv dmb dup eon eor eor3 ext extr fmov isb ld1
ld1r ld2 ld4 ldadd ldaddab ldaddal ldaddl ldapr ldaprb ldapur ldapurb ldp ldr
ldrb ldrh ldrsb ldrsh ldrsw ldur ldurb ldurh lsl lsr madd mov movi movk msub
mul mvn neg nop orr rbit rev ror sbc sbcs sbfx shl shrn smaddl st1 stlr stlrb
stlur stlurb stp str strb strh stur sturb sturh sub subs swpab swpal swpb swplb sxtb
sxtw tst ubfiz ubfx udiv umaddl umaxp uminv umulh umull uqsub ushl ushll ushll2
ushr uzp1 xar xtn zip1""".split())
CONDITIONAL = {"cbz", "cbnz", "tbz", "tbnz"} | {
    "b." + suffix for suffix in "eq ne cs hs cc lo mi pl vs vc hi ls ge lt gt le al nv".split()
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_range(data, offset, length, reason="range outside bytes"):
    require(type(offset) is int and type(length) is int and offset >= 0 and length >= 0
            and offset <= len(data) and length <= len(data) - offset, reason)
    return data[offset:offset + length]


def unpack(data, offset, fmt):
    return struct.unpack(fmt, bounded_range(data, offset, struct.calcsize(fmt)))


def leb(data, offset, *, signed=False, limit=None):
    """Bounded 64-bit canonical LEB; return value and next byte offset."""
    limit = len(data) if limit is None else limit
    require(type(limit) is int and 0 <= offset < limit <= len(data), "LEB starts outside bound")
    start, value, shift = offset, 0, 0
    for _ in range(10):
        require(offset < limit, "truncated LEB")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        shift += 7
        if not byte & 128:
            if signed and byte & 64:
                value -= 1 << shift
            require(-(1 << 63) <= value < (1 << 63) if signed else 0 <= value < (1 << 64), "LEB overflow")
            # Refuse alternative redundant encodings, so table boundaries have
            # one reviewed interpretation. This is stricter than Rust's reader.
            remaining, encoded = value, []
            while True:
                part = remaining & 127
                remaining >>= 7
                done = (remaining == 0 and not part & 64) or (remaining == -1 and part & 64) if signed else remaining == 0
                encoded.append(part if done else part | 128)
                if done:
                    break
            require(data[start:offset] == bytes(encoded), "noncanonical LEB")
            return value, offset
    raise ValueError("overlong LEB")


def parse_macho(data):
    """Read checked thin little-endian ARM64 executable sections and starts."""
    magic, cpu, subtype, filetype, count, command_bytes, flags, reserved = unpack(data, 0, "<8I")
    require((magic, cpu, subtype, filetype, reserved) == (0xFEEDFACF, 0x0100000C, 0, 2, 0), "unsupported Mach-O header")
    bounded_range(data, 32, command_bytes)
    require(0 < count <= command_bytes // 8, "invalid load-command count")
    sections, segments, function_command = {}, {}, None
    cursor = 32
    for _ in range(count):
        command, size = unpack(data, cursor, "<II")
        require(size >= 8 and size % 8 == 0 and cursor + size <= 32 + command_bytes, "invalid load command")
        if command == 0x19:
            require(size >= 72, "short segment command")
            name = bounded_range(data, cursor + 8, 16).split(b"\0", 1)[0].decode("ascii")
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = unpack(data, cursor + 24, "<4Q4I")
            require(name not in segments and size == 72 + 80 * nsects, "duplicate or malformed segment")
            bounded_range(data, fileoff, filesize)
            require(filesize <= vmsize and vmaddr + vmsize <= (1 << 64), "segment bounds overflow")
            segments[name] = dict(address=vmaddr, size=vmsize, offset=fileoff, file_size=filesize)
            for index in range(nsects):
                pos = cursor + 72 + 80 * index
                section = bounded_range(data, pos, 16).split(b"\0", 1)[0].decode("ascii")
                parent = bounded_range(data, pos + 16, 16).split(b"\0", 1)[0].decode("ascii")
                address, length, offset, align, reloff, nreloc, sflags, _, _, _ = unpack(data, pos + 32, "<2Q8I")
                key = (parent, section)
                require(parent == name and key not in sections, "duplicate or foreign section")
                require(vmaddr <= address and length <= vmaddr + vmsize - address, "section outside segment")
                require(align <= 31 and address % (1 << align) == 0, "section alignment")
                zerofill = sflags & 255 in (1, 12, 18)
                if not zerofill:
                    bounded_range(data, offset, length)
                    require(fileoff <= offset and length <= fileoff + filesize - offset
                            and address - vmaddr == offset - fileoff, "section file/VM mismatch")
                sections[key] = dict(address=address, offset=offset, size=length, flags=sflags, zerofill=zerofill)
        elif command == 0x26:
            require(size == 16 and function_command is None, "duplicate function-start command")
            function_command = unpack(data, cursor + 8, "<II")
        cursor += size
    require(cursor == 32 + command_bytes and "__TEXT" in segments, "load-command extent")
    for key in (("__TEXT", "__text"), ("__TEXT", "__unwind_info"), ("__TEXT", "__gcc_except_tab")):
        require(key in sections and not sections[key]["zerofill"], "required section missing")
    # Only file-backed sections are compared; zero-fill has no on-disk bytes.
    ranges = sorted((s["offset"], s["offset"] + s["size"]) for s in sections.values() if not s["zerofill"] and s["size"])
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "overlapping file sections")
    require(function_command is not None, "missing function starts")
    raw = bounded_range(data, *function_command)
    base = segments["__TEXT"]["address"]
    text = sections[("__TEXT", "__text")]
    starts, offset, address = [], 0, base
    while True:
        delta, offset = leb(raw, offset)
        if delta == 0:
            require(not any(raw[offset:]), "function-start trailing bytes")
            break
        address += delta
        require(text["address"] <= address < text["address"] + text["size"] and address % 4 == 0, "invalid function start")
        starts.append(address)
    require(starts and len(starts) == len(set(starts)), "empty or duplicate function starts")
    return dict(base=base, sections=sections, function_starts=starts, segments=segments)


def section_bytes(data, image, name):
    value = image["sections"][("__TEXT", name)]
    return bounded_range(data, value["offset"], value["size"])


def parse_unwind(data, image):
    """Decode compact range metadata; DWARF fallback remains an opaque mode."""
    raw = section_bytes(data, image, "__unwind_info")
    version, co, cn, po, pn, io, count = unpack(raw, 0, "<7I")
    require(version == 1 and count >= 2 and cn <= 256 and pn <= 3, "unsupported unwind header")
    regions = [(0, 28)]
    def region(offset, length):
        bounded_range(raw, offset, length)
        require(offset % 4 == 0 and (not length or offset >= 28), "unwind alignment")
        if length:
            require(all(offset + length <= a or offset >= b for a, b in regions), "overlapping unwind arrays")
            regions.append((offset, offset + length))
    region(co, 4 * cn)
    region(po, 4 * pn)
    region(io, 12 * count)
    common = list(unpack(raw, co, "<" + "I" * cn))
    # The SDK stores signed 32-bit image-relative addresses of pointer slots,
    # not direct function addresses. No slot value/loaded personality is assumed.
    personalities = [image["base"] + value for value in unpack(raw, po, "<" + "i" * pn)]
    indices = [unpack(raw, io + 12 * i, "<III") for i in range(count)]
    require(all(a[0] < b[0] and a[2] <= b[2] for a, b in zip(indices, indices[1:])), "unsorted unwind indices")
    require(indices[-1][1] == 0 and all(item[1] for item in indices[:-1]), "invalid unwind sentinel")
    text = image["sections"][("__TEXT", "__text")]
    text_end = text["address"] + text["size"]
    require(text["address"] <= image["base"] + indices[0][0] < text_end
            and image["base"] + indices[-1][0] in (text_end, text_end + 1), "unwind sentinel/text bounds")
    rows, descriptors, pages = [], {}, []
    for index, (start, page, lsda) in enumerate(indices[:-1]):
        next_start, _, next_lsda = indices[index + 1]
        require((next_lsda - lsda) % 8 == 0, "invalid LSDA descriptor span")
        region(lsda, next_lsda - lsda)
        previous = None
        for pos in range(lsda, next_lsda, 8):
            function, table = unpack(raw, pos, "<II")
            require(start <= function < next_start and (previous is None or previous < function), "unsorted/outside LSDA owner")
            owner = image["base"] + function
            require(owner not in descriptors, "duplicate LSDA owner")
            descriptors[owner] = image["base"] + table
            previous = function
        kind, entry_offset, entry_count = unpack(raw, page, "<IHH")
        require(entry_count > 0 and kind in (2, 3), "unsupported second-level page")
        if kind == 2:
            require(entry_offset >= 8 and entry_count <= 511 and entry_offset + 8 * entry_count <= 4096, "invalid regular page")
            region(page, 8)
            region(page + entry_offset, 8 * entry_count)
            entries = [unpack(raw, page + entry_offset + 8 * i, "<II") for i in range(entry_count)]
        else:
            encoding_offset, encoding_count = unpack(raw, page + 8, "<HH")
            require(entry_offset >= 12 and entry_count <= 1021 and cn + encoding_count <= 256
                    and entry_offset + 4 * entry_count <= 4096
                    and encoding_offset + 4 * encoding_count <= 4096, "invalid compressed page")
            region(page, 12)
            region(page + entry_offset, 4 * entry_count)
            region(page + encoding_offset, 4 * encoding_count)
            local = list(unpack(raw, page + encoding_offset, "<" + "I" * encoding_count))
            encodings = common + local
            entries = []
            for i in range(entry_count):
                word, = unpack(raw, page + entry_offset + 4 * i, "<I")
                require(word >> 24 < len(encodings), "compressed encoding index")
                entries.append((start + (word & 0xFFFFFF), encodings[word >> 24]))
        require(entries[0][0] == start and all(start <= f < next_start for f, _ in entries)
                and all(a[0] < b[0] for a, b in zip(entries, entries[1:])), "unordered/outside compact ranges")
        pages.append(dict(kind=kind, offset=page, count=entry_count))
        for position, (function, encoding) in enumerate(entries):
            stop = entries[position + 1][0] if position + 1 < len(entries) else next_start
            mode = encoding & 0x0F000000
            require(mode in (0, 0x02000000, 0x03000000, 0x04000000), "unsupported ARM64 unwind mode")
            require(not encoding & 0x80000000, "non-start compact encoding unsupported")
            personality = (encoding >> 28) & 3
            require(personality <= pn, "missing personality slot")
            owner = image["base"] + function
            has_lsda = bool(encoding & 0x40000000)
            require(has_lsda == (owner in descriptors), "compact flag/LSDA descriptor mismatch")
            if mode == 0x03000000:
                eh = image["sections"].get(("__TEXT", "__eh_frame"))
                require(eh is not None and (encoding & 0xFFFFFF) < eh["size"], "DWARF fallback outside eh_frame")
            rows.append(dict(start=owner, end=image["base"] + stop, encoding=encoding,
                             mode={0: "none", 0x02000000: "frameless", 0x03000000: "dwarf_fallback", 0x04000000: "frame"}[mode],
                             personality_index=personality, lsda=descriptors.get(owner)))
    require(set(descriptors) <= {row["start"] for row in rows}, "descriptor without compact row")
    return dict(entries=rows, descriptors=descriptors, personalities=personalities, pages=pages,
                raw_sha256=digest(raw), dwarf_fde_cfi_verified=False)


def parse_lsda(raw, owner_start, owner_end):
    """Decode the observed Rust LSDA encoding subset, without inferring unwind.

    Accept omitted LPStart only; hence offsets use the supplied owner start.
    Type table encodings ff/9b are recorded, not resolved. Rust's first signed
    action-index semantics is reported separately from generic action links.
    """
    require(type(owner_start) is int and type(owner_end) is int and 0 <= owner_start < owner_end < 1 << 64, "invalid LSDA owner")
    lpstart, types = unpack(raw, 0, "<BB")
    require(lpstart == 255 and types in (255, 0x9B), "unsupported LSDA pointer encoding")
    cursor, type_base = 2, None
    if types != 255:
        offset, cursor = leb(raw, cursor)
        type_base = cursor + offset
        require(cursor <= type_base <= len(raw), "type table outside LSDA")
    encoding, = unpack(raw, cursor, "<B")
    cursor += 1
    require(encoding == 1, "unsupported call-site encoding")
    length, cursor = leb(raw, cursor)
    table_start, table_end = cursor, cursor + length
    bounded_range(raw, table_start, length)
    require(type_base is None or table_end <= type_base, "call table overlaps type base")
    rows, previous = [], owner_start
    while cursor < table_end:
        values = []
        for _ in range(4):
            value, cursor = leb(raw, cursor, limit=table_end)
            values.append(value)
        start, length, landing, action = values
        first, end = owner_start + start, owner_start + start + length
        require(length > 0 and previous <= first < end <= owner_end, "invalid/overlapping call-site interval")
        require(landing == 0 or owner_start <= owner_start + landing < owner_end, "landing pad outside owner")
        require(landing == 0 or (owner_start + landing) % 4 == 0, "unaligned landing pad")
        require(landing != 0 or action == 0, "action without landing pad")
        rows.append(dict(start=first, end=end, landing_pad=owner_start + landing if landing else None,
                         action_offset=action, rust_action="none" if not landing else "cleanup"))
        previous = end
    require(cursor == table_end, "call table partial row")
    records = {}
    high_type = 0
    for row in rows:
        action = row["action_offset"]
        if not action:
            continue
        pos, visited = table_end + action - 1, set()
        first = True
        while True:
            require(pos >= table_end and pos not in visited, "action cycle or backwards table escape")
            visited.add(pos)
            limit = len(raw) if type_base is None else type_base
            type_index, next_pos = leb(raw, pos, signed=True, limit=limit)
            displacement_pos = next_pos
            displacement, next_pos = leb(raw, next_pos, signed=True, limit=limit)
            record = dict(offset=pos, end=next_pos, type_index=type_index, next_displacement=displacement,
                          next_offset=displacement_pos + displacement if displacement else None)
            if pos in records:
                require(records[pos] == record, "inconsistent action record")
            records[pos] = record
            high_type = max(high_type, type_index)
            if first:
                row["rust_action"] = "cleanup" if type_index == 0 else "catch" if type_index > 0 else "filter"
                first = False
            if not displacement:
                break
            pos = displacement_pos + displacement
    ordered = sorted(records.values(), key=lambda r: r["offset"])
    require(all(a["end"] <= b["offset"] for a, b in zip(ordered, ordered[1:])), "overlapping action records")
    if high_type:
        require(type_base is not None and type_base - 4 * high_type >= table_end, "missing type entries")
        require(all(record["end"] <= type_base - 4 * high_type for record in ordered), "action/type overlap")
    return dict(owner_start=owner_start, owner_end=owner_end, rows=rows, action_records=ordered,
                lpstart_encoding=lpstart, type_encoding=types, type_base_offset=type_base,
                call_site_encoding=encoding, table_start=table_start, table_end=table_end,
                raw_sha256=digest(raw), missing_ip_rust_action="terminate", type_targets_resolved=False)


def parse_eh_frame(raw, section_address):
    """Decode observed CIE/FDE header+augmentation mapping, never CFI opcodes.

    This narrow ARM64 subset uses 32-bit record lengths, CIE v1 zR/zPLR,
    PC-relative native-width R/L, and an indirect PC-relative signed32 P slot.
    Unknown encodings/augmentations refuse; personality slots are not read.
    """
    require(type(section_address) is int and 0 <= section_address < 1 << 64, "invalid eh_frame address")
    require(len(raw) <= (1 << 64) - section_address, "eh_frame VM span overflow")
    cursor, cies, fdes = 0, {}, {}
    while cursor < len(raw):
        begin = cursor
        length, = unpack(raw, cursor, "<I")
        if length == 0:
            require(not any(raw[cursor:]), "bytes after eh_frame terminator")
            break
        require(length != 0xFFFFFFFF, "DWARF64 record unsupported")
        require(begin % 4 == 0 and length >= 4 and length % 4 == 0, "invalid eh_frame record length")
        end = begin + 4 + length
        bounded_range(raw, begin, 4 + length)
        identifier, = unpack(raw, begin + 4, "<I")
        cursor = begin + 8
        def fixed(fmt):
            nonlocal cursor
            size = struct.calcsize(fmt)
            require(cursor + size <= end, "truncated eh_frame field")
            value = unpack(raw, cursor, fmt)[0]
            cursor += size
            return value
        if identifier == 0:
            version = fixed("<B")
            require(version == 1, "unsupported CIE version")
            zero = raw.find(b"\0", cursor, end)
            require(zero >= cursor, "unterminated CIE augmentation")
            augmentation = raw[cursor:zero].decode("ascii")
            require(augmentation in ("zR", "zPLR"), "unsupported CIE augmentation")
            cursor = zero + 1
            code_align, cursor = leb(raw, cursor, limit=end)
            data_align, cursor = leb(raw, cursor, signed=True, limit=end)
            return_register = fixed("<B")
            require((code_align, data_align, return_register) == (1, -8, 30), "unsupported ARM64 CIE parameters")
            aug_length, cursor = leb(raw, cursor, limit=end)
            aug_start, aug_end = cursor, cursor + aug_length
            require(aug_end <= end, "CIE augmentation exceeds record")
            personality_slot, personality_encoding, lsda_encoding = None, None, 255
            if augmentation == "zPLR":
                personality_encoding = fixed("<B")
                require(personality_encoding == 0x9B, "unsupported personality encoding")
                field_address = section_address + cursor
                relative = fixed("<i")
                personality_slot = field_address + relative
                require(0 <= personality_slot < 1 << 64, "personality slot overflow")
                lsda_encoding = fixed("<B")
                require(lsda_encoding == 0x10, "unsupported LSDA encoding")
            pointer_encoding = fixed("<B")
            require(pointer_encoding == 0x10, "unsupported FDE pointer encoding")
            require(cursor == aug_end, "CIE augmentation length mismatch")
            cies[begin] = dict(offset=begin, length=4 + length, version=version, augmentation=augmentation,
                               code_alignment=code_align, data_alignment=data_align, return_register=return_register,
                               pointer_encoding=pointer_encoding, lsda_encoding=lsda_encoding,
                               personality_encoding=personality_encoding, personality_slot=personality_slot,
                               augmentation_start=aug_start, augmentation_end=aug_end,
                               cfi_start=cursor, cfi_end=end, cfi_sha256=digest(raw[cursor:end]),
                               raw_sha256=digest(raw[begin:end]))
        else:
            # Backward displacement is based at the CIE-pointer FIELD, not the
            # FDE record header or the byte after the pointer.
            cie_offset = begin + 4 - identifier
            require(cie_offset in cies, "FDE does not refer to prior CIE boundary")
            cie = cies[cie_offset]
            pointer_address = section_address + cursor
            relative = fixed("<q")
            start = pointer_address + relative
            # Range is the low-format-nibble native unsigned width. Never add
            # the pointer field address to this scalar length.
            span = fixed("<Q")
            require(0 <= start < 1 << 64 and 0 < span <= (1 << 64) - start, "invalid FDE code range")
            aug_length, cursor = leb(raw, cursor, limit=end)
            aug_start, aug_end = cursor, cursor + aug_length
            require(aug_end <= end, "FDE augmentation exceeds record")
            lsda = None
            if cie["lsda_encoding"] != 255:
                pointer_address = section_address + cursor
                relative = fixed("<q")
                # libunwind peeks at the scalar first: raw zero means NO LSDA,
                # not the address of the encoded pointer field.
                if relative:
                    lsda = pointer_address + relative
                    require(0 <= lsda < 1 << 64, "FDE LSDA pointer overflow")
            require(cursor == aug_end, "FDE augmentation length mismatch")
            fdes[begin] = dict(offset=begin, length=4 + length, cie_offset=cie_offset,
                               start=start, end=start + span, lsda=lsda,
                               personality_slot=cie["personality_slot"],
                               augmentation_start=aug_start, augmentation_end=aug_end,
                               cfi_start=cursor, cfi_end=end, cfi_sha256=digest(raw[cursor:end]),
                               raw_sha256=digest(raw[begin:end]))
        cursor = end
    require(cies and fdes, "empty CIE/FDE inventory")
    ordered = sorted(fdes.values(), key=lambda row: row["start"])
    require(all(a["end"] <= b["start"] for a, b in zip(ordered, ordered[1:])), "overlapping FDE code regions")
    return dict(cies=cies, fdes=fdes, raw_sha256=digest(raw), cfi_instructions_interpreted=False)


def resolve_unwind(compact, eh_frame, image, functions):
    """Bind every fallback hint to its actual FDE mapping; refuse discordance.

    Raw FDE region/LSDA/personality slot are authoritative for the parsed fallback
    row. This validates mapping only, not actual runtime selection or CFI state.
    """
    fdes, used, mappings, descriptors = eh_frame["fdes"], set(), [], {}
    exception = image["sections"][("__TEXT", "__gcc_except_tab")]
    def readable_slot(address):
        return any(not section["zerofill"] and section["address"] <= address
                   and address + 8 <= section["address"] + section["size"]
                   for section in image["sections"].values())
    for row in compact["entries"]:
        if row["mode"] == "dwarf_fallback":
            hint = row["encoding"] & 0xFFFFFF
            require(hint in fdes and hint not in used, "missing or repeated compact FDE hint")
            used.add(hint)
            fde = fdes[hint]
            require(fde["start"] == row["start"] and fde["start"] in functions, "compact/FDE function start differs")
            require(fde["end"] <= row["end"] and fde["end"] <= functions[fde["start"]]["end"], "FDE range escapes compact/function extent")
            require(fde["lsda"] == row["lsda"], "compact/FDE LSDA differs")
            if row["personality_index"]:
                expected = compact["personalities"][row["personality_index"] - 1]
                require(fde["personality_slot"] == expected, "compact/CIE personality slot differs")
            # A zero compact personality never erases a nonzero CIE slot.
            record = dict(start=fde["start"], end=fde["end"], compact_end=row["end"],
                          source="fde_augmentation", fde_offset=hint, cie_offset=fde["cie_offset"],
                          lsda=fde["lsda"], personality_slot=fde["personality_slot"])
        else:
            record = dict(start=row["start"], end=row["end"], compact_end=row["end"],
                          source="compact", fde_offset=None, cie_offset=None, lsda=row["lsda"],
                          personality_slot=compact["personalities"][row["personality_index"] - 1] if row["personality_index"] else None)
        if record["personality_slot"] is not None:
            require(readable_slot(record["personality_slot"]), "personality slot outside file-backed image")
        if record["lsda"] is not None:
            require(record["personality_slot"] is not None, "LSDA without a selected personality slot")
            require(record["start"] in functions and record["end"] <= functions[record["start"]]["end"], "LSDA mapping crosses owner")
            require(exception["address"] <= record["lsda"] < exception["address"] + exception["size"], "mapped LSDA outside section")
            require(record["start"] not in descriptors, "duplicate resolved LSDA owner")
            descriptors[record["start"]] = record["lsda"]
        mappings.append(record)
    require(used == set(fdes), "raw FDE not covered by compact fallback hint")
    require(descriptors == compact["descriptors"], "resolved/compact descriptor membership differs")
    return dict(mappings=mappings, descriptors=descriptors, checked_fde_mapping=True,
                checked_fde_count=len(used), cie_count=len(eh_frame["cies"]),
                cfi_instructions_interpreted=False, loaded_personality_targets_authenticated=False)


def call_action(table, instruction_address, *, ip_before_instruction=False):
    """Source-style lookup for a BL return IP: PC+4 then subtract one byte.

    The alternative denotes GetIPInfo's before-instruction address, exactly PC.
    This lookup is descriptive only; graph coverage never depends on BL alone.
    """
    require(type(instruction_address) is int and type(ip_before_instruction) is bool, "invalid IP lookup")
    ip = instruction_address if ip_before_instruction else instruction_address + 3
    if table is None:
        return "none"
    for row in table["rows"]:
        if row["start"] <= ip < row["end"]:
            return row["rust_action"]
    return "terminate"


def direct_target(operand):
    # LLVM annotations are labels, not extra machine operands. A label can
    # itself contain commas or angle brackets (demangled Rust generics).
    if " <" in operand:
        operand, annotation = operand.split(" <", 1)
        require(annotation.endswith(">") and "\n" not in annotation, "malformed target annotation")
    value = operand.split(",")[-1].strip()
    require(re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None, "malformed direct target")
    return int(value, 16)


def coverage_graph(instructions, functions, stubs, lsdas, roots, seed_landing_pads=True):
    """Overapproximate direct control with table-wide landing-pad activation.

    Reaching any instruction of an owner seeds all listed landing pads, whether
    or not a BL in its protected interval was reached. This deliberately includes
    speculative cleanup, catch and filter entries. Ordinary continuations remain
    after every call, including panic/unwind/exit names. No stack state is reused.
    """
    require(type(seed_landing_pads) is bool and roots and all(root in functions for root in roots), "invalid graph roots")
    starts = sorted(functions)
    require(all(start % 4 == 0 and start < functions[start]["end"] for start in starts), "invalid function bounds")
    require(all(functions[a]["end"] <= b for a, b in zip(starts, starts[1:])), "overlapping functions")
    require(set(lsdas) <= set(functions), "LSDA owner absent from functions")
    def owner(pc):
        index = bisect_right(starts, pc) - 1
        return starts[index] if index >= 0 and pc < functions[starts[index]]["end"] else None
    for start, table in lsdas.items():
        require(table["owner_start"] == start and table["owner_end"] == functions[start]["end"], "LSDA/graph owner mismatch")
        for row in table["rows"]:
            landing = row["landing_pad"]
            require(landing is None or owner(landing) == start and landing in instructions, "unmapped landing pad")
    pending = deque(roots)
    visited, active, landing_seeds, direct_calls = set(), set(), set(), set()
    frontiers, edge_set = {}, set()
    def frontier(pc, kind, detail):
        own = owner(pc)
        frontiers[(pc, kind, str(detail))] = dict(address=pc, kind=kind, detail=str(detail),
                                                owner=own, owner_name=functions[own]["name"] if own is not None else None)
    def enqueue(source, target, kind, allow_cross=False):
        own, other = owner(source), owner(target)
        if not allow_cross and own is not None and not own <= target < functions[own]["end"]:
            frontier(source, "function_fallthrough", hex(target))
        elif target in stubs:
            frontier(source, "native_edge", stubs[target])
        elif other is None:
            frontier(source, "unresolved_target", hex(target))
        elif other != own and (not allow_cross or target != other):
            frontier(source, "cross_owner_nonentry", hex(target))
        elif target not in instructions:
            frontier(source, "missing_instruction", hex(target))
        else:
            edge_set.add((source, target, kind))
            pending.append(target)
    while pending:
        pc = pending.popleft()
        if pc in visited:
            continue
        own = owner(pc)
        require(own is not None and pc in instructions, "unmapped graph seed")
        visited.add(pc)
        if own not in active:
            active.add(own)
            if seed_landing_pads and own in lsdas:
                for row in lsdas[own]["rows"]:
                    if row["landing_pad"] is not None:
                        landing = row["landing_pad"]
                        landing_seeds.add((own, landing))
                        edge_set.add((own, landing, "conservative_table_seed"))
                        pending.append(landing)
        operation, operands = instructions[pc]
        if operation in ("ret", "retab", "retaa"):
            if operation != "ret" or operands not in ("", "x30"):
                frontier(pc, "unsupported_return", operation + " " + operands)
            continue
        if operation in ("brk", "udf", "hlt", "svc", "hvc", "smc"):
            frontier(pc, "trap_or_system_control", operation + " " + operands)
            # Trap/system resumption is opaque; retain its ordinary next byte
            # path conservatively rather than treating it as proven noreturn.
            enqueue(pc, pc + 4, "possible_resume")
            continue
        if operation in ("br", "braa", "brab"):
            frontier(pc, "indirect_branch", operands)
            continue
        if operation in ("blr", "blraa", "blrab"):
            frontier(pc, "indirect_call", operands)
            enqueue(pc, pc + 4, "call_continuation")
            continue
        if operation in ("b", "bl") or operation in CONDITIONAL:
            target = direct_target(operands)
            if operation == "bl":
                direct_calls.add((pc, target))
                enqueue(pc, target, "call", allow_cross=True)
                enqueue(pc, pc + 4, "call_continuation")
            elif operation == "b":
                enqueue(pc, target, "branch_or_tail", allow_cross=True)
            else:
                enqueue(pc, target, "conditional_branch", allow_cross=True)
                enqueue(pc, pc + 4, "conditional_fallthrough")
            continue
        normalized = operation
        vector = re.fullmatch(r"([a-z][a-z0-9]*)\.(b|h|s|d|8b|16b|4h|8h|2s|4s|1d|2d)", operation)
        if vector:
            normalized = vector[1]
        if normalized not in STRAIGHT:
            frontier(pc, "unsupported_instruction", operation + " " + operands)
        enqueue(pc, pc + 4, "ordinary_fallthrough")
    categories = Counter(item["kind"] for item in frontiers.values())
    native = Counter(item["detail"] for item in frontiers.values() if item["kind"] == "native_edge")
    return dict(reachable_instructions=sorted(visited), reachable_functions=sorted(active),
                landing_pad_seeds=[list(x) for x in sorted(landing_seeds)],
                direct_calls=[list(x) for x in sorted(direct_calls)],
                edges=[list(x) for x in sorted(edge_set)],
                frontiers=sorted(frontiers.values(), key=lambda x: (x["address"], x["kind"], x["detail"])),
                frontier_counts=dict(sorted(categories.items())), native_symbols=dict(sorted(native.items())),
                complete_exception_semantics=False, landing_pad_register_state_known=False)


def parse_text(disassembly, starts_text, stubs_text, image):
    """Cross-check captured text ownership against raw LC_FUNCTION_STARTS."""
    marker = "Disassembly of section __TEXT,__text:"
    require(marker in disassembly, "missing text disassembly")
    body = disassembly.split(marker, 1)[1].split("\nDisassembly of section ", 1)[0]
    instructions, labels = {}, {}
    for line in body.splitlines():
        label = re.fullmatch(r"([0-9a-fA-F]+) <(.+)>:", line.strip())
        if label:
            address = int(label[1], 16)
            require(address not in labels, "duplicate disassembly label")
            labels[address] = label[2]
        match = re.fullmatch(r"\s*([0-9a-fA-F]+):\s+(\S+)\s*(.*)", line)
        if match:
            address = int(match[1], 16)
            require(address not in instructions, "duplicate disassembly instruction")
            instructions[address] = (match[2], match[3].split(";", 1)[0].strip())
    text = image["sections"][("__TEXT", "__text")]
    require(set(instructions) == set(range(text["address"], text["address"] + text["size"], 4)), "incomplete text disassembly")
    names = {}
    for line in starts_text.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{16})\s+(.+)", line)
        if match:
            address = int(match[1], 16)
            require(address not in names, "duplicate text function")
            names[address] = match[2]
    require(set(names) == set(image["function_starts"]), "raw/text function-start mismatch")
    starts = image["function_starts"]
    functions = {start: dict(name=labels.get(start, names[start]), mangled_name=names[start], end=starts[i + 1] if i + 1 < len(starts) else text["address"] + text["size"])
                 for i, start in enumerate(starts)}
    active, stubs = False, {}
    for line in stubs_text.splitlines():
        if line.startswith("Indirect symbols for "):
            active = "(__TEXT,__stubs)" in line
        match = re.fullmatch(r"(0x[0-9a-fA-F]+)\s+\d+\s+(\S+)", line)
        if active and match:
            address = int(match[1], 16)
            require(address not in stubs, "duplicate native stub")
            stubs[address] = match[2]
    require(stubs, "missing native stub inventory")
    return instructions, functions, stubs


def analyze_image(data, disassembly, starts_text, stubs_text, unwind_text):
    image = parse_macho(data)
    compact = parse_unwind(data, image)
    instructions, functions, stubs = parse_text(disassembly, starts_text, stubs_text, image)
    eh_section = image["sections"].get(("__TEXT", "__eh_frame"))
    require(eh_section is not None, "missing eh_frame")
    eh_frame = parse_eh_frame(section_bytes(data, image, "__eh_frame"), eh_section["address"])
    resolved = resolve_unwind(compact, eh_frame, image, functions)
    captured_rows = re.findall(r"function offset=(0x[0-9a-f]+), LSDA offset=(0x[0-9a-f]+)", unwind_text)
    captured = {image["base"] + int(a, 16): image["base"] + int(b, 16) for a, b in captured_rows}
    require(len(captured_rows) == len(captured), "duplicate captured LSDA owner")
    require(captured == compact["descriptors"], "raw/captured LSDA descriptor mismatch")
    require(set(compact["descriptors"]) <= set(functions), "LSDA owner is not raw function start")
    values = list(resolved["descriptors"].values())
    require(len(values) == len(set(values)), "shared LSDA blob unsupported")
    exception_section = image["sections"][("__TEXT", "__gcc_except_tab")]
    low, high = exception_section["address"], exception_section["address"] + exception_section["size"]
    require(all(low <= value < high for value in values), "LSDA outside exception section")
    boundaries = sorted(values) + [high]
    ends = dict(zip(boundaries, boundaries[1:]))
    tables = {}
    regions = {item["start"]: item for item in resolved["mappings"]}
    for owner, address in resolved["descriptors"].items():
        offset = exception_section["offset"] + address - low
        raw = bounded_range(data, offset, ends[address] - address)
        table = parse_lsda(raw, owner, regions[owner]["end"])
        # The actual FDE protected region can omit function-end padding. Its
        # offsets were validated above before associating it with the enclosing
        # graph owner, whose LC_FUNCTION_STARTS extent includes that padding.
        table.update(address=address, bytes=len(raw), region_end=regions[owner]["end"],
                     owner_end=functions[owner]["end"], mapping_source=regions[owner]["source"])
        tables[owner] = table
    roots = [start for start, fn in functions.items() if "parliament_memory_entry::workspace::worker::" in fn["name"]]
    require(len(roots) == 1, "missing or ambiguous worker root")
    ordinary = coverage_graph(instructions, functions, stubs, tables, roots, False)
    augmented = coverage_graph(instructions, functions, stubs, tables, roots, True)
    require(set(ordinary["reachable_instructions"]) <= set(augmented["reachable_instructions"]), "coverage lost ordinary instructions")
    old_frontiers = {(f["address"], f["kind"], f["detail"]) for f in ordinary["frontiers"]}
    extra = [f for f in augmented["frontiers"] if (f["address"], f["kind"], f["detail"]) not in old_frontiers]
    call_rows = []
    starts = sorted(functions)
    for pc, target in augmented["direct_calls"]:
        own = starts[bisect_right(starts, pc) - 1]
        if own in tables:
            call_rows.append(dict(address=pc, owner=own, target=target, rust_action_at_return_pc_minus_one=call_action(tables[own], pc)))
    return dict(binary_sha256=digest(data), function_count=len(functions), instruction_count=len(instructions),
                compact=compact, eh_frame=eh_frame, resolved_unwind=resolved,
                lsda_tables=tables, function_names={start: fn["name"] for start, fn in functions.items()},
                ordinary=ordinary, exception_augmented=augmented, newly_exposed_frontiers=extra,
                new_instruction_count=len(set(augmented["reachable_instructions"]) - set(ordinary["reachable_instructions"])),
                new_function_count=len(set(augmented["reachable_functions"]) - set(ordinary["reachable_functions"])),
                call_lookup_descriptions=call_rows, **FALSE_FLAGS)


def load_inputs(stage):
    inventory_bytes = (stage / "input-inventory.json").read_bytes()
    require(digest(inventory_bytes) == INVENTORY_SHA256, "input inventory changed")
    inventory = json.loads(inventory_bytes)
    extra_bytes = (stage / "input-inventory-fde.json").read_bytes()
    require(digest(extra_bytes) == FDE_INVENTORY_SHA256, "FDE reference inventory changed")
    extra = json.loads(extra_bytes)
    require(not set(inventory["inputs"]) & set(extra["inputs"]), "duplicate supplemental input")
    inventory["inputs"].update(extra["inputs"])
    contents, observed = {}, {}
    for key, item in inventory["inputs"].items():
        source = Path(item["source_path"]).read_bytes()
        snapshot = (stage / item["snapshot"]).read_bytes()
        require(source == snapshot and digest(snapshot) == item["sha256"] and len(source) == item["bytes"], "selected input drift: " + key)
        contents[key], observed[key] = snapshot, digest(snapshot)
    return contents, observed


def report(stage):
    """Use one immutable selected inventory, checking live and archived bytes twice."""
    stage = Path(stage).resolve()
    contents, before = load_inputs(stage)
    build = json.loads(contents["build_receipt"])
    require(build["source_stable"] is True and build["profile_qualified"] is False, "unexpected build scope")
    outputs = {}
    for mode in ("portable", "accel"):
        require(before[mode + "_binary"] == build["binaries"][mode]["sha256"], "binary/build mismatch")
        outputs[mode] = analyze_image(contents[mode + "_binary"], *(contents[mode + "_" + part].decode() for part in ("disassembly", "starts", "stubs", "unwind")))
    _, after = load_inputs(stage)
    require(before == after, "source changed during analysis")
    return dict(schema="parliament-exception-coverage-v1", verdict="PASS_UNDER_STATED_PREMISES",
                checked_metadata_and_coverage=True, selected_input_count=len(before),
                input_sha256_before=before, input_sha256_after=after, modes=outputs,
                scope=["Selected retained-image metadata and direct-control coverage only; not a full historical build closure or current-checkout claim.",
                       "All table landing pads of every reached owner are seeded, including unreachable protected intervals and catch/filter pads.",
                       "Ordinary and unknown-call continuations remain; no native/panic name proves noreturn or no unwind.",
                       "Rust first-action classification and return-PC-minus-one lookup are conditional source interpretation, not loaded personality authentication.",
                       "Compact ranges may cover several functions; DWARF fallback FDE/CIE region, LSDA and personality-slot mappings are checked, but CFI and loaded personality targets remain unresolved.",
                       "Landing-pad SP/FP/register state, native unwind costs, asynchronous/foreign exceptional reentry and indirect targets remain unknown.",
                       "No complete allocator/native/stack/workspace bound, target measurement, independent unsafe review or production qualification follows."],
                **FALSE_FLAGS)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("output already exists")
    try:
        value = report(args.stage)
        code = 2 if args.require_qualified else 0
    except (OSError, ValueError, KeyError, TypeError, struct.error, UnicodeError) as error:
        value = dict(schema="parliament-exception-coverage-v1", verdict="UNKNOWN", error=str(error),
                     checked_metadata_and_coverage=False, **FALSE_FLAGS)
        code = 1
    with args.out.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
