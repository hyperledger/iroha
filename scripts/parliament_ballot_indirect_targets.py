#!/usr/bin/env python3
"""Extract PRG provider targets from the two frozen ARM64 Parliament workers.

Requires Python 3.11+, retained /tmp/parliament-resource-contract executables,
prior compiled-stack artifacts, unchanged source premises, and Xcode objdump.
No environment variables, compilation, executable invocation, or library edits.
Only the explicitly selected output directory is written.

Raw Mach-O words, dyld pointer rebases, constructor constant stores, and indirect
slot-load instructions are checked. Completeness of the target sets still rests
on the pinned Rust source's private Prg/Encryptor ownership and ordinary memory
safety; this is NOT a binary points-to proof or a stable Rust-vtable ABI claim.
A separate conditional graph rerun uses all three providers per mode. Native,
remaining indirect, exception and recursive gaps remain open.
"""

import argparse
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("docs/validation/parliament_ballot_compiled_stack")
BUILD = Path("docs/validation/parliament_ballot_resource_contract")
PREMISES = ["crates/iroha_zkp_vole/src/prg.rs", "crates/iroha_zkp_vole/src/bavc.rs",
            "crates/iroha_zkp_vole/src/vole/convert.rs"]
SLOT_ASSUMPTION = "Target-set completeness assumes pinned private Prg/Encryptor construction and ordinary Rust memory safety; not whole-binary points-to analysis."


def sha(path):
    """Hash exact source, metadata, or executable bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sections(data):
    """Read checked thin ARM64 Mach-O 64-bit segment/section descriptors.

    Layout follows the pinned Apple SDK mach-o/loader.h segment_command_64 and
    section_64. Unsupported chained fixups are rejected, never read as pointers.
    """
    if len(data) < 32:
        raise ValueError("truncated Mach-O header")
    magic, cpu, subtype, filetype, ncmds, size, _, _ = struct.unpack_from("<8I", data)
    if (magic, cpu, subtype, filetype) != (0xFEEDFACF, 0x100000C, 0, 2):
        raise ValueError("expected thin ARM64 executable without pointer authentication")
    end = 32 + size
    if end > len(data) or ncmds > size // 8:
        raise ValueError("truncated load commands")
    position, output = 32, []
    for _ in range(ncmds):
        if position + 8 > end:
            raise ValueError("missing load command")
        command, length = struct.unpack_from("<II", data, position)
        if length < 8 or length % 8 or position + length > end:
            raise ValueError("invalid load command length")
        if command == 0x80000034:
            raise ValueError("chained fixups are unsupported")
        if command == 0x19:
            if length < 72:
                raise ValueError("truncated segment")
            (_, _, name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot,
             count, flags) = struct.unpack_from("<II16sQQQQiiII", data, position)
            if length != 72 + count * 80 or fileoff + filesize > len(data) or flags & 1:
                raise ValueError("unsupported or truncated segment mapping")
            segment_name = name.rstrip(b"\0").decode("ascii")
            for index in range(count):
                values = struct.unpack_from("<16s16sQQ8I", data, position + 72 + index * 80)
                section_name, owner = (value.rstrip(b"\0").decode("ascii") for value in values[:2])
                address, size, offset = values[2:5]
                if owner != segment_name or address < vmaddr or address + size > vmaddr + vmsize:
                    raise ValueError("section outside segment")
                output.append({"segment": owner, "section": section_name, "address": address,
                               "size": size, "offset": offset, "section_flags": values[8],
                               "segment_address": vmaddr, "segment_fileoff": fileoff,
                               "segment_filesize": filesize, "segment_flags": flags,
                               "segment_initprot": initprot, "segment_maxprot": maxprot})
        position += length
    if position != end:
        raise ValueError("unconsumed load command bytes")
    return output


def read_constant(data, descriptors, address, length):
    """Read one file-backed, post-fixup-readonly __DATA_CONST,__const region."""
    matches = [item for item in descriptors if item["address"] <= address and
               address + length <= item["address"] + item["size"]]
    if len(matches) != 1:
        raise ValueError("constant does not have one containing section")
    section = matches[0]
    if (section["segment"], section["section"], section["section_flags"] & 0xFF) != ("__DATA_CONST", "__const", 0):
        raise ValueError("expected regular __DATA_CONST,__const")
    if not section["segment_flags"] & 0x10:
        raise ValueError("segment not marked read-only after fixups")
    offset = section["offset"] + address - section["address"]
    mapping_offset = section["segment_fileoff"] + address - section["segment_address"]
    if offset != mapping_offset or offset + length > len(data) or offset + length > section["segment_fileoff"] + section["segment_filesize"]:
        raise ValueError("constant outside file-backed segment or inconsistent offset")
    return data[offset:offset + length], offset


def parse_rebases(text):
    """Keep explicit pointer rebases in the relevant constant section only."""
    return {int(match[1], 16) for line in text.splitlines()
            if (match := re.fullmatch(r"__DATA_CONST\s+__const\s+(0x[0-9A-Fa-f]+)\s+pointer", line.strip()))}


def instruction_evidence(instructions, addresses):
    """Serialize exact decoded instructions in a small reviewable extract."""
    return [{"address": hex(address), "instruction": " ".join(instructions[address]).rstrip()}
            for address in addresses]


def pointer_store(instructions, after_add, start, end):
    """Check the small constant-preserving path to the constructor fat-pointer store.

    Only the observed mov-w9/immediate, direct b, and shared stp sequence is
    supported. Any changed opcode, loop, target, or clobber fails closed.
    """
    address, visited = after_add, []
    while start <= address < end and address not in visited:
        visited.append(address)
        op, operands = instructions[address]
        if (op, operands) == ("stp", "x20, x8, [x19, #0x8]"):
            return instruction_evidence(instructions, visited)
        if op == "mov" and re.fullmatch(r"w9, #(?:0x[0-9a-f]+|\d+)", operands):
            address += 4
        elif op == "b" and (match := re.fullmatch(r"(0x[0-9a-f]+)(?: <.*>)?", operands)):
            address = int(match[1], 16)
        else:
            raise ValueError("unproved constructor vtable-store path")
    raise ValueError("constructor store path escaped or looped")


def catalog_tables(data, instructions, names, functions, rebases):
    """Extract all three emitted constructor tables and their exact slot words."""
    constructors = [fn for fn in functions if fn["name"].startswith("iroha_zkp_vole::prg::Prg::new")]
    if len(constructors) != 1:
        raise ValueError("expected one emitted PRG constructor")
    constructor = constructors[0]
    start, end = int(constructor["address"], 16), int(constructor["end"], 16)
    descriptors, result = sections(data), []
    for address in range(start, end - 4, 4):
        op, operands = instructions[address]
        page = re.fullmatch(r"x8, (0x[0-9a-f]+)(?: <.*>)?", operands)
        next_op, next_operands = instructions[address + 4]
        offset = re.fullmatch(r"x8, x8, #(0x[0-9a-f]+|\d+)", next_operands)
        if op != "adrp" or not page or next_op != "add" or not offset:
            continue
        page_address = int(page[1], 16)
        if page_address % 4096:
            raise ValueError("unaligned ADRP page")
        table = page_address + int(offset[1], 0)
        raw, file_offset = read_constant(data, descriptors, table, 32)
        drop, size, alignment, encrypt = struct.unpack("<4Q", raw)
        if table not in rebases or table + 24 not in rebases or {table + 8, table + 16} & rebases:
            raise ValueError("table pointer rebases or scalar slots differ")
        if drop not in names or encrypt not in names:
            raise ValueError("table target is not an exact decoded function symbol")
        encrypt_name, drop_name = names[encrypt], names[drop]
        level = re.search(r"Aes(128|192|256)", encrypt_name)
        if not level or "Encryptor" not in encrypt_name or "::encrypt::" not in encrypt_name:
            raise ValueError("unexpected provider encrypt target")
        level = int(level[1])
        if "drop_in_place" not in drop_name or f"Aes{level}" not in drop_name:
            raise ValueError("mismatched provider destructor")
        if size != {128: 704, 192: 832, 256: 960}[level] or alignment not in {8, 16}:
            raise ValueError("unexpected emitted provider layout")
        result.append({"level_bits": level, "table_address": hex(table), "file_offset": file_offset,
                       "raw_32_bytes_hex": raw.hex(), "size_word": size, "alignment_word": alignment,
                       "drop_address": hex(drop), "drop_symbol": drop_name,
                       "encrypt_address": hex(encrypt), "encrypt_symbol": encrypt_name,
                       "rebased_pointer_slots": [hex(table), hex(table + 24)],
                       "constructor_address": hex(start), "constructor_symbol": constructor["name"],
                       "constant_instructions": instruction_evidence(instructions, [address, address + 4]),
                       "store_path": pointer_store(instructions, address + 8, start, end)})
    if sorted(item["level_bits"] for item in result) != [128, 192, 256]:
        raise ValueError("expected exactly the three AES provider tables")
    emitted = {address for address, name in names.items() if "Encryptor" in name and "::encrypt::" in name}
    if emitted != {int(item["encrypt_address"], 16) for item in result}:
        raise ValueError("additional or missing emitted Encryptor method")
    return sorted(result, key=lambda item: item["level_bits"])


def catalog_site(site, instructions, function, tables):
    """Validate observed indirect load/spill shapes and assign a conditional set."""
    address = int(site["address"], 16)
    if instructions[address] != ("blr", "x8") or site["kind"] != "indirect_call":
        raise ValueError("changed indirect call instruction")
    start, end = int(function["address"], 16), int(function["end"], 16)
    if not start <= address < end:
        raise ValueError("site outside named function")
    if "Prg::fill::" in function["name"]:
        role, slot = "encrypt", 24
        if address - 8 < start or instructions[address - 4] != ("mov", "x2, x23"):
            raise ValueError("unproved encrypt pre-call argument setup")
        loads = [a for a in range(start, end - 8, 4)
                 if instructions[a] == ("ldp", "x9, x8, [x0]") and
                 instructions[a + 4] == ("ldr", "x8, [x8, #0x18]") and
                 instructions[a + 8] == ("stp", "x8, x9, [sp, #0x10]")]
        if len(loads) != 1 or instructions[address - 8] != ("ldp", "x8, x0, [sp, #0x10]"):
            raise ValueError("unproved encrypt slot/spill/reload shape")
        evidence = instruction_evidence(instructions, [loads[0], loads[0] + 4, loads[0] + 8,
                                                         address - 8, address - 4, address])
    else:
        role, slot = "drop", 0
        if address - 16 < start or instructions[address - 4] not in {
            ("mov", "x0, x19"), ("mov", "x0, x20"), ("ldr", "x0, [sp, #0x90]")
        }:
            raise ValueError("unproved destructor pre-call argument setup")
        op, operands = instructions[address - 12]
        load = re.fullmatch(r"x8, \[(x8|x20|x21)\]", operands)
        branch_op, branch_operands = instructions[address - 8]
        branch = re.fullmatch(r"x8, (0x[0-9a-f]+)(?: <.*>)?", branch_operands)
        if op != "ldr" or not load or branch_op != "cbz" or not branch or int(branch[1], 16) != address + 4:
            raise ValueError("unproved destructor slot/null-check shape")
        following = [instructions[a] for a in range(address + 4, min(address + 28, end), 4)]
        if ("ldr", f"x1, [{load[1]}, #0x8]") not in following or ("ldr", f"x2, [{load[1]}, #0x10]") not in following:
            raise ValueError("unproved destructor size/alignment loads")
        evidence = instruction_evidence(instructions, range(address - 16, min(address + 28, end), 4))
    return {**site, "slot_offset_bytes": slot, "role": role, "instruction_evidence": evidence,
            "conditional_targets": [{"address": table[role + "_address"], "symbol": table[role + "_symbol"],
                                     "table_address": table["table_address"], "level_bits": table["level_bits"]}
                                    for table in tables], "target_set_premise": SLOT_ASSUMPTION,
            "binary_points_to_proof": False}


def rerun_regions(analyzer, report, sites):
    """Recalculate separate graph regions with only the seven conditional sets."""
    functions = {int(fn["address"], 16): copy.deepcopy(fn) for fn in report["functions"]}
    for site in sites:
        candidates = [fn for fn in functions.values() if fn["name"] == site["function"]]
        if len(candidates) != 1:
            raise ValueError("ambiguous site owner")
        function = candidates[0]
        old = [gap for gap in function["gaps"] if gap["address"] == site["address"] and gap["kind"] == "indirect_call"]
        if len(old) != 1 or old[0]["caller_depth_bytes"] != site["caller_depth_bytes"]:
            raise ValueError("original indirect gap does not match")
        function["gaps"].remove(old[0])
        for target in site["conditional_targets"]:
            if int(target["address"], 16) not in functions:
                raise ValueError("conditional target absent from analyzed functions")
            function["calls"].append({"address": site["address"], "target": target["address"],
                                      "kind": "source_conditional_indirect", "caller_depth_bytes": site["caller_depth_bytes"]})
    return [analyzer.call_region(functions, int(root["address"], 16)) for root in report["roots"]]


def load_analyzer(root):
    """Load only the exact archived analyzer bytes pinned by the old receipt."""
    receipt = json.loads((root / BASE / "receipt.json").read_text())
    template = root / BASE / "parliament_ballot_stack_audit.py.template"
    expected = receipt["source_after"]["scripts/parliament_ballot_stack_audit.py"]
    data = template.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("frozen analyzer template changed")
    # Execute the verified bytes directly; never substitute a timestamp-matched
    # Python bytecode cache for the source whose hash the receipt names.
    module = types.ModuleType("frozen_parliament_stack")
    module.__file__ = str(template)
    exec(compile(data, str(template), "exec"), module.__dict__)
    return module


def run(root, output):
    """Guard sources and binaries, extract catalog, and retain separate reruns."""
    # Never leave a stale successful catalog beside a failed newer extraction.
    # A partial failed attempt remains separate; callers choose another path.
    output.mkdir(parents=True, exist_ok=False)
    stack_receipt = json.loads((root / BASE / "receipt.json").read_text())
    build_receipt = json.loads((root / BUILD / "build-receipt.json").read_text())
    for key in ["original_build_receipt", "original_build_source_manifest"]:
        pinned = stack_receipt[key]
        if sha(root / pinned["path"]) != pinned["sha256"]:
            raise ValueError("original build/source identity differs from frozen stack receipt")
    frozen = {line.split("  ", 1)[1]: line.split("  ", 1)[0]
              for line in (root / BUILD / "build-source.sha256").read_text().splitlines()}
    inputs = {str(root / source): frozen[source] for source in PREMISES}
    for directory, filename in [(BASE, "receipt.json"), (BUILD, "build-receipt.json"), (BUILD, "build-source.sha256")]:
        inputs[str(root / directory / filename)] = sha(root / directory / filename)
    inputs[str(Path(__file__).resolve())] = sha(__file__)
    inputs[str(root / BASE / "parliament_ballot_stack_audit.py.template")] = stack_receipt["source_after"]["scripts/parliament_ballot_stack_audit.py"]
    for path, expected in inputs.items():
        if sha(path) != expected:
            raise ValueError(f"source premise or frozen input mismatch: {path}")
    tool = subprocess.check_output(["xcrun", "--find", "llvm-objdump"], text=True).strip()
    inputs[tool] = sha(tool)
    sdk = Path(subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip())
    header = sdk / "usr/include/mach-o/loader.h"
    inputs[str(header)] = sha(header)
    inputs[sys.executable] = sha(sys.executable)
    analyzer, modes, commands = load_analyzer(root), {}, []
    for mode in ["portable", "accel"]:
        report_path = root / BASE / f"{mode}.json"
        report = json.loads(report_path.read_text())
        inputs[str(report_path)] = stack_receipt["reports"][mode]["sha256"]
        binary = Path(build_receipt["binaries"][mode]["path"])
        inputs[str(binary)] = build_receipt["binaries"][mode]["sha256"]
        if sha(binary) != inputs[str(binary)] or sha(report_path) != inputs[str(report_path)]:
            raise ValueError("frozen binary or graph report mismatch")
        disassembly_path = root / BASE / mode / "disassembly.txt"
        old_command = next(c for c in report["identity"]["commands"] if c["output"].endswith("/disassembly.txt"))
        inputs[str(disassembly_path)] = old_command["sha256"]
        if sha(disassembly_path) != old_command["sha256"]:
            raise ValueError("frozen disassembly mismatch")
        instructions, names = analyzer.parse_disassembly(disassembly_path.read_text())
        command = [tool, "--macho", "--rebase", str(binary)]
        process = subprocess.run(command, check=True, capture_output=True, text=True)
        rebase_path = output / f"{mode}-rebases.txt"
        rebase_path.write_text(process.stdout)
        commands.append({"command": command, "stdout": str(rebase_path), "stdout_sha256": sha(rebase_path), "stderr": process.stderr})
        binary_bytes = binary.read_bytes()
        tables = catalog_tables(binary_bytes, instructions, names, report["functions"], parse_rebases(process.stdout))
        sites = []
        for site in stack_receipt["reports"][mode]["backend_indirect_sites"]:
            owners = [fn for fn in report["functions"] if fn["name"] == site["function"]]
            if len(owners) != 1:
                raise ValueError("nonunique site owner")
            sites.append(catalog_site(site, instructions, owners[0], tables))
        if len(sites) != 7 or sorted(s["role"] for s in sites) != ["drop"] * 6 + ["encrypt"]:
            raise ValueError("unexpected backend indirect site coverage")
        regions = rerun_regions(analyzer, report, sites)
        load_commands_end = 32 + struct.unpack_from("<I", binary_bytes, 20)[0]
        modes[mode] = {"binary_sha256": inputs[str(binary)], "constructor_tables": tables, "sites": sites,
                       "mach_o_header_and_load_commands_hex": binary_bytes[:load_commands_end].hex(),
                       "constant_section": [section for section in sections(binary_bytes)
                                            if (section["segment"], section["section"]) == ("__DATA_CONST", "__const")],
                       "conditional_stack_regions": regions, "graph_edges_added": 21,
                       "complete_stack_bound_bytes": None, "source_conditional": True}
    for path, expected in inputs.items():
        if sha(path) != expected:
            raise ValueError(f"input changed during extraction: {path}")
    result = {"format": "parliament-indirect-target-catalog-v1", "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "binary_pointer_address_convention": "preferred unslid Mach-O VM addresses; dyld applies the same image slide to pointer rebases",
              "inputs": inputs, "inputs_unchanged": True, "python": sys.version,
              "commands": commands, "objdump_version": subprocess.check_output([tool, "--version"], text=True),
              "modes": modes, "target_set_premise": SLOT_ASSUMPTION, "no_rebuild_or_execution": True,
              "production_profile_qualified": False, "complete_workspace_certificate": False,
              "full_stack_sufficiency_established": False}
    path = output / "catalog.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    """Expose an explicit-output, read-only-binary CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new diagnostic artifact directory")
    args = parser.parse_args()
    result = run(ROOT, args.output)
    print(json.dumps({mode: {"tables": len(data["constructor_tables"]), "sites": len(data["sites"]),
                            "worker_region": next(r["resolved_region_stack_bytes"] for r in data["conditional_stack_regions"] if "workspace::worker" in r["root"])}
                      for mode, data in result["modes"].items()}, indent=2))


if __name__ == "__main__":
    main()
