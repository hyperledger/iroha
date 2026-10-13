#!/usr/bin/env python3
"""Check conditional allocator activation in the exact retained ARM64 workers.

Python 3.11+, repository compiled-stack/frontier artifacts and their retained
executables are required. No environment variables, builds, execution, network,
or installed runtime/source correspondence is used. Only a NEW output directory
is written. Old evidence is never changed. Unknown code patterns fail closed.

The result is deliberately split: finite CFG/address checks can PASS, whereas
unconditional activation remains UNKNOWN. Private-state noninterference, memory
safety, the ordinary ARM64 call ABI and the already declared provider premises
are required to propagate the checked activation across opaque calls. Failure
handlers, callbacks, traps and unwinding are not proved harmless or absent.
"""
from __future__ import annotations

import argparse
from collections import deque
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
STACK = Path("docs/validation/parliament_ballot_compiled_stack")
FRONTIERS = Path("docs/validation/parliament_ballot_stack_frontiers")
TARGETS = Path("docs/validation/parliament_ballot_indirect_targets")
BUILD = Path("docs/validation/parliament_ballot_resource_contract")
WORKSPACE = Path("crates/iroha_parliament_ballot_proof/examples/resource_contract/workspace.rs")
FLAG_NAME = re.compile(r"__ZN17resource_contract9workspace6ACTIVE17h[0-9a-f]{16}E(?:\.0)?")
CONDITIONAL = {"cbz", "cbnz", "tbz", "tbnz"} | {"b." + x for x in "eq ne cs hs cc lo mi pl vs vc hi ls ge lt gt le al nv".split()}
BOUNDARY_OPS = {"ret", "br", "brk", "udf", "hlt"}


def sha(path: Path) -> str:
    """Identify bytes, not filesystem timestamps."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def active_symbol(data: bytes) -> dict:
    """Read one local, section-defined ACTIVE symbol from a thin ARM64 Mach-O."""
    if len(data) < 32:
        raise ValueError("truncated Mach-O header")
    magic, cpu, _, _, count, commands_size, _, _ = struct.unpack_from("<8I", data)
    if magic != 0xFEEDFACF or cpu != 0x0100000C or commands_size > len(data) - 32:
        raise ValueError("expected thin little-endian ARM64 Mach-O")
    offset, symtab = 32, None
    for _ in range(count):
        if offset + 8 > 32 + commands_size:
            raise ValueError("truncated load command")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > 32 + commands_size:
            raise ValueError("invalid load-command range")
        if command == 2:
            if size != 24 or symtab is not None:
                raise ValueError("ambiguous symbol table")
            symtab = struct.unpack_from("<4I", data, offset + 8)
        offset += size
    if offset != 32 + commands_size or symtab is None:
        raise ValueError("missing symbol table or command-size mismatch")
    symbols, count, strings, strings_size = symtab
    if symbols + count * 16 > len(data) or strings + strings_size > len(data):
        raise ValueError("symbol table outside image")
    result = []
    for index in range(count):
        string_index, kind, section, _, address = struct.unpack_from("<IBBHQ", data, symbols + index * 16)
        if string_index >= strings_size:
            raise ValueError("symbol string outside table")
        end = data.find(b"\0", strings + string_index, strings + strings_size)
        if end < 0:
            raise ValueError("unterminated symbol")
        name = data[strings + string_index:end].decode("utf-8")
        if FLAG_NAME.fullmatch(name):
            # N_PEXT may remain on a private symbol; N_EXT/STAB/undefined may not.
            if kind not in {0x0E, 0x1E} or section == 0 or address == 0:
                raise ValueError("ACTIVE is not a local section-defined symbol")
            result.append({"symbol": name, "address": hex(address), "n_type": kind, "section": section})
    if len(result) != 1:
        raise ValueError("missing or ambiguous private ACTIVE")
    return result[0]


def target(operands: str) -> int:
    """Parse only a literal LLVM branch target."""
    match = re.search(r"(?:^|,\s*)(0x[0-9a-f]+)(?:\s|$)", operands)
    if not match:
        raise ValueError("nonliteral control target")
    return int(match[1], 16)


def cfg(start: int, end: int, instructions: dict, straight: set) -> tuple[dict, list]:
    """Include both branch outcomes and ordinary call continuation; retain exits.

    An unknown opcode, missing instruction or an indirect jump fails the local
    proof. Native/direct calls are not silently deemed side-effect free: their
    noninterference remains an explicit external premise of the final result.
    """
    graph, exits, queue = {}, [], deque([start])
    while queue:
        address = queue.popleft()
        if address in graph:
            continue
        if address not in instructions or not start <= address < end:
            raise ValueError("missing or out-of-function CFG instruction")
        op, operands = instructions[address]
        successors = []
        if op == "br":
            raise ValueError("unresolved indirect jump in local CFG")
        if op in BOUNDARY_OPS:
            exits.append({"address": hex(address), "kind": op, "detail": operands})
        elif op == "b" or op in CONDITIONAL:
            destination = target(operands)
            if start <= destination < end:
                successors.append(destination)
            else:
                exits.append({"address": hex(address), "kind": "tail", "target": hex(destination)})
            if op != "b":
                successors.append(address + 4)
        elif op in {"bl", "blr"}:
            if op == "bl":
                target(operands)
            exits.append({"address": hex(address), "kind": op, "detail": operands})
            successors.append(address + 4)
        elif op.split(".", 1)[0] in straight:
            successors.append(address + 4)
        else:
            raise ValueError("unknown local CFG instruction: " + op)
        graph[address] = []
        for successor in successors:
            if successor == end:
                exits.append({"address": hex(address), "kind": "function_fallthrough", "target": hex(end)})
            elif start <= successor < end:
                graph[address].append(successor)
                queue.append(successor)
            else:
                raise ValueError("invalid local CFG successor")
    return graph, exits


def reaches(graph: dict, start: int, goal: int, removed: set | None = None) -> bool:
    """Check ordinary graph reachability while deleting explicit nodes."""
    queue, seen, removed = [start], set(), removed or set()
    while queue:
        address = queue.pop()
        if address in seen or address in removed:
            continue
        if address == goal:
            return True
        if address not in graph:
            raise ValueError("missing reachability node")
        seen.add(address)
        queue.extend(graph[address])
    return False


def source_contract(text: str) -> dict:
    """Pin the private source-level access inventory, with literal line evidence."""
    expected = ["static ACTIVE: AtomicBool = AtomicBool::new(false);",
                "if ACTIVE.load(Ordering::Acquire) {",
                "ACTIVE.store(false, Ordering::Release);",
                "ACTIVE.store(false, Ordering::Release);",
                "ACTIVE.store(true, Ordering::Release);"]
    entries = [{"line": i + 1, "text": line.strip()} for i, line in enumerate(text.splitlines()) if re.search(r"\bACTIVE\b", line)]
    if [x["text"] for x in entries] != expected:
        raise ValueError("private flag source access inventory changed")
    checks = ["let joined = unsafe { mapping.run(worker, request.cast()) };\n    ACTIVE.store(false, Ordering::Release);",
              "request.result = execute(request);\n    // All record/statement/verifier/error ownership has ended in execute.\n    ACTIVE.store(false, Ordering::Release);",
              "ACTIVE.store(true, Ordering::Release);\n    let mut result",
              "let receipt = reservation.verify(request.row, request.role, &record);"]
    if any(text.count(check) != 1 for check in checks):
        raise ValueError("worker activation/call/join source shape changed")
    return {"accesses": entries, "private_no_address_export_at_source": True,
            "scope": "Exact reviewed file and source-level privacy, not whole-binary alias analysis."}


def references(instructions: dict, flag: int, functions: dict) -> list:
    """Catalog exact adjacent ADRP+ADD materializations, not arbitrary aliases.

    Reviewed literal materializations in these images use this spelling. The
    catalog checks that spelling and the source-level ownership premise; it
    does not assert that unknown integer/alias stores cannot address the flag.
    """
    result = []
    for address, (op, operands) in instructions.items():
        if op != "adrp":
            continue
        match = re.fullmatch(r"(x\d+), (0x[0-9a-f]+)(?: <.*>)?", operands)
        if not match or int(match[2], 16) != flag & ~4095:
            continue
        register = match[1]
        next_op, next_args = instructions.get(address + 4, ("", ""))
        add = re.fullmatch(rf"{register}, {register}, #(0x[0-9a-f]+|\d+)", next_args)
        if next_op == "add" and add and int(match[2], 16) + int(add[1], 0) == flag:
            owners = [fn for fn in functions.values() if int(fn["address"], 16) <= address < int(fn["end"], 16)]
            if len(owners) != 1:
                raise ValueError("ambiguous flag-reference owner")
            result.append({"address": hex(address), "register": register, "function": owners[0]["name"],
                           "function_address": owners[0]["address"],
                           "instructions": [f"{instructions[address + i][0]} {instructions[address + i][1]}" for i in (0, 4)]})
    return sorted(result, key=lambda x: int(x["address"], 16))


def register_number(register: str) -> int | None:
    """Normalize X/W aliases; zero/vector/stack registers are not GPR storage."""
    match = re.fullmatch(r"[xw](\d+)", register)
    return int(match[1]) if match and int(match[1]) <= 30 else None


def propagate(graph: dict, instructions: dict, start: int, flag: int, initial=None) -> tuple[dict, list]:
    """Conservatively propagate constants for flag access and store-value checks.

    This is a bounded GPR constant analysis. Unknown pointers stay unknown; their
    non-aliasing is NOT proved. Known/possibly flag-derived pointer escape or
    unsupported manipulation fails closed instead of just dropping that fact.
    """
    initial = dict(initial or {})
    states, queue, problems = {start: (initial, {r for r, v in initial.items() if v == flag})}, deque([start]), set()
    while queue:
        address = queue.popleft()
        known, taint = states[address]
        values, derived = dict(known), set(taint)
        op, operands = instructions[address]
        fields = operands.split(", ")
        first = register_number(fields[0])
        if op == "ret" and taint.intersection({0, 1}):
            problems.add((address, "flag-derived pointer returned in ABI result register"))
        if (op == "b" or op in CONDITIONAL) and target(operands) not in graph and taint.intersection(range(9)):
            problems.add((address, "flag-derived pointer passed in tail-call argument/sret register"))
        memory = re.search(r"\[(x\d+|sp)(?:, ([^\]]+))?\]", operands)
        memory_register = register_number(memory[1]) if memory else None
        if memory and memory_register in taint and (memory[2] is not None or "]!" in operands or "]," in operands):
            problems.add((address, "unsupported flag-derived memory offset/writeback"))
        if op.startswith("st"):
            data = operands.split("[", 1)[0]
            if any(register_number(r.strip()) in taint for r in data.split(",")):
                problems.add((address, "flag-derived pointer stored/escaped"))
        if op in {"bl", "blr"}:
            if taint.intersection(range(9)):
                problems.add((address, "flag-derived pointer passed in call argument/sret register"))
            for register in list(values):
                if register <= 18 or register == 30:
                    values.pop(register, None)
                    derived.discard(register)
        elif op == "adrp" or op == "adr":
            match = re.fullmatch(r"x\d+, (0x[0-9a-f]+)(?: <.*>)?", operands)
            if first is None or not match:
                raise ValueError("unknown ADR encoding")
            values[first] = int(match[1], 16)
            derived.discard(first)
            if values[first] == flag:
                derived.add(first)
        elif op in {"mov", "add", "sub"} and first is not None:
            value, pointer = None, False
            supported_shape = (op == "mov" and len(fields) == 2) or (op in {"add", "sub"} and len(fields) == 3)
            if not supported_shape and any(register_number(field) in taint for field in fields):
                problems.add((address, "unsupported flag-derived operand shape"))
            if op == "mov" and len(fields) == 2:
                source = register_number(fields[1])
                if re.fullmatch(r"#-?(?:0x[0-9a-f]+|\d+)", fields[1]):
                    value = int(fields[1][1:], 0)
                elif fields[1] in {"xzr", "wzr"}:
                    value = 0
                elif source is not None:
                    value, pointer = known.get(source), source in taint
            elif op in {"add", "sub"} and len(fields) == 3:
                source = register_number(fields[1])
                pointer = any(register_number(field) in taint for field in fields[1:])
                if source in known and re.fullmatch(r"#(?:0x[0-9a-f]+|\d+)", fields[2]):
                    value = known[source] + (1 if op == "add" else -1) * int(fields[2][1:], 0)
                elif pointer:
                    problems.add((address, "unsupported flag-derived arithmetic"))
            if fields[0].startswith("w") and value is not None:
                value &= 0xFFFFFFFF
            values.pop(first, None)
            derived.discard(first)
            if value is not None:
                values[first] = value
            if pointer or value == flag:
                derived.add(first)
        elif op not in CONDITIONAL | {"b", "ret", "br", "brk", "udf", "hlt", "cmp", "cmn", "tst", "ccmp", "ccmn"} and not op.startswith("st"):
            destinations = [first]
            if op == "ldp" or op.startswith(("swp", "ldadd")):
                destinations.append(register_number(fields[1]))
            # LDADD's first operand also contributes to a memory write. It is
            # not an ordinary load that can discard pointer-derived input.
            if op.startswith("ldadd") and first in taint:
                problems.add((address, "flag-derived atomic read-modify-write data"))
            # Loads consume an address without propagating it into loaded data.
            if not op.startswith("ld") and any(register_number(r) in taint for r in fields):
                problems.add((address, "unsupported flag-derived instruction"))
            for register in destinations:
                values.pop(register, None)
                derived.discard(register)
        if memory and ("]!" in operands or "]," in operands):
            values.pop(memory_register, None)
            derived.discard(memory_register)
        for successor in graph[address]:
            if successor not in states:
                new = values.copy(), derived.copy()
            else:
                old, old_taint = states[successor]
                new = ({r: v for r, v in old.items() if values.get(r) == v}, old_taint | derived)
            if states.get(successor) != new:
                states[successor] = new
                queue.append(successor)
    return states, [{"address": hex(a), "reason": reason} for a, reason in sorted(problems)]


def flag_accesses(instructions: dict, states: dict, flag: int) -> list:
    """Recognize only unoffset one-byte acquire/release accesses to the flag."""
    result = []
    for address, (values, taint) in sorted(states.items()):
        op, operands = instructions[address]
        memory = re.search(r"\[(x\d+)(?:, [^\]]+)?\]", operands)
        if not memory:
            continue
        base = register_number(memory[1])
        if base not in taint and values.get(base) != flag:
            continue
        match = re.fullmatch(r"(w\d+|wzr), \[(x\d+)\]", operands)
        if values.get(base) != flag or not match or op not in {"ldaprb", "ldarb", "stlrb"}:
            raise ValueError(f"unresolved flag-derived memory access at {address:#x}")
        item = {"address": hex(address), "kind": "load" if op != "stlrb" else "store", "instruction": op + " " + operands}
        if op == "stlrb":
            value = 0 if match[1] == "wzr" else values.get(register_number(match[1]))
            if value not in (0, 1):
                raise ValueError("unknown flag store value")
            item["value"] = value
        result.append(item)
    return result


def analyze_mode(analyzer, stack: dict, boundary: dict, data: bytes) -> dict:
    """Check worker activation and four explicit guarded native allocation arms."""
    symbol = active_symbol(data)
    flag = int(symbol["address"], 16)
    instructions, _ = analyzer.parse_disassembly(stack["disassembly"])
    functions = {int(fn["address"], 16): fn for fn in stack["functions"]}
    refs = references(instructions, flag, functions)
    if not refs:
        raise ValueError("no private flag references")
    owners = sorted({int(ref["function_address"], 16) for ref in refs})
    owner_analysis, stores = {}, []
    for address in owners:
        fn = functions[address]
        graph, exits = cfg(address, int(fn["end"], 16), instructions, analyzer.STRAIGHT)
        states, problems = propagate(graph, instructions, address, flag)
        if problems:
            raise ValueError("flag propagation unresolved: " + json.dumps(problems))
        accesses = flag_accesses(instructions, states, flag)
        # Every materialized pointer must be consumed as a checked memory base,
        # possibly after ABI-preserving calls/branches, or the result is unknown.
        for ref in (x for x in refs if int(x["function_address"], 16) == address):
            after = int(ref["address"], 16) + 8
            if after not in graph or not any(reaches(graph, after, int(a["address"], 16)) for a in accesses):
                raise ValueError("flag materialization has no resolved access")
        owner_analysis[address] = graph, states, accesses, exits
        stores.extend({**a, "function": fn["name"], "function_address": hex(address)} for a in accesses if a["kind"] == "store")
    workers = [a for a, fn in functions.items() if fn["name"].startswith("resource_contract::workspace::worker::")]
    if len(workers) != 1:
        raise ValueError("worker root ambiguous")
    worker = workers[0]
    reservation = int(boundary["conditional_boundary_roots"]["reservation"]["address"], 16)
    graph, states, accesses, exits = owner_analysis[worker]
    calls = [a for a in graph if instructions[a][0] == "bl" and target(instructions[a][1]) == reservation]
    true_stores = [int(a["address"], 16) for a in accesses if a["kind"] == "store" and a["value"] == 1]
    if len(calls) != 1 or len(true_stores) != 1:
        raise ValueError("unique activation/call missing")
    call, activation = calls[0], true_stores[0]
    if not reaches(graph, worker, call) or reaches(graph, worker, call, {activation}):
        raise ValueError("true store does not dominate reservation call")
    for item in accesses:
        if item["kind"] == "store" and item["value"] != 1:
            address = int(item["address"], 16)
            if reaches(graph, activation, address) and reaches(graph, address, call):
                raise ValueError("clear can precede reservation call")
    reachable_names = set(boundary["conditional_boundary_roots"]["reservation"]["per_function_maximum_entry_sp_bytes"])
    # This prior report keys its reachable frame map by emitted function address.
    if any(item["function_address"] in reachable_names for item in stores):
        raise ValueError("known flag writer occurs in reservation graph")
    if len(stores) != 3 or sorted(a["value"] for a in stores) != [0, 0, 1]:
        raise ValueError("compiled flag writer inventory differs from source")
    native = boundary["conditional_boundary_roots"]["reservation"]["frontiers"]
    sites = [x for x in native if x.get("detail") in {"_malloc", "_posix_memalign"}]
    if len(sites) != 4:
        raise ValueError("expected four System allocation sites")
    checked = []
    for site in sites:
        owners = [a for a, fn in functions.items() if fn["name"] == site["function"]]
        if len(owners) != 1 or owners[0] not in owner_analysis:
            raise ValueError("System allocation owner lacks checked flag access")
        start = owners[0]
        local, _, accesses, _ = owner_analysis[start]
        loads = [a for a in accesses if a["kind"] == "load"]
        if len(loads) != 1:
            raise ValueError("allocation arm flag load ambiguous")
        load = int(loads[0]["address"], 16)
        branch = load + 4
        destination_register = instructions[load][1].split(",", 1)[0]
        op, operands = instructions[branch]
        if op != "cbz" or not operands.startswith(destination_register + ", "):
            raise ValueError("expected immediate zero-test of acquired flag")
        zero = target(operands)
        address = int(site["address"], 16)
        if (not reaches(local, start, address) or reaches(local, start, address, {load})
                or reaches(local, start, address, {branch}) or not reaches(local, zero, address)
                or reaches(local, branch + 4, address)):
            raise ValueError("native allocation is not exclusive to the false arm")
        checked.append({**site, "status": "PASS_UNDER_PREMISES", "load": loads[0],
                        "zero_branch": hex(branch), "false_successor": hex(zero),
                        "true_successor": hex(branch + 4)})
    between_calls = [x for x in exits if x["kind"] in {"bl", "blr"} and reaches(graph, activation, int(x["address"], 16)) and reaches(graph, int(x["address"], 16), call) and int(x["address"], 16) != call]
    return {"local_checks": "PASS", "unconditional_activation": "UNKNOWN",
            "flag": symbol, "literal_reference_catalog": refs, "resolved_stores": stores,
            "worker_entry": hex(worker), "activation_store": hex(activation), "reservation_call": hex(call),
            "true_store_dominates_call": True, "known_clear_before_call": False,
            "known_writer_in_reservation_graph": False,
            "calls_between_activation_and_verification_requiring_noninterference": between_calls,
            "checked_native_allocation_sites": checked,
            "conditional_system_frontier_count_before": sum(x.get("native_category") == "system_allocator" for x in native),
            "conditional_system_frontier_count_after": sum(x.get("native_category") == "system_allocator" for x in native) - len(checked),
            "unconditional_frontier_count_unchanged": True,
            "failure_native_trap_unwind_frontiers_retained": True,
            "whole_binary_alias_or_callback_proof": False}


def run(root: Path, output: Path) -> dict:
    """Guard prior evidence and publish a new receipt; failures remain UNKNOWN."""
    output.mkdir(parents=True, exist_ok=False)
    inputs = {str(Path(__file__).resolve()): sha(Path(__file__).resolve()), str(Path(sys.executable).resolve()): sha(Path(sys.executable).resolve())}
    report = {"schema": "parliament-allocator-activation-v1", "status": "UNKNOWN", "modes": {},
              "inputs": inputs, "complete_workspace_certificate": False, "complete_stack_bound_bytes": None,
              "profile_qualified": False, "all_inputs_panic_free_proved": False,
              "no_rebuild_or_worker_execution": True,
              "premises": ["Correct source/compiler linkage and memory-safe execution of the frozen image.",
                           "The private flag address is not exported; ordinary opaque callees, native code, callbacks and other threads do not write it or reenter a flag-writing worker/setup path. This is an explicit noninterference premise, not proved from finite observations.",
                           "Ordinary calls preserve AArch64 callee-saved registers and return as modeled. Exceptional/unwind continuations remain outside this normal-path calculation.",
                           "Existing source-conditional provider target sets and failure-entry boundary premises remain unchanged."],
              "limitations": ["Unresolved aliases/opaque writers remain UNKNOWN unconditionally; no whole-binary points-to proof.",
                              "Four explicit allocation arms only; free provenance, native hidden work, failure handlers, traps, fallthroughs and unwinding remain open.",
                              "Reservation::verify called directly without the worker activation has no activation guarantee."]}
    try:
        for directory in (STACK, FRONTIERS, TARGETS):
            manifest = root / directory / "SHA256SUMS"
            inputs[str(manifest)] = sha(manifest)
            for line in manifest.read_text().splitlines():
                expected, relative = line.split("  ", 1)
                path = root / relative
                if sha(path) != expected:
                    raise ValueError("old artifact changed: " + relative)
                inputs[str(path)] = expected
        boundary = json.loads((root / FRONTIERS / "report.json").read_text())
        build_path = root / BUILD / "build-receipt.json"
        build = json.loads(build_path.read_text())
        inputs[str(build_path)] = sha(build_path)
        if not build["build_passed"] or build["source_changes"]:
            raise ValueError("original build not successful/source-stable")
        source = root / WORKSPACE
        if sha(source) != build["started_source_sha256"][str(WORKSPACE)]:
            raise ValueError("worker source no longer matches frozen binary")
        inputs[str(source)] = sha(source)
        report["source_contract"] = source_contract(source.read_text())
        (output / "workspace.rs.template").write_bytes(source.read_bytes())
        template = root / STACK / "parliament_ballot_stack_audit.py.template"
        analyzer = types.ModuleType("frozen_activation_stack_parser")
        analyzer.__file__ = str(template)
        exec(compile(template.read_bytes(), str(template), "exec"), analyzer.__dict__)
        for mode in ("portable", "accel"):
            binary = Path(build["binaries"][mode]["path"])
            expected = build["binaries"][mode]["sha256"]
            if sha(binary) != expected or boundary["modes"][mode]["binary_sha256"] != expected:
                raise ValueError("frozen executable changed")
            inputs[str(binary)] = expected
            stack = json.loads((root / STACK / (mode + ".json")).read_text())
            stack["disassembly"] = (root / STACK / mode / "disassembly.txt").read_text()
            report["modes"][mode] = analyze_mode(analyzer, stack, boundary["modes"][mode], binary.read_bytes())
            report["modes"][mode]["binary_sha256"] = expected
        report["status"] = "PASS_UNDER_PREMISES"
    except (ValueError, KeyError, OSError, UnicodeError, struct.error) as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    changes = {}
    for name, expected in inputs.items():
        path = Path(name)
        actual = sha(path) if path.is_file() else None
        if actual != expected:
            changes[name] = {"before": expected, "after": actual}
    report["input_changes"] = changes
    if changes:
        report["status"] = "UNKNOWN"
    report["observed_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    """Expose one explicit new-output diagnostic, with nonzero exit on unknown."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new directory; existing evidence is refused")
    args = parser.parse_args()
    report = run(ROOT, args.output.resolve())
    print(json.dumps({"status": report["status"], "failure": report.get("failure"), "complete_workspace_certificate": False}))
    return 0 if report["status"] == "PASS_UNDER_PREMISES" else 1


if __name__ == "__main__":
    raise SystemExit(main())
