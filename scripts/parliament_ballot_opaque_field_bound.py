#!/usr/bin/env python3
"""Bound one retained ARM64 constructor locally, leaving callees and errors open.

No binaries are executed and no historical analyzer is rerun. This limited
symbolic interpreter requires the reviewed instruction vocabulary and fails
closed on any unproved argument, ownership, control or return-layout condition.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct

U64_MAX = (1 << 64) - 1
STARTS = {"portable": 0x100013B28, "accel": 0x100013B2C}
TARGETS = {
    "portable": {0x100007114: "shim", 0x1000008C0: "alloc", 0x10005C3C0: "memcpy", 0x10005BC18: "handle_error"},
    "accel": {0x100007118: "shim", 0x1000008C0: "alloc", 0x10005A128: "memcpy", 0x100059980: "handle_error"},
}
MANIFESTS = {
    "current_candidate": "40b01704bcad1551c5a44cf8b5b8311f64d3f751a19caf36fb2ec1641611c7ba",
    "current_correspondence": "aa1c81d1f598776f046cb429b0ccff01f35ba31fbb9a962aa1f3b373a5e3bc8b",
}
SOURCE = "docs/validation/parliament_ballot_frontend_bound/analysis/source/src/framing.rs.template"
SOURCE_SHA = "784c28ba9a115cb2775d78f7147fdcbd1fac5835affd1ef9938a7f1a2c2fc0a0"


def require(condition, reason):
    """Refuse unsupported evidence without assertions disabled by Python -O."""
    if not condition:
        raise ValueError(reason)


def parse_body(text, start, end):
    """Select every aligned instruction, retaining operands but not annotations."""
    require(type(start) is int and type(end) is int and start < end, "invalid range")
    body = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]+):\s+([a-z.]+)(?:\s+(.*))?", line)
        if match and start <= int(match[1], 16) < end:
            address = int(match[1], 16)
            require(address not in body, "duplicate instruction")
            operand = (match[3] or "").split(";", 1)[0].split(" <", 1)[0].strip()
            body[address] = (match[2], re.sub(r"\s+", " ", operand))
    require(set(body) == set(range(start, end, 4)), "missing or misaligned instruction")
    return body


def branch(operand):
    """Require a complete direct absolute branch operand."""
    require(re.fullmatch(r"0x[0-9a-f]+", operand) is not None, "unknown branch operand")
    return int(operand, 16)


def control_graph(body, mode):
    """Derive the complete acyclic local graph, retaining the final-call frontier."""
    require(mode in STARTS, "unknown mode")
    start, end = STARTS[mode], STARTS[mode] + 156
    require(set(body) == set(range(start, end, 4)), "constructor extent changed")
    edges, calls = {}, {}
    for address, (op, operands) in body.items():
        if op == "ret":
            require(operands == "", "nonstandard return")
            successors = []
        elif op in ("b", "b.ls"):
            successors = [branch(operands)] + ([address + 4] if op == "b.ls" else [])
        elif op == "cbz":
            parts = operands.split(", ")
            require(len(parts) == 2, "invalid zero branch")
            successors = [branch(parts[1]), address + 4]
        elif op == "bl":
            target = branch(operands)
            require(target in TARGETS[mode], "unknown callee")
            calls[address] = TARGETS[mode][target]
            if address == end - 4:
                require(calls[address] == "handle_error", "unknown final continuation")
                successors = []
            else:
                require(calls[address] != "handle_error", "error call moved into ordinary flow")
                successors = [address + 4]
        else:
            require(op in {"stp", "ldp", "add", "mov", "cmp", "str", "strh"}, "unsupported opcode")
            successors = [address + 4]
        require(all(n in body for n in successors), "control leaves body")
        edges[address] = successors
    visiting, visited = set(), set()

    def walk(node):
        require(node not in visiting, "cyclic constructor control")
        if node in visited:
            return
        visiting.add(node)
        for child in edges[node]:
            walk(child)
        visiting.remove(node)
        visited.add(node)

    walk(start)
    require(visited == set(body), "unreachable reviewed instruction")
    return edges, calls


def analyze_body(body, mode):
    """Derive all length/allocator path classes and validate the reviewed contract.

    Registers carry exact constants, original pointer/owner tokens or the
    original length symbol with an unsigned interval. Callees clobber volatile
    registers, preserve saved registers and memory by the explicit ABI/ownership
    premises, and allocator return is split into null/non-null alternatives.
    """
    edges, targets = control_graph(body, mode)
    start, end = STARTS[mode], STARTS[mode] + 156
    initial = dict(pc=start, regs={f"x{i}": f"entry:x{i}" for i in range(31)},
                   sp=0, stack={}, output={}, interval=[0, U64_MAX], compare=None,
                   calls=[], path=[], maximum_depth=0, allocated=None)
    initial["regs"].update(x0="input", x1="length", x8="output")
    pending, finished = [initial], []

    def read(state, register):
        require(re.fullmatch(r"[xw](?:[0-9]|[12][0-9]|30)", register) is not None, "unknown register")
        value = state["regs"]["x" + register[1:]]
        if register[0] == "w":
            require(type(value) is int, "unproved narrow-register value")
            value &= (1 << 32) - 1
        return value

    def write(state, register, value):
        require(re.fullmatch(r"[xw](?:[0-9]|[12][0-9]|30)", register) is not None, "unknown destination")
        if register[0] == "w":
            require(type(value) is int, "unproved zero extension")
            value &= (1 << 32) - 1
        state["regs"]["x" + register[1:]] = value

    def split_length(state, threshold, target, fallthrough):
        low, high = state["interval"]
        for a, b, pc in ((low, min(high, threshold), target), (max(low, threshold + 1), high, fallthrough)):
            if a <= b:
                child = copy.deepcopy(state)
                child["interval"], child["pc"] = [a, b], pc
                pending.append(child)

    while pending:
        state = pending.pop()
        pc = state["pc"]
        require(pc in body and pc not in state["path"], "invalid symbolic continuation")
        state["path"].append(pc)
        op, operand = body[pc]
        parts = operand.split(", ")
        next_pc = pc + 4
        if op == "mov":
            require(len(parts) == 2, "invalid move")
            value = int(parts[1][1:], 0) if parts[1].startswith("#") else read(state, parts[1])
            write(state, parts[0], value)
        elif op == "add":
            require(len(parts) == 3 and parts[1] == "sp" and parts[2].startswith("#"), "unknown address arithmetic")
            require(parts[0] == "x29" and int(parts[2][1:], 0) == 32 and state["sp"] == -48, "frame-pointer setup")
            write(state, parts[0], ("stack", state["sp"] + int(parts[2][1:], 0)))
        elif op in ("stp", "ldp", "str", "strh"):
            match = re.fullmatch(r"(x\d+|w\d+)(?:, (x\d+))?, \[(sp|x\d+)(?:, #(-?0x[0-9a-f]+))?\](!)?(?:, #(0x[0-9a-f]+))?", operand)
            require(match is not None, "unsupported memory operand")
            r1, r2, base, offset, pre, post = match.groups()
            require((r2 is not None) == (op in ("stp", "ldp")), "memory arity")
            require(r1.startswith("w") if op == "strh" else r1.startswith("x"), "memory register width")
            displacement = int(offset or "0", 0)
            require(not (pre and post), "ambiguous indexed memory")
            if pre or post:
                require(base == "sp", "non-stack writeback")
            if pre:
                state["sp"] += displacement
                displacement = 0
            require(state["sp"] % 16 == 0 and -48 <= state["sp"] <= 0, "stack extent/alignment")
            state["maximum_depth"] = max(state["maximum_depth"], -state["sp"])
            location = ("stack", state["sp"]) if base == "sp" else read(state, base)
            require(location == "output" or isinstance(location, tuple) and location[0] == "stack", "write outside output/stack")
            size = 2 if op == "strh" else 8
            for index, register in enumerate([r1] + ([r2] if r2 else [])):
                pos = displacement + index * 8 + (location[1] if isinstance(location, tuple) else 0)
                memory = state["stack"] if isinstance(location, tuple) else state["output"]
                require((-48 <= pos and pos + size <= 0) if memory is state["stack"] else (0 <= pos and pos + size <= 32), "memory outside owned object")
                key = (pos, size)
                if op == "ldp":
                    require(key in memory, "uninitialized stack restore")
                    write(state, register, memory[key])
                else:
                    require(not any(max(pos, a) < min(pos + size, a + b) and key != (a, b) for a, b in memory), "overlapping stores")
                    memory[key] = read(state, register)
            if post:
                state["sp"] += int(post, 0)
                require(state["sp"] % 16 == 0 and -48 <= state["sp"] <= 0, "post-index stack extent/alignment")
        elif op == "cmp":
            require(len(parts) == 2 and parts[1].startswith("#"), "unknown comparison")
            require(read(state, parts[0]) == "length", "comparison lost input length")
            state["compare"] = int(parts[1][1:], 0)
        elif op == "b.ls":
            require(state["compare"] is not None, "missing unsigned comparison")
            split_length(state, state["compare"], branch(operand), next_pc)
            continue
        elif op == "b":
            next_pc = branch(operand)
        elif op == "cbz":
            value = read(state, parts[0])
            if value == "length":
                split_length(state, 0, branch(parts[1]), next_pc)
                continue
            require(value in (0, "allocated"), "unproved zero test")
            next_pc = branch(parts[1]) if value == 0 else next_pc
        elif op == "bl":
            kind = targets[pc]
            args = [read(state, f"x{i}") for i in range(3 if kind == "memcpy" else 2)] if kind != "shim" else []
            require(state["sp"] == -48, "callee stack not preserved")
            if kind == "alloc":
                require(args == ["length", 1] and 1 <= state["interval"][0] <= state["interval"][1] <= 256, "allocation arguments/length guard")
            elif kind == "memcpy":
                expected = "allocated" if state["allocated"] else 1
                require(args == [expected, "input", "length"] and state["interval"][1] <= 256, "copy arguments/length guard")
                require(state["allocated"] or state["interval"] == [0, 0], "dangling destination with nonzero copy")
            elif kind == "handle_error":
                require(args == [1, "length"] and state["allocated"] is False and state["interval"][0] > 0, "allocation-error argument/branch")
            state["calls"].append(dict(kind=kind, address=hex(pc), arguments=args,
                                       length_interval=state["interval"][:], frame_depth_bytes=-state["sp"]))
            for i in range(19):
                state["regs"][f"x{i}"] = f"clobbered:{pc}:x{i}"
            state["regs"]["x30"] = f"callee_link:{pc}"
            state["compare"] = None
            if kind == "alloc":
                for value in (0, "allocated"):
                    child = copy.deepcopy(state)
                    child["allocated"] = value != 0
                    child["regs"]["x0"], child["pc"] = value, next_pc
                    pending.append(child)
                continue
            if kind == "handle_error":
                require(pc == end - 4, "allocation error is not retained final frontier")
                state["outcome"] = "unknown_frontier"
                state["continuation"] = hex(end)
                finished.append(state)
                continue
        elif op == "ret":
            require(state["sp"] == 0, "stack not restored")
            require(all(read(state, f"x{i}") == f"entry:x{i}" for i in list(range(19, 30)) + [30]), "callee-saved/link register not restored")
            state["outcome"] = "error" if state["interval"][0] > 256 else "success"
            finished.append(state)
            continue
        else:
            raise ValueError("unsupported instruction")
        state["pc"] = next_pc
        pending.append(state)

    profiles = {}
    for state in finished:
        interval, output = state["interval"], state["output"]
        if state["outcome"] == "unknown_frontier":
            name, sequence = "allocation_failure", ["shim", "alloc", "handle_error"]
            require(interval == [1, 256] and output == {}, "failure prefix owns unexpected result")
        elif state["outcome"] == "error":
            name, sequence = "oversize", []
            require(interval == [257, U64_MAX], "wrong oversize partition")
            require(output == {(8, 2): 8, (16, 8): 256, (24, 8): "length", (0, 8): 1}, "error result layout changed")
        else:
            name, sequence = ("empty", ["memcpy"]) if interval == [0, 0] else ("allocated", ["shim", "alloc", "memcpy"])
            require(interval in ([0, 0], [1, 256]), "wrong success partition")
            require(output == {(8, 8): "length", (16, 8): 1 if name == "empty" else "allocated", (24, 8): "length", (0, 8): 0}, "success vector/result layout changed")
        require(name not in profiles, "duplicate semantic path")
        require([c["kind"] for c in state["calls"]] == sequence, "unexpected call sequence")
        profiles[name] = dict(length_interval=interval, outcome=state["outcome"],
                              local_instructions=len(state["path"]), calls=state["calls"],
                              path=[hex(a) for a in state["path"]], maximum_frame_bytes=state["maximum_depth"],
                              output_stores=[dict(offset=a, bytes=b, value=v) for (a, b), v in sorted(output.items())])
        if "continuation" in state:
            profiles[name]["hypothetical_return_continuation"] = state["continuation"]
    require(set(profiles) == {"oversize", "empty", "allocated", "allocation_failure"}, "incomplete path classes")
    require(set(a for s in finished for a in s["path"]) == set(body), "unproved reachable instruction")
    frame = max(p["maximum_frame_bytes"] for p in profiles.values())
    return dict(profiles=profiles, maximum_local_instructions=max(p["local_instructions"] for p in profiles.values()),
                frame_bytes=frame, own_stack_including_red_zone_bytes=frame + 128,
                instruction_count=len(body), cfg={hex(a): [hex(n) for n in v] for a, v in sorted(edges.items())},
                ordinary_control_acyclic=True, unknown_terms=["shim", "allocator", "native memcpy", "allocation-error work and continuation", "unwind/exceptional reentry"],
                no_complete_constructor_cost_bound=True)


def digest(path):
    """Hash exact retained bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text_bytes(binary, address, size):
    """Extract a range from the known ARM64 executable's file-backed text section."""
    require(len(binary) >= 32, "short image")
    magic, cpu, _, kind, count, total, _, _ = struct.unpack_from("<8I", binary)
    require((magic, cpu, kind) == (0xFEEDFACF, 0x100000C, 2) and 32 + total <= len(binary), "unsupported image")
    offset, matches = 32, []
    for _ in range(count):
        require(offset + 8 <= 32 + total, "truncated command")
        command, extent = struct.unpack_from("<II", binary, offset)
        require(extent >= 8 and extent % 8 == 0 and offset + extent <= 32 + total, "invalid command")
        if command == 0x19:
            require(extent >= 72, "short segment")
            fields = struct.unpack_from("<II16sQQQQiiII", binary, offset)
            require(extent == 72 + 80 * fields[9], "section count")
            for i in range(fields[9]):
                row = struct.unpack_from("<16s16sQQ8I", binary, offset + 72 + 80 * i)
                name, owner, start, length, position = row[:5]
                if (name.rstrip(b"\0"), owner.rstrip(b"\0")) == (b"__text", b"__TEXT"):
                    require(start <= address <= address + size <= start + length and position + length <= len(binary), "body outside text")
                    matches.append(binary[position + address - start:position + address - start + size])
        offset += extent
    require(offset == 32 + total and len(matches) == 1, "ambiguous text section")
    return matches[0]


def report(root):
    """Authenticate retained evidence, analyze both bodies, and record live drift separately."""
    root = Path(root).resolve()
    guards = {}

    def guard(path, expected):
        path = Path(path).resolve()
        actual = digest(path)
        require(str(path) not in guards or guards[str(path)] == actual, "mid-read drift")
        guards[str(path)] = actual
        require(actual == expected, "retained identity changed: " + str(path))

    for name, expected in MANIFESTS.items():
        folder = root / "docs/validation" / ("parliament_ballot_" + name)
        guard(folder / "SHA256SUMS", expected)
        seen = set()
        for line in (folder / "SHA256SUMS").read_text().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            require(match is not None and match[2] not in seen, "bad retained manifest")
            seen.add(match[2])
            path = (root / match[2]) if name == "current_candidate" else (folder / match[2])
            require(path.resolve().is_relative_to(folder), "retained manifest escape")
            guard(path, match[1])
    base = root / "docs/validation/parliament_ballot_current_candidate"
    build = json.loads((base / "build-v2/build-receipt.json").read_text())
    capture = json.loads((base / "stack/receipt.json").read_text())
    correspondence = json.loads((root / "docs/validation/parliament_ballot_current_correspondence/analysis/report.json").read_text())
    require(build["source_stable"] and all(c["exit"] == 0 and not c["source_changes"] for c in build["commands"]), "failed retained build")
    require(capture["capture_passed"] and not capture["input_changes"], "failed retained capture")
    require(correspondence["verdict"] == "PASS_UNDER_STATED_PREMISES" and not correspondence["input_changes"], "failed retained correspondence")
    source = root / SOURCE
    guard(source, SOURCE_SHA)
    source_name = str(root / "crates/iroha_parliament_ballot_proof/src/framing.rs")
    require(build["source_files"][source_name] == SOURCE_SHA, "source not in successful build")
    # Resolve the exact old lock from its manifest-bound bytes. Every other
    # recorded build input must still match; never adopt a changed live hash.
    lock_archive = base / "build-v2/generated-source/root-Cargo.lock.template.template"
    historical_inputs, live_drift = {}, {}
    for name, expected in build["source_files"].items():
        live = Path(name)
        observed = digest(live) if live.is_file() else None
        resolved = lock_archive if name == str(root / "Cargo.lock") else live
        guard(resolved, expected)
        historical_inputs[name] = {"sha256": expected, "resolved_path": str(resolved)}
        if observed != expected:
            live_drift[name] = {"captured": expected, "observed": observed,
                                "original_resolved_path": str(resolved)}
    modes = {}
    for mode, start in STARTS.items():
        image = build["binaries"][mode]
        guard(Path(image["path"]), image["sha256"])
        require(capture["captures"][mode]["binary_sha256"] == image["sha256"], "capture binary differs")
        stored = json.loads((base / f"stack/{mode}.json").read_text())
        identity = stored["identity"]
        require(identity["binary_sha256"] == image["sha256"] and identity["binary_tool_and_analyzer_unchanged_during_capture"], "unstable disassembly identity")
        for command in identity["commands"]:
            guard(Path(command["output"]), command["sha256"])
            require(command["stderr"] == "", "captured tool error")
        owners = [f for f in stored["functions"] if "framing::OpaqueField::new::" in f["name"]]
        require(len(owners) == 1 and owners[0]["address"] == hex(start) and owners[0]["end"] == hex(start + 156), "function owner/range differs")
        body = parse_body((base / f"stack/{mode}/disassembly.txt").read_text(), start, start + 156)
        stubs = (base / f"stack/{mode}/stubs.txt").read_text()
        memcpy = next(a for a, n in TARGETS[mode].items() if n == "memcpy")
        require(re.search(rf"^0x{memcpy:016x}\s+\d+ _memcpy$", stubs, re.M) is not None, "copy stub identity")
        functions = {int(f["address"], 16): f["name"] for f in stored["functions"]}
        for address, kind in TARGETS[mode].items():
            if kind != "memcpy":
                pattern = {"alloc": "__rustc::__rust_alloc", "shim": "__rustc::__rust_no_alloc_shim_is_unstable_v2", "handle_error": "alloc::raw_vec::handle_error::"}[kind]
                require(pattern in functions.get(address, ""), "callee identity changed")
        require("framing::frame_bytes::" in functions.get(start + 156, ""), "unknown next function")
        result = analyze_body(body, mode)
        require(result["frame_bytes"] == owners[0]["maximum_sp_decrement_bytes"] and not owners[0]["frame_errors"], "frame capture disagreement")
        result.update(binary_sha256=image["sha256"], body_sha256=hashlib.sha256(text_bytes(Path(image["path"]).read_bytes(), start, 156)).hexdigest(),
                      body_start=hex(start), body_end=hex(start + 156), source_sha256=SOURCE_SHA)
        modes[mode] = result
    after = {name: digest(Path(name)) for name in guards}
    require(after == guards, "retained evidence changed during analysis")
    return dict(schema="parliament-opaque-field-bound-v1", verdict="PASS_UNDER_STATED_PREMISES", modes=modes,
                input_sha256=guards, input_after_sha256=after, observed_build_input_drift=live_drift,
                historical_build_inputs=historical_inputs,
                correspondence_scope="Manifest-authenticated prior compiled correspondence; no existing analyzer rerun and no prior live-input pin refreshed.",
                applies_to_current_checkout=False, complete_constructor_cost_certificate=False,
                complete_workspace_certificate=False, complete_native_cost_certificate=False,
                physical_cost_calibrated=False, profile_qualified=False, production_gate_changed=False,
                scope="Retained image ordinary-return paths and prefixes ending at the allocation-error call. Native/callee work, error continuation and exceptional reentry remain unknown. Compiler/disassembler correspondence, ABI preservation, valid disjoint input/output/stack and fresh allocation/copy contracts are explicit premises. Live build-input observations do not transfer this result to the checkout.")


def main(argv=None):
    """Write a new report; retain UNKNOWN when analysis refuses."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("output already exists")
    try:
        value = report(args.root)
        code = 2 if args.require_qualified else 0
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        value = dict(schema="parliament-opaque-field-bound-v1", verdict="UNKNOWN", error=str(error),
                     applies_to_current_checkout=False, complete_constructor_cost_certificate=False,
                     complete_native_cost_certificate=False, complete_workspace_certificate=False,
                     physical_cost_calibrated=False, profile_qualified=False, production_gate_changed=False)
        code = 1
    with args.out.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
