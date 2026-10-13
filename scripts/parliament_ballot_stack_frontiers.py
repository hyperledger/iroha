#!/usr/bin/env python3
"""Separate frozen ARM64 verifier frame obligations at explicit failure entries.

Requires Python 3.11+, the retained compiled-stack/provider catalogs and worker
images, and installed Rust 1.93.1 rustdoc source HTML (override --rustdoc-src).
No environment variables, build, worker execution, or network request is used.
Only a new --output directory is written; existing evidence is never replaced.

This is a boundary calculation, not a panic-unreachability or full stack proof.
Three pinned source functions returning ! are explicit excluded entries. The !
type means no normal return, not no unwind, allocation, native work, or stack.
Every cut remains a reported frontier. Native calls, indirect I/O destruction,
traps and function fallthroughs remain unknown; no input is declared panic-free.
"""

import argparse
from collections import Counter, deque
import copy
import datetime
import hashlib
import html
import json
from pathlib import Path
import re
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
STACK = Path("docs/validation/parliament_ballot_compiled_stack")
TARGETS = Path("docs/validation/parliament_ballot_indirect_targets")
BUILD = Path("docs/validation/parliament_ballot_resource_contract")
COMMIT = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf"
BOUNDARIES = {
    "core::panicking::panic_fmt": (
        "core/panicking.rs", "pub const fn panic_fmt(fmt: fmt::Arguments<'_>) -> ! {",
        "Panic formatting/handler entry; handler, formatting and unwind/abort behavior excluded."),
    "core::panicking::panic_nounwind_fmt": (
        "core/panicking.rs", "pub const fn panic_nounwind_fmt(fmt: fmt::Arguments<'_>, force_no_backtrace: bool) -> ! {",
        "Non-unwinding panic formatting entry; handler/native/abort stack still excluded."),
    "alloc::alloc::handle_alloc_error": (
        "alloc/alloc.rs", "pub const fn handle_alloc_error(layout: Layout) -> ! {",
        "Infallible-allocation failure handler entry; hook/abort/runtime stack excluded."),
}
NATIVE_CATEGORIES = {
    "memory": {"_memcpy", "_memcmp", "_memset", "_bzero"},
    "system_allocator": {"_malloc", "_posix_memalign", "_free"},
    "termination_or_resource_report": {"__exit", "_write"},
    "unwind": {"__Unwind_Resume"},
    "host_io": {"_open", "_read", "_fstat", "_close", "___error"},
    "native_thread_stack_query": {"_pthread_self", "_pthread_get_stackaddr_np", "_pthread_get_stacksize_np"},
}


def sha(path):
    """Hash exact input bytes, including archived executable identities."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def base_symbol(name):
    """Remove only the emitted Rust hash suffix; do not classify by substring."""
    return re.sub(r"::h[0-9a-f]{16}$", "", name)


def rustdoc_source(text):
    """Extract the exact highlighted source block, omitting numbered anchors."""
    opening, closing = '<pre class="rust"><code>', '</code></pre>'
    if text.count(opening) != 1 or text.count(closing) != 1:
        raise ValueError("expected one rustdoc source block")
    code = text.split(opening, 1)[1].split(closing, 1)[0]
    anchors = re.findall(r'<a href=#(\d+) id=(\d+) data-nosnippet>(\d+)</a>', code)
    if not anchors or any(tuple(map(int, entry)) != (i, i, i) for i, entry in enumerate(anchors, 1)):
        raise ValueError("rustdoc source line anchors differ")
    code = re.sub(r'<a href=#\d+ id=\d+ data-nosnippet>\d+</a>', '', code)
    code = html.unescape(re.sub(r'<[^>]+>', '', code))
    if len(code.splitlines()) != len(anchors):
        raise ValueError("rustdoc source line count differs")
    return code


def boundary_sources(rustdoc, output, inputs):
    """Retain installed literal ! signatures and source snapshots with identity."""
    sources, result = {}, {}
    for name, (relative, signature, scope) in BOUNDARIES.items():
        if relative not in sources:
            path = rustdoc / (relative + ".html")
            inputs[str(path)] = sha(path)
            code = rustdoc_source(path.read_text())
            archive = output / (relative.replace('/', '-') + '.template')
            archive.write_text(code)
            sources[relative] = code, archive, path
        code, archive, path = sources[relative]
        lines = code.splitlines()
        locations = [i for i, line in enumerate(lines) if line == signature]
        if len(locations) != 1:
            raise ValueError("missing or changed failure-entry signature: " + name)
        line = locations[0]
        result[name] = {
            "signature": signature, "signature_line": line + 1, "scope": scope,
            "literal_excerpt": [{"line": i + 1, "text": lines[i]}
                                for i in range(max(0, line - 6), min(len(lines), line + 25))],
            "installed_html": str(path), "installed_html_sha256": inputs[str(path)],
            "extracted_source": str(archive), "extracted_source_sha256": sha(archive),
            "corresponding_commit_url": f"https://github.com/rust-lang/rust/blob/{COMMIT}/library/{relative.split('/', 1)[0]}/src/{relative.split('/', 1)[1]}",
            "provenance": "Installed Rust 1.93.1 rustdoc source; release/commit matches original rustc build receipt. No independently attested std build or LLVM noreturn metadata claimed.",
            "no_normal_return": True, "no_unwind_or_native_work_proved": False,
        }
    return result


def load_analyzer(root, inputs):
    """Load checked archived analyzer bytes without trusting a bytecode cache."""
    receipt_path = root / STACK / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    template = root / STACK / "parliament_ballot_stack_audit.py.template"
    expected = receipt["source_after"]["scripts/parliament_ballot_stack_audit.py"]
    if sha(template) != expected:
        raise ValueError("frozen stack analyzer changed")
    inputs[str(receipt_path)], inputs[str(template)] = sha(receipt_path), expected
    module = types.ModuleType("frozen_stack_frontier_analyzer")
    module.__file__ = str(template)
    exec(compile(template.read_bytes(), str(template), "exec"), module.__dict__)
    return module


def provider_graph(report, sites):
    """Copy the frozen graph and add only the previously guarded provider sets."""
    functions = {int(fn["address"], 16): copy.deepcopy(fn) for fn in report["functions"]}
    if len(functions) != len(report["functions"]):
        raise ValueError("duplicate function address")
    for site in sites:
        owners = [fn for fn in functions.values() if fn["name"] == site["function"]]
        if len(owners) != 1:
            raise ValueError("ambiguous provider owner")
        function = owners[0]
        gaps = [gap for gap in function["gaps"] if gap["address"] == site["address"] and gap["kind"] == "indirect_call"]
        if len(gaps) != 1 or gaps[0]["caller_depth_bytes"] != site["caller_depth_bytes"]:
            raise ValueError("provider gap differs")
        function["gaps"].remove(gaps[0])
        for target in site["conditional_targets"]:
            address = int(target["address"], 16)
            if address not in functions or functions[address]["name"] != target["symbol"]:
                raise ValueError("provider target differs")
            function["calls"].append({"address": site["address"], "target": target["address"],
                                      "kind": "source_conditional_indirect", "caller_depth_bytes": site["caller_depth_bytes"]})
    return functions


def cut_failure_entries(functions, source_evidence):
    """Turn incoming failure calls into explicit opaque frontiers, not zero-cost calls.

    Call continuations, original local maxima, and all other gaps are retained.
    No branch is declared infeasible, and no noreturn-based CFG rewrite is used.
    """
    copied, targets = copy.deepcopy(functions), {}
    for name in BOUNDARIES:
        matches = [address for address, fn in copied.items() if base_symbol(fn["name"]) == name]
        if len(matches) != 1 or name not in source_evidence:
            raise ValueError("missing or ambiguous explicit failure entry: " + name)
        targets[matches[0]] = name
    for function in copied.values():
        retained = []
        for call in function["calls"]:
            target = int(call["target"], 16)
            if target not in targets:
                retained.append(call)
                continue
            function["gaps"].append({"address": call["address"], "kind": "failure_boundary",
                                      "detail": targets[target], "target": call["target"],
                                      "caller_depth_bytes": call["caller_depth_bytes"],
                                      "original_call_kind": call["kind"]})
        function["calls"] = retained
    return copied


def reachable(functions, root):
    """Find syntactic direct/provider reachability; native hidden calls stay unknown."""
    pending, seen = [root], set()
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        if address not in functions:
            raise ValueError("call target missing from function graph")
        seen.add(address)
        pending.extend(int(call["target"], 16) for call in functions[address]["calls"])
    return seen


def shortest_path(functions, root, target):
    """Retain a concrete syntactic call path; not a claim of input feasibility."""
    queue, previous = deque([root]), {root: None}
    while queue:
        current = queue.popleft()
        if current == target:
            result = []
            while previous[current] is not None:
                parent, call = previous[current]
                result.append({"caller": functions[parent]["name"], **call,
                               "callee": functions[current]["name"]})
                current = parent
            return list(reversed(result))
        for call in functions[current]["calls"]:
            child = int(call["target"], 16)
            if child not in functions:
                raise ValueError("path target missing")
            if child not in previous:
                previous[child] = current, call
                queue.append(child)
    raise ValueError("frontier owner is not reachable")


def caller_envelope(analyzer, functions, root):
    """Bound modeled caller frames and per-frontier entry depth, never its callee.

    Positive-weight SCCs and frame errors fail; zero-weight tail cycles collapse.
    Local/red-zone maxima are unchanged from the frozen conservative CFG. Opaque
    calls may return under that analyzer's ABI assumption; their extra stack and
    hidden callbacks are not bounded by these caller-contribution numbers.
    """
    seen = reachable(functions, root)
    if any(functions[node]["frame_errors"] for node in seen):
        raise ValueError("reachable frame error prevents caller envelope")
    graph = {node: [int(call["target"], 16) for call in functions[node]["calls"]] for node in seen}
    groups = analyzer.components(graph)
    owner = {node: i for i, group in enumerate(groups) for node in group}
    successors, incoming = {i: [] for i in range(len(groups))}, Counter()
    for node in seen:
        for call in functions[node]["calls"]:
            child = int(call["target"], 16)
            if call["caller_depth_bytes"] < 0:
                raise ValueError("negative call depth")
            if owner[node] == owner[child]:
                if call["caller_depth_bytes"] != 0:
                    raise ValueError("positive recursive component prevents caller envelope")
            else:
                successors[owner[node]].append((owner[child], call["caller_depth_bytes"]))
                incoming[owner[child]] += 1
    queue = deque(i for i in range(len(groups)) if not incoming[i])
    depth, processed = {owner[root]: 0}, 0
    while queue:
        parent = queue.popleft()
        processed += 1
        for child, amount in successors[parent]:
            if parent in depth:
                depth[child] = max(depth.get(child, 0), depth[parent] + amount)
            incoming[child] -= 1
            if incoming[child] == 0:
                queue.append(child)
    if processed != len(groups) or len(depth) != len(groups):
        raise ValueError("incomplete condensation traversal")
    frontiers = []
    for node in sorted(seen):
        for gap in functions[node]["gaps"]:
            if gap["caller_depth_bytes"] < 0:
                raise ValueError("negative frontier depth")
            item = {"function": functions[node]["name"], **gap,
                    "maximum_modeled_caller_sp_bytes": depth[owner[node]] + gap["caller_depth_bytes"],
                    "callee_stack_bytes": None}
            if gap["kind"] == "native_edge":
                categories = [name for name, symbols in NATIVE_CATEGORIES.items() if gap["detail"] in symbols]
                item["native_category"] = categories[0] if categories else "unclassified_native"
            frontiers.append(item)
    maximum = max(depth[owner[node]] + functions[node]["local_frame_plus_red_zone_bytes"] for node in seen)
    endpoints = {}
    for item in frontiers:
        if item['kind'] not in {'native_edge', 'failure_boundary'}:
            continue
        key = item['kind'], item['detail']
        entry = endpoints.setdefault(key, {'kind': key[0], 'endpoint': key[1], 'sites': 0,
                                          'maximum_modeled_caller_sp_bytes': 0, 'callee_stack_bytes': None})
        entry['sites'] += 1
        entry['maximum_modeled_caller_sp_bytes'] = max(entry['maximum_modeled_caller_sp_bytes'], item['maximum_modeled_caller_sp_bytes'])
    return {"modeled_caller_frame_envelope_bytes": maximum,
            "per_function_maximum_entry_sp_bytes": {hex(node): depth[owner[node]] for node in sorted(seen)},
            "frontiers": frontiers, "frontier_kind_counts": dict(sorted(Counter(f["kind"] for f in frontiers).items())),
            "native_category_counts": dict(sorted(Counter(f["native_category"] for f in frontiers if f["kind"] == "native_edge").items())),
            "opaque_endpoint_obligations": [endpoints[key] for key in sorted(endpoints)],
            "root": functions[root]["name"], "address": hex(root), "reachable_functions": len(seen),
            "complete_stack_bound_bytes": None, "failure_entries_excluded_not_proved_unreachable": True,
            "ordinary_call_return_abi_assumption": "Opaque callees preserve caller SP/FP on return; their peak and hidden calls are unknown."}


def classify_indirects(full, cut, worker, verifier):
    """Explain every worker-reachable indirect call after provider expansion."""
    full_seen, worker_seen, verifier_seen = reachable(full, worker), reachable(cut, worker), reachable(cut, verifier)
    output = []
    for owner in sorted(full_seen):
        for gap in full[owner]["gaps"]:
            if gap["kind"] != "indirect_call":
                continue
            path = shortest_path(full, worker, owner)
            crossed = [edge for edge in path if base_symbol(edge["callee"]) in BOUNDARIES]
            if owner in verifier_seen:
                category = "remains_inside_conditional_verifier_graph"
            elif owner in worker_seen:
                category = "worker_only_frontier"
            else:
                category = "only_behind_explicit_failure_entry_in_resolved_graph"
                if not crossed:
                    raise ValueError("removed owner path did not cross a failure entry")
            output.append({"function": full[owner]["name"], **gap, "category": category,
                           "worker_call_path": path, "first_failure_entry_on_this_path": crossed[0] if crossed else None,
                           "path_input_feasibility_proved": False})
    return output


def run(root, output, rustdoc):
    """Guard frozen sources/images, retain sources and a separate proof-boundary report."""
    output.mkdir(parents=True, exist_ok=False)
    catalog_path = root / TARGETS / 'catalog.json'
    catalog = json.loads(catalog_path.read_text())
    # Verify the complete old artifact inventory; never edit or repin it.
    inputs = {str(Path(__file__).resolve()): sha(__file__), str(Path(sys.executable).resolve()): sha(sys.executable)}
    for directory in [STACK, TARGETS]:
        manifest = root / directory / 'SHA256SUMS'
        inputs[str(manifest)] = sha(manifest)
        for line in manifest.read_text().splitlines():
            expected, relative = line.split('  ', 1)
            path = root / relative
            if sha(path) != expected:
                raise ValueError("frozen artifact changed: " + relative)
            inputs[str(path)] = expected
    for path, expected in catalog['inputs'].items():
        if sha(path) != expected:
            raise ValueError("catalog input changed: " + path)
        inputs[path] = expected
    build = json.loads((root / BUILD / 'build-receipt.json').read_text())
    if f'commit-hash: {COMMIT}' not in build['rustc'] or 'release: 1.93.1' not in build['rustc']:
        raise ValueError("unexpected original compiler identity")
    frozen = {line.split('  ', 1)[1]: line.split('  ', 1)[0]
              for line in (root / BUILD / 'build-source.sha256').read_text().splitlines()}
    for relative in ['crates/iroha_parliament_ballot_proof/examples/resource_contract/budget.rs',
                     'crates/iroha_parliament_ballot_proof/examples/resource_contract/workspace.rs']:
        if sha(root / relative) != frozen[relative]:
            raise ValueError("source boundary changed from original worker build")
        inputs[str(root / relative)] = frozen[relative]
    sources = boundary_sources(rustdoc, output, inputs)
    analyzer, modes = load_analyzer(root, inputs), {}
    for mode in ['portable', 'accel']:
        report = json.loads((root / STACK / f'{mode}.json').read_text())
        full = provider_graph(report, catalog['modes'][mode]['sites'])
        cut = cut_failure_entries(full, sources)
        roots = {}
        for label, name in [('worker', 'resource_contract::workspace::worker'),
                            ('reservation', 'resource_contract::budget::Reservation::verify')]:
            matches = [address for address, fn in full.items() if base_symbol(fn['name']) == name]
            if len(matches) != 1:
                raise ValueError("missing or ambiguous boundary root")
            roots[label] = matches[0]
            previous = [item for item in catalog['modes'][mode]['conditional_stack_regions']
                        if item['address'] == hex(matches[0])]
            if len(previous) != 1 or analyzer.call_region(full, matches[0]) != previous[0]:
                raise ValueError("provider-expanded graph differs from frozen catalog")
        indirects = classify_indirects(full, cut, roots['worker'], roots['reservation'])
        envelopes = {name: caller_envelope(analyzer, cut, address) for name, address in roots.items()}
        modes[mode] = {
            'binary_sha256': catalog['modes'][mode]['binary_sha256'],
            'failure_entry_addresses': {base_symbol(fn['name']): hex(address) for address, fn in full.items() if base_symbol(fn['name']) in BOUNDARIES},
            'remaining_indirect_classification': indirects,
            'indirect_classification_counts': dict(sorted(Counter(item['category'] for item in indirects).items())),
            'conditional_boundary_roots': envelopes,
            'original_worker_positive_recursive_components': next(r['positive_weight_recursive_components'] for r in catalog['modes'][mode]['conditional_stack_regions'] if r['address'] == hex(roots['worker'])),
            'positive_recursive_components_after_failure_cut': [],
            'positive_recursive_component_absence_scope': 'Reachable modeled direct/provider graph only; caller_envelope rejects any positive-weight SCC.',
        }
    for path, expected in inputs.items():
        if sha(path) != expected:
            raise ValueError("input changed during boundary analysis: " + path)
    result = {'format': 'parliament-stack-failure-boundaries-v1',
              'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'inputs': inputs, 'inputs_unchanged': True, 'boundary_source_evidence': sources,
              'modes': modes, 'no_rebuild_or_worker_execution': True,
              'all_inputs_panic_free_proved': False, 'complete_8_mib_stack_sufficiency': False,
              'complete_workspace_certificate': False, 'profile_qualified': False,
              'scope': 'Modeled caller-frame envelopes up to explicit opaque frontiers. Failure handlers, native/hidden callees, unwind, traps and caller runtime remain unbounded.'}
    (output / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    """Expose non-destructive source/graph analysis with explicit output ownership."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new output directory, must not exist')
    parser.add_argument('--rustdoc-src', type=Path, default=Path.home() / '.rustup/toolchains/1.93.1-aarch64-apple-darwin/share/doc/rust/html/src', help='installed Rust 1.93.1 rustdoc source HTML root')
    args = parser.parse_args()
    report = run(ROOT, args.output, args.rustdoc_src)
    print(json.dumps({mode: {'indirects': data['indirect_classification_counts'],
                            'caller_frames': {root: item['modeled_caller_frame_envelope_bytes'] for root, item in data['conditional_boundary_roots'].items()}}
                      for mode, data in report['modes'].items()}, indent=2))


if __name__ == '__main__':
    main()
