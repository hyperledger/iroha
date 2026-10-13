"""Adversarial controls for the separate frozen-stack failure-boundary analysis."""

import copy
import html
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / 'parliament_ballot_stack_frontiers.py'
SPEC = importlib.util.spec_from_file_location('parliament_stack_frontiers', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ANALYZER = MODULE.load_analyzer(MODULE.ROOT, {})


def function(address, name, frame=128, calls=(), gaps=()):
    """Build independent small call graphs with explicit local-frame weights."""
    return {'address': hex(address), 'name': name, 'local_frame_plus_red_zone_bytes': frame,
            'calls': list(calls), 'gaps': list(gaps), 'frame_errors': []}


def call(address, target, depth):
    """Represent one compiled caller contribution, independent of callee size."""
    return {'address': hex(address), 'target': hex(target), 'caller_depth_bytes': depth, 'kind': 'call'}


def gap(address, kind='native_edge', detail='_memcpy', depth=0):
    """Represent an unknown continuation whose cost must never become zero."""
    return {'address': hex(address), 'kind': kind, 'detail': detail, 'caller_depth_bytes': depth}


def failures():
    """Supply all three explicit failure symbols; unrelated panic names are absent."""
    return {0x8000 + i * 0x100: function(0x8000 + i * 0x100, name + '::h0123456789abcdef')
            for i, name in enumerate(MODULE.BOUNDARIES)}


def test_symbol_classification_is_exact_not_a_panic_name_substring():
    assert MODULE.base_symbol('core::panicking::panic_fmt::h0123456789abcdef') == 'core::panicking::panic_fmt'
    assert MODULE.base_symbol('app::panic_fmt::h1234') == 'app::panic_fmt::h1234'
    assert MODULE.base_symbol('core::panicking::panic_fmt_extra::h0123456789abcdef') not in MODULE.BOUNDARIES


def rustdoc(code):
    """Encode a tiny independent highlighted-source document with numbered anchors."""
    return '<pre class="rust"><code>' + ''.join(
        f'<a href=#{i} id={i} data-nosnippet>{i}</a><span>{html.escape(line)}</span>\n'
        for i, line in enumerate(code.splitlines(), 1)) + '</code></pre>'


def test_source_extraction_preserves_literals_but_removes_only_html_markup():
    code = "// Literal <T> & 'quote'\npub fn fail() -> ! { panic!(); }\n"
    assert MODULE.rustdoc_source(rustdoc(code)) == code
    for invalid in [rustdoc(code) * 2, rustdoc(code).replace('id=2', 'id=3'),
                    rustdoc(code).replace('data-nosnippet>2', 'data-nosnippet>9'),
                    rustdoc(code).replace('</code></pre>', ''),
                    rustdoc(code).replace('</span>\n', '</span>\n\n')]:
        with pytest.raises(ValueError):
            MODULE.rustdoc_source(invalid)


def test_literal_failure_signatures_are_checked_and_archived(tmp_path):
    src, out = tmp_path / 'src', tmp_path / 'out'
    out.mkdir()
    sources = {}
    for _, (relative, signature, _) in MODULE.BOUNDARIES.items():
        sources.setdefault(relative, []).append(signature)
    for relative, signatures in sources.items():
        path = src / (relative + '.html')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rustdoc('\n'.join(signatures) + '\n'))
    inputs = {}
    result = MODULE.boundary_sources(src, out, inputs)
    assert len(result) == 3 and len(inputs) == 2
    assert all(item['no_normal_return'] and not item['no_unwind_or_native_work_proved'] for item in result.values())
    changed = src / 'core/panicking.rs.html'
    changed.write_text(changed.read_text().replace('-&gt; !', '-&gt; ()'))
    with pytest.raises(ValueError, match='signature'):
        MODULE.boundary_sources(src, out, {})


def test_failure_cut_keeps_explicit_frontier_and_other_continuations():
    fs = failures()
    fs[0x1000] = function(0x1000, 'entry', calls=[call(0x1004, 0x8000, 64), call(0x1008, 0x2000, 16)],
                          gaps=[gap(0x100c)])
    fs[0x2000] = function(0x2000, 'normal_result_cleanup')
    before = copy.deepcopy(fs)
    cut = MODULE.cut_failure_entries(fs, MODULE.BOUNDARIES)
    assert fs == before
    assert cut[0x1000]['calls'] == [call(0x1008, 0x2000, 16)]
    assert cut[0x1000]['gaps'][0] == gap(0x100c)
    boundary = cut[0x1000]['gaps'][1]
    assert (boundary['kind'], boundary['target'], boundary['caller_depth_bytes']) == ('failure_boundary', '0x8000', 64)
    assert cut[0x8000] == fs[0x8000]
    with pytest.raises(ValueError, match='failure entry'):
        MODULE.cut_failure_entries({k: v for k, v in fs.items() if k != 0x8000}, MODULE.BOUNDARIES)


def test_longest_fanin_path_and_frontier_caller_depth_have_independent_expected_values():
    fs = {0x1000: function(0x1000, 'entry', 160, [call(0x1004, 0x2000, 32), call(0x1008, 0x3000, 16)]),
          0x2000: function(0x2000, 'middle', 224, [call(0x2004, 0x3000, 96)]),
          0x3000: function(0x3000, 'leaf', 208, gaps=[gap(0x3004, depth=80)])}
    report = MODULE.caller_envelope(ANALYZER, fs, 0x1000)
    # entry32 + middle96 gives leaf entry128, exceeding direct entry16.
    assert report['per_function_maximum_entry_sp_bytes']['0x3000'] == 128
    assert report['modeled_caller_frame_envelope_bytes'] == 128 + 208
    assert report['frontiers'][0]['maximum_modeled_caller_sp_bytes'] == 128 + 80
    assert report['frontiers'][0]['callee_stack_bytes'] is None
    assert report['complete_stack_bound_bytes'] is None
    assert report['opaque_endpoint_obligations'] == [
        {'kind': 'native_edge', 'endpoint': '_memcpy', 'sites': 1,
         'maximum_modeled_caller_sp_bytes': 208, 'callee_stack_bytes': None}]


def test_zero_depth_tail_cycle_does_not_accumulate_but_positive_cycle_refuses():
    fs = {0x1000: function(0x1000, 'entry', 128, [call(0x1004, 0x2000, 0)]),
          0x2000: function(0x2000, 'tail', 128, [call(0x2004, 0x1000, 0), call(0x2008, 0x3000, 32)]),
          0x3000: function(0x3000, 'leaf', 160)}
    assert MODULE.caller_envelope(ANALYZER, fs, 0x1000)['modeled_caller_frame_envelope_bytes'] == 192
    fs[0x2000]['calls'][0]['caller_depth_bytes'] = 16
    with pytest.raises(ValueError, match='positive recursive'):
        MODULE.caller_envelope(ANALYZER, fs, 0x1000)


@pytest.mark.parametrize('mutation', ['frame_error', 'missing_target', 'negative_call', 'negative_frontier'])
def test_incomplete_or_inconsistent_graph_never_receives_a_caller_bound(mutation):
    fs = {0x1000: function(0x1000, 'entry', 128, [call(0x1004, 0x2000, 0)], [gap(0x1008)]),
          0x2000: function(0x2000, 'leaf')}
    if mutation == 'frame_error':
        fs[0x2000]['frame_errors'] = [{'kind': 'unproved_sp'}]
    elif mutation == 'missing_target':
        del fs[0x2000]
    elif mutation == 'negative_call':
        fs[0x1000]['calls'][0]['caller_depth_bytes'] = -16
    else:
        fs[0x1000]['gaps'][0]['caller_depth_bytes'] = -16
    with pytest.raises(ValueError):
        MODULE.caller_envelope(ANALYZER, fs, 0x1000)


def test_unknown_native_indirect_and_trap_frontiers_are_retained():
    fs = {0x1000: function(0x1000, 'entry', gaps=[gap(0x1004, detail='_new_runtime'),
                                              gap(0x1008, 'indirect_call', 'x8'),
                                              gap(0x100c, 'exceptional_terminal', 'brk #1')])}
    result = MODULE.caller_envelope(ANALYZER, fs, 0x1000)
    assert len(result['frontiers']) == 3
    assert result['native_category_counts'] == {'unclassified_native': 1}
    assert result['complete_stack_bound_bytes'] is None


def test_three_indirect_classes_are_distinguished_without_discarding_io_failure():
    fs = failures()
    fs[0x1000] = function(0x1000, 'worker', calls=[call(0x1004, 0x2000, 16), call(0x1008, 0x3000, 16)])
    fs[0x2000] = function(0x2000, 'reservation', calls=[call(0x2004, 0x8000, 32)], gaps=[gap(0x2008, 'indirect_call', 'x1')])
    fs[0x3000] = function(0x3000, 'host_io_drop', gaps=[gap(0x3004, 'indirect_call', 'x2')])
    fs[0x8000]['calls'] = [call(0x8004, 0x9000, 64)]
    fs[0x9000] = function(0x9000, 'panic_hook', gaps=[gap(0x9004, 'indirect_call', 'x3')])
    cut = MODULE.cut_failure_entries(fs, MODULE.BOUNDARIES)
    result = {r['function']: r for r in MODULE.classify_indirects(fs, cut, 0x1000, 0x2000)}
    assert result['reservation']['category'] == 'remains_inside_conditional_verifier_graph'
    assert result['host_io_drop']['category'] == 'worker_only_frontier'
    assert result['panic_hook']['category'] == 'only_behind_explicit_failure_entry_in_resolved_graph'
    assert result['panic_hook']['first_failure_entry_on_this_path']['target'] == '0x8000'
    assert not result['panic_hook']['path_input_feasibility_proved']


def test_provider_edges_are_copied_and_unknown_targets_fail():
    fs = [function(0x1000, 'owner', gaps=[gap(0x1004, 'indirect_call', 'x8', 32)]), function(0x2000, 'provider')]
    report = {'functions': fs}
    site = {'function': 'owner', 'address': '0x1004', 'caller_depth_bytes': 32,
            'conditional_targets': [{'address': '0x2000', 'symbol': 'provider'}]}
    before = copy.deepcopy(report)
    expanded = MODULE.provider_graph(report, [site])
    assert report == before
    assert not expanded[0x1000]['gaps']
    assert expanded[0x1000]['calls'][0]['target'] == '0x2000'
    site['conditional_targets'][0]['symbol'] = 'other_provider'
    with pytest.raises(ValueError, match='target differs'):
        MODULE.provider_graph(report, [site])


def test_missing_path_refuses_and_existing_successful_output_is_untouched(tmp_path):
    fs = {0x1000: function(0x1000, 'entry'), 0x2000: function(0x2000, 'unreachable')}
    with pytest.raises(ValueError, match='not reachable'):
        MODULE.shortest_path(fs, 0x1000, 0x2000)
    result = tmp_path / 'report.json'
    result.write_text('prior evidence\n')
    with pytest.raises(FileExistsError):
        MODULE.run(MODULE.ROOT, tmp_path, tmp_path)
    assert result.read_text() == 'prior evidence\n'
