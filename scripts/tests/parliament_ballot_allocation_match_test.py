"""Observed streams must match exact source layouts and lifetimes, not just peaks."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parliament_ballot_allocation_match as match


def example():
    grammar = [{"op": "alloc", "id": "a", "size": 128, "align": 8},
               {"op": "alloc", "id": "b", "size": 256, "align": 8},
               {"op": "free", "id": "a"}, {"op": "free", "id": "b"}]
    return grammar, [[1, 0, 128, 8], [1, 256, 256, 8], [2, 0, 128, 8], [2, 256, 256, 8]]


def test_exact_order_offsets_layouts_and_complete_consumption():
    grammar, records = example()
    result = match.compare(records, grammar)
    assert result["allocations_observed"] == 2
    assert result["peak_block_bytes"] == 384
    assert not result["complete_allocation_correspondence"]
    for wrong in (records[:-1], records + [[1, 0, 1, 1]], records[:2] + list(reversed(records[2:]))):
        with pytest.raises(ValueError):
            match.compare(wrong, grammar)
    for index, value in ((1, 64), (2, 127), (3, 16)):
        wrong = deepcopy(records)
        wrong[0][index] = value
        with pytest.raises(ValueError):
            match.compare(wrong, grammar)


def test_repetition_variable_counts_and_retained_state():
    body = [{"op": "alloc", "id": "p", "size": 960, "align": 16}, {"op": "free", "id": "p"}]
    repeat = {"op": "repeat_restoring", "id": "providers", "min": 1, "max": 3, "body": body}
    grammar = [{"op": "alloc", "id": "owner", "size": 128, "align": 1}, repeat,
               {"op": "free", "id": "owner"}]
    for count in (1, 2, 3):
        records = [[1, 0, 128, 1]] + [[1, 1024, 960, 16], [2, 1024, 960, 16]] * count + [[2, 0, 128, 1]]
        assert match.compare(records, grammar)["provider_repetitions"][0]["observed"] == count
    for count in (0, 4):
        records = [[1, 0, 128, 1]] + [[1, 1024, 960, 16], [2, 1024, 960, 16]] * count + [[2, 0, 128, 1]]
        with pytest.raises(ValueError):
            match.compare(records, grammar)
    bad = deepcopy(grammar)
    bad[1]["body"][1]["id"] = "owner"
    with pytest.raises(ValueError, match="repetition"):
        match.compare([], bad[1:2])


def test_realloc_allocate_before_release_is_observable():
    grammar, records = example()
    # Same peak and allocations, but releasing the old buffer first is rejected.
    reordered = [records[0], records[2], [1, 0, 256, 8], [2, 0, 256, 8]]
    with pytest.raises(ValueError):
        match.compare(reordered, grammar)


@pytest.mark.parametrize("record", [[True, 0, 1, 1], [1, -1, 1, 1], [3, 0, 1, 1],
                                    [1, 0, 0, 1], [1, 0, 1, 3], [1, match.HEAP_BYTES - 1, 2, 1]])
def test_record_validation(record):
    with pytest.raises(ValueError, match="invalid observed"):
        match.compare([record], [])


def test_unfinished_or_invalid_grammar_refuses():
    with pytest.raises(ValueError, match="retained"):
        match.compare([[1, 0, 128, 1]], [{"op": "alloc", "id": "live", "size": 128, "align": 1}])
    with pytest.raises(ValueError):
        match.compare([], [{"op": "free", "id": "missing"}])
    with pytest.raises(ValueError):
        match.compare([], [{"op": "repeat_restoring", "min": True, "max": 0, "body": []}])
    assert match.compare([], [])["events_matched"] == 0


def test_cli_reports_success_and_failure(tmp_path, capsys):
    grammar, records = example()
    gp, rp = tmp_path / "grammar.json", tmp_path / "records.json"
    gp.write_text(json.dumps(grammar)); rp.write_text(json.dumps(records))
    with patch.object(sys, "argv", ["match", "--records", str(rp), "--grammar", str(gp)]):
        assert match.main() == 0
        assert json.loads(capsys.readouterr().out)["finite_ordered_stream_match"]
        rp.write_text("[]")
        assert match.main() == 1
        assert not json.loads(capsys.readouterr().out)["finite_ordered_stream_match"]
