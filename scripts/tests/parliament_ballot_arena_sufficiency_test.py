"""Conditional arena coverage claims stay scoped and fail closed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch
import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import check_parliament_ballot_arena_sufficiency as check


def test_frontend_spatial_envelope_covers_every_buddy_order():
    proof = check.frontend_spatial_proof()
    assert proof["conditional_spatial_success"]
    assert proof["maximum_post_request_block_bytes"] == 3670016
    assert len(proof["all_noninput_buddy_orders"]) == 13
    assert all(x["guaranteed_free_block"] for x in proof["all_noninput_buddy_orders"])
    assert not proof["source_to_compiled_allocation_correspondence_proved"]
    with patch.object(check.frontend, "frontend_bounds", return_value={
        "maximum_live_objects_including_input": 1000, "maximum_copied_input_rounded_block": 524288,
        "maximum_other_rounded_block": 262144, "maximum_layout_alignment": 8}):
        with pytest.raises(ValueError):
            check.frontend_spatial_proof()


def test_full_schedules_peak_and_restore_all_rows_modes_roles():
    for row in check.backend.ROWS:
        for accel in (False, True):
            for role in ("registration", "vote"):
                result = check.trace_result(check.full_trace(row, role, seats=1000, accel=accel))
                assert result["live_exit_block_bytes"] == 0
                assert result["peak_block_bytes"] < 8 * 1024 * 1024
                assert not result["profile_qualified"]
                assert result["restoring_groups_checked"] > 0


def test_class_domain_and_registration_input_order_are_exhaustive():
    classes = list(check.frontend.registration_retained_classes())
    assert len(classes) == 32768
    assert len({tuple(item["ranges"]) for item in classes}) == len(classes)
    for row in check.backend.ROWS:
        low = check.frontend.canonical_record_bytes(row, "registration", registration_lengths=(0,) * 7)
        high = check.frontend.canonical_record_bytes(row, "registration")
        assert check.block_bytes(low, 1) == check.block_bytes(high, 1)


def test_accumulation_keeps_peak_witnesses_and_stream_digest():
    report = check.trace_result(check.full_trace("candidate", "vote", seats=3))
    total = {"classes_checked": 0}
    digest = hashlib.sha256()
    check._accumulate(total, {"seats": 3}, report, digest)
    assert total["classes_checked"] == 1
    assert total["peak_block_bytes_witness"] == {"seats": 3}
    assert digest.hexdigest() != hashlib.sha256().hexdigest()


def test_source_guard_rejects_drift(tmp_path):
    assert check.source_inventory()["arena"][check.ARENA_PATH] == check.ARENA_SHA256
    path = tmp_path / check.ARENA_PATH
    path.parent.mkdir(parents=True)
    path.write_text("changed")
    with pytest.raises(ValueError, match="arena source changed"):
        check.source_inventory(tmp_path)


def test_main_keeps_qualification_closed_and_reports_failure(tmp_path, capsys):
    output = tmp_path / "result.json"
    with patch.object(check, "run_all", return_value={"profile_qualified": False}):
        with patch.object(sys, "argv", ["check", "--output", str(output), "--require-qualified"]):
            assert check.main() == 2
        assert not json.loads(output.read_text())["profile_qualified"]
    with patch.object(check, "run_all", side_effect=ValueError("no proof")):
        with patch.object(sys, "argv", ["check"]):
            assert check.main() == 1
    assert "no proof" in capsys.readouterr().out


def test_failure_atomically_replaces_previous_pass(tmp_path):
    output = tmp_path / "result.json"
    output.write_text('{"conditional_source_model_sufficiency": true}')
    with patch.object(check, "run_all", side_effect=ValueError("source drift")):
        with patch.object(sys, "argv", ["check", "--output", str(output)]):
            assert check.main() == 1
    assert json.loads(output.read_text())["conditional_source_model_sufficiency"] is False
    assert list(tmp_path.iterdir()) == [output]


def test_retained_classes_do_not_imply_monotone_frontend_growth():
    upper = (1024, 128, 64, 128, 64, 128, 0)
    interior = (564, 87, 34, 86, 16, 83, 0)
    assert [check.block_bytes(n, 1) if n else 0 for n in upper] == [check.block_bytes(n, 1) if n else 0 for n in interior]
    schedules = []
    for lengths in (upper, interior):
        front = check.frontend.frontend_trace("candidate", "registration", registration_lengths=lengths)
        schedules.append([event["size"] for event in front["prefix"]
                          if event["op"] == "alloc" and ".mu_frame." in event["id"]])
    assert len(schedules[1]) > len(schedules[0])
    assert max(schedules[1]) > max(schedules[0])
    assert check.frontend_spatial_proof()["conditional_spatial_success"]
