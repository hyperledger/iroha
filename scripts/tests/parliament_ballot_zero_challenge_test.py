"""Exact fallback membership, source binding and independent finite-tree controls."""

from itertools import product
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_parliament_ballot_zero_challenge as check


@pytest.mark.parametrize("tau,grind,limit,leaves,count", [(33, 8, 229, 6400, 11), (22, 6, 225, 61440, 12)])
def test_actual_rows_zero_challenge_and_exact_threshold(tau, grind, limit, leaves, count):
    shape = check.geometry(256, tau, grind, limit)
    assert shape["leaves"] == leaves and sum(shape["depths"]) == 256 - grind
    hidden = check.decode_challenge(shape, bytes(32))
    assert hidden == [0] * tau
    heap, ancestor = check.heap_boundary(shape, hidden), check.ancestor_boundary(shape, hidden)
    assert heap == ancestor
    assert len(heap["revealed_nodes"]) == count
    assert heap["marked_nodes"] - 2 * tau + 1 == count
    assert heap["selected_leaves"] == list(range(leaves - 1, leaves - 1 + tau))
    assert check.admissible(shape, bytes(32))
    assert check.admissible(check.geometry(256, tau, grind, count), bytes(32))
    assert not check.admissible(check.geometry(256, tau, grind, count - 1), bytes(32))


@pytest.mark.parametrize("tau,grind,limit", [(33, 8, 229), (22, 6, 225)])
def test_every_grinding_bit_is_refused_and_last_data_bit_is_decoded(tau, grind, limit):
    shape = check.geometry(256, tau, grind, limit)
    for position in range(shape["n_delta"], 256):
        challenge = (1 << position).to_bytes(32, "little")
        with pytest.raises(ValueError, match="grinding"):
            check.decode_challenge(shape, challenge)
        with pytest.raises(ValueError, match="grinding"):
            check.admissible(shape, challenge)
    decoded = check.decode_challenge(shape, (1 << (shape["n_delta"] - 1)).to_bytes(32, "little"))
    assert decoded[:-1] == [0] * (tau - 1)
    assert decoded[-1] == 1 << (shape["depths"][-1] - 1)
    for bad in (b"", bytes(31), bytes(33), "0" * 32):
        with pytest.raises(ValueError, match="length"):
            check.decode_challenge(shape, bad)


@pytest.mark.parametrize("tau,grind", [(3, 3), (2, 4), (3, 2)])
def test_exhaustive_toy_patterns_cross_check_different_tree_algorithms(tau, grind):
    shape = check.geometry(8, tau, grind, 128)
    actual_patterns = set()
    for value in range(256):
        if value >= 1 << shape["n_delta"]:
            with pytest.raises(ValueError, match="grinding"):
                check.decode_challenge(shape, bytes([value]))
            continue
        hidden = check.decode_challenge(shape, bytes([value]))
        actual_patterns.add(tuple(hidden))
        direct, independent = check.heap_boundary(shape, hidden), check.ancestor_boundary(shape, hidden)
        assert direct == independent
        assert len(direct["revealed_nodes"]) == direct["marked_nodes"] - 2 * tau + 1
    assert actual_patterns == set(product(*(range(size) for size in shape["vector_sizes"])))
    assert len(actual_patterns) == 1 << shape["n_delta"]


def test_malformed_indices_and_geometry_fail_before_heap_construction():
    shape = check.geometry(8, 3, 3, 128)
    assert check.decode_challenge(shape, bytes([0b00011001])) == [1, 2, 1]
    for hidden in ([], [0, 0], [0, 0, 0, 0], [-1, 0, 0], [4, 0, 0], [0, 0, 2], [False, 0, 0]):
        for operation in (check.check_indices, check.heap_boundary, check.ancestor_boundary):
            with pytest.raises(ValueError, match="index"):
                operation(shape, hidden)
    for arguments in ((True, 3, 3, 128), (7, 3, 1, 128), (264, 3, 1, 128),
                      (8, 1, 3, 128), (8, 3, 8, 128), (8, 3, 7, 128),
                      (8, 3, 3, 0), (8, 3, 3, 65537), (256, 2, 0, 128),
                      (256, 16, 16, 128)):
        with pytest.raises(ValueError):
            check.geometry(*arguments)


def test_certificate_binds_both_roles_exact_counts_references_and_work():
    report = check.certificate()
    assert report["fallback_admissible_both_rows_and_roles"] and not report["source_changes"]
    assert report["source_sha256"] == check.PINNED
    for row in report["rows"].values():
        assert set(row["role_results"]) == {"registration", "vote"}
        assert all(role["admissible"] and role["same_row_geometry"] for role in row["role_results"].values())
        work = row["source_admissibility_work"]
        assert work["challenge_bit_reads"] == 256
        assert work["mark_initializations"] == row["nodes"] == 2 * row["leaves"] - 1
        assert work["parent_iterations"] == row["leaves"] - 1
        assert work["selected_leaf_marks"] == row["tau"]
        assert row["source_shape_guards"]["leaves_plus_tau"] <= 1 << 31
    for reference in report["source_references"]:
        source = (check.ROOT / reference["path"]).read_bytes().splitlines(keepends=True)
        excerpt = b"".join(source[reference["start_line"] - 1:reference["end_line"]])
        assert check.hashlib.sha256(excerpt).hexdigest() == reference["excerpt_sha256"]
    for claim in ("counter_preimage_or_valid_proof_claim", "uniform_H5_lemma_proved", "simulator_distribution_proved",
                  "complete_simulator_resource_bound", "independent_cryptographic_review", "profile_qualified"):
        assert report[claim] is False


def test_source_semantic_drift_is_refused_without_repinning(tmp_path):
    for name in check.PINNED:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((check.ROOT / name).read_bytes())
    assert check.verify_sources(tmp_path) == check.PINNED
    target = tmp_path / "crates/iroha_zkp_vole/src/bavc.rs"
    target.write_text(target.read_text().replace("if nodes > shape.t_open", "if nodes >= shape.t_open"))
    with pytest.raises(ValueError, match="source changed"):
        check.certificate(tmp_path)


def test_boundary_disagreement_cannot_emit_certificate():
    with patch.object(check, "ancestor_boundary", return_value={}):
        with pytest.raises(ValueError, match="cross-check failed"):
            check.certificate()


def test_loaded_leaf_listing_must_match_even_when_root_snapshot_is_pinned(tmp_path):
    imported = tmp_path / "changed_ledger.py"
    imported.write_text("def leaf_vectors(sizes): return []\n")
    with patch.object(check.ledger, "__file__", str(imported)):
        with pytest.raises(ValueError, match="loaded independent leaf-listing"):
            check.certificate(check.ROOT)


def test_cli_help_new_output_and_refusal_do_not_overwrite(tmp_path, capsys):
    with patch.object(sys, "argv", ["zero-check", "--help"]):
        with pytest.raises(SystemExit) as result:
            check.main()
        assert result.value.code == 0 and "--output" in capsys.readouterr().out
    output = tmp_path / "new"
    with patch.object(sys, "argv", ["zero-check", "--output", str(output)]):
        assert check.main() == 0
        report = json.loads(capsys.readouterr().out)
        assert report == json.loads((output / "report.json").read_text())
        before = check.digest(output / "report.json")
        assert check.main() == 1
        assert json.loads(capsys.readouterr().out)["profile_qualified"] is False
        assert check.digest(output / "report.json") == before
    with patch.object(sys, "argv", ["zero-check", "--root", str(tmp_path / "missing")]):
        assert check.main() == 1
        assert "failure" in json.loads(capsys.readouterr().out)
