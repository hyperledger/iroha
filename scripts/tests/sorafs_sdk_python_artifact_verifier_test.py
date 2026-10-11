"""Real original-file custody with synthetic transcripts; never SDK qualification."""
from __future__ import annotations

import builtins
import copy
from dataclasses import FrozenInstanceError, replace
import io
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import sorafs_sdk_python_artifact_verifier as adapter
from sorafs_python_archive import execution_archive
from sorafs_python_consumer_artifact import canonical_json
from sorafs_python_dependency_install_test import harness
import sorafs_sdk_artifact_index as indices
import sorafs_python_index_fixture as synthetic


@pytest.fixture(scope="module")
def template(harness, tmp_path_factory):
    return synthetic.fixture(harness, tmp_path_factory.mktemp("synthetic-python-adapter-inputs"))


def indexed(tmp_path, template, *, mutate=None):
    members, manifest, originals = copy.deepcopy(template)
    if mutate: mutate(members, manifest, originals)
    manifest["retained"] = {name: adapter.identity(raw) for name, raw in sorted(members.items())}
    members["manifest.json"] = canonical_json(manifest)
    originals["python-execution.zip"] = execution_archive(members)
    python_inputs = sorted(set(originals) - {"iroha_python.whl", "python-execution.zip"})
    rows = []
    for name, suffix in zip(indices.CONSUMERS, indices.SUFFIXES, strict=True):
        if name == "python":
            artifact, execution, inputs = "iroha_python.whl", "python-execution.zip", python_inputs
        else:
            artifact = name + suffix; execution = artifact if name == "java_source_kotlin" else name + "-execution.zip"
            inputs = [name + "-input.bin"]
            if name == "java_source_kotlin": inputs.append("kotlin_jvm.zip")
            for path in (artifact, execution, inputs[0]): originals.setdefault(path, ("inert other consumer " + path).encode())
        rows.append({"consumer": name, "version": "0.0.1", "artifact": artifact, "execution": execution, "inputs": sorted(inputs)})
    value = {"schema": indices.SCHEMA, "candidate": {"source_commit": synthetic.COMMIT, "workspace_source_manifest_sha256": synthetic.SOURCE_DIGEST},
             "files": {name: adapter.identity(raw) for name, raw in sorted(originals.items())}, "consumers": rows}
    index = indices.parse_index(canonical_json(value), expected_source_commit=synthetic.COMMIT, expected_source_manifest_sha256=synthetic.SOURCE_DIGEST)
    for name, raw in originals.items(): (tmp_path / name).write_bytes(raw)
    return index


def run(index, opened, template, **override):
    originals = template[2]
    options = dict(trusted_source_root=ROOT, expected_runtime_manifest_sha256=adapter.identity(originals["runtime.json"])["sha256"],
                   expected_dependency_manifest_sha256=adapter.identity(originals["dependencies.json"])["sha256"])
    options.update(override)
    return adapter.verify_python_consumer(index, opened, **options)


@pytest.fixture
def candidate(monkeypatch):
    # Only candidate Git identity is synthetic. All byte, archive, input, source,
    # installed content, closed report and held-file verifiers remain actual.
    monkeypatch.setattr(adapter.native, "source_state", lambda root: (synthetic.COMMIT, True))
    monkeypatch.setattr(adapter.native, "workspace_source_manifest_sha256", lambda root: synthetic.SOURCE_DIGEST)


def test_exact_twenty_original_roles_and_77_case_content_join(tmp_path, template, candidate, monkeypatch):
    index = indexed(tmp_path, template)
    original_open, original_io_open = builtins.open, io.open
    def guarded(original):
        def call(path, *args, **kwargs):
            if isinstance(path, (str, Path)):
                assert not str(path).startswith(("/observed/", "/selected/")), "historical input path was reopened"
            return original(path, *args, **kwargs)
        return call
    with indices.OpenedIndexFiles(tmp_path, index) as opened:
        with monkeypatch.context() as scope:
            scope.setattr(builtins, "open", guarded(original_open)); scope.setattr(io, "open", guarded(original_io_open))
            observed = run(index, opened, template)
    assert len(observed.cases) == 77 and all(phases == ("setup", "call", "teardown") for _, phases in observed.cases)
    assert not hasattr(observed, "passed") and not hasattr(observed, "qualified")
    with pytest.raises(FrozenInstanceError): observed.source_commit = "c" * 40


@pytest.mark.parametrize("mutation", ("candidate", "scope", "retained_extra", "source", "tool", "package", "environment_extra", "interpreter", "config", "links", "metadata", "command", "native_output", "dependency_rows", "bool_size", "int_generated", "requirements", "input", "report", "native_manifest", "runtime_bundle", "missing_role", "ambiguous_role", "seal_object", "seal_bound"))
def test_resealed_content_cannot_replace_an_original_join(tmp_path, template, candidate, mutation):
    def change(members, manifest, originals):
        if mutation == "candidate": manifest["source_commit"] = "c" * 40
        elif mutation == "scope": manifest["scope"] = "digest-only"
        elif mutation == "retained_extra": members["unowned.bin"] = b"unowned"
        elif mutation in ("source", "tool", "package"):
            prefix = {"source": "snapshot/", "tool": "tools/", "package": "package-source/"}[mutation]
            members[next(name for name in members if name.startswith(prefix))] += b"# substituted\n"
        elif mutation == "environment_extra": members["environment/unowned.bin"] = b"extra"
        elif mutation == "interpreter": members["environment/bin/python"] += b"replacement"
        elif mutation == "config": members["environment/pyvenv.cfg"] = members["environment/pyvenv.cfg"].replace(b"--copies", b"--symlinks")
        elif mutation == "links": manifest["environment_links"] = {"lib64": "elsewhere"}
        elif mutation == "metadata": members[next(n for n in members if n.startswith("installed-metadata/"))] += b"substitute"
        elif mutation == "command": manifest["commands"][4]["argv"].append("--index-url=foreign")
        elif mutation == "native_output":
            members["logs/native-before.stdout"] = b"unowned"; manifest["commands"][3]["stdout"] = adapter.identity(b"unowned")
        elif mutation == "dependency_rows": manifest["dependency_files"].pop()
        elif mutation == "bool_size": next(row for row in manifest["dependency_files"] if row["size"] == 0)["size"] = False
        elif mutation == "int_generated": manifest["dependency_files"][0]["generated"] = int(manifest["dependency_files"][0]["generated"])
        elif mutation == "requirements": members["inputs/requirements.txt"] += b"foreign\n"
        elif mutation == "input":
            value = json.loads(members["inputs/child.json"]); value["source_files"].pop(); members["inputs/child.json"] = canonical_json(value)
        elif mutation == "report": members["child-report.json"] += b"\n"
        elif mutation == "native_manifest":
            value = json.loads(originals["native.json"]); value["artifact_sha256"] = "d" * 64
            raw = canonical_json(value); originals["native.json"] = members["inputs/native-abi29.json"] = raw; manifest["native_manifest"] = adapter.identity(raw)
        elif mutation == "runtime_bundle":
            originals["runtime.bundle"] += b"extra"; manifest["runtime_bundle"] = adapter.identity(originals["runtime.bundle"])
        elif mutation == "missing_role": originals.pop("idna.whl")
        elif mutation == "ambiguous_role": originals["idna.whl"] = originals["native.json"]
        elif mutation == "seal_object": manifest["wheels"][0]["seal"] = {"unowned": True}
        else: manifest["wheels"][0]["seal"] = "x" * 513
    index = indexed(tmp_path, template, mutate=change)
    with indices.OpenedIndexFiles(tmp_path, index) as opened:
        with pytest.raises((ValueError, RuntimeError)): run(index, opened, template)


@pytest.mark.parametrize("field", ("expected_runtime_manifest_sha256", "expected_dependency_manifest_sha256"))
def test_execution_cannot_select_its_own_approved_pin(tmp_path, template, candidate, field):
    index = indexed(tmp_path, template)
    with indices.OpenedIndexFiles(tmp_path, index) as opened:
        with pytest.raises(ValueError, match="independent manifest pin"):
            run(index, opened, template, **{field: "d" * 64})


def test_actual_dirty_checkout_cannot_claim_synthetic_candidate(tmp_path, template):
    index = indexed(tmp_path, template)
    with indices.OpenedIndexFiles(tmp_path, index) as opened:
        with pytest.raises(ValueError, match="clean selected candidate"):
            run(index, opened, template)


def test_original_index_owner_cannot_be_replaced(tmp_path, template, candidate):
    index = indexed(tmp_path, template)
    with indices.OpenedIndexFiles(tmp_path, index) as opened:
        with pytest.raises(ValueError, match="same original indexed"):
            run(replace(index), opened, template)


def test_late_original_path_substitution_prevents_observation_return(tmp_path, template, candidate, monkeypatch):
    index = indexed(tmp_path, template)
    original = adapter.verify_report_origins
    def substitute(*args, **kwargs):
        result = original(*args, **kwargs)
        path = tmp_path / "idna.whl"; body = path.read_bytes(); path.unlink(); path.write_bytes(body)
        return result
    monkeypatch.setattr(adapter, "verify_report_origins", substitute)
    with pytest.raises(ValueError, match="original indexed file changed|physical owner"):
        with indices.OpenedIndexFiles(tmp_path, index) as opened:
            run(index, opened, template)


def test_late_new_package_source_is_included_in_final_census(tmp_path, template, candidate, monkeypatch):
    index = indexed(tmp_path, template)
    # An inert source fixture lives inside target; no repository checkout or
    # canonical source is modified. Candidate selection remains synthetic.
    source = tmp_path / "source-fixture"; source.mkdir()
    for name, raw in template[0].items():
        if name.startswith("tools/"): relative = "scripts/" + name.removeprefix("tools/")
        elif name.startswith("snapshot/"): relative = name.removeprefix("snapshot/")
        elif name.startswith("package-source/"): relative = name.removeprefix("package-source/")
        else: continue
        path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    original = adapter.verify_report_origins
    def add_source(*args, **kwargs):
        result = original(*args, **kwargs)
        (source / "python/iroha_python/src/iroha_python/test_added_after_census.py").write_bytes(b"# new build input\n")
        return result
    monkeypatch.setattr(adapter, "verify_report_origins", add_source)
    with indices.OpenedIndexFiles(tmp_path, index) as opened:
        with pytest.raises(ValueError, match="candidate source members"):
            run(index, opened, template, trusted_source_root=source)
