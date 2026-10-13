"""Pure identity/publication controls; no compiled bundle or hardware evidence.

Mock subprocess records and public bytes exercise producer policy only. Every
source/tool mutation is confined to a disposable test directory, never the repo.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def producer():
    spec = importlib.util.spec_from_file_location(
        "fastpq_bundle_policy", ROOT / "scripts/build_fastpq_metal_bundle.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def captured_repo(producer, tmp_path):
    root = tmp_path / "repo"
    for path in producer.SOURCE_INPUTS:
        copied = root / path
        copied.parent.mkdir(parents=True, exist_ok=True)
        copied.write_bytes((ROOT / path).read_bytes())
    return root


def mock_children(producer, monkeypatch, tmp_path, *, fault=None):
    """Never execute these public stand-ins or label their bytes authentic."""
    tools = {}
    for name in ("metal", "metallib"):
        path = tmp_path / name
        path.write_bytes(b"public mocked process identity " + name.encode())
        tools[name] = path
    calls = []

    def run(arguments, commands):
        calls.append(arguments)
        stdout, stderr, status = "", "", 0
        if arguments[1:] == ["-v"]:
            stdout = "public mocked version"
        elif arguments[1:] == ["-help"]:
            stdout = "unsupported" if fault == "flag" else "-fno-fast-math"
        elif "-c" in arguments:
            if fault == "compile":
                status, stderr = 9, "terminal compiler refusal"
            elif fault != "output":
                Path(arguments[-1]).write_bytes(b"public mocked AIR")
        else:
            if fault == "link":
                status, stderr = 7, "terminal linker refusal"
            elif fault != "link_output":
                Path(arguments[-1]).write_bytes(b"public mocked library, never admitted")
        commands.append({"arguments": arguments, "returncode": status,
                         "stdout": stdout, "stderr": stderr})
        return subprocess.CompletedProcess(arguments, status, stdout, stderr)

    monkeypatch.setattr(producer, "find_tool", lambda name, commands: tools[name])
    monkeypatch.setattr(producer, "run", run)
    return tools, calls


def test_exact_ordered_source_and_full_inventory_match_private_pins(producer):
    inputs, digest = producer.snapshot(ROOT)
    assert len(inputs) == 8
    assert len(producer.TRANSLATION_UNITS) == 6
    assert len(producer.kernel_inventory(inputs)) == 16
    owner = (ROOT / "crates/fastpq_prover/src/metal_artifact.rs").read_text()
    raw = owner.split("const SOURCE_SHA256: [u8; 32] = [", 1)[1].split("];", 1)[0]
    assert bytes(int(word, 16) for word in re.findall(r"0x[0-9a-f]{2}", raw)).hex() == digest
    assert tuple(re.findall(r'\(\s*"(crates/[^\"]+)",\s*include_bytes!', owner)) == producer.SOURCE_INPUTS
    names = owner.split("pub const ENTRY_POINTS:", 1)[1].split("];", 1)[0]
    assert tuple(re.findall(r'"([a-z0-9_]+)"', names)) == producer.ENTRY_POINTS


def test_source_loader_and_ordinary_producer_are_retired_before_device_access():
    build = (ROOT / "crates/fastpq_prover/build.rs").read_text()
    loader = (ROOT / "crates/fastpq_prover/src/metal.rs").read_text()
    discovery = (ROOT / "crates/fastpq_prover/src/backend.rs").read_text()
    for retired in ("new_library_with_source", "new_library_with_file",
                    "FASTPQ_METAL_LIB", "compile_embedded_metal_library"):
        assert retired not in loader
    for retired in ("xcrun", "metallib", "FASTPQ_METAL_LIB", "compile_metal_shaders"):
        assert retired not in build
    select = loader.split("fn select_metal_device()", 1)[1].split("\nfn ", 1)[0]
    assert select.index("admitted_bundle") < select.index("Device::")
    load = loader.split("fn load_metal_library(", 1)[1].split("\nfn ", 1)[0]
    assert load.index("admitted_bundle") < load.index("new_library_with_data")
    available = discovery.split("fn metal_available()", 1)[1].split("\nfn ", 1)[0]
    assert available.index("admitted_bundle") < available.index("metal_device_visible_via_api")


def test_natural_child_wait_has_no_timeout_signal_install_or_cleanup(producer):
    tree = ast.parse(Path(producer.__file__).read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    waits = [node for node in calls if isinstance(node.func, ast.Attribute)
             and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "subprocess" and node.func.attr == "run"]
    assert len(waits) == 1
    assert all(keyword.arg != "timeout" for keyword in waits[0].keywords)
    assert not any(isinstance(node.func, ast.Attribute) and node.func.attr in
                   ("kill", "terminate", "send_signal", "rmtree", "unlink") for node in calls)


def test_captured_sources_six_natural_children_and_unqualified_create_only_metadata(
    producer, captured_repo, monkeypatch, tmp_path
):
    _, calls = mock_children(producer, monkeypatch, tmp_path)
    output = tmp_path / "candidate"
    record = producer.generate(captured_repo, output, "aarch64-apple-darwin")
    assert [row["path"] for row in record["sources"]] == list(producer.SOURCE_INPUTS)
    compiles = [call for call in calls if "-c" in call]
    assert len(compiles) == 6
    assert [Path(call[-3]).name for call in compiles] == [Path(p).name for p in producer.TRANSLATION_UNITS]
    assert all("-fno-fast-math" in call for call in compiles)
    assert record["entry_points"] == list(producer.ENTRY_POINTS)
    assert record["admission_authority"] is record["signed_provenance"] is record["hardware_qualification"] is False
    assert record["library"]["sha256"] == hashlib.sha256((output / "fastpq.metallib").read_bytes()).hexdigest()
    assert json.loads((output / "generation.json").read_text()) == record
    before = (output / "fastpq.metallib").read_bytes()
    previous_calls = len(calls)
    with pytest.raises(producer.GenerationError, match="create-only output already exists"):
        producer.generate(captured_repo, output, "aarch64-apple-darwin")
    assert len(calls) == previous_calls
    assert (output / "fastpq.metallib").read_bytes() == before


@pytest.mark.parametrize("fault,diagnostic", [
    ("flag", "does not advertise"), ("compile", "terminal compiler refusal"),
    ("link", "terminal linker refusal"), ("output", "fresh non-empty regular file"),
    ("link_output", "Metal library was not produced"),
])
def test_terminal_refusal_keeps_generation_and_never_publishes(
    producer, captured_repo, monkeypatch, tmp_path, fault, diagnostic
):
    _, calls = mock_children(producer, monkeypatch, tmp_path, fault=fault)
    output = tmp_path / "candidate"
    with pytest.raises(producer.GenerationError, match=diagnostic):
        producer.generate(captured_repo, output, "aarch64-apple-darwin")
    assert not output.exists()
    generations = list(tmp_path.glob(".candidate.generation-*"))
    assert len(generations) == 1
    assert (generations[0] / "source" / producer.SOURCE_INPUTS[0]).is_file()
    assert calls


@pytest.mark.parametrize("owner", ["source", "captured_source", "compiler", "linker"])
def test_source_and_actual_tool_identity_drift_refuse_before_publication(
    producer, captured_repo, monkeypatch, tmp_path, owner
):
    tools, _ = mock_children(producer, monkeypatch, tmp_path)
    original = producer.run

    def drift(arguments, commands):
        result = original(arguments, commands)
        if arguments[0] == str(tools["metallib"]) and "-o" in arguments:
            if owner == "source":
                changed = captured_repo / producer.SOURCE_INPUTS[0]
            elif owner == "captured_source":
                changed = Path(arguments[-1]).parent / "source" / producer.SOURCE_INPUTS[0]
                changed.chmod(0o600)
            else:
                changed = tools["metal" if owner == "compiler" else "metallib"]
            changed.write_bytes(changed.read_bytes() + b"public drift")
        return result

    monkeypatch.setattr(producer, "run", drift)
    with pytest.raises(producer.GenerationError, match="changed during generation"):
        producer.generate(captured_repo, tmp_path / "candidate", "aarch64-apple-darwin")
    assert not (tmp_path / "candidate").exists()


def test_extra_kernel_refuses_before_any_tool_owner(producer, captured_repo, monkeypatch, tmp_path):
    source = captured_repo / producer.TRANSLATION_UNITS[0]
    source.write_bytes(source.read_bytes() + b"\nkernel void foreign_kernel() {}\n")
    monkeypatch.setattr(producer, "find_tool", lambda *_: pytest.fail("must refuse before tools"))
    with pytest.raises(producer.GenerationError, match="sixteen entry points"):
        producer.generate(captured_repo, tmp_path / "candidate", "aarch64-apple-darwin")
    assert not list(tmp_path.glob(".candidate.generation-*"))


def test_explicit_non_generation_avoids_even_missing_source_and_existing_output(producer, monkeypatch, tmp_path):
    output = tmp_path / "candidate"
    output.mkdir()
    marker = output / "original"
    marker.write_bytes(b"untouched")
    monkeypatch.setattr(producer, "snapshot", lambda *_: pytest.fail("no source access"))
    monkeypatch.setattr(producer, "run", lambda *_: pytest.fail("no child access"))
    assert producer.main(["--skip", "--repo-root", str(tmp_path / "absent"), "--output", str(output)]) == 0
    assert marker.read_bytes() == b"untouched"


def test_late_source_drift_retains_partial_output_without_generation_metadata(
    producer, captured_repo, monkeypatch, tmp_path
):
    mock_children(producer, monkeypatch, tmp_path)
    original_copy = producer.shutil.copyfileobj

    def copy_then_drift(source, destination):
        original_copy(source, destination)
        changed = captured_repo / producer.SOURCE_INPUTS[0]
        changed.write_bytes(changed.read_bytes() + b"late public source drift")

    monkeypatch.setattr(producer.shutil, "copyfileobj", copy_then_drift)
    output = tmp_path / "candidate"
    with pytest.raises(producer.GenerationError, match="changed before metadata publication"):
        producer.generate(captured_repo, output, "aarch64-apple-darwin")
    assert (output / "fastpq.metallib").is_file()
    assert not (output / "generation.json").exists()
    assert len(list(tmp_path.glob(".candidate.generation-*"))) == 1


def test_tool_version_probe_refuses_changed_file_identity(
    producer, captured_repo, monkeypatch, tmp_path
):
    tools, _ = mock_children(producer, monkeypatch, tmp_path)
    original_run = producer.run

    def changed_probe(arguments, commands):
        result = original_run(arguments, commands)
        if arguments[0] == str(tools["metal"]) and arguments[1:] == ["-v"]:
            tools["metal"].write_bytes(b"public probe-time drift")
        return result

    monkeypatch.setattr(producer, "run", changed_probe)
    with pytest.raises(producer.GenerationError, match="identity changed during its version probe"):
        producer.generate(captured_repo, tmp_path / "candidate", "aarch64-apple-darwin")
    assert not (tmp_path / "candidate").exists()
