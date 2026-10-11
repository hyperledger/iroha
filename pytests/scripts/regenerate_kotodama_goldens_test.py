"""Unit tests for the fail-closed Kotodama golden regeneration pipeline."""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "regenerate_kotodama_goldens.py"
)
SPEC = importlib.util.spec_from_file_location("regenerate_kotodama_goldens", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
goldens = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = goldens
SPEC.loader.exec_module(goldens)


ABI_HASH = bytes(range(32))


def artifact(mode: int = 0, suffix: bytes = b"", abi_hash: bytes = ABI_HASH) -> bytes:
    """Build the minimum header shape accepted by the script validator."""

    return (
        b"IVM\0"
        + bytes([1, 1, mode, 0])
        + struct.pack("<Q", goldens.MAX_CYCLES)
        + b"\x01"
        + abi_hash
        + b"CNTR"
        + struct.pack("<I", 0)
        + suffix
    )


def test_read_map_accepts_aliases_but_rejects_conflicts(tmp_path: Path) -> None:
    mapping = tmp_path / "goldens.tsv"
    mapping.write_text(
        "# owner, source, artifact\n"
        "kotodama-standard\ta/demo.ko\ta/demo.to\n"
        "synthetic\t0\tfixtures/executor.to\n"
        "kotodama-standard\ta/demo.ko\tb/alias.to\n",
        encoding="utf-8",
    )
    rows = goldens.read_map(mapping)
    assert len(rows) == 2
    assert len(goldens.unique_builds(rows)) == 1

    mapping.write_text(
        "kotodama-standard\ta/demo.ko\ta/demo.to\n"
        "kotodama-zk\ta/demo.ko\tb/alias.to\n",
        encoding="utf-8",
    )
    with pytest.raises(goldens.GoldenError, match="conflicting execution modes"):
        goldens.read_map(mapping)

    mapping.write_text(
        "kotodama-standard\ta/demo.ko\ta/Demo.to\n"
        "kotodama-standard\ta/demo.ko\ta/demo.to\n",
        encoding="utf-8",
    )
    with pytest.raises(goldens.GoldenError, match="duplicate logical"):
        goldens.read_map(mapping)


def test_unique_builds_rejects_stem_collisions() -> None:
    rows = [
        goldens.Golden("standard", Path("a/demo.ko"), Path("a/demo.to")),
        goldens.Golden("standard", Path("b/demo.ko"), Path("b/demo.to")),
    ]
    with pytest.raises(goldens.GoldenError, match="staged stem collision"):
        goldens.unique_builds(rows)


def test_output_inventory_maps_compiler_artifacts_and_ignores_data() -> None:
    sources = [Path("contracts/demo.ko"), Path("contracts/alias.ko")]
    outputs = [
        Path("contracts/demo.to"),
        Path("published/alias.to"),
        Path("fixtures/norito_payload.to"),
        Path("fixtures/hand_authored_ivm.to"),
    ]
    rows = [
        goldens.Golden("standard", sources[0], outputs[0]),
        goldens.Golden("standard", sources[1], outputs[1]),
    ]

    assert goldens.compiler_owned_outputs(sources, outputs) == outputs[:2]
    goldens.validate_output_inventory(rows, sources, outputs)

    with pytest.raises(goldens.GoldenError, match="missing explicit golden map rows"):
        goldens.validate_output_inventory(rows[:1], sources, outputs)

    wrong_source = [
        rows[0],
        goldens.Golden("standard", sources[0], outputs[1]),
    ]
    with pytest.raises(goldens.GoldenError, match="invalid source mappings"):
        goldens.validate_output_inventory(wrong_source, sources, outputs)


def test_repository_compiler_owned_outputs_have_explicit_source_rows() -> None:
    root = goldens.repository_root()
    rows = goldens.read_map(root / goldens.MAP_PATH)
    sources = goldens.tracked_sources(root)
    outputs = goldens.tracked_outputs(root)

    goldens.validate_output_inventory(rows, sources, outputs)
    assert set(goldens.compiler_owned_outputs(sources, outputs)) == {
        row.destination for row in rows
    }


def test_noop_output_requires_exact_fresh_notices() -> None:
    goldens.validate_noop_build_output("fresh a.to\nfresh b.to\n", 2)
    with pytest.raises(goldens.GoldenError, match="performed compilation"):
        goldens.validate_noop_build_output("fresh a.to\nbuilt b.to\n", 2)
    with pytest.raises(goldens.GoldenError, match="performed compilation"):
        goldens.validate_noop_build_output("fresh a.to fresh b.to\n", 2)
    with pytest.raises(goldens.GoldenError, match="performed compilation"):
        goldens.validate_noop_build_output("fresh a.to\nunexpected diagnostic\n", 1)


def test_artifact_validation_binds_v1_budget_mode_and_debug_policy(
    tmp_path: Path,
) -> None:
    path = tmp_path / "demo.to"
    path.write_bytes(artifact())
    goldens.validate_artifact(path, "standard", ABI_HASH)

    path.write_bytes(artifact(goldens.ZK_MODE_BIT))
    goldens.validate_artifact(path, "zk", ABI_HASH)
    with pytest.raises(goldens.GoldenError, match="wrong ZK execution bit"):
        goldens.validate_artifact(path, "standard", ABI_HASH)

    path.write_bytes(artifact(suffix=b"DBG1"))
    with pytest.raises(goldens.GoldenError, match="forbidden debug metadata"):
        goldens.validate_artifact(path, "standard", ABI_HASH)

    mutated = bytearray(artifact())
    mutated[6] = 0x80
    path.write_bytes(mutated)
    with pytest.raises(goldens.GoldenError, match="unknown execution-mode bits"):
        goldens.validate_artifact(path, "standard", ABI_HASH)

    mutated = bytearray(artifact())
    mutated[7] = 8
    path.write_bytes(mutated)
    with pytest.raises(goldens.GoldenError, match="vector-length override"):
        goldens.validate_artifact(path, "standard", ABI_HASH)

    with pytest.raises(goldens.GoldenError, match="compiler ABI hash"):
        goldens.validate_artifact(path, "standard", b"\xff" * 32)


def test_manifest_abi_hash_requires_canonical_hash_text(tmp_path: Path) -> None:
    manifest = tmp_path / "demo.manifest.json"
    digest = ABI_HASH.hex().upper()
    manifest.write_text(
        json.dumps(
            {"abi_hash": f"hash:{digest}#{goldens.literal_checksum('hash', digest)}"}
        ),
        encoding="utf-8",
    )
    assert goldens.manifest_abi_hash(manifest) == ABI_HASH

    for value in [
        None,
        ABI_HASH.hex(),
        f"hash:{ABI_HASH.hex()}#abcd",
        "hash:00#ABCD",
        f"hash:{digest}#0000",
    ]:
        manifest.write_text(json.dumps({"abi_hash": value}), encoding="utf-8")
        with pytest.raises(goldens.GoldenError, match="ABI hash"):
            goldens.manifest_abi_hash(manifest)


def test_repository_compiler_manifests_derive_one_current_abi_hash() -> None:
    root = goldens.repository_root()
    manifest_paths = [
        root / destination for destination in goldens.COMPILER_MANIFESTS.values()
    ]
    current_hashes = {
        goldens.manifest_abi_hash(manifest_path) for manifest_path in manifest_paths
    }

    assert len(current_hashes) == 1
    current_hash = current_hashes.pop()
    current_digest = current_hash.hex().upper()
    current_checksum = goldens.literal_checksum("hash", current_digest)
    for manifest_path in manifest_paths:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert document["abi_hash"] == (
            f"hash:{current_digest}#{current_checksum}"
        )


def test_tracked_verification_never_rewrites_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "nested" / "destination.to"
    destination.parent.mkdir()
    destination.write_bytes(b"canonical")
    # The declared artifact mode is explicit even under an owner-private umask.
    destination.chmod(0o644)
    rendered = (
        goldens.RenderedFile(Path("nested/destination.to"), 0o644, b"canonical"),
    )
    monkeypatch.setattr(goldens, "repository_root", lambda: tmp_path)

    before = destination.stat().st_mtime_ns
    assert goldens.verify_rendered_tree(tmp_path, rendered) == 0
    assert destination.stat().st_mtime_ns == before

    destination.write_bytes(b"stale")
    with pytest.raises(goldens.GoldenError, match="stale"):
        goldens.verify_rendered_tree(tmp_path, rendered)
    assert destination.read_bytes() == b"stale"


@pytest.mark.parametrize("runtime_mode", [0o600])
def test_runtime_manifest_verification_uses_node_independent_admission_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime_mode: int
) -> None:
    root = tmp_path / "repo"
    release = tmp_path / "stage" / "release"
    release.mkdir(parents=True)
    row = goldens.Golden(
        "standard", Path("demo/example.ko"), Path("demo/example.to")
    )
    artifact_path = release / "example.to"
    generated_manifest = release / "example.manifest.json"
    artifact_path.write_bytes(artifact())
    generated_manifest.write_bytes(b'{"canonical":true}\n')
    artifact_path.chmod(0o600)
    generated_manifest.chmod(0o600)
    admission_tool = tmp_path / "bin" / "ivm_artifact_admit"
    commands: list[list[str]] = []

    def fake_run(command: list[object], cwd: Path) -> str:
        rendered = [str(part) for part in command]
        commands.append(rendered)
        assert cwd == root
        runtime_manifest = Path(rendered[rendered.index("--out") + 1])
        runtime_manifest.write_bytes(generated_manifest.read_bytes())
        runtime_manifest.chmod(runtime_mode)
        return ""

    monkeypatch.setattr(goldens, "run", fake_run)
    goldens.verify_runtime_manifests(admission_tool, root, release.parent, [row])

    assert artifact_path.stat().st_mode & 0o777 == 0o600
    assert generated_manifest.stat().st_mode & 0o777 == 0o600
    assert (release.parent / "verified" / "example.manifest.json").stat().st_mode & 0o777 == runtime_mode

    assert commands == [
        [
            str(admission_tool),
            "--code-file",
            str(artifact_path),
            "--out",
            str(release.parent / "verified" / "example.manifest.json"),
        ]
    ]


@pytest.mark.parametrize("output", ["missing", "malformed", "oversized", "public", "symlink", "hardlink", "directory", "fifo"])
def test_success_status_cannot_substitute_for_exact_protected_admission_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    stage = tmp_path / "stage"
    release = stage / "release"
    release.mkdir(parents=True)
    expected = release / "example.manifest.json"
    expected.write_bytes(b'{"canonical":true}')
    expected.chmod(0o600)
    row = goldens.Golden("standard", Path("example.ko"), Path("example.to"))

    def fake_run(command: list[object], cwd: Path) -> str:
        assert cwd == tmp_path
        destination = Path(command[-1])
        if output == "missing":
            return "success is not evidence"
        if output == "symlink":
            destination.symlink_to(expected)
        elif output == "hardlink":
            goldens.os.link(expected, destination)
        elif output == "directory":
            destination.mkdir()
        elif output == "fifo":
            goldens.os.mkfifo(destination, 0o600)
        else:
            destination.write_bytes(
                b"not-json" if output == "malformed" else
                expected.read_bytes() * 2 if output == "oversized" else expected.read_bytes()
            )
            destination.chmod(0o644 if output == "public" else 0o600)
        return ""

    monkeypatch.setattr(goldens, "run", fake_run)
    with pytest.raises(goldens.GoldenError):
        goldens.verify_runtime_manifests(tmp_path / "ivm_artifact_admit", tmp_path, stage, [row])


def test_admission_error_stops_the_generator_before_manifest_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    row = goldens.Golden("standard", Path("example.ko"), Path("example.to"))

    def reject(command: list[object], cwd: Path) -> str:
        raise goldens.GoldenError("contract admission failed: invalid complete V1 artifact")

    monkeypatch.setattr(goldens, "run", reject)
    with pytest.raises(goldens.GoldenError, match="contract admission failed"):
        goldens.verify_runtime_manifests(tmp_path / "ivm_artifact_admit", tmp_path, stage, [row])
    assert not (stage / "verified" / "example.manifest.json").exists()


def test_contract_test_commands_pin_filter_and_exact_acceptance_paths(
    tmp_path: Path,
) -> None:
    koto = tmp_path / "bin" / "koto"
    stage = tmp_path / "stage"
    commands = [
        [str(part) for part in command]
        for command in goldens.contract_test_commands(koto, stage)
    ]

    assert commands == [
        [str(koto), "test", "list", str(goldens.TEST_SOURCE)],
        [
            str(koto),
            "test",
            "run",
            "--filter",
            goldens.FILTERED_TEST_FRAGMENT,
            str(goldens.TEST_SOURCE),
        ],
        [
            str(koto),
            "test",
            "run",
            "--filter",
            goldens.EXACT_TEST_NAME,
            "--exact",
            str(goldens.TEST_SOURCE),
        ],
        [
            str(koto),
            "test",
            "run",
            "--jobs",
            "2",
            "--seed",
            "0",
            "--format",
            "json",
            str(goldens.TEST_SOURCE),
        ],
        [
            str(koto),
            "test",
            "run",
            "--jobs",
            "2",
            "--seed",
            "0",
            "--junit",
            str(stage / "contract-flow-tests.xml"),
            str(goldens.TEST_SOURCE),
        ],
    ]


def test_source_checks_keep_independent_roots_in_separate_requests(
    tmp_path: Path,
) -> None:
    koto = tmp_path / "bin" / "koto"
    standard = [Path("contracts/b.ko"), Path("contracts/a.ko")]
    zk = [Path("contracts/private.ko")]

    commands = [
        [str(part) for part in command]
        for command in goldens.source_check_commands(koto, standard, zk)
    ]

    assert commands == [
        [str(koto), "check", "--format", "human", "contracts/a.ko"],
        [str(koto), "check", "--format", "human", "contracts/b.ko"],
        [
            str(koto),
            "check",
            "--format",
            "human",
            "--zk",
            "contracts/private.ko",
        ],
    ]
    assert all(
        sum(part.endswith(".ko") for part in command) == 1 for command in commands
    )


def test_run_contract_tests_executes_only_the_pinned_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    stage = tmp_path / "stage"
    root.mkdir()
    stage.mkdir()
    koto = tmp_path / "bin" / "koto"
    expected = goldens.contract_test_commands(koto, stage)
    commands: list[list[object]] = []

    def fake_run(command: list[object], cwd: Path) -> str:
        index = len(commands)
        assert cwd == root
        assert [str(part) for part in command] == [
            str(part) for part in expected[index]
        ]
        commands.append(command)
        if index == 3:
            return json.dumps(
                {
                    "target": str(goldens.TEST_SOURCE),
                    "seed": 0,
                    "passed": 1,
                    "failed": 0,
                    "tests": [
                        {
                            "name": goldens.EXACT_TEST_NAME,
                            "line": 7,
                            "passed": True,
                            "duration_ns": 10,
                            "failure": None,
                        }
                    ],
                }
            )
        if index == 4:
            (stage / "contract-flow-tests.xml").write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<testsuite name="{goldens.TEST_SOURCE}" tests="1" '
                'failures="0" time="0.000000010" seed="0">\n'
                f'  <testcase name="{goldens.EXACT_TEST_NAME}" '
                f'classname="{goldens.TEST_SOURCE}" line="7" '
                'time="0.000000010">\n'
                "  </testcase>\n"
                "</testsuite>\n",
                encoding="utf-8",
            )
        return ""

    monkeypatch.setattr(goldens, "run", fake_run)
    goldens.run_contract_tests(koto, root, stage)

    assert len(commands) == len(expected) == 5
    report = json.loads(
        (stage / "contract-flow-tests.json").read_text(encoding="utf-8")
    )
    assert report["tests"][0]["name"] == goldens.EXACT_TEST_NAME


def test_contract_report_validation_rejects_malformed_or_divergent_output(
    tmp_path: Path,
) -> None:
    valid = {
        "target": "demo.test.ko",
        "seed": 0,
        "passed": 1,
        "failed": 0,
        "tests": [
            {
                "name": "roundtrip",
                "line": 3,
                "passed": True,
                "duration_ns": 1,
                "failure": None,
            }
        ],
    }
    junit = tmp_path / "report.xml"
    junit.write_text(
        '<testsuite name="demo.test.ko" tests="1" failures="0" '
        'time="0.000000001" seed="0">\n'
        '  <testcase name="roundtrip" classname="demo.test.ko" '
        'line="3" time="0.000000001"></testcase>\n'
        "</testsuite>\n",
        encoding="utf-8",
    )
    goldens.validate_contract_test_reports(json.dumps(valid), junit)

    with pytest.raises(goldens.GoldenError, match="invalid JSON"):
        goldens.validate_contract_test_reports("{", junit)

    failed = json.loads(json.dumps(valid))
    failed["failed"] = 1
    failed["passed"] = 0
    failed["tests"][0]["passed"] = False
    failed["tests"][0]["failure"] = "rejected"
    with pytest.raises(goldens.GoldenError, match="complete successful run"):
        goldens.validate_contract_test_reports(json.dumps(failed), junit)

    divergent = junit.read_text(encoding="utf-8").replace(
        'name="roundtrip"', 'name="different"'
    )
    junit.write_text(divergent, encoding="utf-8")
    with pytest.raises(goldens.GoldenError, match="inventories differ"):
        goldens.validate_contract_test_reports(json.dumps(valid), junit)


def test_artifact_code_metrics_locates_literals_and_counts_relocation_nops(
    tmp_path: Path,
) -> None:
    path = tmp_path / "demo.to"
    literal_data = b"abc"
    literal_section = (
        b"LTLB"
        + struct.pack("<III", 1, 1, len(literal_data))
        + struct.pack("<Q", 25)
        + literal_data
        + b"\0"
    )
    code = struct.pack("<II", goldens.RELOCATION_NOP_WORD, 0x0102_0304)
    path.write_bytes(artifact(suffix=literal_section + code))

    metrics = goldens.artifact_code_metrics(path)
    assert metrics.code_bytes == 8
    assert metrics.instruction_words == 2
    assert metrics.relocation_nop_words == 1
    assert path.read_bytes()[metrics.code_offset :] == code


def test_performance_gate_rejects_one_percent_padding(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage"
    release = stage / "release"
    release.mkdir(parents=True)
    source = Path("samples/demo.ko")
    row = goldens.Golden("standard", source, Path("samples/demo.to"))

    # One placeholder among 100 words is exactly 1%, which is not below 1%.
    words = [goldens.RELOCATION_NOP_WORD, *([0x0102_0304] * 99)]
    (release / "demo.to").write_bytes(
        artifact(suffix=b"".join(struct.pack("<I", word) for word in words))
    )
    with pytest.raises(goldens.GoldenError, match="strictly less than 1%"):
        goldens.validate_performance(stage, [row])

    # Padding-free output is accepted without retaining an obsolete predecessor
    # revision as a predicted release gate.
    (release / "demo.to").write_bytes(
        artifact(suffix=b"".join(struct.pack("<I", 0x0102_0304) for _ in range(101)))
    )
    goldens.validate_performance(stage, [row])


def test_two_pass_rendering_binds_paths_modes_bytes_and_manifest() -> None:
    first = (
        goldens.RenderedFile(Path("a/one.to"), 0o644, b"one"),
        goldens.RenderedFile(Path("b/two.to"), 0o644, b"two"),
    )
    goldens.compare_renderings(first, tuple(first))
    assert goldens.owner_manifest(first) == goldens.owner_manifest(tuple(first))

    with pytest.raises(goldens.GoldenError, match="path sets"):
        goldens.compare_renderings(first, first[::-1])
    with pytest.raises(goldens.GoldenError, match="mode"):
        goldens.compare_renderings(
            first,
            (first[0], goldens.RenderedFile(Path("b/two.to"), 0o600, b"two")),
        )
    with pytest.raises(goldens.GoldenError, match="bytes"):
        goldens.compare_renderings(
            first,
            (first[0], goldens.RenderedFile(Path("b/two.to"), 0o644, b"drift")),
        )


def test_sealed_regular_reader_rejects_hard_links(tmp_path: Path) -> None:
    source = tmp_path / "source"
    alias = tmp_path / "alias"
    source.write_bytes(b"sealed")
    try:
        os.link(source, alias)
    except (NotImplementedError, OSError):
        pytest.skip("hard links are unavailable")
    with pytest.raises(goldens.GoldenError, match="one hard link"):
        goldens.seal_file(source, "test input")


@pytest.mark.skipif(os.name != "posix", reason="POSIX child umask contract")
def test_tool_children_are_private_without_changing_parent_umask(tmp_path: Path) -> None:
    output = tmp_path / "runtime.manifest.json"
    previous = os.umask(0o000)
    try:
        result = goldens.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('canonical'); print('done')",
                output,
            ],
            tmp_path,
        )
        assert result == "done\n"
        assert output.read_text() == "canonical"
        assert output.stat().st_mode & 0o777 == 0o600
        observed = os.umask(0o000)
        assert observed == 0o000
    finally:
        os.umask(previous)


def test_private_compiler_output_publishes_as_a_separate_public_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "stage" / "release" / "example.to"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"canonical artifact")
    source.chmod(0o600)
    monkeypatch.setattr(goldens, "COMPILER_MANIFESTS", {})
    rows = [goldens.Golden("standard", Path("example.ko"), Path("demo/example.to"))]
    rendered = goldens.rendered_files(source.parent.parent, rows)
    assert rendered == (
        goldens.RenderedFile(Path("demo/example.to"), 0o644, source.read_bytes()),
    )
    destination = tmp_path / "published"
    goldens.publish_create_only(destination, rendered)
    assert goldens.verify_rendered_tree(destination, rendered) == 0
    public = destination / "demo/example.to"
    assert public.read_bytes() == source.read_bytes()
    assert public.stat().st_mode & 0o777 == 0o644
    assert source.stat().st_mode & 0o777 == 0o600
    assert public.stat().st_ino != source.stat().st_ino
    for invalid_mode in (0o400, 0o640, 0o644, 0o666):
        source.chmod(invalid_mode)
        with pytest.raises(goldens.GoldenError, match="must use mode 0600"):
            goldens.rendered_files(source.parent.parent, rows)
    source.chmod(0o600)
