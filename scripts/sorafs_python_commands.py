"""One fixed Python producer operation catalog and captured-log relation.

Pure path/byte checks support remote artifact replay without opening historical
producer paths. Matching observations do not establish that an approved producer
ran them; signed aggregate authority remains a separate consuming requirement.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath

from sorafs_python_consumer_artifact import ArtifactError, MAX_OUTPUT_BYTES, _object, _path
from sorafs_python_environment import DISTRIBUTION_PROBE, PIP_BOOTSTRAP, RUNTIME_PROBE
from sorafs_python_runtime_inputs import RuntimeManifest


@dataclass(frozen=True)
class PythonCommand:
    """Exact source-owned argv, log bound, deadline and stderr contract."""
    label: str
    argv: tuple[str, ...]
    stdout_limit: int = 32 * 1024 * 1024
    timeout_seconds: int = 1200
    empty_stderr: bool = False


STDERR_LIMIT = 1024 * 1024


def execution_commands(*, source_root: PurePosixPath, work: PurePosixPath,
                       runtime: RuntimeManifest, pip_filename: str,
                       native_filename: str) -> tuple[PythonCommand, ...]:
    """Derive the exact nine operations for one canonical producer topology."""
    for path in (source_root, work):
        _path(str(path), absolute=True)
    if not work.is_relative_to(source_root / "target") or work == source_root / "target":
        raise ArtifactError("recorded Python operation must remain beneath its source target directory")
    for name in (pip_filename, native_filename):
        _path(name, absolute=False)
        if len(PurePosixPath(name).parts) != 1:
            raise ArtifactError("recorded input filename is not one original basename")
    if not pip_filename.endswith(".whl"):
        raise ArtifactError("pip input must be its original wheel")
    environment = work / "environment"
    python = str(environment / "bin/python3.12")
    base = runtime.executable.path
    _path(base, absolute=True)
    native = (python, "-I", "-B", str(source_root / "scripts/check_native_sdk_artifact.py"),
              "verify", "--artifact", str(work / "native" / native_filename),
              "--manifest", str(work / "inputs/native-abi29.json"), "--source-root", str(source_root),
              "--python", python)
    probe = (python, "-I", "-B", "-c", RUNTIME_PROBE)
    return (
        PythonCommand("runtime-before", (base, "-I", "-S", "-B", "-c", RUNTIME_PROBE), 64 * 1024, 30, True),
        PythonCommand("create-environment", (base, "-I", "-S", "-B", "-m", "venv", "--without-pip", "--copies", str(environment))),
        PythonCommand("environment-before", probe, 64 * 1024, 30, True),
        PythonCommand("native-before", native, timeout_seconds=120, empty_stderr=True),
        PythonCommand("install", (python, "-I", "-B", "-c", PIP_BOOTSTRAP,
                                  str(work / "wheels" / pip_filename), str(work / "inputs/requirements.txt"))),
        PythonCommand("installed-distributions", (python, "-I", "-B", "-c", DISTRIBUTION_PROBE), 64 * 1024, 30, True),
        PythonCommand("execute", (python, "-I", "-B",
                                  str(work / "snapshot/scripts/fixtures/SorafsPythonConsumerQualificationRunner.py"),
                                  "--input", str(work / "inputs/child.json")), MAX_OUTPUT_BYTES, 1200, True),
        PythonCommand("environment-after", probe, 64 * 1024, 30, True),
        PythonCommand("native-after", native, timeout_seconds=120, empty_stderr=True),
    )


def verify_command_observations(rows: object, members: dict[str, bytes], *,
                                expected: tuple[PythonCommand, ...]) -> None:
    """Join closed command observations to the exact operations and actual log bytes."""
    if type(rows) is not list or len(rows) != len(expected):
        raise ArtifactError("recorded Python command inventory differs")
    for row, command in zip(rows, expected, strict=True):
        row = _object(row, {"label", "argv", "returncode", "stdout", "stderr"}, "command")
        if (row["label"] != command.label or row["argv"] != list(command.argv)
                or type(row["returncode"]) is not int or row["returncode"] != 0):
            raise ArtifactError("recorded Python operation differs or did not succeed")
        for stream, bound in (("stdout", command.stdout_limit), ("stderr", STDERR_LIMIT)):
            name = "logs/" + command.label + "." + stream
            body = members.get(name)
            reference = _object(row[stream], {"sha256", "size"}, "command log")
            if (type(body) is not bytes or len(body) > bound or type(reference["size"]) is not int
                    or reference != {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
                    or (stream == "stderr" and command.empty_stderr and body)):
                raise ArtifactError("recorded Python operation log differs from actual bytes")
    actual = {name for name in members if name.startswith("logs/")}
    wanted = {"logs/" + command.label + "." + stream
              for command in expected for stream in ("stdout", "stderr")}
    if actual != wanted:
        raise ArtifactError("recorded Python logs contain missing or unowned operations")
