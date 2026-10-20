#!/usr/bin/env python3
"""Explicit offline FastPQ Metal candidate producer; Python 3.10+ and real tools.

Ordinary Cargo/runtime paths never invoke this producer. Select full Xcode with
xcode-select or DEVELOPER_DIR/SDKROOT/TOOLCHAINS before invoking it. Outputs are
create-only; generation directories are retained on success and failure. Children
exit naturally: no timeout, signals, tool installation, download or cache cleanup.
Generation metadata is an unqualified candidate, never its own admission authority
or signed provenance. Independently reviewed pins and real device parity remain due.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

SOURCE_INPUTS = (
    "crates/fastpq_prover/metal/include/params.h",
    "crates/fastpq_prover/metal/kernels/field.metal",
    "crates/fastpq_prover/metal/kernels/ntt_stage.metal",
    "crates/fastpq_prover/metal/kernels/exact_root.metal",
    "crates/fastpq_prover/metal/kernels/poseidon.metal",
    "crates/fastpq_prover/metal/kernels/digest384.metal",
    "crates/fastpq_prover/metal/kernels/keccak256.metal",
    "crates/fastpq_prover/metal/kernels/bn254.metal",
)
TRANSLATION_UNITS = SOURCE_INPUTS[2:]
ENTRY_POINTS = (
    "fastpq_fft_columns", "fastpq_lde_columns", "fastpq_fft_post_tiling",
    "exact_root_bit_reverse_v1", "exact_root_local_tiles_v1", "exact_root_global_stage_v1",
    "poseidon_permute", "poseidon_hash_rows", "poseidon_hash_columns",
    "fastpq_digest384_last_fields", "digest384_hash_frames_v1", "digest384_indexed_first_coordinate_v1",
    "fastpq_sha3_256_continuations", "bn254_fft_columns", "bn254_lde_columns", "bn254_poseidon_hash_words",
)
LANGUAGE = "macos-metal2.4"
REMEDIATION = (
    "verify that xcode-select -p or DEVELOPER_DIR selects full Xcode and accept its license; "
    "if needed run xcodebuild -downloadComponent MetalToolchain manually. "
    "Use --skip for explicit non-generation; no Metal compiler is invoked by ordinary builds/runtime."
)


class GenerationError(Exception):
    """A terminal generation refusal; retained work is never auto-cleaned."""


def digest_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def snapshot(root: Path) -> tuple[dict[str, bytes], str]:
    """Bind exactly eight ordered path/length/byte owners, without text rewriting."""
    inputs = {path: (root / path).read_bytes() for path in SOURCE_INPUTS}
    result = hashlib.sha256()
    for path, data in inputs.items():
        name = path.encode("utf-8")
        result.update(len(name).to_bytes(4, "little"))
        result.update(name)
        result.update(len(data).to_bytes(8, "little"))
        result.update(data)
    return inputs, result.hexdigest()


def kernel_inventory(inputs: dict[str, bytes]) -> tuple[str, ...]:
    entries = tuple(
        name.decode("ascii")
        for data in inputs.values()
        for name in re.findall(rb"\bkernel\s+void\s+(\w+)\s*\(", data)
    )
    if entries != ENTRY_POINTS:
        raise GenerationError("source kernel inventory differs from the exact sixteen entry points")
    return entries


def run(arguments: list[str], commands: list[dict]) -> subprocess.CompletedProcess[str]:
    """Wait for the actual child's natural terminal status; never cancel it."""
    try:
        result = subprocess.run(arguments, check=False, capture_output=True, text=True)
    except OSError as error:
        raise GenerationError(f"failed to launch {arguments[0]}: {error}") from error
    commands.append({"arguments": arguments, "returncode": result.returncode,
                     "stdout": result.stdout, "stderr": result.stderr})
    return result


def diagnostic(result: subprocess.CompletedProcess[str]) -> str:
    return " ".join((result.stderr + " " + result.stdout).split())[:2000] or "no diagnostic output"


def find_tool(name: str, commands: list[dict]) -> Path:
    diagnostics = []
    for arguments in (["xcrun", "-sdk", "macosx", "--find", name], ["xcrun", "--find", name]):
        result = run(arguments, commands)
        if result.returncode == 0:
            path = Path(result.stdout.strip())
            if result.stdout.strip() and path.is_file():
                # The basename selects the Apple multi-call tool mode. Resolve the
                # directory, but retain the discovered final component (metallib).
                return path.parent.resolve(strict=True) / path.name
        diagnostics.append(diagnostic(result))
    raise GenerationError(f"failed to locate {name}: {'; '.join(diagnostics)}")


def require_tool_identity(path: Path, identity: dict, when: str) -> None:
    """Reject alias retargeting even when the replacement has identical bytes."""
    if (str(path) != identity["path"]
            or str(path.resolve(strict=True)) != identity["resolved_path"]
            or digest_file(path) != identity["sha256"]):
        raise GenerationError(f"{path.name} identity changed {when}")


def probe_tool(path: Path, commands: list[dict]) -> dict:
    """Pin invocation mode and resolved bytes separately, retaining both probes."""
    identity = {"path": str(path), "resolved_path": str(path.resolve(strict=True)),
                "sha256": digest_file(path)}
    result = run([str(path), "-v"], commands)
    if result.returncode != 0:
        raise GenerationError(f"{path.name} failed its -v probe: {diagnostic(result)}")
    require_tool_identity(path, identity, "during its version probe")
    help_result = run([str(path), "-help"], commands)
    if help_result.returncode != 0:
        raise GenerationError(f"{path.name} failed its -help probe: {diagnostic(help_result)}")
    require_tool_identity(path, identity, "during its help probe")
    return {**identity, "version_stdout": result.stdout, "version_stderr": result.stderr,
            "help_stdout": help_result.stdout, "help_stderr": help_result.stderr}


def recheck_tool(path: Path, identity: dict, commands: list[dict], when: str) -> None:
    """Reobserve the original invocation mode before publishing any approval input."""
    require_tool_identity(path, identity, when)
    if probe_tool(path, commands) != identity:
        raise GenerationError(f"{path.name} mode changed {when}")


def require_output(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise GenerationError(f"{label} was not produced as a fresh non-empty regular file: {path}")


def generate(root: Path, output: Path, target: str) -> dict:
    """Retain exact source/tool owners, then publish a create-only candidate."""
    if output.exists() or output.is_symlink():
        raise GenerationError(f"create-only output already exists: {output}")
    inputs, source_digest = snapshot(root)
    inventory = kernel_inventory(inputs)
    producer = Path(__file__).resolve(strict=True)
    producer_digest = digest_file(producer)
    generation = output.parent / f".{output.name}.generation-{uuid.uuid4().hex}"
    generation.mkdir(mode=0o700)
    # Compile captured copies, never a mixture of files re-read across children.
    for path, data in inputs.items():
        captured = generation / "source" / path
        captured.parent.mkdir(parents=True, exist_ok=True)
        with captured.open("xb") as destination:
            destination.write(data)
        captured.chmod(0o444)
    commands: list[dict] = []
    try:
        metal = find_tool("metal", commands)
        metal_identity = probe_tool(metal, commands)
        metallib = find_tool("metallib", commands)
        metallib_identity = probe_tool(metallib, commands)
        # Help is retained diagnostic evidence, not option acceptance authority:
        # Apple Metal may advertise only -ffast-math, while accepting its negative.
        # Every original compilation must accept the unchanged deterministic flag;
        # an ignored argument is a hard error, never a silently weakened policy.
        flags = [f"-std={LANGUAGE}", "-O3", "-fno-fast-math",
                 "-Werror=unused-command-line-argument"]
        modules = generation / "metal_modules"
        modules.mkdir()
        include = generation / "source/crates/fastpq_prover/metal/include"
        kernels = generation / "source/crates/fastpq_prover/metal/kernels"
        objects = []
        for path in TRANSLATION_UNITS:
            source = generation / "source" / path
            air = generation / f"{source.stem}.air"
            result = run([str(metal), *flags, "-c", f"-fmodules-cache-path={modules}",
                          "-I", str(include), "-I", str(kernels), str(source), "-o", str(air)], commands)
            if result.returncode != 0:
                raise GenerationError(f"failed to compile Metal shader {path}: {diagnostic(result)}")
            require_output(air, "Metal AIR object")
            objects.append(air)
        library = generation / "fastpq.metallib"
        result = run([str(metallib), *(str(path) for path in objects), "-o", str(library)], commands)
        if result.returncode != 0:
            raise GenerationError(f"failed to link Metal library: {diagnostic(result)}")
        # Some linker modes exit successfully after warning that every AIR input
        # was ignored. Such output is not a completed library generation.
        if re.search(r"\bwarning\b|\bignoring\s+(?:file|object)\b",
                     result.stderr + "\n" + result.stdout, re.IGNORECASE):
            raise GenerationError(f"Metal linker warned or omitted input: {diagnostic(result)}")
        require_output(library, "Metal library")
        library_digest = digest_file(library)
        captured, captured_digest = snapshot(generation / "source")
        if captured != inputs or captured_digest != source_digest:
            raise GenerationError("captured eight source inputs changed during generation")
        current, current_digest = snapshot(root)
        if current != inputs or current_digest != source_digest:
            raise GenerationError("original eight source inputs changed during generation")
        recheck_tool(metal, metal_identity, commands, "during generation")
        recheck_tool(metallib, metallib_identity, commands, "during generation")
        if digest_file(producer) != producer_digest:
            raise GenerationError("original producer source changed during generation")
        # Exclusively claim this candidate only after natural successful exits.
        # The metadata is published last; a failed partial output is retained.
        output.mkdir(mode=0o700)
        published = output / "fastpq.metallib"
        with library.open("rb") as source, published.open("xb") as destination:
            shutil.copyfileobj(source, destination)
        if digest_file(published) != library_digest:
            raise GenerationError("library bytes changed before create-only publication")
        current, current_digest = snapshot(root)
        if current != inputs or current_digest != source_digest:
            raise GenerationError("original eight source inputs changed before metadata publication")
        recheck_tool(metal, metal_identity, commands, "before metadata publication")
        recheck_tool(metallib, metallib_identity, commands, "before metadata publication")
        if digest_file(producer) != producer_digest:
            raise GenerationError("original producer source changed before metadata publication")
        captured, captured_digest = snapshot(generation / "source")
        if captured != inputs or captured_digest != source_digest:
            raise GenerationError("captured eight source inputs changed before metadata publication")
        record = {
            "status": "unqualified generation candidate", "admission_authority": False,
            "signed_provenance": False, "hardware_qualification": False,
            "requested_target": target, "language": LANGUAGE, "flags": flags,
            "source_sha256": source_digest, "entry_points": list(inventory),
            "sources": [{"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for path, data in inputs.items()],
            "producer": {"path": str(producer), "sha256": producer_digest},
            "compiler": metal_identity, "linker": metallib_identity,
            "library": {"bytes": published.stat().st_size, "sha256": library_digest},
            "generation_directory": str(generation), "commands": commands,
            "pending": "independent pins/target review, repeated genuine generation, all sixteen real pipelines and complete output parity",
        }
        with (output / "generation.json").open("x", encoding="utf-8") as destination:
            json.dump(record, destination, indent=2)
            destination.write("\n")
        return record
    except GenerationError as error:
        raise GenerationError(f"{error}; retained generation directory: {generation}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, help="new create-only candidate directory; parent must exist")
    parser.add_argument("--target", choices=("aarch64-apple-darwin", "x86_64-apple-darwin"), help="explicit requested profile; independently reviewed against actual tool evidence before admission")
    parser.add_argument("--skip", action="store_true", help="explicit non-generation: no source/tool/output access")
    args = parser.parse_args(argv)
    if args.skip:
        print("explicit --skip: no Metal generation, tool probes or downloads")
        return 0
    if args.output is None or args.target is None:
        parser.error("generation requires explicit --output and --target")
    try:
        record = generate(args.repo_root.resolve(strict=True), args.output.absolute(), args.target)
    except (GenerationError, OSError, UnicodeError) as error:
        print(f"Metal compiler/linker is unavailable or generation refused: {error}; {REMEDIATION}", file=sys.stderr)
        return 1
    print(f"unqualified create-only FastPQ candidate: {args.output}; sha256={record['library']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
