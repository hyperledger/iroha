#!/usr/bin/env python3
"""Reject repository-owned Wasm/WASI runtimes, artifacts and build support.

Requires Python 3.10+ and Git. Checks tracked and nonignored untracked files in
the current checkout, including unstaged edits. It never changes files and has
no environment override. Upstream vendored source is not an Iroha build target.
Only the named upstream source roots are exempt from
text checks; artifacts are checked everywhere in the Git-owned boundary.
This static declaration check does not resolve dynamically constructed programs.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


SELF = "scripts/check_ivm_only.py"
TEST = "pytests/scripts/ivm_only_guard_test.py"
UPSTREAM_VENDOR_ROOTS = {
    "vendor/find_cuda_helper",
    "vendor/vega-prover",
    "vendor/wayland-scanner-0.31.10",
}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
BUILD_SUFFIXES = JS_SUFFIXES | {
    ".rs", ".toml", ".json", ".yml", ".yaml", ".sh", ".py",
    ".kts", ".gradle", ".kt", ".nix", ".cmake", ".c", ".h", ".cpp",
    ".hpp", ".cc", ".cxx", ".java", ".swift", ".cs", ".fs", ".fsx",
    ".ps1", ".bash", ".zsh", ".bat", ".cmd", ".dockerfile", ".go",
}
BUILD_FILENAMES = {"Makefile", "Dockerfile", "CMakeLists.txt"}
TARGET = re.compile(r"\b(?:wasm32|wasm64)(?:-[\w-]+)?\b|\bwasm_js\b")
TOOL = re.compile(r"\b(?:wasm[-_]bindgen|wasm-pack|wasmtime|wasmer|wasmi|wasmparser|wasm-encoder)\b")
WASI = re.compile(r'target_os\s*=\s*[\"\']wasi[\"\']|\ballow_wasi\s*:|^\s*WasiLite\s*[,={]')
CONFIG_WASI = re.compile(r'(?m)^\s*allow_wasi\s*=|[\"\']allow_wasi[\"\']\s*:')
NO_STD = re.compile(r"#!\s*\[\s*(?:no_std\b|cfg_attr\s*\([^\]]*\bno_std\b)")
JS_RUNTIME = re.compile(
    r"\bWebAssembly\s*(?:\.|\[)"
    r"|\b(?:globalThis|global|window|self)\s*\.\s*WebAssembly\b"
    r"|\brequire\s*\(\s*[\"'](?:@[^/]+/)?(?:wasm|wasi)"
    r"|\b(?:from\s*|require\s*\(\s*|import\s*\(?\s*)[\"'](?:node:)?wasi[\"']"
)
GRADLE_TARGET = re.compile(r"\bwasm(?:Js|Wasi)?\s*[({]")
GO_BUILD = re.compile(
    r"^\s*//\s*(?:go:build|\+build)\s+.*\b(?:wasm|wasm32|wasm64|wasi|wasip1|wasip2)\b"
)
GO_TARGET_FILE = re.compile(r"_(?:wasm|wasm32|wasm64|wasi|wasip1|wasip2)(?:_test)?\.go$")


def repository_paths(root: Path) -> list[Path]:
    """Enumerate the current Git-owned source boundary without a base ref."""
    output = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    return sorted({Path(name.decode("utf-8")) for name in output.split(b"\0") if name})


def check_path(root: Path, relative: Path) -> list[str]:
    """Return concrete forbidden artifacts or executable/build declarations."""
    name = relative.as_posix()
    path = root / relative
    if not path.is_file():
        return []
    suffix = relative.suffix.lower()
    if GO_TARGET_FILE.search(relative.name):
        return [f"{name}: Go WebAssembly/WASI build targets are prohibited"]
    if suffix in {".wasm", ".wat", ".wast"}:
        return [f"{name}: WebAssembly artifacts are prohibited; IVM bytecode uses .to"]
    with path.open("rb") as stream:
        if stream.read(4) == b"\x00asm":
            return [f"{name}: WebAssembly binary magic is prohibited"]
    # Exempt source text only. A vendored binary remains a
    # prohibited artifact, and an arbitrary nested directory is not upstream.
    if name in {SELF, TEST}:
        return []
    if any(name.startswith(prefix + "/") for prefix in UPSTREAM_VENDOR_ROOTS):
        return []
    if suffix not in BUILD_SUFFIXES and relative.name not in BUILD_FILENAMES:
        return []
    # Lockfiles record optional upstream targets too. Their corresponding
    # first-party package manifests are always checked.
    if relative.name in {"package-lock.json", "pnpm-lock.yaml"}:
        return []
    rules = [TARGET, TOOL, WASI]
    if suffix in {".toml", ".json"}:
        rules.append(CONFIG_WASI)
    if suffix in JS_SUFFIXES:
        rules.append(JS_RUNTIME)
    if suffix in {".kts", ".gradle"}:
        rules.append(GRADLE_TARGET)
    lines = path.read_text(encoding="utf-8").splitlines()
    code_lines = [
        "" if line.lstrip().startswith(("//", "# ", "///", "//!", "* ")) else line
        for line in lines
    ]
    findings = []
    found_lines = set()
    for number, line in enumerate(code_lines, 1):
        if any(rule.search(line) for rule in rules):
            found_lines.add(number)
    if suffix == ".go":
        # Go selects build targets through comments. Check these before the
        # generic comment exclusion can erase the active build constraint.
        for number, line in enumerate(lines, 1):
            if GO_BUILD.search(line):
                found_lines.add(number)
    if suffix == ".rs":
        # Rust attributes may span lines, including cfg_attr's condition and
        # no_std argument. Preserve newlines when skipping documentation.
        code = "\n".join(code_lines)
        for match in NO_STD.finditer(code):
            found_lines.add(code.count("\n", 0, match.start()) + 1)
    for number in sorted(found_lines):
        findings.append(
            f"{name}:{number}: forbidden non-IVM build/runtime declaration: {lines[number - 1].strip()}"
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    """Run the full current-tree policy check and print actionable findings."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    findings = [finding for path in repository_paths(root) for finding in check_path(root, path)]
    if findings:
        print("IVM-only guard failed:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("IVM-only guard passed: no prohibited artifacts or static build/runtime declarations found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
