#!/usr/bin/env python3
"""Build and run bounded macOS native-probe controls in fresh subprocesses.

Python 3.11+, Xcode command-line tools, 64-bit macOS (not arm64e). Supply a NEW
--output-dir; no environment variables are required. No repository, device or
production files are changed. The only environment added to child controls is
DYLD_INSERT_LIBRARIES for this freshly compiled dylib. Existing DYLD_* settings
cause refusal because they alter interception. This is endpoint diagnostics,
not a complete runtime allocation or memory certificate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SOURCE_NAMES = ("np_api.h", "np_interpose.c", "np_controls.c", "np_unit.c",
                "run_controls.py", "test_controls.py", "README.md")
ENDPOINTS = (
    "malloc", "calloc", "realloc", "free", "posix_memalign", "aligned_alloc", "valloc",
    "malloc_zone_malloc", "malloc_zone_calloc", "malloc_zone_realloc", "malloc_zone_free",
    "malloc_zone_memalign", "malloc_zone_valloc", "mmap", "munmap", "mach_vm_allocate",
    "mach_vm_map", "mach_vm_deallocate", "vm_allocate", "vm_map", "vm_deallocate",
)
CONTROLS = ENDPOINTS + ("empty", "outside", "unadmitted", "terminal", "failure")
UNITS = ("overflow", "product", "collision", "wrong_order", "sealed", "concurrent", "nested")


def sha256(path: Path) -> str:
    """Hash exact source, executable or SDK declaration bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inventory() -> dict[str, str]:
    """Pin this small diagnostic's sources, controls and reproduction note."""
    return {name: sha256(HERE / name) for name in SOURCE_NAMES}


def validate_control(case: str, result: dict) -> None:
    """Validate declared observations independently of the C exit status."""
    if not isinstance(result, dict) or result.get("control_passed") is not True:
        raise ValueError(f"{case}: control did not report success")
    expected_phase = 0 if case == "unadmitted" else 1 if case == "terminal" else 2
    if (result.get("case") != case or result.get("abi_version") != 1
            or result.get("invalid_flags") != 0 or result.get("phase_before_seal") != expected_phase
            or result.get("transitions") != (8, 10, 14)[expected_phase]
            or result.get("profile_qualified") is not False):
        raise ValueError(f"{case}: bad phase/ABI/validity result")
    endpoints = result.get("endpoints")
    if not isinstance(endpoints, list) or len(endpoints) != len(ENDPOINTS):
        raise ValueError(f"{case}: endpoint inventory missing")
    for item, name in zip(endpoints, ENDPOINTS):
        if not isinstance(item, dict) or item.get("name") != name:
            raise ValueError(f"{case}: endpoint order differs")
        phases = item.get("phases")
        if not isinstance(phases, list) or len(phases) != 3:
            raise ValueError(f"{case}: bad phase array")
        for counts in phases:
            if (not isinstance(counts, list) or len(counts) != 3
                    or any(type(n) is not int or not 0 <= n < 1 << 64 for n in counts)
                    or counts[2] > counts[0]):
                raise ValueError(f"{case}: bad counter array")
    charged = {item["name"]: item["phases"][1] for item in endpoints}
    if case in ENDPOINTS and charged[case][0] < 1:
        raise ValueError(f"{case}: required endpoint was not intercepted")
    if case == "terminal" and charged["malloc"][0] < 1:
        raise ValueError("terminal: deliberately charged malloc was not intercepted")
    if case in {"empty", "outside", "unadmitted"} and any(c[0] for c in charged.values()):
        raise ValueError(f"{case}: expected empty charged interval")
    if case == "outside" and (endpoints[0]["phases"][0][0] < 1 or endpoints[0]["phases"][2][0] < 1):
        raise ValueError("outside: setup/teardown control missed")
    if case == "failure" and charged["mmap"][2] != 1:
        raise ValueError("failure: mmap failure sentinel missed")


def run(output: Path) -> dict:
    """Create one bounded build/control receipt; preserve failures and raw exits."""
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "parliament-native-probe-controls-v1", "controls_passed": False,
              "complete_native_coverage": False, "complete_workspace_certificate": False,
              "profile_qualified": False, "commands": [], "started_unix": time.time()}
    receipt = output / "receipt.json"

    def save() -> None:
        temporary = output / "receipt.tmp"
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        temporary.replace(receipt)

    def command(args: list[str], label: str, env: dict | None = None) -> subprocess.CompletedProcess:
        entry = {"command": args, "label": label}
        report["commands"].append(entry)
        save()
        try:
            result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=60)
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            entry.update({"timeout_seconds": 60, "stdout": decoded(error.stdout), "stderr": decoded(error.stderr)})
            save()
            raise
        entry.update({"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        save()
        if result.returncode:
            raise ValueError(f"{label}: child exit {result.returncode}")
        return result

    try:
        interfering = {"CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
                       "MACOSX_DEPLOYMENT_TARGET"}
        if (sys.platform != "darwin" or any(key.startswith("DYLD_") for key in os.environ)
                or interfering.intersection(os.environ)):
            raise ValueError("requires macOS without inherited DYLD_*/compiler include or deployment overrides")
        report["host"] = {"machine": platform.machine(), "macos_version": platform.mac_ver()[0]}
        sources = source_inventory()
        report["sources_before"] = sources
        compiler = Path(command(["xcrun", "--find", "clang"], "find-clang").stdout.strip())
        sdk = Path(command(["xcrun", "--show-sdk-path"], "find-sdk").stdout.strip())
        report["compiler"] = {"path": str(compiler), "sha256": sha256(compiler)}
        command([str(compiler), "--version"], "clang-version")
        headers = ["stdlib.h", "malloc/malloc.h", "sys/mman.h", "mach/mach.h", "mach/mach_vm.h", "mach/vm_map.h"]
        report["sdk_declaration_headers"] = {name: sha256(sdk / "usr/include" / name) for name in headers}
        report["sdk_header_scope"] = "selected direct declarations, not transitive SDK/runtime implementation coverage"
        library, controls, unit = (output / name for name in ("libnp.dylib", "np_controls", "np_unit"))
        common = [str(compiler), "-isysroot", str(sdk), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-builtin"]
        command(common + ["-dynamiclib", str(HERE / "np_interpose.c"), "-o", str(library)], "build-interposer")
        command(common + [str(HERE / "np_controls.c"), str(library), "-o", str(controls)], "build-controls")
        command(common + ["-Wno-unused-function", str(HERE / "np_unit.c"), "-o", str(unit)], "build-unit")
        report["binaries"] = {p.name: sha256(p) for p in (library, controls, unit)}
        command(["nm", "-u", str(library)], "interposer-imports")
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(library))
        report["control_environment"] = {"DYLD_INSERT_LIBRARIES": str(library)}
        for case in UNITS:
            command([str(unit), case], "unit-" + case)
        for case in CONTROLS:
            result = command([str(controls), case], "control-" + case, env)
            validate_control(case, json.loads(result.stdout))
        report["sources_after"] = source_inventory()
        if report["sources_after"] != sources:
            raise ValueError("probe source changed during build/controls")
        if any(sha256(output / name) != digest for name, digest in report["binaries"].items()):
            raise ValueError("probe binary changed during controls")
        if sha256(compiler) != report["compiler"]["sha256"]:
            raise ValueError("compiler changed during build/controls")
        if any(sha256(sdk / "usr/include" / name) != digest for name, digest in report["sdk_declaration_headers"].items()):
            raise ValueError("reviewed SDK declarations changed during build/controls")
        report.update({"controls_passed": True, "endpoint_positive_controls": len(ENDPOINTS),
                       "scope_failure_controls": len(CONTROLS) - len(ENDPOINTS), "internal_unit_scenarios": len(UNITS)})
    except (Exception, KeyboardInterrupt) as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    finally:
        report["finished_unix"] = time.time()
        save()
    return report


def main() -> int:
    """Expose fresh-path-only reproduction with failing exit on any missing control."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run(args.output_dir.resolve())
    except OSError as error:
        print(f"native probe refused output: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"controls_passed": report["controls_passed"], "profile_qualified": False,
                      "receipt": str(args.output_dir.resolve() / "receipt.json"), "failure": report.get("failure")}))
    return 0 if report["controls_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
