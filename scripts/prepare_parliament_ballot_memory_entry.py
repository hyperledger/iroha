#!/usr/bin/env python3
"""Derive a standalone in-memory verification entry without editing frozen inputs.

Python 3.11+, reviewed resource-worker sources and a new explicit output path.
No environment variables, network, builds or root manifest/lock changes. File
retrieval and staging ownership remain outside charged execution. The derived
worker reserves the actual borrowed length before copying into its arena and
publishes fatal debits through a separately counted shared page without output.
It requires separate build and execution evidence and never qualifies production.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = "crates/iroha_parliament_ballot_proof/examples/resource_contract"
PROBE = "crates/iroha_parliament_ballot_proof/examples/memory_entry"
FROZEN = "docs/validation/parliament_ballot_resource_contract/build-source.sha256"
PACKAGE = "parliament-memory-entry"


def digest(path: Path) -> str:
    """Identify exact source bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive_workspace(source: str) -> str:
    """Replace file retrieval with one lifetime-bounded borrowed-slice copy.

    The original allocator routing, reservation, supplied stack, join and cleanup
    remain intact. Fatal exhaustion now publishes to shared control before exit.
    This is a new worker; no old evidence transfers to it.
    """
    changes = [
        ("    ffi::OsStr,\n    fs::OpenOptions,\n    io::Read,\n    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},\n    path::Path,\n", ""),
        ("AtomicBool, AtomicPtr, AtomicU64, Ordering", "AtomicBool, AtomicPtr, Ordering"),
        ("static CHARGED_UNITS: AtomicU64 = AtomicU64::new(0);\nstatic CHARGED_BYTES: AtomicU64 = AtomicU64::new(0);\n", ""),
        ("    CHARGED_UNITS.store(0, Ordering::Relaxed);\n    CHARGED_BYTES.store(0, Ordering::Relaxed);\n", ""),
        ("    CHARGED_UNITS.store(charge.verification_units, Ordering::Relaxed);\n    CHARGED_BYTES.store(charge.input_bytes, Ordering::Relaxed);", "    super::fatal::admit(charge.verification_units, charge.input_bytes);"),
        ("    pub workspace_reserved_bytes: usize,", "    pub workspace_reserved_bytes: usize,\n    pub fatal_control_reserved_bytes: usize,"),
        ("    let mapping = native::Mapping::new(options.heap_limit)?;", "    let fatal_control_reserved_bytes = super::fatal::reserved_bytes()\n        .map_err(|error| native::NativeError(error.0, error.1))?;\n    let mapping = native::Mapping::new(options.heap_limit)?;\n    let workspace_reserved_bytes = mapping.length().checked_add(fatal_control_reserved_bytes)\n        .filter(|bytes| *bytes <= native::WORKSPACE_LIMIT)\n        .ok_or(native::NativeError(\"workspace_with_fatal_control\", 0))?;"),
        ("    let workspace_reserved_bytes = mapping.length();\n", ""),
        ("            workspace_reserved_bytes,", "            workspace_reserved_bytes,\n            fatal_control_reserved_bytes,"),
        ("    pub path: &'a Path,", "    /// Immutable caller bytes retained until the synchronous worker join.\n    pub record: &'a [u8],"),
        ("    path: [u8; 4096],\n    path_length: usize,", "    // Derived from the same borrowed slice in run; never supplied separately.\n    record: *const u8,\n    record_length: usize,"),
        ("    if options.path.as_os_str().as_bytes().len() > 4096 || options.heap_limit > HEAP_BYTES {", "    if options.heap_limit > HEAP_BYTES {"),
        ("    let mut path = [0u8; 4096];\n    let path_bytes = options.path.as_os_str().as_bytes();\n    path[..path_bytes.len()].copy_from_slice(path_bytes);\n", ""),
        ("    // SAFETY: the fixed control partition is aligned and large enough, and all\n    // Request fields are fixed-size; no external caller input buffer is retained.", "    // SAFETY: the fixed control partition is aligned and large enough for\n    // Request. Its read-only pointer is derived from options.record; that\n    // borrow remains valid until run returns after joining any started worker."),
        ("            path,\n            path_length: path_bytes.len(),", "            record: options.record.as_ptr(),\n            record_length: options.record.len(),"),
        ("    let mut result = ResultState::failure(\"input_error\", \"read\", 3);", "    let mut result = ResultState::failure(\"worker_error\", \"not_verified\", 4);"),
        ("    if file.read_exact(&mut record).is_err() || !matches!(file.read(&mut [0u8; 1]), Ok(0)) {\n        return result;\n    }", "    // SAFETY: run derived pointer and length from one live immutable slice;\n    // it cannot return before this worker joins. reserve checked the actual\n    // length before ACTIVE and before this owned arena copy. The borrowed\n    // caller capacity is never adopted by the arena.\n    let staged = unsafe { std::slice::from_raw_parts(request.record, length) };\n    record.copy_from_slice(staged);"),
    ]
    for old, new in changes:
        if source.count(old) != 1:
            raise ValueError("reviewed workspace anchor changed: " + old.splitlines()[0])
        source = source.replace(old, new)
    fatal_begin = source.index("fn exhausted() -> ! {")
    fatal_end = source.index("#[derive(Clone, Copy)]\npub struct Options", fatal_begin)
    fatal_old = source[fatal_begin:fatal_end]
    if (fatal_old.count("libc::write(") != 1 or fatal_old.count("libc::_exit(73)") != 1
            or fatal_old.count("fn decimal(") != 1 or fatal_old.count("fn append(") != 1):
        raise ValueError("reviewed exhaustion block changed")
    source = source[:fatal_begin] + "fn exhausted() -> ! {\n    super::fatal::exhausted()\n}\n\n" + source[fatal_end:]
    test_begin = source.index("    #[test]\n    fn exhaustion_decimal_writer_is_bounded_and_exact()")
    test_end = source.index("    #[test]\n    fn operational_failures_are_never_invalid_proofs()", test_begin)
    source = source[:test_begin] + source[test_end:]
    begin = source.index("fn execute(request: &Request) -> ResultState {\n") + len("fn execute(request: &Request) -> ResultState {\n")
    end = source.index("    let mut budget = Budget::new(request.units, request.input_bytes);", begin)
    retrieval = source[begin:end]
    if (not retrieval.startswith("    let path = Path::new(OsStr::from_bytes(")
            or retrieval.count("OpenOptions::new()") != 1 or retrieval.count("file.metadata()") != 1
            or retrieval.count("usize::try_from(metadata.len())") != 1):
        raise ValueError("reviewed execute retrieval block changed")
    source = source[:begin] + "    let length = request.record_length;\n" + source[end:]
    execute = source[begin:source.index("fn classify(", begin)]
    if any(word in execute for word in ("file.", "OpenOptions", "read_exact", "Path::", "metadata()")):
        raise ValueError("retrieval remained inside charged worker")
    if not (execute.index("budget.reserve(length)") < execute.index("super::fatal::admit(")
            < execute.index("ACTIVE.store(true")
            < execute.index("vec![0u8; length]") < execute.index("record.copy_from_slice(staged)")
            < execute.index("reservation.verify(")):
        raise ValueError("reservation/copy/verification ordering changed")
    return source


def manifest(root: Path) -> str:
    """Mirror repository dependency overrides without changing their ownership."""
    text = f'''[package]
name = "{PACKAGE}"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[features]
default = []
accel = ["iroha_parliament_ballot_proof/accel"]

[[bin]]
name = "{PACKAGE}"
path = "driver.rs"

[dependencies]
'''
    for name in ("iroha_parliament_ballot_proof", "iroha_zkp_vole", "norito"):
        options = ', features = ["json"], default-features = false' if name == "norito" else ""
        # The driver selects either row, so it needs the diagnostic comparator row.
        if name == "iroha_parliament_ballot_proof":
            options = ', features = ["diagnostics"]'
        text += f'{name} = {{ path = {json.dumps(str(root / "crates" / name))}{options} }}\n'
    text += 'libc = "0.2.177"\nthiserror = "2.0"\nsha3 = { version = "0.10.8", default-features = false, features = ["std"] }\n\n[patch.crates-io]\n'
    for name, value in tomllib.loads((root / "Cargo.toml").read_text())["patch"]["crates-io"].items():
        if set(value) != {"path"}:
            raise ValueError("unreviewed root patch kind")
        text += f'{name} = {{ path = {json.dumps(str((root / value["path"]).resolve()))} }}\n'
    return text


def prepare(output: Path, root: Path = ROOT) -> dict:
    """Prepare once and retain exact derivation and source identities."""
    if output.exists():
        raise ValueError("output must be a new directory")
    frozen = {name: value for value, name in (line.split("  ", 1) for line in (root / FROZEN).read_text().splitlines())}
    required = [f"{RESOURCE}/{name}.rs" for name in ("arena", "budget", "native", "workspace")]
    for name in required:
        if digest(root / name) != frozen.get(name):
            raise ValueError("frozen source changed: " + name)
    required += [f"{PROBE}/{name}.rs" for name in ("driver", "staging", "fatal")]
    required += ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/prepare_parliament_ballot_memory_entry.py"]
    sources = {name: digest(root / name) for name in required}
    output.mkdir(parents=True)
    for name in ("driver", "staging", "fatal"):
        (output / f"{name}.rs").write_bytes((root / PROBE / f"{name}.rs").read_bytes())
    driver = (output / "driver.rs").read_text()
    for name in ("arena", "budget", "native"):
        anchor = f'"../resource_contract/{name}.rs"'
        if driver.count(anchor) != 1:
            raise ValueError("driver path anchor changed")
        driver = driver.replace(anchor, json.dumps(str(root / RESOURCE / f"{name}.rs")))
    (output / "driver.rs").write_text(driver)
    original = (root / RESOURCE / "workspace.rs").read_text()
    derived = derive_workspace(original)
    (output / "generated_workspace.rs").write_text(derived)
    (output / "workspace.diff").write_text("".join(difflib.unified_diff(original.splitlines(True), derived.splitlines(True), fromfile="frozen-workspace.rs", tofile="memory-entry-workspace.rs")))
    (output / "Cargo.toml").write_text(manifest(root))
    for name in ("Cargo.lock", "root-Cargo.lock.template"):
        (output / name).write_bytes((root / "Cargo.lock").read_bytes())
    after = {name: digest(root / name) for name in required}
    report = {"schema": "parliament-memory-entry-preparation-v1", "source_files": sources,
              "source_changes": {name: [before, after[name]] for name, before in sources.items() if after[name] != before},
              "generated_files": {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()},
              "root": str(root), "output": str(output), "root_lock_modified": False,
              "profile_qualified": False, "complete_workspace_certificate": False}
    (output / "preparation.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["source_changes"]:
        raise ValueError("source changed during preparation")
    return report


def compare_locks(reference: Path, derived: Path) -> dict:
    """Require package-identity membership, not dependency/feature/build parity."""
    old, new = (tomllib.loads(path.read_text())["package"] for path in (reference, derived))
    identity = lambda package: (package["name"], package["version"], package.get("source"), package.get("checksum"))
    allowed = {identity(package) for package in old}
    extra = [identity(package) for package in new if package["name"] != PACKAGE and identity(package) not in allowed]
    probe = [package for package in new if package["name"] == PACKAGE]
    if extra or len(probe) != 1 or probe[0]["version"] != "0.0.0" or probe[0].get("source"):
        raise ValueError("diagnostic dependency identity drift or invalid diagnostic package")
    return {"original_packages": len(old), "diagnostic_packages": len(new), "unexpected_dependency_identities": extra,
            "reference_sha256": digest(reference), "derived_sha256": digest(derived),
            "comparison_scope": "name/version/source/checksum membership only; not dependency-edge, feature or build parity",
            "profile_qualified": False}


def main() -> int:
    """Prepare a new tree or check its separately resolved lock."""
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--check-lock", nargs=2, type=Path, metavar=("REFERENCE", "DERIVED"))
    args = parser.parse_args()
    try:
        report = compare_locks(*args.check_lock) if args.check_lock else prepare(args.output.resolve())
        print(json.dumps(report, indent=2))
        return 0
    except (ValueError, OSError) as error:
        print(json.dumps({"failure": str(error), "profile_qualified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
