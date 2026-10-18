#!/usr/bin/env python3
"""Derive a standalone allocation-stream diagnostic without editing frozen inputs.

Python 3.11+, reviewed resource-worker sources and a new explicit output path.
No environment variables, network, builds or root manifest/lock changes. The
derived allocator adds fixed-recorder calls; the separate diagnostic read modes
inject post-reservation failures. These binaries require their own build and
measurement evidence and do not qualify the original worker or production.
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
PROBE = "crates/iroha_parliament_ballot_proof/examples/allocation_trace"
FROZEN = "docs/validation/parliament_ballot_resource_contract/build-source.sha256"
PACKAGE = "parliament-allocation-trace"


def digest(path: Path) -> str:
    """Identify exact source bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive_workspace(source: str, control_path: Path) -> str:
    """Add recorded allocator events and explicit diagnostic interval/read hooks."""
    changes = [
        ("            pointer\n        } else {", "            crate::trace::record_alloc(pointer, layout);\n            pointer\n        } else {"),
        ("            unsafe { (&*arena).release(pointer, layout) };", "            crate::trace::record_free(pointer, layout);\n            unsafe { (&*arena).release(pointer, layout) };"),
        ("    let mapping = native::Mapping::new(options.heap_limit)?;", "    let mapping = native::Mapping::new(options.heap_limit)?;\n    crate::trace::set_base(mapping.arena().cast::<u8>().wrapping_add(native::CONTROL_BYTES));"),
        ("    ACTIVE.store(true, Ordering::Release);", "    crate::trace::begin();\n    ACTIVE.store(true, Ordering::Release);"),
        ("    // All record/statement/verifier/error ownership has ended in execute.\n    ACTIVE.store(false, Ordering::Release);", "    // All record/statement/verifier/error ownership has ended in execute.\n    let trace_was_active = ACTIVE.load(Ordering::Acquire);\n    ACTIVE.store(false, Ordering::Release);\n    if trace_was_active { crate::trace::end(); }"),
        ("    if file.read_exact(&mut record).is_err() || !matches!(file.read(&mut [0u8; 1]), Ok(0)) {", "    if !crate::trace::read_record(&mut file, &mut record) {"),
    ]
    for old, new in changes:
        if source.count(old) != 1:
            raise ValueError("reviewed workspace anchor changed: " + old.splitlines()[0])
        source = source.replace(old, new)
    # The read hook owns the unchanged ordinary File reads in the derived build.
    source = source.replace("    io::Read,\n", "")
    return source + "\n#[path = " + json.dumps(str(control_path)) + "]\nmod trace_controls;\npub use trace_controls::run as run_trace_control;\n"


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
    required += [f"{PROBE}/{name}.rs" for name in ("driver", "trace", "controls")]
    required += ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/prepare_parliament_ballot_allocation_trace.py"]
    sources = {name: digest(root / name) for name in required}
    output.mkdir(parents=True)
    for name in ("driver", "trace", "controls"):
        (output / f"{name}.rs").write_bytes((root / PROBE / f"{name}.rs").read_bytes())
    driver = (output / "driver.rs").read_text()
    for name in ("arena", "budget", "native"):
        anchor = f'"../resource_contract/{name}.rs"'
        if driver.count(anchor) != 1:
            raise ValueError("driver path anchor changed")
        driver = driver.replace(anchor, json.dumps(str(root / RESOURCE / f"{name}.rs")))
    (output / "driver.rs").write_text(driver)
    original = (root / RESOURCE / "workspace.rs").read_text()
    derived = derive_workspace(original, output / "controls.rs")
    (output / "generated_workspace.rs").write_text(derived)
    (output / "workspace.diff").write_text("".join(difflib.unified_diff(original.splitlines(True), derived.splitlines(True), fromfile="frozen-workspace.rs", tofile="allocation-trace-workspace.rs")))
    (output / "Cargo.toml").write_text(manifest(root))
    for name in ("Cargo.lock", "root-Cargo.lock.template"):
        (output / name).write_bytes((root / "Cargo.lock").read_bytes())
    after = {name: digest(root / name) for name in required}
    report = {"schema": "parliament-allocation-trace-preparation-v1", "source_files": sources,
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
