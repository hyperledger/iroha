"""Synthetic indexed Python transcript; no process/native execution or approval.

Builds real bounded archives and original input files around inert native/runtime
bytes and fabricated observations. The adapter tests explicitly mock only clean
candidate selection. This fixture cannot serve as release evidence.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import io
from pathlib import Path
import struct
import zipfile

import sorafs_sdk_python_artifact_verifier as a
from sorafs_python_consumer_artifact import REPORT_PREFIX, canonical_json
from sorafs_python_consumer_cases import expected_node_ids, TEST_PATH
from sorafs_python_dependency_inputs import MODULES, SCHEMA as DEP_SCHEMA
from sorafs_python_runtime_inputs import MAGIC, SCHEMA as RUNTIME_SCHEMA
from sorafs_python_dependency_install_test import original_wheel, record_bytes

ROOT = Path(__file__).resolve().parents[2]
WORK = Path("/observed/source/target/python")
ENV = WORK / "environment"
COMMIT, SOURCE_DIGEST = "a" * 40, "b" * 64


def seal(raw, inode):
    return f"{hashlib.sha256(raw).hexdigest()}:1:{inode}:{len(raw)}:1:1:0o600"


def archive_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for entry, raw in entries:
            archive.writestr(entry, raw)
    return output.getvalue()


def install(harness, entries, wheel, path, raw):
    dist = wheel.dist_info_root
    values = {entry.filename: body for entry, body in entries if not entry.is_dir() and entry.filename != dist + "/RECORD"}
    values.update({dist + "/INSTALLER": b"pip\n", dist + "/REQUESTED": b"",
                   dist + "/direct_url.json": canonical_json({"archive_info": {"hashes": {"sha256": a.identity(raw)["sha256"]}}, "url": path.as_uri()})})
    for name in getattr(wheel, "console_scripts", ()):
        values["../../../bin/" + name] = b"# inert generated script\n"
    values[dist + "/RECORD"] = record_bytes(harness, values, dist + "/RECORD")
    return {(name.removeprefix("../../../") if name.startswith("../../../") else a.SITE + name): body for name, body in values.items()}


def fixture(harness, temporary):
    members, originals, environment = {}, {}, {}
    parsed_wheels, contents, paths, seals = [], [], [], []
    with a.OriginalInputs() as trusted:
        sources = a.source_snapshot(ROOT, trusted)
        members.update({"snapshot/" + name: raw for name, raw in sources.items()})
        members.update({"tools/" + name: trusted.read(ROOT / "scripts" / name, 1024 * 1024) for name in a.TOOLS})
        for number, owner in enumerate((a.verifier.NATIVE_OWNER, a.verifier.SDK_OWNER)):
            example = harness["valid_entries"]() if number == 0 else harness["sdk_entries"]
            entries = [harness["member"](entry.filename.replace("-0.0.0.", "-0.0.1."), raw.replace(b"0.0.0", b"0.0.1"))
                       for entry, raw in example if ".dist-info/" in entry.filename and not entry.filename.endswith("/RECORD")]
            root = ROOT / "python" / owner.package / "src" / owner.package
            for path in sorted(root.rglob("*")):
                if path.is_file() and (path.suffix == ".py" or path.name == "py.typed" or path.relative_to(root).as_posix() == "examples/connect_app_metadata.json"):
                    entries.append(harness["member"](owner.package + "/" + path.relative_to(root).as_posix(), path.read_bytes()))
            if number == 0:
                entries.append(harness["member"]("iroha_native/_crypto.abi3.so", b"inert non-executable native control"))
            entries = harness["with_record"](entries, owner.package + "-0.0.1.dist-info/RECORD")
            raw = archive_bytes(entries)
            wheel = a.verifier.parse_wheel_bytes(raw, owner=owner, extension_suffixes=(".abi3.so",))
            selected = a.authenticate_package_source(wheel, ROOT, trusted)
            members.update({"package-source/" + name: body for name, body in selected.items()})
            name = owner.package + ".whl"; path = WORK / "wheels" / name
            originals[name] = raw
            installed = install(harness, entries, wheel, path, raw)
            environment.update(installed)
            content = a.verifier.verify_installed_wheel_bytes(wheel, source_uri=path.as_uri(), wheel_sha256=a.identity(raw)["sha256"],
                installed_files={key.removeprefix(a.SITE): body for key, body in installed.items()})
            parsed_wheels.append(wheel); contents.append(content); paths.append(path); seals.append(seal(raw, number + 10))
    dependency_rows, archives, dep_paths = [], [], {}
    for module in MODULES:
        archive, entries = original_wheel(harness, temporary, module)
        dep_paths[module] = WORK / "wheels" / (module + ".whl")
        originals[module + ".whl"] = archive.raw
        dependency_rows.append({"module": module, "version": archive.wheel.version, "file": asdict(archive.wheel.file)})
        archives.append(archive)
        environment.update(install(harness, entries, archive, dep_paths[module], archive.raw))
    dep_raw = canonical_json({"schema": DEP_SCHEMA, "wheels": dependency_rows})
    executable = b"inert selected interpreter"
    stdlib = {"encodings/__init__.py": b"encodings", "os.py": b"os", "site.py": b"site", "sysconfig.py": b"sysconfig"}
    runtime_raw = canonical_json({"schema": RUNTIME_SCHEMA, "platform": "darwin", "version": "3.12.14",
        "executable": {"path": "/selected/runtime/bin/python3.12", **a.identity(executable)}, "shared_runtime": [],
        "stdlib": {"root": "/selected/runtime/lib/python3.12", "files": [{"path": name, **a.identity(raw)} for name, raw in sorted(stdlib.items())], "directories": ["encodings"], "links": []},
        "stdlib_zip": {"path": "/selected/runtime/lib/python312.zip", "sha256": None, "size": None}, "site_packages": {"kind": "absent", "target": None}})
    runtime = a.parse_runtime_manifest(runtime_raw, expected_sha256=a.identity(runtime_raw)["sha256"])
    bundle = MAGIC + struct.pack(">Q", len(runtime_raw)) + runtime_raw + executable + b"".join(raw for _, raw in sorted(stdlib.items()))
    for name in ("python", "python3", "python3.12"): environment["bin/" + name] = executable
    for name in ("activate", "activate.csh", "activate.fish", "Activate.ps1"): environment["bin/" + name] = b"# inert generated activation\n"
    environment["pyvenv.cfg"] = ("home = /selected/runtime/bin\ninclude-system-site-packages = false\nversion = 3.12.14\nexecutable = /selected/runtime/bin/python3.12\ncommand = /selected/runtime/bin/python3.12 -m venv --copies --without-pip " + str(ENV) + "\n").encode()
    installed = a.verify_dependency_install(tuple(archives), environment, environment=ENV, wheel_paths_by_module=dep_paths, native_sdk_content=tuple(contents))
    source_rows = [{"path": name, **a.identity(raw)} for name, raw in sources.items()]
    child_input = {"schema": a.child.INPUT_SCHEMA, "snapshot_root": str(WORK / "snapshot"), "environment_root": str(ENV),
        "native_wheel": {"path": str(paths[0]), "seal": seals[0]}, "sdk_wheel": {"path": str(paths[1]), "seal": seals[1]},
        "source_files": source_rows, "python": {"path": str(ENV / "bin/python3.12"), **a.identity(executable)}}
    input_raw = canonical_json(child_input)
    observations = []
    for number, (wheel, content) in enumerate(zip(parsed_wheels, contents, strict=True)):
        files = [{"path": str(ENV / a.SITE / member.name), "seal": seal(environment[a.SITE + member.name], 100 + number * 1000 + offset)} for offset, member in enumerate(content.files)]
        modules = []
        for member in (wheel.package_member, wheel.native_member if number == 0 else "iroha_python/sorafs.py"):
            name = wheel.owner.package if member == wheel.package_member else wheel.owner.package + ("._crypto" if number == 0 else ".sorafs")
            modules.append({"name": name, "member": member, "path": str(ENV / a.SITE / member), **a.identity(environment[a.SITE + member]), "loader": "ExtensionFileLoader" if name == "iroha_native._crypto" else "SourceFileLoader"})
        observations.append({"owner": wheel.owner.package, "path": str(paths[number]), "seal": seals[number], "version": "0.0.1", "installed_files": files, "loaded_modules": sorted(modules, key=lambda row: row["name"])})
    source_deps = []
    for name, prefix, suffix in (("norito", "python/norito_py/src", "norito/__init__.py"), ("iroha_torii_client", "python/iroha_torii_client", "__init__.py")):
        root = WORK / "snapshot" / prefix
        source_deps.append({"module": name, "root": str(root), "loaded_modules": [{"name": name, "path": str(root / suffix), **a.identity(sources[prefix + "/" + suffix]), "loader": "SourceFileLoader"}]})
    report = {"schema": "sorafs.python.reference_child_report.v1", "input_sha256": a.identity(input_raw)["sha256"], "source_files": source_rows,
        "python": {**child_input["python"], "version": "3.12.14"}, "pytest": {"path": str(ENV / a.SITE / "pytest/__init__.py"), **a.identity(environment[a.SITE + "pytest/__init__.py"]), "version": "9.0.3"},
        "wheels": observations, "dependencies": source_deps, "cases": [{"nodeid": name, "phases": [{"phase": phase, "outcome": "passed"} for phase in ("setup", "call", "teardown")]} for name in expected_node_ids(sources[TEST_PATH])], "captured_output": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}}
    native_body = a.native_member(originals["iroha_native.whl"], parsed_wheels[0])
    native_raw = a.native.canonical_manifest_bytes({"schema": a.native.SCHEMA, "sdk": "python", "target": "aarch64-apple-darwin", "artifact_sha256": a.identity(native_body)["sha256"], "artifact_size": len(native_body), "bridge_abi_version": 31,
        "source_commit": COMMIT, "source_tree_clean": True, "workspace_source_manifest_sha256": SOURCE_DIGEST, "required_symbols": list(a.native.REQUIRED_SYMBOLS["python"]), "privacy_c_exports": [], "privacy_c_exports_inspected": False})
    members.update({"environment/" + name: raw for name, raw in environment.items()})
    for wheel in parsed_wheels:
        for name in ("RECORD", "direct_url.json"):
            member = wheel.dist_info_root + "/" + name
            members["installed-metadata/" + member] = environment[a.SITE + member]
    members.update({"inputs/runtime.json": runtime_raw, "inputs/dependencies.json": dep_raw, "inputs/native-abi31.json": native_raw, "inputs/child.json": input_raw,
        "inputs/requirements.txt": a.pinned_requirements([(p, a.verifier.FileSeal.parse(s).sha256) for p, s in zip(paths, seals, strict=True)] + [(dep_paths[x.wheel.module], x.wheel.file.sha256) for x in archives]), "child-report.json": canonical_json(report)})
    catalog = a.execution_commands(source_root=WORK.parent.parent, work=WORK, runtime=runtime, pip_filename="pip.whl", native_filename="_crypto.abi3.so")
    commands = []
    for command in catalog:
        output = b""
        if command.label in ("runtime-before", "environment-before", "environment-after"):
            private = command.label != "runtime-before"
            output = canonical_json({"platform": "darwin", "implementation": "cpython", "version": runtime.version,
                "executable": str(ENV / "bin/python3.12") if private else runtime.executable.path, "base_executable": runtime.executable.path,
                "prefix": str(ENV) if private else "/selected/runtime", "base_prefix": "/selected/runtime", "stdlib": runtime.stdlib_root,
                "shared_runtime": runtime.executable.path, "isolated": 1, "no_site": 0 if private else 1, "no_bytecode": True,
                "path": [runtime.zip_path, runtime.stdlib_root, runtime.stdlib_root + "/lib-dynload"] + ([str(ENV / a.SITE.rstrip("/"))] if private else [])})
        elif command.label == "execute": output = REPORT_PREFIX + base64.b64encode(canonical_json(report)) + b"\n"
        elif command.label == "installed-distributions":
            versions = {x.wheel.module: x.wheel.version for x in archives}; versions.update({p.owner.distribution: "0.0.1" for p in parsed_wheels})
            output = canonical_json({"distributions": [{"module": name, "version": version, "root": str(ENV / a.SITE.rstrip("/"))} for name, version in sorted(versions.items())]})
        members["logs/" + command.label + ".stdout"] = output
        members["logs/" + command.label + ".stderr"] = b""
        commands.append({"label": command.label, "argv": list(command.argv), "returncode": 0, "stdout": a.identity(output), "stderr": a.identity(b"")})
    manifest = {"schema": a.SCHEMA, "consumer": "python", "scope": "posix-host-native", "source_commit": COMMIT, "source_manifest_sha256": SOURCE_DIGEST,
        "runtime_manifest": a.identity(runtime_raw), "dependency_manifest": a.identity(dep_raw), "runtime_bundle": a.identity(bundle), "native_manifest": a.identity(native_raw), "environment_links": {},
        "dependency_files": [asdict(row) for row in installed.files], "wheels": [{"owner": p.owner.package, "path": str(path), "seal": s} for p, path, s in zip(parsed_wheels, paths, seals, strict=True)], "commands": commands}
    originals.update({"runtime.json": runtime_raw, "dependencies.json": dep_raw, "runtime.bundle": bundle, "native.json": native_raw})
    return members, manifest, originals
