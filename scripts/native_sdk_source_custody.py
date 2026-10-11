"""Repository-owned current Native SDK source and actual dep-info custody contract.

Input metadata and compiler receipts are data only; no external Python
controller is executed.
"""
import hashlib
import json
import argparse
import os
import tomllib
from pathlib import Path

SUPPORTED_GIT_SOURCES = {
    "git+https://github.com/zcash/orchard.git?rev=9d07047d32c4787e1b7964b4cf4fa0286c93824c#9d07047d32c4787e1b7964b4cf4fa0286c93824c",
}

EXCLUDED_OUTPUT_DIRECTORIES = {".git", "__pycache__"}
NATIVE_PACKAGE_OWNERS = {"connect_norito_bridge", "iroha_js_host"}
EXPLICIT_NATIVE_INPUTS = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml",
    ".cargo/iroha-fast", "scripts/cargo_fast.sh", "codec/rans/tables/rans_seed0.toml",
    "scripts/norito_schema_capture/derive_probe.rs", "artifacts/poseidon/constants.ron",
}
RUNTIME_INPUT_PREFIXES = ("fixtures/", "data_model/", "tests/interop/",
                          "crates/connect_norito_bridge/include/", "crates/soranet_pq/include/")


# cc/PQClean native inputs are not enumerated by rustc's Make dep-info. Bind
# their complete captured package-owned source/recipe sets conservatively.
NATIVE_BUILD_INPUT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++",
    ".s", ".asm", ".inc", ".inl", ".metal", ".cu", ".cuh", ".m", ".mm",
    ".sh", ".py", ".pl", ".pm", ".cmake", ".mk", ".make", ".in",
    ".def", ".map", ".ld", ".lds", ".a", ".o", ".obj", ".lib", ".ptx", ".air", ".metallib",
}
NATIVE_BUILD_INPUT_NAMES = {
    "Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "configure", "config.guess", "config.sub",
}
# These current build scripts read data without a Rust include, so rustc .d
# alone does not bind them. Other include_str!/include! assets remain in .d.
PACKAGE_BUILD_DATA_INPUTS = {
    "ivm": {"spec/syscalls.toml"},
    "kotodama_lang": {"grammar/v1.lex", "src/i18n/translations/messages.v1.tsv"},
    "oid-registry": {"assets/oid_db.txt"},
}


def native_build_input_keys(packages, seen, root, names):
    """Select native originals and current build recipes in the exact metadata graph.

    Use captured key names only; no generated Cargo output or private helper is
    adopted. Selecting both original and current sets binds additions/removals.
    """
    prefixes, explicit = [], set()
    for identifier in seen:
        package = packages[identifier]
        manifest = original_file(Path(package["manifest_path"]))
        if manifest.is_relative_to(root):
            prefix = str(manifest.parent.relative_to(root))
            prefix = prefix + "/" if prefix != "." else ""
        else:
            kind = "registry:" if package["source"].startswith("registry+") else "git:"
            prefix = kind + str(manifest.parent) + "/"
        prefixes.append(prefix)
        explicit.update(prefix + name for name in PACKAGE_BUILD_DATA_INPUTS.get(package["name"], ()))
        for target in package.get("targets", ()):
            if target.get("kind") == ["custom-build"]:
                path = original_file(Path(target["src_path"]))
                if not path.is_relative_to(manifest.parent):
                    raise RuntimeError("Custom-build source is outside its selected package owner")
                explicit.add(prefix + str(path.relative_to(manifest.parent)))
    return {name for name in names
            if name in explicit or (any(name.startswith(prefix) and (prefix or not name.startswith(("registry:", "git:")))
                                            for prefix in prefixes)
                                    and (Path(name).suffix.lower() in NATIVE_BUILD_INPUT_SUFFIXES
                                         or Path(name).name in NATIVE_BUILD_INPUT_NAMES))}


def consumed_source_projection(metadata, root, originals, current, receipts,
                               selected_package="connect_norito_bridge"):
    """Bind actual compiler inputs plus fixed manifest/config/runtime dependencies.

    Call only after complete retained dep-info verification. Broad original capture
    remains immutable evidence; changes outside this projection are diagnostics,
    never a claim that the historical broad snapshot equals the current tree.
    This contract qualifies local units only, never release source provenance.
    """
    if selected_package not in NATIVE_PACKAGE_OWNERS:
        raise RuntimeError("Unreviewed native package owner")
    if metadata.get("workspace_root") != str(root):
        raise RuntimeError("Actual Cargo metadata names a different workspace")
    packages, _, seen, _ = closure(metadata, {selected_package})
    explicit = set(EXPLICIT_NATIVE_INPUTS)
    for identifier in seen:
        package = packages[identifier]
        manifest = original_file(Path(package["manifest_path"]))
        if manifest.is_relative_to(root):
            explicit.add(str(manifest.relative_to(root)))
        else:
            kind = "registry:" if package["source"].startswith("registry+") else "git:"
            explicit.add(kind + str(manifest))
    consumed = {row["path"] for receipt in receipts for item in receipt["dep_info"]
                for row in item["matched_originals"]}
    native_inputs = native_build_input_keys(packages, seen, root, originals.keys() | current.keys())
    expected = {name: sha for name, sha in originals.items()
                if name in consumed or name in explicit or name in native_inputs
                or name.startswith(RUNTIME_INPUT_PREFIXES)}
    observed = {name: sha for name, sha in current.items()
                if name in consumed or name in explicit or name in native_inputs
                or name.startswith(RUNTIME_INPUT_PREFIXES)}
    if not expected or expected != observed or not consumed <= expected.keys():
        changes = sorted(name for name in expected.keys() | observed.keys()
                         if expected.get(name) != observed.get(name))
        raise RuntimeError("Current compiler/runtime/manifest source custody differs: " + ", ".join(changes[:12]))
    return expected

def _source_directories(names, current, package_root, root, metadata):
    """Prune owned Cargo outputs by path, retaining nested source `target` namespaces."""
    output_roots = {root / "target", Path(metadata["target_directory"])}
    if package_root is not None:
        output_roots.add(package_root / "target")
    return sorted(name for name in names
                  if name not in EXCLUDED_OUTPUT_DIRECTORIES
                  and current / name not in output_roots)

# Capture the complete actual declared Bridge graph, including its canonical iroha SDK owner.

def original_directory(path):
    """Reject every lexical alias before a source owner is walked or resolved."""
    path = Path(path)
    if not path.is_absolute():
        raise RuntimeError("Source owner must be absolute")
    for owner in (path, *path.parents):
        if owner.is_symlink() or not owner.is_dir():
            raise RuntimeError("Source owner traverses an alias or non-directory")
    return path


def original_file(path):
    """Authenticate a real source leaf and its complete lexical ancestry."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Input is not an original regular file")
    original_directory(path.parent)
    return path


def closure(metadata, selected_names):
    packages={p["id"]:p for p in metadata["packages"]}
    nodes={n["id"]:n for n in metadata["resolve"]["nodes"]}
    selected={i for i in metadata["workspace_members"] if packages[i]["name"] in selected_names}
    if {packages[i]["name"] for i in selected} != selected_names:
        raise RuntimeError("Actual selected package roots disagree")
    seen=set(selected);pending=list(selected)
    while pending:
        for dep in nodes[pending.pop()]["deps"]:
            if dep["pkg"] not in seen:
                seen.add(dep["pkg"]);pending.append(dep["pkg"])
    local={i for i in seen if packages[i]["source"] is None}
    return packages, selected, seen, local

def source_identity(metadata, root, selected_names, digest):
    root = original_directory(root)
    packages,selected,seen,local=closure(metadata,selected_names)
    lock_path = original_file(root / "Cargo.lock")
    lock_bytes = lock_path.read_bytes()
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    locked = tomllib.loads(lock_bytes.decode("utf-8"))
    locked_external_owners = {
        (package["name"], package["version"], package["source"])
        for package in locked.get("package", []) if package.get("source")
    }
    paths=set()
    # Exact root-outside originals read by actual Crypto SM2/SoraNet units,
    # plus retained Primitives/Norito documentation and rANS input custody.
    # Local captured schema, diagnostic TSVs and PQ vectors are captured below.
    for relative in ['norito.md', 'scripts/norito_schema_capture/derive_probe.rs', 'codec/rans/tables/rans_seed0.toml', 'artifacts/poseidon/constants.ron', 'fixtures/sm/sm2_fixture.json', 'tests/interop/soranet/interop/rust/snnet-interop-nk2-v1.json', 'tests/interop/soranet/interop/rust/snnet-interop-nk3-v1.json']:
        p=root/relative
        if p.is_symlink() or not p.is_file():
            raise RuntimeError("Declared public outside-package input custody changed")
        paths.add(original_file(p))
    for relative in ["Cargo.toml","Cargo.lock","rust-toolchain.toml",".cargo/config",".cargo/config.toml", ".cargo/iroha-fast", "scripts/cargo_fast.sh"]:
        p=root/relative
        if p.is_file():
            if p.is_symlink():raise RuntimeError("Global Cargo input is a symlink")
            paths.add(original_file(p))
    for identifier in local:
        directory=original_directory(Path(packages[identifier]["manifest_path"]).parent)
        if not directory.is_relative_to(root) or directory.is_symlink():
            raise RuntimeError("Local source owner is outside exact worktree or symlinked")
        for current, dirs, files in os.walk(directory,followlinks=False):
            owner=Path(current)
            dirs[:] = _source_directories(dirs, owner, directory, root, metadata)
            for name in dirs:
                if (owner/name).is_symlink():raise RuntimeError("Local input directory is symlinked")
            for name in files:
                p=owner/name
                if p.is_symlink() or not p.is_file():raise RuntimeError("Local input is not a regular retained file")
                paths.add(original_file(p))
    # All public workspace fixture files are actual outside-package inputs used
    # across the default Model whole library (including privacy exact12 and mobile).
    for relative in ["fixtures", "data_model", "tests/interop"]:
        for current, dirs, files in os.walk(root/relative, followlinks=False):
            owner=Path(current)
            dirs[:] = _source_directories(dirs, owner, None, root, metadata)
            for name in dirs:
                if (owner/name).is_symlink():raise RuntimeError("Outside fixture directory is symlinked")
            for name in files:
                p=owner/name
                if p.is_symlink() or not p.is_file():raise RuntimeError("Outside fixture is not a regular retained file")
                paths.add(original_file(p))
    values = {str(p.relative_to(root)):digest(p) for p in sorted(paths)}
    # Conservatively traverse EVERY metadata dependency edge, including transitive dev.
    # Registry source bytes are original inputs, separate from emitted generated outputs.
    for identifier in sorted(seen):
        package = packages[identifier]
        if package["source"] is None:
            continue
        source = package["source"]
        if source == "registry+https://github.com/rust-lang/crates.io-index":
            key_kind = "registry:"
        elif source in SUPPORTED_GIT_SOURCES:
            key_kind = "git:"
        else:
            raise RuntimeError("Unreviewed external source identity")
        if (package["name"], package["version"], source) not in locked_external_owners:
            raise RuntimeError("External metadata owner is absent from the actual Cargo.lock")
        directory = original_directory(Path(package["manifest_path"]).parent)
        for current, dirs, files in os.walk(directory, followlinks=False):
            owner = original_directory(Path(current))
            dirs[:] = _source_directories(dirs, owner, directory, root, metadata)
            for name in dirs:
                original_directory(owner / name)
            for name in sorted(files):
                path = original_file(owner / name)
                values[key_kind + str(path)] = digest(path)
    if values.get("Cargo.lock") != lock_sha256 or digest(lock_path) != lock_sha256:
        raise RuntimeError("Cargo.lock changed during prospective source capture")
    return values


def capture(metadata, root, digest, selected_package="connect_norito_bridge"):
    """Capture a fixed native package owner's graph and all declared original inputs."""
    if selected_package not in NATIVE_PACKAGE_OWNERS:
        raise RuntimeError("Unreviewed native package owner")
    if metadata.get("workspace_root") != str(root):
        raise RuntimeError("Actual Cargo metadata names a different workspace")
    return source_identity(metadata, root, {selected_package}, digest)


def make_words(text):
    """Decode rustc escaped Make words without shell or executable evaluation."""
    words, current, escaped = [], [], False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)
    if escaped:
        raise RuntimeError("Unterminated dep-info escape")
    if current:
        words.append("".join(current))
    return words


def cargo_messages(text, object_pairs_hook=None):
    """Read actual Cargo JSON, retaining only the known preceding wrapper diagnostics."""
    messages = []
    for line in text.splitlines():
        if not messages and line.startswith("[cargo-fast] "):
            continue
        if not line.strip():
            continue
        value = json.loads(line, object_pairs_hook=object_pairs_hook)
        if not isinstance(value, dict) or not isinstance(value.get("reason"), str):
            raise RuntimeError("Cargo output contains a non-message value")
        messages.append(value)
    if (not messages or messages[-1] != {"reason": "build-finished", "success": True}
            or sum(item.get("reason") == "build-finished" for item in messages) != 1):
        raise RuntimeError("Cargo output lacks one successful natural terminal")
    return messages


def dep_info_names(message):
    """Derive exact permitted rustc dep-info owners from original Cargo JSON."""
    names = set()
    for filename in message["filenames"]:
        path = Path(filename)
        if path.suffix in {".rlib", ".rmeta", ".a", ".so", ".dylib"}:
            names.add(path.with_name(path.stem.removeprefix("lib") + ".d"))
            compiled = path.parent / "deps" / path.name
            names.add(compiled.with_name(compiled.stem.removeprefix("lib") + ".d"))
        elif path.suffix == ".d":
            names.add(path)
        else:
            names.add(Path(str(path) + ".d"))
        if message["target"]["kind"] == ["custom-build"]:
            suffix = path.parent.name.rsplit("-", 1)[-1]
            if path.name != "build-script-build" or len(suffix) != 16 or any(c not in "0123456789abcdef" for c in suffix):
                raise RuntimeError("Custom-build owner identity differs")
            names.add(path.parent / ("build_script_build-" + suffix + ".d"))
    return {str(path) for path in names}


def verify_dep_info(messages, receipts, root, originals, output_root, retained_root, digest):
    """Reconcile each actual compiler message with its retained original dep-info.

    Generated OUT_DIR bytes remain actual generated outputs. They never repair
    a missing prospective source original or establish retrospective provenance.
    """
    artifacts = [item for item in messages if item.get("reason") == "compiler-artifact"]
    if len(artifacts) != len(receipts):
        raise RuntimeError("Compiler artifact/dep-info count differs")
    for message, receipt in zip(artifacts, receipts):
        if (receipt.get("package_id") != message["package_id"] or receipt.get("target") != message["target"]
                or not isinstance(receipt.get("dep_info"), list) or not receipt["dep_info"]):
            raise RuntimeError("Compiler artifact/dep-info relationship differs")
        allowed = dep_info_names(message)
        observed = set()
        for item in receipt["dep_info"]:
            actual = item.get("actual_dep_info")
            held = Path(item["retained_dep_info"])
            expected = retained_root / (hashlib.sha256(actual.encode()).hexdigest() + ".d")
            if actual not in allowed or actual in observed or held != expected:
                raise RuntimeError("Retained dep-info owner is not exact")
            observed.add(actual)
            original_file(held)
            if digest(held) != item["sha256"]:
                raise RuntimeError("Retained compiler dep-info changed")
            lines = held.read_text().replace("\\\n", "").splitlines()
            rule = next((line for line in lines if ": " in line), None)
            if rule is None:
                raise RuntimeError("Actual dep-info has no dependency rule")
            names = make_words(rule.split(": ", 1)[1])
            if not names:
                raise RuntimeError("Actual dep-info dependency rule is empty")
            matched, generated = [], []
            for name in names:
                path = Path(name)
                if not path.is_absolute():
                    path = root / path
                original_file(path)
                path = path.resolve(strict=True)
                if path.is_relative_to(root):
                    key = str(path.relative_to(root))
                else:
                    owners = [kind + str(path) for kind in ("registry:", "git:") if kind + str(path) in originals]
                    if len(owners) != 1:
                        raise RuntimeError("External dep-info original is absent or ambiguous: " + str(path))
                    key = owners[0]
                current = digest(path)
                if key in originals:
                    if current != originals[key]:
                        raise RuntimeError("Actual dependency differs from prospective original: " + key)
                    matched.append({"path": key, "sha256": current})
                elif path.is_relative_to(output_root) and "build" in path.parts and "out" in path.parts:
                    generated.append({"path": str(path), "sha256": current,
                                      "custody": "actual generated output; no source-before claim"})
                else:
                    raise RuntimeError("Actual dependency lacks prospective original custody")
            if item.get("matched_originals") != matched or item.get("actual_generated_outputs") != generated:
                raise RuntimeError("Retained dep-info source/generated projection differs")


def dep_files(message):
    """Locate actual emitted artifact dep-info; never scan unrelated target files."""
    found = set()
    for filename in message['filenames']:
        path = Path(filename)
        if path.suffix in {'.rlib', '.rmeta', '.a', '.so', '.dylib'}:
            candidate = path.with_name(path.stem.removeprefix('lib') + '.d')
        elif path.suffix == '.d':
            candidate = path
        else:
            candidate = Path(str(path) + '.d')
        if candidate.is_file() and not candidate.is_symlink():
            found.add(candidate)
    if not found and any(kind in {'rlib', 'cdylib', 'staticlib'} for kind in message['target']['kind']):
        # Cargo reports top-level copied library aliases. The exact same-name deps
        # artifacts retain rustc's dep-info; authenticate both bytes and output rules.
        for filename in message['filenames']:
            alias = Path(filename)
            if alias.suffix not in {'.rlib', '.a', '.so', '.dylib'}:
                continue
            compiled = alias.parent / 'deps' / alias.name
            candidate = compiled.with_name(compiled.stem.removeprefix('lib') + '.d')
            for path in (alias, compiled, candidate):
                if not path.is_file() or any(owner.is_symlink() for owner in (path, *path.parents)):
                    raise RuntimeError('Cargo library alias custody differs')
            def artifact_digest(path):
                owner = hashlib.sha256()
                with path.open('rb') as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        owner.update(chunk)
                return owner.digest()
            if artifact_digest(alias) != artifact_digest(compiled):
                raise RuntimeError('Cargo library alias differs from rustc emitted bytes')
            rules = candidate.read_text().replace('\\\n', '').splitlines()
            outputs = {word for line in rules if ': ' in line
                       for word in make_words(line.split(': ', 1)[0])}
            if str(compiled) not in outputs:
                raise RuntimeError('actual library dep-info lacks exact compiled output owner')
            found.add(candidate)
    if not found and message['target']['kind'] == ['custom-build']:
        # Cargo exposes a copied build-script-build alias, while rustc's dep-info
        # retains its underscore crate name and the exact emitted owner-directory hash.
        for filename in message['filenames']:
            alias = Path(filename)
            suffix = alias.parent.name.rsplit('-', 1)[-1]
            if alias.name != 'build-script-build' or len(suffix) != 16 or any(c not in '0123456789abcdef' for c in suffix):
                raise RuntimeError('custom-build owner identity differs')
            compiled = alias.parent / ('build_script_build-' + suffix)
            candidate = Path(str(compiled) + '.d')
            if alias.is_symlink() or compiled.is_symlink() or not alias.is_file() or not compiled.is_file():
                raise RuntimeError('actual custom-build aliases are not retained originals')
            if hashlib.sha256(alias.read_bytes()).digest() != hashlib.sha256(compiled.read_bytes()).digest():
                raise RuntimeError('Cargo custom-build alias differs from rustc emitted bytes')
            if candidate.is_file() and not candidate.is_symlink():
                found.add(candidate)
    if not found:
        raise RuntimeError('no actual emitted Rust dep-info located')
    return sorted(found)


def reconcile(message, root, source_before, retained, digest, output_root):
    """Report uncovered original inputs as errors, distinguishing generated outputs."""
    receipts = []
    for dep_file in dep_files(message):
        raw = dep_file.read_bytes()
        complete = raw.decode('utf-8').replace('\\\n', '')
        rule = next((line for line in complete.splitlines() if ': ' in line), None)
        if rule is None:
            raise RuntimeError('actual dep-info has no dependency rule')
        names = make_words(rule.split(': ', 1)[1])
        if not names:
            raise RuntimeError('actual dep-info dependency rule is empty')
        matched, generated, uncovered = [], [], []
        for name in names:
            path = Path(name)
            if not path.is_absolute():
                path = root / path
            # Check the compiler's lexical input before resolving it. Resolving first
            # would silently adopt an uncaptured leaf or directory alias as its target.
            if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in path.parents):
                raise RuntimeError('dep-info lexical input traverses a symlink or is not a regular file')
            path = path.resolve(strict=True)
            if path.is_relative_to(root):
                key = str(path.relative_to(root))
            else:
                candidates = [kind + str(path) for kind in ('registry:', 'git:')
                              if kind + str(path) in source_before]
                if len(candidates) > 1:
                    raise RuntimeError('external dep-info original has ambiguous captured ownership')
                key = candidates[0] if candidates else 'uncaptured-external:' + str(path)
            current = digest(path)
            if key in source_before:
                if current != source_before[key]:
                    raise RuntimeError('actual dependency differs from captured original: ' + key)
                matched.append({'path': key, 'sha256': current})
            elif path.is_relative_to(output_root) and 'build' in path.parts and 'out' in path.parts:
                # This is an output of the actual Cargo build, not an unavailable source
                # preimage. It cannot retrospectively qualify any missing original.
                generated.append({'path': str(path), 'sha256': current,
                                  'custody': 'actual generated output; no source-before claim'})
            else:
                uncovered.append({'path': str(path), 'sha256_after_only': current})
        if uncovered:
            raise RuntimeError('original inputs lacked prospective capture: ' + repr(uncovered))
        held = retained / (hashlib.sha256(str(dep_file).encode()).hexdigest() + '.d')
        if held.exists():
            if held.read_bytes() != raw:
                raise RuntimeError('dep-info identity changed in one Cargo emission')
        else:
            held.write_bytes(raw)
        if digest(dep_file) != digest(held):
            raise RuntimeError('actual dep-info changed during capture')
        receipts.append({'actual_dep_info': str(dep_file), 'retained_dep_info': str(held),
                         'sha256': digest(held), 'matched_originals': matched,
                         'actual_generated_outputs': generated})
    return {'package_id': message['package_id'], 'target': message['target'],
            'dep_info': receipts}

def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["capture", "reconcile"], default="capture")
    parser.add_argument("--package", choices=sorted(NATIVE_PACKAGE_OWNERS), default="connect_norito_bridge")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--messages", type=Path)
    parser.add_argument("--source-before", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--retained", type=Path)
    args = parser.parse_args()
    def digest(path):
        value = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(chunk)
        return value.hexdigest()
    original_directory(args.root)
    if args.mode == "capture":
        if args.metadata is None:
            parser.error("capture requires the actual metadata input")
        original_file(args.metadata)
        result = capture(json.loads(args.metadata.read_bytes()), args.root, digest, args.package)
    else:
        if not all([args.messages, args.source_before, args.output_root, args.retained]):
            parser.error("reconcile requires messages, prospective originals, output root and retained directory")
        for path in [args.messages, args.source_before]:
            original_file(path)
        original_directory(args.output_root)
        original_directory(args.retained)
        messages = cargo_messages(args.messages.read_text())
        before = json.loads(args.source_before.read_bytes())
        result = [reconcile(message, args.root, before, args.retained, digest, args.output_root)
                  for message in messages if message.get("reason") == "compiler-artifact"]
        verify_dep_info(messages, result, args.root, before, args.output_root, args.retained, digest)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    cli()
