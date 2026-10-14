#!/usr/bin/env python3
"""Audit the selected Cargo build's canonical inputs against its source census.

Run after a successful Cargo build and the caller's source-stability check.
Cargo JSON selects exact per-artifact depfiles, including generated inputs omitted
by Cargo's aggregate .d. The build-script output is the actual included-file
census, not a second reimplementation of the freshness algorithm. External
registry/toolchain inputs are reported, not attested. This script is diagnostic
build correctness tooling; it does not create registry authority.

Requires Python 3.11+ and the successful build's rustc toolchain. With no
--snapshot-tool, the small maintained Rust evaluator is compiled in temporary
storage using that build's host sha2 rlib; no Cargo build or download is run.
RUSTC, when set, selects the same compiler used for the native build.
"""
from pathlib import Path
import argparse, ast, hashlib, json, os, re, shlex, subprocess, tarfile, tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'scripts/native_source_snapshot.rs'
GENERATED = ROOT / 'crates/iroha_plonk/src/keys/keygen/builtin/generated.rs'
BUILD_RS = ROOT / 'crates/iroha_plonk/build.rs'
HELPER = ROOT / 'crates/iroha_plonk/build_support/source_identity.rs'
EXTERNAL_GENERATED = {
    ('crunchy', '0.2.4'): ('lib.rs', ['build.rs'],
        'Selected crates.io crunchy build.rs emits unroll macro arms from its fixed template and Cargo feature-selected limit (64 by default, optional limit_128 through limit_2048). It reads no external source asset; OUT_DIR selects only the output location.'),
    ('serde_core', '1.0.228'): ('private.rs', ['build.rs'],
        'Selected crates.io serde_core build.rs writes its PRIVATE module template with Cargo package patch version 228. Compiler/target probing affects cfg diagnostics, not the generated private.rs bytes.'),
    ('thiserror', '2.0.18'): ('private.rs', ['build.rs', 'build/probe.rs'],
        'Selected crates.io thiserror build.rs writes its PRIVATE module template with Cargo package patch version 18. Its included build/probe.rs and compiler/bootstrap probing select cfgs, not private.rs contents.'),
    ('thiserror', '1.0.69'): (None, ['build.rs', 'build/probe.rs'],
        'Selected crates.io thiserror 1.0.69 build.rs performs a compiler feature probe and removes its transient probe subdirectory. It emits cfg diagnostics only, writes no included Rust source, and therefore authorizes no generated-input exception.'),
    ('serde', '1.0.228'): ('private.rs', ['build.rs'],
        'Selected crates.io serde build.rs emits its fixed PRIVATE module template with package patch version 228 and a serde_core private-module import. Compiler version probing affects cfg diagnostics, not these output bytes.'),
    ('num-bigint', '0.3.3'): ('radix_bases.rs', ['build.rs'],
        'Selected crates.io num-bigint build.rs deterministically emits greatest-radix-power tables for all 16/32/64-bit integer widths. Target pointer width and autocfg probes select consumption/compiler cfgs, not generated table bytes; the complete generated table is independently recomputed here.'),
}
CANONICAL_GENERATED = {
    'connect_norito_bridge': {
        'kagemusha_wallet_runtime_trust.rs': (
            ['build.rs'],
            'Canonical bridge build.rs emits exactly one immutable public authority/key selection from MOBILE_SDK_WALLET_RUNTIME_AUTHORITY and MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX. The emitted selection is recorded; the production build owner separately checks its expected public trust inputs.'),
    },
    'ivm': {
        'iso20022_schema_v1.rs': (
            ['build.rs', 'src/assets/iso20022_schema_v1/schema_v1.tsv'],
            'Canonical IVM build.rs generates the Rust schema from the included canonical TSV asset; no runtime or external asset input.'),
        'syscall_signatures.rs': (
            ['build.rs', 'spec/syscalls.toml'],
            'Canonical IVM build.rs reads the canonical syscall specification and emits sorted register-window metadata; no runtime or external asset input.'),
    },
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolved(path):
    path = Path(path)
    absolute = path if path.is_absolute() else ROOT / path
    lexical = Path(os.path.abspath(absolute))
    canonical = absolute.resolve(strict=True)
    if lexical.is_relative_to(ROOT) and canonical != lexical:
        raise ValueError(f'Canonical compiler input traverses a symlink: {lexical}')
    return canonical


def inputs(depfile, absent_watchers):
    first = depfile.read_text().replace('\\\n', '').splitlines()[0]
    if ': ' not in first:
        raise ValueError(f'unsupported or empty depfile: {depfile}')
    paths = []
    for token in shlex.split(first.split(': ', 1)[1]):
        raw = Path(token)
        raw = raw if raw.is_absolute() else ROOT / raw
        if raw in absent_watchers:
            if raw.exists() or raw.is_symlink():
                raise ValueError(f'Intentionally absent rescan watcher exists: {raw}')
            paths.append(raw)
        else:
            paths.append(resolved(raw))
    if not paths:
        raise ValueError(f'empty depfile: {depfile}')
    return paths


def artifact_depfiles(item):
    candidates = set()
    for name in item['filenames']:
        path = Path(name)
        stem = path.stem if path.suffix else path.name
        if stem.startswith('lib'):
            stem = stem[3:]
        candidate = path.with_name(stem + '.d')
        if candidate.is_file():
            candidates.add(candidate.resolve())
        if path.name == 'build-script-build':
            candidates.update(p.resolve() for p in path.parent.glob('build_script_build-*.d'))
    return candidates


def actual_snapshot(tool):
    """Run only an evaluator pinned to the current maintained helper and driver."""
    record = json.loads(tool.with_name('source-snapshot-build.json').read_text())
    if (sha(HELPER) != record['helperSha256'] or sha(tool) != record['binarySha256']
            or sha(DRIVER) != record['driverSha256']
            or Path(record['helperPath']).resolve(strict=True) != HELPER
            or Path(record['driverPath']).resolve(strict=True) != DRIVER):
        raise ValueError('Snapshot diagnostic driver must be rebuilt from the current maintained helper')
    result = subprocess.run([str(tool), str(ROOT)], cwd=ROOT, capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()
    if not lines or not re.fullmatch('digest=[0-9a-f]{64}', lines[0]):
        raise ValueError('Unexpected actual snapshot output')
    watched = {Path(line.removeprefix('watch=')).resolve() for line in lines[1:] if line.startswith('watch=')}
    return lines[0].removeprefix('digest='), watched


def build_snapshot_tool(directory, events):
    """Compile the thin evaluator with the exact selected host build dependency."""
    host_profiles = set()
    for event in events:
        if (event.get('reason') == 'compiler-artifact'
                and event.get('package_id', '').startswith(
                    'path+file://' + str(ROOT / 'crates/iroha_plonk') + '#')
                and 'custom-build' in event.get('target', {}).get('kind', [])):
            host_profiles.update(Path(name).resolve(strict=True).parents[2]
                                 for name in event['filenames'])
    if len(host_profiles) != 1:
        raise ValueError('Need one exact selected host plonk build-script profile')
    host_deps = host_profiles.pop() / 'deps'
    libraries = {}
    for event in events:
        if (event.get('reason') == 'compiler-artifact'
                and event.get('target', {}).get('name') == 'sha2'
                and event.get('package_id', '').startswith(
                    'registry+https://github.com/rust-lang/crates.io-index#sha2@')):
            for name in event['filenames']:
                path = Path(name).resolve(strict=True)
                if path.suffix == '.rlib' and path.parent == host_deps:
                    libraries[path] = event['features']
    if not libraries:
        raise ValueError('Need a Cargo-selected host sha2 rlib for the snapshot evaluator')
    # Cargo may select both the minimal host build dependency and an accelerated
    # runtime instance. Prefer the fewest features, retaining the exact selection.
    library = min(libraries, key=lambda path: (len(libraries[path]), str(path)))
    tool = directory / 'source-snapshot'
    command = [os.environ.get('RUSTC', 'rustc'), '--edition=2024', '--crate-name',
               'iroha_native_source_snapshot', str(DRIVER), '--extern', 'sha2=' + str(library),
               '-L', 'dependency=' + str(host_deps), '-o', str(tool)]
    before = {path: sha(path) for path in (HELPER, DRIVER, library)}
    subprocess.run(command, cwd=ROOT, check=True)
    if any(sha(path) != digest for path, digest in before.items()):
        raise ValueError('Snapshot evaluator inputs changed during compilation')
    record = {'helperPath': str(HELPER), 'helperSha256': before[HELPER],
              'driverPath': str(DRIVER), 'driverSha256': before[DRIVER],
              'binaryPath': str(tool), 'binarySha256': sha(tool),
              'sha2Path': str(library), 'sha2Sha256': before[library],
              'sha2Features': libraries[library], 'command': command}
    tool.with_name('source-snapshot-build.json').write_text(json.dumps(record, indent=2) + '\n')
    return tool


def external_generated_inputs(events, no_source_records=None):
    """Only reviewed, exact Cargo.lock-selected registry build scripts."""
    lock = (ROOT / 'Cargo.lock').read_text()
    result = {}
    for event in events:
        if event.get('reason') != 'build-script-executed':
            continue
        package_id = event.get('package_id', '')
        matched = re.fullmatch(r'registry\+https://github.com/rust-lang/crates.io-index#([^@]+)@(.+)', package_id)
        if not matched or matched[1] not in {name for name, _ in EXTERNAL_GENERATED}:
            continue
        name, version = matched.groups()
        if (name, version) not in EXTERNAL_GENERATED:
            raise ValueError(f'Unreviewed generated dependency version: {package_id}')
        filename, relative_inputs, relationship = EXTERNAL_GENERATED[name, version]
        records = [e for e in events if e.get('reason') == 'compiler-artifact' and e.get('package_id') == package_id]
        builders = [e for e in records if 'custom-build' in e['target']['kind']]
        roots = {Path(e['target']['src_path']).resolve(strict=True).parent for e in builders}
        if len(roots) != 1:
            raise ValueError(f'Missing or ambiguous exact dependency generator: {package_id}')
        package_root = roots.pop()
        manifest = package_root / 'Cargo.toml'
        blocks = [b for b in lock.split('[[package]]') if re.search(r'^name = "'+re.escape(name)+r'"$', b, re.M)
                  and re.search(r'^version = "'+re.escape(version)+r'"$', b, re.M)]
        if len(blocks) != 1 or 'source = "registry+https://github.com/rust-lang/crates.io-index"' not in blocks[0]:
            raise ValueError(f'Generated dependency is not uniquely pinned by Cargo.lock: {package_id}')
        locked_checksum = re.search(r'^checksum = "([0-9a-f]{64})"$', blocks[0], re.M)
        archive = package_root.parents[2] / 'cache' / package_root.parent.name / f'{name}-{version}.crate'
        if not locked_checksum or sha(archive) != locked_checksum[1]:
            raise ValueError(f'Cargo.lock/registry archive checksum mismatch: {package_id}')
        maintained_inputs = []
        for relative in ['Cargo.toml'] + relative_inputs:
            path = package_root / relative
            digest = sha(path)
            with tarfile.open(archive, 'r:gz') as package:
                original = package.extractfile(f'{name}-{version}/{relative}')
                if original is None or hashlib.sha256(original.read()).hexdigest() != digest:
                    raise ValueError(f'Selected generator input differs from pinned registry archive: {path}')
            maintained_inputs.append({'path':str(path),'sha256':digest})
        if filename is None:
            if no_source_records is not None:
                no_source_records.append({'packageId':package_id,'manifest':str(manifest),
                    'cargoLockChecksum':locked_checksum[1],'registryArchive':str(archive),'registryArchiveSha256':sha(archive),
                    'maintainedGeneratorInputs':maintained_inputs,'relationship':relationship,
                    'buildScriptOutDir':event['out_dir'],'buildScriptCfgs':event['cfgs'],'buildScriptEnvironment':event['env'],
                    'selectedArtifacts':[{'target':e['target'],'features':e['features'],'filenames':e['filenames']} for e in records],
                    'generatedInputExceptions':[], 'scope':'Exact reviewed external build script with no generated source input; no OUT_DIR exception is granted.'})
            continue
        output = Path(event['out_dir']).resolve(strict=True) / filename
        if not output.is_file() or output.is_symlink():
            raise ValueError(f'Missing exact generated dependency output: {output}')
        if name in ('serde', 'serde_core', 'thiserror'):
            expected = '#[doc(hidden)]\npub mod __private' + version.split('.')[-1] + ' {\n    #[doc(hidden)]\n    pub use crate::private::*;\n}\n'
            if name == 'serde':
                expected += 'use serde_core::__private' + version.split('.')[-1] + ' as serde_core_private;\n'
            if output.read_text() != expected:
                raise ValueError(f'Unexpected private module generation: {output}')
        if name == 'num-bigint':
            lines = []
            for bits in (16, 32, 64):
                maximum = (1 << bits) - 1
                lines.extend(['#[deny(overflowing_literals)]', f'pub(crate) static BASES_{bits}: [(u{bits}, usize); 257] = ['])
                for radix in range(257):
                    base, power = (0, 0) if radix == 0 or radix & (radix - 1) == 0 else (radix, 1)
                    if base:
                        while base * radix <= maximum:
                            base *= radix
                            power += 1
                    lines.append(f'    ({base}, {power}), // {radix}')
                lines.append('];')
            if output.read_text() != '\n'.join(lines) + '\n':
                raise ValueError(f'Unexpected radix-base generation: {output}')
        result[output] = {'path':str(output),'sha256':sha(output),'packageId':package_id,
            'manifest':str(manifest),'cargoLockChecksum':locked_checksum[1],'registryArchive':str(archive),'registryArchiveSha256':sha(archive),
            'maintainedGeneratorInputs':maintained_inputs,'relationship':relationship,
            'buildScriptOutDir':event['out_dir'],'buildScriptCfgs':event['cfgs'],
            'buildScriptEnvironment':event['env'],
            'selectedArtifacts':[{'target':e['target'],'features':e['features'],'filenames':e['filenames']} for e in records],
            'scope':'External registry dependency-generated input. Recorded producer relationship and Cargo.lock selection; not part of canonical workspace source attestation.'}
    return result


def canonical_generated_inputs(events, census):
    """Only exact selected local generators with all maintained inputs in census."""
    result = {}
    for event in events:
        if event.get('reason') != 'build-script-executed':
            continue
        package_id = event.get('package_id', '')
        selected = [name for name in CANONICAL_GENERATED
                    if package_id.startswith('path+file://' + str(ROOT / 'crates' / name) + '#')]
        if not selected:
            continue
        if len(selected) != 1:
            raise ValueError('Ambiguous canonical generator selection')
        name = selected[0]
        root = ROOT / 'crates' / name
        artifacts = [e for e in events if e.get('reason') == 'compiler-artifact' and e.get('package_id') == package_id]
        builders = [e for e in artifacts if 'custom-build' in e['target']['kind']]
        if not builders or any(Path(e['target']['src_path']).resolve(strict=True) != root / 'build.rs'
                               or Path(e['manifest_path']).resolve(strict=True) != root / 'Cargo.toml' for e in builders):
            raise ValueError(f'No exact canonical generator artifact: {package_id}')
        out = Path(event['out_dir']).resolve(strict=True)
        if not out.is_relative_to(ROOT / 'target') or out.name != 'out' or not re.fullmatch(re.escape(name) + '-[0-9a-f]+', out.parent.name):
            raise ValueError(f'Unexpected canonical generator OUT_DIR: {out}')
        for filename, (inputs, relationship) in CANONICAL_GENERATED[name].items():
            paths = [root / path for path in ['Cargo.toml'] + inputs]
            if any(path not in census or not path.is_file() or path.is_symlink() for path in paths):
                raise ValueError(f'Canonical generator input omitted from actual source census: {package_id}')
            output = out / filename
            if not output.is_file() or output.is_symlink():
                raise ValueError(f'Missing exact canonical generated output: {output}')
            record = {'path': str(output), 'sha256': sha(output), 'packageId': package_id,
                      'manifest': str(root / 'Cargo.toml'), 'relationship': relationship,
                      'maintainedGeneratorInputs': [{'path': str(p), 'sha256': sha(p)} for p in paths],
                      'buildScriptOutDir': str(out), 'buildScriptCfgs': event['cfgs'],
                      'buildScriptEnvironment': event['env'],
                      'selectedArtifacts': [{'target': e['target'], 'features': e['features'], 'filenames': e['filenames']} for e in artifacts],
                      'scope': 'Exact canonical generated compiler input. Its maintained generator and source assets are included in the actual native source census; output bytes are recorded separately.'}
            if filename == 'kagemusha_wallet_runtime_trust.rs':
                prefix = '// Immutable public authority and key selected by the native artifact build owner.\nconst INSTALLED_RUNTIME_TRUST: Option<(RuntimeAuthority, [u8; 32])> = '
                source = output.read_text()
                if not source.startswith(prefix) or not source.endswith(';\n'):
                    raise ValueError('Unexpected canonical runtime trust output framing')
                value = source[len(prefix):-2]
                if value == 'None':
                    record['publicInputSelectionFromGeneratedOutput'] = None
                else:
                    match = re.fullmatch(r'Some\(\(RuntimeAuthority::(BpngTairaV7|CbsiReleaseV1|ApplicationReleaseV1), (\[[0-9, ]+\])\)\)', value)
                    if not match:
                        raise ValueError('Unknown canonical runtime trust selection')
                    key = bytes(ast.literal_eval(match[2]))
                    if len(key) != 32 or key == bytes(32):
                        raise ValueError('Invalid generated runtime trust key')
                    record['publicInputSelectionFromGeneratedOutput'] = {'authority': match[1], 'publicKeyHex': key.hex()}
            result[output] = record
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cargo-json', type=Path, help='Successful build stdout, json-render-diagnostics format')
    ap.add_argument('--depfile', type=Path, action='append', default=[], help='Additional exact depfile (repeatable)')
    ap.add_argument('--plonk-out-dir', type=Path, action='append', default=[], help='Exact plonk OUT_DIR if JSON unavailable')
    ap.add_argument('--expected-source-digest', help='Optional pinned compiled/exported digest; otherwise require the current maintained snapshot')
    ap.add_argument('--snapshot-tool', type=Path, help='Pinned maintained snapshot evaluator; otherwise compile the thin driver from the selected host sha2 artifact')
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    if args.expected_source_digest is not None and not re.fullmatch('[0-9a-f]{64}', args.expected_source_digest):
        raise ValueError('source digest must be 64 lowercase hex digits')
    depfiles = {p.resolve(strict=True) for p in args.depfile}
    out_dirs = {p.resolve(strict=True) for p in args.plonk_out_dir}
    artifacts = []
    events = []
    if args.cargo_json:
        for line in args.cargo_json.read_text().splitlines():
            if line.startswith('{'):
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(item)
        finished = [e for e in events if e.get('reason') == 'build-finished']
        if not finished or finished[-1].get('success') is not True:
            raise ValueError('Cargo JSON does not end in successful build')
        for e in events:
            if e.get('reason') == 'compiler-artifact':
                selected = artifact_depfiles(e)
                manifest = e.get('manifest_path', '')
                if manifest.startswith(str(ROOT) + '/') and not selected:
                    raise ValueError(f'No exact depfile for local artifact: {e["target"]["name"]}')
                depfiles.update(selected)
                artifacts.append({'packageId': e['package_id'], 'target': e['target']['name'],
                                  'depfiles': [str(p) for p in sorted(selected)]})
            if e.get('reason') == 'build-script-executed' and '/crates/iroha_plonk#' in e.get('package_id', ''):
                out_dirs.add(Path(e['out_dir']).resolve(strict=True))
    if not depfiles or not out_dirs:
        raise ValueError('Need exact selected depfiles and plonk build-script OUT_DIR')
    # Use the maintained Rust algorithm itself, never a Python census replica.
    # The evaluator is tiny; it reuses the successful build's exact host sha2 rlib.
    with tempfile.TemporaryDirectory(prefix='native-source-snapshot-') as temporary:
        snapshot_tool = args.snapshot_tool
        if snapshot_tool is None:
            snapshot_tool = build_snapshot_tool(Path(temporary), events)
        actual_before, actual_watched = actual_snapshot(snapshot_tool.resolve(strict=True))
        expected = args.expected_source_digest or actual_before
        if actual_before != expected:
            raise ValueError('Current maintained source snapshot differs from expected compiled/exported identity')
        return audit(args, events, depfiles, out_dirs, artifacts, snapshot_tool,
                     expected, actual_before, actual_watched)


def audit(args, events, depfiles, out_dirs, artifacts, snapshot_tool,
          expected, actual_before, actual_watched):
    """Reconcile selected compiler inputs with the actual compiled and current census."""
    external_no_source = []
    external_generated = external_generated_inputs(events, external_no_source)
    observed_external_generated = set()
    census = set()
    generated_identity = set()
    absent_watchers = set()
    identity_records = []
    for out in sorted(out_dirs):
        identity = out / 'native_source_identity.rs'
        source = identity.read_text()
        if 'NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true;' not in source:
            raise ValueError('Selected plonk build has incomplete source closure')
        values = re.search(r'CURRENT_NATIVE_SOURCE_DIGEST: \[u8; 32\] = \[([^]]+)\]', source)
        digest = bytes(int(x.strip()) for x in values[1].split(',') if x.strip()).hex() if values else None
        if digest != expected:
            raise ValueError(f'Compiled digest mismatch: {out}')
        rescan = out / 'native-source-rescan-required'
        if rescan.exists() or rescan.is_symlink():
            raise ValueError(f'Intentionally absent rescan watcher exists: {rescan}')
        watched = set()
        declared_watches = set()
        for line in (out.parent / 'output').read_text().splitlines():
            if line.startswith('cargo:rerun-if-changed='):
                p = Path(line.split('=', 1)[1])
                declared_watches.add(p)
                if p.is_file():
                    watched.add(p.resolve(strict=True))
        if rescan not in declared_watches:
            raise ValueError('Selected plonk build did not declare its exact rescan watcher')
        absent_watchers.add(rescan)
        if watched != {p for p in actual_watched if p.is_file()}:
            raise ValueError('Actual source census and selected build-script census differ')
        if not {BUILD_RS, HELPER}.issubset(watched):
            raise ValueError('Source identity generator/helper absent from actual census')
        census.update(watched - {GENERATED})
        generated_identity.add(identity.resolve(strict=True))
        identity_records.append({'outDir': str(out), 'identitySha256': sha(identity),
                                 'buildOutputSha256': sha(out.parent / 'output'), 'sourceDigest': digest,
                                 'nativeTarget':json.loads(re.search(r'NATIVE_SOURCE_TARGET: &str = ("[^"]+");', source)[1]),
                                 'targetSupported': 'BUILTIN_TARGET_SUPPORTED: bool = true;' in source})
    canonical_generated = canonical_generated_inputs(events, census)
    observed_canonical_generated = set()
    canonical, external, omitted, exceptions = set(), set(), set(), set()
    observed_absent_watchers = set()
    for depfile in sorted(depfiles):
        for path in inputs(depfile, absent_watchers):
            if path in absent_watchers:
                observed_absent_watchers.add(path)
            elif not path.is_relative_to(ROOT):
                external.add(path)
            elif path in external_generated:
                observed_external_generated.add(path)
            elif path in canonical_generated:
                observed_canonical_generated.add(path)
            elif path in generated_identity:
                exceptions.add(path)
            elif path == GENERATED:
                exceptions.add(path)
            elif path in census:
                canonical.add(path)
            else:
                omitted.add(path)
    actual_after, watched_after = actual_snapshot(snapshot_tool.resolve(strict=True))
    if actual_after != actual_before or watched_after != actual_watched:
        raise ValueError('Source inputs changed during containment audit')
    for path in observed_canonical_generated:
        if sha(path) != canonical_generated[path]['sha256']:
            raise ValueError(f'Canonical generated output changed during audit: {path}')
    result = {
        'passed': not omitted,
        'auditToolSha256':sha(Path(__file__)),
        'actualSourceVerifiedBeforeAndAfter': True,
        'snapshotEvaluator': json.loads(snapshot_tool.with_name('source-snapshot-build.json').read_text()),
        'scope': 'All canonical Rust compiler inputs in the exact selected depfiles; external dependencies/toolchain are reported only. Caller must separately check source stability and target mathematical parity.',
        'sourceDigest': expected,
        'identityBuilds': identity_records,
        'canonicalInputCount': len(canonical), 'externalInputCount': len(external),
        'omittedCanonicalInputs': [str(p) for p in sorted(omitted)],
        'externalDependencyGeneratedInputs':[external_generated[p] for p in sorted(observed_external_generated)],
        'externalBuildScriptsWithoutGeneratedSource':external_no_source,
        'canonicalGeneratedInputs':[canonical_generated[p] for p in sorted(observed_canonical_generated)],
        'absentBuildWatchExceptions': [{'path':str(p),'relationship':'Exact selected plonk OUT_DIR marker explicitly declared by the maintained build.rs to force source membership rescan. Deliberately absent Cargo watcher, not a Rust source input.'} for p in sorted(observed_absent_watchers)],
        'generatedExceptions': [{'path': str(p), 'sha256': sha(p),
            'relationship': ('Finite strict-generated registry DATA, sole deliberate data exclusion; source freshness is checked by the consuming registry.' if p == GENERATED else
                'Generated only by included iroha_plonk/build.rs + build_support/source_identity.rs from the actual complete census. Target labels are diagnostic; target support is a separate predicate.')} for p in sorted(exceptions)],
        'depfiles': [{'path': str(p), 'sha256': sha(p)} for p in sorted(depfiles)],
        'artifacts': artifacts,
        'canonicalInputs': [str(p) for p in sorted(canonical)],
        'externalInputs': [str(p) for p in sorted(external)],
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed','sourceDigest','canonicalInputCount','externalInputCount','omittedCanonicalInputs')}, indent=2))
    if omitted:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
