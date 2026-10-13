#!/usr/bin/env python3
"""Prepare an isolated, derived native-observer diagnostic crate, never production.

Python3.11+, current reviewed resource sources and a new explicit output path.
No environment variables, network, builds or root manifest/lock mutation. The
new temporary crate mirrors root patches; its lock must be resolved separately,
checked against the copied root lock, then built --locked. Generation retains
an exact workspace patch and all source hashes. No frozen source is rewritten.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[1]
RESOURCE='crates/iroha_parliament_ballot_proof/examples/resource_contract'
PROBE='crates/iroha_parliament_ballot_proof/examples/native_probe'
FROZEN='docs/validation/parliament_ballot_resource_contract/build-source.sha256'


def digest(path:Path)->str:
    """Hash source bytes, not their pathname or modification time."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive_workspace(source:str, control_path:Path)->str:
    """Insert reviewed markers without changing admission or proof outcomes."""
    replacements=[
        ('    ACTIVE.store(true, Ordering::Release);','    crate::observer::begin();\n    ACTIVE.store(true, Ordering::Release);'),
        ('    // All record/statement/verifier/error ownership has ended in execute.\n    ACTIVE.store(false, Ordering::Release);',
         '    // All record/statement/verifier/error ownership has ended in execute.\n    let probe_was_active = ACTIVE.load(Ordering::Acquire);\n    ACTIVE.store(false, Ordering::Release);\n    if probe_was_active { crate::observer::end(); }'),
        ('    unsafe { libc::_exit(73) }','    crate::observer::terminal();\n    unsafe { libc::_exit(73) }'),
    ]
    for old,new in replacements:
        if source.count(old)!=1:raise ValueError('workspace marker anchor changed')
        source=source.replace(old,new)
    return source+'\n#[path = '+json.dumps(str(control_path))+']\nmod probe_control;\npub use probe_control::run as run_probe_control;\n'


def prepare(output:Path, root:Path=ROOT)->dict:
    """Create a new standalone diagnostic source tree and preserve its derivation."""
    if output.exists():raise ValueError('output must be a new directory')
    frozen={line.split('  ',1)[1]:line.split('  ',1)[0] for line in (root/FROZEN).read_text().splitlines()}
    names=[f'{RESOURCE}/{name}.rs' for name in ['arena','budget','native','workspace']]
    for name in names:
        if digest(root/name)!=frozen.get(name):raise ValueError('frozen resource source changed: '+name)
    output.mkdir(parents=True)
    sources={name:digest(root/name) for name in names}
    for source in sorted((root/PROBE).glob('*.rs')):
        (output/source.name).write_bytes(source.read_bytes())
        sources[str(source.relative_to(root))]=digest(source)
    driver=(output/'driver.rs').read_text()
    for name in ['arena','budget','native']:
        old=f'"../resource_contract/{name}.rs"'
        if driver.count(old)!=1:raise ValueError('driver module anchor changed')
        driver=driver.replace(old,json.dumps(str(root/RESOURCE/(name+'.rs'))))
    (output/'driver.rs').write_text(driver)
    original=(root/RESOURCE/'workspace.rs').read_text()
    derived=derive_workspace(original,output/'routed_control.rs')
    (output/'generated_workspace.rs').write_text(derived)
    (output/'workspace.diff').write_text(''.join(difflib.unified_diff(original.splitlines(True),derived.splitlines(True),fromfile='frozen-workspace.rs',tofile='diagnostic-workspace.rs')))
    manifest='''[package]\nname = "parliament-native-probe"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[workspace]\n\n[features]\ndefault = []\naccel = ["iroha_parliament_ballot_proof/accel"]\n\n[[bin]]\nname = "parliament-native-probe"\npath = "driver.rs"\n\n[dependencies]\n'''
    for name in ['iroha_parliament_ballot_proof','iroha_zkp_vole','norito']:
        features=', features = ["json"], default-features = false' if name=='norito' else ''
        manifest+=f'{name} = {{ path = {json.dumps(str(root/"crates"/name))}{features} }}\n'
    manifest+='libc = "0.2.177"\nthiserror = "2.0"\nsha3 = { version = "0.10.8", default-features = false, features = ["std"] }\n\n[patch.crates-io]\n'
    root_manifest=tomllib.loads((root/'Cargo.toml').read_text())
    for name,entry in root_manifest['patch']['crates-io'].items():
        if set(entry)!={'path'}:raise ValueError('new root patch kind requires explicit review')
        manifest+=f'{name} = {{ path = {json.dumps(str((root/entry["path"]).resolve()))} }}\n'
    (output/'Cargo.toml').write_text(manifest)
    (output/'Cargo.lock').write_bytes((root/'Cargo.lock').read_bytes())
    (output/'root-Cargo.lock.template').write_bytes((root/'Cargo.lock').read_bytes())
    for name in ['Cargo.toml','Cargo.lock',f'{PROBE}/np_api.h','scripts/prepare_parliament_ballot_native_probe.py']:
        sources[name]=digest(root/name)
    report={'source_files':sources,'generated_files':{p.name:digest(p) for p in sorted(output.iterdir()) if p.is_file()},'root':str(root),'output':str(output),'frozen_sources_unchanged':True,'profile_qualified':False,'root_lock_modified':False}
    (output/'preparation.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def compare_locks(reference:Path, derived:Path)->dict:
    """Refuse new dependency identities; the only new package is the probe itself."""
    old=tomllib.loads(reference.read_text())['package']
    new=tomllib.loads(derived.read_text())['package']
    identity=lambda p:(p['name'],p['version'],p.get('source'),p.get('checksum'))
    allowed={identity(p) for p in old}
    unexpected=[identity(p) for p in new if p['name']!='parliament-native-probe' and identity(p) not in allowed]
    if unexpected:raise ValueError('diagnostic dependency identity drift: '+repr(unexpected))
    probe=[p for p in new if p['name']=='parliament-native-probe']
    if len(probe)!=1 or probe[0]['version']!='0.0.0' or probe[0].get('source'):raise ValueError('missing or wrong standalone probe package')
    return {'original_packages':len(old),'diagnostic_packages':len(new),'unexpected_dependency_identities':unexpected,'reference_sha256':digest(reference),'derived_sha256':digest(derived),'comparison_scope':'package name/version/source/checksum membership only; not dependency-edge, feature or compiled-build parity','profile_qualified':False}


def main()->int:
    """Prepare once, or verify the separately resolved standalone dependency lock."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--check-lock',nargs=2,type=Path,metavar=('REFERENCE','DERIVED'))
    args=parser.parse_args()
    try:
        if args.check_lock:report=compare_locks(*args.check_lock)
        elif args.output:report=prepare(args.output.resolve())
        else:parser.error('--output or --check-lock required')
        print(json.dumps(report,indent=2));return 0
    except (OSError,ValueError) as error:
        print(json.dumps({'failure':str(error),'profile_qualified':False}));return 1
if __name__=='__main__':raise SystemExit(main())
