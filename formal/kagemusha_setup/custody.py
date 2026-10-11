"""Relative source custody and isolated access to the unchanged reference code."""
from functools import lru_cache
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REFERENCE = ROOT/'fixtures/native_prover/reference_verifier'
MODULES = ('__init__.py', 'codec.py', 'curve.py', 'descriptor.py',
           'parameters.py', 'transcript.py', 'verify.py')
FILES = frozenset(('README.md', '__init__.py', 'bounded.py', 'case.py', 'check.py', 'control_goldens.json', 'custody.py', 'finite.py', 'load_a1_case.py', 'load_a1_descriptor.norito', 'parameters.py', 'preimage.py', 'produce_parameters.py', 'public_setup.py', 'raw_setup.py', 'rebind.py', 'requests.py', 'simulator.py', 'test_bounded.py', 'test_custody.py', 'test_finite.py', 'test_generic.py', 'test_load_a1_case.py', 'test_preimage.py', 'test_proof.py', 'test_raw.py', 'test_requests.py', 'test_seam.py'))
SOURCES = frozenset((
    'crates/iroha_pasta/src/curve/hash_to_curve.rs',
    'crates/iroha_pasta/src/curve/pallas.rs',
    'crates/iroha_pasta/src/curve/vesta.rs',
    'crates/iroha_pasta/src/field/cios.rs',
    'crates/iroha_pasta/src/field/fp.rs',
    'crates/iroha_pasta/src/field/fq.rs',
    'crates/iroha_pasta/src/field/mod.rs',
    'crates/iroha_pasta/src/params.rs',
    'crates/iroha_plonk/src/keys/keygen.rs',
    'crates/iroha_plonk/src/keys/keygen/rebuild.rs',
    'crates/iroha_plonk/src/keys/mod.rs',
    'crates/iroha_plonk/src/keys/pk/artifact.rs',
    'crates/iroha_plonk/src/keys/source_fingerprint.rs',
    'crates/iroha_plonk/src/keys/vk.rs',
    'crates/iroha_plonk/src/pcs/ipa/commit.rs',
    'crates/iroha_plonk/src/pcs/ipa/mod.rs',
    'crates/iroha_plonk/src/pcs/ipa/prover.rs',
    'crates/iroha_plonk/src/pcs/ipa/verifier.rs',
    'crates/iroha_plonk/src/transcript/pipa_r.rs',
    'fixtures/native_prover/kats_v1.json',
    'fixtures/native_prover/reference_v1.json',
    'fixtures/native_prover/reference_verifier/__init__.py',
    'fixtures/native_prover/reference_verifier/codec.py',
    'fixtures/native_prover/reference_verifier/curve.py',
    'fixtures/native_prover/reference_verifier/descriptor.py',
    'fixtures/native_prover/reference_verifier/parameters.py',
    'fixtures/native_prover/reference_verifier/transcript.py',
    'fixtures/native_prover/reference_verifier/verify.py',
    'formal/kagemusha_pasta/auxiliary.py',
    'formal/kagemusha_pasta/check.py',
    'formal/kagemusha_pasta/primes.py',
    'formal/kagemusha_pasta/source_manifest.json',
    'formal/kagemusha_pasta/supplied_primes.json',
))


def require(condition, message):
    """Explicit refusal remains active under optimized Python."""
    if not condition:
        raise ValueError(message)


def sha(raw):
    """Non-protocol custody digest."""
    return hashlib.sha256(raw).hexdigest()


def validate_manifest(manifest):
    """Only the maintained package and exact production/reference source roles."""
    require(type(manifest) is dict and set(manifest) == {'schema', 'files', 'sources'},
            'exact source manifest grammar')
    require(manifest['schema'] == 'kagemusha.setup.controls.sources.v1', 'source schema')
    require(type(manifest['files']) is dict and set(manifest['files']) == FILES,
            'exact maintained inventory')
    require(type(manifest['sources']) is dict and set(manifest['sources']) == SOURCES,
            'exact dependency inventory')
    for digest in (*manifest['files'].values(), *manifest['sources'].values()):
        require(type(digest) is str and len(digest) == 64 and
                all(c in '0123456789abcdef' for c in digest), 'canonical SHA256 pin')


def checked_sources():
    """Reject optimized execution before reading the exact pinned inputs."""
    require(sys.flags.optimize == 0, 'unoptimized setup controls only')
    manifest = json.loads((HERE/'source_manifest.json').read_text())
    validate_manifest(manifest)
    for base, rows in ((HERE, manifest['files']), (ROOT, manifest['sources'])):
        for name, digest in rows.items():
            require(sha((base/name).read_bytes()) == digest, 'changed source '+name)
    return manifest


@lru_cache(maxsize=1)
def reference_curve():
    """Load only original Curve arithmetic under a distinct private namespace."""
    checked_sources()
    name = '_kagemusha_setup_original_arithmetic'
    require(name not in sys.modules, 'original arithmetic namespace already occupied')
    spec = importlib.util.spec_from_file_location(name, REFERENCE/'__init__.py',
                                                submodule_search_locations=[str(REFERENCE)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return importlib.import_module(name+'.curve')


def validate_algebra():
    """Reuse maintained prime and auxiliary-group certificates, no new arithmetic."""
    from ..kagemusha_pasta import auxiliary, primes
    result = primes.verify(json.loads((ROOT/'formal/kagemusha_pasta/supplied_primes.json').read_text()),
                           primes.roots_from_source())
    rows = [auxiliary.constants('pallas', 'fp'), auxiliary.constants('vesta', 'fq')]
    require([row[0] for row in rows] == [int(n) for n in result['roots']], 'same source primes')
    groups = [auxiliary.certify(name, row[0], rows[1-i][0], *row[1:])
              for i, (name, row) in enumerate(zip(('pallas', 'vesta'), rows))]
    return {'primes': result, 'groups': groups,
            'scope': 'Exact prime/group/map premises; no setup or privacy theorem execution'}


def write_new(path, raw):
    """Retain a new diagnostic original without replacing prior evidence."""
    with Path(path).open('xb') as stream:
        stream.write(raw)


def save(path, value):
    """Exclusively retain non-protocol diagnostic JSON."""
    write_new(path, (json.dumps(value, indent=2, sort_keys=True)+'\n').encode())
