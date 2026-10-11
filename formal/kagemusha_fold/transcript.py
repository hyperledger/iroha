"""Bounded source-bound PIPA-AS transcript schedules, never a fold verifier."""

from functools import lru_cache
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REFERENCE = ROOT / 'fixtures/native_prover/reference_verifier'
FILES = frozenset(('README.md', 'transcript.py', 'test_transcript.py'))
SOURCES = frozenset((
    'crates/iroha_pasta/src/poseidon/mod.rs',
    'crates/iroha_pasta/src/poseidon/rp57_fp.bin',
    'crates/iroha_pasta/src/poseidon/rp57_fq.bin',
    'crates/iroha_pasta/src/curve/mod.rs',
    'crates/iroha_plonk/src/transcript/mod.rs',
    'crates/iroha_plonk/src/transcript/pipa_r.rs',
    'crates/iroha_plonk_recursion/src/accumulation.rs',
    'crates/iroha_plonk_recursion/src/accumulation_circuit.rs',
    'crates/iroha_plonk_recursion/src/transcript.rs',
    'crates/iroha_plonk_recursion/src/claim.rs',
    'crates/iroha_plonk_recursion/src/tests.rs',
    'crates/iroha_plonk_gadgets/src/pow5_fq/duplex.rs',
    'crates/iroha_plonk_gadgets/src/poseidon/sponge.rs',
    'fixtures/native_prover/kats_v1.json',
    'fixtures/native_prover/reference_verifier/__init__.py',
    'fixtures/native_prover/reference_verifier/curve.py',
    'fixtures/native_prover/reference_verifier/transcript.py',
))
DOMAIN = int.from_bytes(b'pipa-as1', 'little')
IV = (1 << 64, 0, 0)
K = 16


def require(condition, message):
    """Reject explicitly, including before any subject load under python -O."""
    if not condition:
        raise ValueError(message)


def validate_manifest(manifest):
    """Admit the exact maintained/reference/native source roles, not arbitrary paths."""
    require(type(manifest) is dict and set(manifest) == {'schema', 'files', 'sources'},
            'manifest grammar')
    require(manifest['schema'] == 'kagemusha.fold.transcript-controls.v1', 'manifest schema')
    require(type(manifest['files']) is dict and set(manifest['files']) == FILES,
            'control inventory')
    require(type(manifest['sources']) is dict and set(manifest['sources']) == SOURCES,
            'source inventory')
    for digest in (*manifest['files'].values(), *manifest['sources'].values()):
        require(type(digest) is str and len(digest) == 64 and
                all(c in '0123456789abcdef' for c in digest), 'canonical digest')


def checked_sources():
    """Rehash only the explicit small inputs before loading the unchanged reference."""
    require(sys.flags.optimize == 0, 'unoptimized controls only')
    manifest = json.loads((HERE / 'transcript_source_manifest.json').read_text())
    validate_manifest(manifest)
    for base, rows in ((HERE, manifest['files']), (ROOT, manifest['sources'])):
        for name, digest in rows.items():
            require(hashlib.sha256((base / name).read_bytes()).hexdigest() == digest,
                    'changed source ' + name)
    return manifest


@lru_cache(maxsize=1)
def _load_reference():
    name = '_kagemusha_fold_transcript_reference'
    require(name not in sys.modules, 'reference namespace occupied')
    spec = importlib.util.spec_from_file_location(
        name, REFERENCE / '__init__.py', submodule_search_locations=[str(REFERENCE)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return importlib.import_module(name + '.transcript')


@lru_cache(maxsize=1)
def reference():
    """Access just Sponge/Curve arithmetic; no setup, parameters or proof imports."""
    checked_sources()
    return _load_reference()


def curve(tag):
    """Choose one of the two explicit curve orientations."""
    require(type(tag) is int and tag in (0, 1), 'curve tag')
    return reference().Curve(tag)


def scalar_words(tag, value):
    """Native injective one-word/two-limb scalar encoding, without alias reduction."""
    c = curve(tag)
    require(type(value) is int and 0 <= value < c.scalar, 'canonical scalar')
    if tag == 1:
        return (value,)
    return (value & ((1 << 128) - 1), value >> 128)


def mapped_word(tag, value):
    """Apply the actual full-width map, preserving zero rather than retrying."""
    c = curve(tag)
    require(type(value) is int and 0 <= value < c.base, 'canonical base word')
    return value % c.scalar


def point_words(tag, point):
    """Check canonical finite affine coordinates for a syntactic transcript point."""
    c = curve(tag)
    require(type(point) is tuple and len(point) == 2, 'affine point')
    x, y = point
    require(all(type(v) is int and 0 <= v < c.base for v in point), 'canonical point')
    require((y*y - x*x*x - 5) % c.base == 0, 'point on curve')
    return point


def fixture_inputs(tag, count):
    """Rust prelude KAT inputs at count2; other bounded counts are only syntactic."""
    c = curve(tag)
    require(type(count) is int and 1 <= count <= 16, 'bounded input count')
    short = ((c.base - 1, c.base - 2), 3, (0,) * 13 + (9,) * 3)
    full = ((c.base - 1, 2), 16, tuple(range(2, 18)))
    return (short,) * (count - 1) + (full,)


def prelude_words(tag, inputs, salt):
    """Domain, salt, count, then ordered point/source-k/all16 scalar carriers."""
    c = curve(tag)
    require(type(inputs) is tuple and 1 <= len(inputs) <= 16, 'bounded input list')
    require(type(salt) is int and 0 <= salt < c.base, 'canonical salt')
    words = [DOMAIN, salt, len(inputs)]
    full = False
    for row in inputs:
        require(type(row) is tuple and len(row) == 3, 'input grammar')
        point, source_k, challenges = row
        require(type(source_k) is int and 1 <= source_k <= K, 'source k')
        require(type(challenges) is tuple and len(challenges) == K, 'challenge count')
        require(all(type(v) is int and 0 <= v < c.scalar for v in challenges),
                'canonical source challenge')
        require(challenges[:K-source_k] == (0,) * (K-source_k) and
                all(v != 0 for v in challenges[K-source_k:]), 'source padding/nonzero')
        full |= source_k == K
        words.extend((*point_words(tag, point), source_k))
        for value in challenges:
            words.extend(scalar_words(tag, value))
    require(full, 'full source required')
    return tuple(words)


def padded_blocks(words):
    """Independent native block schedule: pairs, then odd or even tail padding."""
    require(type(words) is tuple and len(words) <= 1024, 'bounded word tuple')
    pairs = tuple((words[i], words[i+1]) for i in range(0, len(words)-1, 2))
    tail = (words[-1], 1) if len(words) % 2 else (1, 0)
    return pairs + (tail,)


def trace_script(tag, buffers):
    """Run unchanged RP57 arithmetic while recording every input/output triple."""
    c, ref = curve(tag), reference()
    require(type(buffers) is tuple and 1 <= len(buffers) <= 32, 'bounded squeezes')
    require(all(type(row) is tuple for row in buffers), 'word tuples')
    require(sum(map(len, buffers)) <= 1024, 'bounded total words')
    require(all(type(v) is int and 0 <= v < c.base for row in buffers for v in row),
            'canonical input word')

    class TraceSponge(ref.Sponge):
        def __init__(self):
            super().__init__(c.base)
            self.edges = []

        def permute(self):
            before = tuple(self.state)
            super().permute()
            self.edges.append((before, tuple(self.state)))

    sponge = TraceSponge()
    raw, endpoints = [], []
    for row in buffers:
        for word in row:
            sponge.absorb(word)
        raw.append(sponge.squeeze())
        endpoints.append(len(sponge.edges))
    return {'raw': tuple(raw), 'mapped': tuple(v % c.scalar for v in raw),
            'edges': tuple(sponge.edges), 'endpoints': tuple(endpoints),
            'state': tuple(sponge.state), 'pending': tuple(sponge.buffer)}


def fold_script(tag, inputs, salt):
    """All19 syntactic squeezes; fixed finite L/R do not assert the IPA equation."""
    c = curve(tag)
    first = prelude_words(tag, inputs, salt)
    left, right = point_words(tag, (c.base - 1, 2)), point_words(tag, (c.base - 1, c.base - 2))
    return (first, (), ()) + ((*left, *right),) * K


def expected_positions(tag, count):
    """Exact native primitive call count for the bounded input list."""
    require(type(tag) is int and tag in (0, 1), 'curve tag')
    require(type(count) is int and 1 <= count <= 16, 'bounded input count')
    return 52 + ((35 if tag == 0 else 19) * count + 1) // 2


def check_trace(tag, buffers, trace):
    """Compare every observed input with a separately derived carried block state."""
    c = curve(tag)
    prior, cursor = IV, 0
    require(len(buffers) == len(trace['raw']) == len(trace['endpoints']), 'squeeze count')
    for index, row in enumerate(buffers):
        for a, b in padded_blocks(row):
            require(cursor < len(trace['edges']), 'missing primitive')
            before, after = trace['edges'][cursor]
            require(before == (prior[0], (prior[1]+a) % c.base, (prior[2]+b) % c.base),
                    'primitive input schedule')
            require(len(after) == 3 and all(type(v) is int and 0 <= v < c.base for v in after),
                    'canonical output state')
            prior, cursor = after, cursor + 1
        require(trace['endpoints'][index] == cursor and trace['raw'][index] == prior[1],
                'endpoint/projection')
        require(trace['mapped'][index] == prior[1] % c.scalar, 'mapped projection')
    require(cursor == len(trace['edges']) and trace['state'] == prior and trace['pending'] == (),
            'final state/extra primitive')
