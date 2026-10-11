"""Interpret the canonical descriptor directly from PIPA §2/§4 and Norito.

No circuit builder, Rust bindings, native executable, or generated interpreter
is used. Every expression is evaluated from its own postfix statement.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import require
from .codec import Cursor, descriptor_frame, MAX_COUNT
from .curve import Curve
from .transcript import KATS


def uint(width):
    """A fixed-width scalar decoder for a bounded Norito field."""
    return lambda reader: reader.integer(width)


def enum(reader: Cursor, maximum: int) -> int:
    """A unit enum uses one canonical u32 tag."""
    value = reader.integer(4)
    require(value <= maximum, 'enum tag')
    return value


def query(reader: Cursor) -> tuple[int, int]:
    """Column index followed by signed i32 rotation."""
    return reader.field(uint(4)), reader.field(lambda r: r.integer(4, True))


def expression(reader: Cursor):
    """Postfix nodes, retaining their exact order and unmodified constants."""
    def node(cursor):
        tag = enum(cursor, 7)
        if tag in (0, 7):
            value = cursor.field(lambda c: c.read(32))
        elif tag in (1, 2, 3):
            value = cursor.field(uint(4))
        else:
            value = None
        return tag, value
    return reader.sequence(node)


def selector_plan(reader: Cursor):
    """Compression switch, first fixed column and original selector entries."""
    def item(cursor):
        return cursor.field(uint(1)), cursor.field(uint(4)), cursor.field(uint(1))
    return (reader.field(uint(1)), reader.field(uint(4)),
            reader.field(lambda c: c.sequence(item)))


def lookup(reader: Cursor):
    """Equal-width ordered input and table expressions."""
    return (reader.field(lambda c: c.sequence(expression)),
            reader.field(lambda c: c.sequence(expression)))


def column(reader: Cursor):
    """An equality column identity, independent of any point value."""
    return reader.field(lambda c: enum(c, 2)), reader.field(uint(4))


def instance_type(reader: Cursor):
    """V2 Field, Bounded or Bits, without changing generic scalar encoding."""
    tag = enum(reader, 2)
    return (tag, reader.field(uint(1)) if tag == 2 else None)


@dataclass
class Descriptor:
    """A decoded statement and its authenticated original frame."""
    raw: bytes
    version: int
    values: dict

    @classmethod
    def decode(cls, raw: bytes, version: int) -> Descriptor:
        """Select a descriptor profile explicitly; never try fallback schemas."""
        r = descriptor_frame(raw, version)
        v = {}
        v['protocol_version'] = r.field(uint(2))
        v['curve'] = r.field(lambda c: enum(c, 1))
        for name in ('base_modulus', 'scalar_modulus', 'params_digest'):
            v[name] = r.field(lambda c: c.read(32))
        v['k'] = r.field(uint(1))
        v['transcript'] = r.field(lambda c: enum(c, 1 if version == 1 else 2))
        v['instance_mode'] = r.field(lambda c: enum(c, 1))
        v['proof_suffix'] = r.field(lambda c: enum(c, 1))
        for name, width in [('degree', 1), ('blinding_factors', 2),
                            ('permutation_chunk_len', 1), ('quotient_pieces', 1)]:
            v[name] = r.field(uint(width))
        v['lookup_kind'] = r.field(lambda c: enum(c, 0))
        for name in ('num_fixed_columns', 'num_advice_columns'):
            v[name] = r.field(uint(4))
        v['instance_lengths'] = r.field(lambda c: c.sequence(uint(4)))
        for name in ('fixed_queries', 'advice_queries', 'instance_queries'):
            v[name] = r.field(lambda c: c.sequence(query))
        v['selectors'] = r.field(selector_plan)
        v['gates'] = r.field(lambda c: c.sequence(lambda g: g.sequence(expression)))
        v['permutation'] = r.field(lambda c: c.sequence(column))
        v['lookups'] = r.field(lambda c: c.sequence(lookup))
        v['instance_types'] = r.field(lambda c: c.sequence(instance_type)) if version == 2 else None
        r.finish()
        descriptor = cls(raw, version, v)
        descriptor.validate()
        return descriptor

    def __getitem__(self, name):
        return self.values[name]

    @property
    def curve(self):
        """The descriptor's explicitly validated curve."""
        return Curve(self['curve'])

    @property
    def n(self):
        """Domain row count."""
        return 1 << self['k']

    @property
    def usable(self):
        """Rows before the last-product and blinding masks."""
        return self.n - self['blinding_factors'] - 1

    @property
    def permutation_sets(self):
        """Exact permutation product count from equality columns and degree."""
        return (len(self['permutation']) + self['degree'] - 3) // (self['degree'] - 2)

    @property
    def digest(self):
        """The protocol-separated binding of the complete canonical frame."""
        return hashlib.blake2b(self.raw, digest_size=32,
                              person=f'PIPA-v{self.version}-CircDesc'.encode()).digest()

    def repr(self, key: bytes) -> int:
        """The key binding in its explicit base or scalar transcript field."""
        modulus = self.curve.base if self['transcript'] == 2 else self.curve.scalar
        return int.from_bytes(hashlib.blake2b(self.digest + key, digest_size=64,
                              person=f'Iroha-PlonkVK-v{self.version}'.encode()).digest(),
                              'little') % modulus

    def expression(self, nodes, evaluations=None):
        """Validate degree/stack/index rules, or interpret the same postfix tree."""
        stack = []
        modulus = self.curve.scalar
        for tag, value in nodes:
            if tag in (0, 7):
                require(len(value) == 32 and int.from_bytes(value, 'little') < modulus,
                        'expression constant')
                value = int.from_bytes(value, 'little')
            if tag == 0:
                stack.append(0 if evaluations is None else value)
            elif tag in (1, 2, 3):
                name = ('fixed_queries', 'advice_queries', 'instance_queries')[tag - 1]
                require(value < len(self[name]), 'expression query')
                stack.append(1 if evaluations is None else evaluations[tag - 1][value])
            elif tag in (4, 7):
                require(bool(stack), 'unary expression stack')
                if evaluations is not None:
                    stack[-1] = (-stack[-1] if tag == 4 else stack[-1] * value) % modulus
            elif tag in (5, 6):
                require(len(stack) >= 2, 'binary expression stack')
                right, left = stack.pop(), stack.pop()
                if evaluations is None:
                    stack.append(max(left, right) if tag == 5 else left + right)
                else:
                    stack.append((left + right if tag == 5 else left * right) % modulus)
            else:
                require(False, 'expression node')
            require(len(stack) <= 1024, 'expression stack bound')
        require(len(stack) == 1, 'expression result')
        return stack[0]

    def validate(self):
        """All semantic rules in §4, with the reference's explicit k<=10 bound."""
        v, curve = self.values, self.curve
        require(v['protocol_version'] == 1, 'protocol version')
        require(1 <= v['k'] <= 10, 'reference domain exponent')
        require(int.from_bytes(v['base_modulus'], 'little') == curve.base and
                int.from_bytes(v['scalar_modulus'], 'little') == curve.scalar, 'curve moduli')
        pinned = [entry for entry in KATS['params_ipa'][curve.name] if entry['k'] == v['k']]
        require(len(pinned) == 1 and v['params_digest'].hex() == pinned[0]['sha256'],
                'descriptor parameter identity')
        d = v['degree']
        require(3 <= d <= 9 and v['permutation_chunk_len'] == d - 2 and
                v['quotient_pieces'] == d - 1, 'degree pieces')
        counts = [v['num_fixed_columns'], v['num_advice_columns'], len(v['instance_lengths'])]
        require(all(count <= MAX_COUNT for count in counts), 'column count')
        tables = [v['fixed_queries'], v['advice_queries'], v['instance_queries']]
        rotations = {0}
        advice_counts = [0] * counts[1]
        for count, table in zip(counts, tables):
            require(len(set(table)) == len(table), 'duplicate query')
            require(all(index < count for index, _ in table), 'query column')
            rotations.update(rotation for _, rotation in table)
        for index, _ in tables[1]:
            advice_counts[index] += 1
        b = max(3, max(advice_counts, default=1)) + 2
        require(v['blinding_factors'] == b and self.n >= b + 3, 'blinding rows')
        require(all(length <= self.usable for length in v['instance_lengths']), 'instance capacity')
        require(len(set(v['permutation'])) == len(v['permutation']), 'duplicate equality column')
        for kind, index in v['permutation']:
            table = tables[(1, 0, 2)[kind]]
            require((index, 0) in table, 'equality query')
        for gate in v['gates']:
            require(bool(gate), 'empty gate')
            require(all(self.expression(e) <= d for e in gate), 'gate degree')
        for inputs, outputs in v['lookups']:
            require(len(inputs) == len(outputs) and len(inputs) > 0, 'lookup width')
            a = max(self.expression(e) for e in inputs)
            s = max(self.expression(e) for e in outputs)
            require(max(4, 2 + max(1, a) + max(1, s)) <= d, 'lookup degree')
        nz, nl = self.permutation_sets, len(v['lookups'])
        if nz + nl:
            rotations.add(1)
        if nl:
            rotations.add(-1)
        if nz >= 2:
            rotations.add(-(b + 1))
        require(len({r % self.n for r in rotations}) == len(rotations), 'aliased rotations')
        require(all(count + 1 <= b - 1 for count in advice_counts), 'witness exposure')
        require(not nl or 3 <= b - 1, 'lookup exposure')
        require(not nz or (3 if nz >= 2 else 2) + 1 <= b - 1, 'permutation exposure')
        compress, first, entries = v['selectors']
        require(compress in (0, 1), 'selector compression')
        combinations = {comb for _, comb, _ in entries}
        require(combinations == set(range(len(combinations))) and
                first + len(combinations) == counts[0], 'selector columns')
        for combination in combinations:
            members = [(degree, root) for degree, comb, root in entries if comb == combination]
            require({root for _, root in members} == set(range(1, len(members) + 1)), 'selector roots')
            require((first + combination, 0) in tables[0], 'selector query')
        require(all(degree <= d for degree, _, _ in entries), 'selector degree')
        if not compress:
            require(all((comb, root) == (i, 1) for i, (_, comb, root) in enumerate(entries)),
                    'uncompressed selectors')
        types = v['instance_types']
        if types is not None:
            require(len(types) == counts[2], 'instance type count')
            require(all(tag != 2 or bits <= 253 for tag, bits in types), 'instance bit type')
        require(v['transcript'] != 2 or (v['instance_mode'] == 1 and v['proof_suffix'] == 1),
                'PIPA-R profile')

    def check_instances(self, instances):
        """Exact shape, canonical scalars and V2 type bounds."""
        require(isinstance(instances, (list, tuple)), 'instance matrix')
        require(len(instances) == len(self['instance_lengths']), 'instance columns')
        for i, (column, length) in enumerate(zip(instances, self['instance_lengths'])):
            require(isinstance(column, (list, tuple)), 'instance column')
            require(len(column) == length, 'instance length')
            require(all(type(value) is int and 0 <= value < self.curve.scalar for value in column),
                    'instance scalar')
            if self['instance_types'] is not None:
                tag, bits = self['instance_types'][i]
                bound = (self.curve.scalar if tag == 0 else
                         min(self.curve.base, self.curve.scalar) if tag == 1 else 1 << bits)
                require(all(value < bound for value in column), 'instance type')
