"""Diagnostic raw random-oracle adapter for the exact public setup XMD recipe.

The primitive here is an ideal 512-bit random oracle, not actual BLAKE2b.
Diagnostic random.Random coins are not production entropy. No pinned release
parameters, verifier, or production hash implementation is changed.
"""
from dataclasses import dataclass
from .preimage import Swu
from .custody import require

PAIR_ATTEMPTS = 4096
DRAW_ATTEMPTS = 256


class Refused(Exception):
    """An explicit, terminal failure outcome; it is never silently retried."""


def bounded_uniform(rng, upper, attempts=128):
    """Uniform integer conditional on bounded rejection-sampling success."""
    if type(upper) is not int or upper <= 0 or type(attempts) is not int or attempts < 0:
        raise ValueError('positive upper and finite nonnegative draw budget required')
    for _ in range(attempts):
        value = rng.getrandbits(upper.bit_length())
        if 0 <= value < upper:
            return value
    raise Refused('canonical draw exhausted')


def lift(residue, modulus, rng, attempts=128):
    """Uniform exact 64-byte representative of one canonical field residue."""
    if type(residue) is not int or not 0 <= residue < modulus or not 0 < modulus < 1 << 512:
        raise ValueError('canonical residue and modulus required')
    count = ((1 << 512) - 1 - residue) // modulus + 1
    j = bounded_uniform(rng, count, attempts)
    return (residue + modulus * j).to_bytes(64, 'big')


def dst(tag):
    """The exact native Halo2-Parameters DST including its length byte."""
    if tag not in (0, 1):
        raise ValueError('Pallas or Vesta required')
    text = b'Halo2-Parameters-' + (b'pallas', b'vesta')[tag] + b'_XMD:BLAKE2b_SSWU_RO_'
    return text + bytes([len(text)])


def setup_message(message):
    """Only the full k<=16 generator prefix and the shared W/U messages."""
    return type(message) is bytes and (message in (b'\x01', b'\x02') or
        len(message) == 5 and message[0] == 0 and int.from_bytes(message[1:], 'little') < 1 << 16)


def input0(tag, message):
    """First XMD primitive input for one designated setup message."""
    if not setup_message(message):
        raise ValueError('designated setup message required')
    return bytes(128) + message + bytes([0, 128, 0]) + dst(tag)


def input1(tag, b0):
    """Second XMD primitive input, including its exact step byte."""
    if len(b0) != 64:
        raise ValueError('64-byte b0 required')
    return b0 + b'\x01' + dst(tag)


def input2(tag, b0, b1):
    """Third XMD primitive input, with native XOR and step byte."""
    if len(b0) != 64 or len(b1) != 64:
        raise ValueError('64-byte XMD words required')
    return bytes(a ^ b for a, b in zip(b0, b1)) + b'\x02' + dst(tag)


def recognize0(data):
    """Recognize predictable raw setup inputs before any high-level request."""
    for tag in (0, 1):
        tail = bytes([0, 128, 0]) + dst(tag)
        if data.startswith(bytes(128)) and data.endswith(tail):
            message = data[128:-len(tail)]
            if setup_message(message) and input0(tag, message) == data:
                return tag, message
    return None


@dataclass(frozen=True)
class SetupWords:
    """Simulator-private log and exact raw output words for one setup answer."""
    scalar: int
    b1: bytes
    b2: bytes


class RawSetupOracle:
    """One shared, bounded, append-only ideal primitive table.

    Recognized raw b0 queries allocate the complete triple atomically. The
    simulator checks both inner inputs before exposing b0. Private logs are
    available only to the model's simulator, never part of query() output.
    """

    def __init__(self, rng, sampler, query_budget=256, setup_budget=32):
        if any(type(n) is not int or n < 0 for n in (query_budget, setup_budget)):
            raise ValueError('finite nonnegative budgets required')
        self.rng, self.sampler = rng, sampler
        self.query_budget, self.setup_budget = query_budget, setup_budget
        self.table, self.logs = {}, {}
        self.queries = 0
        self.stopped = None

    def refuse(self, reason):
        self.stopped = reason
        raise Refused(reason)

    def query(self, data):
        if self.stopped is not None:
            raise Refused(self.stopped)
        if type(data) is not bytes or len(data) > 1 << 20:
            self.refuse('bounded raw byte query required')
        if self.queries >= self.query_budget:
            self.refuse('query budget exhausted')
        self.queries += 1
        if data in self.table:
            return self.table[data]
        selected = recognize0(data)
        if selected is None:
            answer = self.rng.getrandbits(512).to_bytes(64, 'big')
            self.table[data] = answer
            return answer
        if len(self.logs) >= self.setup_budget:
            self.refuse('setup budget exhausted')
        tag, message = selected
        try:
            words = self.sampler(tag)
        except Refused as error:
            self.refuse(str(error))
        if not isinstance(words, SetupWords) or len(words.b1) != 64 or len(words.b2) != 64:
            self.refuse('malformed private sampler output')
        b0 = self.rng.getrandbits(512).to_bytes(64, 'big')
        first, second = input1(tag, b0), input2(tag, b0, words.b1)
        if len({data, first, second}) != 3 or first in self.table or second in self.table:
            self.refuse('occupied XMD input; no overwrite')
        # Atomic model boundary: no observer query interleaves these assignments.
        self.table.update({data: b0, first: words.b1, second: words.b2})
        self.logs[(tag, message)] = words.scalar
        return b0

    def expand(self, tag, message):
        """Read the native three-call interface, including exact cache replays."""
        b0 = self.query(input0(tag, message))
        b1 = self.query(input1(tag, b0))
        b2 = self.query(input2(tag, b0, b1))
        return b1, b2


class FreshTargetSampler:
    """Refresh t, u and the inverse slot on EVERY ordinary failed attempt.

    Zero targets stay in the distribution. A canonical-draw or lift exhaustion
    immediately returns the raw adapter's terminal Refused outcome. Logs and
    attempt records are private simulator state, not raw-oracle API replies.
    There is deliberately no fixed-target argument or pair_preimage() call.
    """

    def __init__(self, raw, rng, *, pair_attempts=PAIR_ATTEMPTS,
                 draw_attempts=DRAW_ATTEMPTS, models=None):
        require(type(pair_attempts) is int and 0 <= pair_attempts <= PAIR_ATTEMPTS,
                'bounded pair attempts')
        require(type(draw_attempts) is int and 0 <= draw_attempts <= DRAW_ATTEMPTS,
                'bounded canonical draws')
        self.raw, self.rng = raw, rng
        self.pair_attempts, self.draw_attempts = pair_attempts, draw_attempts
        self.models = (raw.Swu(0), raw.Swu(1)) if models is None else tuple(models)
        require(len(self.models) == 2, 'two source curves or explicit test models')
        self.records = []

    def __call__(self, tag):
        require(type(tag) is int and tag in (0, 1), 'exact curve tag')
        model = self.models[tag]
        record = {'curve': tag, 'attempts': 0, 'status': 'started',
                  'pair_attempts': self.pair_attempts, 'draw_attempts': self.draw_attempts}
        self.records.append(record)
        try:
            for attempt in range(self.pair_attempts):
                record['attempts'] = attempt+1
                # All three draws precede the deterministic inverse. Each is
                # uniform conditional on success; each cap stops the whole call.
                scalar = self.raw.bounded_uniform(self.rng, model.curve.scalar,
                                                   self.draw_attempts)
                u = self.raw.bounded_uniform(self.rng, model.p, self.draw_attempts)
                slot = self.raw.bounded_uniform(self.rng, 9, self.draw_attempts)
                target = model.multiply(model.forward(1), scalar)
                remainder = model.add(target, model.negate(model.forward(u)))
                fiber = model.inverse(remainder)
                require(len(fiber) <= 9 and len(set(fiber)) == len(fiber),
                        'complete inverse has unique bounded slots')
                if slot >= len(fiber):
                    continue
                v = fiber[slot]
                require(model.add(model.forward(u), model.forward(v)) == target,
                        'exact inverse equation')
                words = self.raw.SetupWords(scalar,
                    self.raw.lift(u, model.p, self.rng, self.draw_attempts),
                    self.raw.lift(v, model.p, self.rng, self.draw_attempts))
                record['status'] = 'returned'
                return words
            raise self.raw.Refused('fresh-target pair attempts exhausted')
        except self.raw.Refused as error:
            record['status'], record['reason'] = 'refused', str(error)
            raise

