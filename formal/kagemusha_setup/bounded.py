"""Bounded source-map chosen-parameter producer; synthetic setup, never authority.

Importing this module creates no sampler, parameters,
or output. Large execution needs an explicit Limits.allow_large choice.
"""
from dataclasses import dataclass, asdict
import hashlib
import json
import os
import stat
from pathlib import Path
import tracemalloc

from .custody import require, sha

MAX_K = 16
MAX_CONTEXTS = 2*((1 << MAX_K)+2)
MAX_QUERIES = 1 << 20
MAX_REQUESTS = 34
MAX_QUERY_BYTES = 256
MAX_MEMORY_BYTES = 2 << 30


@dataclass(frozen=True)
class Limits:
    """Finite owner limits; reservation/traced allocations are not an RSS claim."""
    max_k: int = 6
    contexts: int = 132
    queries: int = 1024
    entries: int = 412
    requests: int = 8
    memory_bytes: int = 32 << 20
    output_bytes: int = 1 << 20
    allow_large: bool = False

    def validate(self):
        bounds = {'max_k':(0,MAX_K), 'contexts':(0,MAX_CONTEXTS),
                  'queries':(0,MAX_QUERIES), 'entries':(0,3*MAX_CONTEXTS+MAX_QUERIES),
                  'requests':(1,MAX_REQUESTS), 'memory_bytes':(1,MAX_MEMORY_BYTES),
                  'output_bytes':(1,32 << 20)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            require(type(value) is int and low <= value <= high, 'bounded '+name)
        require(type(self.allow_large) is bool, 'explicit large flag')
        require(self.max_k <= 6 or self.allow_large, 'large execution requires opt-in')
        # Logical object reservation for controlled containers. This is an
        # explicit conservative engineering allowance, not a Python/RSS theorem.
        require(self.reservation() <= self.memory_bytes, 'memory reservation insufficient')
        return self

    def reservation(self):
        return ((16 << 20)+1536*self.entries+1024*self.contexts+
                512*(1 << self.max_k)+3*(64*(1 << self.max_k)+68))


class TracedMemory:
    """Checkpoint peak Python allocations; overshoot and RSS remain observable.

    The CLI starts a fresh tracemalloc instance before model construction. This
    does not impose an OS address-space limit or claim instantaneous RSS control.
    The largest unchecked region is one bounded sampler call or FFT stage.
    """
    def __init__(self, limit):
        require(not tracemalloc.is_tracing(), 'exclusive fresh traced-allocation owner')
        self.limit = limit
        tracemalloc.start(1)

    def checkpoint(self):
        current, peak = tracemalloc.get_traced_memory()
        require(peak <= self.limit, 'traced allocation budget exceeded')
        return {'current_bytes':current, 'peak_bytes':peak}

    def observe(self):
        current, peak = tracemalloc.get_traced_memory()
        return {'current_bytes':current, 'peak_bytes':peak,
                'limit_bytes':self.limit, 'process_rss_qualified':False}

    def close(self):
        tracemalloc.stop()


def scalar_ifft(values, curve, k, checkpoint=lambda: None):
    """Reviewed radix-two IFFT, one normalization, plus native k0 case."""
    require(type(k) is int and 0 <= k <= MAX_K, 'scalar IFFT exponent')
    n, m = 1 << k, curve.scalar
    require(len(values) == n and all(type(v) is int and 0 <= v < m for v in values),
            'scalar IFFT canonical input')
    if k == 0:
        checkpoint()
        return tuple(values)
    out = list(values)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            out[i], out[j] = out[j], out[i]
    root = pow(curve.omega(k), -1, m)
    width = 2
    while width <= n:
        step = pow(root, n//width, m)
        for start in range(0, n, width):
            power = 1
            for offset in range(width//2):
                left = out[start+offset]
                right = out[start+offset+width//2]*power % m
                out[start+offset] = (left+right) % m
                out[start+offset+width//2] = (left-right) % m
                power = power*step % m
        checkpoint()
        width *= 2
    scale = pow(n, -1, m)
    return tuple(value*scale % m for value in out)


class OracleView:
    """Internal small-family facade; no second primitive table or sampler."""
    def __init__(self, owner):
        self.owner = owner

    @property
    def logs(self):
        return self.owner.oracle.logs

    def expand(self, tag, message):
        owner = self.owner
        b0 = owner.query(owner.raw.input0(tag,message))
        b1 = owner.query(owner.raw.input1(tag,b0))
        return b1, owner.query(owner.raw.input2(tag,b0,b1))


class Owner:
    """One shared raw oracle, one sampler, no restart after an owner failure.

    Callers may inspect tables only as private diagnostic custody. They are not
    public oracle capabilities. The CLI never retains all point objects.
    """
    def __init__(self, raw, parameters, rng, limits=Limits(), *, sampler=None,
                 memory=None):
        self.limits = limits.validate()
        self.raw, self.parameters, self.memory = raw, parameters, memory
        self.sampler = (raw.FreshTargetSampler(raw, rng) if sampler is None else sampler)
        self.oracle = raw.RawSetupOracle(rng, self.sampler, query_budget=limits.queries,
                                         setup_budget=limits.contexts)
        self.family = parameters.ParameterFamily(raw, OracleView(self), self.sampler)
        self.stopped, self.requests, self.output_used = None, [], 0
        self._checkpoint()

    def _checkpoint(self):
        if self.memory is not None:
            self.memory.checkpoint()

    def _ready(self):
        if self.stopped is not None:
            raise self.raw.Refused(self.stopped)

    def query(self, data):
        """Bound raw API calls and potential atomic triple allocation first."""
        self._ready()
        try:
            require(type(data) is bytes and len(data) <= MAX_QUERY_BYTES,
                    'bounded raw byte query')
            growth = 0 if data in self.oracle.table else (3 if self.raw.recognize0(data) else 1)
            require(len(self.oracle.table)+growth <= self.limits.entries, 'raw entry budget exceeded')
            answer = self.oracle.query(data)
            self._checkpoint()
            return answer
        except BaseException as error:
            self.stopped = type(error).__name__+': '+str(error)
            raise

    def point(self, tag, message):
        """Same three raw queries and independent source-map/log check as small owner."""
        self._ready()
        try:
            require(type(tag) is int and tag in (0,1), 'exact curve tag')
            require(type(message) is bytes and self.raw.setup_message(message), 'setup message')
            answer = self.family.point(tag, message)
            self._checkpoint()
            return answer
        except BaseException as error:
            self.stopped = type(error).__name__+': '+str(error)
            raise

    def derive(self, tag, k):
        """All g, first-invalid g, IFFT, W/U, encoding-order identity checks."""
        self._ready()
        record = {'curve':tag, 'k':k, 'status':'started'}
        try:
            require(type(tag) is int and tag in (0,1), 'exact curve tag')
            require(type(k) is int and 0 <= k <= self.limits.max_k, 'selected domain bound')
            require(len(self.requests) < self.limits.requests, 'request budget exceeded')
            size = 64*(1 << k)+68
            require(self.output_used+size <= self.limits.output_bytes, 'wire output budget exceeded')
            self.requests.append(record)
            model, n = self.sampler.models[tag], 1 << k
            curve = model.curve
            base = model.isogeny(model.forward(1))
            g, encoded_g, first_invalid = [], bytearray(), None
            for i in range(n):
                point, log = self.point(tag, b'\0'+i.to_bytes(4,'little'))
                g.append(log)
                encoded_g.extend(curve.encode(point))
                if point[2] == 0 and first_invalid is None:
                    first_invalid = i
            if first_invalid is not None:
                raise self.raw.Refused('native parameter identity at index '+str(first_invalid))
            lagrange = scalar_ifft(g, curve, k, self._checkpoint)
            encoded_lagrange, first_invalid = bytearray(), None
            for i, log in enumerate(lagrange):
                point = curve.multiply(base, log)
                encoded_lagrange.extend(curve.encode(point))
                if point[2] == 0 and first_invalid is None:
                    first_invalid = n+i
                self._checkpoint()
            w, w_log = self.point(tag,b'\1')
            u, u_log = self.point(tag,b'\2')
            for index, point in ((2*n,w),(2*n+1,u)):
                if point[2] == 0 and first_invalid is None:
                    first_invalid = index
            if first_invalid is not None:
                raise self.raw.Refused('native parameter identity at index '+str(first_invalid))
            encoded = (k.to_bytes(4,'little')+bytes(encoded_g)+bytes(encoded_lagrange)+
                       curve.encode(w)+curve.encode(u))
            require(len(encoded) == size, 'native wire extent')
            result = self.parameters.Parameters(tag,k,base,bytes(encoded),
                       {'g':tuple(g),'lagrange':lagrange,'w':w_log,'u':u_log})
            self._checkpoint()
            self.output_used += size
            record.update(status='returned', bytes=size, sha256=sha(result.raw))
            return result
        except BaseException as error:
            record.update(status='refused', reason=type(error).__name__+': '+str(error))
            if not self.requests or self.requests[-1] is not record:
                # A failed request before append is preserved separately; the
                # owner is terminal and cannot use this to evade request limits.
                self.rejected_request = record
            self.stopped = record['reason']
            raise

    def persist(self, directory):
        """Stream exact private raw table/log/attempt state, including failures."""
        directory = Path(directory)
        emitted = 0
        disk_cap = 1024*self.limits.entries+2048*self.limits.contexts+(1 << 20)
        def rows(name, values):
            nonlocal emitted
            with (directory/name).open('x') as stream:
                for value in values:
                    encoded = json.dumps(value,sort_keys=True)+'\n'
                    emitted += len(encoded.encode())
                    require(emitted <= disk_cap, 'private evidence byte budget exceeded')
                    stream.write(encoded)
                stream.flush()
        rows('raw-table-private.jsonl', ({'input':key.hex(),'answer':value.hex()}
                                        for key,value in self.oracle.table.items()))
        rows('context-logs-private.jsonl', ({'curve':tag,'message':message.hex(),'scalar':scalar}
                   for (tag,message),scalar in self.oracle.logs.items()))
        rows('sampler-attempts-private.jsonl', iter(self.sampler.records))
        summary = {'limits':asdict(self.limits),'logical_reservation_bytes':self.limits.reservation(),
                   'contexts':len(self.oracle.logs),'raw_entries':len(self.oracle.table),
                   'raw_queries':self.oracle.queries,'sampler_calls':len(self.sampler.records),
                   'oracle_stopped':self.oracle.stopped,'owner_stopped':self.stopped,
                   'requests':self.requests,'rejected_request':getattr(self,'rejected_request',None),
                   'output_bytes':self.output_used,'family_resamples':0,
                   'private_jsonl_bytes':emitted,'private_jsonl_cap':disk_cap,
                   'simulator_private_state_not_public_API':True}
        with (directory/'owner-state.json').open('x') as stream:
            json.dump(summary,stream,indent=2,sort_keys=True);stream.write('\n')
        return summary


def new_output(path):
    """Fresh owner-only diagnostic tree; no overwrite or durability claim."""
    path = Path(path).resolve()
    path.mkdir(mode=0o700,parents=True,exist_ok=False)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'owner-only output directory')
    return path


def artifact_inventory(directory, max_files, max_bytes):
    """Bounded streaming final custody hashes; no all-table or log-tree copy."""
    directory = Path(directory)
    paths = sorted(directory.iterdir())
    require(len(paths) <= max_files, 'artifact file budget exceeded')
    rows, total = [], 0
    for path in paths:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), 'regular artifact required')
        total += before.st_size
        require(total <= max_bytes, 'artifact byte budget exceeded')
        digest = hashlib.sha256()
        flags = os.O_RDONLY | getattr(os,'O_NOFOLLOW',0)
        with os.fdopen(os.open(path,flags),'rb') as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns) ==
                    (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),
                    'artifact changed before read')
            consumed = 0
            while block := stream.read(1 << 20):
                consumed += len(block)
                require(consumed <= before.st_size,'artifact grew during read')
                digest.update(block)
            after = os.fstat(stream.fileno())
        current = path.lstat()
        require(consumed == before.st_size and
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) ==
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) and
                (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns) ==
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),
                'artifact changed during read')
        rows.append({'name':path.name,'bytes':consumed,'sha256':digest.hexdigest()})
    require(sorted(path.name for path in directory.iterdir()) == [row['name'] for row in rows],
            'artifact namespace changed during read')
    return rows
