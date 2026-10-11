"""Bounded sequential diagnostic requests with private entropy and exact replay.

This is a simulator interface, not wallet storage or production proof authority.
It makes no crash durability, constant-time or ideal-randomness claim.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import secrets

from .simulator import simulate, sample_budget


# Diagnostic intake limits; the descriptor's protocol bounds remain separate.
MAX_INSTANCE_COLUMNS = 256
MAX_INSTANCE_VALUES = 256


def require(value, message):
    if not value:
        raise ValueError(message)


@dataclass(frozen=True)
class Outcome:
    """A canonical attempt response; preflight refusals raise ValueError."""
    proof: bytes | None


class Coins:
    """Per-request facade over one owner stream, never a seed reset."""
    def __init__(self, owner):
        self.owner = owner
        self.calls = 0

    def getrandbits(self, width):
        require(type(width) is int and 1 <= width <= 256, 'bounded bit width')
        require(self.calls < self.owner.per_request_draws, 'request entropy cap')
        require(self.owner.draws < self.owner.total_draws, 'owner entropy cap')
        # Count a failing source invocation too. The source must not be retried
        # or replaced after failure within this request.
        self.calls += 1
        self.owner.draws += 1
        value = self.owner.entropy(width)
        require(type(value) is int and 0 <= value < 1 << width, 'canonical source bits')
        return value


class Owner:
    """Finite atomic requests; private evidence is separate from public outcomes.

    The entropy callable is invoked sequentially. The default uses OS-backed
    secrets.randbits; tests pass one explicitly seeded source for reproducibility.
    Neither choice is identified with ideal independent bits without its own
    substitution assumption. No seed argument or implicit per-request reset
    exists. A failed canonical request is memoized and never retried internally.
    """
    def __init__(self, directory, *, max_requests=8, per_request_draws=40960,
                 total_draws=327680, entropy=secrets.randbits, allow_large=False):
        for value, maximum in ((max_requests,64),(per_request_draws,1 << 20),
                               (total_draws,1 << 24)):
            require(type(value) is int and 1 <= value <= maximum, 'finite owner budget')
        require(callable(entropy), 'explicit bit source')
        require(type(allow_large) is bool, 'explicit large flag')
        self.allow_large = allow_large
        self.root = Path(directory).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.max_requests, self.per_request_draws = max_requests, per_request_draws
        self.total_draws, self.entropy = total_draws, entropy
        self.draws, self.records, self.busy = 0, {}, False

    def submit(self, request_id, case, instances):
        """Accept one canonical request, or replay its exact immutable outcome.

        Invalid request syntax, changed request bindings, reentrant calls and
        exhausted request capacity are refused before drawing entropy. Bindings
        store exact bytes/integers, so replay does not rely on a digest collision
        assumption. Callers own admitted private test cases; no foreign case is
        promoted to shipping parameter authority by this method.
        """
        require(not self.busy, 'atomic owner request')
        require(type(request_id) is bytes and 1 <= len(request_id) <= 64,
                'bounded request identity')
        # Bound columns and their aggregate before visiting any scalar. These
        # finite diagnostic limits do not replace the descriptor's exact shape.
        require(type(instances) is list and len(instances) <= MAX_INSTANCE_COLUMNS and
                all(type(column) is list and len(column) <= MAX_INSTANCE_VALUES for column in instances) and
                sum(len(column) for column in instances) <= MAX_INSTANCE_VALUES and
                all(type(value) is int for column in instances for value in column),
                'bounded canonical instance container')
        require(case.descriptor['k'] <= 6 or self.allow_large, 'large simulation requires opt-in')
        case.descriptor.check_instances(instances)
        budget = sample_budget(case)
        require(all(type(value) is bytes for value in
                    (case.descriptor.raw, case.key, case.raw_params, case.public_original)),
                'immutable admitted case originals')
        frozen_instances = tuple(tuple(column) for column in instances)
        binding = (case.descriptor.raw, case.key, case.raw_params, case.public_original, frozen_instances)
        if request_id in self.records:
            record = self.records[request_id]
            require(record['binding'] == binding, 'request binding changed')
            return record['outcome']
        require(len(self.records) < self.max_requests, 'owner request cap')
        index = len(self.records)
        record = {'binding':binding, 'outcome':Outcome(None), 'index':index,
                  'failure':None, 'draws':0, 'simulated_draw_budget':budget}
        failed_outcome = record['outcome']
        self.records[request_id] = record
        self.busy = True
        coins = Coins(self)
        try:
            directory = self.root/f'{index:04d}'
            directory.mkdir(mode=0o700, exist_ok=False)
            # Copy only the case record's output location; the admitted verifier,
            # key/descriptor and setup/log objects retain exactly the same values.
            selected = replace(case, directory=directory)
            args, verified, private = simulate(selected, [list(c) for c in frozen_instances], coins,
                                              allow_large=self.allow_large)
            proof = args['proof']
            require(type(proof) is bytes and len(proof) <= 10000, 'bounded proof outcome')
            require((directory/'proof.bin').read_bytes() == proof, 'retained proof differs')
            # Publish success only after all fallible validation and metadata.
            proof_sha256 = hashlib.sha256(proof).hexdigest()
            outcome = Outcome(proof)
            record['proof_sha256'] = proof_sha256
            record['outcome'] = outcome
            return record['outcome']
        except BaseException as error:
            record['outcome'] = failed_outcome
            record.pop('proof_sha256', None)
            record['failure'] = type(error).__name__+': '+str(error)
            if not isinstance(error, Exception):
                raise
            return record['outcome']
        finally:
            record['draws'] = coins.calls
            self.busy = False

    def retain_private_observation(self):
        """Diagnostic-only observations; never part of the public Outcome API."""
        rows = []
        for request_id, record in self.records.items():
            descriptor, key, params, public_original, instances = record['binding']
            rows.append({'request_id':request_id.hex(),'index':record['index'],
                         'status':'proved' if record['outcome'].proof is not None else 'failed',
                         'draws':record['draws'],'failure':record['failure'],
                         'simulated_draw_budget':record['simulated_draw_budget'],
                         'proof_sha256':record.get('proof_sha256'),
                         'descriptor_sha256':hashlib.sha256(descriptor).hexdigest(),
                         'key_sha256':hashlib.sha256(key).hexdigest(),
                         'parameter_sha256':hashlib.sha256(params).hexdigest(),
                         'public_original_sha256':hashlib.sha256(public_original).hexdigest(),
                         'instances':instances})
        data = {'scope':'Private diagnostic state; no public timing/failure-reason API',
                'requests':rows,'entropy_calls':self.draws,'max_requests':self.max_requests,
                'per_request_draws':self.per_request_draws,'total_draws':self.total_draws,
                'crash_durability':False,'C12_closed':False}
        with (self.root/'private-observation.json').open('x') as stream:
            json.dump(data,stream,indent=2,sort_keys=True);stream.write('\n')
        return data
