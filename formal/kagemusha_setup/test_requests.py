"""Small sequential/adaptive simulator controls; no native or full-size proof."""
from dataclasses import FrozenInstanceError, dataclass, fields, replace
import hashlib
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import Mock, patch

from .custody import ROOT

OUTPUT = None


class _ShapeDescriptor(dict):
    """Request-boundary fixture only; never a decoded or admitted descriptor."""
    def __init__(self, lengths, k=16):
        super().__init__(k=k)
        self.lengths = lengths
        self.raw = repr((lengths, k)).encode()
        self.checked = 0

    def check_instances(self, instances):
        from .requests import require
        self.checked += 1
        require([len(column) for column in instances] == self.lengths, 'fixture descriptor shape')
        require(all(0 <= value < 257 for column in instances for value in column),
                'fixture canonical scalar')


@dataclass
class _ShapeCase:
    """Immutable-byte binding fixture; has no parameters, keys or proof authority."""
    descriptor: _ShapeDescriptor
    directory: Path
    key: bytes = b'request-shape-key-fixture'
    raw_params: bytes = b'request-shape-parameter-fixture'
    public_original: bytes = b'request-shape-original-fixture'


class RequestShapeTests(unittest.TestCase):
    """Bounded admission and failure replay, with no simulator or proof execution."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='request-shapes-', dir=OUTPUT if OUTPUT is not None else ROOT/'target')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        simulator = patch(__package__+'.requests.simulate',
                          side_effect=ValueError('deliberate pre-proof sentinel'))
        budget = patch(__package__+'.requests.sample_budget',
                       return_value={'scope': 'request-shape data fixture'})
        self.addCleanup(simulator.stop)
        self.addCleanup(budget.stop)
        self.simulator, self.budget = simulator.start(), budget.start()
        self.entropy = Mock(side_effect=AssertionError('unexpected entropy'))

    def owner_case(self, lengths, *, allow_large=True, k=16):
        from .requests import Owner
        owner = Owner(self.root/f'owner-{len(list(self.root.iterdir()))}',
                      entropy=self.entropy, allow_large=allow_large, max_requests=1)
        return owner, _ShapeCase(_ShapeDescriptor(lengths, k), self.root)

    def test_load_69_admitted_failure_replays_at_capacity_and_changed_binding_refuses(self):
        owner, case = self.owner_case([69])
        values = [list(range(69))]
        result = owner.submit(b'load', case, values)
        self.assertIsNone(result.proof)
        self.assertIn('deliberate pre-proof sentinel', owner.records[b'load']['failure'])
        self.assertEqual(self.simulator.call_count, 1)
        values[0][0] = 7
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            owner.submit(b'load', case, values)
        self.assertIs(owner.submit(b'load', case, [list(range(69))]), result)
        self.assertEqual(self.simulator.call_count, 1)
        self.assertEqual(owner.draws, 0)
        self.entropy.assert_not_called()

    def test_same_256_total_budget_accepts_different_descriptor_shapes(self):
        for lengths in ([256], [128, 128], [64, 64, 64, 64]):
            with self.subTest(lengths=lengths):
                owner, case = self.owner_case(lengths)
                self.assertIsNone(owner.submit(b'bounded', case, [[0]*n for n in lengths]).proof)
                self.assertIn(b'bounded', owner.records)
        self.assertEqual(self.simulator.call_count, 3)
        self.entropy.assert_not_called()

    def test_oversize_containers_refuse_before_descriptor_and_attempt(self):
        for values in ([[0]*257], [[0]*129, [0]*128], [[] for _ in range(257)]):
            with self.subTest(lengths=[len(c) for c in values]):
                owner, case = self.owner_case([len(c) for c in values])
                with self.assertRaisesRegex(ValueError, 'bounded canonical instance container'):
                    owner.submit(b'large', case, values)
                self.assertEqual(case.descriptor.checked, 0)
                self.assertEqual(owner.records, {})
        self.simulator.assert_not_called()
        self.budget.assert_not_called()
        self.entropy.assert_not_called()

    def test_non_list_columns_and_non_integer_values_refuse_before_attempt(self):
        for values in (([0],), [(0,)], [[True]], [[1.0]], [[None]]):
            with self.subTest(values=values):
                owner, case = self.owner_case([1])
                with self.assertRaisesRegex(ValueError, 'bounded canonical instance container'):
                    owner.submit(b'syntax', case, values)
                self.assertEqual(case.descriptor.checked, 0)
                self.assertEqual(owner.records, {})
        self.simulator.assert_not_called()
        self.entropy.assert_not_called()

    def test_descriptor_shape_and_scalar_validation_remain_required(self):
        for values, reason in (([[0]*68], 'descriptor shape'), ([[0]*70], 'descriptor shape'),
                               ([[-1]+[0]*68], 'canonical scalar'), ([[257]+[0]*68], 'canonical scalar')):
            with self.subTest(reason=reason):
                owner, case = self.owner_case([69])
                with self.assertRaisesRegex(ValueError, reason):
                    owner.submit(b'invalid', case, values)
                self.assertEqual(case.descriptor.checked, 1)
                self.assertEqual(owner.records, {})
        self.simulator.assert_not_called()
        self.budget.assert_not_called()
        self.entropy.assert_not_called()

    def test_large_opt_in_is_still_required_and_small_requests_keep_working(self):
        owner, case = self.owner_case([69], allow_large=False)
        with self.assertRaisesRegex(ValueError, 'large simulation requires opt-in'):
            owner.submit(b'load', case, [[0]*69])
        self.assertEqual(case.descriptor.checked, 0)
        self.assertEqual(owner.records, {})
        small, small_case = self.owner_case([1], allow_large=False, k=6)
        self.assertIsNone(small.submit(b'small', small_case, [[1]]).proof)
        self.assertEqual(self.simulator.call_count, 1)
        self.entropy.assert_not_called()

    def test_five_column_q0_shape_replays_and_keeps_descriptor_checks(self):
        # Exact historical Load Q0 lengths, used only as request-shape DATA.
        # This fixture neither decodes nor admits the native descriptor.
        lengths = [124, 2, 1, 1, 1]
        owner, case = self.owner_case(lengths)
        values = [list(range(n)) for n in lengths]
        result = owner.submit(b'q0', case, values)
        self.assertIsNone(result.proof)
        self.assertIn('deliberate pre-proof sentinel', owner.records[b'q0']['failure'])
        self.assertIs(owner.submit(b'q0', case, [column[:] for column in values]), result)
        changed = [column[:] for column in values]
        changed[0][0] = 7
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            owner.submit(b'q0', case, changed)
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            owner.submit(b'q0', replace(case, key=case.key+b'foreign'), values)
        self.assertEqual(self.simulator.call_count, 1)
        self.assertEqual(set(owner.records), {b'q0'})
        self.assertEqual(owner.draws, 0)

        # Same aggregate with a different partition still fails exact lengths.
        for invalid, reason in (([[0]*123, [0]*3, [0], [0], [0]], 'descriptor shape'),
                                ([[-1]+[0]*123, [0, 0], [0], [0], [0]], 'canonical scalar'),
                                ([[257]+[0]*123, [0, 0], [0], [0], [0]], 'canonical scalar')):
            refused, selected = self.owner_case(lengths)
            before_budget = self.budget.call_count
            with self.assertRaisesRegex(ValueError, reason):
                refused.submit(b'q0', selected, invalid)
            self.assertEqual(selected.descriptor.checked, 1)
            self.assertEqual(refused.records, {})
            self.assertEqual(self.budget.call_count, before_budget)
        no_large, selected = self.owner_case(lengths, allow_large=False)
        with self.assertRaisesRegex(ValueError, 'large simulation requires opt-in'):
            no_large.submit(b'q0', selected, values)
        self.assertEqual(selected.descriptor.checked, 0)
        self.assertEqual(no_large.records, {})
        self.assertEqual(self.simulator.call_count, 1)
        self.entropy.assert_not_called()

    def test_named_column_limit_accepts_256_and_refuses_257(self):
        from . import requests
        for lengths in ([0]*256, [1]*256):
            with self.subTest(lengths=lengths):
                owner, case = self.owner_case(lengths)
                outcome = owner.submit(b'columns', case, [[0]*n for n in lengths])
                self.assertIsNone(outcome.proof)
                self.assertIn('deliberate pre-proof sentinel', owner.records[b'columns']['failure'])
                self.assertEqual(case.descriptor.checked, 1)
                self.assertEqual(owner.draws, 0)
        self.assertEqual(self.simulator.call_count, 2)
        for values in ([[] for _ in range(257)], [[0]]+[[] for _ in range(256)]):
            owner, case = self.owner_case([len(column) for column in values])
            before_budget = self.budget.call_count
            with self.assertRaisesRegex(ValueError, 'bounded canonical instance container'):
                owner.submit(b'columns', case, values)
            self.assertEqual(case.descriptor.checked, 0)
            self.assertEqual(owner.records, {})
            self.assertEqual(self.budget.call_count, before_budget)
        self.assertEqual(self.simulator.call_count, 2)
        self.entropy.assert_not_called()
        self.assertEqual((requests.MAX_INSTANCE_COLUMNS, requests.MAX_INSTANCE_VALUES), (256, 256))

    def test_shape_budgets_refuse_before_visiting_scalar_values(self):
        sentinel = object()
        real_type = type
        def metadata_type(value):
            if value is sentinel:
                raise AssertionError('scalar visited before shape budget refusal')
            return real_type(value)
        # Per-column, aggregate, many-column aggregate, then column-count caps.
        matrices = ([[sentinel]*257], [[sentinel]*129, [sentinel]*128],
                    [[sentinel, sentinel]]+[[sentinel] for _ in range(255)],
                    [[sentinel]]+[[] for _ in range(256)])
        for values in matrices:
            owner, case = self.owner_case([len(column) for column in values])
            with patch(__package__+'.requests.type', side_effect=metadata_type, create=True):
                with self.assertRaisesRegex(ValueError, 'bounded canonical instance container'):
                    owner.submit(b'over-limit', case, values)
            self.assertEqual(case.descriptor.checked, 0)
            self.assertEqual(owner.records, {})
            self.assertEqual(owner.draws, 0)
        self.simulator.assert_not_called()
        self.budget.assert_not_called()
        self.entropy.assert_not_called()


class OwnerTests(unittest.TestCase):
    verified_toy_proofs = 0

    @classmethod
    def setUpClass(cls):
        from . import case
        from .requests import Owner
        cls.families, observation = case.build_families(OUTPUT/'families')
        cls.cases, cls.owners, cls.outcomes = {}, {}, {}
        for tag in (0,1):
            selected = case.make_case(OUTPUT/f'case-{tag}',tag,cls.families[tag])
            stream = random.Random(919+tag)
            owner = Owner(OUTPUT/f'owner-{tag}',entropy=stream.getrandbits,max_requests=2)
            first = owner.submit(b'first',selected,[[1]])
            if first.proof is None:
                raise ValueError('first actual proof failed: '+str(owner.records))
            cls.verified_toy_proofs += 1
            # Next input is a function of the first public proof, using fresh
            # draws from the same stream. No second default seed exists.
            second_input = [[int.from_bytes(first.proof[-96:-64],'little') % 3+1]]
            second = owner.submit(b'second',selected,second_input)
            if second.proof is None:
                raise ValueError('second actual proof failed: '+str(owner.records))
            cls.verified_toy_proofs += 1
            cls.cases[tag], cls.owners[tag] = selected, owner
            cls.outcomes[tag] = (first,second,second_input)
            owner.retain_private_observation()

    def test_first_proof_preserves_goldens_and_second_verifies_both_curves(self):
        goldens = json.loads((ROOT/'formal/kagemusha_setup/control_goldens.json').read_text())
        for tag,case in self.cases.items():
            first,second,second_input = self.outcomes[tag]
            self.assertEqual(hashlib.sha256(first.proof).hexdigest(),
                             goldens['cases'][f'{tag}-ordinary']['proof_sha256'])
            self.assertNotEqual(first.proof,second.proof)
            for outcome,instance in ((first,[[1]]),(second,second_input)):
                case.verifier.verify(descriptor=case.descriptor.raw,version=2,key=case.key,
                                     parameter_bytes=case.raw_params,instances=instance,
                                     proof=outcome.proof)

    def test_replay_is_exact_at_capacity_and_consumes_no_entropy(self):
        for tag,owner in self.owners.items():
            before = owner.draws
            first,second,second_input = self.outcomes[tag]
            self.assertIs(owner.submit(b'first',self.cases[tag],[[1]]),first)
            self.assertIs(owner.submit(b'second',self.cases[tag],second_input),second)
            self.assertEqual(owner.draws,before)
            with self.assertRaisesRegex(ValueError,'request cap'):
                owner.submit(b'third',self.cases[tag],[[1]])
            self.assertEqual(owner.draws,before)

    def test_changed_binding_and_invalid_syntax_refuse_before_entropy(self):
        owner,case = self.owners[0],self.cases[0]
        before = owner.draws
        with self.assertRaisesRegex(ValueError,'binding changed'):
            owner.submit(b'first',case,[[2]])
        with self.assertRaisesRegex(ValueError,'binding changed'):
            owner.submit(b'first',replace(case,key=case.key+b'foreign'),[[1]])
        with self.assertRaisesRegex(ValueError,'binding changed'):
            owner.submit(b'first',replace(case,public_original=case.public_original+b'foreign'),[[1]])
        for request,instance in ((b'',[[1]]),(b'x'*65,[[1]]),(b'ok',[[True]])):
            with self.assertRaises(ValueError):
                owner.submit(request,case,instance)
        self.assertEqual(owner.draws,before)

    def test_failed_identity_is_memoized_without_resampling(self):
        from .requests import Owner
        calls = []
        def zeros(width):
            calls.append(width)
            return 0
        owner = Owner(OUTPUT/'zero-failure',entropy=zeros)
        result = owner.submit(b'failed',self.cases[0],[[1]])
        self.assertIsNone(result.proof)
        self.assertEqual(calls,[self.cases[0].descriptor.curve.scalar.bit_length()])
        self.assertIs(owner.submit(b'failed',self.cases[0],[[1]]),result)
        self.assertEqual(len(calls),1)
        self.assertIn('point identity',owner.records[b'failed']['failure'])
        owner.retain_private_observation()

    def test_entropy_caps_invalid_bits_and_provider_failure_are_terminal(self):
        from .requests import Owner
        for label,source,cap,reason in (
                ('negative',lambda n:-1,8192,'canonical source bits'),
                ('boolean',lambda n:True,8192,'canonical source bits'),
                ('overwide',lambda n:1 << n,8192,'canonical source bits'),
                ('source-fault',lambda n:(_ for _ in ()).throw(OSError('entropy unavailable')),8192,'entropy unavailable'),
                ('request-cap',lambda n:1,1,'request entropy cap')):
            owner = Owner(OUTPUT/label,entropy=source,per_request_draws=cap)
            first = owner.submit(b'one',self.cases[0],[[1]])
            before = owner.draws
            self.assertIsNone(first.proof)
            self.assertIn(reason,owner.records[b'one']['failure'])
            self.assertIs(owner.submit(b'one',self.cases[0],[[1]]),first)
            self.assertEqual(owner.draws,before)
            owner.retain_private_observation()
        owner = Owner(OUTPUT/'global-cap',entropy=lambda n:1,total_draws=1)
        owner.submit(b'one',self.cases[0],[[1]])
        owner.submit(b'two',self.cases[0],[[1]])
        self.assertEqual(owner.draws,1)
        self.assertEqual(owner.records[b'two']['draws'],0)
        self.assertIn('owner entropy cap',owner.records[b'two']['failure'])
        interrupted = Owner(OUTPUT/'interrupted',entropy=lambda n:(_ for _ in ()).throw(KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            interrupted.submit(b'interrupted',self.cases[0],[[1]])
        self.assertIsNone(interrupted.submit(b'interrupted',self.cases[0],[[1]]).proof)
        self.assertEqual(interrupted.draws,1)
        self.assertIn('KeyboardInterrupt',interrupted.records[b'interrupted']['failure'])

    def test_field_rejection_exhaustion_is_retained_without_restart(self):
        from .requests import Owner
        calls = []
        def rejected(width):
            calls.append(width)
            return (1 << width)-1
        owner = Owner(OUTPUT/'field-exhaustion',entropy=rejected)
        first = owner.submit(b'exhausted',self.cases[0],[[1]])
        self.assertIsNone(first.proof)
        self.assertEqual(len(calls),128)
        self.assertEqual(owner.draws,128)
        self.assertIn('bounded field sampler exhausted',owner.records[b'exhausted']['failure'])
        self.assertIs(owner.submit(b'exhausted',self.cases[0],[[1]]),first)
        self.assertEqual(len(calls),128)
        owner.retain_private_observation()

    def test_late_metadata_failure_never_publishes_success(self):
        from .requests import Owner
        # Fault injection only: no transcript/verifier is run and this returned
        # byte fixture is never accepted as a proof or counted as one.
        def retained(selected, instances, coins, **kwargs):
            proof = b'unverified-publication-control'
            (selected.directory/'proof.bin').write_bytes(proof)
            return {'proof':proof},None,None
        for label,error in (('late-error',OSError('metadata unavailable')),
                            ('late-interrupt',KeyboardInterrupt('metadata interrupted'))):
            owner = Owner(OUTPUT/label,entropy=lambda n:(_ for _ in ()).throw(RuntimeError('unexpected')))
            with patch(__package__+'.requests.simulate',side_effect=retained), patch(__package__+'.requests.hashlib.sha256',side_effect=error):
                if isinstance(error,Exception):
                    self.assertIsNone(owner.submit(b'late',self.cases[0],[[1]]).proof)
                else:
                    with self.assertRaises(KeyboardInterrupt):
                        owner.submit(b'late',self.cases[0],[[1]])
            first = owner.records[b'late']['outcome']
            self.assertIsNone(first.proof)
            self.assertNotIn('proof_sha256',owner.records[b'late'])
            self.assertIn(type(error).__name__,owner.records[b'late']['failure'])
            self.assertIs(owner.submit(b'late',self.cases[0],[[1]]),first)
            self.assertEqual(owner.draws,0)
            owner.retain_private_observation()

    def test_outcome_is_immutable_and_does_not_expose_private_observation(self):
        from .requests import Outcome
        self.assertEqual([field.name for field in fields(Outcome)],['proof'])
        result = self.outcomes[0][0]
        with self.assertRaises(FrozenInstanceError):
            result.proof = b'changed'
        with self.assertRaises(FileExistsError):
            self.owners[0].retain_private_observation()

    def test_owner_budgets_and_existing_storage_refuse_without_entropy(self):
        from .requests import Owner
        for index,args in enumerate(({'max_requests':0},{'max_requests':True},
                                     {'per_request_draws':1 << 21},{'total_draws':0})):
            path = OUTPUT/f'bad-budget-{index}'
            with self.assertRaises(ValueError):
                Owner(path,entropy=lambda n:(_ for _ in ()).throw(RuntimeError('unexpected')),**args)
            self.assertFalse(path.exists())
        with self.assertRaises(FileExistsError):
            Owner(OUTPUT/'owner-0')

    def test_reentrant_request_is_refused_without_hidden_second_attempt(self):
        from .requests import Owner
        owner = None
        def reenter(width):
            return owner.submit(b'nested',self.cases[0],[[1]])
        owner = Owner(OUTPUT/'reentrant',entropy=reenter)
        self.assertIsNone(owner.submit(b'outer',self.cases[0],[[1]]).proof)
        self.assertEqual(set(owner.records),{b'outer'})
        self.assertEqual(owner.draws,1)
        self.assertIn('atomic owner request',owner.records[b'outer']['failure'])

    def test_storage_failure_retains_exact_failed_outcome_before_entropy(self):
        from .requests import Owner
        owner = Owner(OUTPUT/'storage-failure',entropy=lambda n:(_ for _ in ()).throw(RuntimeError('unexpected')))
        (owner.root/'0000').mkdir()
        result = owner.submit(b'blocked',self.cases[0],[[1]])
        self.assertIsNone(result.proof)
        self.assertEqual(owner.draws,0)
        self.assertIs(owner.submit(b'blocked',self.cases[0],[[1]]),result)
        self.assertIn('FileExistsError',owner.records[b'blocked']['failure'])
