"""Small producer controls; explicitly no large parameter or proof generation."""
from dataclasses import replace
import json
from pathlib import Path
import random
import sys
import subprocess
import os
import stat
import unittest
from unittest.mock import patch
from .bounded import Limits, Owner, scalar_ifft, new_output, artifact_inventory
from .custody import HERE, ROOT, checked_sources, require, sha

from . import raw_setup as RAW, parameters as PARAMS

OUTPUT = None


def owner(seed=2026100951,limits=Limits(),sampler=None,memory=None):
    return Owner(RAW,PARAMS,random.Random(seed),limits,sampler=sampler,memory=memory)


class ProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require(OUTPUT is not None, 'explicit fresh small output')
        cls.owner = owner(limits=Limits(queries=4096))
        cls.results = {}
        for tag in (0,1):
            cls.owner.query(RAW.input0(tag,b'\0'+bytes(4)))
            for k in (0,2,6):
                result = cls.owner.derive(tag,k)
                cls.results[tag,k] = result
                (OUTPUT/f'{tag}-k{k}.bin').write_bytes(result.raw)
        cls.owner.persist(OUTPUT)

    def test_small_domains_match_unchanged_quadratic_family_both_curves(self):
        before = (dict(self.owner.oracle.table),dict(self.owner.oracle.logs),
                  len(self.owner.sampler.records))
        reference = PARAMS.ParameterFamily(RAW,self.owner.oracle,self.owner.sampler)
        for tag in (0,1):
            for k in (0,2,6):
                self.assertEqual(self.results[tag,k],reference.derive(tag,k))
        self.assertEqual((self.owner.oracle.table,self.owner.oracle.logs,
                          len(self.owner.sampler.records)),before)

    def test_shared_context_replay_and_prefixes(self):
        before = (dict(self.owner.oracle.table),dict(self.owner.oracle.logs),
                  len(self.owner.sampler.records))
        for tag in (0,1):
            for k in (0,2):
                small,large = self.results[tag,k],self.results[tag,6]
                self.assertEqual(small.logs['g'],large.logs['g'][:1 << k])
                self.assertEqual((small.logs['w'],small.logs['u']),
                                 (large.logs['w'],large.logs['u']))
            for message in (b'\0'+bytes(4),b'\1',b'\2'):
                self.owner.point(tag,message)
        self.assertEqual((self.owner.oracle.table,self.owner.oracle.logs,
                          len(self.owner.sampler.records)),before)
        self.assertEqual(len(self.owner.oracle.logs),132)

    def test_ifft_direct_formula_and_canonical_refusals(self):
        for model in self.owner.sampler.models:
            curve,m = model.curve,model.curve.scalar
            for k in (0,2,6):
                n = 1 << k
                omega = 1 if k == 0 else curve.omega(k)
                values = tuple((j*j+11) % m for j in range(n))
                expected = tuple(sum(values[i]*pow(omega,(-i*j) % n,m) for i in range(n))*
                                 pow(n,-1,m) % m for j in range(n))
                self.assertEqual(scalar_ifft(values,curve,k),expected)
            for values,k in (([0],17),([0],True),([m]*4,2),([0]*4,3)):
                with self.assertRaises(ValueError):
                    scalar_ifft(values,curve,k)

    def test_large_default_and_logical_memory_refusal_before_contexts(self):
        self.assertEqual(Limits().validate().max_k,6)
        for limits in (replace(Limits(),max_k=16),replace(Limits(),memory_bytes=1),
                       replace(Limits(),queries=True),replace(Limits(),contexts=131077),
                       replace(Limits(),max_k=17),replace(Limits(),output_bytes=33 << 20)):
            with self.assertRaises(ValueError):
                limits.validate()
        full = Limits(max_k=16,contexts=131076,queries=393228,entries=393228,
                      requests=2,memory_bytes=1024 << 20,output_bytes=9 << 20,allow_large=True)
        self.assertLess(full.validate().reservation(),full.memory_bytes)

    def test_context_query_entry_and_output_caps_are_terminal(self):
        for limits,error in ((replace(Limits(),contexts=0),'setup budget'),
                             (replace(Limits(),queries=0),'query budget'),
                             (replace(Limits(),entries=0),'entry budget'),
                             (replace(Limits(),output_bytes=1),'output budget')):
            subject = owner(limits=limits)
            with self.assertRaisesRegex(Exception,error):
                subject.derive(0,0)
            before = (dict(subject.oracle.table),dict(subject.oracle.logs),len(subject.sampler.records))
            with self.assertRaises(RAW.Refused):
                subject.derive(0,0)
            self.assertEqual((subject.oracle.table,subject.oracle.logs,len(subject.sampler.records)),before)
            self.assertEqual(before,({},{},0))

    def test_sampler_failure_retained_and_no_family_resampling(self):
        coins = random.Random(2026100952)
        sampler = RAW.FreshTargetSampler(RAW,coins,pair_attempts=0)
        subject = Owner(RAW,PARAMS,coins,sampler=sampler)
        with self.assertRaisesRegex(RAW.Refused,'pair attempts'):
            subject.derive(0,0)
        self.assertEqual(sampler.records[0]['status'],'refused')
        self.assertEqual(subject.oracle.table,{})
        with self.assertRaises(RAW.Refused):
            subject.query(b'new query')
        self.assertEqual(len(sampler.records),1)
        directory = OUTPUT/'sampler-failure';directory.mkdir()
        record = subject.persist(directory)
        self.assertIsNotNone(record['owner_stopped'])
        self.assertEqual(record['family_resamples'],0)

    def test_native_g_identity_collects_prefix_then_stops_without_w_u(self):
        for tag in (0,1):
            coins = random.Random(2026100953+tag)
            original = RAW.FreshTargetSampler(RAW,coins)
            model = original.models[tag]
            words = RAW.SetupWords(0,RAW.lift(1,model.p,coins,256),
                                   RAW.lift(model.p-1,model.p,coins,256))
            class ConstantSampler:
                models = original.models
                def __init__(self): self.records = []
                def __call__(self,tag):
                    self.records.append({'curve':tag,'status':'identity-fixture'})
                    return words
            sampler = ConstantSampler()
            subject = Owner(RAW,PARAMS,coins,sampler=sampler)
            with self.assertRaisesRegex(RAW.Refused,'identity at index 0'):
                subject.derive(tag,2)
            self.assertEqual(set(subject.oracle.logs),
                             {(tag,b'\0'+i.to_bytes(4,'little')) for i in range(4)})
            self.assertEqual(len(subject.oracle.table),12)
            with self.assertRaises(RAW.Refused):
                subject.derive(tag,2)
            self.assertEqual(len(sampler.records),4)

    def test_lagrange_identity_checked_after_w_u_and_request_cap(self):
        # Deliberate point-source fault injection for native control-flow only.
        # This fixture does not claim a raw-oracle distribution or valid family.
        subject = owner(limits=replace(Limits(),requests=1))
        model = subject.sampler.models[0]
        base = model.isogeny(model.forward(1))
        calls = []
        def constant(tag,message):
            calls.append(message)
            return base,1
        with patch.object(subject,'point',side_effect=constant):
            with self.assertRaisesRegex(RAW.Refused,'identity at index 5'):
                subject.derive(0,2)
        self.assertEqual(calls,[b'\0'+i.to_bytes(4,'little') for i in range(4)]+[b'\1',b'\2'])
        good = owner(limits=replace(Limits(),requests=1))
        with patch.object(good,'point',return_value=(base,1)):
            good.derive(0,0)
            with self.assertRaisesRegex(ValueError,'request budget'):
                good.derive(0,0)
        self.assertIsNotNone(good.stopped)

    def test_memory_checkpoint_failure_and_streamed_state_retained(self):
        subject = owner()
        class Exhausted:
            def checkpoint(self): raise ValueError('traced allocation budget exceeded')
        subject.memory = Exhausted()
        with self.assertRaisesRegex(ValueError,'allocation budget'):
            subject.query(b'unrelated')
        before = dict(subject.oracle.table)
        with self.assertRaises(RAW.Refused):
            subject.query(b'another')
        self.assertEqual(subject.oracle.table,before)
        directory = OUTPUT/'memory-failure';directory.mkdir()
        subject.persist(directory)
        rows = [json.loads(line) for line in (directory/'raw-table-private.jsonl').read_text().splitlines()]
        self.assertEqual({bytes.fromhex(row['input']):bytes.fromhex(row['answer']) for row in rows},before)

    def test_owner_only_fresh_output_and_streaming_inventory(self):
        directory = new_output(OUTPUT/'fresh-directory')
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        (directory/'one').write_bytes(b'abc')
        expected = [{'name':'one','bytes':3,'sha256':sha(b'abc')}]
        self.assertEqual(artifact_inventory(directory,1,3),expected)
        for files,size in ((0,3),(1,2)):
            with self.assertRaisesRegex(ValueError,'budget'):
                artifact_inventory(directory,files,size)
        with self.assertRaises(FileExistsError):
            new_output(directory)
        (directory/'link').symlink_to(directory/'one')
        with self.assertRaisesRegex(ValueError,'regular'):
            artifact_inventory(directory,2,6)

    def test_cli_prelaunch_flags_source_and_optimized_refuse(self):
        # Every child stops before subject import/model creation or output mkdir.
        for index,args in enumerate((['--k','16'],['--contexts','0'],['--seed','-1'])):
            out = OUTPUT/('cli-refusal-'+str(index))
            command = [sys.executable,'-B','-S','-m','formal.kagemusha_setup.produce_parameters',
                       '--output',str(out),*args]
            result = subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(out.exists())
            (OUTPUT/('cli-refusal-'+str(index)+'.json')).write_text(json.dumps(
                {'command':command,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr}))
        out = OUTPUT/'optimized-refusal'
        command = [sys.executable,'-O','-B','-S','-m','formal.kagemusha_setup.produce_parameters',
                   '--output',str(out)]
        result = subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('unoptimized producer only',result.stderr)
        self.assertFalse(out.exists())
        # A copied minimal repository has the exact package bytes and manifest,
        # then deliberately lacks one pinned source. It must fail source custody
        # before imports of curve/parameter subjects or creating its output.
        from . import custody
        copied = new_output(OUTPUT/'missing-source-repository')
        package = copied/'formal/kagemusha_setup'
        package.mkdir(parents=True,mode=0o700)
        for name in (*custody.FILES,'source_manifest.json'):
            (package/name).write_bytes((HERE/name).read_bytes())
        (package/'README.md').unlink()
        out = OUTPUT/'source-refusal'
        env = {key:value for key,value in os.environ.items()
               if key not in ('PYTHONPATH','PYTHONHOME')}
        command = [sys.executable,'-B','-S','-m','formal.kagemusha_setup.produce_parameters',
                   '--output',str(out)]
        result = subprocess.run(command,cwd=copied,env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('FileNotFoundError',result.stderr)
        self.assertIn('README.md',result.stderr)
        self.assertFalse(out.exists())
        (OUTPUT/'cli-missing-source.json').write_text(json.dumps(
            {'command':command,'cwd':str(copied),'exit':result.returncode,
             'stdout':result.stdout,'stderr':result.stderr}))

    def test_final_allocation_refusal_after_retention_keeps_observation(self):
        from .produce_parameters import finalize
        directory = new_output(OUTPUT/'final-memory-failure')
        class Retain:
            def persist(self,path):
                for name in ('raw-table-private.jsonl','context-logs-private.jsonl',
                             'sampler-attempts-private.jsonl','owner-state.json'):
                    (path/name).write_bytes(b'kept')
                return {'retained':True}
        class Exhausted:
            def checkpoint(self): raise ValueError('traced allocation budget exceeded')
            def observe(self): return {'peak_bytes':33 << 20,'limit_bytes':32 << 20}
        before = checked_sources()
        (directory/'started.json').write_bytes(b'kept')
        record = {'success':True,'parameter_outputs':[]}
        with self.assertRaisesRegex(ValueError,'allocation budget'):
            finalize(directory,Limits(),Retain(),Exhausted(),record,before)
        self.assertFalse(record['success'])
        self.assertEqual(record['traced_allocations']['peak_bytes'],33 << 20)
        self.assertEqual(record['artifacts'][0]['sha256'],sha(b'kept'))

    def test_final_inventory_joins_generated_wire_and_exact_namespace(self):
        from .produce_parameters import finalize
        before = checked_sources()
        for kind in ('valid','hash','length','missing','extra'):
            directory = new_output(OUTPUT/('inventory-join-'+kind))
            names = ('started.json','raw-table-private.jsonl','context-logs-private.jsonl',
                     'sampler-attempts-private.jsonl','owner-state.json',
                     '0-k0-parameters.bin','0-k0-logs-private.jsonl','0-k0-identity.json')
            for name in names:
                (directory/name).write_bytes(b'kept')
            record = {'success':True,'parameter_outputs':[{'curve':0,'k':0,'bytes':4,
                                                          'sha256':sha(b'kept')}]}
            if kind == 'hash':
                (directory/'0-k0-parameters.bin').write_bytes(b'FAIL')
            elif kind == 'length':
                (directory/'0-k0-parameters.bin').write_bytes(b'longer')
            elif kind == 'missing':
                (directory/'0-k0-identity.json').unlink()
            elif kind == 'extra':
                (directory/'extra').write_bytes(b'x')
            if kind == 'valid':
                finalize(directory,Limits(),None,None,record,before)
                self.assertTrue(record['success'])
                self.assertTrue(record['generated_parameter_wires_match_retained'])
            else:
                with self.assertRaisesRegex(ValueError,'wire differ|artifact namespace'):
                    finalize(directory,Limits(),None,None,record,before)
                self.assertFalse(record['success'])
                self.assertIn('retention_failure',record)

