"""Fourteen bounded controls for plumbing only; no A1 construction or proofs."""
import ast
import copy
from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from . import load_a1_case as subject


class Memory:
    def __init__(self,*_):self.checks=0;self.closed=False
    def checkpoint(self):self.checks+=1
    def observe(self):return {'test_sentinel':True,'checks':self.checks}
    def close(self):self.closed=True


class ConstructorControls(unittest.TestCase):
    def temporary(self):
        result=tempfile.TemporaryDirectory(prefix='a1-constructor-control-')
        self.addCleanup(result.cleanup);return Path(result.name).resolve()

    def owner(self,path):
        # This fixture bypasses only package custody for a pure ledger test.
        # It cannot yield an actual native profile or verifier acceptance.
        with patch.object(subject,'source_snapshot',return_value={'sentinel':'source'}):
            return subject.Constructor(path,originals=path.parent,allow_large=True,entropy=Mock(side_effect=AssertionError('entropy forbidden')))

    def sentinel(self,owner):
        owner.memory=Memory()
        return SimpleNamespace(descriptor=SimpleNamespace(raw=b'data-only-descriptor'),key=b'key',
                               public_original=b'original',raw_params=b'parameters')

    def test_large_and_shape_preflight_before_io_entropy_import(self):
        root=self.temporary()
        with patch.object(subject,'source_snapshot',side_effect=AssertionError('source forbidden')) as source:
            for flag in (False,None,1,'yes'):
                with self.assertRaisesRegex(ValueError,'explicit large'):
                    subject.Constructor(root/'x',originals=root,allow_large=flag,entropy=lambda _:0)
            with self.assertRaisesRegex(ValueError,'closed constructor inputs'):
                subject.Constructor(root/'x',originals=root,allow_large=True,entropy=0)
            with self.assertRaisesRegex(ValueError,'fresh output'):
                subject.Constructor(root,originals=root,allow_large=True,entropy=lambda _:0)
            with self.assertRaisesRegex(ValueError,'closed allocation ceiling'):
                subject.Constructor(root/'x',originals=root,allow_large=True,entropy=lambda _:0,
                                    limits=replace(subject.Limits(),memory_bytes=1))
            with patch.object(subject.sys,'dont_write_bytecode',False):
                with self.assertRaisesRegex(ValueError,'bytecode-free constructor'):
                    subject.Constructor(root/'no-bytecode',originals=root,allow_large=True,entropy=lambda _:0)
            file=root/'not-directory';file.write_bytes(b'DATA')
            for location in (root/'missing',file):
                with self.assertRaisesRegex(ValueError,'exact originals directory'):
                    subject.Constructor(root/'source-refusal',originals=location,allow_large=True,entropy=lambda _:0)
            link=root/'linked-originals';link.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'symbolic links'):
                subject.Constructor(root/'source-refusal',originals=link,allow_large=True,entropy=lambda _:0)
            source.assert_not_called()
            self.assertFalse((root/'source-refusal').exists())

    def test_closed_a1_identity_has_no_caller_profile(self):
        self.assertEqual(set(inspect.signature(subject.Constructor).parameters),
                         {'directory','originals','allow_large','entropy','limits'})
        self.assertEqual(subject.D,(39386,'e7e535287ff5b2f41ff3c4a92dac549981b1dea243ba191930cc24932a51c087'))
        self.assertEqual(subject.PK,(140511414,'04824c5fdb5d8f59ef66de7a822d170ece02134b50abe9b65b63ebe3b8fa3a34'))
        manifest=subject.source_snapshot()
        self.assertEqual(manifest['files']['load_a1_descriptor.norito'],subject.D[1])
        missing=copy.deepcopy(manifest)
        del missing['files']['load_a1_descriptor.norito']
        from .custody import validate_manifest
        with self.assertRaisesRegex(ValueError,'exact maintained inventory'):
            validate_manifest(missing)
        original_read=Path.read_bytes
        fixture=subject.HERE/'load_a1_descriptor.norito'
        def changed(path):
            raw=original_read(path)
            return raw+b'changed' if path==fixture else raw
        with patch.object(Path,'read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'changed source load_a1_descriptor.norito'):
                subject.source_snapshot()
        tree=ast.parse(textwrap.dedent(inspect.getsource(subject.Constructor._construct)))
        reads=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='read_original']
        self.assertEqual([ast.unparse(n.args[1]) for n in reads],['D','V','PK'])
        root=self.temporary()
        with self.assertRaises(TypeError):subject.Constructor(root/'x',originals=root,allow_large=True,
                                                             entropy=lambda _:0,chosen=object())

    def test_bound_extent_and_full_tail_required(self):
        root=self.temporary();raw=b'bounded-original';path=root/'small';path.write_bytes(raw)
        pin=(len(raw),subject.sha(raw));observation={}
        self.assertEqual(subject.read_original(path,pin,observation=observation),raw)
        self.assertEqual(observation['bytes_hashed'],len(raw));self.assertEqual(observation['bytes_read'],len(raw))
        self.assertEqual(observation['observed_sha256'],pin[1]);self.assertEqual(observation['extension_sentinel_bytes'],0)
        self.assertTrue(observation['passed']);self.assertTrue(observation['identities_unchanged'])
        self.assertIn('stat_identity_before',observation)
        for changed,why in ((raw[:-1],'extent/type'),(raw+b'x','extent/type'),(b'X'+raw[1:],'exact original digest')):
            path.write_bytes(changed)
            observed={}
            with self.assertRaisesRegex(ValueError,why):subject.read_original(path,pin,observation=observed)
            self.assertFalse(observed['passed']);self.assertEqual(observed['observed_namespace_bytes'],len(changed))
            self.assertIn('error',observed)
            if why=='exact original digest':self.assertEqual(observed['observed_sha256'],subject.sha(changed))
        with self.assertRaisesRegex(ValueError,'bounded original'):subject.read_original(path,(subject.PK[0]+1,'0'*64))

    def test_nofollow_and_namespace_replacement(self):
        root=self.temporary();raw=b'custody';path=root/'original';path.write_bytes(raw)
        link=root/'link';link.symlink_to(path)
        with self.assertRaisesRegex(ValueError,'symbolic'):subject.read_original(link,(len(raw),subject.sha(raw)))
        replaced=False
        def replace_inode():
            nonlocal replaced
            if not replaced:
                replaced=True;replacement=root/'replacement';replacement.write_bytes(raw);replacement.replace(path)
        with self.assertRaisesRegex(ValueError,'changed during read'):
            subject.read_original(path,(len(raw),subject.sha(raw)),replace_inode)
        self.assertTrue(replaced)
        changed=False
        def change_bytes():
            nonlocal changed
            if not changed:changed=True;path.write_bytes(b'X'+raw[1:])
        with self.assertRaisesRegex(ValueError,'changed during read'):
            subject.read_original(path,(len(raw),subject.sha(raw)),change_bytes)

    def test_canonical_header_key_and_scalar_binding(self):
        from .public_setup import PublicSetup
        class Descriptor:
            n=1;digest=b'd'*32;curve=SimpleNamespace(scalar=101)
            def __getitem__(self,name):return {'num_fixed_columns':1,'permutation':[0]}[name]
        d=Descriptor();key=b'key';tail=(5).to_bytes(32,'little')+(7).to_bytes(32,'little')
        raw=b'PIPAPK01'+d.digest+len(key).to_bytes(4,'little')+key+b'c'*32+tail
        got=PublicSetup.decode(raw,d,key,subject.sha(raw));self.assertEqual(got.fixed,((5,),));self.assertEqual(got.sigma,((7,),))
        for offset in (0,8,40,44):
            changed=bytearray(raw);changed[offset]^=1
            with self.assertRaises(ValueError):PublicSetup.decode(bytes(changed),d,key,subject.sha(changed))
        with self.assertRaises(ValueError):PublicSetup.decode(raw[:-1],d,key,subject.sha(raw[:-1]))
        changed=raw[:-32]+(101).to_bytes(32,'little')
        with self.assertRaisesRegex(ValueError,'canonical scalar'):PublicSetup.decode(changed,d,key,subject.sha(changed))

    def test_historical_copy_uses_official_kats(self):
        from . import rebind as shared
        root=self.temporary();seen=[]
        def before():
            seen.append(True)
            self.assertEqual(json.loads((root/'historical/kats_v1.json').read_text()),
                             json.loads((subject.ROOT/'fixtures/native_prover/kats_v1.json').read_text()))
        modules=shared._reference(root/'historical',subject.D[1],allow_large=True,resource_curve=1,before_import=before)
        self.assertEqual(seen,[True])
        raw=(subject.HERE/'load_a1_descriptor.norito').read_bytes()
        self.assertEqual((len(raw),subject.sha(raw)),subject.D)
        descriptor=modules['descriptor'].Descriptor.decode(raw,2)
        subject.check_profile(descriptor)
        for field,value in (('curve',0),('k',15),('instance_lengths',[68])):
            changed=copy.deepcopy(descriptor);changed.values[field]=value
            with self.assertRaisesRegex(ValueError,'closed historical A1'):subject.check_profile(changed)
        source=Path(modules['descriptor'].__file__).read_text()
        self.assertIn("v['curve'] == 1",source);self.assertIn(subject.D[1],source)
        self.assertNotIn("v['curve'] == 0 and hashlib",source)

    def test_private_authority_precedes_any_import(self):
        from . import rebind as shared
        root=self.temporary();wire=(6).to_bytes(4,'little')+bytes(64*64+64)
        def before():
            kats=json.loads((root/'private/kats_v1.json').read_text())
            self.assertEqual(kats['params_ipa'],{'ep':[],'eq':[{'k':6,'byte_len':len(wire),'sha256':subject.sha(wire)}]})
            receipt=json.loads((root/'private/copy-receipt.json').read_text())
            self.assertTrue(receipt['authority_before_import'])
            raise RuntimeError('stop before loader')
        with patch.object(shared.importlib.util,'spec_from_file_location',side_effect=AssertionError('early import')) as loader:
            with self.assertRaisesRegex(RuntimeError,'stop before loader'):
                shared._reference(root/'private',subject.D[1],(1,6,wire),allow_large=True,
                                  resource_curve=1,before_import=before)
            loader.assert_not_called()

    def test_single_owner_no_detached_parameters_admission(self):
        owner=self.owner(self.temporary()/'result');owner.output=Mock()
        from . import bounded
        actual=[];fake=SimpleNamespace(derive=Mock(side_effect=RuntimeError('stop at actual selected derive')))
        def create(*args,**kw):actual.append((args,kw));return fake
        b=SimpleNamespace(TracedMemory=Memory,Limits=bounded.Limits,Owner=create)
        public=SimpleNamespace(PublicSetup=SimpleNamespace(decode=Mock(return_value=object())))
        old={'descriptor':SimpleNamespace(Descriptor=SimpleNamespace(decode=lambda *_:object())),
             'verify':SimpleNamespace(key_points=lambda *_:None)}
        with patch.object(subject,'modules',return_value=(b,object(),object(),public,object())),\
             patch.object(subject,'read_original',return_value=b'DATA'),patch.object(subject,'check_profile'),\
             patch.object(owner,'_reference',return_value=old):
            with self.assertRaisesRegex(RuntimeError,'selected derive'):owner._construct()
        self.assertIs(owner.setup_owner,fake);fake.derive.assert_called_once_with(1,16)
        self.assertIs(actual[0][1]['memory'],owner.memory)
        self.assertEqual(actual[0][0][3].reservation(),subject.SETUP_RESERVATION)
        self.assertEqual(owner.entropy.calls,0)
        from . import rebind as shared
        seen=[];ticks=[]
        curve=SimpleNamespace(multiply=lambda base,value:seen.append((base,value)) or value,
                              encode=lambda value:value.to_bytes(32,'little'))
        encoded=shared._parameter_bytes(curve,'sentinel-base',1,(1,2),(3,4),5,6,lambda:ticks.append(True))
        self.assertEqual(encoded,(1).to_bytes(4,'little')+b''.join(i.to_bytes(32,'little') for i in range(1,7)))
        self.assertEqual(seen,[('sentinel-base',i) for i in range(1,7)]);self.assertEqual(len(ticks),6)
        node=next(n for n in ast.walk(ast.parse(inspect.getsource(shared._finish_case)))
                  if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='scalar_ifft')
        self.assertEqual(ast.unparse(node.args[-1]),'checkpoint')

    def test_terminal_setup_refusal_no_retry(self):
        for cause in ('canonical draw exhausted','native parameter identity','occupied XMD input','entry cap'):
            owner=self.owner(self.temporary()/'result')
            with patch.object(subject,'source_snapshot',return_value=owner.before),\
                 patch.object(owner,'_construct',side_effect=ValueError(cause)) as construct:
                first=owner.build();second=owner.build()
            self.assertIs(first,second);self.assertIsNone(first.case);self.assertIn(cause,first.error)
            construct.assert_called_once();self.assertEqual(owner.entropy.calls,0)
            self.assertTrue((owner.directory/'failure.json').is_file())

    def test_late_publication_failure_and_interrupt(self):
        owner=self.owner(self.temporary()/'result');case=self.sentinel(owner)
        original=subject.Outputs.save
        def fail_inventory(out,path,value,**kw):
            if Path(path).name=='inventory.json':raise OSError('injected retention')
            return original(out,path,value,**kw)
        with patch.object(subject,'source_snapshot',return_value=owner.before),\
             patch.object(owner,'_construct',return_value=case),patch.object(subject.Outputs,'save',fail_inventory):
            failed=owner.build();self.assertIs(owner.build(),failed)
        self.assertIsNone(failed.case);self.assertIn('injected retention',failed.error);self.assertTrue(owner.memory.closed)
        owner=self.owner(self.temporary()/'interrupted')
        with patch.object(subject,'source_snapshot',return_value=owner.before),\
             patch.object(owner,'_construct',side_effect=KeyboardInterrupt('interrupted')) as construct:
            with self.assertRaises(KeyboardInterrupt):owner.build()
            self.assertIsNone(owner.build().case);construct.assert_called_once()

    def test_success_replay_identity_without_new_entropy(self):
        owner=self.owner(self.temporary()/'result');case=self.sentinel(owner)
        retained=SimpleNamespace(query=Mock(return_value=b'same residual answer'),stopped=None,requests=[],
            oracle=SimpleNamespace(table={},logs={},queries=0,stopped=None),sampler=SimpleNamespace(records=[]))
        owner.setup_owner=retained
        with patch.object(subject,'source_snapshot',return_value=owner.before),\
             patch.object(owner,'_construct',return_value=case) as construct:
            first=owner.build();second=owner.build()
        self.assertIs(first,second);self.assertIs(first.case,case);construct.assert_called_once()
        self.assertFalse(owner.memory.closed);self.assertEqual(owner.entropy.calls,0)
        self.assertIsNone(first.error);self.assertFalse((owner.directory/'failure.json').exists())
        self.assertIs(owner.setup_owner,retained)
        self.assertEqual(owner.query(b'future query'),b'same residual answer')
        retained.query.assert_called_once_with(b'future query')
        owner.output.verify();owner.close();self.assertTrue(owner.memory.closed)
        with self.assertRaisesRegex(ValueError,'completed live'):owner.query(b'query')
        retained.query.assert_called_once_with(b'future query')

    def test_reference_copy_delta_and_kat_grammar(self):
        from . import rebind as shared
        root=self.temporary();mods=shared._reference(root/'ref',subject.D[1],allow_large=True,resource_curve=1)
        receipt=json.loads((root/'ref/copy-receipt.json').read_text())
        for row in receipt['source_changes']:
            if row['name'] not in ('descriptor.py','parameters.py'):
                self.assertEqual(row['before_sha256'],row['after_sha256'])
        with self.assertRaises(FileExistsError):shared._reference(root/'ref',subject.D[1],allow_large=True,resource_curve=1)
        with self.assertRaisesRegex(ValueError,'canonical exact descriptor'):
            shared.reference(root/'bad',"bad' injection",allow_large=True)
        self.assertFalse((root/'bad').exists())
        with self.assertRaisesRegex(ValueError,'large reference authority'):
            shared.reference(root/'no-large',parameter_authority=(1,16,b''))
        self.assertFalse((root/'no-large').exists())
        self.assertIn('_decide',vars(mods['parameters']))

    def test_finite_counts_and_budget_refusals(self):
        source=Mock(side_effect=[3,9]);bits=subject.Bits(source)
        self.assertEqual([bits.getrandbits(2),bits.getrandbits(4)],[3,9])
        self.assertEqual([call.args for call in source.call_args_list],[(2,),(4,)])
        self.assertEqual(bits.calls,2)
        for width in (0,513,True,'8'):
            with self.assertRaisesRegex(ValueError,'bounded setup bit width'):bits.getrandbits(width)
        self.assertEqual(bits.calls,2);self.assertEqual(source.call_count,2)
        for value in (True,-1,256,None):
            invalid=subject.Bits(Mock(return_value=value))
            with self.assertRaisesRegex(ValueError,'canonical setup bits'):invalid.getrandbits(8)
            self.assertEqual(invalid.calls,1);invalid.source.assert_called_once_with(8)
        self.assertEqual(44+2154+32+67*65536*32,subject.PK[0])
        self.assertEqual(subject.SETUP_RESERVATION+subject.CASE_ALLOWANCE,2<<30)
        root=self.temporary();out=subject.Outputs(root/'bounded',replace(subject.Limits(),output_bytes=10,files=1))
        with self.assertRaisesRegex(ValueError,'before write'):
            with out.stream(out.root/'file',terminal=True) as emit:emit(b'1234567');emit(b'8901')
        self.assertEqual((out.root/'file').read_bytes(),b'1234567');self.assertEqual(out.used,7)
        with self.assertRaisesRegex(ValueError,'file budget'):
            with out.stream(out.root/'second',terminal=True):pass
        (out.root/'empty-foreign').mkdir()
        with self.assertRaisesRegex(ValueError,'unexpected output directory'):out.verify()

    def test_no_production_authority_bridge(self):
        from . import rebind as shared
        root=self.temporary();modules=shared.reference(root/'official')
        official=(subject.ROOT/'fixtures/native_prover/kats_v1.json').read_bytes()
        self.assertEqual(json.loads((root/'official/kats_v1.json').read_text()),json.loads(official))
        wire=(6).to_bytes(4,'little')+bytes(64*64+64)
        pin=next(row for row in json.loads(official)['params_ipa']['eq'] if row['k']==6)
        self.assertNotEqual(subject.sha(wire),pin['sha256'])
        with self.assertRaisesRegex(ValueError,'unpinned parameters'):
            modules['parameters'].Parameters.decode(wire,modules['curve'].Curve(1),6)
        self.assertEqual((subject.ROOT/'fixtures/native_prover/kats_v1.json').read_bytes(),official)


if __name__=='__main__':unittest.main(verbosity=2)
