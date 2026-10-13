"""Process-lifetime controls, including a real naturally exiting native child."""
from __future__ import annotations


import copy
import ctypes
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY/'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import private_settlement_process_observer as observer
import private_settlement_session_control as control


def linux_stat(*, pid=123, name=b'a) ) strange (worker', state=b'R', changes=None):
    fields=[state]+[b'0']*49
    for index,value in {1:100,2:123,11:17,12:29,19:900}.items():
        fields[index]=str(value).encode()
    for index,value in (changes or {}).items():
        fields[index]=value
    return str(pid).encode()+b' ('+name+b') '+b' '.join(fields)+b'\n'


def inventory(n):
    coordinates=[('coordinator',None,None)]+[('global_validator',None,v) for v in range(4)]
    coordinates += [('dataspace_validator',d,v) for d in range(n) for v in range(4)]
    return [{'role':role,'dataspace_ordinal':d,'validator_ordinal':v,'pid':1000+i,
             'executable_sha256':('b' if role=='coordinator' else 'a')*64,
             'revision':'c'*40,'health_observed':True}
            for i,(role,d,v) in enumerate(coordinates)]


def declarations(rows=None,n=3,**extra):
    args={'participants':n,'worker_pid':900,'adapter_pid':800,'process_group':900,
          'commit':'c'*40,'validator_sha256':'a'*64,'worker_sha256':'b'*64}
    args.update(extra)
    return observer.benchmark_process_declarations(inventory(n) if rows is None else rows,**args)


class ParserAndImageTests(unittest.TestCase):
    def test_linux_stat_handles_parentheses_and_exact_field_numbers(self):
        self.assertEqual(observer.parse_linux_stat(linux_stat(),123),
                         {'ppid':100,'pgid':123,'utime':17,'stime':29,'start_ticks':900})

    def test_linux_stat_rejects_missing_identity_dead_process_and_bad_counters(self):
        malformed=[b'',linux_stat(pid=124),linux_stat(state=b'Z'),linux_stat(state=b'X'),
                   linux_stat(changes={19:b'0'}),linux_stat(changes={11:b'-1'}),
                   linux_stat(changes={12:str(1<<64).encode()}),linux_stat(changes={1:b'0'}),
                   b'123 (worker) R 100',b'x'* (observer.MAX_KERNEL_RECORD_BYTES+1)]
        for raw in malformed:
            with self.subTest(length=len(raw)),self.assertRaises(observer.ProcessObservationError):
                observer.parse_linux_stat(raw,123)

    def test_linux_rss_uses_unique_smaps_rollup_kibibytes(self):
        self.assertEqual(observer.parse_linux_rollup(b'00000-fffff [rollup]\nRss:  1025 kB\nPss: 2 kB\n'),1049600)
        for raw in (b'',b'Pss: 2 kB',b'Rss: 0 kB',b'Rss: 10 B',b'Rss: -1 kB',
                    b'Rss: 1 kB\nRss: 2 kB',b'Rss: 999999999999999 kB'):
            with self.subTest(raw=raw),self.assertRaises(observer.ProcessObservationError):
                observer.parse_linux_rollup(raw)

    def test_descriptor_kernel_record_is_bounded_and_rejects_leaf_links(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);(root/'stat').write_bytes(b'kernel record')
            (root/'link').symlink_to('stat')
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(observer.kernel_record(fd,'stat'),b'kernel record')
                with self.assertRaises(OSError):
                    observer.kernel_record(fd,'link')
                with mock.patch.object(observer,'MAX_KERNEL_RECORD_BYTES',5):
                    with self.assertRaises(observer.ProcessObservationError):
                        observer.kernel_record(fd,'stat')
            finally:
                os.close(fd)

    def test_image_binds_exact_bytes_metadata_and_named_file(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'image';path.write_bytes(b'original executable')
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            with observer.ExecutableImage(path,digest) as image:
                image.validate()
                replacement=path.with_suffix('.new');replacement.write_bytes(path.read_bytes())
                replacement.replace(path)
                with self.assertRaises(observer.ProcessObservationError):
                    image.validate()
            image.close()
            with self.assertRaises(observer.ProcessObservationError):
                image.validate()

    def test_image_rejects_digest_substitution_zero_digest_empty_and_changed_file(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'image';path.write_bytes(b'original')
            for digest in ('0'*64,'a'*64,'SHA'):
                with self.assertRaises(observer.ProcessObservationError):
                    observer.ExecutableImage(path,digest)
            with observer.ExecutableImage(path,hashlib.sha256(path.read_bytes()).hexdigest()) as image:
                path.write_bytes(b'mutated!')
                with self.assertRaises(observer.ProcessObservationError):
                    image.validate()
            path.write_bytes(b'')
            with self.assertRaises(observer.ProcessObservationError):
                observer.ExecutableImage(path,hashlib.sha256(b'').hexdigest())

    def test_unsupported_platform_never_substitutes_ps_estimates(self):
        with mock.patch.object(sys,'platform','unsupported'):
            for constructor in (observer.native_reader,observer.DarwinProcessReader,observer.LinuxProcessReader):
                with self.assertRaises(observer.ProcessObservationError):
                    constructor()


class DarwinCpuTimebaseTests(unittest.TestCase):
    def test_integer_scaling_keeps_fraction_and_large_tick_precision(self):
        for numer, denom in ((1,1),(125,3),(1,3),(1_000_000_000,1)):
            for ticks in (0,1,2,3,7,1036634,2**53+1):
                expected=ticks*numer//denom
                if expected < 1 << 64:
                    self.assertEqual(observer.darwin_cpu_nanoseconds(ticks,numer,denom),expected)
        self.assertEqual(observer.darwin_cpu_nanoseconds(1036634,125,3),43_193_083)
        self.assertEqual(observer.darwin_cpu_nanoseconds(2**64,1,2),2**63)
        self.assertEqual(observer.darwin_cpu_nanoseconds(2**64-1,1,1),2**64-1)

    def test_invalid_native_values_and_scaled_overflow_are_rejected(self):
        cases=[(-1,1,1),(True,1,1),(1.0,1,1),(1<<65,1,1),
               (1,0,1),(1,1,0),(1,-1,1),(1,1,-1),(1,True,1),(1,1,True),
               (1,1<<32,1),(1,1,1<<32),(1,1_000_000_001,1),
               (1<<64,1,1),((1<<64)-1,125,3)]
        for args in cases:
            with self.subTest(args=args),self.assertRaises(observer.ProcessObservationError):
                observer.darwin_cpu_nanoseconds(*args)

    def test_kernel_call_status_and_timebase_are_mandatory(self):
        for status,numer,denom in ((0,125,3),(5,125,3),(0,0,3),(0,125,0)):
            def call(pointer):
                pointer._obj.numer=numer;pointer._obj.denom=denom
                return status
            library=SimpleNamespace(mach_timebase_info=mock.Mock(side_effect=call))
            with self.subTest(values=(status,numer,denom)), \
                    mock.patch.object(sys,'platform','darwin'), \
                    mock.patch.object(observer.ctypes,'CDLL',return_value=library):
                if status==0 and numer>0 and denom>0:
                    self.assertEqual(observer.darwin_cpu_timebase(),(125,3))
                    self.assertEqual(library.mach_timebase_info.argtypes,
                                     (ctypes.POINTER(observer._MachTimebaseInfo),))
                    self.assertIs(library.mach_timebase_info.restype,ctypes.c_int)
                else:
                    with self.assertRaises(observer.ProcessObservationError):
                        observer.darwin_cpu_timebase()
        with mock.patch.object(sys,'platform','linux'),self.assertRaises(observer.ProcessObservationError):
            observer.darwin_cpu_timebase()

    def test_sample_converts_sum_and_reports_conservative_integer_tick_unit(self):
        from nexus import resource_process
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'image';path.write_bytes(b'executable fixture')
            info=SimpleNamespace(pid=123,ppid=100,pgid=123,uid=os.geteuid(),ruid=os.getuid(),
                                 start_sec=1000,start_usec=7)
            def usage(_pid,_kind,pointer):
                pointer._obj.user_time=1;pointer._obj.system_time=2
                pointer._obj.start_abstime=99;pointer._obj.rss=4096
                return 0
            def read_path(_pid,buffer,_size):
                encoded=os.fsencode(path.resolve());buffer.value=encoded
                return len(encoded)
            reader=object.__new__(observer.DarwinProcessReader)
            reader.native=resource_process
            reader.reader=object.__new__(resource_process.DarwinProcessReader)
            reader.reader._identity=mock.Mock(return_value=info)
            reader.reader.lib=SimpleNamespace(proc_pid_rusage=usage,proc_pidpath=read_path)
            reader.cpu_numer=125;reader.cpu_denom=3
            with observer.ExecutableImage(path,hashlib.sha256(path.read_bytes()).hexdigest()) as image, \
                    mock.patch.object(resource_process,'_image_uuids',return_value={bytes(16)}), \
                    mock.patch.object(resource_process,'darwin_absolute_time',return_value=1):
                sample=reader.sample(123,image)
            self.assertEqual(sample['cpu_time_ns'],125)
            self.assertEqual(sample['cpu_counter_unit_ns'],42)
            self.assertEqual(sample['rss_bytes'],4096)
            self.assertEqual(sample['identity']['birth']['start_abstime'],99)
            self.assertEqual(sample['identity']['pid'],123)
            self.assertEqual(reader.reader._identity.call_count,2)


class InventoryAndScopeTests(unittest.TestCase):
    def test_inventory_has_every_validator_coordinator_and_proof_worker(self):
        for n in (2,3,4,8,16):
            rows=declarations(n=n)
            self.assertEqual(len(rows),4*(n+1)+2)
            self.assertEqual(rows[-1],{'label':'proof_worker','pid':900,'ppid':800,'pgid':900,'image':'worker'})
            self.assertTrue(all(row['ppid']==900 for row in rows[:-1]))

    def test_inventory_rejects_duplicates_missing_reordered_wrong_build_or_health(self):
        for kind in ('missing','duplicate','reordered','hash','revision','health','bool','owner_pid'):
            rows=inventory(3)
            if kind=='missing':rows.pop()
            if kind=='duplicate':rows[1]['pid']=rows[0]['pid']
            if kind=='reordered':rows[0],rows[1]=rows[1],rows[0]
            if kind=='hash':rows[-1]['executable_sha256']='d'*64
            if kind=='revision':rows[-1]['revision']='e'*40
            if kind=='health':rows[-1]['health_observed']=1
            if kind=='bool':rows[1]['validator_ordinal']=False
            if kind=='owner_pid':rows[0]['pid']=900
            with self.subTest(kind=kind),self.assertRaises(observer.ProcessObservationError):
                declarations(rows)

    def fixture(self):
        sample={'identity':{'pid':123,'ppid':100,'pgid':123,'uid':os.geteuid(),
                           'birth':{'kind':'fixture','counter':1},'executable_sha256':'a'*64},
                'cpu_time_ns':10,'cpu_counter_unit_ns':1,'rss_bytes':100}
        reader=mock.Mock();reader.sample.side_effect=lambda *args:copy.deepcopy(sample)
        scope=observer.ProcessScope([{'label':'owned','pid':123,'ppid':100,'pgid':123,'image':'worker'}],
                                    reader,{'worker':SimpleNamespace(sha256='a'*64)})
        return sample,scope

    def test_scope_monotonic_cpu_and_exact_all_process_rss(self):
        sample,scope=self.fixture()
        sample['cpu_time_ns']=25;sample['rss_bytes']=200
        result=scope.observe()
        self.assertEqual(result['cpu_time_ns']-scope.initial['cpu_time_ns'],15)
        self.assertEqual(result['rss_bytes'],200)
        self.assertGreaterEqual(result['finished_monotonic_ns'],result['started_monotonic_ns'])

    def test_scope_rejects_reuse_reparent_exec_wrong_pid_cpu_rollback_and_units(self):
        changes=[('identity','pid',124),('identity','ppid',200),('identity','pgid',200),
                 ('identity','birth',{'kind':'fixture','counter':2}),
                 ('identity','executable_sha256','b'*64),('identity','uid',os.geteuid()+1),
                 (None,'cpu_time_ns',9),(None,'cpu_time_ns',True),(None,'cpu_time_ns',1<<64),
                 (None,'cpu_counter_unit_ns',2),(None,'rss_bytes',True),(None,'rss_bytes',0)]
        for section,key,value in changes:
            sample,scope=self.fixture()
            (sample if section is None else sample[section])[key]=value
            with self.subTest(key=key),self.assertRaises(observer.ProcessObservationError):
                scope.observe()

    def test_scope_rejects_duplicate_rows_and_unbound_image(self):
        row={'label':'owned','pid':123,'ppid':100,'pgid':123,'image':'worker'}
        for rows in ([],[row,row],[{**row,'pid':True}],[row]):
            with self.assertRaises(observer.ProcessObservationError):
                observer.ProcessScope(rows,mock.Mock(),{})

    def test_scope_never_recovers_after_identity_error(self):
        sample,scope=self.fixture()
        sample['identity']['ppid']=101
        with self.assertRaises(observer.ProcessObservationError):scope.observe()
        sample['identity']['ppid']=100
        with self.assertRaises(observer.ProcessObservationError):scope.observe()

    def test_returned_snapshot_cannot_rebind_the_pinned_identity(self):
        sample,scope=self.fixture()
        scope.initial['processes'][0]['identity']['birth']['counter']=2
        sample['identity']['birth']['counter']=2
        with self.assertRaises(observer.ProcessObservationError):scope.observe()


class ResourceWindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name).resolve()
        self.records=control.RecordDirectory(self.root)
        self.index=0

    def tearDown(self):
        self.records.close();self.temporary.cleanup()

    def window(self,scope,interval_ms):
        prefix=f'window-{self.index}'
        self.index+=1
        (self.root/prefix).mkdir(mode=0o700)
        return observer.ProcessResourceWindow(scope,records=self.records,prefix=prefix,
            outer_timeout_ms=300000,deadline_monotonic_ns=time.monotonic_ns()+299_000_000_000,
            interval_ms=interval_ms)

    def observations(self,result):
        chunks=[];reference=result['journal']['chunk_tail']
        while reference is not None:
            chunk=control.decode(self.records.read(reference))
            chunks.append(chunk['observations']);reference=chunk['previous_chunk']
        return [row for chunk in reversed(chunks) for row in chunk]

    def test_window_includes_baseline_periodic_peak_and_final_cumulative_cpu(self):
        observed=threading.Event()
        class Scope:
            def __init__(self):self.count=0
            def observe(self):
                self.count+=1
                index=self.count
                if index==2:observed.set()
                return {'started_monotonic_ns':10*index,'finished_monotonic_ns':10*index+1,
                        'cpu_time_ns':100*index,'rss_bytes':900 if index==2 else 200,'processes':[]}
        scope=Scope();window=self.window(scope,interval_ms=10)
        self.assertTrue(observed.wait(2))
        result=window.finish()
        self.assertEqual(result['outcome']['kind'],'succeeded')
        self.assertTrue(result['sampler_stopped_observed'])
        self.assertEqual(result['outcome']['sampled_peak_rss_bytes'],900)
        self.assertEqual(result['outcome']['cpu_time_ns'],100*(len(self.observations(result))-1))
        self.assertEqual(self.observations(result)[0],control.decode(self.records.read(window.baseline_reference)))
        with self.assertRaises(observer.ProcessObservationError):window.finish()

    def test_periodic_or_final_failure_cannot_be_hidden_by_a_later_good_sample(self):
        for failure_index in (2,3):
            observed=threading.Event()
            class Scope:
                def __init__(self):self.count=0
                def observe(self):
                    self.count+=1
                    if self.count>=2:observed.set()
                    if self.count==failure_index:raise observer.ProcessObservationError('fixture failure')
                    return {'started_monotonic_ns':self.count*10,'finished_monotonic_ns':self.count*10+1,
                            'cpu_time_ns':self.count,'rss_bytes':1,'processes':[]}
            scope=Scope();window=self.window(scope,interval_ms=10)
            self.assertTrue(observed.wait(2))
            result=window.finish()
            self.assertEqual(result['outcome'],{'kind':'failed','reason':'process_observation_failed'})
            self.assertEqual(scope.count,failure_index)
            self.assertNotIn('cpu_time_ns',result['outcome'])

    def test_short_attempt_still_has_two_actual_boundary_observations(self):
        scope=mock.Mock()
        scope.observe.side_effect=[{'started_monotonic_ns':1,'finished_monotonic_ns':2,
                                    'cpu_time_ns':3,'rss_bytes':4,'processes':[]},
                                   {'started_monotonic_ns':5,'finished_monotonic_ns':6,
                                    'cpu_time_ns':7,'rss_bytes':8,'processes':[]}]
        result=self.window(scope,interval_ms=1000).finish()
        self.assertEqual(len(self.observations(result)),2)
        self.assertEqual(result['outcome']['cpu_time_ns'],4)
        self.assertEqual(result['outcome']['sampled_peak_rss_bytes'],8)
        self.assertEqual(result['outcome']['maximum_observation_gap_ns'],3)

    def test_long_n16_evidence_is_streamed_without_one_oversize_record(self):
        (self.root/'long').mkdir(mode=0o700)
        policy=observer.resource_window_policy(300000,100)
        journal=observer.ResourceObservationJournal(self.records,'long',policy)
        # Seventy realistic-sized fixture rows exceed one 16MiB transport file
        # over 1,024 observations, while each immutable chunk remains bounded.
        process={'identity':{'executable_path':'/fixture/'+'x'*256,'sha256':'a'*64},'rss_bytes':1}
        total=0
        for index in range(1024):
            row={'started_monotonic_ns':index*10,'finished_monotonic_ns':index*10+1,
                 'processes':[process]*70,'cpu_time_ns':index,'rss_bytes':70}
            total+=len(control.canonical(row));journal.append(row)
            self.assertLess(len(journal.pending),16)
        journal.flush();manifest=journal.manifest()
        self.assertGreater(total,control.MAX_FRAME_BYTES)
        self.assertEqual(manifest['observed_count'],1024)
        self.assertEqual(manifest['recorded_count'],1024)
        self.assertEqual(manifest['chunk_count'],64)
        self.assertLess(len(control.canonical(manifest)),4096)
        reference=manifest['chunk_tail'];sequence=63;count=0
        while reference is not None:
            self.assertLess(reference['bytes'],4*1024*1024+4096)
            chunk=control.decode(self.records.read(reference))
            self.assertEqual(chunk['sequence'],sequence)
            self.assertEqual(chunk['first_observation_index'],sequence*16)
            count+=len(chunk['observations']);sequence-=1;reference=chunk['previous_chunk']
        self.assertEqual((count,sequence),(1024,-1))

    def test_stream_rejects_budget_excess_and_never_omits_the_failure(self):
        (self.root/'bounded').mkdir(mode=0o700)
        policy=observer.resource_window_policy(1,1000)
        journal=observer.ResourceObservationJournal(self.records,'bounded',policy)
        row={'started_monotonic_ns':1,'finished_monotonic_ns':2,'processes':[],
             'cpu_time_ns':1,'rss_bytes':1}
        for index in range(policy['maximum_observations']):
            journal.append({**row,'started_monotonic_ns':index*10,'finished_monotonic_ns':index*10+1})
        with self.assertRaises(observer.ProcessObservationError):
            journal.append({**row,'started_monotonic_ns':100,'finished_monotonic_ns':101})
        self.assertTrue(journal.failed)
        self.assertEqual(journal.failure_reason,'observation_count_budget_exceeded')
        self.assertEqual(journal.manifest()['observed_count'],policy['maximum_observations'])
        with self.assertRaises(observer.ProcessObservationError):journal.flush()

    def test_chunk_publication_failure_is_terminal_and_retains_existing_files(self):
        (self.root/'failed').mkdir(mode=0o700)
        journal=observer.ResourceObservationJournal(self.records,'failed',observer.resource_window_policy(1000,100))
        journal.append({'started_monotonic_ns':1,'finished_monotonic_ns':2,'processes':[],
                        'cpu_time_ns':1,'rss_bytes':1})
        with mock.patch.object(self.records,'publish',side_effect=OSError('fixture publication failure')):
            with self.assertRaises(OSError):journal.flush()
        self.assertTrue(journal.failed)
        self.assertEqual(journal.failure_reason,'observation_publication_failed')
        self.assertEqual(journal.manifest()['unpublished_count'],1)
        self.assertEqual(journal.manifest()['recorded_count'],0)
        with self.assertRaises(observer.ProcessObservationError):journal.flush()

    def replay_fixture(self):
        (self.root/'replay').mkdir(mode=0o700)
        expected=[{'label':f'process-{i}','identity':{'pid':100+i,'birth':{'kind':'fixture','counter':1}},
                   'cpu_counter_unit_ns':1} for i in range(2)]
        observations=[]
        for index in range(18):
            rows=[{**item,'cpu_time_ns':index*10+i+1,'rss_bytes':100+index+i}
                  for i,item in enumerate(expected)]
            observations.append({'started_monotonic_ns':index*10,'finished_monotonic_ns':index*10+1,
                'processes':rows,'cpu_time_ns':sum(row['cpu_time_ns'] for row in rows),
                'rss_bytes':sum(row['rss_bytes'] for row in rows)})
        baseline=self.records.publish('replay/baseline.json',control.canonical(observations[0]))
        journal=observer.ResourceObservationJournal(self.records,'replay',observer.resource_window_policy(300000,100))
        for observation in observations:journal.append(observation)
        journal.flush()
        first,last=observations[0],observations[-1]
        metrics={'cpu_time_ns':last['cpu_time_ns']-first['cpu_time_ns'],
                 'sampled_peak_rss_bytes':last['rss_bytes'],'maximum_observation_gap_ns':9,
                 'baseline_started_monotonic_ns':0,'baseline_finished_monotonic_ns':1,
                 'final_started_monotonic_ns':170,'final_finished_monotonic_ns':171}
        window={'version':1,'kind':'benchmark_process_resource_window','baseline':baseline,
                'sampler_stopped_observed':True,'journal':journal.manifest(),
                'outcome':{'kind':'succeeded',**metrics}}
        return window,expected,metrics

    def test_stream_reducer_recomputes_all_processes_and_chunks(self):
        window,expected,metrics=self.replay_fixture()
        actual=observer.validate_resource_window(window,records=self.records,
                outer_timeout_ms=300000,expected_processes=expected)
        self.assertEqual(actual,metrics)

    def test_baseline_crossing_deadline_never_starts_sampler_or_releases_work(self):
        (self.root/'late').mkdir(mode=0o700)
        scope=mock.Mock()
        scope.observe.return_value={'started_monotonic_ns':10,'finished_monotonic_ns':21,
                                    'processes':[],'cpu_time_ns':1,'rss_bytes':1}
        with mock.patch.object(observer.time,'monotonic_ns',side_effect=[10,10,21]),\
                mock.patch.object(observer.threading,'Thread') as thread:
            with self.assertRaises(observer.ProcessObservationError):
                observer.ProcessResourceWindow(scope,records=self.records,prefix='late',
                    outer_timeout_ms=1,deadline_monotonic_ns=20,interval_ms=100)
            thread.assert_not_called()
        self.assertTrue((self.root/'late/baseline.json').is_file())

    def test_stream_reducer_rejects_manifest_metrics_count_budget_and_identity_substitution(self):
        window,expected,_=self.replay_fixture()
        changes=[('outcome','cpu_time_ns',1),('outcome','sampled_peak_rss_bytes',1),
                 ('outcome','maximum_observation_gap_ns',0),('journal','observed_count',17),
                 ('journal','recorded_count',17),('journal','observed_bytes',1),
                 ('journal','unpublished_count',1),('journal','chunk_count',1)]
        for section,key,value in changes:
            changed=copy.deepcopy(window);changed[section][key]=value
            with self.subTest(key=key),self.assertRaises(observer.ProcessObservationError):
                observer.validate_resource_window(changed,records=self.records,
                    outer_timeout_ms=300000,expected_processes=expected)
        for args in ({'outer_timeout_ms':299000,'expected_processes':expected},
                     {'outer_timeout_ms':300000,'expected_processes':list(reversed(expected))}):
            with self.assertRaises(observer.ProcessObservationError):
                observer.validate_resource_window(window,records=self.records,**args)

    def test_stream_reducer_rejects_hidden_per_process_cpu_regression_after_rebinding_chunk(self):
        window,expected,_=self.replay_fixture()
        reference=window['journal']['chunk_tail'];raw=self.records.read(reference)
        chunk=control.decode(raw)
        row=chunk['observations'][-1]
        # Keep aggregate CPU unchanged while moving one process backwards.
        row['processes'][0]['cpu_time_ns']-=20;row['processes'][1]['cpu_time_ns']+=20
        replacement=control.canonical(chunk)
        (self.root/reference['path']).write_bytes(replacement)
        reference.update(sha256=hashlib.sha256(replacement).hexdigest(),bytes=len(replacement))
        with self.assertRaises(observer.ProcessObservationError):
            observer.validate_resource_window(window,records=self.records,
                outer_timeout_ms=300000,expected_processes=expected)


class NativeChildTests(unittest.TestCase):
    def test_native_owned_child_image_birth_cpu_rss_and_natural_exit(self):
        # Framework Python launchers may exec a different Mach-O image. Pin a
        # direct native executable so this test does not authorize that change.
        path=Path('/bin/cat').resolve(strict=True)
        with path.open('rb') as stream:
            digest=hashlib.file_digest(stream,'sha256').hexdigest()
        # The fixture owns only this child. EOF on its input lets it exit;
        # neither this module nor this test sends any signal.
        reader=observer.native_reader()
        try:
            child=subprocess.Popen([str(path)],stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                child.stdin.write(b'ready\n');child.stdin.flush()
                self.assertEqual(child.stdout.readline(),b'ready\n')
                with observer.ExecutableImage(path,digest) as image:
                    scope=observer.ProcessScope([{'label':'native_child','pid':child.pid,'ppid':os.getpid(),
                                                 'pgid':child.pid,'image':'worker'}],reader,{'worker':image})
                    first=scope.initial['processes'][0]
                    self.assertGreater(first['rss_bytes'],0)
                    self.assertEqual(first['identity']['executable_sha256'],digest)
                    self.assertIn(first['identity']['birth']['kind'],('darwin_bsdinfo','linux_proc'))
                    child.stdin.write(b'worked\n');child.stdin.flush()
                    self.assertEqual(child.stdout.readline(),b'worked\n')
                    after=scope.observe()['processes'][0]
                    self.assertEqual(first['identity'],after['identity'])
                    self.assertGreaterEqual(after['cpu_time_ns'],first['cpu_time_ns'])
                    child.stdin.close();self.assertEqual(child.wait(timeout=10),0)
                    with self.assertRaises((ValueError,OSError)):
                        scope.observe()
            finally:
                if not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=10)
                child.stdout.close();child.stderr.close()
        finally:
            reader.close()


    def test_reader_setup_failure_precedes_any_child_spawn(self):
        result=unittest.TestResult()
        with mock.patch.object(observer,'native_reader',side_effect=RuntimeError('reader fixture setup failed')):
            with mock.patch.object(subprocess,'Popen') as spawn:
                NativeChildTests('test_native_owned_child_image_birth_cpu_rss_and_natural_exit').run(result)
        spawn.assert_not_called()
        self.assertEqual(result.testsRun,1);self.assertEqual(len(result.errors),1)
        self.assertEqual(result.failures,[])
        self.assertIn('reader fixture setup failed',result.errors[0][1])



if __name__=='__main__':
    unittest.main()
