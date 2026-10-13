"""Exact owned-child terminal proof, rejection mutations and actual Darwin controls."""
import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import shutil
import tempfile
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from nexus import resource_process as native
from nexus import resource_process_exit as terminal
import private_settlement_process_observer as observer
import zk_resource_harness as harness


class TerminalFixture:

    def fixture(self):
        identity={'pid':424242,'ppid':os.getpid(),'pgid':os.getpgrp(),'uid':os.geteuid(),
            'birth':{'kind':'darwin_bsdinfo','started_seconds':1000,'started_microseconds':4,'start_abstime':100},
            'loaded_image_uuid':'12'*16,'executable_path':'/admitted/command','executable_sha256':'ab'*32}
        binding={'identity':identity,'ruid':os.getuid(),'cpu_time_ns':50}
        info=SimpleNamespace(pid=identity['pid'],ppid=identity['ppid'],pgid=identity['pgid'],
            uid=identity['uid'],ruid=binding['ruid'],start_sec=1000,start_usec=4,flags=4,xstatus=0)
        usage=native._RusageV0();usage.uuid[:]=bytes.fromhex(identity['loaded_image_uuid'])
        usage.start_abstime=100;usage.exit_abstime=200;usage.user_time=80;usage.system_time=20
        reader=SimpleNamespace(_identity=mock.Mock(return_value=info),_usage=mock.Mock(return_value=usage))
        queue=mock.Mock();queue.control.return_value=[]
        image=mock.Mock()
        with mock.patch.object(select,'kqueue',return_value=queue):
            monitor=terminal.DarwinOwnedChildMonitor(identity['pid'],image,reader,1,1)
        self.addCleanup(monitor.close)
        sample={'identity':identity,'cpu_time_ns':50}
        monitor.bind_sample(binding,sample)
        error=native.NativeProcessUnavailable(identity['pid'],'proc_pidinfo',errno.ESRCH,300,400)
        return monitor,error,reader,queue,image,binding,sample,info,usage

    def proof(self):
        monitor,error,*_=self.fixture()
        return monitor.authenticate(error)



class TerminalTests(TerminalFixture, unittest.TestCase):
    def test_registration_precedes_admission_and_proof_transfers_once(self):
        monitor,error,reader,queue,image,binding,sample,_,_=self.fixture()
        registration=queue.control.call_args_list[0].args[0][0]
        self.assertEqual(registration.ident,424242)
        self.assertTrue(registration.fflags & select.KQ_NOTE_EXEC)
        proof=monitor.authenticate(error)
        self.assertEqual(proof['identity'],sample['identity'])
        self.assertEqual(proof['real_uid'],binding['ruid'])
        self.assertEqual(proof['failure'],error.fact())
        self.assertEqual(proof['terminal_cpu_time_ns'],100)
        self.assertEqual(reader._identity.call_count,2)
        self.assertTrue(all(c.kwargs=={'include_exited':True} for c in reader._identity.call_args_list))
        with self.assertRaises(ValueError):monitor.authenticate(error)
        with self.assertRaises(ValueError):monitor.bind_sample(binding,sample)

    def test_clock_inside_or_after_failed_syscall_never_qualifies(self):
        for exit_tick in (301,350,400,401,0,100):
            with self.subTest(exit_tick=exit_tick):
                monitor,error,_,_,_,_,_,_,usage=self.fixture();usage.exit_abstime=exit_tick
                with self.assertRaises(ValueError):monitor.authenticate(error)
                self.assertTrue(monitor.failed)
                usage.exit_abstime=200
                with self.assertRaises(ValueError):monitor.authenticate(error)

    def test_native_identity_and_original_ruid_mutations_fail(self):
        for field in ['pid','ppid','pgid','uid','ruid','start_sec','start_usec','flags','xstatus']:
            with self.subTest(field=field):
                monitor,error,reader,_,_,_,_,info,_=self.fixture()
                changed=copy.copy(info)
                setattr(changed,field,0 if field=='flags' else getattr(changed,field)+1)
                reader._identity.side_effect=[info,changed]
                with self.assertRaises(ValueError):monitor.authenticate(error)

    def test_native_rusage_mutations_and_cpu_rollback_fail(self):
        for field in ['start_abstime','uuid','user_time']:
            with self.subTest(field=field):
                monitor,error,_,_,_,_,_,_,usage=self.fixture()
                if field=='uuid':usage.uuid[:]=b'X'*16
                elif field=='user_time':usage.user_time=0;usage.system_time=0
                else:usage.start_abstime+=1
                with self.assertRaises(ValueError):monitor.authenticate(error)

    def test_generic_errors_wrong_errno_and_wrong_pid_cannot_be_upgraded(self):
        original=native.NativeProcessUnavailable(424242,'proc_pidinfo',errno.ESRCH,300,400)
        class DerivedUnavailable(native.NativeProcessUnavailable):
            pass
        for error in [ValueError('unavailable'),PermissionError('denied'),
            SimpleNamespace(pid=original.pid,fact=original.fact),
            DerivedUnavailable(424242,'proc_pidinfo',errno.ESRCH,300,400),
            native.NativeProcessUnavailable(424243,'proc_pidinfo',errno.ESRCH,300,400),
            native.NativeProcessUnavailable(424242,'proc_pidinfo',errno.EPERM,300,400),
            native.NativeProcessUnavailable(424242,'unknown',errno.ESRCH,300,400),
            native.NativeProcessUnavailable(424242,'proc_pidinfo',errno.ESRCH,401,400)]:
            with self.subTest(error=type(error).__name__):
                monitor,*_=self.fixture()
                with self.assertRaises(ValueError):monitor.authenticate(error)

    def test_monitor_failure_foreign_event_exec_and_pinned_file_failure(self):
        mutations=['exec','foreign','error','poll','file','closed']
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                monitor,error,_,queue,image,*_=self.fixture()
                event=SimpleNamespace(ident=424242,filter=select.KQ_FILTER_PROC,flags=0,
                                      fflags=select.KQ_NOTE_EXIT|terminal.NOTE_EXITSTATUS)
                if mutation=='exec':event.fflags|=select.KQ_NOTE_EXEC;queue.control.return_value=[event]
                if mutation=='foreign':event.ident+=1;queue.control.return_value=[event]
                if mutation=='error':event.flags=select.KQ_EV_ERROR;queue.control.return_value=[event]
                if mutation=='poll':queue.control.side_effect=OSError('kernel unavailable')
                if mutation=='file':image.validate.side_effect=ValueError('changed original')
                if mutation=='closed':monitor.close()
                with self.assertRaises((ValueError,OSError)):monitor.authenticate(error)

    def test_monitor_checks_exec_after_native_sandwich(self):
        monitor,error,reader,queue,*_=self.fixture()
        def after_read(*args,**kwargs):
            queue.control.return_value=[SimpleNamespace(ident=424242,filter=select.KQ_FILTER_PROC,
                flags=0,fflags=select.KQ_NOTE_EXEC)]
            return reader._identity.return_value
        reader._identity.side_effect=after_read
        with self.assertRaisesRegex(ValueError,'another image'):monitor.authenticate(error)
        self.assertEqual(reader._identity.call_count,2)

    def test_missing_baseline_and_failed_registration_never_admit(self):
        monitor,error,*_=self.fixture();monitor.bound=None
        with self.assertRaises(ValueError):monitor.authenticate(error)
        queue=mock.Mock();queue.control.side_effect=OSError('registration refused')
        with mock.patch.object(select,'kqueue',return_value=queue),self.assertRaises(OSError):
            terminal.DarwinOwnedChildMonitor(424242,mock.Mock(),mock.Mock(),1,1)
        queue.close.assert_called_once()

    def test_closed_proof_schema_rejects_each_field_mutation(self):
        good=self.proof()
        for key in list(good):
            bad=copy.deepcopy(good);del bad[key]
            with self.subTest(missing=key),self.assertRaises(ValueError):
                terminal.validate_terminal(bad,good['identity'],50)
        for key,value in [('version',True),('exec_observed',0),('registered_before_baseline',1),
            ('real_uid',-1),('terminal_cpu_time_ns',49),('exit_status',65536),
            ('exit_abstime',350),('last_sample_cpu_time_ns',True)]:
            bad=copy.deepcopy(good);bad[key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):
                terminal.validate_terminal(bad,good['identity'],50)
        bad=copy.deepcopy(good);bad['unexpected']='unbounded text'
        with self.assertRaises(ValueError):terminal.validate_terminal(bad,good['identity'],50)

    def replay_fixture(self):
        proof=self.proof();identity=proof['identity']
        baseline={'processes':[{'identity':identity,'cpu_time_ns':50}]}
        admission={'version':1,'kind':'darwin_owned_child_admission','identity':identity,
                   'real_uid':proof['real_uid'],'cpu_time_ns':50}
        raw={p:harness.control.canonical(v) for p,v in {
            'observations/terminal.json':proof,'observations/baseline.json':baseline,
            'observations/native-admission.json':admission}.items()}
        bindings={p:{'path':p,'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for p,v in raw.items()}
        sampled={'state':'not_sampled','observations':1,'native_failure':proof['failure'],
                 'terminal':bindings['observations/terminal.json']}
        process={'pid':424242,'sampled':sampled,'exit':{'kind':'exited','code':0},
                 'timed_out':False,'cpu_user_ns':100,'cpu_system_ns':0}
        return process,SimpleNamespace(raw=raw,bindings=bindings)

    def test_replay_binds_proof_reference_admission_original_failure_and_reap(self):
        process,snapshot=self.replay_fixture()
        self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),[])
        for mutation in ['missing','extra','binding','ruid','pid','future','failure','status','cpu','oversize']:
            with self.subTest(mutation=mutation):
                process,snapshot=self.replay_fixture();proof=json.loads(snapshot.raw['observations/terminal.json'])
                if mutation=='missing':snapshot.raw.pop('observations/native-admission.json')
                if mutation=='extra':proof['injected']=True
                if mutation=='binding':process['sampled']['terminal']=dict(process['sampled']['terminal'],sha256='0'*64)
                if mutation=='ruid':proof['real_uid']+=1
                if mutation=='pid':process['pid']+=1
                if mutation=='future':proof['exit_abstime']=350
                if mutation=='failure':process['sampled']['native_failure']=dict(proof['failure'],before_abstime=500)
                if mutation=='status':process['exit']['code']=1
                if mutation=='cpu':proof['terminal_cpu_time_ns']=harness.CPU_ROUNDING_SLACK_NS+101
                if mutation=='oversize':process['sampled']['terminal']=dict(process['sampled']['terminal'],bytes=terminal.MAX_TERMINAL_BYTES+1)
                snapshot.raw['observations/terminal.json']=harness.control.canonical(proof)
                self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),['native_terminal_evidence_invalid'])

    def test_rejected_observation_remains_rejected_with_valid_terminal_diagnostics(self):
        process,snapshot=self.replay_fixture();process['sampled']['state']='failed';process['sampled']['reason']='journal_failed'
        self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),[])
        self.assertEqual(harness.process_reasons(process,{'stdout':{'complete':True},'stderr':{'complete':True}}),
                         ['process_observation_failed:journal_failed'])

    def test_replay_rejects_admission_numeric_type_substitution(self):
        for mutation in ('float_cpu','float_uid','bool_cpu','bool_uid'):
            with self.subTest(mutation=mutation):
                process,snapshot=self.replay_fixture()
                admission=json.loads(snapshot.raw['observations/native-admission.json'])
                if mutation.endswith('cpu'):
                    admission['cpu_time_ns']=float(admission['cpu_time_ns']) if mutation.startswith('float') else True
                else:
                    admission['identity']['uid']=float(admission['identity']['uid']) if mutation.startswith('float') else True
                # Encode deliberately invalid intake directly: the trusted
                # canonical writer already refuses floating point values.
                raw=json.dumps(admission).encode()
                snapshot.raw['observations/native-admission.json']=raw
                snapshot.bindings['observations/native-admission.json']={
                    'path':'observations/native-admission.json','bytes':len(raw),
                    'sha256':hashlib.sha256(raw).hexdigest()}
                self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),
                    ['native_terminal_evidence_invalid'])

    def test_replay_validates_identity_shape_before_recursive_equality(self):
        process,snapshot=self.replay_fixture()
        nested=0
        for _ in range(400):
            nested={'x':nested}
        for path in ('observations/native-admission.json','observations/baseline.json'):
            document=json.loads(snapshot.raw[path])
            identity=document['identity'] if path.endswith('native-admission.json') else document['processes'][0]['identity']
            identity['birth']=nested
            raw=json.dumps(document).encode()
            self.assertLess(len(raw),terminal.MAX_TERMINAL_BYTES)
            snapshot.raw[path]=raw
            snapshot.bindings[path]={'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),
            ['native_terminal_evidence_invalid'])

    def test_replay_rejects_outer_process_type_and_state_substitution(self):
        mutations=[
            ('pid_float',lambda p:p.update(pid=float(p['pid']))),
            ('user_float',lambda p:p.update(cpu_user_ns=float(p['cpu_user_ns']))),
            ('system_float',lambda p:p.update(cpu_system_ns=float(p['cpu_system_ns']))),
            ('timeout_integer',lambda p:p.update(timed_out=0)),
            ('exit_float',lambda p:p['exit'].update(code=0.0)),
            ('exit_bool',lambda p:p['exit'].update(code=False)),
            ('exit_extra',lambda p:p['exit'].update(extra=0)),
            ('signal_bool',lambda p:p.update(exit={'kind':'signaled','signal':True})),
            ('unknown_state',lambda p:p['sampled'].update(state='unknown')),
            ('observation_bool',lambda p:p['sampled'].update(observations=True)),
            ('observation_float',lambda p:p['sampled'].update(observations=1.0)),
        ]
        for name,change in mutations:
            with self.subTest(mutation=name):
                process,snapshot=self.replay_fixture();change(process)
                self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),
                    ['native_terminal_evidence_invalid'])
        for field,value in [('observations',2.0),('observations',True),
                            ('sampled_cpu_time_ns',0.0),('sampled_cpu_time_ns',False)]:
            with self.subTest(validated_field=field,value=value):
                process,snapshot=self.replay_fixture()
                process['sampled'].update(state='validated',observations=2,sampled_cpu_time_ns=0)
                self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),[])
                process['sampled'][field]=value
                self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),
                    ['native_terminal_evidence_invalid'])

    def test_replay_keeps_well_typed_failed_status_mismatch_as_rejected_diagnostic(self):
        process,snapshot=self.replay_fixture()
        process['sampled'].update(state='failed',reason='native_terminal_reap_differs')
        process['exit']={'kind':'signaled','signal':9}
        self.assertEqual(harness._terminal_evidence_reasons(process,snapshot),[])
        self.assertEqual(harness.process_reasons(process,
            {'stdout':{'complete':True},'stderr':{'complete':True}}),
            ['command_signal:9','process_observation_failed:native_terminal_reap_differs'])

    def test_native_syscall_retains_exact_bracket_and_errno(self):
        reader=object.__new__(native.DarwinProcessReader)
        def failed(*args):ctypes.set_errno(errno.ESRCH);return 0
        reader.lib=SimpleNamespace(proc_pidinfo=failed)
        with mock.patch.object(native,'darwin_absolute_time',side_effect=[300,400]),self.assertRaises(native.NativeProcessUnavailable) as caught:
            reader._identity(424242)
        self.assertEqual(caught.exception.fact(),{'pid':424242,'operation':'proc_pidinfo','errno':errno.ESRCH,'before_abstime':300,'after_abstime':400})
        def denied(*args):ctypes.set_errno(errno.EPERM);return 0
        reader.lib.proc_pidinfo=denied
        with mock.patch.object(native,'darwin_absolute_time',side_effect=[300,400]),self.assertRaises(native.ProcessObservationError) as caught:
            reader._identity(424242)
        self.assertNotIsInstance(caught.exception,native.NativeProcessUnavailable)


@unittest.skipUnless(sys.platform=='darwin','actual Darwin process and exec controls')
class NativeTerminalTests(unittest.TestCase):
    def test_real_unreaped_child_terminal_preserves_exact_original_and_generic_scope_fails(self):
        path=Path('/usr/bin/tee').resolve();child=subprocess.Popen([str(path)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL)
        reader=observer.DarwinProcessReader()
        with observer.ExecutableImage(path,hashlib.sha256(path.read_bytes()).hexdigest()) as image:
            monitor=terminal.DarwinOwnedChildMonitor(child.pid,image,reader.reader,reader.cpu_numer,reader.cpu_denom)
            try:
                scope=observer.ProcessScope([{'label':'measured_command','pid':child.pid,'ppid':os.getpid(),
                    'pgid':os.getpgid(child.pid),'image':'command'}],reader,{'command':image})
                monitor.bind_sample(reader.last_native_binding,scope.initial['processes'][0])
                child.stdin.close()
                deadline=time.monotonic()+5
                while True:
                    usage=reader.reader._usage(child.pid,include_exited=True)
                    if usage.exit_abstime:break
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(0.001)
                with self.assertRaises(native.NativeProcessUnavailable) as caught:scope.observe()
                self.assertTrue(scope.failed)
                proof=monitor.authenticate(caught.exception)
                self.assertEqual(proof['identity'],scope.initial['processes'][0]['identity'])
                self.assertLessEqual(proof['exit_abstime'],proof['failure']['before_abstime'])
                pid,status,_=os.wait4(child.pid,0);child.returncode=os.waitstatus_to_exitcode(status)
                self.assertEqual(pid,child.pid);self.assertEqual(status,proof['exit_status']);self.assertEqual(status,0)
            finally:
                monitor.close();reader.close()
                if not child.stdin.closed:child.stdin.close()
                child.wait(timeout=5)

    def test_real_same_image_exec_cannot_rebind_to_matching_uuid(self):
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('actual same-image exec control requires a native C compiler')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root/'same_image.c'
        source.write_text('#include <unistd.h>\nint main(int argc, char **argv) { '
            'if (argc > 1) return 0; char byte; '
            'if (write(1, "R", 1) != 1 || read(0, &byte, 1) != 1) return 2; '
            'execl(argv[0], argv[0], "after-exec", (char *)0); return 3; }\n')
        path = root/'same_image'
        subprocess.run([compiler, '-Wall', '-Wextra', '-Werror', str(source), '-o', str(path)], check=True, capture_output=True)
        child=subprocess.Popen([str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        self.assertEqual(child.stdout.read(1),b'R');reader=observer.DarwinProcessReader()
        with observer.ExecutableImage(path,hashlib.sha256(path.read_bytes()).hexdigest()) as image:
            monitor=terminal.DarwinOwnedChildMonitor(child.pid,image,reader.reader,reader.cpu_numer,reader.cpu_denom)
            try:
                sample=reader.sample(child.pid,image);monitor.bind_sample(reader.last_native_binding,sample)
                child.stdin.write(b'go\n');child.stdin.flush();child.wait(timeout=5)
                with self.assertRaisesRegex(ValueError,'another image'):monitor.check()
                self.assertTrue(monitor.failed)
            finally:
                monitor.close();reader.close();child.stdin.close();child.stdout.close()
                child.wait(timeout=5)


class HarnessTransitionTests(TerminalFixture, unittest.TestCase):
    """Exercise the actual sampler loop with exact terminal and permanent failure branches."""
    def run_transition(self, *, sample_error='native', journal_error=False, flush_error=False,
                       baseline_error=False, reap_status=0, timeout=False):
        monitor,error,_,_,_,binding,sample,_,_=self.fixture()
        scope=SimpleNamespace(initial={'processes':[sample]},observe=mock.Mock())
        if sample_error=='native':scope.observe.side_effect=error
        elif sample_error=='generic':scope.observe.side_effect=ValueError('CPU regressed')
        else:scope.observe.return_value={'processes':[sample]}
        reader=SimpleNamespace(last_native_binding=binding,close=mock.Mock())
        journal=SimpleNamespace(append=mock.Mock(),flush=mock.Mock(),failed=False,failure_reason=None,count=1)
        if journal_error:journal.append.side_effect=[None,ValueError('journal storage failed')]
        if flush_error:journal.flush.side_effect=ValueError('journal flush failed')
        records=mock.Mock()
        def publish(path,raw):
            if baseline_error and path=='observations/baseline.json':raise ValueError('baseline publication failed')
            return {'path':path,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        records.publish.side_effect=publish
        usage=SimpleNamespace(ru_utime=1.0,ru_stime=0.0,ru_maxrss=1024)
        child=SimpleNamespace(pid=424242,returncode=None)
        reaps=[None,None] if timeout else [None,(reap_status,usage)]
        with mock.patch.object(harness.observer,'native_reader',return_value=reader), \
             mock.patch.object(harness,'_owned_child_monitor',return_value=monitor), \
             mock.patch.object(harness.observer,'ProcessScope',return_value=scope), \
             mock.patch.object(harness.observer,'ResourceObservationJournal',return_value=journal), \
             mock.patch.object(harness.os,'getpgid',return_value=os.getpgrp()), \
             mock.patch.object(harness.time,'sleep'), \
             mock.patch.object(harness.time,'monotonic_ns',side_effect=[1,2,20_000_000,21_000_000] if timeout else lambda:1), \
             mock.patch.object(harness,'_try_reap',side_effect=reaps), \
             mock.patch.object(harness,'_kill_own_child',return_value=(9,usage)) as deadline, \
             mock.patch.object(monitor,'authenticate',wraps=monitor.authenticate) as authenticate:
            result=harness.observe_child(child,mock.Mock(),records,100,10 if timeout else 10000)
        return result,authenticate.call_count,deadline.call_count,records

    def test_authenticated_exit_stops_sampling_before_reap_and_keeps_provenance(self):
        result,count,signals,records=self.run_transition()
        self.assertEqual(result['sampled']['state'],'not_sampled')
        self.assertEqual(result['sampled']['observations'],1)
        self.assertEqual(result['sampled']['native_failure']['before_abstime'],300)
        self.assertEqual(result['sampled']['terminal']['path'],'observations/terminal.json')
        self.assertEqual((count,signals),(1,0))
        self.assertEqual(result['exit'],{'kind':'exited','code':0})
        self.assertEqual(len([c for c in records.publish.call_args_list if c.args[0]=='observations/terminal.json']),1)

    def test_generic_cpu_journal_baseline_and_flush_failure_stay_rejected(self):
        for options in [{'sample_error':'generic'},{'sample_error':None,'journal_error':True},
                        {'baseline_error':True},{'flush_error':True}]:
            with self.subTest(options=options):
                result,count,_,_=self.run_transition(**options)
                self.assertEqual(result['sampled']['state'],'failed')
                self.assertEqual(result['exit'],{'kind':'exited','code':0})
                self.assertEqual(count,1 if options.get('flush_error') else 0)

    def test_late_reap_timeout_status_and_cpu_consistency_are_not_qualified(self):
        for options in [{'reap_status':256},{'reap_status':9},{'timeout':True}]:
            with self.subTest(options=options):
                result,count,signals,_=self.run_transition(**options)
                self.assertEqual(result['sampled']['state'],'failed')
                self.assertEqual(result['sampled']['reason'],'native_terminal_reap_differs')
                self.assertEqual(count,1)
                self.assertEqual(signals,int(options.get('timeout',False)))


class RegistrationFailureTests(unittest.TestCase):
    def test_failed_registration_cannot_be_excused_by_immediate_or_later_reap(self):
        usage=SimpleNamespace(ru_utime=1.0,ru_stime=0.0,ru_maxrss=1024)
        for error_number in (errno.EACCES,errno.EMFILE,errno.ESRCH):
            for later in (False,True):
                with self.subTest(errno=error_number,later=later):
                    child=SimpleNamespace(pid=424242,returncode=None)
                    reader=mock.Mock()
                    reaps=[None,(0,usage)] if later else [(0,usage)]
                    with mock.patch.object(harness.observer,'native_reader',return_value=reader), \
                         mock.patch.object(harness,'_owned_child_monitor',side_effect=OSError(error_number,'registration refused')), \
                         mock.patch.object(harness.observer,'ProcessScope') as scope, \
                         mock.patch.object(harness.time,'sleep'), \
                         mock.patch.object(harness,'_try_reap',side_effect=reaps):
                        result=harness.observe_child(child,mock.Mock(),mock.Mock(),100,10000)
                    scope.assert_not_called()
                    self.assertEqual(result['sampled'],{'state':'failed','reason':'native_monitor_registration_failed',
                        'monitor_failure':{'operation':'owned_child_monitor_registration','errno':error_number}})
                    self.assertEqual(result['exit'],{'kind':'exited','code':0})
                    reader.close.assert_called_once()
                    snapshot=SimpleNamespace(bindings={},raw={})
                    self.assertEqual(harness._terminal_evidence_reasons(result,snapshot),[])
                    self.assertEqual(harness.process_reasons(result,{'stdout':{'complete':True},'stderr':{'complete':True}}),
                        ['process_observation_failed:native_monitor_registration_failed'])
                    result['sampled']['state']='not_sampled'
                    self.assertEqual(harness._terminal_evidence_reasons(result,snapshot),['native_terminal_evidence_invalid'])


class ReapDeadlineTests(TerminalFixture, unittest.TestCase):
    """The actual initial, live and terminal polling paths share one deadline."""

    def run_reap(self, path, observed_at):
        monitor,error,_,_,_,binding,sample,_,_=self.fixture()
        scope=SimpleNamespace(initial={'processes':[sample]},observe=mock.Mock(side_effect=error))
        reader=SimpleNamespace(last_native_binding=binding,close=mock.Mock())
        journal=SimpleNamespace(append=mock.Mock(),flush=mock.Mock(),failed=False,failure_reason=None,count=1)
        records=mock.Mock()
        records.publish.side_effect=lambda path,raw:{'path':path,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        child=SimpleNamespace(pid=424242,returncode=None)
        usage=SimpleNamespace(ru_utime=1.0,ru_stime=0.0,ru_maxrss=1024)
        started=100
        clock={'now':started,'polls':0}
        def reap(pid):
            self.assertEqual(pid,child.pid)
            clock['polls']+=1
            if path in ('terminal_auth','terminal_poll') and clock['polls']==1:
                return None
            clock['now']=observed_at
            return (0,usage)
        real_authenticate=monitor.authenticate
        def authenticate(cause):
            proof=real_authenticate(cause)
            if path=='terminal_auth':
                clock['now']=observed_at
            return proof
        with mock.patch.object(harness.observer,'native_reader',return_value=reader), \
             mock.patch.object(harness,'_owned_child_monitor',return_value=monitor), \
             mock.patch.object(harness.observer,'ProcessScope',
                side_effect=error if path=='initial' else None,
                return_value=scope), \
             mock.patch.object(harness.observer,'ResourceObservationJournal',return_value=journal), \
             mock.patch.object(harness.os,'getpgid',return_value=os.getpgrp()), \
             mock.patch.object(harness.time,'sleep'), \
             mock.patch.object(harness.time,'monotonic_ns',side_effect=lambda:clock['now']), \
             mock.patch.object(harness,'_try_reap',side_effect=reap), \
             mock.patch.object(harness,'_kill_own_child') as signal, \
             mock.patch.object(monitor,'authenticate',side_effect=authenticate) as terminal_read:
            result=harness.observe_child(child,mock.Mock(),records,100,10)
        signal.assert_not_called()
        self.assertEqual(terminal_read.call_count,int(path.startswith('terminal')))
        self.assertEqual(child.returncode,0)
        self.assertEqual(result['exit'],{'kind':'exited','code':0})
        reader.close.assert_called_once()
        return result

    def test_first_successful_reap_at_or_after_deadline_is_never_qualified(self):
        for path in ('initial','live','terminal_auth','terminal_poll'):
            for observed_at in (10_000_100,20_000_100):
                with self.subTest(path=path,observed_at=observed_at):
                    result=self.run_reap(path,observed_at)
                    self.assertTrue(result['timed_out'])
                    self.assertGreaterEqual(result['wall_ns'],10_000_000)
                    self.assertIn('command_timeout',harness.process_reasons(result,
                        {'stdout':{'complete':True},'stderr':{'complete':True}}))
                    if path.startswith('terminal'):
                        self.assertEqual(result['sampled']['state'],'failed')
                        self.assertEqual(result['sampled']['reason'],'native_terminal_reap_differs')
                        self.assertIn('terminal',result['sampled'])

    def test_first_successful_reap_before_deadline_keeps_valid_control(self):
        for path in ('initial','live','terminal_auth','terminal_poll'):
            with self.subTest(path=path):
                result=self.run_reap(path,10_000_099)
                self.assertFalse(result['timed_out'])
                self.assertEqual(result['sampled']['state'],'not_sampled')
                self.assertEqual(harness.process_reasons(result,
                    {'stdout':{'complete':True},'stderr':{'complete':True}}),[])


class InitialAbsenceTests(TerminalFixture, unittest.TestCase):
    """An immediate exit cannot excuse generic failure or a retained exec."""

    def run_initial(self,error,monitor,*,later=False):
        child=SimpleNamespace(pid=424242,returncode=None)
        usage=SimpleNamespace(ru_utime=1.0,ru_stime=0.0,ru_maxrss=1024)
        reader=mock.Mock()
        reaps=[None,(0,usage)] if later else [(0,usage)]
        with mock.patch.object(harness.observer,'native_reader',return_value=reader), \
             mock.patch.object(harness,'_owned_child_monitor',return_value=monitor), \
             mock.patch.object(harness.observer,'ProcessScope',side_effect=error), \
             mock.patch.object(harness.os,'getpgid',return_value=os.getpgrp()), \
             mock.patch.object(harness.time,'sleep'), \
             mock.patch.object(harness,'_try_reap',side_effect=reaps), \
             mock.patch.object(harness,'_kill_own_child') as signal:
            result=harness.observe_child(child,mock.Mock(),mock.Mock(),100,10000)
        signal.assert_not_called()
        reader.close.assert_called_once()
        self.assertEqual(result['exit'],{'kind':'exited','code':0})
        return result

    def test_generic_initial_failure_stays_failed_despite_immediate_or_later_exit(self):
        for error in (ValueError('CPU regressed'),PermissionError(errno.EPERM,'denied'),
                      ValueError('process parent or group differs from owner'),OSError(errno.ESRCH,'untyped missing'),
                      native.NativeProcessUnavailable(424243,'proc_pidinfo',errno.ESRCH,300,400),
                      native.NativeProcessUnavailable(424242,'proc_pidinfo',errno.EACCES,300,400)):
            for later in (False,True):
                with self.subTest(error=type(error).__name__,later=later):
                    monitor,*_=self.fixture()
                    result=self.run_initial(error,monitor,later=later)
                    self.assertEqual(result['sampled']['state'],'failed')
                    self.assertTrue(harness.process_reasons(result,
                        {'stdout':{'complete':True},'stderr':{'complete':True}}))

    def test_exact_initial_absence_requires_immediate_reap_and_clean_retained_monitor(self):
        for event in ('none','exec','poll_failure','foreign','later'):
            with self.subTest(event=event):
                monitor,error,_,queue,*_=self.fixture()
                if event in ('exec','foreign'):
                    queue.control.return_value=[SimpleNamespace(ident=424243 if event=='foreign' else 424242,
                        filter=select.KQ_FILTER_PROC,flags=0,
                        fflags=select.KQ_NOTE_EXEC if event=='exec' else select.KQ_NOTE_EXIT)]
                elif event=='poll_failure':
                    queue.control.side_effect=OSError('event observation unavailable')
                result=self.run_initial(error,monitor,later=event=='later')
                self.assertEqual(result['sampled']['state'],'not_sampled' if event=='none' else 'failed')
                self.assertEqual(result['sampled']['native_failure'],error.fact())
