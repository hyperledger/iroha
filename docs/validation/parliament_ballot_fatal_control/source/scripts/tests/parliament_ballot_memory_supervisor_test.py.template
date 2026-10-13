"""Native fatal control validation and owned-child lifecycle regressions."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parliament_ballot_memory_supervisor as supervisor


def slot(state=supervisor.EXHAUSTED, units=1, size=1, magic=supervisor.MAGIC):
    return struct.pack('=4Q', magic, state, units, size) + bytes(os.sysconf('SC_PAGESIZE') - 32)


def child(code=73, stdout='', stderr=''):
    return subprocess.CompletedProcess(['bound-worker'], code, stdout, stderr)


def command(state=supervisor.EXHAUSTED, code=73, units=1, size=1, suffix=''):
    script = f'''import mmap,os,stat,struct,sys,time
fd=int(sys.argv[-1]); info=os.fstat(fd)
assert sys.argv[-2]=='--fatal-fd'
assert stat.S_ISREG(info.st_mode) and info.st_nlink==0 and info.st_uid==os.geteuid()
assert info.st_mode & 0o077==0 and info.st_size==os.sysconf('SC_PAGESIZE')
with mmap.mmap(fd,info.st_size,access=mmap.ACCESS_WRITE) as page:
 assert not any(page[:])
 page[:32]=struct.pack('=4Q',{supervisor.MAGIC},{state},{units},{size})
{suffix}
sys.exit({code})
'''
    return [sys.executable, '-c', script]


def test_native_slot_checks_exact_identity_page_and_debit():
    assert supervisor.decode_slot(slot(), 1)['state'] == 3
    assert supervisor.decode_slot(slot(supervisor.SETUP, 0, 0), 425985)['charged_units'] == 0
    assert supervisor.decode_slot(slot(supervisor.ADMITTED, 1, 0), 0)['charged_bytes'] == 0
    for raw, size in [(b'', 1), (slot()[:-1], 1), (slot(magic=0), 1), (slot(state=4), 1),
                      (slot(supervisor.SETUP), 1), (slot(units=0), 1), (slot(size=2), 1),
                      (slot(size=425985), 425985), (slot()[:-1]+b'x', 1), (slot(), True)]:
        with pytest.raises(ValueError):
            supervisor.decode_slot(raw, size)


def test_only_committed_resource_exit_publishes_resource_failure():
    result = supervisor.finish(child(), slot(), 1)
    value = json.loads(result.stdout)
    assert result.returncode == 73 and value['charged_units'] == value['charged_bytes'] == 1
    assert value['fatal_control_reserved_bytes'] == os.sysconf('SC_PAGESIZE')
    assert not value['profile_qualified'] and not value['complete_workspace_certificate']
    assert result.supervisor_evidence['raw_stdout'] == ''
    assert result.supervisor_evidence['fatal_report_synthesized']
    assert not result.supervisor_evidence['refund_permitted']
    for process, raw in [(child(), slot(supervisor.ADMITTED)), (child(), slot(supervisor.SETUP, 0, 0)),
                         (child(), bytes(os.sysconf('SC_PAGESIZE'))), (child(0), slot()),
                         (child(-6), slot()), (child(stdout='fake output'), slot()),
                         (child(stderr='unexpected output'), slot())]:
        failed = supervisor.finish(process, raw, 1)
        assert failed.returncode == 74 and not failed.stdout
        assert failed.supervisor_evidence['raw_exit'] == process.returncode
        assert 'worker error' in failed.stderr
        assert not failed.supervisor_evidence['refund_permitted']


def test_ordinary_stdout_is_preserved_and_not_synthesized():
    process = child(0, '{"outcome":"accepted","charged_units":1,"charged_bytes":1}\n')
    result = supervisor.finish(process, slot(supervisor.ADMITTED), 1)
    assert result.stdout == process.stdout and result.returncode == 0
    assert not result.supervisor_evidence['fatal_report_synthesized']


def test_owned_process_reports_shared_debit_only_after_death():
    result = supervisor.run(command(), input_bytes=1)
    assert result.returncode == 73
    assert result.supervisor_evidence['read_after_child_exit']
    assert result.supervisor_evidence['fatal_control']['charged_bytes'] == 1
    second = supervisor.run(command(supervisor.SETUP, 2, 0, 0,
        suffix='print(\'{"outcome":"admission_rejected","charged_units":0,"charged_bytes":0}\')'), input_bytes=425985)
    assert second.returncode == 2 and second.supervisor_evidence['fatal_control']['state'] == 1


@pytest.mark.parametrize('broken', [False, True])
def test_resource_exit_ignores_full_or_broken_stdout(broken):
    read, write = os.pipe()
    try:
        if broken:
            os.close(read); read = None
        else:
            os.set_blocking(write, False)
            while True:
                try:
                    os.write(write, bytes(4096))
                except BlockingIOError:
                    break
            os.set_blocking(write, True)
        result = supervisor.run(command(), input_bytes=1, stdout_fd=write, timeout=5)
        assert result.returncode == 73
        assert result.supervisor_evidence['fatal_report_synthesized']
        assert not result.supervisor_evidence['stdout_captured']
    finally:
        os.close(write)
        if read is not None:
            os.close(read)


def test_timeout_retains_admitted_debit_without_inventing_resource_failure():
    result = supervisor.run(command(supervisor.ADMITTED, suffix='time.sleep(60)'), input_bytes=1, timeout=.2)
    assert result.returncode == 74 and not result.stdout
    assert result.supervisor_evidence['timeout']
    assert result.supervisor_evidence['fatal_control']['charged_units'] == 1
    assert not result.supervisor_evidence['fatal_report_synthesized']
    assert not result.supervisor_evidence['refund_permitted']


def test_invalid_caller_contract_never_starts_a_child():
    with patch.object(supervisor.subprocess, 'Popen') as spawn:
        for kwargs in ({'input_bytes':True}, {'input_bytes':-1}, {'input_bytes':1,'text':False},
                       {'input_bytes':1,'capture_output':False}):
            with pytest.raises(ValueError):
                supervisor.run(['worker'], **kwargs)
        with pytest.raises(ValueError):
            supervisor.run(['worker','--fatal-fd','4'], input_bytes=1)
        assert not spawn.called


def test_ordinary_reports_require_matching_state_outcome_and_exact_debit():
    for code, outcome, state, units, size in [(0, 'accepted', 2, 1, 1),
            (1, 'rejected', 2, 1, 1), (2, 'admission_rejected', 1, 0, 0), (3, 'input_error', 1, 0, 0)]:
        value = {'outcome':outcome, 'charged_units':units, 'charged_bytes':size}
        raw = slot(state, units, size)
        assert supervisor.finish(child(code, json.dumps(value)), raw, 1).returncode == code
        for changed in ({**value, 'charged_units':True}, {**value, 'charged_bytes':size+1},
                        {**value, 'charged_units':1-units}, {**value, 'outcome':'accepted' if code else 'rejected'}):
            result = supervisor.finish(child(code, json.dumps(changed)), raw, 1)
            assert result.returncode == 74 and not result.stdout
        contradictory = slot(1, 0, 0) if state == 2 else slot(2, 1, 1)
        assert supervisor.finish(child(code, json.dumps(value)), contradictory, 1).returncode == 74
    for output in ('', '[]', 'null', '{"charged_units":1,"charged_units":0}',
                   '{"outcome":"accepted","charged_units":NaN,"charged_bytes":1}'):
        assert supervisor.finish(child(0, output), slot(2), 1).returncode == 74


def test_timeout_racing_resource_exit_discards_synthetic_report():
    class Race:
        def __init__(self, args, **kwargs):
            import mmap
            with mmap.mmap(kwargs['pass_fds'][0], os.sysconf('SC_PAGESIZE'), access=mmap.ACCESS_WRITE) as page:
                page[:] = slot()
            self.returncode = 73
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired('owned-child', timeout)
            return '', ''

        def kill(self):
            pass

    with patch.object(supervisor.subprocess, 'Popen', Race):
        result = supervisor.run(['worker'], input_bytes=1)
    assert result.returncode == 74 and not result.stdout
    assert result.supervisor_evidence['timeout']
    assert result.supervisor_evidence['fatal_report_discarded_on_timeout']
    assert not result.supervisor_evidence['fatal_report_synthesized']
    assert result.supervisor_evidence['raw_exit'] == 73
    assert result.supervisor_evidence['fatal_control']['charged_units'] == 1
