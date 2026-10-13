"""Authenticate terminal facts for one owned Darwin child without relaxing live observers.

Darwin publishes saved exit rusage before live PID lookup disappears and before
wait4 becomes ready. Only an exit preceding the failed syscall's lower clock
bound can end sampling. A retained kernel NOTE_EXEC registration closes the
otherwise unauthenticated final-image gap after the text vnode is released.
"""
from __future__ import annotations

import copy
import errno
import os
import re
import select
from . import resource_process as native

MAX_TERMINAL_BYTES = 16 * 1024
NOTE_EXITSTATUS = 0x04000000  # SDK sys/event.h; Python exposes no name for it.
PROC_FLAG_INEXIT = 4         # SDK sys/proc_info.h.
U64 = (1 << 64) - 1
PID_MAX = (1 << 31) - 1
FAILURE_OPERATIONS = frozenset({'proc_pidinfo', 'proc_pid_rusage', 'proc_pidpath'})


def _require(condition, reason):
    if not condition:
        raise native.ProcessObservationError(reason)


def _uint(value, maximum=U64):
    return type(value) is int and 0 <= value <= maximum


def _same_typed(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(_same_typed(left[k], right[k]) for k in left)
    return left == right


def validate_failure(fact):
    """Decode only exact native availability facts with a bounded syscall bracket."""
    _require(type(fact) is dict and set(fact) == {
        'pid', 'operation', 'errno', 'before_abstime', 'after_abstime'}, 'invalid native failure fields')
    _require(_uint(fact['pid'], PID_MAX) and fact['pid'] > 1, 'invalid native failure PID')
    _require((type(fact['operation']) is str and fact['operation'] in FAILURE_OPERATIONS and type(fact['errno']) is int
              and fact['errno'] == errno.ESRCH)
             or (fact['operation'] == 'proc_pid_rusage_exited' and type(fact['errno']) is int
                 and fact['errno'] == 0), 'invalid native failure operation or errno')
    _require(_uint(fact['before_abstime']) and _uint(fact['after_abstime'])
             and 0 < fact['before_abstime'] <= fact['after_abstime'], 'invalid native failure bracket')


def validate_terminal(proof, identity, last_cpu_time_ns):
    """Validate the closed public terminal schema against the admitted sample."""
    _require(type(proof) is dict and set(proof) == {
        'version', 'kind', 'identity', 'real_uid', 'before_flags', 'after_flags',
        'exit_abstime', 'failure', 'exit_status', 'last_sample_cpu_time_ns',
        'terminal_cpu_time_ns', 'registered_before_baseline', 'exec_observed'},
        'invalid terminal fields')
    _require(type(proof['version']) is int and proof['version'] == 1
             and proof['kind'] == 'darwin_owned_child_terminal', 'invalid terminal version')
    _require(type(identity) is dict and set(identity) == {
        'pid', 'ppid', 'pgid', 'uid', 'birth', 'loaded_image_uuid',
        'executable_path', 'executable_sha256'}, 'invalid terminal identity fields')
    for key in ('pid', 'ppid', 'pgid'):
        _require(_uint(identity[key], PID_MAX) and identity[key] > 1, 'invalid terminal process identity')
    _require(_uint(identity['uid'], (1 << 32) - 1), 'invalid terminal UID')
    birth = identity['birth']
    _require(type(birth) is dict and set(birth) == {
        'kind', 'started_seconds', 'started_microseconds', 'start_abstime'}
        and birth['kind'] == 'darwin_bsdinfo', 'invalid terminal birth')
    _require(_uint(birth['started_seconds']) and birth['started_seconds'] > 0
             and _uint(birth['started_microseconds'], 999999)
             and _uint(birth['start_abstime']) and birth['start_abstime'] > 0,
             'invalid terminal birth counters')
    for key, size in [('loaded_image_uuid', 32), ('executable_sha256', 64)]:
        value = identity[key]
        _require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None
                 and value != '0' * size, 'invalid terminal image digest')
    path = identity['executable_path']
    _require(type(path) is str and path.startswith('/') and '\x00' not in path
             and len(os.fsencode(path)) <= 4096, 'invalid terminal executable path')
    # Equality alone must not admit bool-as-int or extra nested fields.
    _require(type(proof['identity']) is dict and _same_typed(proof['identity'], identity),
             'terminal identity differs')
    _require(_uint(proof['real_uid'], (1 << 32) - 1), 'invalid terminal RUID')
    for key in ('before_flags', 'after_flags'):
        _require(_uint(proof[key], (1 << 32) - 1) and proof[key] & PROC_FLAG_INEXIT,
                 'terminal process is not in exit')
    validate_failure(proof['failure'])
    _require(proof['failure']['pid'] == identity['pid'], 'terminal failure PID differs')
    _require(_uint(proof['exit_abstime']) and birth['start_abstime'] < proof['exit_abstime']
             <= proof['failure']['before_abstime'], 'exit did not precede failed syscall')
    _require(_uint(proof['exit_status'], 65535), 'invalid terminal exit status')
    _require(os.WIFEXITED(proof['exit_status']) or os.WIFSIGNALED(proof['exit_status']),
             'terminal status is not an exit')
    _require(_uint(last_cpu_time_ns) and _uint(proof['last_sample_cpu_time_ns'])
             and proof['last_sample_cpu_time_ns'] == last_cpu_time_ns
             and _uint(proof['terminal_cpu_time_ns'])
             and proof['terminal_cpu_time_ns'] >= last_cpu_time_ns,
             'terminal CPU counter regressed')
    _require(proof['registered_before_baseline'] is True and proof['exec_observed'] is False,
             'terminal monitor did not retain original image lifetime')


class DarwinOwnedChildMonitor:
    """Own one pre-baseline kernel registration and consume at most one terminal proof."""

    def __init__(self, pid, image, reader, numer, denom):
        _require(type(pid) is int and 1 < pid <= PID_MAX, 'invalid owned child PID')
        self.pid, self.image, self.reader = pid, image, reader
        self.numer, self.denom = numer, denom
        self.bound = None
        self.last_cpu = None
        self.failed = False
        self.consumed = False
        self.closed = False
        self.queue = select.kqueue()
        try:
            self.queue.control([select.kevent(pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                fflags=select.KQ_NOTE_EXEC | select.KQ_NOTE_EXIT | NOTE_EXITSTATUS)], 0, 0)
        except BaseException:
            self.close()
            raise

    def check(self):
        """Consume only this registered process's events; any exec permanently refuses."""
        _require(not self.closed and not self.failed, 'owned child monitor unavailable')
        try:
            for event in self.queue.control([], 4, 0):
                _require(event.ident == self.pid and event.filter == select.KQ_FILTER_PROC
                         and not event.flags & select.KQ_EV_ERROR
                         and event.fflags != 0
                         and not event.fflags & ~(select.KQ_NOTE_EXEC | select.KQ_NOTE_EXIT | NOTE_EXITSTATUS),
                         'invalid owned child event')
                _require(not event.fflags & select.KQ_NOTE_EXEC, 'owned child executed another image')
                _require(not event.fflags & NOTE_EXITSTATUS or event.fflags & select.KQ_NOTE_EXIT,
                         'exit status without exit event')
        except BaseException:
            self.failed = True
            raise

    def bind_sample(self, binding, sample):
        """Retain RUID from the same native admission; never derive it after exit."""
        self.check()
        _require(not self.consumed and type(binding) is dict and set(binding) == {
            'identity', 'ruid', 'cpu_time_ns'}, 'invalid native sample binding')
        _require(binding['identity'] == sample['identity']
                 and binding['cpu_time_ns'] == sample['cpu_time_ns']
                 and _uint(binding['ruid'], (1 << 32) - 1)
                 and binding['identity']['pid'] == self.pid
                 and binding['identity']['ppid'] == os.getpid(), 'native sample binding differs')
        if self.bound is None:
            self.bound = copy.deepcopy(binding)
        else:
            _require(binding['identity'] == self.bound['identity']
                     and binding['ruid'] == self.bound['ruid']
                     and binding['cpu_time_ns'] >= self.last_cpu, 'native sample binding changed')
        self.last_cpu = binding['cpu_time_ns']

    def authenticate(self, error):
        """One immediate exact terminal sandwich; never wait for a later qualifying exit."""
        _require(not self.consumed and self.bound is not None and not self.failed
                 and not self.closed, 'terminal proof is unavailable or already consumed')
        self.consumed = True
        try:
            _require(type(error) is native.NativeProcessUnavailable and error.pid == self.pid,
                     'untyped or foreign native availability failure')
            failure = error.fact()
            validate_failure(failure)
            self.image.validate()
            before = self.reader._identity(self.pid, include_exited=True)
            usage = self.reader._usage(self.pid, include_exited=True)
            after = self.reader._identity(self.pid, include_exited=True)
            expected = self.bound['identity']
            birth = expected['birth']
            for info in (before, after):
                _require(all(int(getattr(info, key)) == value for key, value in {
                    'pid': self.pid, 'ppid': expected['ppid'], 'pgid': expected['pgid'],
                    'uid': expected['uid'], 'ruid': self.bound['ruid'],
                    'start_sec': birth['started_seconds'],
                    'start_usec': birth['started_microseconds']}.items()), 'terminal native identity changed')
            _require(int(usage.start_abstime) == birth['start_abstime']
                     and bytes(usage.uuid).hex() == expected['loaded_image_uuid'], 'terminal native image or birth changed')
            # Inspect events after all native identity reads, never before the sandwich only.
            self.check()
            self.image.validate()
            cpu = (int(usage.user_time) + int(usage.system_time)) * self.numer // self.denom
            proof = {'version': 1, 'kind': 'darwin_owned_child_terminal',
                'identity': copy.deepcopy(expected), 'real_uid': self.bound['ruid'],
                'before_flags': int(before.flags), 'after_flags': int(after.flags),
                'exit_abstime': int(usage.exit_abstime), 'failure': failure,
                'exit_status': int(after.xstatus), 'last_sample_cpu_time_ns': self.last_cpu,
                'terminal_cpu_time_ns': cpu, 'registered_before_baseline': True, 'exec_observed': False}
            _require(before.xstatus == after.xstatus, 'terminal exit status changed')
            validate_terminal(proof, expected, self.last_cpu)
            return proof
        except BaseException:
            self.failed = True
            raise

    def close(self):
        """Close only this observation descriptor; never signal any process."""
        if not self.closed:
            self.closed = True
            self.queue.close()
