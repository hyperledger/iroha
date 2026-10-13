#!/usr/bin/env python3
"""Supervise one standalone ballot child with an out-of-band fatal control page.

Python 3.11+, a 64-bit Linux/macOS host and a source-bound memory-entry executable
are required. No environment variables or network access are needed. Each child
gets a fresh owner-only unlinked shared page. This native process-control ABI is
not a proof codec or production wire format. Only after child death does the
supervisor read it and publish a fatal report; charged execution performs no I/O
for that report. Missing/mismatched evidence is an operational error, never an
invalid-proof decision or an inferred refund. Normal stdout publication occurs
after the worker's charged interval and may still experience backpressure.
"""
from __future__ import annotations

import json
import mmap
import os
import struct
import subprocess
import tempfile

MAGIC = 0x5041524C46415431
SETUP, ADMITTED, EXHAUSTED = 1, 2, 3
MAX_INPUT_BYTES = 425984
HEADER = struct.Struct('=4Q')


def ordinary_report(output: str, code: int, slot: dict) -> None:
    """Reject ordinary decisions whose outcome or debit contradicts shared state."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate ordinary report field')
            value[key] = item
        return value

    def constant(value):
        raise ValueError('nonfinite ordinary report number: ' + value)

    value = json.loads(output, object_pairs_hook=pairs, parse_constant=constant)
    expected = {0: ('accepted', ADMITTED), 1: ('rejected', ADMITTED),
                2: ('admission_rejected', SETUP), 3: ('input_error', SETUP)}
    if (not isinstance(value, dict) or code not in expected
            or (value.get('outcome'), slot['state']) != expected[code]):
        raise ValueError('ordinary outcome/exit contradicts shared state')
    for key in ('charged_units', 'charged_bytes'):
        if type(value.get(key)) is not int or value[key] != slot[key]:
            raise ValueError('ordinary debit contradicts shared state')


def decode_slot(raw: bytes, input_bytes: int) -> dict:
    """Check the native, fully quiescent control page without guessing a debit."""
    page = os.sysconf('SC_PAGESIZE')
    if type(input_bytes) is not int or input_bytes < 0:
        raise ValueError('actual input length must be a nonnegative integer')
    if len(raw) != page or page < HEADER.size:
        raise ValueError('fatal control page length differs')
    magic, state, units, charged_bytes = HEADER.unpack_from(raw)
    if magic != MAGIC or state not in (SETUP, ADMITTED, EXHAUSTED):
        raise ValueError('fatal control identity/state missing')
    if any(raw[HEADER.size:]):
        raise ValueError('fatal control reserved bytes changed')
    if state == SETUP:
        if units != 0 or charged_bytes != 0:
            raise ValueError('setup control carries a debit')
    elif units != 1 or charged_bytes != input_bytes or charged_bytes > MAX_INPUT_BYTES:
        raise ValueError('admitted debit differs from actual bounded input')
    return {'state': state, 'charged_units': units, 'charged_bytes': charged_bytes,
            'reserved_bytes': page}


def finish(child: subprocess.CompletedProcess, raw: bytes, input_bytes: int,
           stdout_captured: bool = True) -> subprocess.CompletedProcess:
    """Require exit and committed shared state to agree before publishing failure."""
    evidence = {'raw_exit': child.returncode, 'raw_stdout': child.stdout,
                'raw_stderr': child.stderr, 'stdout_captured': stdout_captured,
                'fatal_control_hex': raw.hex(), 'read_after_child_exit': True,
                'refund_permitted': False, 'fatal_report_synthesized': False}
    output, error, code = child.stdout or '', child.stderr or '', child.returncode
    try:
        slot = decode_slot(raw, input_bytes)
        evidence['fatal_control'] = slot
        if code == 73:
            if slot['state'] != EXHAUSTED or output or error:
                raise ValueError('resource exit lacks an exclusive committed fatal result')
            output = json.dumps({'outcome': 'resource_exhausted',
                                 'charged_units': slot['charged_units'],
                                 'charged_bytes': slot['charged_bytes'],
                                 'fatal_control_reserved_bytes': slot['reserved_bytes'],
                                 'arena_enforced': True, 'complete_workspace_certificate': False,
                                 'profile_qualified': False}, sort_keys=True) + '\n'
            evidence['fatal_report_synthesized'] = True
        elif slot['state'] == EXHAUSTED:
            raise ValueError('fatal marker without the designated resource exit')
        elif code in (0, 1, 2, 3):
            if not stdout_captured or error:
                raise ValueError('ordinary result lacks exclusive captured stdout')
            ordinary_report(output, code, slot)
    except ValueError as failure:
        evidence['failure'] = str(failure)
        # Keep the child's raw evidence above. No malformed slot becomes proof rejection.
        code, output = 74, ''
        error = 'fatal-control worker error: ' + str(failure) + '\n'
    result = subprocess.CompletedProcess(child.args, code, output, error)
    result.supervisor_evidence = evidence
    return result


def run(command: list[str], *, input_bytes: int, capture_output: bool = True,
        text: bool = True, timeout: float = 120,
        stdout_fd: int | None = None) -> subprocess.CompletedProcess:
    """Run one owned child; capture exact fatal debit without depending on stdout.

    ``stdout_fd`` is solely a regression control for a full or broken sink. Its
    ownership remains with the caller. The child alone receives the shared fd.
    A timeout terminates this diagnostic child, retains the control bytes after
    death, and returns operational failure rather than an inferred proof result.
    """
    if not capture_output or not text or type(input_bytes) is not int or input_bytes < 0:
        raise ValueError('explicit text capture and actual input length are required')
    if any(arg == '--fatal-fd' for arg in command):
        raise ValueError('supervisor alone supplies fatal control ownership')
    page = os.sysconf('SC_PAGESIZE')
    if not isinstance(command, list) or not command or page < HEADER.size or page & (page - 1):
        raise ValueError('invalid command or native page size')
    with tempfile.TemporaryFile() as backing:
        os.fchmod(backing.fileno(), 0o600)
        os.ftruncate(backing.fileno(), page)
        with mmap.mmap(backing.fileno(), page, access=mmap.ACCESS_WRITE) as shared:
            shared[:] = bytes(page)
            argv = [*command, '--fatal-fd', str(backing.fileno())]
            child = subprocess.Popen(argv, stdout=subprocess.PIPE if stdout_fd is None else stdout_fd,
                                     stderr=subprocess.PIPE, text=True, pass_fds=(backing.fileno(),))
            timed_out = False
            try:
                output, error = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # This is exclusively the diagnostic child created immediately above.
                child.kill()
                output, error = child.communicate()
            raw = bytes(shared[:])  # Read once the only writer has exited.
            observed = subprocess.CompletedProcess(argv, child.returncode, output or '', error or '')
            result = finish(observed, raw, input_bytes, stdout_fd is None)
            if timed_out:
                result.supervisor_evidence['timeout'] = True
                result.supervisor_evidence['fatal_report_discarded_on_timeout'] = result.supervisor_evidence['fatal_report_synthesized']
                result.supervisor_evidence['fatal_report_synthesized'] = False
                result.returncode = 74
                result.stdout = ''
                result.stderr = 'fatal-control worker error: diagnostic child timed out\n'
            return result
