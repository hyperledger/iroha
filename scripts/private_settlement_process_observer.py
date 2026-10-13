"""Read exact benchmark process lifetimes and resources without process control.

Darwin uses the existing Nexus Mach-O/image reader plus native CPU counters.
Linux uses descriptor-relative kernel proc files, boot ID and start ticks.
Neither adapter accepts a process name or substitutes a replacement PID owner.
"""
from __future__ import annotations

import ctypes
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
from typing import Any

MAX_EXECUTABLE_BYTES = 4 * 1024**3
MAX_KERNEL_RECORD_BYTES = 1024**2
MAX_EXACT_INTEGER = 1 << 53
PID_MAX = (1 << 31) - 1


class ProcessObservationError(ValueError):
    """An admitted executable or process lifetime cannot be authenticated."""


def require(condition: bool, reason: str) -> None:
    """Reject a missing kernel fact; never replace it with a zero estimate."""
    if not condition:
        raise ProcessObservationError(reason)


def metadata(info: os.stat_result) -> tuple[int, ...]:
    """Retain object identity and modification metadata for an executable."""
    return tuple(getattr(info, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
    ))


class ExecutableImage:
    """Hold the exact hashed regular executable file while observing processes."""

    def __init__(self, path: Path, expected_sha256: str):
        require(type(expected_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None
                and expected_sha256 != "0"*64, "invalid executable SHA-256")
        self.path = path.resolve(strict=True)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_EXECUTABLE_BYTES,
                    "executable is not a bounded regular file")
            self.identity = metadata(info)
            self.sha256 = expected_sha256
            digest, offset = hashlib.sha256(), 0
            while offset < info.st_size:
                chunk = os.pread(self.fd, min(1024**2, info.st_size-offset), offset)
                require(bool(chunk), "executable truncated during hashing")
                digest.update(chunk)
                offset += len(chunk)
            require(digest.hexdigest() == expected_sha256, "executable differs from the admitted source build")
            self.validate()
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def validate(self) -> None:
        """Reject named replacement and modification of the pinned descriptor."""
        require(self.fd >= 0, "executable image is closed")
        require(metadata(os.fstat(self.fd)) == self.identity
                == metadata(os.stat(self.path, follow_symlinks=False)), "pinned executable changed")

    def close(self) -> None:
        """Release this image descriptor once."""
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> ExecutableImage:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def parse_linux_stat(raw: bytes, pid: int) -> dict[str, int]:
    """Parse kernel stat after the last comm parenthesis, including odd names."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_KERNEL_RECORD_BYTES, "invalid proc stat size")
    prefix, separator, suffix = raw.rpartition(b") ")
    require(bool(separator) and prefix.startswith(f"{pid} (".encode()), "proc stat PID/comm differs")
    fields = suffix.split()
    require(len(fields) >= 22 and fields[0] in (b"R",b"S",b"D",b"T",b"t",b"I"),
            "process exited or has an unsupported kernel state")
    result = {}
    for key, index in (("ppid",1),("pgid",2),("utime",11),("stime",12),("start_ticks",19)):
        token = fields[index]
        require(token.isdigit() and len(token)<=20, "invalid proc stat counter")
        value = int(token)
        require(value < 1<<64, "proc stat counter exceeds u64")
        result[key] = value
    require(1 < pid <= PID_MAX and 0 < result["ppid"] <= PID_MAX
            and 0 < result["pgid"] <= PID_MAX and result["start_ticks"] > 0,
            "invalid proc lifetime or parent/group identity")
    return result


def parse_linux_rollup(raw: bytes) -> int:
    """Use smaps_rollup RSS rather than the approximate statm resident count."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_KERNEL_RECORD_BYTES, "invalid smaps rollup size")
    lines = [line for line in raw.splitlines() if line.startswith(b"Rss:")]
    require(len(lines)==1, "smaps rollup omitted or repeated RSS")
    found = re.fullmatch(rb"Rss:\s+([0-9]+)\s+kB\s*", lines[0])
    require(found is not None, "smaps rollup RSS has an invalid unit or value")
    rss = int(found[1])*1024
    require(0 < rss <= MAX_EXACT_INTEGER, "RSS is unavailable or exceeds exact range")
    return rss


def kernel_record(directory: int, name: str) -> bytes:
    """Bound one proc pseudo-file without following an untrusted leaf link."""
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "kernel record is not regular")
        chunks, length = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_KERNEL_RECORD_BYTES+1-length))
            if not chunk:
                break
            chunks.append(chunk); length += len(chunk)
            require(length <= MAX_KERNEL_RECORD_BYTES, "kernel record exceeds its read bound")
        return b"".join(chunks)
    finally:
        os.close(fd)


class LinuxProcessReader:
    """Observe an exact kernel proc directory, birth and executable inode."""

    def __init__(self):
        require(sys.platform.startswith("linux"), "Linux process reader requires Linux")
        self.proc = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",self.boot_id) is not None
                    and self.boot_id.replace('-','') != '0'*32, "invalid Linux boot identity")
            self.clock_ticks = os.sysconf('SC_CLK_TCK')
            require(type(self.clock_ticks) is int and 0 < self.clock_ticks <= 1_000_000
                    and 1_000_000_000 % self.clock_ticks == 0, "unsupported kernel CPU clock resolution")
        except BaseException:
            os.close(self.proc)
            self.proc = -1
            raise

    def sample(self, pid: int, image: ExecutableImage) -> dict[str, Any]:
        """Read lifetime before/after resources and bind the loaded kernel image."""
        require(type(pid) is int and 1 < pid <= PID_MAX and self.proc >= 0, "invalid PID or closed reader")
        image.validate()
        directory = os.open(str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.proc)
        executable = -1
        try:
            directory_info = os.fstat(directory)
            require(directory_info.st_uid == os.geteuid(), "process belongs to another effective user")
            before = parse_linux_stat(kernel_record(directory,'stat'),pid)
            # /proc/<pid>/exe is deliberately followed: this is the kernel's
            # loaded executable reference, not a user-supplied pathname alias.
            executable = os.open('exe',os.O_RDONLY|os.O_CLOEXEC,dir_fd=directory)
            require(metadata(os.fstat(executable)) == image.identity, "running Linux executable differs")
            observed_path = os.readlink('exe',dir_fd=directory)
            require(observed_path == str(image.path), "running executable path changed or was deleted")
            rss = parse_linux_rollup(kernel_record(directory,'smaps_rollup'))
            after = parse_linux_stat(kernel_record(directory,'stat'),pid)
            require(all(before[key]==after[key] for key in ('ppid','pgid','start_ticks'))
                    and after['utime']>=before['utime'] and after['stime']>=before['stime'],
                    "Linux lifetime or CPU clock changed during observation")
            require(metadata(os.fstat(executable)) == image.identity
                    and os.readlink('exe',dir_fd=directory)==observed_path,
                    "running Linux image changed during observation")
            named = os.stat(str(pid),dir_fd=self.proc,follow_symlinks=False)
            require((named.st_dev,named.st_ino,named.st_uid)
                    ==(directory_info.st_dev,directory_info.st_ino,directory_info.st_uid),
                    "Linux process directory was replaced")
            image.validate()
            return {'identity':{'pid':pid,'ppid':after['ppid'],'pgid':after['pgid'],
                    'uid':directory_info.st_uid,'birth':{'kind':'linux_proc','boot_id':self.boot_id,
                    'start_ticks':after['start_ticks']},'executable_path':str(image.path),
                    'executable_sha256':image.sha256},
                    'cpu_time_ns':(after['utime']+after['stime'])*(1_000_000_000//self.clock_ticks),
                    'cpu_counter_unit_ns':1_000_000_000//self.clock_ticks,'rss_bytes':rss}
        finally:
            if executable>=0:
                os.close(executable)
            os.close(directory)

    def close(self) -> None:
        """Close the proc root once without signaling any process."""
        if self.proc>=0:
            os.close(self.proc);self.proc=-1


class _MachTimebaseInfo(ctypes.Structure):
    """Native mach_timebase_info_data_t, whose unsigned ratio converts ticks to ns."""

    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def darwin_cpu_timebase() -> tuple[int, int]:
    """Read the kernel timebase; rusage_info CPU values are Mach absolute ticks."""
    require(sys.platform == 'darwin', 'Darwin CPU timebase requires Darwin')
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    library.mach_timebase_info.argtypes = (ctypes.POINTER(_MachTimebaseInfo),)
    library.mach_timebase_info.restype = ctypes.c_int
    info = _MachTimebaseInfo()
    require(library.mach_timebase_info(ctypes.byref(info)) == 0,
            'native CPU timebase unavailable')
    numer, denom = int(info.numer), int(info.denom)
    darwin_cpu_nanoseconds(0, numer, denom)
    return numer, denom


def darwin_cpu_nanoseconds(ticks: int, numer: int, denom: int) -> int:
    """Convert a cumulative CPU counter with exact integer scaling, then bound it."""
    require(type(ticks) is int and 0 <= ticks < 1 << 65,
            'native CPU tick sum outside range')
    require(type(numer) is int and type(denom) is int
            and 0 < numer < 1 << 32 and 0 < denom < 1 << 32
            and (numer + denom - 1) // denom <= 1_000_000_000,
            'invalid native CPU timebase')
    nanoseconds = ticks * numer // denom
    require(nanoseconds < 1 << 64, 'native CPU time exceeds u64')
    return nanoseconds


class DarwinProcessReader:
    """Extend the existing Nexus native image/birth reader with parent and CPU."""

    def __init__(self):
        require(sys.platform=='darwin','Darwin process reader requires Darwin')
        from nexus import resource_process
        self.native = resource_process
        self.reader = resource_process.DarwinProcessReader()
        self.cpu_numer, self.cpu_denom = darwin_cpu_timebase()

    def sample(self,pid:int,image:ExecutableImage)->dict[str,Any]:
        """Match native BSD birth and loaded UUID around RSS and CPU reads."""
        require(type(pid) is int and 1<pid<=PID_MAX,'invalid PID')
        image.validate()
        before=self.reader._identity(pid)
        usage=self.reader._usage(pid)
        actual=self.reader._path(pid)
        after=self.reader._identity(pid)
        key=lambda info:(info.pid,info.ppid,info.pgid,info.uid,info.ruid,info.start_sec,info.start_usec)
        require(key(before)==key(after),'native process lifetime/parent/group changed')
        uuids=self.native._image_uuids(image.fd,os.fstat(image.fd).st_size)
        require(actual==image.path and bytes(usage.uuid) in uuids,'running Mach-O image differs')
        rss=int(usage.rss)
        require(0<rss<=MAX_EXACT_INTEGER,'RSS unavailable or outside exact range')
        image.validate()
        sample = {'identity':{'pid':pid,'ppid':int(after.ppid),'pgid':int(after.pgid),'uid':int(after.uid),
                'birth':{'kind':'darwin_bsdinfo','started_seconds':int(after.start_sec),
                'started_microseconds':int(after.start_usec),'start_abstime':int(usage.start_abstime)},
                'loaded_image_uuid':bytes(usage.uuid).hex(),'executable_path':str(image.path),
                'executable_sha256':image.sha256},
                'cpu_time_ns':darwin_cpu_nanoseconds(int(usage.user_time)+int(usage.system_time),
                                                     self.cpu_numer,self.cpu_denom),
                'cpu_counter_unit_ns':(self.cpu_numer+self.cpu_denom-1)//self.cpu_denom,
                'rss_bytes':rss}
        # Keep the native RUID with this exact successful sample. The generic
        # serialized scope intentionally has no platform-specific RUID field.
        self.last_native_binding = {'identity': copy.deepcopy(sample['identity']),
                                    'ruid': int(after.ruid), 'cpu_time_ns': sample['cpu_time_ns']}
        return sample

    def close(self)->None:
        """Darwin's reader holds no per-process descriptor between samples."""


def native_reader()->LinuxProcessReader|DarwinProcessReader:
    """Select only an implemented native kernel adapter."""
    if sys.platform=='darwin':
        return DarwinProcessReader()
    if sys.platform.startswith('linux'):
        return LinuxProcessReader()
    raise ProcessObservationError('unsupported benchmark process platform')


def benchmark_process_declarations(inventory:list[dict[str,Any]], *,participants:int,
        worker_pid:int,adapter_pid:int,process_group:int,commit:str,
        validator_sha256:str,worker_sha256:str)->list[dict[str,Any]]:
    """Require every committee process, coordinator and proof-generating worker."""
    require(type(participants) is int and participants in (2,3,4,8,16),'unsupported benchmark topology')
    expected=[('coordinator',None,None)]
    expected.extend(('global_validator',None,v) for v in range(4))
    expected.extend(('dataspace_validator',n,v) for n in range(participants) for v in range(4))
    require(type(inventory) is list and len(inventory)==len(expected),'incomplete benchmark process inventory')
    require(all(type(pid) is int and 1<pid<=PID_MAX for pid in (worker_pid,adapter_pid,process_group)),
            'invalid benchmark process owner')
    rows=[]
    for index,(observed,coordinates) in enumerate(zip(inventory,expected)):
        fields={'role','dataspace_ordinal','validator_ordinal','pid','executable_sha256','revision','health_observed'}
        require(type(observed) is dict and set(observed)==fields,'invalid benchmark process row')
        require((observed['role'],observed['dataspace_ordinal'],observed['validator_ordinal'])==coordinates
                and all(value is None or type(value) is int for value in
                        (observed['dataspace_ordinal'],observed['validator_ordinal'])),
                'benchmark process roles are absent, duplicated or reordered')
        require(observed['revision']==commit and observed['health_observed'] is True,
                'benchmark process revision or health differs')
        image='worker' if observed['role']=='coordinator' else 'validator'
        require(observed['executable_sha256']==(worker_sha256 if image=='worker' else validator_sha256),
                'benchmark process uses an unbound executable')
        rows.append({'label':f'process-{index:03}-{observed["role"]}','pid':observed['pid'],
                     'ppid':worker_pid,'pgid':process_group,'image':image})
    rows.append({'label':'proof_worker','pid':worker_pid,'ppid':adapter_pid,'pgid':process_group,'image':'worker'})
    require(all(type(row['pid']) is int and 1<row['pid']<=PID_MAX for row in rows)
            and len({row['pid'] for row in rows})==len(rows),'benchmark process PID is invalid or reused')
    return rows


class ProcessScope:
    """Pin the actual worker and every declared child throughout one session."""

    def __init__(self, declarations:list[dict[str,Any]], reader:Any, images:dict[str,ExecutableImage]):
        require(type(declarations) is list and 1<=len(declarations)<=70,'invalid process scope size')
        for row in declarations:
            require(type(row) is dict and set(row)=={'label','pid','ppid','pgid','image'},
                    'invalid process declaration fields')
            require(all(type(row[key]) is int and 1<row[key]<=PID_MAX for key in ('pid','ppid','pgid')),
                    'invalid declared process or owner identity')
        require(len({row['pid'] for row in declarations})==len(declarations),'duplicate scoped process')
        self.declarations=tuple(dict(row) for row in declarations)
        self.reader,self.images=reader,images
        self._identities=None
        self._cpu=None
        self._units=None
        self.failed=False
        self.failure_reason=None
        self.initial=self.observe()

    def observe(self)->dict[str,Any]:
        """Reject restart, disappearance, parent/group/image change or CPU rollback."""
        require(not self.failed,'process scope previously failed')
        try:
            return self._observe()
        except BaseException:
            self.failed=True
            raise

    def _observe(self)->dict[str,Any]:
        started=time.monotonic_ns()
        rows=[]
        for declaration in self.declarations:
            expected_fields={'label','pid','ppid','pgid','image'}
            require(set(declaration)==expected_fields,'invalid process declaration fields')
            require(type(declaration['label']) is str and re.fullmatch(r'[a-z0-9_.-]{1,80}',declaration['label']) is not None,
                    'invalid process label')
            require(declaration['image'] in self.images,'unbound process executable')
            observed=self.reader.sample(declaration['pid'],self.images[declaration['image']])
            require(observed['identity']['pid']==declaration['pid']
                    and observed['identity']['uid']==os.geteuid()
                    and observed['identity']['executable_sha256']==self.images[declaration['image']].sha256
                    and observed['identity']['ppid']==declaration['ppid']
                    and observed['identity']['pgid']==declaration['pgid'], 'process parent or group differs from owner')
            require(type(observed['rss_bytes']) is int and 0<observed['rss_bytes']<=MAX_EXACT_INTEGER,
                    'process RSS is not a positive exact integer')
            require(type(observed['cpu_counter_unit_ns']) is int
                    and 0<observed['cpu_counter_unit_ns']<=1_000_000_000,
                    'invalid native CPU counter unit')
            rows.append({'label':declaration['label'],**observed})
        identities=[row['identity'] for row in rows]
        cpu=[row['cpu_time_ns'] for row in rows]
        units=[row['cpu_counter_unit_ns'] for row in rows]
        require(len({row['label'] for row in rows})==len(rows),'duplicate process label')
        if self._identities is not None:
            require(identities==self._identities,'session process restarted or changed executable')
            require(units==self._units,'native CPU counter units changed')
            require(all(current>=prior for current,prior in zip(cpu,self._cpu)),'session process CPU counter regressed')
        require(sum(row['rss_bytes'] for row in rows)<=MAX_EXACT_INTEGER,'aggregate process RSS exceeds exact range')
        require(all(type(value) is int and 0<=value<1<<64 for value in cpu)
                and sum(cpu)<1<<64,'aggregate CPU time exceeds u64')
        self._identities,self._cpu,self._units=copy.deepcopy(identities),cpu,units
        return {'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),'processes':rows,
                'cpu_time_ns':sum(cpu),'rss_bytes':sum(row['rss_bytes'] for row in rows)}


def resource_window_policy(outer_timeout_ms:int,interval_ms:int)->dict[str,int]:
    """Derive bounded evidence storage from the sealed attempt's whole budget."""
    require(type(outer_timeout_ms) is int and 0<outer_timeout_ms<=(1<<64)//1_000_000,
            'invalid attempt resource deadline')
    require(type(interval_ms) is int and 10<=interval_ms<=1000,'invalid sampling interval')
    count=(outer_timeout_ms+interval_ms-1)//interval_ms+2
    return {'outer_timeout_ms':outer_timeout_ms,'requested_sampling_interval_ms':interval_ms,
            'observations_per_chunk':16,'maximum_observation_bytes':256*1024,
            'maximum_observations':count,'maximum_observation_bytes_total':count*256*1024}


class ResourceObservationJournal:
    """Publish bounded immutable chunks without retaining a whole attempt in RAM."""

    def __init__(self,records:Any,prefix:str,policy:dict[str,int]):
        import private_settlement_session_control as control
        require(policy==resource_window_policy(policy['outer_timeout_ms'],policy['requested_sampling_interval_ms']),
                'resource journal policy differs from its sealed derivation')
        control.reference({'path':prefix,'sha256':'1'*64,'bytes':1})
        self.control,self.records,self.prefix,self.policy=control,records,prefix,dict(policy)
        self.pending:list[dict[str,Any]]=[]
        self.count,self.recorded_count,self.total_bytes,self.chunks=0,0,0,0
        self.tail=None
        self.first,self.last=None,None
        self.peak,self.maximum_gap=0,0
        self.failed=False
        self.failure_reason=None

    def append(self,observation:dict[str,Any])->None:
        """Reject oversize or excess observations; never silently omit a sample."""
        require(not self.failed,'resource journal previously failed')
        reason='invalid_process_observation'
        try:
            raw=self.control.canonical(observation)
            reason='observation_byte_budget_exceeded'
            require(0<len(raw)<=self.policy['maximum_observation_bytes'],'resource observation exceeds byte budget')
            reason='observation_count_budget_exceeded'
            require(self.count<self.policy['maximum_observations'],'resource observation count exceeds attempt budget')
            reason='invalid_process_observation'
            require(set(observation)=={'started_monotonic_ns','finished_monotonic_ns','processes','cpu_time_ns','rss_bytes'},
                    'resource observation fields differ')
            require(all(type(observation[key]) is int and 0<=observation[key]<1<<64 for key in
                        ('started_monotonic_ns','finished_monotonic_ns','cpu_time_ns','rss_bytes')),
                    'invalid resource observation counter')
            require(observation['finished_monotonic_ns']>=observation['started_monotonic_ns']
                    and observation['rss_bytes']>0,'invalid resource observation boundaries')
            value=self.control.decode(raw)
            if self.last is not None:
                gap=value['started_monotonic_ns']-self.last['finished_monotonic_ns']
                require(gap>=0 and value['cpu_time_ns']>=self.last['cpu_time_ns'],
                        'resource observations overlap or regress')
                self.maximum_gap=max(self.maximum_gap,gap)
            self.pending.append(value)
            if self.first is None:self.first=value
            self.last=value
            self.peak=max(self.peak,value['rss_bytes'])
            self.count+=1;self.total_bytes+=len(raw)
            require(self.total_bytes<=self.policy['maximum_observation_bytes_total'],
                    'resource observation bytes exceed attempt budget')
            if len(self.pending)==self.policy['observations_per_chunk']:self.flush()
        except BaseException:
            self.failed=True
            if self.failure_reason is None:self.failure_reason=reason
            raise

    def flush(self)->None:
        """Commit all buffered observations into one linked chunk exactly once."""
        require(not self.failed,'resource journal previously failed')
        if not self.pending:return
        try:
            value={'version':1,'kind':'benchmark_process_observation_chunk','sequence':self.chunks,
                   'first_observation_index':self.recorded_count,'previous_chunk':self.tail,
                   'observations':self.pending}
            raw=self.control.canonical(value)
            require(len(raw)<=4*1024*1024+4096,'resource chunk exceeds its byte bound')
            reference=self.records.publish(f'{self.prefix}/chunk-{self.chunks:020d}.json',raw)
            self.tail=reference;self.chunks+=1;self.recorded_count+=len(self.pending);self.pending=[]
        except BaseException:
            self.failed=True
            self.failure_reason='observation_publication_failed'
            raise

    def manifest(self)->dict[str,Any]:
        """Return constant-size chain bindings, including unrecorded failure counts."""
        return {'policy':dict(self.policy),'chunk_tail':self.tail,'chunk_count':self.chunks,
                'observed_count':self.count,'recorded_count':self.recorded_count,
                'observed_bytes':self.total_bytes,'unpublished_count':len(self.pending)}


class ProcessResourceWindow:
    """Stream native CPU/RSS observations between worker timing handshakes.

    The adapter publishes ``baseline_reference`` before releasing timed work,
    then calls finish after measurement_finished. Linked chunks preserve every
    sampled observation and gap. These records do not measure network traffic
    or claim the continuous RSS maximum between samples.
    """

    def __init__(self,scope:ProcessScope,*,records:Any,prefix:str,outer_timeout_ms:int,
                 deadline_monotonic_ns:int,interval_ms:int=100):
        policy=resource_window_policy(outer_timeout_ms,interval_ms)
        self.journal=ResourceObservationJournal(records,prefix,policy)
        self.scope,self.interval_ms,self.deadline=scope,interval_ms,deadline_monotonic_ns
        require(type(self.deadline) is int and time.monotonic_ns()<self.deadline
                and self.deadline-time.monotonic_ns()<=outer_timeout_ms*1_000_000,
                'resource window deadline exceeds the registered attempt budget')
        baseline=scope.observe()
        self.journal.append(baseline)
        self.baseline_reference=records.publish(prefix+'/baseline.json',self.journal.control.canonical(baseline))
        require(time.monotonic_ns()<=self.deadline,'baseline publication crossed the attempt deadline')
        self._stop=threading.Event()
        self._error:BaseException|None=None
        self._error_reason='process_observation_failed'
        self._finished=False
        self._thread=threading.Thread(target=self._sample_periodically,name='aps-benchmark-resources',daemon=True)
        self._thread.start()

    def _observe(self)->None:
        require(time.monotonic_ns()<self.deadline,'resource observation passed the attempt deadline')
        observation=self.scope.observe()
        require(time.monotonic_ns()<=self.deadline,'resource observation crossed the attempt deadline')
        self.journal.append(observation)

    def _sample_periodically(self)->None:
        while not self._stop.wait(self.interval_ms/1000):
            try:
                self._observe()
            except BaseException as error:
                self._error=error
                self._error_reason=(self.journal.failure_reason if self.journal.failed
                                    else 'resource_window_deadline_exceeded' if time.monotonic_ns()>=self.deadline
                                    else 'process_observation_failed')
                return

    def finish(self)->dict[str,Any]:
        """Finalize the evidence chain or retain an explicit incomplete/failed record."""
        require(not self._finished,'resource window already finalized')
        self._finished=True;self._stop.set();self._thread.join(timeout=10)
        if self._thread.is_alive():
            self._error=ProcessObservationError('resource sampler did not stop')
            self._error_reason='resource_sampler_did_not_stop'
        if self._error is None:
            try:self._observe()
            except BaseException as error:
                self._error=error
                self._error_reason=(self.journal.failure_reason if self.journal.failed
                                    else 'resource_window_deadline_exceeded' if time.monotonic_ns()>=self.deadline
                                    else 'process_observation_failed')
        if not self._thread.is_alive() and not self.journal.failed:
            try:self.journal.flush()
            except BaseException as error:
                self._error=error;self._error_reason='observation_publication_failed'
        common={'version':1,'kind':'benchmark_process_resource_window',
                'baseline':self.baseline_reference,'sampler_stopped_observed':not self._thread.is_alive(),
                'journal':self.journal.manifest()}
        if self._error is not None:
            return {**common,'outcome':{'kind':'failed','reason':self._error_reason}}
        first,last=self.journal.first,self.journal.last
        require(self.journal.count>=2 and self.journal.recorded_count==self.journal.count,
                'resource window lacks complete boundary records')
        return {**common,'outcome':{'kind':'succeeded','cpu_time_ns':last['cpu_time_ns']-first['cpu_time_ns'],
                'sampled_peak_rss_bytes':self.journal.peak,'maximum_observation_gap_ns':self.journal.maximum_gap,
                'baseline_started_monotonic_ns':first['started_monotonic_ns'],
                'baseline_finished_monotonic_ns':first['finished_monotonic_ns'],
                'final_started_monotonic_ns':last['started_monotonic_ns'],
                'final_finished_monotonic_ns':last['finished_monotonic_ns']}}


def validate_resource_window(window:dict[str,Any],*,records:Any,outer_timeout_ms:int,
                             expected_processes:list[dict[str,Any]],interval_ms:int=100)->dict[str,int]:
    """Recompute a complete streamed native-resource window from retained bytes.

    ``expected_processes`` is the session-ready native observation projected to
    label, identity and cpu_counter_unit_ns. This reducer never infers a process
    lifetime from its display name, and never trusts the manifest's aggregates.
    """
    import private_settlement_session_control as control
    policy=resource_window_policy(outer_timeout_ms,interval_ms)
    require(type(window) is dict and set(window)=={'version','kind','baseline',
            'sampler_stopped_observed','journal','outcome'} and type(window['version']) is int
            and window['version']==1 and window['kind']=='benchmark_process_resource_window'
            and window['sampler_stopped_observed'] is True,'incomplete resource window')
    require(type(expected_processes) is list and 1<=len(expected_processes)<=70
            and len({r['label'] for r in expected_processes})==len(expected_processes),
            'invalid expected native process inventory')
    for expected in expected_processes:
        require(type(expected) is dict and set(expected)=={'label','identity','cpu_counter_unit_ns'},
                'invalid native process identity projection')
    journal=window['journal']
    require(type(journal) is dict and set(journal)=={'policy','chunk_tail','chunk_count',
            'observed_count','recorded_count','observed_bytes','unpublished_count'},
            'resource journal manifest fields differ')
    require(control.canonical(journal['policy'])==control.canonical(policy),'resource window budget differs')
    for key in ('chunk_count','observed_count','recorded_count','observed_bytes','unpublished_count'):
        control.unsigned(journal[key])
    count=journal['recorded_count']
    require(2<=count<=policy['maximum_observations'] and journal['observed_count']==count
            and journal['unpublished_count']==0 and journal['chunk_count']==(count+15)//16,
            'resource journal omits or adds observations')
    baseline_ref=control.reference(window['baseline'])
    require(baseline_ref['path'].endswith('/baseline.json'),'resource baseline locator differs')
    prefix=baseline_ref['path'].removesuffix('/baseline.json')
    baseline_raw=records.read(baseline_ref)
    baseline=control.decode(baseline_raw)
    current=control.reference(journal['chunk_tail'])
    remaining=count
    last=None;first=None;later=None;total=0;peak=0;maximum_gap=0
    for sequence in range(journal['chunk_count']-1,-1,-1):
        require(current['path']==f'{prefix}/chunk-{sequence:020d}.json'
                and current['bytes']<=4*1024*1024+4096,'resource chunk path, order or bound differs')
        chunk=control.decode(records.read(current))
        require(set(chunk)=={'version','kind','sequence','first_observation_index','previous_chunk','observations'}
                and type(chunk['version']) is int and chunk['version']==1
                and chunk['kind']=='benchmark_process_observation_chunk'
                and type(chunk['sequence']) is int and chunk['sequence']==sequence
                and type(chunk['first_observation_index']) is int
                and chunk['first_observation_index']==sequence*16,'resource chunk coordinates differ')
        observations=chunk['observations'];expected_count=remaining-sequence*16
        require(type(observations) is list and len(observations)==expected_count
                and 1<=expected_count<=16,'resource chunk omitted or duplicated samples')
        for observed in reversed(observations):
            raw=control.canonical(observed)
            require(len(raw)<=policy['maximum_observation_bytes'],'resource sample exceeds bound')
            require(type(observed) is dict and set(observed)=={'started_monotonic_ns',
                'finished_monotonic_ns','processes','cpu_time_ns','rss_bytes'},'resource sample fields differ')
            for key in ('started_monotonic_ns','finished_monotonic_ns','cpu_time_ns','rss_bytes'):
                control.unsigned(observed[key])
            require(observed['finished_monotonic_ns']>=observed['started_monotonic_ns'],
                    'resource observation has reversed boundaries')
            rows=observed['processes']
            require(type(rows) is list and len(rows)==len(expected_processes),'resource inventory is incomplete')
            for index,(row,expected) in enumerate(zip(rows,expected_processes)):
                require(type(row) is dict and set(row)=={'label','identity','cpu_time_ns',
                        'cpu_counter_unit_ns','rss_bytes'},'resource process row fields differ')
                require(control.canonical({key:row[key] for key in expected})==control.canonical(expected),
                        'resource process lifetime, order, image or clock unit changed')
                control.unsigned(row['cpu_time_ns']);control.unsigned(row['rss_bytes'])
                require(0<row['rss_bytes']<=MAX_EXACT_INTEGER,'invalid process RSS')
                if later is not None:
                    require(row['cpu_time_ns']<=later['processes'][index]['cpu_time_ns'],
                            'individual native CPU counter regressed')
            cpu=sum(row['cpu_time_ns'] for row in rows);rss=sum(row['rss_bytes'] for row in rows)
            require(cpu<1<<64 and 0<rss<=MAX_EXACT_INTEGER
                    and observed['cpu_time_ns']==cpu and observed['rss_bytes']==rss,
                    'resource aggregate differs from complete process rows')
            if later is not None:
                gap=later['started_monotonic_ns']-observed['finished_monotonic_ns']
                require(gap>=0,'resource observations overlap or regress')
                maximum_gap=max(maximum_gap,gap)
            if last is None:last=observed
            first=observed;later=observed;total+=len(raw);peak=max(peak,rss)
        remaining-=len(observations)
        if sequence:
            current=control.reference(chunk['previous_chunk'])
        else:
            require(chunk['previous_chunk'] is None,'first resource chunk has an invented predecessor')
    require(remaining==0 and control.canonical(first)==baseline_raw
            and total==journal['observed_bytes'] and total<=policy['maximum_observation_bytes_total'],
            'resource baseline/count/byte inventory differs')
    require(last['finished_monotonic_ns']-first['started_monotonic_ns']<=outer_timeout_ms*1_000_000,
            'resource window exceeds the registered attempt budget')
    metrics={'cpu_time_ns':last['cpu_time_ns']-first['cpu_time_ns'],'sampled_peak_rss_bytes':peak,
             'maximum_observation_gap_ns':maximum_gap,
             'baseline_started_monotonic_ns':first['started_monotonic_ns'],
             'baseline_finished_monotonic_ns':first['finished_monotonic_ns'],
             'final_started_monotonic_ns':last['started_monotonic_ns'],
             'final_finished_monotonic_ns':last['finished_monotonic_ns']}
    require(control.canonical(window['outcome'])==control.canonical({'kind':'succeeded',**metrics}),
            'resource outcome differs from actual complete retained observations')
    require(records.read(baseline_ref)==baseline_raw,'resource baseline changed during replay')
    return metrics
