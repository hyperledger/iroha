"""Bound RSS to exact Darwin validator lifetimes and reviewed executable images.

This adapter only reads explicitly supplied local PIDs. The outer transaction
collector owns request timing and the probe deadline. Unsupported hosts fail
closed; this module does not estimate RSS from Kura counts or process names.
"""
from __future__ import annotations

import ctypes
import errno
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys

MAX_EXECUTABLE_BYTES = 4 * 1024**3
MAX_LOAD_COMMAND_BYTES = 16 * 1024**2
MAX_EXECUTABLE_PATH_BYTES = 4096
MAX_EXECUTABLE_PATH_COMPONENTS = 64
MAX_EXACT_INTEGER = 1 << 53
MAX_PEERS = 64
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class ProcessObservationError(ValueError):
    """An exact process observation is unavailable or changed identity."""


def darwin_absolute_time() -> int:
    """Read the kernel's unscaled monotonic clock, shared with rusage exit ticks."""
    clock = ctypes.CDLL("/usr/lib/libSystem.B.dylib").mach_absolute_time
    clock.argtypes = ()
    clock.restype = ctypes.c_uint64
    return int(clock())


class NativeProcessUnavailable(ProcessObservationError):
    """One native syscall's unavailable process, with its original clock bracket."""

    def __init__(self, pid: int, operation: str, error_number: int,
                 before_abstime: int, after_abstime: int):
        super().__init__("native process unavailable")
        self.pid, self.operation, self.error_number = pid, operation, error_number
        self.before_abstime, self.after_abstime = before_abstime, after_abstime

    def fact(self) -> dict:
        """Bounded public provenance; never include a native exception string."""
        return {"pid": self.pid, "operation": self.operation, "errno": self.error_number,
                "before_abstime": self.before_abstime, "after_abstime": self.after_abstime}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProcessObservationError(message)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    """Pin directory ownership and identity while allowing unrelated children."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _pread(fd: int, size: int, offset: int, limit: int) -> bytes:
    _require(0 <= offset <= limit and 0 <= size <= limit - offset,
             "executable structure exceeds its admitted file")
    data = os.pread(fd, size, offset)
    _require(len(data) == size, "executable structure became truncated")
    return data


def _thin_uuid(fd: int, offset: int, length: int, limit: int) -> bytes:
    """Read exactly one LC_UUID from a bounded 64-bit Mach-O slice."""
    _require(length >= 32, "Mach-O slice is too short")
    header = _pread(fd, 32, offset, limit)
    byte_order = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}.get(header[:4])
    _require(byte_order is not None, "expected a 64-bit Mach-O image")
    fields = struct.unpack(byte_order + "8I", header)
    _require(fields[3] == 2, "Mach-O slice must be MH_EXECUTE")
    count, size = fields[4], fields[5]
    _require(0 < count <= 65536 and count * 8 <= size <= MAX_LOAD_COMMAND_BYTES
             and size <= length - 32, "Mach-O load commands exceed their bound")
    commands = _pread(fd, size, offset + 32, limit)
    position = 0
    found = None
    for _ in range(count):
        _require(position + 8 <= size, "truncated Mach-O load command")
        command, command_size = struct.unpack_from(byte_order + "II", commands, position)
        _require(command_size >= 8 and command_size % 8 == 0
                 and command_size <= size - position, "invalid Mach-O load command size")
        if command == 0x1B:  # LC_UUID, mach-o/loader.h
            _require(command_size == 24 and found is None, "duplicate or malformed Mach-O UUID")
            found = commands[position + 8:position + 24]
        position += command_size
    _require(position == size and found is not None and any(found),
             "Mach-O image has no exact nonzero UUID")
    return found


def _image_uuids(fd: int, length: int) -> frozenset[bytes]:
    """Admit thin or bounded universal Mach-O executable images."""
    header = _pread(fd, 8, 0, length)
    if header[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return frozenset({_thin_uuid(fd, 0, length, length)})
    _require(header[:4] == b"\xca\xfe\xba\xbe", "unsupported executable image format")
    count = struct.unpack(">I", header[4:])[0]
    _require(1 <= count <= 32, "universal image architecture count exceeds its bound")
    table_end = 8 + count * 20
    table = _pread(fd, count * 20, 8, length)
    ranges = []
    uuids = set()
    for index in range(count):
        _, _, offset, size, alignment = struct.unpack_from(">5I", table, index * 20)
        _require(alignment <= 31 and offset % (1 << alignment) == 0
                 and offset >= table_end and size >= 32 and offset <= length
                 and size <= length - offset, "invalid universal image slice")
        _require(all(offset + size <= start or end <= offset for start, end in ranges),
                 "overlapping universal image slices")
        ranges.append((offset, offset + size))
        uuid = _thin_uuid(fd, offset, size, length)
        _require(uuid not in uuids, "duplicate universal image UUID")
        uuids.add(uuid)
    return frozenset(uuids)


class ExecutableImage:
    """Retain an owned executable and its original lexical namespace.

    This admits the on-disk main image, not the complete loaded runtime. Dynamic
    libraries, shader files and their search namespaces need their own retained
    runtime closure; neither an LC_UUID nor this file hash proves that closure.
    """

    __slots__ = ("_path", "_fd", "_chain", "_identity", "_sha256", "_uuids")

    def __init__(self, path: Path, expected_sha256: str):
        _require(not hasattr(self, "_path"), "executable owner cannot be readmitted")
        _require(type(expected_sha256) is str
                 and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
                 "executable digest must be canonical SHA-256")
        _require(type(path) is type(Path('/')) and path.anchor == '/'
                 and str(path) == os.path.abspath(path)
                 and 1 <= len(path.parts) - 1 <= MAX_EXECUTABLE_PATH_COMPONENTS
                 and len(os.fsencode(path)) <= MAX_EXECUTABLE_PATH_BYTES,
                 "executable path must be bounded absolute lexical form")
        self._path = path
        self._fd = -1
        self._chain = []
        try:
            # Like the physical bundle owner, retain each directory edge. Its
            # semantic allocation is unrelated, so do not import that owner.
            for part in path.parts[:-1]:
                parent = self._chain[-1][0] if self._chain else None
                descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=parent)
                try:
                    directory = os.fstat(descriptor)
                    _require(stat.S_ISDIR(directory.st_mode), "executable ancestor is not a directory")
                    self._chain.append((descriptor, part, _directory_identity(directory)))
                except BaseException:
                    os.close(descriptor)
                    raise
            self._fd = os.open(path.name, _FILE_FLAGS, dir_fd=self._chain[-1][0])
            info = os.fstat(self.fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                     and info.st_nlink == 1 and info.st_mode & stat.S_IXUSR
                     and info.st_mode & 0o7022 == 0
                     and 0 < info.st_size <= MAX_EXECUTABLE_BYTES,
                     "executable is not a bounded owned single-link executable file")
            self._identity = _file_identity(info)
            digest = hashlib.sha256()
            offset = 0
            while offset < info.st_size:
                chunk = _pread(self.fd, min(1024**2, info.st_size - offset), offset, info.st_size)
                digest.update(chunk)
                offset += len(chunk)
            _require(digest.hexdigest() == expected_sha256, "executable differs from the pinned digest")
            self._sha256 = expected_sha256
            self._uuids = _image_uuids(self.fd, info.st_size)
            self.validate()
        except BaseException:
            self.close()
            raise

    @property
    def path(self) -> Path:
        """The original admitted lexical path; callers cannot retarget it."""
        return self._path

    @property
    def fd(self) -> int:
        """The retained descriptor, or minus one after controlled close."""
        return self._fd

    @property
    def identity(self) -> tuple[int, ...]:
        """The immutable admitted file identity; validation never refreshes it."""
        return self._identity

    @property
    def sha256(self) -> str:
        """The independently supplied digest matched against the original file."""
        return self._sha256

    @property
    def uuids(self) -> frozenset[bytes]:
        """The UUID set parsed from the same original admitted image."""
        return self._uuids

    def _validate_ancestors(self) -> None:
        """Recheck every retained original directory and named parent edge."""
        for index, (descriptor, name, identity) in enumerate(self._chain):
            parent = self._chain[index - 1][0] if index else None
            _require(_directory_identity(os.fstat(descriptor)) == identity
                     and _directory_identity(os.stat(name, dir_fd=parent,
                                                      follow_symlinks=False)) == identity,
                     "pinned executable ancestor changed")

    def validate(self) -> None:
        """Reject replacement or mutation of the hashed file and its named entry."""
        _require(self.fd >= 0 and bool(self._chain), "executable descriptor is closed")
        self._validate_ancestors()
        _require(_file_identity(os.fstat(self.fd)) == self.identity
                 and _file_identity(os.stat(self.path.name, dir_fd=self._chain[-1][0],
                                            follow_symlinks=False)) == self.identity,
                 "pinned executable file changed")
        self._validate_ancestors()

    def close(self) -> None:
        """Release the retained descriptor once collection and checks finish."""
        if self.fd >= 0:
            os.close(self.fd)
            self._fd = -1
        while self._chain:
            os.close(self._chain.pop()[0])

    def __enter__(self) -> ExecutableImage:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class _BsdInfo(ctypes.Structure):
    """Native proc_bsdinfo from the pinned macOS SDK sys/proc_info.h."""
    _fields_ = [
        *[(name, ctypes.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
            "svuid", "svgid", "reserved")],
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        *[(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")],
        ("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64),
    ]


class _RusageV0(ctypes.Structure):
    """Native rusage_info_v0 from the pinned macOS SDK sys/resource.h."""
    _fields_ = [("uuid", ctypes.c_uint8 * 16), *[(name, ctypes.c_uint64) for name in (
        "user_time", "system_time", "idle_wakeups", "interrupt_wakeups", "pageins",
        "wired_size", "rss", "footprint", "start_abstime", "exit_abstime")]]


@dataclass(frozen=True)
class ProcessIdentity:
    """Kernel lifetime and actual loaded image, independent of display names."""
    pid: int
    uid: int
    start_seconds: int
    start_microseconds: int
    start_abstime: int
    image_uuid: str
    executable_sha256: str


@dataclass(frozen=True)
class ProcessSample:
    """One current resident-byte measurement for the exact process lifetime."""
    identity: ProcessIdentity
    rss_bytes: int


class DarwinProcessReader:
    """Read one declared PID with bounded native calls and identity rechecks."""

    def __init__(self):
        # TODO: Add a separately validated Linux kernel adapter before qualifying
        # Linux hardware; unsupported platforms must not use name/ps estimates.
        _require(sys.platform == "darwin", "this process adapter requires Darwin")
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pid_rusage.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        self.lib.proc_pid_rusage.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        self.lib.proc_pidpath.restype = ctypes.c_int

    def _call(self, pid: int, operation: str, invoke):
        before = darwin_absolute_time()
        ctypes.set_errno(0)
        result = invoke()
        error_number = ctypes.get_errno()
        after = darwin_absolute_time()
        missing = result < 0 if operation == "proc_pid_rusage" else result <= 0
        if missing and error_number == errno.ESRCH:
            raise NativeProcessUnavailable(pid, operation, error_number, before, after)
        return result, before, after

    def _identity(self, pid: int, *, include_exited: bool = False) -> _BsdInfo:
        info = _BsdInfo()
        result, _, _ = self._call(pid, "proc_pidinfo", lambda: self.lib.proc_pidinfo(
            pid, 3, int(include_exited), ctypes.byref(info), ctypes.sizeof(info)))
        _require(result == ctypes.sizeof(info) and info.pid == pid
                 and info.uid == os.geteuid() and info.ruid == os.getuid()
                 and info.start_sec > 0 and info.start_usec < 1_000_000,
                 "validator process identity is unavailable or foreign")
        return info

    def _usage(self, pid: int, *, include_exited: bool = False) -> _RusageV0:
        usage = _RusageV0()
        result, before, after = self._call(pid, "proc_pid_rusage", lambda:
            self.lib.proc_pid_rusage(pid, 0, ctypes.byref(usage)))
        _require(result == 0 and usage.start_abstime > 0,
                 "validator resident accounting is unavailable")
        if usage.exit_abstime > 0 and not include_exited:
            raise NativeProcessUnavailable(pid, "proc_pid_rusage_exited", 0, before, after)
        return usage

    def _path(self, pid: int) -> Path:
        path_buffer = ctypes.create_string_buffer(MAX_EXECUTABLE_PATH_BYTES)
        count, _, _ = self._call(pid, "proc_pidpath", lambda:
            self.lib.proc_pidpath(pid, path_buffer, len(path_buffer)))
        _require(0 < count < len(path_buffer) and path_buffer.raw[count] == 0,
                 "validator executable path is unavailable or truncated")
        return Path(os.fsdecode(path_buffer.raw[:count])).resolve(strict=True)

    def sample(self, pid: int, image: ExecutableImage) -> ProcessSample:
        """Reject exit, PID reuse, exec/image mismatch, or RSS outside exact range."""
        _require(type(pid) is int and 1 < pid <= (1 << 31) - 1, "invalid validator PID")
        image.validate()
        before = self._identity(pid)
        usage = self._usage(pid)
        observed_path = self._path(pid)
        after = self._identity(pid)
        key = lambda info: (info.pid, info.uid, info.ruid, info.start_sec, info.start_usec)
        _require(key(before) == key(after), "validator lifetime changed during observation")
        uuid = bytes(usage.uuid)
        _require(observed_path == image.path and uuid in image.uuids,
                 "running validator image differs from the pinned executable")
        _require(0 < usage.rss <= MAX_EXACT_INTEGER, "validator RSS is unavailable or outside exact range")
        image.validate()
        return ProcessSample(ProcessIdentity(pid, after.uid, after.start_sec, after.start_usec,
                                             usage.start_abstime, uuid.hex(), image.sha256), int(usage.rss))


class PinnedProcess:
    """Never silently replace a restarted validator with the current PID owner."""
    def __init__(self, peer_id: str, pid: int, image: ExecutableImage, reader: DarwinProcessReader):
        _require(isinstance(peer_id, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", peer_id) is not None,
                 "invalid public peer label")
        self.peer_id, self.pid, self.image, self.reader = peer_id, pid, image, reader
        self.identity = reader.sample(pid, image).identity

    def sample(self) -> ProcessSample:
        """Measure the original lifetime or fail explicitly."""
        observed = self.reader.sample(self.pid, self.image)
        _require(observed.identity == self.identity, "pinned validator restarted or changed image")
        return observed


def sample_peers(peers: tuple[PinnedProcess, ...]) -> tuple[ProcessSample, ...]:
    """Return every declared peer once, without a partial or saturating total."""
    _require(4 <= len(peers) <= MAX_PEERS, "resource scope requires 4..64 validator processes")
    _require(len({peer.peer_id for peer in peers}) == len(peers)
             and len({peer.pid for peer in peers}) == len(peers), "duplicate validator process or label")
    samples = tuple(peer.sample() for peer in peers)
    _require(sum(sample.rss_bytes for sample in samples) <= MAX_EXACT_INTEGER,
             "aggregate validator RSS exceeds exact range")
    return samples
