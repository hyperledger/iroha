"""Exact executable and process identity tests for the local resource adapter."""
from dataclasses import replace
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import stat
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("resource_process_under_test", ROOT / "scripts/nexus/resource_process.py")
process = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = process
SPEC.loader.exec_module(process)
UUID = bytes(range(1, 17))


@pytest.fixture(autouse=True)
def mocked_native_clock_on_other_hosts(monkeypatch):
    """Native-call fakes use a deterministic clock; actual Darwin keeps its clock."""
    if sys.platform != "darwin":
        monkeypatch.setattr(process, "darwin_absolute_time", lambda: 1)


def thin(uuid=UUID, order="<"):
    return struct.pack(order + "8I", 0xFEEDFACF, 0x100000C, 0, 2, 1, 24, 0, 0) + struct.pack(order + "II", 0x1B, 24) + uuid


def image_path(tmp_path, raw=None):
    raw = thin() if raw is None else raw
    path = tmp_path / "iroha3d"
    path.write_bytes(raw)
    path.chmod(0o700)
    return path, hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("order", ["<", ">"])
def test_exact_image_pin_and_close(tmp_path, order):
    path, digest = image_path(tmp_path, thin(order=order))
    with process.ExecutableImage(path, digest) as image:
        assert image.uuids == frozenset({UUID})
        assert image.sha256 == digest
        image.validate()
        fd = image.fd
    assert image.fd == -1
    with pytest.raises(OSError):
        os.fstat(fd)
    image.close()
    with pytest.raises(process.ProcessObservationError, match="closed"):
        image.validate()


def test_universal_image_pins_each_nonoverlapping_slice(tmp_path):
    second = bytes(reversed(UUID))
    raw = (struct.pack(">II", 0xCAFEBABE, 2)
           + struct.pack(">5I", 0x100000C, 0, 64, 56, 3)
           + struct.pack(">5I", 0x1000007, 0, 128, 56, 3))
    raw += bytes(64 - len(raw)) + thin() + bytes(8) + thin(second)
    path, digest = image_path(tmp_path, raw)
    with process.ExecutableImage(path, digest) as image:
        assert image.uuids == frozenset({UUID, second})


@pytest.mark.parametrize("mutation", ["empty", "short", "magic", "commands", "bytes", "size", "uuid_missing", "uuid_zero", "duplicate", "tail", "fat_count", "fat_overlap", "fat_alignment"])
def test_malformed_images_fail_before_pin(tmp_path, mutation):
    raw = bytearray(thin())
    if mutation == "empty": raw = bytearray()
    if mutation == "short": raw = raw[:12]
    if mutation == "magic": raw[:4] = b"ELF!"
    if mutation == "commands": struct.pack_into("<I", raw, 16, 65537)
    if mutation == "bytes": struct.pack_into("<I", raw, 20, process.MAX_LOAD_COMMAND_BYTES + 1)
    if mutation == "size": struct.pack_into("<I", raw, 36, 16)
    if mutation == "uuid_missing": struct.pack_into("<I", raw, 32, 0x10)
    if mutation == "uuid_zero": raw[-16:] = bytes(16)
    if mutation == "duplicate":
        raw.extend(raw[32:]); struct.pack_into("<II", raw, 16, 2, 48)
    if mutation == "tail":
        raw.extend(bytes(8)); struct.pack_into("<I", raw, 20, 32)
    if mutation == "fat_count": raw = bytearray(struct.pack(">II", 0xCAFEBABE, 33))
    if mutation in {"fat_overlap", "fat_alignment"}:
        raw = bytearray(struct.pack(">II", 0xCAFEBABE, 2)
                        + struct.pack(">5I", 0, 0, 64, 56, 3)
                        + struct.pack(">5I", 0, 0, 64, 56, 32 if mutation == "fat_alignment" else 3))
        raw.extend(bytes(64 - len(raw)) + thin())
    path, digest = image_path(tmp_path, raw)
    with pytest.raises(process.ProcessObservationError):
        process.ExecutableImage(path, digest)


@pytest.mark.parametrize("mutation", ["replace", "write", "symlink", "unlink"])
def test_pinned_descriptor_and_name_cannot_change(tmp_path, mutation):
    path, digest = image_path(tmp_path)
    with process.ExecutableImage(path, digest) as image:
        if mutation == "replace":
            alternate = tmp_path / "replacement"
            alternate.write_bytes(thin())
            alternate.replace(path)
        if mutation == "write": path.write_bytes(thin(bytes(reversed(UUID))))
        if mutation == "symlink":
            target = tmp_path / "same"
            path.rename(target)
            path.symlink_to(target)
        if mutation == "unlink": path.unlink()
        with pytest.raises((process.ProcessObservationError, FileNotFoundError)):
            image.validate()


@pytest.mark.parametrize("digest", ["0" * 64, "A" * 64, "0" * 63, "0" * 65])
def test_digest_must_match_pinned_image(tmp_path, digest):
    path, _ = image_path(tmp_path)
    with pytest.raises(process.ProcessObservationError):
        process.ExecutableImage(path, digest)


def identity(pid=123):
    return process.ProcessIdentity(pid, os.getuid(), 100, 5, 500, UUID.hex(), "1" * 64)


@pytest.mark.parametrize("field,value", [("pid", 124), ("uid", 99), ("start_seconds", 101), ("start_microseconds", 6), ("start_abstime", 501), ("image_uuid", "0" * 32), ("executable_sha256", "2" * 64)])
def test_lifetime_or_image_change_never_rebinds(field, value):
    baseline = identity()
    rows = iter([process.ProcessSample(baseline, 10), process.ProcessSample(replace(baseline, **{field: value}), 20)])
    reader = SimpleNamespace(sample=lambda *_: next(rows))
    pinned = process.PinnedProcess("validator-0", 123, None, reader)
    with pytest.raises(process.ProcessObservationError, match="restarted or changed"):
        pinned.sample()
    assert pinned.identity == baseline


def test_peer_scope_requires_every_unique_validator_and_checked_total():
    def peer(index, rss=100):
        return SimpleNamespace(peer_id=str(index), pid=index + 2, sample=lambda: process.ProcessSample(identity(index + 2), rss))
    peers = tuple(peer(i) for i in range(4))
    assert len(process.sample_peers(peers)) == 4
    assert sum(row.rss_bytes for row in process.sample_peers(peers)) == 400
    for invalid in [peers[:3], (peers[0],) * 4, tuple(peer(i) for i in range(65)), tuple(peer(i, process.MAX_EXACT_INTEGER) for i in range(4))]:
        with pytest.raises(process.ProcessObservationError):
            process.sample_peers(invalid)
    peers[3].sample = lambda: (_ for _ in ()).throw(process.ProcessObservationError("exited"))
    with pytest.raises(process.ProcessObservationError, match="exited"):
        process.sample_peers(peers)


def test_unsupported_platform_is_explicit(monkeypatch):
    monkeypatch.setattr(process.sys, "platform", "unsupported")
    with pytest.raises(process.ProcessObservationError, match="requires Darwin"):
        process.DarwinProcessReader()


@pytest.mark.parametrize("label", ["", "x" * 129, "validator/0", "validator\n0", None])
def test_peer_label_is_bounded_public_identity(label):
    reader = SimpleNamespace(sample=lambda *_: pytest.fail("invalid label reached process reader"))
    with pytest.raises(process.ProcessObservationError):
        process.PinnedProcess(label, 123, None, reader)


@pytest.mark.parametrize("failure", ["short", "pid", "uid", "ruid", "seconds", "microseconds"])
def test_native_identity_unavailable_or_foreign_is_rejected(failure):
    reader = process.DarwinProcessReader.__new__(process.DarwinProcessReader)
    def identity_info(_pid, _flavor, _argument, pointer, size):
        info = pointer._obj
        info.pid = 124 if failure == "pid" else 123
        info.uid = os.geteuid() + (1 if failure == "uid" else 0)
        info.ruid = os.getuid() + (1 if failure == "ruid" else 0)
        info.start_sec = 0 if failure == "seconds" else 50
        info.start_usec = 1_000_000 if failure == "microseconds" else 1
        return size - 1 if failure == "short" else size
    reader.lib = SimpleNamespace(proc_pidinfo=identity_info)
    with pytest.raises(process.ProcessObservationError):
        reader._identity(123)


@pytest.mark.skipif(sys.platform != "darwin", reason="actual Darwin kernel observation")
def test_actual_current_process_rss_and_loaded_uuid_are_bound():
    reader = process.DarwinProcessReader()
    # Homebrew's sys.executable is a launcher which execs a different image.
    # This native smoke pins the kernel-reported test image; real trials supply
    # their reviewed daemon artifact path and digest before launching validators.
    path_buffer = ctypes.create_string_buffer(4096)
    count = reader.lib.proc_pidpath(os.getpid(), path_buffer, len(path_buffer))
    assert 0 < count < len(path_buffer)
    path = Path(os.fsdecode(path_buffer.raw[:count])).resolve(strict=True)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with process.ExecutableImage(path, digest) as image:
        pinned = process.PinnedProcess("test-process", os.getpid(), image, reader)
        first = pinned.sample()
        second = pinned.sample()
        assert first.identity == second.identity == pinned.identity
        assert first.identity.pid == os.getpid()
        assert bytes.fromhex(first.identity.image_uuid) in image.uuids
        assert 0 < first.rss_bytes <= process.MAX_EXACT_INTEGER
        assert 0 < second.rss_bytes <= process.MAX_EXACT_INTEGER
    launcher = Path(sys.executable).resolve(strict=True)
    if launcher != path:
        with process.ExecutableImage(launcher, hashlib.sha256(launcher.read_bytes()).hexdigest()) as wrong_image:
            with pytest.raises(process.ProcessObservationError, match="differs from the pinned"):
                reader.sample(os.getpid(), wrong_image)


@pytest.mark.parametrize("failure", ["none", "pid_reuse", "uuid", "path", "exited", "zero_rss", "large_rss", "missing_usage", "truncated_path"])
def test_native_reader_rechecks_each_identity_and_memory_boundary(tmp_path, failure):
    path, digest = image_path(tmp_path)
    reader = process.DarwinProcessReader.__new__(process.DarwinProcessReader)
    before = SimpleNamespace(pid=123, uid=os.geteuid(), ruid=os.getuid(), start_sec=50, start_usec=1)
    after = SimpleNamespace(**vars(before))
    if failure == "pid_reuse": after.start_usec = 2
    identities = iter([before, after])
    reader._identity = lambda _: next(identities)

    def rusage(_pid, _version, pointer):
        usage = pointer._obj
        usage.uuid[:] = bytes(reversed(UUID)) if failure == "uuid" else UUID
        usage.rss = 0 if failure == "zero_rss" else process.MAX_EXACT_INTEGER + 1 if failure == "large_rss" else 4096
        usage.start_abstime = 4
        usage.exit_abstime = 1 if failure == "exited" else 0
        return -1 if failure == "missing_usage" else 0

    def pidpath(_pid, buffer, _size):
        target = tmp_path if failure == "path" else path
        data = os.fsencode(target)
        buffer.value = data
        return len(buffer) if failure == "truncated_path" else len(data)

    reader.lib = SimpleNamespace(proc_pid_rusage=rusage, proc_pidpath=pidpath)
    with process.ExecutableImage(path, digest) as image:
        if failure == "none":
            sample = reader.sample(123, image)
            assert sample.rss_bytes == 4096
            assert sample.identity.start_microseconds == 1
        else:
            with pytest.raises(process.ProcessObservationError):
                reader.sample(123, image)


@pytest.mark.parametrize("mode", [0o000, 0o600, 0o644, 0o011, 0o720, 0o702,
                                  0o777, 0o1700, 0o2700, 0o4700])
def test_unreviewed_executable_permissions_rejected_before_content_read(tmp_path, monkeypatch, mode):
    path, digest = image_path(tmp_path)
    # Darwin clears setgid when the temporary directory supplies a group the
    # owner does not hold. Bind a held group before requesting the invalid mode.
    os.chown(path, -1, os.getegid())
    path.chmod(mode)
    assert stat.S_IMODE(path.stat().st_mode) == mode
    monkeypatch.setattr(process.os, "pread", lambda *_: pytest.fail("invalid mode reached content read"))
    try:
        with pytest.raises((process.ProcessObservationError, PermissionError)):
            process.ExecutableImage(path, digest)
    finally:
        path.chmod(0o700)


@pytest.mark.parametrize("mode", [0o500, 0o700, 0o750, 0o755])
def test_owned_readable_executable_modes_are_explicitly_admitted(tmp_path, mode):
    path, digest = image_path(tmp_path)
    path.chmod(mode)
    with process.ExecutableImage(path, digest) as image:
        assert image.path == path
        assert image.sha256 == digest
        assert image.uuids == frozenset({UUID})
        image.validate()


@pytest.mark.parametrize("kind", ["foreign_uid", "hardlink", "directory", "fifo"])
def test_nonowned_aliased_or_nonregular_images_fail_before_read(tmp_path, monkeypatch, kind):
    path, digest = image_path(tmp_path)
    if kind == "foreign_uid":
        uid = os.geteuid()
        monkeypatch.setattr(process.os, "geteuid", lambda: uid + 1)
    elif kind == "hardlink":
        os.link(path, tmp_path / "alias")
        assert path.stat().st_nlink == 2
    else:
        path.unlink()
        if kind == "directory":
            path.mkdir(mode=0o700)
        else:
            os.mkfifo(path, 0o700)
    monkeypatch.setattr(process.os, "pread", lambda *_: pytest.fail("invalid file reached content read"))
    with pytest.raises(process.ProcessObservationError, match="owned single-link executable"):
        process.ExecutableImage(path, digest)


@pytest.mark.parametrize("kind", ["leaf", "parent", "grandparent"])
def test_original_symlink_is_never_resolved_during_admission(tmp_path, kind):
    real = tmp_path / "real"
    real.mkdir()
    nested = real / "nested"
    nested.mkdir()
    path, digest = image_path(nested)
    if kind == "leaf":
        selected = nested / "alias"
        selected.symlink_to(path)
    elif kind == "parent":
        selected_parent = real / "alias"
        selected_parent.symlink_to(nested, target_is_directory=True)
        selected = selected_parent / path.name
    else:
        selected_parent = tmp_path / "alias"
        selected_parent.symlink_to(real, target_is_directory=True)
        selected = selected_parent / "nested" / path.name
    assert selected.read_bytes() == path.read_bytes()
    with pytest.raises(OSError):
        process.ExecutableImage(selected, digest)


@pytest.mark.parametrize("kind", ["relative", "parent_component", "root", "double_root", "bytes", "components"])
def test_lexical_path_bounds_fail_before_any_open(tmp_path, monkeypatch, kind):
    path, digest = image_path(tmp_path)
    selected = {
        "relative": Path("iroha3d"),
        "parent_component": tmp_path / "unused" / ".." / path.name,
        "root": Path("/"),
        "double_root": Path("//iroha3d"),
        "bytes": Path("/" + "x" * process.MAX_EXECUTABLE_PATH_BYTES),
        "components": Path("/" + "/".join(["x"] * (process.MAX_EXECUTABLE_PATH_COMPONENTS + 1))),
    }[kind]
    monkeypatch.setattr(process.os, "open", lambda *_a, **_k: pytest.fail("invalid path reached open"))
    with pytest.raises(process.ProcessObservationError, match="bounded absolute lexical"):
        process.ExecutableImage(selected, digest)


@pytest.mark.parametrize("kind", [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 2**32 - 1])
@pytest.mark.parametrize("order", ["<", ">"])
def test_every_thin_slice_requires_mh_execute(tmp_path, kind, order):
    raw = bytearray(thin(order=order))
    struct.pack_into(order + "I", raw, 12, kind)
    path, digest = image_path(tmp_path, raw)
    with pytest.raises(process.ProcessObservationError, match="MH_EXECUTE"):
        process.ExecutableImage(path, digest)


@pytest.mark.parametrize("bad_slice", [0, 1])
def test_universal_image_cannot_hide_a_library_slice(tmp_path, bad_slice):
    slices = [bytearray(thin()), bytearray(thin(bytes(reversed(UUID))))]
    struct.pack_into("<I", slices[bad_slice], 12, 6)
    raw = (struct.pack(">II", 0xCAFEBABE, 2)
           + struct.pack(">5I", 0x100000C, 0, 64, 56, 3)
           + struct.pack(">5I", 0x1000007, 0, 128, 56, 3))
    raw += bytes(64 - len(raw)) + slices[0] + bytes(8) + slices[1]
    path, digest = image_path(tmp_path, raw)
    with pytest.raises(process.ProcessObservationError, match="MH_EXECUTE"):
        process.ExecutableImage(path, digest)


@pytest.mark.parametrize("level", ["parent", "grandparent"])
def test_renamed_original_ancestor_cannot_be_replaced_with_a_symlink(tmp_path, level):
    grandparent = tmp_path / "original"
    grandparent.mkdir()
    parent = grandparent / "nested"
    parent.mkdir()
    path, digest = image_path(parent)
    selected = parent if level == "parent" else grandparent
    moved = tmp_path / "moved"
    with process.ExecutableImage(path, digest) as image:
        old_leaf = process._file_identity(os.fstat(image.fd))
        selected.rename(moved)
        selected.symlink_to(moved, target_is_directory=True)
        assert process._file_identity(os.fstat(image.fd)) == old_leaf
        assert path.read_bytes() == thin()
        with pytest.raises(process.ProcessObservationError, match="ancestor changed"):
            image.validate()


@pytest.mark.parametrize("kind", ["fresh_directory", "mode", "removed"])
def test_original_ancestor_identity_is_retained(tmp_path, kind):
    parent = tmp_path / "original"
    parent.mkdir(mode=0o700)
    path, digest = image_path(parent)
    with process.ExecutableImage(path, digest) as image:
        if kind == "mode":
            parent.chmod(0o755)
        else:
            parent.rename(tmp_path / "moved")
            if kind == "fresh_directory":
                parent.mkdir(mode=0o700)
                replacement, replacement_digest = image_path(parent)
                assert replacement_digest == digest
                assert replacement.stat().st_ino != os.fstat(image.fd).st_ino
        with pytest.raises((process.ProcessObservationError, FileNotFoundError)):
            image.validate()


def test_unrelated_directory_children_do_not_change_executable_namespace(tmp_path):
    path, digest = image_path(tmp_path)
    with process.ExecutableImage(path, digest) as image:
        (tmp_path / "log").write_bytes(b"unrelated append-only output")
        (tmp_path / "state").mkdir()
        image.validate()
        (tmp_path / "log").unlink()
        (tmp_path / "state").rmdir()
        image.validate()


@pytest.mark.parametrize("kind", ["hardlink", "mode", "same_uuid_content", "same_bytes_inode"])
def test_postadmission_image_changes_never_repin(tmp_path, kind):
    path, digest = image_path(tmp_path, thin() + b"original")
    with process.ExecutableImage(path, digest) as image:
        original = image.identity
        if kind == "hardlink":
            os.link(path, tmp_path / "alias")
        elif kind == "mode":
            path.chmod(0o755)
        elif kind == "same_uuid_content":
            path.write_bytes(thin() + b"modified")
            assert path.stat().st_size == original[-3]
        else:
            replacement = tmp_path / "replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o700)
            replacement.replace(path)
        with pytest.raises(process.ProcessObservationError, match="file changed"):
            image.validate()
        assert image.identity == original
        assert image.sha256 == digest


def test_matching_uuid_is_not_a_substitute_for_exact_content_hash(tmp_path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first, first_digest = image_path(first_dir, thin() + b"original")
    second, second_digest = image_path(second_dir, thin() + b"modified")
    assert first_digest != second_digest
    with process.ExecutableImage(first, first_digest) as a, process.ExecutableImage(second, second_digest) as b:
        assert a.uuids == b.uuids == frozenset({UUID})
        assert a.sha256 != b.sha256
    with pytest.raises(process.ProcessObservationError, match="pinned digest"):
        process.ExecutableImage(second, first_digest)


def test_context_closes_leaf_and_every_retained_ancestor(tmp_path):
    path, digest = image_path(tmp_path)
    with process.ExecutableImage(path, digest) as image:
        descriptors = [image.fd, *(item[0] for item in image._chain)]
        assert len(descriptors) == len(path.parts)
        assert len(set(descriptors)) == len(descriptors)
    assert image.fd == -1
    assert image._chain == []
    image.close()
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("failure", ["ancestor_fstat", "leaf_fstat", "read", "parse", "validate", "panic"])
def test_failed_admission_closes_every_opened_descriptor(tmp_path, monkeypatch, failure):
    path, digest = image_path(tmp_path)
    opened = []
    real_open, real_fstat, real_pread = os.open, os.fstat, os.pread
    def opening(name, flags, **kwargs):
        descriptor = real_open(name, flags, **kwargs)
        opened.append((descriptor, name))
        return descriptor
    def checking(descriptor):
        name = next((name for fd, name in opened if fd == descriptor), None)
        if ((failure == "ancestor_fstat" and name == tmp_path.name)
                or (failure == "leaf_fstat" and name == path.name)):
            raise OSError("injected fstat failure")
        return real_fstat(descriptor)
    def reading(*args):
        if failure == "read":
            raise OSError("injected reader failure")
        if failure == "panic":
            raise KeyboardInterrupt("injected unwind")
        return real_pread(*args)
    monkeypatch.setattr(process.os, "open", opening)
    monkeypatch.setattr(process.os, "fstat", checking)
    monkeypatch.setattr(process.os, "pread", reading)
    if failure == "parse":
        monkeypatch.setattr(process, "_image_uuids", lambda *_: (_ for _ in ()).throw(ValueError("injected parse failure")))
    if failure == "validate":
        monkeypatch.setattr(process.ExecutableImage, "validate", lambda *_: (_ for _ in ()).throw(ValueError("injected final check failure")))
    with pytest.raises((OSError, ValueError, KeyboardInterrupt)):
        process.ExecutableImage(path, digest)
    assert opened
    for descriptor, _ in opened:
        with pytest.raises(OSError):
            real_fstat(descriptor)


@pytest.mark.parametrize("bound", ["bytes", "components"])
def test_exact_lexical_path_bound_is_admitted_one_less_is_not(tmp_path, monkeypatch, bound):
    path, digest = image_path(tmp_path)
    name, exact = ("MAX_EXECUTABLE_PATH_BYTES", len(os.fsencode(path))) if bound == "bytes" else (
        "MAX_EXECUTABLE_PATH_COMPONENTS", len(path.parts) - 1)
    monkeypatch.setattr(process, name, exact)
    with process.ExecutableImage(path, digest) as image:
        image.validate()
    monkeypatch.setattr(process, name, exact - 1)
    monkeypatch.setattr(process.os, "open", lambda *_a, **_k: pytest.fail("over-bound path reached open"))
    with pytest.raises(process.ProcessObservationError, match="bounded absolute lexical"):
        process.ExecutableImage(path, digest)


@pytest.mark.parametrize("phase", ["hash", "uuid"])
def test_ancestor_replacement_during_admission_is_rejected_and_closes_owner(tmp_path, monkeypatch, phase):
    parent = tmp_path / "original"
    parent.mkdir()
    path, digest = image_path(parent)
    moved = tmp_path / "moved"
    def mutation():
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        assert path.read_bytes() == thin()
    if phase == "hash":
        original_read = process._pread
        changed = False
        def reading(*args):
            nonlocal changed
            data = original_read(*args)
            if not changed:
                changed = True
                mutation()
            return data
        monkeypatch.setattr(process, "_pread", reading)
    else:
        original_parse = process._image_uuids
        def parsing(*args):
            mutation()
            return original_parse(*args)
        monkeypatch.setattr(process, "_image_uuids", parsing)
    image = process.ExecutableImage.__new__(process.ExecutableImage)
    with pytest.raises(process.ProcessObservationError, match="ancestor changed"):
        image.__init__(path, digest)
    assert image.fd == -1
    assert image._chain == []


def test_leaf_check_cannot_hide_an_ancestor_replacement_before_return(tmp_path, monkeypatch):
    parent = tmp_path / "original"
    parent.mkdir()
    path, digest = image_path(parent)
    with process.ExecutableImage(path, digest) as image:
        original_stat = os.stat
        changed = False
        def checking(name, *args, **kwargs):
            nonlocal changed
            value = original_stat(name, *args, **kwargs)
            if name == path.name and not changed:
                changed = True
                parent.rename(tmp_path / "moved")
                parent.symlink_to(tmp_path / "moved", target_is_directory=True)
            return value
        monkeypatch.setattr(process.os, "stat", checking)
        with pytest.raises(process.ProcessObservationError, match="ancestor changed"):
            image.validate()
        assert changed


@pytest.mark.parametrize("binding", ["path", "fd", "identity", "sha256", "uuids"])
@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("operation", ["assign", "delete"])
def test_admitted_image_bindings_are_read_only_even_after_close(tmp_path, binding, closed, operation):
    original_dir, replacement_dir = tmp_path / "original", tmp_path / "replacement"
    original_dir.mkdir()
    replacement_dir.mkdir()
    path, digest = image_path(original_dir, thin() + b"admitted bytes")
    replacement_path, replacement_digest = image_path(
        replacement_dir, thin(bytes(reversed(UUID))) + b"different bytes")
    assert path.name == replacement_path.name
    assert digest != replacement_digest
    with process.ExecutableImage(path, digest) as admitted, process.ExecutableImage(
            replacement_path, replacement_digest) as replacement:
        original_descriptors = [admitted.fd, *(row[0] for row in admitted._chain)]
        if closed:
            admitted.close()
        snapshot = tuple(getattr(admitted, field) for field in ("path", "fd", "identity", "sha256", "uuids"))
        with pytest.raises(AttributeError):
            if operation == "assign":
                setattr(admitted, binding, getattr(replacement, binding))
            else:
                delattr(admitted, binding)
        assert tuple(getattr(admitted, field) for field in ("path", "fd", "identity", "sha256", "uuids")) == snapshot
        assert admitted.path == path
        assert admitted.sha256 == digest
        assert admitted.uuids == frozenset({UUID})
        assert not hasattr(admitted, "__dict__")
        if closed:
            with pytest.raises(process.ProcessObservationError, match="closed"):
                admitted.validate()
        else:
            admitted.validate()
            assert process._file_identity(os.fstat(admitted.fd)) == admitted.identity
        replacement.validate()
    assert admitted.fd == -1
    assert admitted._chain == []
    admitted.close()
    for descriptor in original_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("same_uuid", [False, True])
def test_same_name_different_image_cannot_retarget_existing_reader_binding(tmp_path, same_uuid):
    original_dir, alternate_dir = tmp_path / "original", tmp_path / "alternate"
    original_dir.mkdir()
    alternate_dir.mkdir()
    path, digest = image_path(original_dir, thin() + b"original")
    other_uuid = UUID if same_uuid else bytes(reversed(UUID))
    alternate, other_digest = image_path(alternate_dir, thin(other_uuid) + b"modified")
    assert path.name == alternate.name and digest != other_digest
    observed_path, observed_uuid = path, UUID
    reader = process.DarwinProcessReader.__new__(process.DarwinProcessReader)
    reader._identity = lambda _: SimpleNamespace(
        pid=123, uid=os.geteuid(), ruid=os.getuid(), start_sec=50, start_usec=1)
    def usage(_pid, _version, pointer):
        pointer._obj.uuid[:] = observed_uuid
        pointer._obj.rss = 4096
        pointer._obj.start_abstime = 4
        pointer._obj.exit_abstime = 0
        return 0
    def pidpath(_pid, buffer, _size):
        data = os.fsencode(observed_path)
        buffer.value = data
        return len(data)
    reader.lib = SimpleNamespace(proc_pid_rusage=usage, proc_pidpath=pidpath)
    with process.ExecutableImage(path, digest) as image, process.ExecutableImage(alternate, other_digest) as other:
        pinned = process.PinnedProcess("peer3", 123, image, reader)
        original = pinned.identity
        for name in ("path", "fd", "identity", "sha256", "uuids"):
            with pytest.raises(AttributeError):
                setattr(image, name, getattr(other, name))
        assert pinned.sample().identity == original
        # Simulate the kernel reporting the other same-basename executable.
        # The old path-retarget defect could mask this mismatch with the same UUID.
        observed_path, observed_uuid = alternate, other_uuid
        with pytest.raises(process.ProcessObservationError, match="differs from the pinned"):
            pinned.sample()
        assert pinned.identity == original
        assert image.path == path and image.sha256 == digest
        image.validate()
        observed_path, observed_uuid = path, UUID
        assert pinned.sample().identity == original


@pytest.mark.parametrize("closed", [False, True])
def test_existing_image_owner_cannot_be_reinitialized_or_reopened(tmp_path, monkeypatch, closed):
    original_dir, alternate_dir = tmp_path / "original", tmp_path / "alternate"
    original_dir.mkdir()
    alternate_dir.mkdir()
    path, digest = image_path(original_dir, thin() + b"original")
    alternate, other_digest = image_path(alternate_dir, thin() + b"modified")
    with process.ExecutableImage(path, digest) as image:
        if closed:
            image.close()
        before = (image.path, image.fd, image.identity, image.sha256, image.uuids, tuple(image._chain))
        monkeypatch.setattr(process.os, "open", lambda *_a, **_k: pytest.fail("readmission reached open"))
        with pytest.raises(process.ProcessObservationError, match="cannot be readmitted"):
            image.__init__(alternate, other_digest)
        assert (image.path, image.fd, image.identity, image.sha256, image.uuids, tuple(image._chain)) == before
        if not closed:
            image.validate()
    assert image.fd == -1
    assert image._chain == []


def test_failed_image_admission_closes_and_cannot_readmit_same_owner(tmp_path, monkeypatch):
    path, digest = image_path(tmp_path)
    opened = []
    real_open = os.open
    def opening(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor
    monkeypatch.setattr(process.os, "open", opening)
    image = process.ExecutableImage.__new__(process.ExecutableImage)
    with pytest.raises(process.ProcessObservationError, match="pinned digest"):
        image.__init__(path, "0" * 64)
    assert opened and image.fd == -1 and image._chain == []
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    monkeypatch.setattr(process.os, "open", lambda *_a, **_k: pytest.fail("failed owner reached readmission"))
    with pytest.raises(process.ProcessObservationError, match="cannot be readmitted"):
        image.__init__(path, digest)
    with pytest.raises(AttributeError):
        image.fd = opened[-1]
    image.close()
    assert image.fd == -1
