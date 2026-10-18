#!/usr/bin/env python3
"""Sign aggregate release manifests and verify them with ``iroha``.

The production signing command never accepts a private key. It invokes a
reviewed external signer with two positional arguments:

    external-signer MANIFEST_PATH NEW_RAW_SIGNATURE_PATH

The signer must create exactly one raw 64-byte Ed25519 signature. The wrapper
executes an owner-private snapshot of the inspected signer against an
owner-private snapshot of the canonical manifest, so path substitution cannot
select a different executable or signing payload. Verification is delegated to
the canonical native contract:

    iroha app sorafs toolkit release-manifest \
      --manifest MANIFEST_PATH \
      --public-key RAW_32_BYTE_PUBLIC_KEY_PATH \
      --public-key-fingerprint REVIEWED_SHA256 \
      --signature RAW_64_BYTE_SIGNATURE_PATH

The native verifier must be supplied by direct path together with an
independently reviewed SHA-256 digest. This wrapper snapshots the exact
executable into an owner-private directory, invokes that snapshot, and rejects
path, permission, hard-link, digest, or identity drift. The verifier receives
owner-private snapshots of the inspected manifest, key, and signature under a
minimal environment, never their mutable source paths.
Executable snapshots are streamed under a fixed 1 GiB ceiling, including files
that grow while being copied; the trusted digest does not replace this bound.

Release output directories remain descriptor-pinned across external execution.
Publication and rollback operate relative to those directories, and substituted
parents or changed output inodes abort the complete output transaction.
Hosts without descriptor-relative, no-follow publication support fail before
the external signer or verifier runs; there is no pathname-based fallback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
ED25519_FIELD_MODULUS = (1 << 255) - 19
ED25519_SCALAR_ORDER = (1 << 252) + 27742317777372353535851937790883648493
MAX_MANIFEST_SIZE = 1024 * 1024
MAX_EXECUTABLE_SIZE = 1024 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
NATIVE_VERIFIER_PROTOCOL = "iroha-toolkit-release-manifest-v1"
EXTERNAL_TOOL_UID_ENV = "IROHA_TAIRA_EXTERNAL_TOOL_UID"
EXTERNAL_TOOL_GID_ENV = "IROHA_TAIRA_EXTERNAL_TOOL_GID"
RELEASE_OUTPUT_DIR_FD_SUPPORTED = all(
    operation in os.supports_dir_fd for operation in (os.open, os.stat, os.unlink)
)


class ReleaseManifestSignatureError(RuntimeError):
    """Raised when aggregate release-manifest signing or verification fails."""


FileIdentity = Tuple[int, int, int, int, int, int]


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _identity(metadata: os.stat_result) -> FileIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _reject_symlink_chain(
    path: Path,
    label: str,
    *,
    leaf_may_be_missing: bool = False,
) -> None:
    components = list(reversed(path.parents)) + [path]
    for index, component in enumerate(components):
        try:
            metadata = component.lstat()
        except FileNotFoundError as exc:
            if leaf_may_be_missing and index == len(components) - 1:
                return
            raise ReleaseManifestSignatureError(
                f"{label} path component is missing: {component}"
            ) from exc
        except OSError as exc:
            raise ReleaseManifestSignatureError(
                f"cannot inspect {label} path component {component}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseManifestSignatureError(
                f"{label} must not contain a symlink path component: {component}"
            )


def _inspect_regular(
    path: Path,
    label: str,
    *,
    executable: bool = False,
) -> os.stat_result:
    _reject_symlink_chain(path, label)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseManifestSignatureError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseManifestSignatureError(f"{label} must be a regular file")
    if metadata.st_nlink != 1:
        raise ReleaseManifestSignatureError(f"{label} must have exactly one hard link")
    if metadata.st_mode & 0o022:
        raise ReleaseManifestSignatureError(
            f"{label} must not be group- or world-writable"
        )
    allowed_owners = {os.getuid(), 0} if hasattr(os, "getuid") else {metadata.st_uid}
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raw_external_uid = os.environ.get(EXTERNAL_TOOL_UID_ENV)
        raw_external_gid = os.environ.get(EXTERNAL_TOOL_GID_ENV)
        if (
            raw_external_uid is not None
            and raw_external_gid is not None
            and raw_external_uid.isascii()
            and raw_external_uid.isdecimal()
            and raw_external_gid.isascii()
            and raw_external_gid.isdecimal()
            and int(raw_external_uid) > 0
            and int(raw_external_gid) > 0
        ):
            allowed_owners.add(int(raw_external_uid))
    if metadata.st_uid not in allowed_owners:
        raise ReleaseManifestSignatureError(
            f"{label} must be owned by the invoking user or root"
        )
    if executable and not os.access(path, os.X_OK):
        raise ReleaseManifestSignatureError(f"{label} must be executable")
    return metadata


def _stable_read(
    path: Path,
    label: str,
    *,
    exact_size: Optional[int] = None,
    max_size: Optional[int] = None,
) -> Tuple[bytes, FileIdentity]:
    before = _inspect_regular(path, label)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseManifestSignatureError(f"cannot open {label}: {exc}") from exc

    opened: Optional[os.stat_result] = None
    closed: Optional[os.stat_result] = None
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ReleaseManifestSignatureError(f"{label} changed while it was opened")
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if exact_size is not None and total > exact_size:
                raise ReleaseManifestSignatureError(
                    f"{label} must contain exactly {exact_size} raw bytes"
                )
            if max_size is not None and total > max_size:
                raise ReleaseManifestSignatureError(
                    f"{label} exceeds the {max_size}-byte size limit"
                )
        closed = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    assert opened is not None
    assert closed is not None
    opened_identity = _identity(opened)
    if opened_identity != _identity(closed):
        raise ReleaseManifestSignatureError(f"{label} changed while it was read")
    payload = b"".join(chunks)
    if exact_size is not None and len(payload) != exact_size:
        raise ReleaseManifestSignatureError(
            f"{label} must contain exactly {exact_size} raw bytes"
        )
    return payload, opened_identity


def _assert_unchanged(
    path: Path,
    label: str,
    expected_payload: bytes,
    expected_identity: FileIdentity,
    *,
    exact_size: Optional[int] = None,
    max_size: Optional[int] = None,
) -> None:
    payload, identity = _stable_read(
        path,
        label,
        exact_size=exact_size,
        max_size=max_size,
    )
    if payload != expected_payload or identity != expected_identity:
        raise ReleaseManifestSignatureError(f"{label} changed during verification")


def _stable_digest(
    path: Path,
    label: str,
    *,
    executable: bool = False,
) -> Tuple[str, FileIdentity]:
    before = _inspect_regular(path, label, executable=executable)
    if executable and (before.st_size <= 0 or before.st_size > MAX_EXECUTABLE_SIZE):
        raise ReleaseManifestSignatureError(f"{label} exceeds the executable byte bound")
    # Stable hashing cannot legitimately consume more bytes than the inspected
    # immutable file. Bound rechecks too, including growth after native execution.
    maximum = before.st_size
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseManifestSignatureError(f"cannot open {label}: {exc}") from exc

    digest = hashlib.sha256()
    opened: Optional[os.stat_result] = None
    closed: Optional[os.stat_result] = None
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ReleaseManifestSignatureError(f"{label} changed while it was opened")
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - consumed))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ReleaseManifestSignatureError(f"{label} grew beyond its inspected byte bound")
            digest.update(chunk)
        closed = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    assert opened is not None
    assert closed is not None
    opened_identity = _identity(opened)
    if opened_identity != _identity(closed):
        raise ReleaseManifestSignatureError(f"{label} changed while it was hashed")
    return digest.hexdigest(), opened_identity


def _assert_digest_unchanged(
    path: Path,
    label: str,
    expected_digest: str,
    expected_identity: FileIdentity,
    *,
    executable: bool = False,
) -> None:
    digest, identity = _stable_digest(path, label, executable=executable)
    if digest != expected_digest or identity != expected_identity:
        raise ReleaseManifestSignatureError(f"{label} changed during execution")


def _validate_sha256(value: str, label: str) -> None:
    if SHA256_RE.fullmatch(value) is None:
        raise ReleaseManifestSignatureError(
            f"{label} must be exactly 64 lowercase hexadecimal characters"
        )


def _validate_ed25519_public_key_encoding(raw_public_key: bytes) -> None:
    """Reject encodings that cannot be canonical compressed Edwards points."""

    if len(raw_public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise ReleaseManifestSignatureError(
            "Ed25519 public key must contain exactly 32 raw bytes"
        )
    if not any(raw_public_key):
        raise ReleaseManifestSignatureError("Ed25519 public key must not be all zero")
    encoded_y = bytearray(raw_public_key)
    encoded_y[-1] &= 0x7F
    if int.from_bytes(encoded_y, "little") >= ED25519_FIELD_MODULUS:
        raise ReleaseManifestSignatureError(
            "Ed25519 public key has a non-canonical point encoding"
        )


def _validate_ed25519_signature_encoding(signature: bytes, label: str) -> None:
    """Reject malformed Ed25519 encodings before invoking the native verifier."""

    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise ReleaseManifestSignatureError(
            f"{label} must contain exactly {ED25519_SIGNATURE_SIZE} raw bytes"
        )
    if not any(signature):
        raise ReleaseManifestSignatureError(f"{label} must not be all zero")

    encoded_r = bytearray(signature[:ED25519_PUBLIC_KEY_SIZE])
    encoded_r[-1] &= 0x7F
    if int.from_bytes(encoded_r, "little") >= ED25519_FIELD_MODULUS:
        raise ReleaseManifestSignatureError(
            f"{label} has a non-canonical Ed25519 R encoding"
        )
    scalar = int.from_bytes(signature[ED25519_PUBLIC_KEY_SIZE:], "little")
    if scalar >= ED25519_SCALAR_ORDER:
        raise ReleaseManifestSignatureError(
            f"{label} has a non-canonical Ed25519 scalar"
        )


def _validate_canonical_manifest(manifest_payload: bytes) -> None:
    def reject_non_finite(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    try:
        manifest = json.loads(
            manifest_payload,
            parse_constant=reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReleaseManifestSignatureError(
            f"aggregate release manifest is not valid strict JSON: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise ReleaseManifestSignatureError(
            "aggregate release manifest root must be an object"
        )
    canonical = (
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    if manifest_payload != canonical:
        raise ReleaseManifestSignatureError(
            "aggregate release manifest is not canonical deterministic JSON"
        )


def _require_new_output(path: Path, label: str) -> None:
    _reject_symlink_chain(path.parent, f"{label} parent")
    if not path.parent.is_dir():
        raise ReleaseManifestSignatureError(f"{label} parent must be a directory")
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReleaseManifestSignatureError(f"cannot inspect {label}: {exc}") from exc
    raise ReleaseManifestSignatureError(f"{label} already exists")


def _install_exclusive(
    path: Path,
    payload: bytes,
    label: str,
    *,
    mode: int = 0o644,
) -> FileIdentity:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ReleaseManifestSignatureError(f"cannot create {label}: {exc}") from exc
    installed: Optional[os.stat_result] = None
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReleaseManifestSignatureError(
                    f"short write while creating {label}"
                )
            view = view[written:]
        os.fsync(descriptor)
        installed = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    assert installed is not None
    return _identity(installed)


def _open_release_output_parent(
    path: Path,
) -> tuple[int, tuple[tuple[int, int], ...], tuple[int, ...]]:
    """Open an output parent without following any component and bind its lineage."""

    if (
        not RELEASE_OUTPUT_DIR_FD_SUPPORTED
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise ReleaseManifestSignatureError(
            "descriptor-anchored release output publication is unavailable"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    lineage = []
    try:
        descriptor = os.open(path.anchor, flags)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        lineage.append((metadata.st_dev, metadata.st_ino))
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            descriptors.append(child)
            descriptor = child
            metadata = os.fstat(descriptor)
            lineage.append((metadata.st_dev, metadata.st_ino))
        return descriptor, tuple(lineage), tuple(descriptors)
    except BaseException as exc:
        # A failed close may already have released its numeric descriptor. Drain
        # every other acquired handle once, never retry, and retain both failures.
        cleanup_errors = []
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if isinstance(exc, (OSError, NotImplementedError)):
            message = "release output parent directory could not be opened without links"
            if cleanup_errors:
                message += f"; {len(cleanup_errors)} descriptor cleanup attempt(s) failed"
            failure = ReleaseManifestSignatureError(message)
            failure.cleanup_errors = tuple(cleanup_errors)
            raise failure from exc
        if cleanup_errors:
            # Preserve control-flow/unexpected exception identity and its existing
            # cause/context on Python 3.10, while retaining cleanup diagnostics.
            exc.cleanup_errors = tuple(cleanup_errors)
        raise


class _ReleaseOutputTransaction:
    """Retain output authority until commit or a terminal, fully attempted rollback.

    Cleanup diagnostics are immutable ``transaction_cleanup_errors`` tuples on
    the original exception. A cleanup-only failure raises the same release error
    type, with ``outputs_retained`` indicating a validated publication whose
    descriptor cleanup failed; that failure never claims rollback succeeded.
    """

    def __init__(self, outputs: list[tuple[Path, str]]) -> None:
        self.outputs = dict(outputs)
        self.parents: dict[
            Path, tuple[int, tuple[tuple[int, int], ...], tuple[int, ...]]
        ] = {}
        # None records ownership before the first fstat can fail. Only the held
        # descriptor may later supply that missing rollback inode identity.
        self.created: list[tuple[Path, int, Optional[FileIdentity]]] = []
        self._state = "new"
        self._active = False
        self._failure: Optional[BaseException] = None
        self._cleanup_reentry: Optional[BaseException] = None

    def _refuse(self, message: str) -> None:
        failure = ReleaseManifestSignatureError(message)
        if self._active and self._state == "closed" and self._cleanup_reentry is None:
            self._cleanup_reentry = failure
        if self._failure is None and self._state != "closed":
            self._failure = failure
        raise failure

    def _healthy(self) -> None:
        if self._failure is not None:
            raise ReleaseManifestSignatureError(
                "release output transaction was invalidated by an earlier failure"
            ) from self._failure

    def _operate(self, action):
        if self._active:
            self._refuse("release output transaction activity is reentrant")
        if self._state != "open":
            self._refuse("release output transaction is not open")
        self._healthy()
        self._active = True
        try:
            result = action()
            self._healthy()
            return result
        except BaseException as exc:
            if self._failure is None:
                self._failure = exc
            raise
        finally:
            self._active = False

    @staticmethod
    def _attach_cleanup(exception: BaseException, errors: tuple[BaseException, ...]) -> None:
        if errors:
            previous = getattr(exception, "transaction_cleanup_errors", ())
            exception.transaction_cleanup_errors = (*previous, *errors)

    @staticmethod
    def _close_descriptors(descriptors) -> tuple[BaseException, ...]:
        errors = []
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as exc:
                errors.append(exc)
        return tuple(errors)

    @classmethod
    def _raise_cleanup(cls, errors: tuple[BaseException, ...], *, outputs_retained=False) -> None:
        label = "validated outputs retained; " if outputs_retained else ""
        failure = ReleaseManifestSignatureError(
            f"release output transaction {label}cleanup failed; {len(errors)} operation(s) failed"
        )
        cls._attach_cleanup(failure, errors)
        failure.outputs_retained = outputs_retained
        raise failure from errors[0]

    def __enter__(self):
        if self._active or self._state != "new" or self._failure is not None:
            self._refuse("release output transaction cannot be entered again")
        self._state = "open"
        try:
            self._operate(self._acquire)
        except BaseException as exc:
            self._attach_cleanup(exc, self._finish(rollback=True))
            raise
        return self

    def _acquire(self) -> None:
        for path, label in self.outputs.items():
            if path.parent not in self.parents:
                acquired = _open_release_output_parent(path.parent)
                try:
                    self.parents[path.parent] = acquired
                except BaseException as exc:
                    # Assignment may publish before an interruption is raised.
                    # The exact retained tuple then belongs only to _finish;
                    # otherwise this local owner must drain its descriptors.
                    if dict.get(self.parents, path.parent) is not acquired:
                        self._attach_cleanup(exc, self._close_descriptors(acquired[2]))
                    raise
            self._healthy()
            _require_new_output(path, label)
        self._assert_unchanged()

    def assert_unchanged(self) -> None:
        """Reject path-lineage replacement and changes to any installed output."""
        self._operate(self._assert_unchanged)

    def _assert_unchanged(self) -> None:
        for parent, (_, expected_lineage, _) in self.parents.items():
            _, lineage, descriptors = _open_release_output_parent(parent)
            try:
                if lineage != expected_lineage:
                    raise ReleaseManifestSignatureError(
                        "release output parent directory was replaced"
                    )
                self._healthy()
            except BaseException as exc:
                self._attach_cleanup(exc, self._close_descriptors(descriptors))
                raise
            errors = self._close_descriptors(descriptors)
            if errors:
                self._raise_cleanup(errors)
            self._healthy()
        for path, descriptor, expected_identity in self.created:
            try:
                named = os.stat(
                    path.name, dir_fd=self.parents[path.parent][0], follow_symlinks=False
                )
                opened = os.fstat(descriptor)
            except OSError as exc:
                raise ReleaseManifestSignatureError(
                    "release output changed during publication"
                ) from exc
            if (expected_identity is None or not stat.S_ISREG(named.st_mode)
                    or _identity(named) != expected_identity or _identity(opened) != expected_identity):
                raise ReleaseManifestSignatureError("release output changed during publication")
            self._healthy()

    def install(self, path: Path, payload: bytes, label: str, *, mode: int = 0o644) -> None:
        """Create and retain one exclusive output under its preflight directory."""
        self._operate(lambda: self._install(path, payload, label, mode))

    def _install(self, path: Path, payload: bytes, label: str, mode: int) -> None:
        if path not in self.outputs:
            raise ReleaseManifestSignatureError("unbound release output path")
        self._assert_unchanged()
        parent_descriptor = self.parents[path.parent][0]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(path.name, flags, mode, dir_fd=parent_descriptor)
        except OSError as exc:
            raise ReleaseManifestSignatureError(f"cannot create {label}: {exc}") from exc
        record = None
        try:
            record = (path, descriptor, None)
            self.created.append(record)
        except BaseException as exc:
            # append may publish before reporting an interruption. Transfer is
            # proved by that exact record, never by a reusable descriptor number.
            # Terminal cleanup owns a published record; only an untransferred
            # descriptor is rolled back and closed by this local owner.
            if record is not None and any(
                    retained is record for retained in list.__iter__(self.created)):
                raise
            if self._failure is None:
                self._failure = exc
            errors = []
            try:
                self._rollback_one(path, descriptor, None, self.parents, errors)
            except BaseException as cleanup_error:
                errors.append(cleanup_error)
            errors.extend(self._close_descriptors((descriptor,)))
            self._attach_cleanup(exc, tuple(errors))
            raise
        try:
            self.created[-1] = (path, descriptor, _identity(os.fstat(descriptor)))
            self._healthy()
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ReleaseManifestSignatureError(f"short write while creating {label}")
                view = view[written:]
                self._healthy()
            os.fsync(descriptor)
            installed = os.fstat(descriptor)
            if installed.st_nlink != 1 or installed.st_mode & 0o022:
                raise ReleaseManifestSignatureError("release output changed during publication")
            self.created[-1] = (path, descriptor, _identity(installed))
            self._assert_unchanged()
            os.fsync(parent_descriptor)
        except OSError as exc:
            raise ReleaseManifestSignatureError(f"cannot publish {label}: {exc}") from exc

    @staticmethod
    def _rollback_one(path, descriptor, identity, parents, errors) -> None:
        # Retained inode erasure is independent of whether its name was replaced.
        # Attempt each cleanup action, but never unlink a known foreign inode.
        for operation in (lambda: os.ftruncate(descriptor, 0), lambda: os.fsync(descriptor)):
            try:
                operation()
            except BaseException as exc:
                errors.append(exc)
        if identity is None:
            try:
                identity = _identity(os.fstat(descriptor))
            except BaseException as exc:
                errors.append(exc)
                return
        parent_descriptor = parents[path.parent][0]
        try:
            named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        except BaseException as exc:
            errors.append(exc)
            return
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != identity[:2]:
            return
        try:
            os.unlink(path.name, dir_fd=parent_descriptor)
        except BaseException as exc:
            errors.append(exc)
            return
        try:
            os.fsync(parent_descriptor)
        except BaseException as exc:
            errors.append(exc)

    def _finish(self, *, rollback: bool) -> tuple[BaseException, ...]:
        # Detach before any cleanup I/O. A close can succeed before it reports an
        # error, and its numeric descriptor may immediately belong to someone else.
        created, parents = tuple(self.created), self.parents
        self.created, self.parents = [], {}
        self._state, self._active = "closed", True
        errors = []
        try:
            if rollback:
                for path, descriptor, identity in reversed(created):
                    try:
                        self._rollback_one(path, descriptor, identity, parents, errors)
                    except BaseException as exc:
                        errors.append(exc)
            errors.extend(self._close_descriptors(tuple(row[1] for row in created)))
            for _, _, descriptors in reversed(tuple(parents.values())):
                errors.extend(self._close_descriptors(descriptors))
        finally:
            self._active = False
        if self._cleanup_reentry is not None and not any(
                error is self._cleanup_reentry for error in errors):
            errors.append(self._cleanup_reentry)
        return tuple(errors)

    def __exit__(self, exception_type, exception, traceback) -> None:
        if self._active:
            self._refuse("release output transaction exit is reentrant")
        if self._state != "open":
            self._refuse("release output transaction is not open")
        if exception is not None:
            self._attach_cleanup(exception, self._finish(rollback=True))
            return
        try:
            self.assert_unchanged()
        except BaseException as exc:
            self._attach_cleanup(exc, self._finish(rollback=True))
            raise
        outputs_retained = bool(self.created)
        errors = self._finish(rollback=False)
        if errors:
            self._raise_cleanup(errors, outputs_retained=outputs_retained)


def _unlink_if_identity(path: Path, expected_identity: FileIdentity) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        return
    if stat.S_ISREG(metadata.st_mode) and _identity(metadata) == expected_identity:
        try:
            path.unlink()
        except OSError:
            pass


def _snapshot_executable(
    source: Path,
    destination: Path,
    expected_sha256: str,
    *,
    label: str,
    mismatch_message: str,
) -> Tuple[str, FileIdentity]:
    before = _inspect_regular(
        source,
        label,
        executable=True,
    )
    if before.st_size <= 0 or before.st_size > MAX_EXECUTABLE_SIZE:
        raise ReleaseManifestSignatureError(f"{label} exceeds the executable byte bound")
    snapshot_label = f"{label} snapshot"
    _require_new_output(destination, snapshot_label)
    read_flags = os.O_RDONLY
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
        write_flags |= os.O_NOFOLLOW
    read_descriptor = -1
    write_descriptor = -1
    snapshot_identity: Optional[FileIdentity] = None
    try:
        read_descriptor = os.open(source, read_flags)
        opened = os.fstat(read_descriptor)
        if opened.st_size <= 0 or opened.st_size > MAX_EXECUTABLE_SIZE:
            raise ReleaseManifestSignatureError(f"{label} exceeds the executable byte bound")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ReleaseManifestSignatureError(
                f"{label} changed while it was opened"
            )
        write_descriptor = os.open(destination, write_flags, 0o700)
        snapshot_identity = _identity(os.fstat(write_descriptor))
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(read_descriptor, min(1024 * 1024, MAX_EXECUTABLE_SIZE + 1 - copied))
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_EXECUTABLE_SIZE:
                raise ReleaseManifestSignatureError(f"{label} exceeds the executable byte bound")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(write_descriptor, view)
                if written <= 0:
                    raise ReleaseManifestSignatureError(
                        f"short write while snapshotting {label}"
                    )
                view = view[written:]
        os.fsync(write_descriptor)
        closed = os.fstat(read_descriptor)
        if _identity(opened) != _identity(closed):
            raise ReleaseManifestSignatureError(
                f"{label} changed while it was snapshotted"
            )
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256:
            raise ReleaseManifestSignatureError(mismatch_message)
    except BaseException:
        if snapshot_identity is not None:
            _unlink_if_identity(destination, snapshot_identity)
        raise
    finally:
        if read_descriptor >= 0:
            os.close(read_descriptor)
        if write_descriptor >= 0:
            os.close(write_descriptor)
    return actual_sha256, _identity(opened)


def _snapshot_native_verifier(
    source: Path,
    destination: Path,
    trusted_sha256: str,
) -> Tuple[str, FileIdentity]:
    return _snapshot_executable(
        source,
        destination,
        trusted_sha256,
        label="native release-manifest verifier",
        mismatch_message=(
            "native release-manifest verifier does not match the reviewed SHA256"
        ),
    )


def _native_snapshot_path(temp_dir: Path, source: Path) -> Path:
    suffix = ".exe" if source.suffix.lower() == ".exe" else ""
    return temp_dir / f"iroha-pinned{suffix}"


def _signer_snapshot_path(temp_dir: Path, source: Path) -> Path:
    suffix = ".exe" if source.suffix.lower() == ".exe" else ""
    return temp_dir / f"external-ed25519-signer-pinned{suffix}"


def _native_verifier_environment() -> Dict[str, str]:
    """Return the minimal environment accepted by the native verifier."""

    environment = {"PATH": os.defpath}
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(key)
            if value:
                environment[key] = value
    return environment


def _external_signer_environment(private_home: Path) -> Dict[str, str]:
    """Return the fixed, secret-free environment accepted by the signer."""

    environment = {
        "HOME": str(private_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": str(private_home),
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(key)
            if value:
                environment[key] = value
    return environment


def _external_tool_execution_identity() -> Optional[Tuple[int, int]]:
    """Return the controller-sealed drop identity required by a root caller."""

    raw_uid = os.environ.get(EXTERNAL_TOOL_UID_ENV)
    raw_gid = os.environ.get(EXTERNAL_TOOL_GID_ENV)
    if (raw_uid is None) != (raw_gid is None):
        raise ReleaseManifestSignatureError(
            "external tool execution identity is incomplete"
        )
    current_uid = os.geteuid() if hasattr(os, "geteuid") else 1
    current_gid = os.getegid() if hasattr(os, "getegid") else 1
    if raw_uid is None:
        if current_uid == 0:
            raise ReleaseManifestSignatureError(
                "root may not snapshot or invoke an external signer/verifier "
                "without the sealed controller identity"
            )
        return None
    assert raw_gid is not None
    if (
        not raw_uid.isascii()
        or not raw_uid.isdecimal()
        or not raw_gid.isascii()
        or not raw_gid.isdecimal()
    ):
        raise ReleaseManifestSignatureError(
            "external tool execution identity is noncanonical"
        )
    uid = int(raw_uid)
    gid = int(raw_gid)
    if raw_uid != str(uid) or raw_gid != str(gid) or uid <= 0 or gid <= 0:
        raise ReleaseManifestSignatureError(
            "external tool execution identity must contain positive canonical IDs"
        )
    if current_uid != 0:
        if (uid, gid) != (current_uid, current_gid):
            raise ReleaseManifestSignatureError(
                "external tool execution identity differs from the current non-root identity"
            )
        return None
    return (uid, gid)


def _drop_external_tool_identity(uid: int, gid: int) -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0 or uid <= 0 or gid <= 0:
        raise ReleaseManifestSignatureError(
            "external tool privilege drop requires root and positive IDs"
        )
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.umask(0o077)
    if os.geteuid() != uid or os.getegid() != gid or os.getgroups():
        raise ReleaseManifestSignatureError(
            "external tool privilege drop did not reach the sealed identity"
        )


def _external_tool_preexec(
    identity: Optional[Tuple[int, int]],
) -> Optional[object]:
    if identity is None:
        return None
    uid, gid = identity

    def drop() -> None:
        _drop_external_tool_identity(uid, gid)

    return drop


def _prepare_external_tool_directory(
    path: Path, identity: Optional[Tuple[int, int]]
) -> None:
    if identity is None:
        return
    uid, gid = identity
    os.chown(path, uid, gid)
    os.chmod(path, 0o700)


def _handoff_external_tool_file(
    path: Path,
    identity: Optional[Tuple[int, int]],
    *,
    mode: int,
) -> FileIdentity:
    if identity is not None:
        os.chown(path, identity[0], identity[1])
    os.chmod(path, mode)
    return _identity(path.lstat())


def _invoke_native_verifier(
    verifier: Path,
    manifest: Path,
    public_key: Path,
    fingerprint: str,
    signature: Path,
    execution_identity: Optional[Tuple[int, int]],
) -> None:
    try:
        completed = subprocess.run(
            [
                str(verifier),
                "app",
                "sorafs",
                "toolkit",
                "release-manifest",
                "--manifest",
                str(manifest),
                "--public-key",
                str(public_key),
                "--public-key-fingerprint",
                fingerprint,
                "--signature",
                str(signature),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
            env=_native_verifier_environment(),
            cwd=str(verifier.parent),
            close_fds=True,
            pass_fds=(),
            restore_signals=True,
            preexec_fn=_external_tool_preexec(execution_identity),
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleaseManifestSignatureError(
            "native release-manifest verifier timed out"
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseManifestSignatureError(
            f"cannot execute native release-manifest verifier: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise ReleaseManifestSignatureError(
            "native release-manifest Ed25519 verification failed "
            f"with status {completed.returncode}"
        )


def _invoke_external_signer(
    signer: Path,
    manifest: Path,
    signature: Path,
    private_home: Path,
    execution_identity: Optional[Tuple[int, int]],
) -> None:
    """Invoke only the fixed, sealed external-signing protocol."""

    try:
        completed = subprocess.run(
            [str(signer), str(manifest), str(signature)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
            env=_external_signer_environment(private_home),
            cwd=str(private_home),
            close_fds=True,
            pass_fds=(),
            restore_signals=True,
            preexec_fn=_external_tool_preexec(execution_identity),
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleaseManifestSignatureError(
            "external Ed25519 signer timed out"
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseManifestSignatureError(
            f"cannot execute external Ed25519 signer: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise ReleaseManifestSignatureError(
            f"external Ed25519 signer exited with status {completed.returncode}"
        )


def _read_verification_inputs(
    manifest: Path,
    signature_file: Path,
    public_key_file: Path,
    trusted_fingerprint: str,
) -> Tuple[
    bytes,
    FileIdentity,
    bytes,
    FileIdentity,
    bytes,
    FileIdentity,
]:
    manifest_payload, manifest_identity = _stable_read(
        manifest,
        "aggregate release manifest",
        max_size=MAX_MANIFEST_SIZE,
    )
    _validate_canonical_manifest(manifest_payload)
    signature, signature_identity = _stable_read(
        signature_file,
        "aggregate release-manifest signature",
        exact_size=ED25519_SIGNATURE_SIZE,
    )
    _validate_ed25519_signature_encoding(
        signature,
        "aggregate release-manifest signature",
    )
    raw_public_key, public_key_identity = _stable_read(
        public_key_file,
        "aggregate release-manifest raw public key",
        exact_size=ED25519_PUBLIC_KEY_SIZE,
    )
    _validate_ed25519_public_key_encoding(raw_public_key)
    actual_fingerprint = hashlib.sha256(raw_public_key).hexdigest()
    if actual_fingerprint != trusted_fingerprint:
        raise ReleaseManifestSignatureError(
            "aggregate release-manifest public key does not match the reviewed fingerprint"
        )
    return (
        manifest_payload,
        manifest_identity,
        signature,
        signature_identity,
        raw_public_key,
        public_key_identity,
    )


def _verify_bytes_with_pinned_native(
    *,
    temp_parent: Path,
    native_verifier: Path,
    trusted_verifier_sha256: str,
    manifest_payload: bytes,
    raw_public_key: bytes,
    trusted_fingerprint: str,
    signature: bytes,
    execution_identity: Optional[Tuple[int, int]],
) -> str:
    """Verify immutable snapshots of the already-inspected input bytes."""

    with tempfile.TemporaryDirectory(
        prefix="iroha-release-manifest-native-verify-",
        dir=str(temp_parent),
    ) as temp_raw:
        temp_dir = Path(temp_raw)
        _prepare_external_tool_directory(temp_dir, execution_identity)
        manifest_snapshot = temp_dir / "release_manifest.json"
        public_key_snapshot = temp_dir / "release_manifest.ed25519.pub"
        signature_snapshot = temp_dir / "release_manifest.ed25519.sig"
        manifest_snapshot_identity = _install_exclusive(
            manifest_snapshot,
            manifest_payload,
            "native manifest snapshot",
            mode=0o400,
        )
        public_key_snapshot_identity = _install_exclusive(
            public_key_snapshot,
            raw_public_key,
            "native public-key snapshot",
            mode=0o400,
        )
        signature_snapshot_identity = _install_exclusive(
            signature_snapshot,
            signature,
            "native signature snapshot",
            mode=0o400,
        )
        manifest_snapshot_identity = _handoff_external_tool_file(
            manifest_snapshot, execution_identity, mode=0o400
        )
        public_key_snapshot_identity = _handoff_external_tool_file(
            public_key_snapshot, execution_identity, mode=0o400
        )
        signature_snapshot_identity = _handoff_external_tool_file(
            signature_snapshot, execution_identity, mode=0o400
        )

        verifier_snapshot = _native_snapshot_path(temp_dir, native_verifier)
        verifier_digest, verifier_source_identity = _snapshot_native_verifier(
            native_verifier,
            verifier_snapshot,
            trusted_verifier_sha256,
        )
        _handoff_external_tool_file(
            verifier_snapshot, execution_identity, mode=0o500
        )
        snapshot_digest, verifier_snapshot_identity = _stable_digest(
            verifier_snapshot,
            "native verifier snapshot",
            executable=True,
        )
        if snapshot_digest != verifier_digest:
            raise ReleaseManifestSignatureError(
                "native verifier snapshot does not match the reviewed executable"
            )

        _invoke_native_verifier(
            verifier_snapshot,
            manifest_snapshot,
            public_key_snapshot,
            trusted_fingerprint,
            signature_snapshot,
            execution_identity,
        )
        _assert_digest_unchanged(
            verifier_snapshot,
            "native verifier snapshot",
            snapshot_digest,
            verifier_snapshot_identity,
            executable=True,
        )
        _assert_digest_unchanged(
            native_verifier,
            "native release-manifest verifier",
            verifier_digest,
            verifier_source_identity,
            executable=True,
        )
        _assert_unchanged(
            manifest_snapshot,
            "native manifest snapshot",
            manifest_payload,
            manifest_snapshot_identity,
            max_size=MAX_MANIFEST_SIZE,
        )
        _assert_unchanged(
            public_key_snapshot,
            "native public-key snapshot",
            raw_public_key,
            public_key_snapshot_identity,
            exact_size=ED25519_PUBLIC_KEY_SIZE,
        )
        _assert_unchanged(
            signature_snapshot,
            "native signature snapshot",
            signature,
            signature_snapshot_identity,
            exact_size=ED25519_SIGNATURE_SIZE,
        )
    return verifier_digest


def verify_release_manifest(
    manifest_path: Path,
    signature_path: Path,
    public_key_path: Path,
    trusted_fingerprint: str,
    release_manifest_verifier_path: Path,
    trusted_release_manifest_verifier_sha256: str,
) -> Dict[str, object]:
    """Verify an aggregate manifest through the pinned native verifier."""

    execution_identity = _external_tool_execution_identity()
    _validate_sha256(trusted_fingerprint, "trusted signing fingerprint")
    _validate_sha256(
        trusted_release_manifest_verifier_sha256,
        "trusted native verifier SHA256",
    )
    manifest = _absolute(manifest_path)
    signature_file = _absolute(signature_path)
    public_key_file = _absolute(public_key_path)
    native_verifier = _absolute(release_manifest_verifier_path)
    if len({manifest, signature_file, public_key_file, native_verifier}) != 4:
        raise ReleaseManifestSignatureError(
            "manifest, signature, public key, and native verifier paths must be distinct"
        )

    (
        manifest_payload,
        manifest_identity,
        signature,
        signature_identity,
        raw_public_key,
        public_key_identity,
    ) = _read_verification_inputs(
        manifest,
        signature_file,
        public_key_file,
        trusted_fingerprint,
    )

    verifier_digest = _verify_bytes_with_pinned_native(
        temp_parent=manifest.parent,
        native_verifier=native_verifier,
        trusted_verifier_sha256=trusted_release_manifest_verifier_sha256,
        manifest_payload=manifest_payload,
        raw_public_key=raw_public_key,
        trusted_fingerprint=trusted_fingerprint,
        signature=signature,
        execution_identity=execution_identity,
    )

    _assert_unchanged(
        manifest,
        "aggregate release manifest",
        manifest_payload,
        manifest_identity,
        max_size=MAX_MANIFEST_SIZE,
    )
    _assert_unchanged(
        signature_file,
        "aggregate release-manifest signature",
        signature,
        signature_identity,
        exact_size=ED25519_SIGNATURE_SIZE,
    )
    _assert_unchanged(
        public_key_file,
        "aggregate release-manifest raw public key",
        raw_public_key,
        public_key_identity,
        exact_size=ED25519_PUBLIC_KEY_SIZE,
    )

    return {
        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "manifest_size": len(manifest_payload),
        "signature_algorithm": "ed25519",
        "public_key_format": "raw-ed25519-32",
        "signer_fingerprint_sha256": trusted_fingerprint,
        "signature_verified": True,
        "native_verifier_protocol": NATIVE_VERIFIER_PROTOCOL,
        "native_verifier_path": str(native_verifier),
        "native_verifier_sha256": verifier_digest,
    }


def sign_release_manifest(
    manifest_path: Path,
    external_signer: Path,
    raw_public_key_path: Path,
    trusted_fingerprint: str,
    signature_output_path: Path,
    public_key_output_path: Path,
    release_manifest_verifier_path: Path,
    trusted_release_manifest_verifier_sha256: str,
    verification_summary_output_path: Optional[Path] = None,
) -> Dict[str, object]:
    """Sign via a pinned external signer and verify through the pinned native verifier.

    TODO(parliament anonymous ballot, P6): the official-release signing corridor must
    require an independent audit input set for the anonymous-ballot relations
    (registration and vote proofs; design section 12.2) before a production publish plan
    is accepted. Define the audit-manifest format and its native `iroha app sorafs
    toolkit` verifier together with those relations; until then this corridor signs and
    verifies the aggregate manifest only.
    """

    execution_identity = _external_tool_execution_identity()
    _validate_sha256(trusted_fingerprint, "trusted signing fingerprint")
    _validate_sha256(
        trusted_release_manifest_verifier_sha256,
        "trusted native verifier SHA256",
    )
    manifest = _absolute(manifest_path)
    signer = _absolute(external_signer)
    raw_public_key_file = _absolute(raw_public_key_path)
    signature_output = _absolute(signature_output_path)
    public_key_output = _absolute(public_key_output_path)
    verification_summary_output = (
        _absolute(verification_summary_output_path)
        if verification_summary_output_path is not None
        else None
    )
    native_verifier = _absolute(release_manifest_verifier_path)

    release_outputs = {signature_output, public_key_output}
    if verification_summary_output is not None:
        release_outputs.add(verification_summary_output)
    if len(release_outputs) != (
        3 if verification_summary_output is not None else 2
    ):
        raise ReleaseManifestSignatureError(
            "signature, public-key, and verification-summary outputs "
            "must be different paths"
        )
    signing_inputs = {manifest, signer, raw_public_key_file, native_verifier}
    outputs = [
        (signature_output, "aggregate signature output"),
        (public_key_output, "aggregate public-key output"),
    ]
    if verification_summary_output is not None:
        outputs.append(
            (
                verification_summary_output,
                "aggregate verification-summary output",
            )
        )
    for output, label in outputs:
        if output in signing_inputs:
            raise ReleaseManifestSignatureError(
                f"{label} must not overwrite a signing input"
            )
        _require_new_output(output, label)

    signer_digest, signer_identity = _stable_digest(
        signer,
        "external signer",
        executable=True,
    )
    raw_public_key, raw_public_key_identity = _stable_read(
        raw_public_key_file,
        "raw Ed25519 public key",
        exact_size=ED25519_PUBLIC_KEY_SIZE,
    )
    _validate_ed25519_public_key_encoding(raw_public_key)
    actual_fingerprint = hashlib.sha256(raw_public_key).hexdigest()
    if actual_fingerprint != trusted_fingerprint:
        raise ReleaseManifestSignatureError(
            "raw Ed25519 public key does not match the reviewed fingerprint"
        )
    manifest_payload, manifest_identity = _stable_read(
        manifest,
        "aggregate release manifest",
        max_size=MAX_MANIFEST_SIZE,
    )
    _validate_canonical_manifest(manifest_payload)

    with (
        _ReleaseOutputTransaction(outputs) as output_transaction,
        tempfile.TemporaryDirectory(
            prefix="iroha-release-manifest-sign-",
            dir=str(manifest.parent),
        ) as signer_temp_raw,
    ):
        signer_temp = Path(signer_temp_raw)
        _prepare_external_tool_directory(signer_temp, execution_identity)
        signature_temp = signer_temp / "release_manifest.json.sig"
        signer_manifest_snapshot = signer_temp / "release_manifest.json"
        signer_manifest_snapshot_identity = _install_exclusive(
            signer_manifest_snapshot,
            manifest_payload,
            "external signer manifest snapshot",
            mode=0o600,
        )
        signer_manifest_snapshot_identity = _handoff_external_tool_file(
            signer_manifest_snapshot,
            execution_identity,
            mode=0o400 if execution_identity is not None else 0o600,
        )
        signer_snapshot = _signer_snapshot_path(signer_temp, signer)
        snapshot_digest, signer_snapshot_source_identity = _snapshot_executable(
            signer,
            signer_snapshot,
            signer_digest,
            label="external signer",
            mismatch_message="external signer changed before it could be snapshotted",
        )
        if signer_snapshot_source_identity != signer_identity:
            raise ReleaseManifestSignatureError(
                "external signer changed before it could be snapshotted"
            )
        _handoff_external_tool_file(
            signer_snapshot, execution_identity, mode=0o500
        )
        signer_snapshot_digest, signer_snapshot_identity = _stable_digest(
            signer_snapshot,
            "external signer snapshot",
            executable=True,
        )
        if signer_snapshot_digest != snapshot_digest:
            raise ReleaseManifestSignatureError(
                "external signer snapshot does not match the inspected executable"
            )
        output_transaction.assert_unchanged()
        _invoke_external_signer(
            signer_snapshot,
            signer_manifest_snapshot,
            signature_temp,
            signer_temp,
            execution_identity,
        )
        output_transaction.assert_unchanged()
        signature, signature_temp_identity = _stable_read(
            signature_temp,
            "external aggregate Ed25519 signature",
            exact_size=ED25519_SIGNATURE_SIZE,
        )
        _validate_ed25519_signature_encoding(
            signature,
            "external aggregate Ed25519 signature",
        )

        _assert_unchanged(
            manifest,
            "aggregate release manifest",
            manifest_payload,
            manifest_identity,
            max_size=MAX_MANIFEST_SIZE,
        )
        _assert_unchanged(
            signer_manifest_snapshot,
            "external signer manifest snapshot",
            manifest_payload,
            signer_manifest_snapshot_identity,
            max_size=MAX_MANIFEST_SIZE,
        )
        _assert_digest_unchanged(
            signer_snapshot,
            "external signer snapshot",
            signer_snapshot_digest,
            signer_snapshot_identity,
            executable=True,
        )
        _assert_digest_unchanged(
            signer,
            "external signer",
            signer_digest,
            signer_identity,
            executable=True,
        )
        _assert_unchanged(
            raw_public_key_file,
            "raw Ed25519 public key",
            raw_public_key,
            raw_public_key_identity,
            exact_size=ED25519_PUBLIC_KEY_SIZE,
        )

        verifier_digest = _verify_bytes_with_pinned_native(
            temp_parent=manifest.parent,
            native_verifier=native_verifier,
            trusted_verifier_sha256=trusted_release_manifest_verifier_sha256,
            manifest_payload=manifest_payload,
            raw_public_key=raw_public_key,
            trusted_fingerprint=trusted_fingerprint,
            signature=signature,
            execution_identity=execution_identity,
        )
        _assert_unchanged(
            manifest,
            "aggregate release manifest",
            manifest_payload,
            manifest_identity,
            max_size=MAX_MANIFEST_SIZE,
        )
        _assert_unchanged(
            raw_public_key_file,
            "raw Ed25519 public key",
            raw_public_key,
            raw_public_key_identity,
            exact_size=ED25519_PUBLIC_KEY_SIZE,
        )
        _assert_unchanged(
            signature_temp,
            "external aggregate Ed25519 signature",
            signature,
            signature_temp_identity,
            exact_size=ED25519_SIGNATURE_SIZE,
        )

        output_transaction.install(
            public_key_output,
            raw_public_key,
            "aggregate raw public-key output",
        )
        output_transaction.install(
            signature_output,
            signature,
            "aggregate signature output",
        )
        verification = verify_release_manifest(
            manifest,
            signature_output,
            public_key_output,
            trusted_fingerprint,
            native_verifier,
            trusted_release_manifest_verifier_sha256,
        )
        verification.update(
            {
                "manifest": str(manifest),
                "signature": str(signature_output),
                "public_key": str(public_key_output),
            }
        )
        if verification_summary_output is not None:
            verification_payload = (
                json.dumps(
                    verification,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            output_transaction.install(
                verification_summary_output,
                verification_payload,
                "aggregate verification-summary output",
                mode=0o600,
            )

    return verification


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign = subparsers.add_parser(
        "sign",
        help="Sign an aggregate manifest via a reviewed external Ed25519 signer",
    )
    sign.add_argument("--manifest", required=True)
    sign.add_argument("--external-signer", required=True)
    sign.add_argument("--signing-public-key", required=True)
    sign.add_argument("--trusted-signing-fingerprint", required=True)
    sign.add_argument("--signature-output", required=True)
    sign.add_argument("--public-key-output", required=True)
    sign.add_argument("--verification-summary-output")
    sign.add_argument("--release-manifest-verifier", required=True)
    sign.add_argument("--trusted-release-manifest-verifier-sha256", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="Verify an aggregate manifest through the pinned native verifier",
    )
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--signature", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--trusted-signing-fingerprint", required=True)
    verify.add_argument("--release-manifest-verifier", required=True)
    verify.add_argument("--trusted-release-manifest-verifier-sha256", required=True)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "sign":
            result = sign_release_manifest(
                Path(args.manifest),
                Path(args.external_signer),
                Path(args.signing_public_key),
                args.trusted_signing_fingerprint,
                Path(args.signature_output),
                Path(args.public_key_output),
                Path(args.release_manifest_verifier),
                args.trusted_release_manifest_verifier_sha256,
                (
                    Path(args.verification_summary_output)
                    if args.verification_summary_output is not None
                    else None
                ),
            )
        else:
            result = verify_release_manifest(
                Path(args.manifest),
                Path(args.signature),
                Path(args.public_key),
                args.trusted_signing_fingerprint,
                Path(args.release_manifest_verifier),
                args.trusted_release_manifest_verifier_sha256,
            )
    except ReleaseManifestSignatureError as exc:
        print(f"release manifest signing error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
