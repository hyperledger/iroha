"""Helpers for loading required native extension modules."""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import NamedTuple

__all__ = ["NativeUnavailableError", "load_crypto_extension", "require_account_codec_v1"]

_BUILD_ERROR_MESSAGE = (
    "iroha_native._crypto extension module is not built. "
    "Build and install the iroha-native wheel before using native SDK operations."
)
_PYTHON_FRAMEWORK_DEPENDENCY_RE = re.compile(
    r"(?:^|/)Python3?\.framework/Versions/(?P<version>[0-9]+\.[0-9]+)/Python3?$"
)
_LIBPYTHON_DEPENDENCY_RE = re.compile(
    r"(?:^|/)libpython(?P<version>[0-9]+\.[0-9]+)[A-Za-z]*"
    r"(?:\.dylib|\.so(?:\.[0-9]+)*)$"
)
_verified_linkage_identity: tuple | None = None
_verified_native_module = None
_verified_native_identity: tuple | None = None
_verified_native_spec = None
_native_load_lock = threading.RLock()
_PYTHON_RUNTIME_DEPENDENCY_MARKER_RE = re.compile(
    r"(?:^|/)(?:Python3?\.framework/|libpython)"
)


class _LinkedPythonRuntimeDependency(NamedTuple):
    kind: str
    path: str
    version: str | None


def _parse_otool_python_dependencies(output: str) -> tuple[_LinkedPythonRuntimeDependency, ...]:
    dependencies: list[_LinkedPythonRuntimeDependency] = []
    for line in output.splitlines():
        value = line.strip()
        if not value or value.endswith(":"):
            continue
        dependency_path = value.split(" (", maxsplit=1)[0]
        framework = _PYTHON_FRAMEWORK_DEPENDENCY_RE.search(dependency_path)
        if framework is not None:
            dependencies.append(
                _LinkedPythonRuntimeDependency(
                    "framework",
                    dependency_path,
                    framework.group("version"),
                )
            )
            continue
        libpython = _LIBPYTHON_DEPENDENCY_RE.search(dependency_path)
        if libpython is not None:
            dependencies.append(
                _LinkedPythonRuntimeDependency(
                    "libpython",
                    dependency_path,
                    libpython.group("version"),
                )
            )
            continue
        if _PYTHON_RUNTIME_DEPENDENCY_MARKER_RE.search(dependency_path):
            dependencies.append(
                _LinkedPythonRuntimeDependency("malformed", dependency_path, None)
            )
    return tuple(dependencies)


def _linked_python_runtime_dependencies(
    candidate: Path,
) -> tuple[_LinkedPythonRuntimeDependency, ...]:
    if sys.platform != "darwin":
        return ()
    try:
        output = subprocess.run(
            ["/usr/bin/otool", "-L", str(candidate)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(
            f"could not inspect Python linkage for extension module at {candidate}"
        ) from error
    if output.returncode != 0:
        raise RuntimeError(
            f"could not inspect Python linkage for extension module at {candidate}: "
            f"otool exited with status {output.returncode}"
        )
    return _parse_otool_python_dependencies(output.stdout)


def _assert_extension_compatible(candidate: Path) -> None:
    dependencies = _linked_python_runtime_dependencies(candidate)
    if not dependencies:
        return
    if len(dependencies) != 1:
        linked = ", ".join(dependency.path for dependency in dependencies)
        raise RuntimeError(
            "iroha_native._crypto extension module at "
            f"{candidate} links multiple Python runtimes ({linked}); rebuild it "
            "with `maturin develop --release`."
        )
    dependency = dependencies[0]
    if dependency.kind == "malformed":
        raise RuntimeError(
            "iroha_native._crypto extension module at "
            f"{candidate} has an unrecognized Python runtime dependency "
            f"({dependency.path}); rebuild it with `maturin develop --release`."
        )
    if dependency.kind == "libpython":
        raise RuntimeError(
            "iroha_native._crypto extension module at "
            f"{candidate} links directly to an alternate Python runtime "
            f"({dependency.path}); rebuild it with `maturin develop --release` "
            "using extension-module dynamic lookup."
        )
    current_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if dependency.version == current_version:
        return
    raise RuntimeError(
        "iroha_native._crypto extension module at "
        f"{candidate} links Python {dependency.version}, but the current interpreter is "
        f"Python {current_version}. Rebuild it with `maturin develop --release` "
        f"using Python {current_version}."
    )


class NativeUnavailableError(RuntimeError):
    """The required canonical native owner is absent or cannot be authenticated."""


def load_crypto_extension():
    """Load the sole packaged native module; reject alternate paths and module stubs."""
    with _native_load_lock:
        return _load_crypto_extension()


def _load_crypto_extension():
    global _verified_linkage_identity, _verified_native_module
    global _verified_native_identity, _verified_native_spec
    module_name = "iroha_native._crypto"
    current = sys.modules.get(module_name)
    if _verified_native_module is None:
        if module_name in sys.modules:
            raise NativeUnavailableError("iroha_native._crypto was pre-seeded outside its native owner")
    elif current is not _verified_native_module:
        raise NativeUnavailableError("iroha_native._crypto replaced its native owner module")
    package_root = Path(__file__).resolve(strict=True).parent
    spec = importlib.machinery.PathFinder.find_spec(
        "iroha_native._crypto", [str(package_root)]
    )
    if (
        spec is None
        or type(spec.loader) is not importlib.machinery.ExtensionFileLoader
        or spec.loader_state is not None
        or spec.submodule_search_locations is not None
        or not isinstance(spec.origin, str)
    ):
        raise NativeUnavailableError(_BUILD_ERROR_MESSAGE)
    origin = Path(spec.origin)
    if (
        origin.parent != package_root
        or not origin.is_absolute()
        or origin.is_symlink()
        or origin.resolve(strict=True) != origin
        or spec.loader.name != "iroha_native._crypto"
        or Path(spec.loader.path) != origin
        or not any(origin.name == "_crypto" + suffix for suffix in importlib.machinery.EXTENSION_SUFFIXES)
    ):
        raise NativeUnavailableError("iroha_native._crypto has an untrusted extension origin")
    metadata = origin.stat()
    identity = (origin, metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
    if _verified_native_module is not None and _verified_native_identity != identity:
        raise NativeUnavailableError("native extension changed after its owner loaded it")
    if _verified_linkage_identity != identity:
        _assert_extension_compatible(origin)
        after = origin.stat()
        if identity != (origin, after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise NativeUnavailableError("native extension changed during runtime linkage inspection")
        _verified_linkage_identity = identity
    module = _verified_native_module
    if module is None:
        # Execute the exact inspected filesystem spec. import_module would accept
        # a pre-seeded ModuleType carrying a copied extension spec and fake APIs.
        try:
            module = importlib.util.module_from_spec(spec)
            if module_name in sys.modules:
                raise NativeUnavailableError("native extension was inserted during owner creation")
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as error:
            if sys.modules.get(module_name) is module:
                sys.modules.pop(module_name, None)
            raise NativeUnavailableError("could not load the packaged iroha_native._crypto extension") from error
        loaded_spec = spec
    else:
        loaded_spec = _verified_native_spec
    loaded = getattr(module, "__spec__", None)
    if (
        loaded is None
        or loaded is not loaded_spec
        or loaded.loader_state is not None
        or type(loaded.loader) is not importlib.machinery.ExtensionFileLoader
        or loaded.name != spec.name
        or loaded.origin != spec.origin
        or loaded.loader.name != spec.loader.name
        or loaded.loader.path != spec.loader.path
        or module.__loader__ is not loaded.loader
        or getattr(module, "__file__", None) != str(origin)
        or sys.modules.get("iroha_native._crypto") is not module
    ):
        raise NativeUnavailableError("iroha_native._crypto did not load from its packaged extension")
    after = origin.stat()
    if identity != (origin, after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise NativeUnavailableError("native extension changed during owner loading")
    _verified_native_module = module
    _verified_native_identity = identity
    _verified_native_spec = loaded
    return module


def require_account_codec_v1():
    """Require ABI 30 and the complete Rust account-address validation surface."""
    native = load_crypto_extension()
    version = getattr(native, "connect_norito_bridge_abi_version", None)
    if not callable(version) or version() != 30 or any(
        not callable(getattr(native, name, None))
        for name in ("_validate_account_address_v1", "_parse_account_address_v1", "_render_account_address_v1")
    ):
        raise NativeUnavailableError("account identities require the complete ABI-30 iroha-native owner")
    return native
