from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import site
import sys
import sysconfig
from pathlib import Path


def _add_path(path: Path) -> None:
    location = str(path)
    if location not in sys.path:
        sys.path.insert(0, location)


_ROOT = Path(__file__).resolve().parents[2]
_add_path(_ROOT)
_add_path(_ROOT / "norito_py" / "src")
_add_path(_ROOT / "iroha_torii_client")
_add_path(_ROOT / "iroha_python" / "tests")

_INSTALLED_PACKAGE_MODE = os.environ.get("IROHA_PYTHON_TEST_INSTALLED_PACKAGE")
if _INSTALLED_PACKAGE_MODE not in {None, "1"}:
    raise RuntimeError("IROHA_PYTHON_TEST_INSTALLED_PACKAGE must be unset or 1")

if _INSTALLED_PACKAGE_MODE == "1":
    for module_name in sorted(name for name in tuple(sys.modules) if type(name) is str):
        if type(module_name) is str and any(
            module_name == owner or module_name.startswith(owner + ".")
            for owner in ("iroha_python", "iroha_native")
        ):
            raise RuntimeError(
                f"installed-package tests reject pre-seeded module {module_name}"
            )

    environment_root = Path(sys.prefix).resolve(strict=True)
    site_package_roots = {
        Path(path).resolve(strict=True)
        for path in (
            *site.getsitepackages(),
            sysconfig.get_paths()["purelib"],
            sysconfig.get_paths()["platlib"],
        )
    }
    site_package_roots = {
        path
        for path in site_package_roots
        if path.is_relative_to(environment_root)
    }
    if not site_package_roots:
        raise RuntimeError("installed-package tests require private venv site-packages")

    def _trusted_origin(spec: object, label: str, loader_type: type) -> Path:
        origin = getattr(spec, "origin", None)
        loader = getattr(spec, "loader", None)
        if not isinstance(origin, str) or type(loader) is not loader_type:
            raise RuntimeError(f"{label} must have a trusted filesystem import spec")
        path = Path(origin)
        if not path.is_absolute() or path.is_symlink():
            raise RuntimeError(f"{label} import origin must be absolute and non-symlinked")
        canonical = path.resolve(strict=True)
        if canonical != path or not any(
            canonical.is_relative_to(site_root)
            for site_root in site_package_roots
        ):
            raise RuntimeError(
                f"{label} must resolve from private venv site-packages, got {canonical}"
            )
        return canonical

    def _package_spec(name: str):
        spec = importlib.machinery.PathFinder.find_spec(name)
        if spec is None or spec.loader_state is not None or spec.submodule_search_locations is None:
            raise RuntimeError(f"{name} must resolve as one installed regular package")
        origin = _trusted_origin(spec, name, importlib.machinery.SourceFileLoader)
        roots = {Path(path).resolve(strict=True) for path in spec.submodule_search_locations}
        if roots != {origin.parent}:
            raise RuntimeError(f"{name} package search path must match its trusted origin")
        if spec.loader.name != name or Path(spec.loader.path) != origin:
            raise RuntimeError(f"{name} source loader must match its trusted origin")
        return spec, origin

    package_spec, package_origin = _package_spec("iroha_python")
    owner_spec, owner_origin = _package_spec("iroha_native")
    native_spec = importlib.machinery.PathFinder.find_spec(
        "iroha_native._crypto", [str(owner_origin.parent)]
    )
    if native_spec is None or native_spec.loader_state is not None:
        raise RuntimeError("iroha_native._crypto must have an unmodified extension spec")
    native_origin = _trusted_origin(native_spec, "iroha_native._crypto", importlib.machinery.ExtensionFileLoader)
    if not any(native_origin.name == f"_crypto{suffix}" for suffix in importlib.machinery.EXTENSION_SUFFIXES):
        raise RuntimeError("iroha_native._crypto origin has the wrong platform suffix")
    if native_origin.parent != owner_origin.parent or native_spec.submodule_search_locations is not None:
        raise RuntimeError("native extension must belong to the authenticated iroha_native package")
    if native_spec.loader.name != "iroha_native._crypto" or Path(native_spec.loader.path) != native_origin:
        raise RuntimeError("iroha_native._crypto loader must match its trusted origin")

    owner = importlib.util.module_from_spec(owner_spec)
    sys.modules["iroha_native"] = owner
    owner_spec.loader.exec_module(owner)
    native = owner.load_crypto_extension()
    package = importlib.util.module_from_spec(package_spec)
    sys.modules["iroha_python"] = package
    package_spec.loader.exec_module(package)

    def _assert_loaded(module, name: str, origin: Path, loader_type: type) -> None:
        spec = module.__spec__
        if (
            sys.modules.get(name) is not module
            or spec is None
            or spec.loader_state is not None
            or module.__loader__ is not spec.loader
            or not isinstance(getattr(module, "__file__", None), str)
            or Path(module.__file__) != origin
            or _trusted_origin(spec, f"loaded {name}", loader_type) != origin
            or spec.loader.name != name
            or Path(spec.loader.path) != origin
        ):
            raise RuntimeError(f"loaded {name} spec changed from its trusted origin")

    _assert_loaded(owner, "iroha_native", owner_origin, importlib.machinery.SourceFileLoader)
    _assert_loaded(package, "iroha_python", package_origin, importlib.machinery.SourceFileLoader)
    _assert_loaded(native, "iroha_native._crypto", native_origin, importlib.machinery.ExtensionFileLoader)
else:
    _SOURCE_ROOTS = {
        "iroha_python": _ROOT / "iroha_python" / "src" / "iroha_python",
        "iroha_native": _ROOT / "iroha_native" / "src" / "iroha_native",
    }

    def _source_names():
        return tuple(sorted(name for name in tuple(sys.modules) if type(name) is str and any(
            name == owner or name.startswith(owner + ".") for owner in _SOURCE_ROOTS
        )))

    # Cached descendants can supply package exports even when no root package
    # is present. Refuse every namespace member before any source dispatch.
    for module_name in _source_names():
        raise RuntimeError(f"source-package tests reject pre-seeded module {module_name}")
    _add_path(_ROOT / "iroha_python" / "src")
    _add_path(_ROOT / "iroha_native" / "src")

    def _source_spec(name: str, origin: Path, loader_type: type):
        if origin.resolve(strict=True) != origin or origin.is_symlink():
            raise RuntimeError(f"source {name} origin must be canonical and non-symlinked")
        package = origin.name == "__init__.py"
        search = None if name in _SOURCE_ROOTS else [str(origin.parent.parent if package else origin.parent)]
        spec = importlib.machinery.PathFinder.find_spec(name, search)
        if (
            type(spec) is not importlib.machinery.ModuleSpec
            or type(spec.loader) is not loader_type
            or type(spec.origin) is not str
            or spec.origin != str(origin)
            or spec.name != name
            or spec.loader_state is not None
            or spec.loader.name != name
            or spec.loader.path != str(origin)
            or spec.submodule_search_locations != ([str(origin.parent)] if package else None)
        ):
            raise RuntimeError(f"source {name} must resolve from its exact filesystem owner")
        return spec

    _SOURCE_IMPORTS = {}
    _SOURCE_LOADED = {}
    for name, package_root in _SOURCE_ROOTS.items():
        origin = package_root / "__init__.py"
        _source_spec(name, origin, importlib.machinery.SourceFileLoader)
        _SOURCE_IMPORTS[name] = (origin, importlib.machinery.SourceFileLoader)
    native_root = _SOURCE_ROOTS["iroha_native"]
    native_spec = importlib.machinery.PathFinder.find_spec("iroha_native._crypto", [str(native_root)])
    # Explicit native absence remains available to anonymous transport tests.
    # Account qualification obtains ABI29 through the unchanged strict loader.
    if native_spec is not None:
        if type(native_spec) is not importlib.machinery.ModuleSpec or type(native_spec.origin) is not str:
            raise RuntimeError("source native extension must have a filesystem origin")
        native_origin = Path(native_spec.origin)
        if native_origin.parent != native_root or not any(
            native_origin.name == f"_crypto{suffix}" for suffix in importlib.machinery.EXTENSION_SUFFIXES
        ):
            raise RuntimeError("source native extension belongs to a different owner")
        _source_spec("iroha_native._crypto", native_origin, importlib.machinery.ExtensionFileLoader)
        _SOURCE_IMPORTS["iroha_native._crypto"] = (native_origin, importlib.machinery.ExtensionFileLoader)

    def _descendant_origin(name: str):
        owner, _, suffix = name.partition(".")
        parts = suffix.split(".")
        if not suffix or any(not part.isidentifier() for part in parts):
            raise RuntimeError(f"loaded source {name} has an unsupported descendant name")
        member = _SOURCE_ROOTS[owner].joinpath(*parts)
        origins = tuple(path for path in (member.with_suffix(".py"), member / "__init__.py") if path.is_file())
        if len(origins) != 1:
            raise RuntimeError(f"loaded source {name} lacks one canonical source member")
        return origins[0], importlib.machinery.SourceFileLoader

    def _assert_source_loaded() -> None:
        from types import ModuleType

        names = _source_names()
        if any(name not in names for name in _SOURCE_LOADED):
            raise RuntimeError("loaded source namespace removed an original module owner")
        for name in names:
            module = sys.modules[name]
            if type(module) is not ModuleType:
                raise RuntimeError(f"loaded source {name} is not its admitted original owner")
            if name not in _SOURCE_IMPORTS:
                _SOURCE_IMPORTS[name] = _descendant_origin(name)
            origin, loader_type = _SOURCE_IMPORTS[name]
            values = vars(module)
            spec = values.get("__spec__")
            package = origin.name == "__init__.py"
            if (
                type(spec) is not importlib.machinery.ModuleSpec
                or type(spec.loader) is not loader_type
                or spec.loader_state is not None
                or values.get("__loader__") is not spec.loader
                or type(values.get("__file__")) is not str
                or values["__file__"] != str(origin)
                or spec.origin != str(origin)
                or spec.name != name
                or spec.loader.name != name
                or spec.loader.path != str(origin)
                or spec.submodule_search_locations != ([str(origin.parent)] if package else None)
                or (package and values.get("__path__") != [str(origin.parent)])
                or (name in _SOURCE_LOADED and _SOURCE_LOADED[name] is not module)
            ):
                raise RuntimeError(f"loaded source {name} changed from its original filesystem owner")
            _source_spec(name, origin, loader_type)
            _SOURCE_LOADED[name] = module

    def pytest_sessionstart(session) -> None:
        _assert_source_loaded()

    def pytest_runtest_setup(item) -> None:
        _assert_source_loaded()

    def pytest_sessionfinish(session, exitstatus) -> None:
        _assert_source_loaded()
