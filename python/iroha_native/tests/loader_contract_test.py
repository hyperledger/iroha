"""Runtime checks for the native owner's explicit absence boundary."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

NATIVE = Path(__file__).resolve().parents[1] / "src/iroha_native"
ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("version", [None, 28, 29, 30, 31])
@pytest.mark.parametrize(
    "missing",
    [None, "_validate_account_address_v1", "_parse_account_address_v1", "_render_account_address_v1"],
)
def test_account_codec_requires_exact_current_abi_and_complete_surface(monkeypatch, version, missing):
    """Exercise ABI admission only; a stub is never native execution evidence."""
    from types import SimpleNamespace

    from iroha_native import _loader

    native = SimpleNamespace()
    if version is not None:
        native.connect_norito_bridge_abi_version = lambda: version
    for name in (
        "_validate_account_address_v1", "_parse_account_address_v1", "_render_account_address_v1"
    ):
        if name != missing:
            setattr(native, name, lambda *args: None)
    monkeypatch.setattr(_loader, "load_crypto_extension", lambda: native)
    if version == 30 and missing is None:
        assert _loader.require_account_codec_v1() is native
    else:
        with pytest.raises(_loader.NativeUnavailableError, match="ABI-30"):
            _loader.require_account_codec_v1()


def _owner_without_extension(tmp_path):
    owner = tmp_path / "iroha_native"
    owner.mkdir()
    for name in ("__init__.py", "_loader.py"):
        shutil.copy2(NATIVE / name, owner / name)
    return tmp_path


def test_native_package_import_does_not_claim_native_availability(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = '''
import sys
sys.path.insert(0, sys.argv[1])
from iroha_native import NativeUnavailableError, load_crypto_extension, require_account_codec_v1
for operation in (load_crypto_extension, require_account_codec_v1):
    try: operation()
    except NativeUnavailableError: pass
    else: raise AssertionError("missing native extension was admitted")
assert "iroha_python" not in sys.modules
assert "iroha_torii_client" not in sys.modules
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], check=True)


def test_anonymous_transport_imports_but_account_operations_require_native(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = '''
import sys
sys.path[:0] = sys.argv[1:]
import iroha_torii_client
from iroha_torii_client import _account_id
from iroha_native import NativeUnavailableError
for operation in (
    lambda: _account_id.validate_canonical_account_id_bytes(b"x"),
    lambda: _account_id.encode_i105_account_id(b"x", 753),
    lambda: _account_id.decode_canonical_i105_account_id("sora1234567"),
):
    try: operation()
    except NativeUnavailableError: pass
    else: raise AssertionError("account operation accepted missing native authority")
assert "iroha_python" not in sys.modules
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root), str(ROOT / "python")], check=True)


def test_native_owner_rejects_preseed_with_real_extension_spec(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = '''
import _json
import importlib.machinery
from pathlib import Path
import shutil
import sys
import types
sys.path.insert(0, sys.argv[1])
from iroha_native import NativeUnavailableError, require_account_codec_v1
root = Path(sys.argv[1]) / "iroha_native"
source = Path(_json.__file__)
suffix = next(s for s in importlib.machinery.EXTENSION_SUFFIXES if source.name.endswith(s))
shutil.copyfile(source, root / ("_crypto" + suffix))
spec = importlib.machinery.PathFinder.find_spec("iroha_native._crypto", [str(root)])
assert type(spec.loader) is importlib.machinery.ExtensionFileLoader
fake = types.ModuleType(spec.name)
fake.__spec__ = spec
fake.__loader__ = spec.loader
fake.__file__ = spec.origin
fake.connect_norito_bridge_abi_version = lambda: 30
for name in ("_validate_account_address_v1", "_parse_account_address_v1", "_render_account_address_v1"):
    setattr(fake, name, lambda *args: b"not-an-address")
sys.modules[spec.name] = fake
try: require_account_codec_v1()
except NativeUnavailableError as error: assert "pre-seeded" in str(error)
else: raise AssertionError("pre-seeded fake account codec was accepted")
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], check=True)


def test_native_owner_executes_actual_extension_initializer(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = '''
import _json
import importlib.machinery
from pathlib import Path
import shutil
import sys
sys.path.insert(0, sys.argv[1])
from iroha_native import NativeUnavailableError, load_crypto_extension
root = Path(sys.argv[1]) / "iroha_native"
source = Path(_json.__file__)
suffix = next(s for s in importlib.machinery.EXTENSION_SUFFIXES if source.name.endswith(s))
shutil.copyfile(source, root / ("_crypto" + suffix))
try: load_crypto_extension()
except NativeUnavailableError as error:
    assert "could not load the packaged" in str(error)
    assert isinstance(error.__cause__, ImportError)
else: raise AssertionError("unrelated native binary was accepted as the Rust owner")
assert "iroha_native._crypto" not in sys.modules
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], check=True)


_ACCOUNT_CODEC_PREDICATE_SETUP = """
import sys
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from iroha_native import NativeUnavailableError
from iroha_native import _loader

# These unit checks isolate the ABI/surface predicate after the loader succeeds.
# Packaged-extension provenance remains covered by the loader tests above.
def unexpected_account_dispatch(*args):
    raise AssertionError("ABI admission dispatched an account operation")

native = SimpleNamespace(
    connect_norito_bridge_abi_version=lambda: 30,
    _validate_account_address_v1=unexpected_account_dispatch,
    _parse_account_address_v1=unexpected_account_dispatch,
    _render_account_address_v1=unexpected_account_dispatch,
)
loads = []
def loaded_owner():
    loads.append(native)
    return native
_loader.load_crypto_extension = loaded_owner
"""


def test_account_codec_accepts_current_abi_from_loaded_owner(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = _ACCOUNT_CODEC_PREDICATE_SETUP + """
assert _loader.require_account_codec_v1() is native
assert loads == [native]
"""
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], check=True)


def test_account_codec_rejects_other_abis_from_loaded_owner(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = _ACCOUNT_CODEC_PREDICATE_SETUP + """
for rejected in (29, 31):
    native.connect_norito_bridge_abi_version = lambda: rejected
    try: _loader.require_account_codec_v1()
    except NativeUnavailableError as error: assert "ABI-30" in str(error)
    else: raise AssertionError(f"non-current ABI {rejected} was accepted")
assert loads == [native, native]
"""
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], check=True)


def test_account_codec_rejects_missing_or_noncallable_native_surface(tmp_path):
    root = _owner_without_extension(tmp_path)
    code = _ACCOUNT_CODEC_PREDICATE_SETUP + """
for name in (
    "connect_norito_bridge_abi_version",
    "_validate_account_address_v1",
    "_parse_account_address_v1",
    "_render_account_address_v1",
):
    original = getattr(native, name)
    for missing in (True, False):
        if missing: delattr(native, name)
        else: setattr(native, name, None)
        try: _loader.require_account_codec_v1()
        except NativeUnavailableError as error: assert "ABI-30" in str(error)
        else: raise AssertionError(f"incomplete native surface {name} was accepted")
        setattr(native, name, original)
assert len(loads) == 8
"""
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], check=True)
