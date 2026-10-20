"""Mandatory execution checks against the freshly installed PyO3 ABI31 module."""

from __future__ import annotations

import pytest
from iroha_native import load_crypto_extension

from iroha_python.crypto import (
    PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1,
    PRIVACY_REQUIRED_BRIDGE_ABI_VERSION,
    is_privacy_native_available,
    privacy_bridge_abi_version,
    privacy_compiled_profile_catalog_v1,
)


def test_authenticated_pyo3_abi31_executes_the_privacy_catalog_contract() -> None:
    native = load_crypto_extension()
    assert native.connect_norito_bridge_abi_version() == PRIVACY_REQUIRED_BRIDGE_ABI_VERSION
    assert native.privacy_bridge_abi_version() == PRIVACY_REQUIRED_BRIDGE_ABI_VERSION
    assert callable(native.privacy_compiled_profile_catalog_v1)
    assert callable(native.privacy_validate_compiled_profile_catalog_v1)
    assert privacy_bridge_abi_version() == PRIVACY_REQUIRED_BRIDGE_ABI_VERSION
    assert is_privacy_native_available()

    direct = bytes(native.privacy_compiled_profile_catalog_v1())
    public_archive = privacy_compiled_profile_catalog_v1()
    assert direct
    assert public_archive == direct
    assert (
        native.privacy_validate_compiled_profile_catalog_v1(direct)
        == PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1["VALID"]
    )
    assert privacy_compiled_profile_catalog_v1() == direct

    hostile = [direct[:-1], direct[1:], direct + b"\x00"]
    for index in {0, len(direct) // 2, len(direct) - 1}:
        mutated = bytearray(direct)
        mutated[index] ^= 0x80
        hostile.append(bytes(mutated))
    for archive in hostile:
        assert (
            native.privacy_validate_compiled_profile_catalog_v1(archive)
            != PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1["VALID"]
        )


def test_native_capability_fetch_requires_the_transport_owner_and_rejects_archives() -> None:
    native = load_crypto_extension()
    assert callable(native._privacy_fetch_exact12_capability_manifest_v1)
    assert callable(native.privacy_validate_exact12_capability_manifest_v1)
    # An archive, duck-typed object, or locally available catalog cannot stand in
    # for the actual SDK transport owner at the native authority boundary.
    for owner in (b"archived-response", object(), {"authenticated": True}):
        with pytest.raises(ValueError, match="ToriiClient transport owner"):
            native._privacy_fetch_exact12_capability_manifest_v1(owner, None)
    for archive in (b"", b"archived-response", native.privacy_compiled_profile_catalog_v1()):
        assert native.privacy_validate_exact12_capability_manifest_v1(archive) != 0
        with pytest.raises(ValueError, match="invalid canonical Exact12"):
            native.privacy_exact12_capability_manifest_v1(archive)
