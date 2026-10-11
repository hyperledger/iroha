"""Tests for the production public-only provisioning-template guard."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "check_nexus_provisioning_templates.py"
)
SPEC = importlib.util.spec_from_file_location("check_nexus_provisioning_templates", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

HASH_IDENTITY = "hash:" + "A5" * 32 + "#95D7"
OTHER_HASH_IDENTITY = "hash:" + "B7" * 32 + "#5D6D"


def _server(private_field: str = "private_key_file") -> str:
    return f'''\
public_key = "public"
{private_field} = "/run/secrets/iroha/node-key"
soranet_transport_public_key = "transport-public"
soranet_transport_private_key_file = "/run/secrets/iroha/transport-key"

[genesis]
public_key = "genesis-public"
expected_hash = "{HASH_IDENTITY}"

[torii.mcp]
enabled = true
profile = "writer"
expose_operator_routes = false
allow_tool_prefixes = ["iroha."]

[streaming]
identity_public_key = "streaming-public"
identity_private_key_file = "/run/secrets/iroha/streaming-key"
'''


def _client() -> str:
    return f'''\
network_id = "{HASH_IDENTITY}"

[account]
chain_discriminant = 753
public_key = "public"
private_key_file = "/run/secrets/iroha/client-key"
'''


def _write_repository(root: pathlib.Path) -> None:
    for relative in (
        *guard.SERVER_TEMPLATES,
        *guard.DEPLOYMENT_SERVER_TEMPLATES,
        *guard.GENERATED_SERVER_TEMPLATES,
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_server(), encoding="utf-8")
    client = root / guard.CLIENT_TEMPLATE
    client.parent.mkdir(parents=True, exist_ok=True)
    client.write_text(_client(), encoding="utf-8")


def test_public_file_bindings_pass(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    guard.validate_repository(tmp_path)


def test_inline_validator_secret_fails(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    target = tmp_path / guard.SERVER_TEMPLATES[0]
    target.write_text(_server("private_key"), encoding="utf-8")
    with pytest.raises(guard.ProvisioningTemplateError, match="forbidden runtime secret"):
        guard.validate_repository(tmp_path)


@pytest.mark.parametrize(
    ("context", "message"),
    [
        ("", "no default network"),
        ('profile = ""\n', "nonempty string"),
        ("chain_discriminant = 0\n", "1..=65535"),
        ('chain_discriminant = "753"\n', "1..=65535"),
    ],
)
def test_client_template_requires_explicit_network_context(
    tmp_path: pathlib.Path, context: str, message: str
) -> None:
    _write_repository(tmp_path)
    client = tmp_path / guard.CLIENT_TEMPLATE
    client.write_text(
        _client().replace("chain_discriminant = 753\n", context), encoding="utf-8"
    )
    with pytest.raises(guard.ProvisioningTemplateError, match=message):
        guard.validate_repository(tmp_path)


def test_client_template_accepts_public_profile(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    client = tmp_path / guard.CLIENT_TEMPLATE
    client.write_text(
        _client().replace("chain_discriminant = 753\n", 'profile = "taira"\n'),
        encoding="utf-8",
    )
    guard.validate_repository(tmp_path)


def test_client_and_validator_identity_drift_fails(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    client = tmp_path / guard.CLIENT_TEMPLATE
    client.write_text(_client().replace(HASH_IDENTITY, OTHER_HASH_IDENTITY), encoding="utf-8")
    with pytest.raises(guard.ProvisioningTemplateError, match="same exact genesis identity"):
        guard.validate_repository(tmp_path)


def test_checked_in_generated_profile_inline_secret_fails(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    target = tmp_path / guard.GENERATED_SERVER_TEMPLATES[-1]
    target.write_text(_server("private_key"), encoding="utf-8")
    with pytest.raises(guard.ProvisioningTemplateError, match="forbidden runtime secret"):
        guard.validate_repository(tmp_path)


def test_placeholder_identity_fails(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    target = tmp_path / guard.SERVER_TEMPLATES[0]
    target.write_text(
        _server().replace(HASH_IDENTITY, "REPLACE_WITH_GENESIS_EXPECTED_HASH"),
        encoding="utf-8",
    )
    with pytest.raises(guard.ProvisioningTemplateError, match="canonical concrete hash"):
        guard.validate_repository(tmp_path)


def test_paired_public_identity_file_passes(tmp_path: pathlib.Path) -> None:
    _write_repository(tmp_path)
    server_source = f'expected_hash_file = "{guard.PUBLIC_IDENTITY_ROOT}/genesis.expected_hash"'
    client_source = f'network_id_file = "{guard.PUBLIC_IDENTITY_ROOT}/genesis.expected_hash"'
    for relative in guard.SERVER_TEMPLATES:
        target = tmp_path / relative
        target.write_text(
            _server().replace(f'expected_hash = "{HASH_IDENTITY}"', server_source),
            encoding="utf-8",
        )
    client = tmp_path / guard.CLIENT_TEMPLATE
    client.write_text(
        _client().replace(f'network_id = "{HASH_IDENTITY}"', client_source),
        encoding="utf-8",
    )
    guard.validate_repository(tmp_path)


@pytest.mark.parametrize(
    ("configured", "drifted"),
    [
        ("[torii.mcp]", "[torii.disabled_mcp]"),
        ("enabled = true", "enabled = 1"),
        ('profile = "writer"', 'profile = "read_only"'),
        ("expose_operator_routes = false", "expose_operator_routes = true"),
        ('allow_tool_prefixes = ["iroha."]', 'allow_tool_prefixes = ["torii."]'),
    ],
)
@pytest.mark.parametrize(
    "relative",
    guard.PUBLIC_MCP_SERVER_TEMPLATES,
    ids=("minamoto", "taira"),
)
def test_public_mcp_profile_drift_fails(
    tmp_path: pathlib.Path,
    configured: str,
    drifted: str,
    relative: pathlib.Path,
) -> None:
    _write_repository(tmp_path)
    target = tmp_path / relative
    target.write_text(
        _server().replace(configured, drifted),
        encoding="utf-8",
    )
    with pytest.raises(guard.ProvisioningTemplateError, match="public writer profile"):
        guard.validate_repository(tmp_path)
