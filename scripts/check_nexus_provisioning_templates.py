#!/usr/bin/env python3
"""Validate runtime key handles and bounded MCP policy in public templates."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections.abc import Mapping

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.9/3.10
    import tomli as tomllib


SERVER_TEMPLATES = (
    pathlib.Path("configs/soranexus/nexus/config.toml"),
    pathlib.Path("defaults/nexus/config.toml"),
)
DEPLOYMENT_SERVER_TEMPLATES = (
    pathlib.Path("configs/soranexus/taira/config.toml"),
)
PUBLIC_MCP_SERVER_TEMPLATES = (
    pathlib.Path("configs/soranexus/nexus/config.toml"),
    pathlib.Path("configs/soranexus/taira/config.toml"),
)
GENERATED_SERVER_TEMPLATES = (
    pathlib.Path("defaults/kagami/iroha3-nexus/config.toml"),
)
CLIENT_TEMPLATE = pathlib.Path("defaults/nexus/client.toml")
SECRET_ROOT = pathlib.PurePosixPath("/run/secrets/iroha")
PUBLIC_IDENTITY_ROOT = pathlib.PurePosixPath("/run/iroha")
HASH_LITERAL = re.compile(r"^hash:([0-9A-F]{64})#([0-9A-F]{4})$")


class ProvisioningTemplateError(ValueError):
    """A checked deployment template violates the public-only contract."""


def _is_canonical_hash_literal(value: str) -> bool:
    matched = HASH_LITERAL.fullmatch(value)
    if matched is None:
        return False
    body, checksum = matched.groups()
    crc = 0xFFFF
    for byte in f"hash:{body}".encode("ascii"):
        crc ^= byte << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021) & 0xFFFF
                if crc & 0x8000
                else (crc << 1) & 0xFFFF
            )
    return checksum == f"{crc:04X}" and int(body[-2:], 16) & 1 == 1


def _load_toml(path: pathlib.Path) -> dict[str, object]:
    try:
        with path.open("rb") as source:
            value = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProvisioningTemplateError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ProvisioningTemplateError(f"{path} is not a TOML table")
    return value


def _require_secret_file(
    table: Mapping[str, object], field: str, label: str
) -> pathlib.PurePosixPath:
    raw = table.get(field)
    if not isinstance(raw, str) or not raw:
        raise ProvisioningTemplateError(f"{label} must set non-empty `{field}`")
    path = pathlib.PurePosixPath(raw)
    if path.parent != SECRET_ROOT or path.name in {"", ".", ".."}:
        raise ProvisioningTemplateError(
            f"{label}.{field} must name one direct runtime file under {SECRET_ROOT}"
        )
    return path


def _require_public_identity_source(
    table: Mapping[str, object],
    inline_field: str,
    file_field: str,
    label: str,
) -> str:
    inline = table.get(inline_field)
    file = table.get(file_field)
    if (inline is None) == (file is None):
        raise ProvisioningTemplateError(
            f"{label} must set exactly one of `{inline_field}` or `{file_field}`"
        )
    if inline is not None:
        if not isinstance(inline, str) or not _is_canonical_hash_literal(inline):
            raise ProvisioningTemplateError(
                f"{label}.{inline_field} must be a canonical concrete hash literal"
            )
        return f"inline:{inline}"

    if not isinstance(file, str) or not file:
        raise ProvisioningTemplateError(f"{label}.{file_field} must be non-empty")
    path = pathlib.PurePosixPath(file)
    if path.parent != PUBLIC_IDENTITY_ROOT or path.name in {"", ".", ".."}:
        raise ProvisioningTemplateError(
            f"{label}.{file_field} must name one direct public identity file under {PUBLIC_IDENTITY_ROOT}"
        )
    return f"file:{path}"


def validate_server_template(path: pathlib.Path) -> str:
    """Validate one public validator template and return its genesis identity."""

    table = _load_toml(path)
    forbidden = ("private_key", "soranet_transport_private_key")
    for field in forbidden:
        if field in table:
            raise ProvisioningTemplateError(
                f"{path} embeds forbidden runtime secret field `{field}`"
            )
    streaming = table.get("streaming")
    if not isinstance(streaming, Mapping):
        raise ProvisioningTemplateError(f"{path} must define `[streaming]`")
    if "identity_private_key" in streaming:
        raise ProvisioningTemplateError(
            f"{path} embeds forbidden runtime secret field `streaming.identity_private_key`"
        )

    secret_paths = [
        _require_secret_file(table, "private_key_file", str(path)),
        _require_secret_file(
            table, "soranet_transport_private_key_file", str(path)
        ),
        _require_secret_file(
            streaming, "identity_private_key_file", f"{path}.streaming"
        ),
    ]
    if len(set(secret_paths)) != len(secret_paths):
        raise ProvisioningTemplateError(
            f"{path} must use distinct files for every configured runtime signing key"
        )

    genesis = table.get("genesis")
    if not isinstance(genesis, Mapping):
        raise ProvisioningTemplateError(f"{path} must define `[genesis]`")
    return _require_public_identity_source(
        genesis,
        "expected_hash",
        "expected_hash_file",
        f"{path}.genesis",
    )


def _require_account_network_context(account: Mapping[str, object], label: str) -> None:
    """Require the explicit client network context; client configs have no default network."""

    profile = account.get("profile")
    discriminant = account.get("chain_discriminant")
    if profile is None and discriminant is None:
        raise ProvisioningTemplateError(
            f"{label} must set `profile` or `chain_discriminant`; client configs have no default network"
        )
    if profile is not None and (not isinstance(profile, str) or not profile.strip()):
        raise ProvisioningTemplateError(f"{label}.profile must be a nonempty string")
    if discriminant is not None and (
        isinstance(discriminant, bool)
        or not isinstance(discriminant, int)
        or not 0 < discriminant <= 0xFFFF
    ):
        raise ProvisioningTemplateError(
            f"{label}.chain_discriminant must be an integer in 1..=65535"
        )


def validate_client_template(path: pathlib.Path) -> str:
    """Validate the public client template and return its exact network identity."""

    table = _load_toml(path)
    account = table.get("account")
    if not isinstance(account, Mapping):
        raise ProvisioningTemplateError(f"{path} must define `[account]`")
    if "private_key" in account:
        raise ProvisioningTemplateError(
            f"{path} embeds forbidden runtime secret field `account.private_key`"
        )
    _require_secret_file(account, "private_key_file", f"{path}.account")
    _require_account_network_context(account, f"{path}.account")
    return _require_public_identity_source(
        table, "network_id", "network_id_file", str(path)
    )


def validate_public_mcp_profile(path: pathlib.Path) -> None:
    """Require the bounded public writer profile expected by the Iroha plugin."""

    table = _load_toml(path)
    torii = table.get("torii")
    mcp = torii.get("mcp") if isinstance(torii, Mapping) else None
    if (
        not isinstance(mcp, Mapping)
        or mcp.get("enabled") is not True
        or mcp.get("profile") != "writer"
        or mcp.get("expose_operator_routes") is not False
        or mcp.get("allow_tool_prefixes") != ["iroha."]
    ):
        raise ProvisioningTemplateError(
            f"{path}.torii.mcp must enable the public writer profile, disable "
            "operator routes, and expose only the `iroha.` tool prefix"
        )


def validate_repository(root: pathlib.Path) -> None:
    """Validate every checked-in production/default provisioning template."""

    server_identities = [
        validate_server_template(root / relative) for relative in SERVER_TEMPLATES
    ]
    client_identity = validate_client_template(root / CLIENT_TEMPLATE)
    if len(set((*server_identities, client_identity))) != 1:
        raise ProvisioningTemplateError(
            "Nexus server and client templates must consume the same exact genesis identity source"
        )
    for relative in GENERATED_SERVER_TEMPLATES:
        validate_server_template(root / relative)
    for relative in DEPLOYMENT_SERVER_TEMPLATES:
        validate_server_template(root / relative)
    for relative in PUBLIC_MCP_SERVER_TEMPLATES:
        validate_public_mcp_profile(root / relative)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
        help="repository root (defaults to the script's parent repository)",
    )
    args = parser.parse_args(argv)
    try:
        validate_repository(args.root.resolve())
    except ProvisioningTemplateError as error:
        print(f"Nexus provisioning template check failed: {error}", file=sys.stderr)
        return 1
    print(
        "Production provisioning templates contain public identities, runtime key handles, "
        "and the bounded public MCP policy"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
