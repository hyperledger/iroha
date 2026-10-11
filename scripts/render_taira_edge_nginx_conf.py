#!/usr/bin/env python3
"""Render Taira nginx routes from a canonical four-validator roster.

The validator-only scope requires explicit interface addresses and existing TLS
certificate paths. It does not install or reload nginx; check the candidate with
the serving host's native nginx before activation.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_PUBLIC_HOST = "taira.sora.org"
DEFAULT_EXPLORER_HOST = "taira-explorer.sora.org"
DEFAULT_TLS_LINEAGE = "taira.sora.org"
DEFAULT_CERTBOT_ROOT = "/var/www/certbot"
DEFAULT_EXPLORER_ROOT = "/Users/administrator/dev/iroha2-block-explorer-web/dist"
DEFAULT_CID_HOST_SUFFIX = "sorafs.taira.sora.org"
DEFAULT_MON_HOST_SUFFIX = "mon.taira.sora.net"
DEFAULT_CLIENT_MAX_BODY_SIZE = "1g"
DEFAULT_UPSTREAM_KEEPALIVE = 64
DEFAULT_UPSTREAM_FAIL_TIMEOUT = "5s"
TAIRA_VALIDATOR_COUNT = 4
ROSTER_TOP_LEVEL_KEYS = frozenset(
    {"network_address", "torii_address", "validators", "soracloud_alias_routes"}
)
ROSTER_VALIDATOR_KEYS = frozenset(
    {
        "slug",
        "account_id",
        "public_key",
        "pop_hex",
        "public_address",
        "torii_public_address",
        "edge_torii_upstream",
    }
)
ROSTER_REQUIRED_VALIDATOR_KEYS = frozenset(
    {"slug", "torii_public_address", "edge_torii_upstream"}
)
ROSTER_ALIAS_ROUTE_KEYS = frozenset({"alias", "edge_upstream"})
PUBLIC_TORII_CORS_ORIGINS = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "https://taira-explorer.sora.org",
    "https://test.soraswap.org",
    "https://dweb.link",
    "https://ipfs.io",
    "https://cloudflare-ipfs.com",
    "https://w3s.link",
    "https://nftstorage.link",
    "https://bokolo.soramitsu.io",
    "https://cbsi-banking.soramitsu.io",
    "https://cbsi-core.soramitsu.io",
    "https://bokolo-pob.soramitsu.io",
    "https://bokolo-bred.soramitsu.io",
    "https://bokolo-anz.soramitsu.io",
    "https://bokolo-bsp.soramitsu.io",
    "https://bokolo-m-selen.soramitsu.io",
    "https://bokolo-ezipei.soramitsu.io",
    "https://bpng.soramitsu.io",
    "https://mibank.soramitsu.io",
    "https://explorer-bpng.soramitsu.io",
    "https://bokolo-explorer.soramitsu.io",
]
PUBLIC_TORII_CORS_METHODS = "GET, POST, DELETE, OPTIONS"
PUBLIC_TORII_CORS_HEADERS = (
    "accept, authorization, content-type, idempotency-key, "
    "x-client-app, x-request-id, x-account-id, x-correlation-id, mcp-method, mcp-name, "
    "mcp-protocol-version, x-api-token, x-iroha-onboarding-token, "
    "x-iroha-account, x-iroha-signature, "
    "x-iroha-timestamp-ms, x-iroha-nonce, x-iroha-witness"
)
PUBLIC_TORII_CORS_EXPOSED_HEADERS = "etag, location, retry-after"
PUBLIC_TORII_CORS_MAX_AGE = "3600"
CANONICAL_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
CANONICAL_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CANONICAL_PORT_RE = re.compile(r"^[1-9][0-9]{0,4}$")
LOCALHOST_UPSTREAM_ALIASES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)


@dataclass(frozen=True)
class EdgeValidator:
    slug: str
    upstream_name: str
    validator_host: str
    upstream_address: str
    https_port: int = 443


@dataclass(frozen=True)
class SoracloudAliasRoute:
    alias: str
    upstream_name: str
    upstream_address: str
    pretty_host: str


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError as error:  # pragma: no cover
            raise SystemExit(
                "python3 must provide tomllib (Python 3.11+) or tomli to load roster TOML"
            ) from error

    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a top-level TOML table")
    return payload


def _require_string(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} field `{key}` must be a non-empty string")
    if value != value.strip():
        raise ValueError(
            f"{context} field `{key}` must not contain surrounding whitespace"
        )
    return value


def _require_canonical_keys(
    payload: dict[str, Any],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    context: str,
) -> None:
    unknown = set(payload).difference(allowed)
    missing = required.difference(payload)
    if unknown:
        raise ValueError(
            f"{context} contains unknown first-release field(s): "
            + ", ".join(f"`{key}`" for key in sorted(unknown))
        )
    if missing:
        raise ValueError(
            f"{context} is missing canonical field(s): "
            + ", ".join(f"`{key}`" for key in sorted(missing))
        )


def _validate_roster_schema(payload: dict[str, Any]) -> None:
    """Reject every non-canonical first-release roster shape."""

    _require_canonical_keys(
        payload,
        allowed=ROSTER_TOP_LEVEL_KEYS,
        required=frozenset({"validators"}),
        context="roster",
    )
    validators = payload.get("validators")
    if not isinstance(validators, list):
        raise ValueError("roster must define a `validators` array of tables")
    if len(validators) != TAIRA_VALIDATOR_COUNT:
        raise ValueError(
            f"roster must define exactly {TAIRA_VALIDATOR_COUNT} validators for Taira"
        )
    for index, validator in enumerate(validators, start=1):
        if not isinstance(validator, dict):
            raise ValueError(f"validator entry #{index} must be a TOML table")
        _require_canonical_keys(
            validator,
            allowed=ROSTER_VALIDATOR_KEYS,
            required=ROSTER_REQUIRED_VALIDATOR_KEYS,
            context=f"validator entry #{index}",
        )
    routes = payload.get("soracloud_alias_routes", [])
    if routes is None:
        raise ValueError("roster `soracloud_alias_routes` must not be null")
    if not isinstance(routes, list):
        raise ValueError("roster `soracloud_alias_routes` must be an array of tables")
    for index, route in enumerate(routes, start=1):
        if not isinstance(route, dict):
            raise ValueError(f"Soracloud alias route entry #{index} must be a TOML table")
        _require_canonical_keys(
            route,
            allowed=ROSTER_ALIAS_ROUTE_KEYS,
            required=ROSTER_ALIAS_ROUTE_KEYS,
            context=f"Soracloud alias route entry #{index}",
        )


def _require_canonical_dns_name(value: str, context: str) -> str:
    if not value:
        raise ValueError(f"{context} must be a non-empty DNS name")
    if value != value.lower():
        raise ValueError(f"{context} must use exact lowercase DNS spelling")
    if value.endswith("."):
        raise ValueError(f"{context} must not use a trailing dot")
    if len(value) > 253:
        raise ValueError(f"{context} exceeds the 253-character DNS name limit")
    labels = value.split(".")
    if any(
        len(label) > 63 or not CANONICAL_DNS_LABEL_RE.fullmatch(label)
        for label in labels
    ):
        raise ValueError(f"{context} must contain canonical lowercase DNS labels")
    return value


def _require_canonical_port(port: str, context: str) -> str:
    if not CANONICAL_PORT_RE.fullmatch(port):
        raise ValueError(
            f"{context} port `{port}` must use canonical decimal spelling"
        )
    if int(port) > 65535:
        raise ValueError(f"{context} port `{port}` must be between 1 and 65535")
    return port


def _split_canonical_host_port(value: str, context: str) -> tuple[str, str, bool]:
    if not value:
        raise ValueError(f"{context} must be a non-empty host:port string")
    if value != value.strip():
        raise ValueError(f"{context} must not contain surrounding whitespace")
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or end + 2 >= len(value) or value[end + 1] != ":":
            raise ValueError(f"{context} must be a valid [ipv6]:port or host:port value")
        host = value[1:end]
        port = value[end + 2 :]
        if "]" in port:
            raise ValueError(f"{context} must be a valid [ipv6]:port value")
        return host, _require_canonical_port(port, context), True
    else:
        if value.count(":") != 1:
            raise ValueError(f"{context} must be a valid host:port value")
        host, port = value.split(":", 1)
        if not host or not port:
            raise ValueError(f"{context} must be a valid host:port value")
        return host, _require_canonical_port(port, context), False


def _require_canonical_upstream_address(value: str, context: str) -> str:
    host, port, bracketed = _split_canonical_host_port(value, context)
    if bracketed:
        try:
            address = ipaddress.IPv6Address(host)
        except ipaddress.AddressValueError as error:
            raise ValueError(f"{context} must contain a valid IPv6 address") from error
        if host != address.compressed:
            raise ValueError(
                f"{context} IPv6 host must use exact lowercase compressed spelling"
            )
        if address.is_unspecified:
            raise ValueError(f"{context} must not use a wildcard address")
        return f"[{host}]:{port}"

    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        address = None
    if address is not None:
        if host != str(address):
            raise ValueError(f"{context} IPv4 host must use exact canonical spelling")
        if address.is_unspecified:
            raise ValueError(f"{context} must not use a wildcard address")
        return value
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError(f"{context} IPv4 host must use exact canonical spelling")

    canonical_host = _require_canonical_dns_name(host, f"{context} host")
    if canonical_host in LOCALHOST_UPSTREAM_ALIASES or canonical_host.endswith(
        ".localhost"
    ):
        raise ValueError(f"{context} must not use a localhost alias")
    return value


def _require_public_validator_hostname(value: str, context: str) -> str:
    host = _require_canonical_dns_name(value, context)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError(f"{context} must use a public DNS hostname, not an IP literal")
    if "." not in host or host.rsplit(".", 1)[-1].isdigit() or host.endswith((".localhost", ".local")):
        raise ValueError(f"{context} must use a public DNS hostname")
    return host


def _validator_listener_from_public_origin(value: str, context: str) -> tuple[str, int]:
    parsed = urlparse(value)
    try:
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError as error:
        raise ValueError(f"{context} must be an exact HTTPS origin") from error
    if parsed.scheme != "https" or not hostname:
        raise ValueError(f"{context} must be an exact https:// DNS origin")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"{context} must not contain credentials, a path, a query, or a fragment"
        )
    canonical_host = _require_public_validator_hostname(hostname, f"{context} hostname")
    port = 443 if explicit_port is None else int(_require_canonical_port(str(explicit_port), context))
    if port == 80:
        raise ValueError(f"{context} HTTPS port80 conflicts with the HTTP/ACME listener")
    canonical_origin = f"https://{canonical_host}" + (f":{port}" if port != 443 else "")
    if value != canonical_origin:
        raise ValueError(f"{context} must use exact canonical spelling `{canonical_origin}`")
    return canonical_host, port


def _require_canonical_slug(value: str, context: str) -> str:
    if len(value) > 63 or not CANONICAL_SLUG_RE.fullmatch(value):
        raise ValueError(
            f"{context} must use exact lowercase kebab-case slug spelling"
        )
    return value


def _nginx_upstream_name_for_slug(slug: str) -> str:
    return _require_canonical_slug(slug, "validator slug").replace("-", "_")


def _require_canonical_soracloud_alias(value: str, context: str) -> str:
    return _require_canonical_dns_name(value, f"{context} alias")


def _soracloud_alias_upstream_name(alias: str) -> str:
    canonical_alias = _require_canonical_soracloud_alias(alias, "Soracloud route")
    identifier = canonical_alias.replace("-", "_").replace(".", "_")
    return f"soracloud_{identifier}_upstream"


def parse_soracloud_alias_routes(
    values: list[str] | None,
    *,
    mon_host_suffix: str = DEFAULT_MON_HOST_SUFFIX,
) -> list[SoracloudAliasRoute]:
    routes: list[SoracloudAliasRoute] = []
    seen_aliases: set[str] = set()
    seen_upstream_names: set[str] = set()
    for index, value in enumerate(values or [], start=1):
        alias_text, separator, upstream_text = value.partition("=")
        if separator == "":
            raise ValueError(
                f"Soracloud alias route #{index} must use ALIAS=HOST:PORT syntax"
            )
        alias = _require_canonical_soracloud_alias(
            alias_text,
            f"Soracloud alias route #{index}",
        )
        if alias in seen_aliases:
            raise ValueError(f"Soracloud alias route `{alias}` is duplicated")
        upstream_name = _soracloud_alias_upstream_name(alias)
        if upstream_name in seen_upstream_names:
            raise ValueError(
                f"Soracloud alias route `{alias}` collides with another nginx upstream name"
            )
        upstream_address = _require_canonical_upstream_address(
            upstream_text,
            f"Soracloud alias route `{alias}` upstream",
        )
        seen_aliases.add(alias)
        seen_upstream_names.add(upstream_name)
        routes.append(
            SoracloudAliasRoute(
                alias=alias,
                upstream_name=upstream_name,
                upstream_address=upstream_address,
                pretty_host=f"{alias}.{mon_host_suffix}",
            )
        )
    return routes


def load_soracloud_alias_route_specs(roster_path: Path) -> list[str]:
    payload = _load_toml(roster_path)
    _validate_roster_schema(payload)
    routes_raw = payload.get("soracloud_alias_routes", [])

    route_specs: list[str] = []
    for index, raw in enumerate(routes_raw, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"Soracloud alias route entry #{index} must be a TOML table")
        context = f"Soracloud alias route `{index}`"
        alias = _require_canonical_soracloud_alias(
            _require_string(raw, "alias", context), context
        )
        upstream_source = _require_canonical_upstream_address(
            _require_string(raw, "edge_upstream", context),
            f"{context} edge_upstream",
        )
        route_specs.append(f"{alias}={upstream_source}")
    return route_specs


def load_edge_validators(roster_path: Path) -> list[EdgeValidator]:
    payload = _load_toml(roster_path)
    _validate_roster_schema(payload)
    validators_raw = payload.get("validators")
    assert isinstance(validators_raw, list)

    validators: list[EdgeValidator] = []
    seen_listeners: set[tuple[str, int]] = set()
    seen_upstreams: set[str] = set()
    for index, raw in enumerate(validators_raw, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"validator entry #{index} must be a TOML table")
        slug = _require_canonical_slug(
            _require_string(raw, "slug", f"validator `{index}`"),
            f"validator entry #{index} field `slug`",
        )
        torii_public_address = _require_string(
            raw, "torii_public_address", f"validator `{slug}`"
        )
        validator_host, https_port = _validator_listener_from_public_origin(
            torii_public_address, f"validator `{slug}` torii_public_address"
        )
        upstream_source = _require_string(
            raw, "edge_torii_upstream", f"validator `{slug}`"
        )
        upstream_address = _require_canonical_upstream_address(
            upstream_source,
            f"validator `{slug}` edge_torii_upstream",
        )
        listener = (validator_host, https_port)
        if listener in seen_listeners:
            raise ValueError(f"validator HTTPS listener `{validator_host}:{https_port}` is duplicated in the roster")
        if upstream_address in seen_upstreams:
            raise ValueError(
                f"edge upstream `{upstream_address}` is duplicated in the roster; "
                "shared-edge nginx expects each validator to expose a distinct upstream target"
            )
        seen_listeners.add(listener)
        seen_upstreams.add(upstream_address)
        validators.append(
            EdgeValidator(
                slug=slug,
                upstream_name=_nginx_upstream_name_for_slug(slug),
                validator_host=validator_host,
                upstream_address=upstream_address,
                https_port=https_port,
            )
        )
    return validators


def _render_proxy_headers(
    host_expr: str, *, forwarded_host_expr: str | None = None, trusted_edge: bool = False,
) -> list[str]:
    # The TLS edge discards caller-supplied XFF rather than appending it. Only
    # the private backend restricted to that exact edge retains those sanitized
    # headers, so a second local hop does not replace the original public caller.
    lines = [
        f"    proxy_set_header Host {host_expr};",
        "    proxy_set_header X-Real-IP $http_x_real_ip;" if trusted_edge else "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $http_x_forwarded_for;" if trusted_edge else "    proxy_set_header X-Forwarded-For $remote_addr;",
        "    proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;" if trusted_edge else "    proxy_set_header X-Forwarded-Proto $scheme;",
    ]
    if forwarded_host_expr is not None:
        lines.insert(3, f"    proxy_set_header X-Forwarded-Host {forwarded_host_expr};")
    return lines


def _render_upstream(name: str, server_lines: list[str], keepalive: int) -> list[str]:
    lines = [f"upstream {name} {{"]
    lines.extend(server_lines)
    lines.append(f"  keepalive {keepalive};")
    lines.append("}")
    return lines


def _render_public_torii_cors_server_lines() -> list[str]:
    return [
        "  proxy_hide_header Access-Control-Allow-Origin;",
        "  proxy_hide_header Access-Control-Allow-Methods;",
        "  proxy_hide_header Access-Control-Allow-Headers;",
        "  proxy_hide_header Access-Control-Expose-Headers;",
        "  proxy_hide_header Access-Control-Max-Age;",
        "  add_header Access-Control-Allow-Origin $taira_public_torii_cors_origin always;",
        f'  add_header Access-Control-Allow-Methods "{PUBLIC_TORII_CORS_METHODS}" always;',
        f'  add_header Access-Control-Allow-Headers "{PUBLIC_TORII_CORS_HEADERS}" always;',
        f'  add_header Access-Control-Expose-Headers "{PUBLIC_TORII_CORS_EXPOSED_HEADERS}" always;',
        f'  add_header Access-Control-Max-Age "{PUBLIC_TORII_CORS_MAX_AGE}" always;',
        '  add_header Vary "Origin" always;',
        "",
        "  if ($request_method = OPTIONS) {",
        "    return 204;",
        "  }",
        "",
    ]


def _render_exact_proxy_location(
    path: str,
    upstream: str,
    *,
    host_expr: str,
    websocket: bool = False,
    retry_non_idempotent: bool = False,
    forwarded_host_expr: str | None = None,
    trusted_edge: bool = False,
) -> list[str]:
    lines = [f"  location = {path} {{", f"    proxy_pass http://{upstream};", "    proxy_http_version 1.1;"]
    if websocket:
        lines.extend(
            [
                "    proxy_set_header Upgrade $http_upgrade;",
                '    proxy_set_header Connection "upgrade";',
            ]
        )
    lines.extend(_render_proxy_headers(host_expr, forwarded_host_expr=forwarded_host_expr, trusted_edge=trusted_edge))
    if retry_non_idempotent:
        lines.extend(
            [
                "    proxy_next_upstream error timeout http_502 http_503 http_504 invalid_header non_idempotent;",
                "    proxy_next_upstream_tries 4;",
            ]
        )
    lines.extend(
        [
            "    proxy_read_timeout 3600;",
            "    proxy_send_timeout 3600;",
            "    proxy_buffering off;",
            "  }",
        ]
    )
    return lines


def _render_prefix_proxy_location(
    path: str,
    upstream: str,
    *,
    host_expr: str,
    retry_non_idempotent: bool = False,
    forwarded_host_expr: str | None = None,
    trusted_edge: bool = False,
) -> list[str]:
    lines = [f"  location ^~ {path} {{", f"    proxy_pass http://{upstream};", "    proxy_http_version 1.1;"]
    lines.extend(_render_proxy_headers(host_expr, forwarded_host_expr=forwarded_host_expr, trusted_edge=trusted_edge))
    if retry_non_idempotent:
        lines.extend(
            [
                "    proxy_next_upstream error timeout http_502 http_503 http_504 invalid_header non_idempotent;",
                "    proxy_next_upstream_tries 4;",
            ]
        )
    lines.extend(
        [
            "    proxy_read_timeout 3600;",
            "    proxy_send_timeout 3600;",
            "    proxy_buffering off;",
            "  }",
        ]
    )
    return lines


def _render_soracloud_alias_server(
    route: SoracloudAliasRoute,
    *,
    client_max_body_size: str,
) -> list[str]:
    lines = [
        "server {",
        "  listen 443 ssl;",
        "  listen [::]:443 ssl;",
        "  http2 on;",
        f"  server_name {route.pretty_host};",
        f"  client_max_body_size {client_max_body_size};",
        "",
        f"  ssl_certificate /etc/letsencrypt/live/{route.pretty_host}/fullchain.pem;",
        f"  ssl_certificate_key /etc/letsencrypt/live/{route.pretty_host}/privkey.pem;",
        "  include /etc/letsencrypt/options-ssl-nginx.conf;",
        "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
        "",
    ]
    lines.extend(
        _render_prefix_proxy_location(
            "/",
            route.upstream_name,
            host_expr=route.alias,
            forwarded_host_expr="$host",
        )
    )
    lines.extend(["}", ""])
    return lines


def _render_connect_stateful_locations(
    connect_upstream: str,
    *,
    host_expr: str,
    forwarded_host_expr: str,
) -> list[str]:
    lines = [
        "  # IrohaConnect session tokens and MCP Connect tools are node-local; keep",
        "  # session creation, management/aggregate status, and websocket authorization on one Torii process.",
    ]
    for location in (
        _render_exact_proxy_location(
            "/v1/connect/session",
            connect_upstream,
            host_expr=host_expr,
            forwarded_host_expr=forwarded_host_expr,
        ),
        _render_prefix_proxy_location(
            "/v1/connect/session/",
            connect_upstream,
            host_expr=host_expr,
            forwarded_host_expr=forwarded_host_expr,
        ),
        _render_exact_proxy_location(
            "/v1/connect/status",
            connect_upstream,
            host_expr=host_expr,
            forwarded_host_expr=forwarded_host_expr,
        ),
        _render_exact_proxy_location(
            "/v1/connect/status/aggregate",
            connect_upstream,
            host_expr=host_expr,
            forwarded_host_expr=forwarded_host_expr,
        ),
        _render_exact_proxy_location(
            "/v1/connect/ws",
            connect_upstream,
            host_expr=host_expr,
            websocket=True,
            forwarded_host_expr=forwarded_host_expr,
        ),
        _render_exact_proxy_location(
            "/v1/mcp",
            connect_upstream,
            host_expr=host_expr,
            forwarded_host_expr=forwarded_host_expr,
        ),
    ):
        lines.extend(location)
        lines.append("")
    return lines


def _canonical_listen_addresses(values: list[str]) -> list[str]:
    if not values:
        raise ValueError("validator listener scope requires explicit listen addresses")
    addresses: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("validator listen address must be a canonical IP literal") from error
        if str(address) != value or "%" in value:
            raise ValueError("validator listen address must use exact canonical IP spelling")
        if address.is_unspecified or address.is_multicast:
            raise ValueError("validator listen address must identify one unicast interface")
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            raise ValueError("validator listen address must not be IPv4-mapped IPv6")
        if value in addresses:
            raise ValueError("validator listen address is duplicated")
        addresses.append(value)
    return addresses


def _canonical_tls_path(value: str, context: str) -> str:
    if (
        not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
        or value.endswith("/")
        or any(part in ("", ".", "..") for part in value.split("/")[1:])
    ):
        raise ValueError(f"{context} must be a canonical absolute nginx file path")
    return value


def _canonical_private_ipv4(value: str, context: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError(f"{context} must be a canonical private IPv4 address") from error
    if str(address) != value or not any(address in network for network in (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )):
        raise ValueError(f"{context} must identify one canonical RFC1918 IPv4 interface")
    return value


def _render_validator_proxy_locations(
    validator: EdgeValidator, *, trusted_edge: bool = False,
) -> list[str]:
    upstream = f"{validator.upstream_name}_upstream"
    lines = _render_exact_proxy_location(
        "/v1/connect/ws", upstream, host_expr="$host", websocket=True, trusted_edge=trusted_edge,
    )
    lines.append("")
    lines.extend(_render_exact_proxy_location(
        "/v1/mcp", upstream, host_expr="$host", trusted_edge=trusted_edge,
    ))
    lines.append("")
    lines.extend(_render_prefix_proxy_location(
        "/", upstream, host_expr="$host", trusted_edge=trusted_edge,
    ))
    return lines


def _render_verification_request_map() -> list[str]:
    """Admit only unchanged-URI reads needed by Native peer verification.

    Operator and account signatures bind the original request path, query and
    body. Peer prefixes must never be stripped before forwarding to Torii.
    POST is allowed only for the three explicit authenticated read operations.
    """
    get_paths = (
        "/health", "/readyz", "/livez", "/status", "/v1/node/capabilities",
        "/v1/sumeragi/status", "/v1/sumeragi/lanes",
        "/v1/sumeragi/consensus-keys", "/v1/parameters",
        "/v1/nexus/lifecycle", "/v1/pipeline/transactions/status",
    )
    post_paths = (
        "/v1/pipeline/transactions/details",
        "/v1/aliases/resolve", "/v1/aliases/by-account",
    )
    lines = [
        'map "$request_method:$request_uri" $taira_peer_verification_read {',
        "  default 0;",
    ]
    for method, paths in (("GET", get_paths), ("POST", post_paths)):
        lines.extend(f"  ~^{method}:{path}(?:[?].*)?$ 1;" for path in paths)
    lines.extend([
        "  ~^GET:/v1/bridge/finality/(?:attestation/)?[1-9][0-9]*(?:[?].*)?$ 1;",
        "  ~^GET:/v1/sns/names/(?:dataspace|account-alias)/[a-z0-9][a-z0-9_.@-]*(?:[?].*)?$ 1;",
        "}", "",
    ])
    return lines


def _render_validator_verification_locations(validator: EdgeValidator) -> list[str]:
    """Forward allowed reads to one peer without modifying signed inputs."""
    return [
        "  # Match the raw URI before nginx normalization; Torii owns authentication.",
        "  if ($taira_peer_verification_read = 0) { return 404; }",
        "  location / {",
        f"    proxy_pass http://{validator.upstream_name}_upstream;",
        "    proxy_http_version 1.1;",
        *_render_proxy_headers("$host"),
        '    proxy_set_header Connection "";',
        "    proxy_pass_request_headers on;",
        "    proxy_request_buffering off;",
        "    proxy_buffering off;",
        "    proxy_cache off;",
        "    proxy_intercept_errors off;",
        "    proxy_next_upstream off;",
        "    proxy_read_timeout 180s;",
        "    proxy_send_timeout 180s;",
        "  }",
    ]


def _render_validator_server(
    validator: EdgeValidator,
    *,
    listens: list[str],
    certificate: str,
    certificate_key: str,
    client_max_body_size: str,
    tls_options: list[str],
    verification_only: bool = False,
) -> list[str]:
    lines = [
        "server {",
        *[f"  listen {listener} ssl;" for listener in listens],
        "  http2 on;",
        f"  server_name {validator.validator_host};",
        f"  client_max_body_size {client_max_body_size};",
        "",
        f"  ssl_certificate {certificate};",
        f"  ssl_certificate_key {certificate_key};",
        *tls_options,
        "",
    ]
    lines.extend(
        _render_validator_verification_locations(validator) if verification_only
        else _render_validator_proxy_locations(validator)
    )
    lines.extend(["}", ""])
    return lines


def render_validator_listeners_conf(
    validators: list[EdgeValidator],
    *,
    listen_addresses: list[str],
    tls_certificate: str,
    tls_certificate_key: str,
    client_max_body_size: str = DEFAULT_CLIENT_MAX_BODY_SIZE,
    verification_only: bool = False,
) -> str:
    """Render only peer upstreams and interface-specific TLS servers.

    Certificate paths are references, never read by this renderer. The caller
    verifies assigned interfaces, current tunnel bindings and native nginx
    admission before activating the result beside existing public routes.
    Verification-only listeners expose an explicit read allowlist on separate
    origins; signed requests retain their original path, query and body.
    """
    if len(validators) != TAIRA_VALIDATOR_COUNT:
        raise ValueError(f"exactly {TAIRA_VALIDATOR_COUNT} edge validators are required for Taira")
    _require_canonical_render_inputs(validators, [], mon_host_suffix=DEFAULT_MON_HOST_SUFFIX)
    addresses = _canonical_listen_addresses(listen_addresses)
    certificate = _canonical_tls_path(tls_certificate, "TLS certificate")
    certificate_key = _canonical_tls_path(tls_certificate_key, "TLS certificate key")
    if certificate == certificate_key:
        raise ValueError("TLS certificate and key paths must be distinct")
    if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]?", client_max_body_size):
        raise ValueError("client maximum body size must be a positive nginx size")
    lines = [
        "# Generated by scripts/render_taira_edge_nginx_conf.py from the Taira validator roster.",
        "# Validator TLS listeners only; existing public routes remain separately owned.",
        "",
    ]
    if verification_only:
        lines.extend(_render_verification_request_map())
    for validator in validators:
        lines.extend(_render_upstream(
            f"{validator.upstream_name}_upstream",
            [f"  server {validator.upstream_address};"], DEFAULT_UPSTREAM_KEEPALIVE,
        ))
        lines.append("")
    for validator in validators:
        listens = [
            f"[{address}]:{validator.https_port}" if ":" in address
            else f"{address}:{validator.https_port}"
            for address in addresses
        ]
        lines.extend(_render_validator_server(
            validator, listens=listens, certificate=certificate,
            certificate_key=certificate_key, client_max_body_size=client_max_body_size,
            tls_options=[],
            verification_only=verification_only,
        ))
    return "\n".join(lines)


def render_private_backend_listeners_conf(
    validators: list[EdgeValidator],
    *,
    listen_address: str,
    port_base: int,
    trusted_edge_address: str,
    client_max_body_size: str = DEFAULT_CLIENT_MAX_BODY_SIZE,
) -> str:
    """Render four private HTTP sockets accepting only the explicitly selected TLS edge.

    Assigned interfaces, free sockets and the selected edge's source address must
    be verified on the actual hosts before activation. The backend retains only
    the caller headers sanitized by that restricted edge and never rewrites URI.
    """
    if len(validators) != TAIRA_VALIDATOR_COUNT:
        raise ValueError(f"exactly {TAIRA_VALIDATOR_COUNT} edge validators are required for Taira")
    _require_canonical_render_inputs(validators, [], mon_host_suffix=DEFAULT_MON_HOST_SUFFIX)
    address = _canonical_private_ipv4(listen_address, "backend listen address")
    edge = _canonical_private_ipv4(trusted_edge_address, "trusted edge address")
    if address == edge:
        raise ValueError("backend and trusted edge must identify distinct interfaces")
    if type(port_base) is not int or not 1024 <= port_base <= 65535 - TAIRA_VALIDATOR_COUNT + 1:
        raise ValueError("backend base port must admit four contiguous unprivileged ports")
    if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]?", client_max_body_size):
        raise ValueError("client maximum body size must be a positive nginx size")
    for validator in validators:
        host, _, _ = _split_canonical_host_port(validator.upstream_address, "backend Torii upstream")
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("private backend upstream must be an exact loopback Torii socket")
    lines = [
        "# Generated by scripts/render_taira_edge_nginx_conf.py from the Taira validator roster.",
        "# Private validator HTTP backends; only the selected TLS edge may forward callers.",
        "",
    ]
    for validator in validators:
        lines.extend(_render_upstream(
            f"{validator.upstream_name}_upstream",
            [f"  server {validator.upstream_address};"], DEFAULT_UPSTREAM_KEEPALIVE,
        ))
        lines.append("")
    for index, validator in enumerate(validators):
        lines.extend([
            "server {", f"  listen {address}:{port_base + index};", "  server_name _;",
            f"  client_max_body_size {client_max_body_size};", f"  allow {edge};", "  deny all;", "",
            '  if ($http_x_real_ip = "") { return 400; }',
            '  if ($http_x_forwarded_for != $http_x_real_ip) { return 400; }',
            '  if ($http_x_forwarded_proto != "https") { return 400; }', "",
        ])
        lines.extend(_render_validator_proxy_locations(validator, trusted_edge=True))
        lines.extend(["}", ""])
    return "\n".join(lines)


def _require_canonical_render_inputs(
    validators: list[EdgeValidator],
    soracloud_alias_routes: list[SoracloudAliasRoute],
    *,
    mon_host_suffix: str,
) -> None:
    seen_slugs: set[str] = set()
    seen_validator_listeners: set[tuple[str, int]] = set()
    seen_upstream_addresses: set[str] = set()
    for index, validator in enumerate(validators, start=1):
        context = f"edge validator #{index}"
        slug = _require_canonical_slug(validator.slug, f"{context} slug")
        expected_upstream_name = _nginx_upstream_name_for_slug(slug)
        if validator.upstream_name != expected_upstream_name:
            raise ValueError(
                f"{context} upstream name must be exactly `{expected_upstream_name}`"
            )
        validator_host = _require_public_validator_hostname(
            validator.validator_host, f"{context} public hostname"
        )
        if type(validator.https_port) is not int:
            raise ValueError(f"{context} HTTPS port must be an integer")
        https_port = int(_require_canonical_port(str(validator.https_port), context))
        if https_port == 80:
            raise ValueError(f"{context} HTTPS port80 conflicts with the HTTP/ACME listener")
        listener = (validator_host, https_port)
        upstream_address = _require_canonical_upstream_address(
            validator.upstream_address, f"{context} upstream"
        )
        if slug in seen_slugs:
            raise ValueError(f"edge validator slug `{slug}` is duplicated")
        if listener in seen_validator_listeners:
            raise ValueError(f"edge validator HTTPS listener `{validator_host}:{https_port}` is duplicated")
        if upstream_address in seen_upstream_addresses:
            raise ValueError(f"edge upstream `{upstream_address}` is duplicated")
        seen_slugs.add(slug)
        seen_validator_listeners.add(listener)
        seen_upstream_addresses.add(upstream_address)

    canonical_mon_suffix = _require_canonical_dns_name(
        mon_host_suffix, "Soracloud Mon host suffix"
    )
    seen_aliases: set[str] = set()
    seen_alias_upstream_names: set[str] = set()
    for index, route in enumerate(soracloud_alias_routes, start=1):
        context = f"Soracloud alias route #{index}"
        alias = _require_canonical_soracloud_alias(route.alias, context)
        expected_upstream_name = _soracloud_alias_upstream_name(alias)
        if route.upstream_name != expected_upstream_name:
            raise ValueError(
                f"{context} upstream name must be exactly `{expected_upstream_name}`"
            )
        _require_canonical_upstream_address(
            route.upstream_address, f"{context} upstream"
        )
        expected_pretty_host = f"{alias}.{canonical_mon_suffix}"
        if route.pretty_host != expected_pretty_host:
            raise ValueError(
                f"{context} pretty host must be exactly `{expected_pretty_host}`"
            )
        if alias in seen_aliases:
            raise ValueError(f"Soracloud alias route `{alias}` is duplicated")
        if route.upstream_name in seen_alias_upstream_names:
            raise ValueError(
                f"Soracloud alias route `{alias}` collides with another nginx upstream name"
            )
        seen_aliases.add(alias)
        seen_alias_upstream_names.add(route.upstream_name)


def render_edge_nginx_conf(
    validators: list[EdgeValidator],
    *,
    soracloud_alias_routes: list[SoracloudAliasRoute] | None = None,
    public_host: str = DEFAULT_PUBLIC_HOST,
    public_upstream_validator: str | None = None,
    explorer_host: str = DEFAULT_EXPLORER_HOST,
    tls_lineage: str = DEFAULT_TLS_LINEAGE,
    certbot_root: str = DEFAULT_CERTBOT_ROOT,
    explorer_root: str = DEFAULT_EXPLORER_ROOT,
    cid_host_suffix: str = DEFAULT_CID_HOST_SUFFIX,
    mon_host_suffix: str = DEFAULT_MON_HOST_SUFFIX,
    client_max_body_size: str = DEFAULT_CLIENT_MAX_BODY_SIZE,
    upstream_keepalive: int = DEFAULT_UPSTREAM_KEEPALIVE,
    upstream_fail_timeout: str = DEFAULT_UPSTREAM_FAIL_TIMEOUT,
) -> str:
    soracloud_alias_routes = soracloud_alias_routes or []
    if len(validators) != TAIRA_VALIDATOR_COUNT:
        raise ValueError(
            f"exactly {TAIRA_VALIDATOR_COUNT} edge validators are required for Taira"
        )
    _require_canonical_render_inputs(
        validators,
        soracloud_alias_routes,
        mon_host_suffix=mon_host_suffix,
    )
    for hostname, context in (
        (public_host, "public edge hostname"),
        (explorer_host, "explorer hostname"),
        (tls_lineage, "TLS lineage"),
        (cid_host_suffix, "SoraFS CID host suffix"),
    ):
        _require_canonical_dns_name(hostname, context)
    if public_upstream_validator is None:
        public_upstream_validator = validators[0].slug
    _require_canonical_slug(public_upstream_validator, "public upstream validator")
    public_validator = next(
        (validator for validator in validators if validator.slug == public_upstream_validator),
        None,
    )
    if public_validator is None:
        raise ValueError("public upstream validator must match an exact validator slug from the roster")

    existing_https_hosts = {public_host, explorer_host, mon_host_suffix}
    existing_https_hosts.update(route.pretty_host for route in soracloud_alias_routes)
    for validator in validators:
        if validator.https_port == 443 and (
            validator.validator_host in existing_https_hosts
            or validator.validator_host.endswith("." + mon_host_suffix)
            or validator.validator_host.endswith("." + cid_host_suffix)
        ):
            raise ValueError(
                f"validator HTTPS listener `{validator.validator_host}:443` conflicts with an existing edge listener"
            )
    public_validator_upstream = f"{public_validator.upstream_name}_upstream"

    escaped_mon_host_suffix = mon_host_suffix.replace(".", r"\.")
    mon_host_pattern = f"~^.+\\.{escaped_mon_host_suffix}$"
    mon_alias_host_var = "$taira_mon_alias_host"
    server_names = list(dict.fromkeys([
        public_host,
        explorer_host,
        mon_host_suffix,
        *[v.validator_host for v in validators],
        f"*.{cid_host_suffix}",
        *[route.pretty_host for route in soracloud_alias_routes],
        mon_host_pattern,
    ]))
    lines: list[str] = [
        "# Generated by scripts/render_taira_edge_nginx_conf.py from the Taira validator roster.",
        "# Shared-edge stress runs require the main nginx.conf to set:",
        "#   worker_rlimit_nofile 65536;",
        "#   events { worker_connections 16384; }",
        "# Deploy on the shared edge host serving:",
        f"# - {public_host} (Torii endpoint / convenience host)",
        f"# - {explorer_host} (Explorer web UI)",
        "# - validator-specific public Torii hostnames from the roster",
        f"# - *.{cid_host_suffix} (origin-isolated SoraFS site hosts)",
        f"# - <alias>.{mon_host_suffix} (public Soracloud browser gateway hosts)",
        "",
        "map $host $taira_mon_alias_host {",
        '  default "";',
        f"  ~^(?<taira_mon_alias_host_capture>.+)\\.{escaped_mon_host_suffix}$ $taira_mon_alias_host_capture;",
        "}",
        "",
        "map $http_origin $taira_public_torii_cors_origin {",
        '  default "";',
        *[f'  "{origin}" $http_origin;' for origin in PUBLIC_TORII_CORS_ORIGINS],
        "}",
        "",
    ]

    for validator in validators:
        lines.extend(
            _render_upstream(
                f"{validator.upstream_name}_upstream",
                [f"  server {validator.upstream_address};"],
                upstream_keepalive,
            )
        )
        lines.append("")

    for route in soracloud_alias_routes:
        lines.extend(
            _render_upstream(
                route.upstream_name,
                [f"  server {route.upstream_address};"],
                upstream_keepalive,
            )
        )
        lines.append("")

    # A public request must observe one coherent validator state. Passive nginx
    # health checks only detect transport failure; they cannot detect a live
    # validator that is hundreds of blocks behind. Keep the public convenience
    # origin pinned to the explicitly selected canonical validator. Operators
    # may move that pin only after verifying the replacement validator's state.
    shared_upstream_servers = [
        f"  server {public_validator.upstream_address} "
        f"max_fails=1 fail_timeout={upstream_fail_timeout};"
    ]
    lines.extend(
        _render_upstream("taira_public_edge_upstream", shared_upstream_servers, upstream_keepalive)
    )
    lines.extend(
        [
            "",
            "server {",
            "  listen 80;",
            "  listen [::]:80;",
            f"  server_name {' '.join(server_names)};",
            "",
            "  location ^~ /.well-known/acme-challenge/ {",
            f"    root {certbot_root};",
            '    default_type "text/plain";',
            "  }",
            "",
            "  location / {",
            "    return 301 https://$host$request_uri;",
            "  }",
            "}",
            "",
            "server {",
            "  listen 443 ssl;",
            "  listen [::]:443 ssl;",
            "  http2 on;",
            f"  server_name {public_host};",
            f"  client_max_body_size {client_max_body_size};",
            "  # Stream signed transaction bodies without nginx temporary files.",
            "  proxy_request_buffering off;",
            "",
            f"  ssl_certificate /etc/letsencrypt/live/{tls_lineage}/fullchain.pem;",
            f"  ssl_certificate_key /etc/letsencrypt/live/{tls_lineage}/privkey.pem;",
            "  include /etc/letsencrypt/options-ssl-nginx.conf;",
            "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
            "",
        ]
    )
    lines.extend(_render_public_torii_cors_server_lines())
    lines.extend(
        _render_connect_stateful_locations(
            public_validator_upstream,
            host_expr="$host",
            forwarded_host_expr="$host",
        )
    )
    for path in ("/v1/app-api/", "/v1/sorafs/storage/", "/v1/sorafs/pin/", "/v1/sorafs/cid/", "/sorafs/cid/"):
        lines.extend(
            _render_prefix_proxy_location(
                path,
                "taira_public_edge_upstream",
                host_expr="$host",
                forwarded_host_expr="$host",
            )
        )
        lines.append("")
    lines.extend(
        _render_prefix_proxy_location(
            "/",
            "taira_public_edge_upstream",
            host_expr="$host",
            forwarded_host_expr="$host",
            retry_non_idempotent=True,
        )
    )
    lines.extend(
        [
            "}",
            "",
            "server {",
            "  listen 443 ssl;",
            "  listen [::]:443 ssl;",
            "  http2 on;",
            f"  server_name {mon_host_suffix};",
            f"  client_max_body_size {client_max_body_size};",
            "",
            f"  ssl_certificate /etc/letsencrypt/live/{mon_host_suffix}/fullchain.pem;",
            f"  ssl_certificate_key /etc/letsencrypt/live/{mon_host_suffix}/privkey.pem;",
            "  include /etc/letsencrypt/options-ssl-nginx.conf;",
            "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
            "",
            "  location = /health {",
            '    default_type "text/plain";',
            "    return 200 \"Healthy\\n\";",
            "  }",
            "",
            "  location = / {",
            '    default_type "text/plain";',
            "    return 200 \"Taira Soracloud Mon gateway\\n\\nUse https://<alias>."
            f"{mon_host_suffix}/<path> for browser clients.\\nExample: "
            f"https://solswap-indexer.sora.{mon_host_suffix}/api/indexer/v1/health\\n\";",
            "  }",
            "",
        ]
    )
    lines.extend(
        [
            "}",
            "",
        ]
    )
    for route in soracloud_alias_routes:
        lines.extend(
            _render_soracloud_alias_server(
                route,
                client_max_body_size=client_max_body_size,
            )
        )
    lines.extend(
        [
            "server {",
            "  listen 443 ssl;",
            "  listen [::]:443 ssl;",
            "  http2 on;",
            f"  server_name *.{mon_host_suffix} {mon_host_pattern};",
            f"  client_max_body_size {client_max_body_size};",
            "",
            "  # Each pretty host receives an exact certificate at Soracloud alias bind time.",
            f"  # Do not use a wildcard certificate here: `*.{mon_host_suffix}` does not",
            f"  # cover multi-label aliases such as solswap-indexer.sora.{mon_host_suffix}.",
            "  ssl_certificate /etc/letsencrypt/live/$ssl_server_name/fullchain.pem;",
            "  ssl_certificate_key /etc/letsencrypt/live/$ssl_server_name/privkey.pem;",
            "  include /etc/letsencrypt/options-ssl-nginx.conf;",
            "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
            "",
        ]
    )
    lines.extend(
        _render_prefix_proxy_location(
            "/",
            "taira_public_edge_upstream",
            host_expr=mon_alias_host_var,
            forwarded_host_expr="$host",
            retry_non_idempotent=True,
        )
    )
    lines.extend(
        [
            "}",
            "",
            "server {",
            "  listen 443 ssl;",
            "  listen [::]:443 ssl;",
            "  http2 on;",
            f"  server_name *.{cid_host_suffix};",
            f"  client_max_body_size {client_max_body_size};",
            "",
            f"  ssl_certificate /etc/letsencrypt/live/{tls_lineage}/fullchain.pem;",
            f"  ssl_certificate_key /etc/letsencrypt/live/{tls_lineage}/privkey.pem;",
            "  include /etc/letsencrypt/options-ssl-nginx.conf;",
            "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
            "",
        ]
    )
    lines.extend(
        _render_prefix_proxy_location(
            "/",
            "taira_public_edge_upstream",
            host_expr="$host",
        )
    )
    lines.extend(["}", ""])

    for validator in validators:
        lines.extend(_render_validator_server(
            validator,
            listens=[str(validator.https_port), f"[::]:{validator.https_port}"],
            certificate=f"/etc/letsencrypt/live/{tls_lineage}/fullchain.pem",
            certificate_key=f"/etc/letsencrypt/live/{tls_lineage}/privkey.pem",
            client_max_body_size=client_max_body_size,
            tls_options=[
                "  include /etc/letsencrypt/options-ssl-nginx.conf;",
                "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
            ],
        ))

    lines.extend(
        [
            "server {",
            "  listen 443 ssl;",
            "  listen [::]:443 ssl;",
            "  http2 on;",
            f"  server_name {explorer_host};",
            "",
            f"  ssl_certificate /etc/letsencrypt/live/{tls_lineage}/fullchain.pem;",
            f"  ssl_certificate_key /etc/letsencrypt/live/{tls_lineage}/privkey.pem;",
            "  include /etc/letsencrypt/options-ssl-nginx.conf;",
            "  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;",
            "",
            f"  root {explorer_root};",
            "  index index.html;",
            "",
            "  location / {",
            "    try_files $uri $uri/ /index.html;",
            "  }",
            "}",
            "",
        ]
    )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the shared-edge Taira nginx config from a validator roster."
    )
    parser.add_argument("--roster", required=True, help="validator roster TOML")
    parser.add_argument("--output", required=True, help="nginx config output path")
    scopes = parser.add_mutually_exclusive_group()
    scopes.add_argument(
        "--validator-listeners-only", action="store_true",
        help="Render only peer TLS listeners beside separately managed public routes",
    )
    scopes.add_argument(
        "--validator-verification-listeners-only", action="store_true",
        help="Render path-preserving peer TLS listeners limited to Native verification reads",
    )
    scopes.add_argument(
        "--private-backend-listeners-only", action="store_true",
        help="Render only private unchanged-URI HTTP backends restricted to one TLS edge",
    )
    parser.add_argument(
        "--validator-listen-address", action="append", default=[], metavar="IP",
        help="Exact assigned interface IP for validator-only scope; repeat for IPv4/IPv6",
    )
    parser.add_argument("--tls-certificate", help="Existing absolute certificate path for validator-only scope")
    parser.add_argument("--tls-certificate-key", help="Existing absolute key path for validator-only scope")
    parser.add_argument("--backend-listen-address", help="Exact assigned RFC1918 IPv4 interface for private backends")
    parser.add_argument("--backend-port-base", type=int, help="First of four contiguous private backend ports")
    parser.add_argument("--backend-trusted-edge-address", help="Exact authenticated TLS edge source IPv4; all other sources denied")
    parser.add_argument("--public-host", default=DEFAULT_PUBLIC_HOST)
    parser.add_argument(
        "--public-upstream-validator",
        default=None,
        help=(
            "Exact validator slug selecting the public Torii upstream; preserve the incoming Host "
            "(defaults to the first ordered validator)"
        ),
    )
    parser.add_argument("--explorer-host", default=DEFAULT_EXPLORER_HOST)
    parser.add_argument("--tls-lineage", default=DEFAULT_TLS_LINEAGE)
    parser.add_argument("--certbot-root", default=DEFAULT_CERTBOT_ROOT)
    parser.add_argument("--explorer-root", default=DEFAULT_EXPLORER_ROOT)
    parser.add_argument("--cid-host-suffix", default=DEFAULT_CID_HOST_SUFFIX)
    parser.add_argument("--mon-host-suffix", default=DEFAULT_MON_HOST_SUFFIX)
    parser.add_argument(
        "--soracloud-alias-route",
        action="append",
        default=[],
        metavar="ALIAS=HOST:PORT",
        help=(
            "route a Soracloud alias to a dedicated service upstream; may be "
            "passed more than once, for example "
            "solswap-indexer.sora=127.0.0.1:8788"
        ),
    )
    parser.add_argument("--client-max-body-size", default=DEFAULT_CLIENT_MAX_BODY_SIZE)
    args = parser.parse_args(argv)

    try:
        validators = load_edge_validators(Path(args.roster))
        soracloud_alias_route_specs = [
            *load_soracloud_alias_route_specs(Path(args.roster)),
            *args.soracloud_alias_route,
        ]
        soracloud_alias_routes = parse_soracloud_alias_routes(
            soracloud_alias_route_specs,
            mon_host_suffix=args.mon_host_suffix,
        )
    except ValueError as error:
        parser.error(str(error))

    try:
        backend_arguments = (
            args.backend_listen_address, args.backend_port_base, args.backend_trusted_edge_address,
        )
        if args.validator_listeners_only or args.validator_verification_listeners_only:
            if any(value is not None for value in backend_arguments):
                raise ValueError("private backend arguments require private backend scope")
            if not args.tls_certificate or not args.tls_certificate_key:
                raise ValueError("validator listener scope requires both explicit TLS file paths")
            if soracloud_alias_routes or args.public_upstream_validator:
                raise ValueError("validator listener scope does not select public or alias routes")
            rendered = render_validator_listeners_conf(
                validators, listen_addresses=args.validator_listen_address,
                tls_certificate=args.tls_certificate,
                tls_certificate_key=args.tls_certificate_key,
                client_max_body_size=args.client_max_body_size,
                verification_only=args.validator_verification_listeners_only,
            )
        elif args.private_backend_listeners_only:
            if any(value is None for value in backend_arguments):
                raise ValueError("private backend scope requires explicit listen address, base port and trusted edge address")
            if args.validator_listen_address or args.tls_certificate or args.tls_certificate_key:
                raise ValueError("private backend scope does not select TLS listeners")
            if soracloud_alias_routes or args.public_upstream_validator:
                raise ValueError("private backend scope does not select public or alias routes")
            rendered = render_private_backend_listeners_conf(
                validators, listen_address=args.backend_listen_address,
                port_base=args.backend_port_base,
                trusted_edge_address=args.backend_trusted_edge_address,
                client_max_body_size=args.client_max_body_size,
            )
        else:
            if any(value is not None for value in backend_arguments):
                raise ValueError("private backend arguments require private backend scope")
            if args.validator_listen_address or args.tls_certificate or args.tls_certificate_key:
                raise ValueError("explicit listener/TLS file arguments require validator listener scope")
            rendered = render_edge_nginx_conf(
                validators,
                soracloud_alias_routes=soracloud_alias_routes,
                public_host=args.public_host,
                public_upstream_validator=args.public_upstream_validator,
                explorer_host=args.explorer_host,
                tls_lineage=args.tls_lineage,
                certbot_root=args.certbot_root,
                explorer_root=args.explorer_root,
                cid_host_suffix=args.cid_host_suffix,
                mon_host_suffix=args.mon_host_suffix,
                client_max_body_size=args.client_max_body_size,
            )
    except ValueError as error:
        parser.error(str(error))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered if rendered.endswith("\n") else f"{rendered}\n", encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
