#!/usr/bin/env python3
"""Guard Torii's narrow wrapper and route macros against semantic drift."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / "crates/iroha_torii/src/lib.rs"
ROUTE_CATALOG_SOURCE_PATH = (
    ROOT / "crates/iroha_torii_shared/src/route_catalog.rs"
)
ROUTE_AUTH_METADATA_SCHEMA_VERSION = 1


class GuardError(AssertionError):
    """A generated wrapper or route surface no longer matches its direct preimage."""


@dataclass(frozen=True)
class InvocationGroup:
    """One source-positioned invocation of a wrapper macro."""

    rows: tuple[tuple[str, ...], ...]
    trailing_comma: bool = True


@dataclass(frozen=True)
class WrapperFamily:
    """Exact macro inputs and hashes derived from the direct wrapper preimage."""

    parameters: tuple[str, ...]
    literal_parameters: frozenset[str]
    invocations: tuple[InvocationGroup, ...]
    definition_sha256: str
    expanded_preimage_sha256: str

    @property
    def rows(self) -> tuple[tuple[str, ...], ...]:
        return tuple(row for group in self.invocations for row in group.rows)


FAMILIES = {
    "subscription_action_handlers": WrapperFamily(
        parameters=("handler", "routing_handler", "access_context"),
        literal_parameters=frozenset({"access_context"}),
        invocations=(
            InvocationGroup(
                rows=(
                    (
                        "handler_subscription_pause",
                        "handle_post_v1_subscription_pause",
                        "v1/subscriptions/{subscription_id}/pause",
                    ),
                    (
                        "handler_subscription_resume",
                        "handle_post_v1_subscription_resume",
                        "v1/subscriptions/{subscription_id}/resume",
                    ),
                    (
                        "handler_subscription_cancel",
                        "handle_post_v1_subscription_cancel",
                        "v1/subscriptions/{subscription_id}/cancel",
                    ),
                    (
                        "handler_subscription_keep",
                        "handle_post_v1_subscription_keep",
                        "v1/subscriptions/{subscription_id}/keep",
                    ),
                )
            ),
            InvocationGroup(
                rows=(
                    (
                        "handler_subscription_charge_now",
                        "handle_post_v1_subscription_charge_now",
                        "v1/subscriptions/{subscription_id}/charge-now",
                    ),
                ),
                trailing_comma=False,
            ),
        ),
        definition_sha256="665f1868ce2a5974afe2cd89c5df4f07120e9eadd7ddf444278695ff233677cd",
        expanded_preimage_sha256="027100af5ea6483b2916b151ddd318d6e3166cc6801e205488029a6a587e527e",
    ),
    "account_recovery_command_handlers": WrapperFamily(
        parameters=("handler", "dto", "metric", "route", "routing_handler"),
        literal_parameters=frozenset({"metric", "route"}),
        invocations=(
            InvocationGroup(
                rows=(
                    (
                        "handler_post_account_recovery_policy_set",
                        "crate::routing::AccountRecoveryPolicySetDto",
                        "account_recovery_policy_set",
                        "v1/accounts/recovery/policy/set",
                        "handle_post_account_recovery_policy_set",
                    ),
                    (
                        "handler_post_account_recovery_propose",
                        "crate::routing::AccountRecoveryProposeDto",
                        "account_recovery_propose",
                        "v1/accounts/recovery/propose",
                        "handle_post_account_recovery_propose",
                    ),
                    (
                        "handler_post_account_recovery_approve",
                        "crate::routing::AccountRecoveryApproveDto",
                        "account_recovery_approve",
                        "v1/accounts/recovery/approve",
                        "handle_post_account_recovery_approve",
                    ),
                    (
                        "handler_post_account_recovery_finalize",
                        "crate::routing::AccountRecoveryFinalizeDto",
                        "account_recovery_finalize",
                        "v1/accounts/recovery/finalize",
                        "handle_post_account_recovery_finalize",
                    ),
                    (
                        "handler_post_account_recovery_cancel",
                        "crate::routing::AccountRecoveryCancelDto",
                        "account_recovery_cancel",
                        "v1/accounts/recovery/cancel",
                        "handle_post_account_recovery_cancel",
                    ),
                )
            ),
        ),
        definition_sha256="5eb1270d79d4a81f2b47e50bf2d9604f40b55709dbe7044ad8ec73e5cf9b4c35",
        expanded_preimage_sha256="6f37bf1e8be7867c0d8817ef1e09c24923e678140e50972c8322651dba47ffae",
    ),
    "iso_payment_submission_handlers": WrapperFamily(
        parameters=(
            "handler",
            "message_type",
            "access_context",
            "payload_builder",
        ),
        literal_parameters=frozenset(
            {
                "message_type",
                "access_context",
            }
        ),
        invocations=(
            InvocationGroup(
                rows=(
                    (
                        "handler_iso_pacs008",
                        "pacs.008",
                        "v1/iso20022/pacs008",
                        "build_pacs008_payload",
                    ),
                    (
                        "handler_iso_pacs009",
                        "pacs.009",
                        "v1/iso20022/pacs009",
                        "build_pacs009_payload",
                    ),
                )
            ),
        ),
        definition_sha256="24d376896f5fa3e44528fe6722f5956f600eba827fed648e085fd0ffa44bd024",
        expanded_preimage_sha256="926c35fed300911fe3aab9f0dff9406d94cd0dc662994fd26039e8fce61d3812",
    ),
    "iso_lifecycle_submission_handlers": WrapperFamily(
        parameters=("handler", "message_type", "access_context"),
        literal_parameters=frozenset({"message_type", "access_context"}),
        invocations=(
            InvocationGroup(
                rows=(
                    (
                        "handler_iso_pacs002_submit",
                        "pacs.002",
                        "v1/iso20022/pacs002",
                    ),
                    (
                        "handler_iso_pacs004_submit",
                        "pacs.004",
                        "v1/iso20022/pacs004",
                    ),
                    (
                        "handler_iso_camt056_submit",
                        "camt.056",
                        "v1/iso20022/camt056",
                    ),
                    (
                        "handler_iso_sese023_submit",
                        "sese.023",
                        "v1/iso20022/sese023",
                    ),
                    (
                        "handler_iso_sese024_submit",
                        "sese.024",
                        "v1/iso20022/sese024",
                    ),
                    (
                        "handler_iso_sese025_submit",
                        "sese.025",
                        "v1/iso20022/sese025",
                    ),
                    (
                        "handler_iso_colr012_submit",
                        "colr.012",
                        "v1/iso20022/colr012",
                    ),
                )
            ),
        ),
        definition_sha256="9409d24394be2a627a2e56e48de200716f229a13f89bfc88ea3603def166dc54",
        expanded_preimage_sha256="da365df6755156153cc52f91597e7ce091588bffeab679331ece77e6d39d40be",
    ),
}

ROUTE_MACRO_DEFINITION_SHA256 = {
    "mount_subscription_mutation": "68947e4ed41a19abd272c78f0aa36e7155064773b2d22242651dcfaec36803ee",
    "catalog_route_policy": "a91b9909b29552873bb09e4a0bb2a7f290b2f784dfe304cec9aa6440d9d59198",
    "define_catalog_route_policies": "55fa267f78a7ea35cdb199bed4427fefb81830b115d96fe27cb113b894408ac8",
    "mount_catalog_route_rows": "3e8928222d7cc7586d5d380b04183132188cc9e4b74f70816a51816d637da23e",
    "mount_local_catalog_route_rows": "74c42676d5766d5d942f9d3dc2d4e7ebbda33330ab1e25be73b355771c57b25d",
}
ROUTE_POLICY_DECLARATIONS_SHA256 = "c9cd5d54a3818e070e662a1406ee781198ed4ab41411acb583a8c475bdfae006"
ROUTE_POLICY_NAMES = ('canonical_account_delete', 'canonical_account_get', 'canonical_account_proof_get', 'canonical_account_post', 'canonical_account_proof_post', 'canonical_signature_delete', 'canonical_signature_get', 'optional_canonical_signature_get', 'canonical_signature_post', 'canonical_signed_post', 'layered_canonical_account_post', 'layered_canonical_signature_get', 'layered_canonical_signature_post', 'layered_canonical_signed_post', 'layered_public_get', 'limited_canonical_account_get', 'limited_canonical_account_post', 'limited_canonical_signature_post', 'limited_optional_canonical_signature_post', 'limited_canonical_signed_post', 'limited_hardened_canonical_signature_get', 'limited_operator_get', 'limited_operator_post', 'limited_protocol_handshake_get', 'limited_protocol_handshake_post', 'limited_public_get', 'limited_unauthenticated_get', 'limited_public_post', 'private_root_owner_get', 'onboarding_get', 'onboarding_post', 'operator_credential_post', 'operator_delete', 'operator_get', 'operator_post', 'protocol_handshake_post', 'public_get', 'public_post', 'unauthenticated_any', 'unauthenticated_get')
ROUTE_ROW_COUNT = 599
ROUTE_TUPLE_SHA256 = "e64d1c7ce3e93b8506f9c390c457070de131023d2b755b23cd7a8654c1c58652"


def _normalized_tokens(source: str) -> bytes:
    """Discard layout/comments while preserving string and raw-string bytes."""

    output: list[str] = []
    index = 0
    state = "code"
    block_depth = 0
    raw_hashes = 0
    while index < len(source):
        if state == "code":
            if source.startswith("//", index):
                state = "line_comment"
                index += 2
                continue
            if source.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            raw = re.match(r'(?:br|rb|r)(#*)"', source[index:])
            if raw:
                token = raw.group(0)
                output.append(token)
                raw_hashes = len(raw.group(1))
                index += len(token)
                state = "raw_string"
                continue
            if source.startswith('b"', index):
                output.append('b"')
                index += 2
                state = "string"
                continue
            if source[index] == '"':
                output.append('"')
                index += 1
                state = "string"
                continue
            if source[index].isspace():
                index += 1
                continue
            output.append(source[index])
            index += 1
            continue
        if state == "line_comment":
            if source[index] == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if source.startswith("/*", index):
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                index += 1
            continue
        if state == "string":
            output.append(source[index])
            if source[index] == "\\" and index + 1 < len(source):
                output.append(source[index + 1])
                index += 2
            elif source[index] == '"':
                state = "code"
                index += 1
            else:
                index += 1
            continue
        raw_end = '"' + "#" * raw_hashes
        if source.startswith(raw_end, index):
            output.append(raw_end)
            index += len(raw_end)
            state = "code"
        else:
            output.append(source[index])
            index += 1
    return "".join(output).encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_MACRO_SOURCE_TOKEN = re.compile(
    r'\s+|//[^\n]*|/\*|(?:br|cr|r)(?P<raw_hashes>\#{0,255})"'
    r'|(?:b|c)?"(?:\\.|[^"\\])*"|(?:b)?\'(?:\\.|[^\'\\\r\n])\''
    r'|r#[A-Za-z_][A-Za-z_0-9]*|[A-Za-z_][A-Za-z_0-9]*|.',
    re.DOTALL,
)


@lru_cache(maxsize=1)
def _macro_source_positions(
    source: str,
) -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int, int, bool], ...]]:
    """Locate code macro declarations and calls through one shared lexer."""

    declarations: list[tuple[str, int]] = []
    invocations: list[tuple[str, int, int, bool]] = []
    previous: list[tuple[str, int]] = []
    cursor = 0
    while cursor < len(source):
        match = _MACRO_SOURCE_TOKEN.match(source, cursor)
        assert match is not None
        token = match.group()
        position = match.start()
        cursor = match.end()
        if token.isspace() or token.startswith("//"):
            continue
        if token == "/*":
            depth = 1
            while depth:
                opening = source.find("/*", cursor)
                closing = source.find("*/", cursor)
                if closing < 0:
                    return ((), ())
                if 0 <= opening < closing:
                    depth += 1
                    cursor = opening + 2
                else:
                    depth -= 1
                    cursor = closing + 2
            continue
        if match.group("raw_hashes") is not None:
            marker = '"' + match.group("raw_hashes")
            closing = source.find(marker, cursor)
            if closing < 0:
                return ((), ())
            cursor = closing + len(marker)
            previous.clear()
            continue
        if token.startswith(('"', 'b"', 'c"')) or (
            token.startswith(("'", "b'")) and len(token) > 1
        ):
            previous.clear()
            continue
        if (
            len(previous) >= 2
            and previous[-1][0] == "!"
            and token in "({["
            and re.fullmatch(r"(?:r#)?[A-Za-z_][A-Za-z_0-9]*", previous[-2][0])
        ):
            qualified = len(previous) >= 3 and previous[-3][0] == ":"
            invocations.append(
                (previous[-2][0].removeprefix("r#"), previous[-2][1], position, qualified)
            )
        identifier = token.removeprefix("r#")
        if (
            len(previous) >= 2
            and previous[-2][0] == "macro_rules"
            and previous[-1][0] == "!"
            and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", identifier)
        ):
            declarations.append((identifier, previous[-2][1]))
        previous = (previous + [(token, position)])[-3:]
    return tuple(declarations), tuple(invocations)


def _macro_definition_starts(source: str) -> tuple[tuple[str, int], ...]:
    """Return code declarations, including raw identifiers and nested-comment separators."""

    return _macro_source_positions(source)[0]


def _route_policy_declarations(source: str) -> str:
    """Bind the sole real generator call and reject direct policy shadowing."""

    declarations, invocations = _macro_source_positions(source)
    calls = [(start, opening, qualified) for name, start, opening, qualified in invocations
             if name == "define_catalog_route_policies"]
    if len(calls) != 1:
        raise GuardError("route policy generator must have exactly one invocation")
    if any(name in ROUTE_POLICY_NAMES for name, _ in declarations):
        raise GuardError("generated route policy has a shadowing direct definition")
    start, opening, qualified = calls[0]
    if qualified:
        raise GuardError("route policy generator must use its connected unqualified namespace")
    if source[opening] != "{":
        raise GuardError("route policy generator invocation must use its declared body")
    closing = _matching_delimiter(source, opening, "{", "}")
    invocation = source[start:closing + 1]
    canonical_invocation = invocation.removeprefix("r#")
    if _sha256(_normalized_tokens(canonical_invocation)) != ROUTE_POLICY_DECLARATIONS_SHA256:
        raise GuardError("route policy declarations, compilation guards, or bodies drifted")
    return invocation


def _unique_macro_start(source: str, name: str) -> int:
    """Reject missing or shadowing declarations, including comment separators."""

    starts = [position for declared, position in _macro_definition_starts(source) if declared == name]
    if len(starts) != 1:
        raise GuardError(f"{name} must have exactly one definition")
    return starts[0]


def _macro_definition(source: str, name: str) -> tuple[str, str]:
    start = _unique_macro_start(source, name)
    invocation = source.index(f"{name}!", start)
    definition = source[start:invocation]
    body_start_marker = "\n        $(\n"
    body_end_marker = "\n        )+\n"
    body_start = definition.index(body_start_marker) + len(body_start_marker)
    body_end = definition.index(body_end_marker, body_start)
    return definition, definition[body_start:body_end]


def _render_value(parameter: str, value: str, family: WrapperFamily) -> str:
    if parameter in family.literal_parameters:
        return json.dumps(value, ensure_ascii=True)
    return value


def _expanded_digest(body: str, family: WrapperFamily) -> str:
    expansions = []
    for row in family.rows:
        if len(row) != len(family.parameters):
            raise GuardError("wrapper row width does not match macro parameter width")
        expansion = body
        for parameter, value in zip(family.parameters, row):
            expansion = expansion.replace(
                f"${parameter}", _render_value(parameter, value, family)
            )
        unresolved = re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", expansion)
        if unresolved:
            raise GuardError(f"unresolved macro parameters: {unresolved}")
        expansions.append(_normalized_tokens(expansion))
    return _sha256(b"\0".join(expansions))


def _matching_parenthesis(source: str, opening: int) -> int:
    depth = 0
    index = opening
    state = "code"
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith("//", index):
                state = "line_comment"
                index += 2
                continue
            if source.startswith("/*", index):
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if source.startswith("*/", index):
                state = "code"
                index += 2
            else:
                index += 1
            continue
        if char == "\\":
            index += 2
        elif char == '"':
            state = "code"
            index += 1
        else:
            index += 1
    raise GuardError("unterminated macro invocation")


def _macro_invocations(source: str, name: str) -> list[tuple[int, str]]:
    matches = []
    pattern = re.compile(rf"\b{re.escape(name)}!\s*\(")
    for match in pattern.finditer(source):
        opening = source.index("(", match.start())
        closing = _matching_parenthesis(source, opening)
        semicolon = closing + 1
        while semicolon < len(source) and source[semicolon].isspace():
            semicolon += 1
        if semicolon >= len(source) or source[semicolon] != ";":
            raise GuardError(f"{name} invocation must end with a semicolon")
        matches.append((match.start(), source[match.start() : semicolon + 1]))
    return matches


def _expected_invocation(
    name: str, family: WrapperFamily, group: InvocationGroup
) -> bytes:
    rows = []
    for row in group.rows:
        values = [
            _render_value(parameter, value, family)
            for parameter, value in zip(family.parameters, row)
        ]
        rows.append(f"({','.join(values)})")
    suffix = "," if group.trailing_comma else ""
    return _normalized_tokens(f"{name}!({','.join(rows)}{suffix});")


def _matching_delimiter(
    source: str, opening: int, left: str = "(", right: str = ")"
) -> int:
    """Find a balanced delimiter while ignoring comments and string contents."""

    depth = 0
    index = opening
    state = "code"
    block_depth = 0
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith("//", index):
                state = "line_comment"
                index += 2
                continue
            if source.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == left:
                depth += 1
            elif char == right:
                depth -= 1
                if depth == 0:
                    return index
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if source.startswith("/*", index):
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                index += 1
            continue
        if char == "\\":
            index += 2
        elif char == '"':
            state = "code"
            index += 1
        else:
            index += 1
    raise GuardError("unterminated source delimiter")


def _split_top_level(source: str, delimiter: str) -> list[str]:
    """Split on one delimiter outside nested Rust token groups."""

    output: list[str] = []
    start = 0
    stack: list[str] = []
    index = 0
    state = "code"
    block_depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith("//", index):
                state = "line_comment"
                index += 2
                continue
            if source.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char in pairs:
                stack.append(pairs[char])
            elif stack and char == stack[-1]:
                stack.pop()
            elif char == delimiter and not stack:
                output.append(source[start:index].strip())
                start = index + 1
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if source.startswith("/*", index):
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                index += 1
            continue
        if char == "\\":
            index += 2
        elif char == '"':
            state = "code"
            index += 1
        else:
            index += 1
    if source[start:].strip():
        output.append(source[start:].strip())
    return output


def _route_macro_definition(source: str, name: str) -> str:
    try:
        start = _unique_macro_start(source, name)
        opening = source.index("{", start)
    except ValueError as error:
        raise GuardError(f"{name} definition is missing") from error
    closing = _matching_delimiter(source, opening, "{", "}")
    return source[start : closing + 1]


def _cfg_target_end(source: str, target: int) -> int:
    """Return the end of the item, block, or statement governed by a cfg."""

    stack: list[str] = []
    index = target
    state = "code"
    block_depth = 0
    pairs = {"(": ")", "[": "]"}
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith("//", index):
                state = "line_comment"
                index += 2
                continue
            if source.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char in pairs:
                stack.append(pairs[char])
            elif stack and char == stack[-1]:
                stack.pop()
            elif not stack and char == "{":
                return _matching_delimiter(source, index, "{", "}") + 1
            elif not stack and char == ";":
                return index + 1
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if source.startswith("/*", index):
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                index += 1
            continue
        if char == "\\":
            index += 2
        elif char == '"':
            state = "code"
            index += 1
        else:
            index += 1
    raise GuardError("cfg attribute has no governed source target")


def _route_cfg_ranges(
    source: str, corridor_start: int, corridor_end: int
) -> list[tuple[int, int, str]]:
    ranges = []
    pattern = re.compile(r"#\[cfg\s*\(")
    for match in pattern.finditer(source, corridor_start, corridor_end):
        opening = source.index("(", match.start())
        closing = _matching_delimiter(source, opening)
        expression = "".join(source[opening + 1 : closing].split())
        cursor = source.find("]", closing) + 1
        while True:
            while cursor < len(source) and source[cursor].isspace():
                cursor += 1
            if not source.startswith("#[", cursor):
                break
            cursor = _matching_delimiter(source, cursor + 1, "[", "]") + 1
        ranges.append((cursor, _cfg_target_end(source, cursor), expression))
    return ranges


def _route_cfg_at(position: int, ranges: list[tuple[int, int, str]]) -> str:
    active = [item for item in ranges if item[0] <= position < item[1]]
    active.sort(key=lambda item: item[0])
    return "&".join(expression for _, _, expression in active) or "always"


def _route_semantics(policy: str, arguments: list[str]) -> tuple[str, str, str]:
    method = policy.rsplit("_", 1)[-1].upper()
    if method not in {"GET", "POST", "DELETE", "ANY"}:
        raise GuardError(f"unknown route method policy: {policy}")

    def require(width: int) -> None:
        if len(arguments) != width:
            raise GuardError(f"{policy} row width drifted")

    if policy.startswith("limited_canonical_account_"):
        require(4)
        limit = f"max({arguments[2]});auth({arguments[3]})"
        auth = f"canonical-account({arguments[1]}.clone())"
    elif policy.startswith("layered_canonical_account_"):
        require(4)
        limit = f"layer({arguments[2]}.clone());auth({arguments[3]})"
        auth = f"canonical-account({arguments[1]}.clone())"
    elif policy.startswith("canonical_account_proof_"):
        if policy == "canonical_account_proof_get":
            require(2)
            proof_limit = "0"
        elif policy == "canonical_account_proof_post":
            require(3)
            proof_limit = arguments[2]
        else:
            raise GuardError(f"unknown canonical proof route policy: {policy}")
        limit = f"proof({proof_limit})"
        auth = f"canonical-account-proof({arguments[1]}.clone())"
    elif policy.startswith("canonical_account_"):
        require(3)
        limit = f"auth({arguments[2]})"
        auth = f"canonical-account({arguments[1]}.clone())"
    elif policy.startswith("limited_operator_"):
        require(3)
        limit = f"max({arguments[2]})"
        auth = f"operator({arguments[1]}.clone())"
    elif policy.startswith("operator_") and policy != "operator_credential_post":
        require(2)
        limit = "none"
        auth = f"operator({arguments[1]}.clone())"
    elif policy.startswith("limited_hardened_canonical_signature_"):
        require(2)
        if policy != "limited_hardened_canonical_signature_get":
            raise GuardError(f"unknown hardened route policy: {policy}")
        limit = f"max({arguments[1]});harden-reputation"
        auth = "handler:CanonicalAccountSignature"
    elif policy.startswith("limited_"):
        require(2)
        limit = f"max({arguments[1]})"
        stem = policy[len("limited_") :].rsplit("_", 1)[0]
        try:
            auth = {
                "public": "public",
                "unauthenticated": "unauthenticated",
                "canonical_signature": "handler:CanonicalAccountSignature",
                "optional_canonical_signature":
                    "handler:OptionalCanonicalAccountSignature",
                "canonical_signed": "handler:CanonicalSignedBody",
                "protocol_handshake": "handler:ProtocolHandshake",
            }[stem]
        except KeyError as error:
            raise GuardError(f"unknown limited route policy: {policy}") from error
    elif policy.startswith("layered_"):
        require(2)
        limit = f"layer({arguments[1]}.clone())"
        stem = policy[len("layered_") :].rsplit("_", 1)[0]
        try:
            auth = {
                "public": "public",
                "canonical_signature": "handler:CanonicalAccountSignature",
                "canonical_signed": "handler:CanonicalSignedBody",
            }[stem]
        except KeyError as error:
            raise GuardError(f"unknown layered route policy: {policy}") from error
    else:
        require(1)
        limit = "none"
        stem = policy.rsplit("_", 1)[0]
        try:
            auth = {
                "public": "public",
                "unauthenticated": "unauthenticated",
                "canonical_signature": "handler:CanonicalAccountSignature",
                "optional_canonical_signature":
                    "handler:OptionalCanonicalAccountSignature",
                "canonical_signed": "handler:CanonicalSignedBody",
                "protocol_handshake": "handler:ProtocolHandshake",
                "operator_credential": "handler:OperatorCredentialExchange",
                "private_root_owner": "handler:PrivateRootOwnerToken",
                "onboarding": "onboarding",
            }[stem]
        except KeyError as error:
            raise GuardError(f"unknown direct route policy: {policy}") from error
    return method, limit, auth


def _route_table_rows(source: str) -> list[tuple[str, str, str, str, str, str]]:
    try:
        corridor_start = source.index(
            '    #[cfg(feature = "telemetry")]\n'
            "    #[allow(clippy::unused_self)]\n"
            "    fn add_telemetry_routes"
        )
        corridor_end = source.index(
            "    fn add_runtime_governance_routes", corridor_start
        )
    except ValueError as error:
        raise GuardError("Torii route-builder corridor markers drifted") from error
    cfg_ranges = _route_cfg_ranges(source, corridor_start, corridor_end)
    positioned_rows = []
    for name, local_catalog in (
        ("mount_catalog_route_rows", False),
        ("mount_local_catalog_route_rows", True),
    ):
        pattern = re.compile(rf"\b{re.escape(name)}!\s*\(")
        for match in pattern.finditer(source, corridor_start, corridor_end):
            opening = source.index("(", match.start())
            closing = _matching_delimiter(source, opening)
            semicolon = closing + 1
            while semicolon < len(source) and source[semicolon].isspace():
                semicolon += 1
            if semicolon >= len(source) or source[semicolon] != ";":
                raise GuardError(f"{name} invocation must end with a semicolon")
            parts = _split_top_level(source[opening + 1 : closing], ";")
            header = _split_top_level(parts[0], ",") if parts else []
            if len(header) != 2 or header[0] != "builder":
                raise GuardError(f"{name} header drifted")
            catalog = header[1]
            cfg = _route_cfg_at(match.start(), cfg_ranges)
            for row in parts[1:]:
                row_match = re.fullmatch(
                    r"([A-Z0-9_]+)\s*=>\s*([a-z0-9_]+)\s*(\(.*\))",
                    row,
                    re.S,
                )
                if not row_match:
                    raise GuardError(f"{name} row syntax drifted")
                descriptor, policy, argument_group = row_match.groups()
                arguments = _split_top_level(argument_group[1:-1], ",")
                if not arguments:
                    raise GuardError(f"{name} row has no handler")
                method, limit, auth = _route_semantics(policy, arguments)
                module = "runtime_governance" if local_catalog else catalog
                positioned_rows.append(
                    (
                        match.start(),
                        (
                            cfg,
                            method,
                            f"route_catalog::{module}::{descriptor}",
                            arguments[0],
                            limit,
                            auth,
                        ),
                    )
                )
    # This local macro applies both an HTTP body limit and canonical account
    # authentication. Its exact definition is checked independently above.
    for position, invocation in _macro_invocations(source, "mount_subscription_mutation"):
        if not corridor_start <= position < corridor_end:
            raise GuardError("subscription mutation escaped the route-builder corridor")
        opening = invocation.index("(")
        closing = _matching_delimiter(invocation, opening)
        arguments = _split_top_level(invocation[opening + 1 : closing], ",")
        if (
            len(arguments) != 2
            or re.fullmatch(r"[A-Z0-9_]+", arguments[0]) is None
            or re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*(?:::[a-zA-Z_][a-zA-Z0-9_]*)*", arguments[1]) is None
        ):
            raise GuardError("subscription mutation route arguments drifted")
        positioned_rows.append(
            (
                position,
                (
                    _route_cfg_at(position, cfg_ranges),
                    "POST",
                    f"route_catalog::application_api::{arguments[0]}",
                    arguments[1],
                    "max(transaction_max_content_len);auth(transaction_max_content_len)",
                    "canonical-account-body(app_state.clone())",
                ),
            )
        )
    positioned_rows.sort(key=lambda item: item[0])
    return [row for _, row in positioned_rows]


def _validate_route_tables(source: str) -> None:
    for name, expected in ROUTE_MACRO_DEFINITION_SHA256.items():
        definition = _route_macro_definition(source, name)
        if _sha256(_normalized_tokens(definition)) != expected:
            raise GuardError(f"{name} definition drifted")
    _route_policy_declarations(source)
    rows = _route_table_rows(source)
    if len(rows) != ROUTE_ROW_COUNT:
        raise GuardError("Torii route row count drifted")
    catalog_source = ROUTE_CATALOG_SOURCE_PATH.read_text(encoding="utf-8")
    schema_match = re.search(
        r"pub const ROUTE_AUTH_METADATA_SCHEMA_VERSION_V1:\s*u16\s*=\s*(\d+)\s*;",
        catalog_source,
    )
    if schema_match is None:
        raise GuardError("route-auth metadata schema version is missing")
    schema_version = int(schema_match.group(1))
    if schema_version != ROUTE_AUTH_METADATA_SCHEMA_VERSION:
        raise GuardError("route-auth metadata schema version drifted")
    digest = _sha256(
        json.dumps(
            {
                "route_auth_metadata_schema_version": schema_version,
                "routes": rows,
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    )
    if digest != ROUTE_TUPLE_SHA256:
        raise GuardError(
            "versioned ordered Torii (cfg, method, descriptor, handler, limit, auth) inventory drifted"
        )


def validate_source(source: str) -> None:
    """Validate exact wrapper/route definitions, expansions, and source ordering."""

    wrapper_names: list[str] = []
    positions: dict[str, list[int]] = {}
    for name, family in FAMILIES.items():
        definition, body = _macro_definition(source, name)
        actual_definition = _sha256(_normalized_tokens(definition))
        if actual_definition != family.definition_sha256:
            raise GuardError(f"{name} definition drifted")
        actual_expansion = _expanded_digest(body, family)
        if actual_expansion != family.expanded_preimage_sha256:
            raise GuardError(f"{name} no longer reconstructs its direct preimage")
        invocations = _macro_invocations(source, name)
        if len(invocations) != len(family.invocations):
            raise GuardError(f"{name} invocation count drifted")
        positions[name] = [position for position, _ in invocations]
        for (_, actual), expected in zip(invocations, family.invocations):
            if _normalized_tokens(actual) != _expected_invocation(name, family, expected):
                raise GuardError(f"{name} invocation inventory drifted")
        wrapper_names.extend(row[0] for row in family.rows)

    if len(wrapper_names) != len(set(wrapper_names)):
        raise GuardError("wrapper names must be globally unique")
    for wrapper in wrapper_names:
        if re.search(rf"\basync\s+fn\s+{re.escape(wrapper)}\b", source):
            raise GuardError(f"{wrapper} escaped its guarded macro family")

    usage = source.index("async fn handler_subscription_usage(")
    subscription_positions = positions["subscription_action_handlers"]
    if not subscription_positions[0] < usage < subscription_positions[1]:
        raise GuardError("subscription usage/action logical order drifted")
    if not (
        positions["account_recovery_command_handlers"][0]
        < source.index("async fn handler_post_account_recovery_status(")
    ):
        raise GuardError("account recovery command/status order drifted")
    if not (
        positions["iso_payment_submission_handlers"][0]
        < source.index("async fn handler_iso_lifecycle_submit(")
        < positions["iso_lifecycle_submission_handlers"][0]
        < source.index("async fn handler_iso_status(")
    ):
        raise GuardError("ISO submission/status logical order drifted")
    _validate_route_tables(source)


class ToriiWrapperMacroInventoryTest(unittest.TestCase):
    """Exercise both source inventories and representative fail-closed mutations."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        validate_source(cls.source)

    def test_canonical_wallet_issuance_is_an_exact_signed_read(self) -> None:
        descriptor = "route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_ISSUANCE_GET"
        rows = [row for row in _route_table_rows(self.source) if row[2] == descriptor]
        self.assertEqual(rows, [(
            'feature="app_api"', "GET", descriptor, "kagemusha_wallet::handler",
            "none", "handler:CanonicalAccountSignature",
        )])
        mount = "KAGEMUSHA_LOAD_ISSUANCE_GET => canonical_signature_get(kagemusha_wallet::handler)"
        self.assertEqual(self.source.count(mount), 1)
        for changed in (
            mount.replace("canonical_signature_get", "sdk_get"),
            mount.replace("kagemusha_wallet::handler", "handler_contracts_get"),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(mount, changed, 1))

    def test_subscription_authority_precedes_every_bypass_and_dispatch(self) -> None:
        definition, _ = _macro_definition(self.source, "subscription_action_handlers")
        extractor = "Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,"
        check = 'require_subscription_draft_account(&req.authority, &verified, "subscription action draft")?;'
        self.assertLess(definition.index(check), definition.index("if limits::is_allowed_by_cidr"))
        self.assertLess(definition.index(check), definition.index("return routing::$routing_handler"))
        variants = (
            (extractor, ""),
            (check, ""),
            (check, check.replace("&req.authority", "&verified.account")),
        )
        for old, new in variants:
            with self.subTest(old=old, new=new):
                self.assertEqual(definition.count(old), 1)
                changed = definition.replace(old, new, 1)
                self.assertNotEqual(changed, definition)
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(definition, changed, 1))
        check_line = next(line for line in definition.splitlines(True) if check in line)
        changed = definition.replace(check_line, "", 1)
        anchor = "                let enforce ="
        self.assertEqual(changed.count(anchor), 1)
        changed = changed.replace(anchor, check_line + anchor, 1)
        with self.assertRaises(GuardError):
            validate_source(self.source.replace(definition, changed, 1))

    def test_subscription_mount_auth_method_and_limits_are_inventoried(self) -> None:
        definition = _route_macro_definition(self.source, "mount_subscription_mutation")
        variants = (
            ("catalog_post($handler)", "catalog_get($handler)"),
            (".authenticated_canonical_account_body(", ".authenticated_operator("),
            ("DefaultBodyLimit::max(transaction_max_content_len)", "DefaultBodyLimit::max(0)"),
            ("app_state.clone(),", "app_state,"),
            ("                            transaction_max_content_len,", "                            0,"),
        )
        for old, new in variants:
            with self.subTest(old=old, new=new):
                self.assertEqual(definition.count(old), 1)
                changed = definition.replace(old, new, 1)
                self.assertNotEqual(changed, definition)
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(definition, changed, 1))

    def test_subscription_mount_route_selection_order_and_cfg_are_inventoried(self) -> None:
        invocations = _macro_invocations(self.source, "mount_subscription_mutation")
        self.assertEqual(len(invocations), 8)
        first, second = invocations[0][1], invocations[1][1]
        for old in (first, second):
            self.assertEqual(self.source.count(old), 1)
        variants = (
            "",
            first + "\n" + first,
            first.replace("SUBSCRIPTIONS_PLANS_POST", "SUBSCRIPTIONS_POST", 1),
            first.replace("handler_subscription_plans_create", "handler_subscriptions_create", 1),
            '#[cfg(feature = "telemetry")]\n' + first,
            first.replace("handler_subscription_plans_create", "|request| handler_subscriptions_create(request)", 1),
        )
        for changed in variants:
            with self.subTest(changed=changed):
                self.assertNotEqual(changed, first)
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(first, changed, 1))
        changed = self.source.replace(first, "__subscription_swap__", 1)
        changed = changed.replace(second, first, 1).replace("__subscription_swap__", second, 1)
        with self.assertRaises(GuardError):
            validate_source(changed)

    def test_missing_and_shadowing_macro_definitions_fail(self) -> None:
        for name in (*FAMILIES, *ROUTE_MACRO_DEFINITION_SHA256):
            with self.subTest(name=name):
                marker = f"macro_rules! {name}"
                self.assertEqual(self.source.count(marker), 1)
                with self.assertRaisesRegex(GuardError, "exactly one definition"):
                    validate_source(self.source.replace(marker, f"macro_rules! unguarded_{name}", 1))
                calls = list(re.finditer(rf"\b{re.escape(name)}!\s*[(\[{{]", self.source))
                self.assertTrue(calls)
                position = calls[-1].start()
                comment_cases = name in {"subscription_action_handlers", "mount_subscription_mutation"}
                separators = (" ", "/* outer /* nested */ tail */", "// separator\n") if comment_cases else (" ",)
                delimiters = ("!", "/* before bang */!", "// before bang\n!") if comment_cases else ("!",)
                for separator in separators:
                    for delimiter in delimiters:
                        duplicate = f"macro_rules{delimiter}{separator}{name} {{ ($($ignored:tt)*) => {{}}; }}\n"
                        changed = self.source[:position] + duplicate + self.source[position:]
                        self.assertNotEqual(changed, self.source)
                        with self.assertRaisesRegex(GuardError, "exactly one definition"):
                            validate_source(changed)

    def test_raw_identifier_shadowing_rejects_every_macro_body_delimiter(self) -> None:
        for name in ("subscription_action_handlers", "mount_subscription_mutation"):
            position = _macro_invocations(self.source, name)[-1][0]
            for body in ("{ ($($ignored:tt)*) => {}; }", "(($($ignored:tt)*) => {});", "[($($ignored:tt)*) => {}];"):
                with self.subTest(name=name, body=body):
                    duplicate = f"macro_rules /* separator */ ! r#{name} {body}\n"
                    changed = self.source[:position] + duplicate + self.source[position:]
                    self.assertNotEqual(changed, self.source)
                    with self.assertRaisesRegex(GuardError, "exactly one definition"):
                        validate_source(changed)

    def test_macro_declaration_discovery_ignores_literal_and_comment_decoys(self) -> None:
        source = (
            '// macro_rules! decoy {}\n'
            '/* outer /* macro_rules! nested {} */ tail */\n'
            '"macro_rules! quoted {}";\n'
            'r###"macro_rules! raw {}"###;\n'
            'br#"macro_rules! raw_byte {}"#;\n'
            'cr#"macro_rules! raw_c {}"#;\n'
            "'{' '\\\\' 'a\n"
            'macro_rules /* before */ ! /* after */ actual { () => {}; }\n'
            'macro_rules! second (() => {});\n'
            'macro_rules! r#raw_named { () => {}; }\n'
        )
        expected = (
            ("actual", source.index("macro_rules /* before */")),
            ("second", source.index("macro_rules! second")),
            ("raw_named", source.index("macro_rules! r#raw_named")),
        )
        self.assertEqual(_macro_definition_starts(source), expected)
        self.assertEqual(_unique_macro_start(source, "actual"), expected[0][1])
        self.assertEqual(_macro_definition_starts("/* unterminated"), ())
        self.assertEqual(_macro_definition_starts('r##"unterminated'), ())

    def test_current_source_reconstructs_exact_preimage(self) -> None:
        validate_source(self.source)

    def test_signature_dispatch_inventory_and_order_mutations_fail(self) -> None:
        mutations = (
            (
                "iroha_torii_shared::subscriptions::SubscriptionActionRequest,",
                "iroha_torii_shared::subscriptions::SubscriptionCreateRequest,",
            ),
            (
                "handle_post_v1_subscription_pause",
                "handle_post_v1_subscription_resume",
            ),
            (
                '"v1/accounts/recovery/approve"',
                '"v1/accounts/recovery/finalize"',
            ),
            (
                "runtime.mark_queued(&msg_id);",
                "runtime.mark_queued(&msg_id); runtime.mark_queued(&msg_id);",
            ),
            (
                "(\n"
                "        handler_iso_sese025_submit,\n"
                '        "sese.025",\n'
                '        "v1/iso20022/sese025"\n'
                "    ),",
                "",
            ),
            ("$message_type:literal", "$message_type:expr"),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                self.assertIn(old, self.source)
                mutated = self.source.replace(old, new, 1)
                with self.assertRaises(GuardError):
                    validate_source(mutated)

    def test_recovery_cancel_requires_exact_authenticated_limited_route(self) -> None:
        expected = (
            'feature="app_api"',
            "POST",
            "route_catalog::contracts_and_verification_keys::ACCOUNT_RECOVERY_CANCEL_POST",
            "handler_post_account_recovery_cancel",
            "layer(contracts_body_limit.clone());auth(transaction_max_content_len)",
            "canonical-account(app_state.clone())",
        )
        self.assertEqual(_route_table_rows(self.source).count(expected), 1)
        for old, new in (
            ("handler_post_account_recovery_cancel", "handler_post_account_recovery_finalize"),
            ("crate::routing::AccountRecoveryCancelDto", "crate::routing::AccountRecoveryFinalizeDto"),
            ('"v1/accounts/recovery/cancel"', '"v1/accounts/recovery/finalize"'),
            ("handle_post_account_recovery_cancel", "handle_post_account_recovery_finalize"),
            ("ACCOUNT_RECOVERY_CANCEL_POST", "ACCOUNT_RECOVERY_FINALIZE_POST"),
        ):
            with self.subTest(old=old):
                self.assertIn(old, self.source)
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(old, new, 1))

    def test_ledger_original_carriers_are_core_signed_reads_in_every_build(self) -> None:
        """Reject feature gating, removal, or weakened authentication on ledger carriers."""
        expected = [
            (
                "always", "GET", "route_catalog::core::RESOURCE_NAMES_STATE",
                "resource_names_state::handler", "none", "handler:CanonicalAccountSignature",
            ),
            (
                "always", "POST", "route_catalog::core::AUTHORITY_ORIGINALS",
                "authority_originals::handler",
                "max(iroha_torii_shared::authority_originals::NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1)",
                "handler:CanonicalAccountSignature",
            ),
        ]
        rows = _route_table_rows(self.source)
        for row in expected:
            self.assertEqual(rows.count(row), 1)
        self.assertEqual(
            [row for row in rows if row[2].endswith(("::RESOURCE_NAMES_STATE", "::AUTHORITY_ORIGINALS"))],
            expected,
        )
        names = "RESOURCE_NAMES_STATE => canonical_signature_get(resource_names_state::handler);"
        originals = "AUTHORITY_ORIGINALS => limited_canonical_signature_post(authority_originals::handler, iroha_torii_shared::authority_originals::NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1);"
        for old, new in (
            (names, ""),
            (names, names.replace("canonical_signature_get", "public_get", 1)),
            (originals, ""),
            (originals, originals.replace("limited_canonical_signature_post", "limited_post", 1)),
        ):
            with self.subTest(target=old, changed=new):
                self.assertEqual(self.source.count(old), 1)
                changed = self.source.replace(old, new, 1)
                self.assertNotEqual(changed, self.source)
                with self.assertRaises(GuardError):
                    validate_source(changed)

    def test_ledger_original_carriers_require_exact_signed_limits_and_order(self) -> None:
        """Reject changes to native carrier limits, methods, handlers and mounting order."""
        rows = _route_table_rows(self.source)
        names = next(row for row in rows if row[2] == "route_catalog::core::RESOURCE_NAMES_STATE")
        originals = next(row for row in rows if row[2] == "route_catalog::core::AUTHORITY_ORIGINALS")
        self.assertEqual(rows.index(originals), rows.index(names) + 1)
        mount = "AUTHORITY_ORIGINALS => limited_canonical_signature_post(authority_originals::handler, iroha_torii_shared::authority_originals::NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1);"
        for changed in (
            "",
            mount + "\n            " + mount,
            mount.replace("limited_canonical_signature_post", "limited_public_post", 1),
            mount.replace("limited_canonical_signature_post", "canonical_signature_get", 1),
            mount.replace("authority_originals::NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1", "resource_names_state::NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1", 1),
            mount.replace("AUTHORITY_ORIGINALS =>", "RESOURCE_NAMES_STATE =>", 1),
            mount.replace("authority_originals::handler", "resource_names_state::handler", 1),
        ):
            with self.subTest(changed=changed):
                self.assertEqual(self.source.count(mount), 1)
                self.assertNotEqual(changed, mount)
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(mount, changed, 1))
        declaration = "    fn add_policy_and_pipeline_routes(&self, builder: &mut RouterBuilder)"
        self.assertEqual(self.source.count(declaration), 1)
        with self.assertRaises(GuardError):
            validate_source(self.source.replace(declaration, '    #[cfg(feature = "app_api")]\n' + declaration, 1))
        names_mount = "RESOURCE_NAMES_STATE => canonical_signature_get(resource_names_state::handler);"
        self.assertEqual(self.source.count(names_mount), 1)
        reordered = self.source.replace(names_mount, "__ledger_carrier_swap__", 1)
        reordered = reordered.replace(mount, names_mount, 1).replace("__ledger_carrier_swap__", mount, 1)
        self.assertNotEqual(reordered, self.source)
        with self.assertRaises(GuardError):
            validate_source(reordered)

    def test_route_policy_generator_and_declared_bodies_stay_connected(self) -> None:
        """Guard every actual policy body, its generator, and the connected dispatcher."""
        invocation = _route_policy_declarations(self.source)
        generator = _route_macro_definition(self.source, "define_catalog_route_policies")
        dispatcher = _route_macro_definition(self.source, "catalog_route_policy")
        for definition, old, new in (
            (dispatcher, "$policy! $arguments", "public_get! $arguments"),
            (generator, "$(#[$guard])*", ""),
            (generator, "$pattern => $body", "$pattern => {}"),
            (invocation, '#[cfg(feature = "app_api")]', '#[cfg(feature = "telemetry")]'),
            (invocation, "catalog_get($handler).authenticated_operator($state.clone())",
             "catalog_get($handler)"),
            (invocation, "HandlerAuthentication::PrivateRootOwnerToken",
             "HandlerAuthentication::OptionalCanonicalAccountSignature"),
            (invocation, "DefaultBodyLimit::max($body_limit)", "DefaultBodyLimit::max(0)"),
            (invocation, "canonical_account_proof_post ($handler:path, $state:ident, $proof_limit:expr)",
             "canonical_account_proof_post ($handler:path, $state:ident, $proof_limit:tt)"),
        ):
            with self.subTest(old=old, new=new):
                self.assertIn(old, definition)
                changed = definition.replace(old, new, 1)
                self.assertNotEqual(changed, definition)
                with self.assertRaises(GuardError):
                    validate_source(self.source.replace(definition, changed, 1))
        for replacement in ("", invocation + "\n" + invocation):
            with self.subTest(generator_invocation=replacement):
                with self.assertRaisesRegex(GuardError, "exactly one invocation"):
                    validate_source(self.source.replace(invocation, replacement, 1))
        for prefix in (
            "spoof::",
            "::",
            "spoof /* namespace */ : /* separator */ : ",
            "spoof /* nested /* namespace */ comment */ :: /* call */ ",
            "spoof::r#",
            "r#spoof /* namespace */ : /* separator */ : r#",
        ):
            with self.subTest(generator_namespace=prefix):
                changed = self.source.replace(invocation, prefix + invocation, 1)
                self.assertNotEqual(changed, self.source)
                with self.assertRaisesRegex(GuardError, "connected unqualified namespace"):
                    validate_source(changed)
        validate_source(self.source.replace(invocation, "r#" + invocation, 1))
        for name in ROUTE_POLICY_NAMES:
            for spelling in (name, "r#" + name):
                with self.subTest(policy=spelling):
                    shadow = f"macro_rules! {spelling} {{ ($($unused:tt)*) => {{}}; }}\n"
                    with self.assertRaisesRegex(GuardError, "shadowing direct definition"):
                        validate_source(self.source.replace(dispatcher, shadow + dispatcher, 1))
        decoys = ('// define_catalog_route_policies! { decoy }\n'
                  '/* outer /* define_catalog_route_policies! { decoy } */ tail */\n'
                  'const DECOY: &str = r###"define_catalog_route_policies! { decoy }"###;\n'
                  '// spoof::define_catalog_route_policies! { decoy }\n'
                  '/* outer /* spoof::r#define_catalog_route_policies! { decoy } */ tail */\n'
                  'const QUALIFIED_DECOY: &str = r###"spoof::define_catalog_route_policies! { decoy }"###;\n')
        validate_source(decoys + self.source)

    def test_route_policy_inventory_and_cfg_mutations_fail(self) -> None:
        mutations = (
            (
                "STATUS => unauthenticated_get(handler_status_root);\n"
                "            STATUS_BLOCKS => unauthenticated_get(handler_status_blocks);\n"
                "            STATUS_PEERS => unauthenticated_get(handler_status_peers);",
                "STATUS_PEERS => unauthenticated_get(handler_status_peers);\n"
                "            STATUS_BLOCKS => unauthenticated_get(handler_status_blocks);\n"
                "            STATUS => unauthenticated_get(handler_status_root);",
            ),
            (
                "TRANSACTION => limited_canonical_signed_post("
                "handler_post_transaction, body_limit);",
                "TRANSACTION => limited_canonical_signed_post("
                "handler_post_transaction, iso_body_limit);",
            ),
            (
                '#[cfg(feature = "telemetry")]\n'
                "    #[allow(clippy::unused_self)]\n"
                "    fn add_telemetry_routes",
                '#[cfg(feature = "app_api")]\n'
                "    #[allow(clippy::unused_self)]\n"
                "    fn add_telemetry_routes",
            ),
            (
                "catalog_get($handler).authenticated_operator($state.clone())",
                "catalog_get($handler).authenticated_operator($state)",
            ),
            (
                "HandlerAuthentication::OptionalCanonicalAccountSignature",
                "HandlerAuthentication::CanonicalAccountSignature",
            ),
            (
                "RESOLVE => limited_optional_canonical_signature_post("
                "handler_alias_resolve, EXACT_ALIAS_READ_MAX_BODY_BYTES);",
                "RESOLVE => limited_canonical_signature_post("
                "handler_alias_resolve, EXACT_ALIAS_READ_MAX_BODY_BYTES);",
            ),
            (
                "ACCOUNTS_BY_ACCOUNT_ID_GET => "
                "optional_canonical_signature_get(handler_account_get);",
                "ACCOUNTS_BY_ACCOUNT_ID_GET => public_get(handler_account_get);",
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                self.assertIn(old, self.source)
                mutated = self.source.replace(old, new, 1)
                with self.assertRaises(GuardError):
                    validate_source(mutated)


if __name__ == "__main__":
    unittest.main()
