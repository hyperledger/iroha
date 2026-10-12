#!/usr/bin/env python3
"""Reject unreviewed panic-recovery boundaries in Torii workers."""

from __future__ import annotations

import difflib
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]

# These modules deliberately convert worker failures into request/provider
# errors or a supervised fatal ingress error. A bare blocking task here would
# run outside the physical worker's suppression, signaling process shutdown
# before its JoinError was handled.
NO_BARE_BLOCKING = (
    "crates/iroha_torii/src/lib.rs",
    "crates/iroha_torii/src/lib_pipeline_handlers.rs",
    "crates/iroha_torii/src/routing.rs",
    "crates/iroha_torii/src/routing/signed_query_execution.rs",
    "crates/iroha_torii/src/privacy_issuance_api.rs",
    "crates/iroha_torii/src/da/ingest.rs",
    "crates/iroha_torii/src/da/spool.rs",
    "crates/iroha_torii/src/da/taikai.rs",
    "crates/iroha_torii/src/private_settlement.rs",
    "crates/iroha_torii/src/sorafs/api.rs",
    "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs",
    "crates/iroha_torii/src/sorafs/api/stream_token_enforcement.rs",
    "crates/iroha_torii/src/sorafs/api/stream_token_body.rs",
    "crates/iroha_torii/src/sorafs/stream_token_cleanup.rs",
    "crates/iroha_torii/src/sorafs/gateway_compliance_api.rs",
    "crates/iroha_torii/src/sorafs/hedging_billing_api.rs",
    "crates/iroha_torii/src/sorafs/orderbook_runtime.rs",
    "crates/iroha_torii/src/sorafs/por/persistence_randomness.rs",
    "crates/iroha_torii/src/sorafs/reserve_runtime.rs",
    "crates/iroha_torii/src/zk_attachments.rs",
    "crates/iroha_torii/src/zk_prover.rs",
    "crates/iroha_torii/src/sns.rs",
    "crates/iroha_torii/src/parliament_tle_release.rs",
    "crates/iroha_torii/src/webhook.rs",
    "crates/irohad/src/runtime_provider_broker/platform_provider_clients_01.rs",
    "crates/irohad/src/runtime_provider_broker/platform_provider_clients_03.rs",
    "crates/irohad/src/sorafs_provider_ingest_finalized_query.rs",
    "crates/irohad/src/sorafs_provider_ingest_runtime.rs",
    "crates/irohad/src/sorafs_provider_ingest_runtime/https_source.rs",
    "crates/irohad/src/external_software_signer/musubi_attestation.rs",
    "crates/irohad/src/musubi_publication_service/private_tls_ingress.rs",
    "crates/irohad/src/sorafs_reputation_runtime.rs",
    "crates/irohad/src/sorafs_hedging_billing_runtime.rs",
    "crates/irohad/src/soracloud_runtime.rs",
)
NO_BARE_STD_THREAD = tuple(
    relative
    for relative in NO_BARE_BLOCKING
    if relative.startswith("crates/irohad/")
    and relative != "crates/irohad/src/soracloud_runtime.rs"
)

REQUIRED_SNIPPETS = {
    "crates/iroha_panic_hook/src/lib.rs": (
        "pub fn catch_unwind_suppressed",
        "with_hook_suppressed_async",
        "blocking_worker_reuse_does_not_retain_suppression",
    ),
    "crates/irohad/src/panic_recovery.rs": (
        "pub(crate) fn spawn_blocking_recoverable",
        "pub(crate) fn recover_joined",
        "pub(crate) fn spawn_thread_recoverable",
        "raw_join_failure_remains_an_unsuppressed_invariant",
    ),
    "crates/iroha_torii/src/panic_recovery.rs": (
        "pub(crate) fn spawn_blocking_recoverable",
        "pub(crate) fn spawn_joined_recoverable",
        "pub(crate) async fn join_recoverable",
        "ordinary_invariant_panics_remain_unsuppressed",
    ),
    "crates/iroha_torii/src/da/taikai.rs": (
        "read_optional_regular_file",
        "crate::panic_recovery::spawn_blocking_recoverable",
    ),
    "crates/iroha_torii/src/private_settlement.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::spawn_joined_recoverable",
    ),
    "crates/iroha_torii/src/sorafs/api.rs": (
        "governance_dag_blocking_response",
        "crate::panic_recovery::spawn_blocking_recoverable",
    ),
    "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs": (
        "let worker_issuer = Arc::clone(&issuer);",
        'sorafs_heavy_blocking_task(&state, "SoraFS token issuance", move ||',
        "let issued = worker_issuer.issue_token(",
        "account-read policy changed during token issuance",
    ),
    "crates/iroha_torii/src/sorafs/api/stream_token_enforcement.rs": (
        "pub(super) async fn enforce_stream_token_for_request(",
        'sorafs_heavy_blocking_task(state, "SoraFS stream-token admission", move ||',
        "Some(cleanup.try_reserve().map_err(|_|",
        "ticket.map(|ticket| ticket.arm(capture, record))",
    ),
    "crates/iroha_torii/src/sorafs/api/stream_token_body.rs": (
        "read_chunk_with_stream_token_lease",
        'sorafs_heavy_blocking_task(state, "SoraFS chunk read", move ||',
        "ensure_stream_token_lease_active(&guard)",
    ),
    "crates/iroha_torii/src/sorafs/stream_token_cleanup.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::join_recoverable",
        "let Some(physical) = work.claim_physical() else",
        "drop(permit.send(work));",
        "settlement.unresolved_if_pending();",
    ),
    "crates/iroha_torii/src/sorafs/gateway_compliance_api.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::join_recoverable",
    ),
    "crates/iroha_torii/src/sorafs/hedging_billing_api.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::join_recoverable",
    ),
    "crates/iroha_torii/src/sorafs/orderbook_runtime.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::join_recoverable",
    ),
    "crates/iroha_torii/src/sorafs/por/persistence_randomness.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::join_recoverable",
    ),
    "crates/iroha_torii/src/sorafs/reserve_runtime.rs": (
        "crate::panic_recovery::spawn_blocking_recoverable",
        "crate::panic_recovery::join_recoverable",
    ),
    "crates/iroha_core/src/executor.rs": (
        "iroha_panic_hook::catch_unwind_suppressed",
    ),
}

FORBIDDEN_RECOVERY_SNIPPETS = {
    "crates/iroha_core/src/executor.rs": (
        "std::panic::catch_unwind",
    ),
    "crates/iroha_torii/src/privacy_issuance_api.rs": (
        "catch_unwind(AssertUnwindSafe(operation))",
    ),
    "crates/iroha_torii/src/da/spool.rs": (
        "catch_unwind(AssertUnwindSafe(move || (run)()))",
    ),
}

REVIEWED_TORII_BOUNDARY_INVENTORY = Path(
    "scripts/panic_recovery_boundaries.inventory"
)
CORE_RECOVERY_SOURCE_PATHS = (
    Path("crates/iroha_core/src/executor.rs"),
    Path("crates/iroha_core_zk/src/lib.rs"),
)
CORE_RECOVERY_SUPPORT_PATHS = tuple(
    Path("crates/iroha_core/src") / name
    for name in (
        "executor_account_lineage_tests.rs",
        "executor_contract_deployment_tests.rs",
        "executor_fee_quote_tests.rs",
        "executor_initial_batch_authorization_tests.rs",
        "executor_initial_permission_authority.rs",
        "executor_execution_fee.rs",
        "executor_execution_effects.rs",
        "executor_contract_dispatch_tests.rs",
        "executor_raw_ivm_work_tests.rs",
        "executor_effect_budget_tests.rs",
        "executor_final_promotion_permission_tests.rs",
        "executor_final_promotion_account_permission_tests.rs",
        "executor_sorafs_repair_tests.rs",
        "executor_stream_token_custody_permission_tests.rs",
        "executor_cross_scope_permission_tests.rs",
        "executor_sorafs_market_tests.rs",
        "executor_sorafs_provider_governance_tests.rs",
        "executor_sorafs_pop_registry_tests.rs",
        "executor_stream_token_direct_source_tests.rs",
        "executor_stream_token_gateway_direct_source_tests.rs",
        "executor_stream_token_gateway_permission_tests.rs",
        "executor_stream_token_gateway_check_permission_tests.rs",
        "executor/private_fees.rs",
        "executor_contract_owner_permission_tests.rs",
        "executor_asset_lock_admission_tests.rs",
        "executor/resource_return_tests.rs",
        "executor/root_scope.rs",
        "executor/root_scope/tests.rs",
        "executor_fastpq_rejection_tail.rs",
        "executor_fastpq_rejection_tail/tests.rs",
        "executor_fastpq_rejection_tail/sponsored_alias_tests.rs",
        "executor_sns_attempt_tests.rs",
        "executor_dpn_domain_enrollment_tests.rs",
        "executor_opaque_sccp_record_tests.rs",
        "executor/fee_sponsor_multisig.rs",
        "executor/fee_sponsor_multisig_tests.rs",
        "executor_runtime_memory_tests.rs",
        "executor_public_pin_admission_tests.rs",
        "executor_opaque_monetary_tests.rs",
        "executor/root_scope/tests/amx_roles.rs",
    )
)
AUDITED_SOURCE_PATHS = (
    Path("crates/iroha_torii"),
    Path("crates/build-support"),
    Path("crates/irohad"),
    Path("crates/iroha_panic_hook/src"),
    Path("crates/iroha_core_zk/src"),
    Path("crates/iroha_kagemusha_proof/tests/common/proof_fixtures/omega_hard_fixture.rs"),
    Path("crates/sorafs_manifest/src/signer/final_promotion/tests/statement_fixture_support.rs"),
    Path("crates/sorafs_manifest/src/signer/final_promotion/tests/statement_fixture.message"),
    *CORE_RECOVERY_SOURCE_PATHS,
    *CORE_RECOVERY_SUPPORT_PATHS,
)
REQUIRED_AUDITED_SOURCE_PATHS = AUDITED_SOURCE_PATHS[:2]
BOUNDARY_IDENTIFIERS = {
    "catch_unwind": frozenset({"catch_unwind"}),
    "spawn_blocking": frozenset({"spawn_blocking", "spawn_blocking_on"}),
    "task_spawn": frozenset(
        {"spawn", "spawn_local", "spawn_local_on", "spawn_on", "spawn_scoped"}
    ),
    # Axum starts each upgraded WebSocket callback in a fresh Tokio task. That
    # task does not inherit Torii's request task-local panic suppression, so
    # every callback must be reviewed like an explicit spawn site.
    "upgrade_task": frozenset({"on_upgrade"}),
}
RAW_STRING_PREFIX = re.compile(r"(?:br|rb|r)(?P<hashes>#{0,255})\"")


class RustToken(NamedTuple):
    """One comment-free Rust lexical token used by the source guard."""

    text: str
    start: int
    end: int


def _rust_tokens(source: str) -> list[RustToken]:
    """Lex enough Rust to distinguish code from comments and literals."""

    tokens: list[RustToken] = []
    cursor = 0
    length = len(source)
    while cursor < length:
        char = source[cursor]
        if char.isspace():
            cursor += 1
            continue
        if source.startswith("//", cursor):
            newline = source.find("\n", cursor + 2)
            cursor = length if newline < 0 else newline + 1
            continue
        if source.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            cursor = end
            continue

        raw = RAW_STRING_PREFIX.match(source, cursor)
        if raw is not None:
            delimiter = '"' + raw.group("hashes")
            end = source.find(delimiter, raw.end())
            end = length if end < 0 else end + len(delimiter)
            tokens.append(RustToken(source[cursor:end], cursor, end))
            cursor = end
            continue

        literal_prefix = 1 if char in {"b", "c"} and cursor + 1 < length else 0
        quote_at = cursor + literal_prefix
        if quote_at < length and source[quote_at] == '"':
            end = quote_at + 1
            escaped = False
            while end < length:
                current = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            tokens.append(RustToken(source[cursor:end], cursor, end))
            cursor = end
            continue

        # A lifetime such as `'a` is an identifier marker, while a character
        # literal has a closing quote. Preserve either as a single token.
        if char == "'" or (char == "b" and cursor + 1 < length and source[cursor + 1] == "'"):
            quote_at = cursor if char == "'" else cursor + 1
            end = quote_at + 1
            closed = False
            if end < length and source[end] == "\\":
                escaped = False
                while end < length and source[end] != "\n":
                    current = source[end]
                    end += 1
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == "'":
                        closed = True
                        break
            elif end + 1 < length and source[end + 1] == "'":
                end += 2
                closed = True
            if closed:
                tokens.append(RustToken(source[cursor:end], cursor, end))
                cursor = end
                continue

        if char == "_" or char.isalpha():
            end = cursor + 1
            while end < length and (source[end] == "_" or source[end].isalnum()):
                end += 1
            tokens.append(RustToken(source[cursor:end], cursor, end))
            cursor = end
            continue

        matched = next(
            (
                punctuation
                for punctuation in ("::", "=>", "->", "..=", "...", "..")
                if source.startswith(punctuation, cursor)
            ),
            char,
        )
        end = cursor + len(matched)
        tokens.append(RustToken(matched, cursor, end))
        cursor = end
    return tokens


def _boundary_aliases(tokens: list[RustToken]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    identifier_kind = {
        identifier: kind
        for kind, identifiers in BOUNDARY_IDENTIFIERS.items()
        for identifier in identifiers
    }
    for index, token in enumerate(tokens):
        kind = identifier_kind.get(token.text)
        if kind is None:
            continue

        # Reject import aliases, including aliases exported for use by another
        # module where the original boundary spelling would otherwise vanish.
        if _genuine_use_item_before(tokens, index):
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor].text not in {";", "{", "}", ","}:
                if tokens[cursor].text == "as" and cursor + 1 < len(tokens):
                    alias = tokens[cursor + 1].text
                    if alias == "_" or alias[0].isalpha():
                        aliases[alias] = kind
                    break
                cursor += 1

        # A local function-item binding hides the call spelling just as
        # effectively as an import alias. Collect every binding in compound
        # patterns too: `(recover, _)`, `[recover]`, and struct patterns must
        # not make a boundary invisible to the cross-module inventory.
        binding_kind = _local_binding_start(tokens, index)
        if binding_kind is None:
            continue
        following = tokens[index + 1].text if index + 1 < len(tokens) else ";"
        if following == "(":
            continue
        equals = next(
            (
                cursor
                for cursor in range(binding_kind + 1, index)
                if tokens[cursor].text == "="
            ),
            None,
        )
        if equals is None:
            continue
        for alias in _binding_pattern_identifiers(
            tokens[binding_kind + 1 : equals]
        ):
            aliases[alias] = kind
    return aliases


def _genuine_use_item_before(tokens: list[RustToken], identifier_index: int) -> bool:
    """Return whether an identifier belongs to a Rust use item, not macro input."""

    statement_start = identifier_index
    while statement_start > 0 and tokens[statement_start - 1].text != ";":
        statement_start -= 1
    prefix = tokens[statement_start:identifier_index]
    use_positions = [
        index for index, candidate in enumerate(prefix) if candidate.text == "use"
    ]
    return any(
        not any(candidate.text == "!" for candidate in prefix[:use_at])
        for use_at in use_positions
    )


def _local_binding_start(tokens: list[RustToken], identifier_index: int) -> int | None:
    """Find the enclosing local-binding keyword before one function item."""

    nesting = 0
    closing = {")": "(", "]": "[", "}": "{"}
    openings = set(closing.values())
    for cursor in range(identifier_index - 1, -1, -1):
        text = tokens[cursor].text
        if text in closing:
            nesting += 1
            continue
        if text in openings:
            if nesting:
                nesting -= 1
                continue
            if text == "{":
                return None
        if nesting == 0:
            if text == ";":
                return None
            if text in {"let", "const", "static"}:
                return cursor
    return None


def _binding_pattern_identifiers(tokens: list[RustToken]) -> list[str]:
    """Return identifiers bound by a Rust ``let``/``const``/``static`` pattern."""

    # Discard a top-level type annotation while retaining colons inside struct
    # patterns such as `Pair { recovery: alias }`.
    depth = 0
    pattern_end = len(tokens)
    for index, token in enumerate(tokens):
        if token.text in {"(", "[", "{"}:
            depth += 1
        elif token.text in {")", "]", "}"}:
            depth = max(0, depth - 1)
        elif token.text == ":" and depth == 0:
            pattern_end = index
            break
    pattern = tokens[:pattern_end]
    excluded = {"let", "const", "static", "mut", "ref", "self", "Self"}
    identifiers: list[str] = []
    for index, token in enumerate(pattern):
        name = token.text
        if (
            name in excluded
            or name == "_"
            or not name
            or not (name[0].isalpha() or name[0] == "_")
        ):
            continue
        previous = pattern[index - 1].text if index else ""
        following = pattern[index + 1].text if index + 1 < len(pattern) else ""
        # Paths and tuple/struct constructors name the pattern shape, not a
        # newly bound local. A struct field label before `:` is likewise not a
        # binding; its value pattern is considered separately.
        if previous == "::" or following in {"::", "(", "{", ":"}:
            continue
        identifiers.append(name)
    return identifiers


def _is_rust_call(tokens: list[RustToken], identifier_index: int) -> bool:
    """Return whether an identifier is followed by a call expression."""

    cursor = identifier_index + 1
    if cursor + 1 < len(tokens) and tokens[cursor].text == "::" and tokens[cursor + 1].text == "<":
        cursor += 2
        depth = 1
        while cursor < len(tokens) and depth:
            depth += tokens[cursor].text == "<"
            depth -= tokens[cursor].text == ">"
            cursor += 1
    return cursor < len(tokens) and tokens[cursor].text == "("


def _direct_raw_catch_unwind_lines(source: str) -> list[int]:
    """Return every direct raw ``catch_unwind`` call in one Rust source."""

    tokens = _rust_tokens(source)
    return [
        source.count("\n", 0, token.start) + 1
        for index, token in enumerate(tokens)
        if token.text == "catch_unwind" and _is_rust_call(tokens, index)
    ]


def _boundary_function_item_references(
    tokens: list[RustToken],
) -> list[tuple[int, str, str]]:
    """Return unaliased function-item uses which can hide a later boundary call."""

    identifier_kind = {
        identifier: kind
        for kind, identifiers in BOUNDARY_IDENTIFIERS.items()
        for identifier in identifiers
    }
    references: list[tuple[int, str, str]] = []
    for index, token in enumerate(tokens):
        kind = identifier_kind.get(token.text)
        if kind is None or _is_rust_call(tokens, index):
            continue
        if _genuine_use_item_before(tokens, index):
            continue
        # A function parameter that happens to use a boundary spelling is not
        # a reference to the function item. Do not exempt every `name:` token:
        # macro input can bind a function item with syntax such as
        # `bind!(std::panic::catch_unwind: recover)`.
        if _is_function_parameter_declaration(tokens, index):
            continue
        # Ordinary named local bindings already receive the more actionable
        # alias diagnostic. Keep anonymous bindings and macro-wrapped RHS
        # references in this conservative set (for example
        # `let _ = call!(catch_unwind)`).
        binding_start = _local_binding_start(tokens, index)
        if binding_start is not None:
            equals = next(
                (
                    cursor
                    for cursor in range(binding_start + 1, index)
                    if tokens[cursor].text == "="
                ),
                None,
            )
            if equals is not None and _binding_pattern_identifiers(
                tokens[binding_start + 1 : equals]
            ):
                continue
        references.append((index, kind, token.text))
    return references


def _is_function_parameter_declaration(
    tokens: list[RustToken], identifier_index: int
) -> bool:
    """Return whether one ``name:`` token is inside a Rust ``fn`` parameter list."""

    if (
        identifier_index + 1 >= len(tokens)
        or tokens[identifier_index + 1].text != ":"
    ):
        return False
    nesting = 0
    opening = None
    for cursor in range(identifier_index - 1, -1, -1):
        text = tokens[cursor].text
        if text == ")":
            nesting += 1
        elif text == "(":
            if nesting:
                nesting -= 1
            else:
                opening = cursor
                break
        elif nesting == 0 and text in {"{", "}", ";", "=>", "="}:
            return False
    if opening is None:
        return False

    # The opening parenthesis belongs to a function declaration only when a
    # `fn` keyword occurs in the same header. Braces/semicolons prevent a macro
    # invocation in a function body from borrowing the enclosing `fn` token.
    angle_depth = 0
    for cursor in range(opening - 1, -1, -1):
        text = tokens[cursor].text
        if text == ">":
            angle_depth += 1
        elif text == "<" and angle_depth:
            angle_depth -= 1
        elif angle_depth == 0:
            if text == "fn":
                return True
            if text in {"{", "}", ";", "=>", "=", "!"}:
                return False
    return False


def _bare_blocking_lines(source: str) -> list[int]:
    """Find raw blocking-task calls, including method and `JoinSet` forms."""

    tokens = _rust_tokens(source)
    return [
        source.count("\n", 0, token.start) + 1
        for index, token in enumerate(tokens)
        if token.text in {"spawn_blocking", "spawn_blocking_on"}
        and _is_rust_call(tokens, index)
    ]


def _bare_std_thread_lines(source: str) -> list[int]:
    """Find explicit raw `std::thread` spawn calls in a recoverable module."""

    tokens = _rust_tokens(source)
    failures: list[int] = []
    for index, token in enumerate(tokens):
        if token.text not in {"scope", "spawn", "spawn_scoped", "spawn_unchecked"} or not _is_rust_call(tokens, index):
            continue
        statement_start = index
        while statement_start > 0 and tokens[statement_start - 1].text not in {";", "{", "}"}:
            statement_start -= 1
        prefix = [candidate.text for candidate in tokens[statement_start:index]]
        rendered = " ".join(prefix)
        if (
            "std :: thread ::" in rendered
            or "thread ::" in rendered
            or "std :: thread :: Builder" in rendered
            or "thread :: Builder" in rendered
        ):
            failures.append(source.count("\n", 0, token.start) + 1)

    def inside_recoverable_spawn(builder_index: int) -> bool:
        for cursor in range(builder_index - 1, 3, -1):
            if tokens[cursor].text != "spawn_thread_recoverable":
                continue
            if [candidate.text for candidate in tokens[cursor - 4 : cursor]] != [
                "crate",
                "::",
                "panic_recovery",
                "::",
            ]:
                continue
            if cursor + 1 >= len(tokens) or tokens[cursor + 1].text != "(":
                continue
            depth = 0
            for end in range(cursor + 1, len(tokens)):
                depth += tokens[end].text == "("
                depth -= tokens[end].text == ")"
                if depth == 0:
                    return builder_index < end
        return False

    # A Builder stored for a later `.spawn(...)` loses the `std::thread`
    # prefix at the call site. Only the reviewed wrapper may consume a raw
    # Builder in these modules.
    for index, token in enumerate(tokens):
        if token.text != "Builder" or index < 4:
            continue
        if [candidate.text for candidate in tokens[index - 4 : index]] != [
            "std",
            "::",
            "thread",
            "::",
        ]:
            continue
        if not inside_recoverable_spawn(index):
            failures.append(source.count("\n", 0, token.start) + 1)

    # Aliasing the module, Builder, or spawn function makes the call prefix
    # indistinguishable from an unrelated method. Forbid those indirections in
    # recoverable daemon modules instead of trying to infer expanded names.
    statement_start = 0
    for index, token in enumerate(tokens):
        if token.text != ";":
            continue
        statement = tokens[statement_start : index + 1]
        statement_start = index + 1
        texts = [candidate.text for candidate in statement]
        if "use" in texts:
            use_at = texts.index("use")
            imported = texts[use_at + 1 :]
            # Rust use-trees may put `std` and its `thread` descendant behind
            # arbitrary braces (`use {std::{thread as th}}`). In these few
            # recoverable modules, reject every std/thread use-tree and every
            # alias of std itself rather than under-resolving that grammar.
            if ("std" in imported and "thread" in imported) or (
                "std" in imported and "as" in imported
            ):
                failures.append(
                    source.count("\n", 0, statement[use_at].start) + 1
                )
        if texts[:3] == ["extern", "crate", "std"] and "as" in texts:
            failures.append(source.count("\n", 0, statement[0].start) + 1)
        if "type" in texts and "=" in texts:
            equals = texts.index("=")
            rhs = texts[equals + 1 :]
            rendered_rhs = " ".join(rhs)
            if "std :: thread" in rendered_rhs or "thread :: Builder" in rendered_rhs:
                failures.append(
                    source.count("\n", 0, statement[texts.index("type")].start) + 1
                )
    return sorted(set(failures))


def _source_inventory(path: Path, root: Path) -> tuple[str, dict[str, int]]:
    """Fingerprint one complete source file and summarize boundary spellings."""

    payload = _stable_read_bytes(path)
    source = payload.decode("utf-8")
    tokens = _rust_tokens(source)
    identifier_kind = {
        identifier: kind
        for kind, identifiers in BOUNDARY_IDENTIFIERS.items()
        for identifier in identifiers
    }
    counts = {kind: 0 for kind in BOUNDARY_IDENTIFIERS}
    spelling_counts: dict[tuple[str, str], int] = {}
    for token in tokens:
        kind = identifier_kind.get(token.text)
        if kind is None:
            continue
        counts[kind] += 1
        key = (kind, token.text)
        spelling_counts[key] = spelling_counts.get(key, 0) + 1
    relative = path.relative_to(root).as_posix()
    rendered_sites = ",".join(
        f"{kind}:{identifier}={count}"
        for (kind, identifier), count in sorted(spelling_counts.items())
    ) or "none"
    digest = hashlib.sha256(payload).hexdigest()
    return f"{relative}\t{digest}\t{rendered_sites}", counts


def _stable_read_bytes(path: Path) -> bytes:
    """Read one unchanged, non-linked regular file for inventory hashing."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    before_path = path.lstat()
    if not stat.S_ISREG(before_path.st_mode):
        raise RuntimeError(f"audited source is not a regular file: {path}")
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
            "st_nlink",
        )
        if any(
            getattr(before, field) != getattr(before_path, field)
            for field in stable_fields
        ):
            raise RuntimeError(f"audited source changed before it was pinned: {path}")
        if before.st_nlink != 1:
            raise RuntimeError(f"audited source must have exactly one hard link: {path}")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(
                f"audited source must not be group- or world-writable: {path}"
            )
        payload = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(fd)
        after_path = path.lstat()
        if len(payload) != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            or getattr(before, field) != getattr(after_path, field)
            for field in stable_fields
        ):
            raise RuntimeError(f"audited source changed while it was read: {path}")
        return bytes(payload)
    finally:
        os.close(fd)


def _git_audited_entries(root: Path) -> list[tuple[str, Path]] | None:
    """Return indexed/untracked modes and paths, or ``None`` outside Git."""

    completed = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--stage",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *(relative.as_posix() for relative in AUDITED_SOURCE_PATHS),
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode == 0:
        entries: list[tuple[str, Path]] = []
        for raw in completed.stdout.split(b"\0"):
            if not raw:
                continue
            metadata, separator, encoded_path = raw.partition(b"\t")
            if not separator:
                entries.append(("untracked", Path(raw.decode("utf-8"))))
                continue
            fields = metadata.split()
            if not separator or len(fields) != 3:
                continue
            mode = fields[0].decode("ascii")
            stage = fields[2].decode("ascii")
            if stage != "0":
                mode = f"conflict:{stage}:{mode}"
            entries.append(
                (mode, Path(encoded_path.decode("utf-8")))
            )
        return entries
    return None


def torii_audited_files(root: Path) -> list[Path]:
    """Return every repository file under the two audited source roots."""

    git_entries = _git_audited_entries(root)
    if git_entries is not None:
        return sorted(
            path
            for mode, relative in git_entries
            if mode != "160000"
            and (path := root / relative).is_file()
            and not path.is_symlink()
        )

    # Synthetic guard tests are intentionally not Git repositories. In that
    # setting every regular file is part of the candidate source closure.
    paths: list[Path] = []
    for relative_root in AUDITED_SOURCE_PATHS:
        source_root = root / relative_root
        if source_root.is_file() and not source_root.is_symlink():
            paths.append(source_root)
        elif source_root.is_dir():
            paths.extend(
                path
                for path in source_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
    return sorted(paths)


def _rust_path_literal(token: str) -> str | None:
    """Decode the deliberately narrow path-literal grammar accepted by the guard."""

    quoted = re.fullmatch(r'"(?P<body>[^"\\]*)"', token, re.DOTALL)
    if quoted is not None:
        return quoted.group("body")
    raw = re.fullmatch(
        r'r(?P<hashes>#{0,255})"(?P<body>.*)"(?P=hashes)',
        token,
        re.DOTALL,
    )
    if raw is not None:
        return raw.group("body")
    return None


def _attribute_end(tokens: list[RustToken], start: int) -> int | None:
    """Return the closing bracket for the attribute beginning at ``# [``."""

    if (
        start + 1 >= len(tokens)
        or tokens[start].text != "#"
        or tokens[start + 1].text != "["
    ):
        return None
    depth = 0
    for index in range(start + 1, len(tokens)):
        if tokens[index].text == "[":
            depth += 1
        elif tokens[index].text == "]":
            depth -= 1
            if depth == 0:
                return index
    return None


def _rust_module_directories(
    path: Path, *, cargo_target_root: bool = False
) -> tuple[Path, ...]:
    """Return every plausible child-module base for one Rust source file.

    A source can simultaneously be a Cargo crate root and a module reached by
    ``mod``/``#[path]`` from another crate root. Those two contexts resolve a
    nested ``mod child;`` differently, so the closed guard probes and seals the
    union rather than collapsing the file to one canonical-path visit.
    """

    ordinary = path.parent if path.name == "mod.rs" else path.parent / path.stem
    crate_root = (
        cargo_target_root
        or path.name in {"lib.rs", "main.rs", "build.rs", "script.rs"}
        or path.parent.name in {"tests", "examples", "benches", "bin"}
    )
    if not crate_root or ordinary == path.parent:
        return (ordinary,)
    return (path.parent, ordinary)


def _cargo_target_source_declarations(
    manifest: Path, data: dict[str, object], root: Path
) -> tuple[list[tuple[str, object]], list[str]]:
    """Return explicit and existing auto-discovered Cargo source targets."""

    relative_manifest = manifest.relative_to(root).as_posix()
    declarations: list[tuple[str, object]] = []
    failures: list[str] = []
    package = data.get("package", {})
    if not isinstance(package, dict):
        package = {}

    if "build" in package:
        build = package["build"]
        if isinstance(build, str):
            declarations.append(("package build script", build))
        elif build is not False:
            failures.append(
                f"{relative_manifest}: package build must be false or one static path"
            )
    elif (manifest.parent / "build.rs").is_file():
        declarations.append(("auto-discovered package build script", "build.rs"))

    library = data.get("lib")
    if isinstance(library, dict) and "path" in library:
        declarations.append(("lib target", library["path"]))
    elif (manifest.parent / "src/lib.rs").is_file():
        declarations.append(("auto-discovered lib target", "src/lib.rs"))

    for section in ("bin", "example", "test", "bench"):
        entries = data.get(section, [])
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            if "path" in entry:
                declarations.append(
                    (f"{section} target #{index + 1}", entry["path"])
                )
                continue
            package_name = package.get("name")
            target_name = entry.get("name", package_name)
            if (
                not isinstance(target_name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", target_name)
                is None
            ):
                failures.append(
                    f"{relative_manifest}: {section} target #{index + 1} "
                    "without path must have one bounded static name"
                )
                continue
            if section == "bin":
                inferred = (
                    "src/main.rs",
                    f"src/bin/{target_name}.rs",
                    f"src/bin/{target_name}/main.rs",
                )
            else:
                directory = {
                    "example": "examples",
                    "test": "tests",
                    "bench": "benches",
                }[section]
                inferred = (
                    f"{directory}/{target_name}.rs",
                    f"{directory}/{target_name}/main.rs",
                )
            existing = [
                path for path in inferred if (manifest.parent / path).is_file()
            ]
            # Seal every plausible conventional source. If no candidate exists,
            # retain the primary Cargo convention so validation fails closed.
            for path in existing or inferred[:1]:
                declarations.append(
                    (f"inferred {section} target #{index + 1}", path)
                )

    automatic: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        (
            "bin",
            "autobins",
            ("src/main.rs", "src/bin/*.rs", "src/bin/*/main.rs"),
        ),
        (
            "example",
            "autoexamples",
            ("examples/*.rs", "examples/*/main.rs"),
        ),
        (
            "test",
            "autotests",
            ("tests/*.rs", "tests/*/main.rs"),
        ),
        (
            "bench",
            "autobenches",
            ("benches/*.rs", "benches/*/main.rs"),
        ),
    )
    for section, switch, patterns in automatic:
        if package.get(switch, True) is False:
            continue
        for pattern in patterns:
            for candidate in sorted(manifest.parent.glob(pattern)):
                if candidate.is_file():
                    declarations.append(
                        (
                            f"auto-discovered {section} target",
                            candidate.relative_to(manifest.parent).as_posix(),
                        )
                    )
    return declarations, failures


def _cargo_target_source_paths(
    root: Path, audited_files: list[Path] | None = None
) -> tuple[list[Path], list[str]]:
    """Resolve Cargo targets even when Git ignore rules hide their sources."""

    audited_roots = tuple((root / relative).resolve() for relative in AUDITED_SOURCE_PATHS)
    sources: list[Path] = []
    failures: list[str] = []
    if audited_files is None:
        audited_files = torii_audited_files(root)
    manifests = [path for path in audited_files if path.name == "Cargo.toml"]
    for manifest in manifests:
        relative_manifest = manifest.relative_to(root).as_posix()
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            failures.append(f"{relative_manifest}: cannot validate Cargo targets: {error}")
            continue
        declarations, declaration_failures = _cargo_target_source_declarations(
            manifest, data, root
        )
        failures.extend(declaration_failures)
        for _label, raw_path in declarations:
            if not isinstance(raw_path, str) or not raw_path or "\0" in raw_path:
                continue
            candidate = manifest.parent / raw_path
            target = candidate.resolve()
            if (
                any(target.is_relative_to(source_root) for source_root in audited_roots)
                and candidate.is_file()
                and not candidate.is_symlink()
            ):
                sources.append(target)
    return sorted(set(sources)), failures


def _inline_module_contexts(tokens: list[RustToken]) -> list[tuple[str, ...]]:
    """Return the inline-module directory stack at each token."""

    inline_openings: dict[int, str] = {}
    for index, token in enumerate(tokens):
        if token.text != "mod" or index + 2 >= len(tokens):
            continue
        name = tokens[index + 1].text
        if (name[0].isalpha() or name[0] == "_") and tokens[index + 2].text == "{":
            inline_openings[index + 2] = name

    contexts: list[tuple[str, ...]] = []
    stack: list[tuple[int, str]] = []
    depth = 0
    for index, token in enumerate(tokens):
        contexts.append(tuple(name for _, name in stack))
        if token.text == "{":
            depth += 1
            if index in inline_openings:
                stack.append((depth, inline_openings[index]))
        elif token.text == "}":
            while stack and stack[-1][0] == depth:
                stack.pop()
            depth = max(0, depth - 1)
    return contexts


def _rust_textual_source_references(
    path: Path,
    root: Path,
    *,
    cargo_target_roots: set[Path] | None = None,
) -> tuple[list[Path], list[str]]:
    """Resolve literal includes plus explicit and conventional Rust modules."""

    if cargo_target_roots is None:
        cargo_target_roots = set()
    module_directories = _rust_module_directories(
        path, cargo_target_root=path.resolve() in cargo_target_roots
    )
    source = path.read_text(encoding="utf-8")
    tokens = _rust_tokens(source)
    contexts = _inline_module_contexts(tokens)
    # (kind, source token, literal, module-relative base)
    references: list[tuple[str, RustToken, str | None, Path]] = []
    path_overrides: set[int] = set()

    for index, token in enumerate(tokens):
        if (
            token.text == "include"
            and index + 2 < len(tokens)
            and tokens[index + 1].text == "!"
            and tokens[index + 2].text in {"(", "{", "["}
        ):
            closing = {"(": ")", "{": "}", "[": "]"}[tokens[index + 2].text]
            literal = None
            if index + 4 < len(tokens):
                candidate_literal = _rust_path_literal(tokens[index + 3].text)
                close_at = index + 4
                if tokens[close_at].text == ",":
                    close_at += 1
                if (
                    candidate_literal is not None
                    and close_at < len(tokens)
                    and tokens[close_at].text == closing
                ):
                    literal = candidate_literal
            references.append(("include!", token, literal, path.parent))

        if token.text != "#" or index + 1 >= len(tokens) or tokens[index + 1].text != "[":
            continue
        end = _attribute_end(tokens, index)
        if end is None:
            references.append(("#[path]", token, None, path.parent))
            continue
        literal = None
        path_token = token
        for cursor in range(index + 2, end - 1):
            if tokens[cursor].text == "path" and tokens[cursor + 1].text == "=":
                literal = _rust_path_literal(tokens[cursor + 2].text)
                path_token = tokens[cursor]
                break
        if path_token is token:
            continue
        cursor = end + 1
        while cursor < len(tokens) and tokens[cursor].text == "#":
            next_end = _attribute_end(tokens, cursor)
            if next_end is None:
                break
            cursor = next_end + 1
        if cursor < len(tokens) and tokens[cursor].text == "pub":
            cursor += 1
            if cursor < len(tokens) and tokens[cursor].text == "(":
                depth = 1
                cursor += 1
                while cursor < len(tokens) and depth:
                    depth += tokens[cursor].text == "("
                    depth -= tokens[cursor].text == ")"
                    cursor += 1
        if cursor < len(tokens) and tokens[cursor].text == "mod":
            path_overrides.add(cursor)
        # Explicit #[path] values are relative to the containing source file;
        # each enclosing inline module contributes one directory component.
        # Unlike an ordinary `mod child;`, an out-of-line module's own stem is
        # not inserted into this base.
        module_bases = [path.parent.joinpath(*contexts[index])]
        if literal:
            existing_bases = [
                base
                for base in module_bases
                if (base / literal).exists() or (base / literal).is_symlink()
            ]
        else:
            existing_bases = []
        for module_base in existing_bases or module_bases[:1]:
            references.append(("#[path]", path_token, literal, module_base))

    for index, token in enumerate(tokens):
        if token.text != "mod" or index in path_overrides or index + 2 >= len(tokens):
            continue
        name = tokens[index + 1].text
        if not (name[0].isalpha() or name[0] == "_") or tokens[index + 2].text != ";":
            continue
        existing: list[Path] = []
        for module_directory in module_directories:
            module_base = module_directory.joinpath(*contexts[index])
            candidates = (
                module_base / f"{name}.rs",
                module_base / name / "mod.rs",
            )
            context_existing = [
                candidate for candidate in candidates if candidate.is_file()
            ]
            if len(context_existing) > 1:
                relative_source = path.relative_to(root).as_posix()
                line = source.count("\n", 0, token.start) + 1
                rendered = ", ".join(
                    candidate.relative_to(root).as_posix()
                    for candidate in context_existing
                )
                return [], [
                    f"{relative_source}:{line}: mod {name} has ambiguous source files: {rendered}"
                ]
            existing.extend(context_existing)
        existing = sorted(set(existing))
        if existing:
            for candidate in existing:
                references.append(("mod", token, candidate.name, candidate.parent))
        else:
            module_base = module_directories[0].joinpath(*contexts[index])
            references.append(("mod", token, None, module_base))

    audited_roots = tuple((root / relative).resolve() for relative in AUDITED_SOURCE_PATHS)
    resolved: list[Path] = []
    failures: list[str] = []
    relative_source = path.relative_to(root).as_posix()
    for kind, token, literal, base in references:
        line = source.count("\n", 0, token.start) + 1
        if literal is None or not literal or "\0" in literal:
            failures.append(
                f"{relative_source}:{line}: {kind} must name one static local source file"
            )
            continue
        candidate = base / literal
        target = candidate.resolve()
        if not any(target.is_relative_to(source_root) for source_root in audited_roots):
            failures.append(
                f"{relative_source}:{line}: {kind} source path escapes the audited source roots: {literal}"
            )
            continue
        if not candidate.is_file() or candidate.is_symlink():
            failures.append(
                f"{relative_source}:{line}: {kind} source path is missing or not a regular file: {literal}"
            )
            continue
        resolved.append(target)
    return resolved, failures


def torii_rust_source_closure(
    root: Path, audited_files: list[Path] | None = None
) -> tuple[list[Path], list[str]]:
    """Return every textual Rust source reachable inside the audited roots."""

    if audited_files is None:
        audited_files = torii_audited_files(root)
    pending = [path for path in audited_files if path.suffix == ".rs"]

    cargo_sources, cargo_failures = _cargo_target_source_paths(root, audited_files)
    cargo_target_roots = {path.resolve() for path in cargo_sources}
    pending.extend(cargo_sources)

    sources: dict[Path, Path] = {}
    failures: list[str] = list(cargo_failures)
    while pending:
        path = pending.pop()
        canonical = path.resolve()
        if canonical in sources or path.is_symlink() or not path.is_file():
            continue
        sources[canonical] = path
        try:
            references, reference_failures = _rust_textual_source_references(
                path, root, cargo_target_roots=cargo_target_roots
            )
        except UnicodeDecodeError:
            failures.append(
                f"{path.relative_to(root).as_posix()}: textual Rust source must be UTF-8"
            )
            continue
        failures.extend(reference_failures)
        pending.extend(references)
    return sorted(sources.values()), sorted(set(failures))


def torii_boundary_inventory(
    root: Path,
    source_paths: list[Path] | None = None,
    audited_paths: list[Path] | None = None,
) -> tuple[list[str], str, dict[str, int]]:
    """Return the complete Torii and shared-build repository-file closure."""

    records: list[str] = []
    counts = {kind: 0 for kind in BOUNDARY_IDENTIFIERS}
    if audited_paths is None:
        audited_paths = torii_audited_files(root)
    if source_paths is None:
        source_paths, _ = torii_rust_source_closure(root, audited_paths)
    source_canonicals = {path.resolve() for path in source_paths}
    audited_files = {path.resolve(): path for path in audited_paths}
    audited_files.update({path.resolve(): path for path in source_paths})
    for canonical, path in sorted(audited_files.items(), key=lambda item: item[1]):
        if canonical in source_canonicals:
            source_record, source_counts = _source_inventory(path, root)
            records.append(source_record)
            for kind, count in source_counts.items():
                counts[kind] += count
            continue
        relative = path.relative_to(root).as_posix()
        digest = hashlib.sha256(_stable_read_bytes(path)).hexdigest()
        kind = "manifest" if path.name == "Cargo.toml" else "repository-file"
        records.append(f"{relative}\t{digest}\t{kind}")
    records.sort()
    encoded = ("\n".join(records) + ("\n" if records else "")).encode("utf-8")
    return records, hashlib.sha256(encoded).hexdigest(), counts


def _reviewed_inventory(root: Path) -> list[str]:
    path = root / REVIEWED_TORII_BOUNDARY_INVENTORY
    if not path.is_file():
        return []
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


def torii_boundary_alias_failures(
    root: Path, source_paths: list[Path] | None = None
) -> list[str]:
    """Reject aliases that could hide boundary use in another Rust module."""

    failures: list[str] = []
    if source_paths is None:
        source_paths, _ = torii_rust_source_closure(root)
    for path in source_paths:
        source = path.read_text(encoding="utf-8")
        tokens = _rust_tokens(source)
        aliases = _boundary_aliases(tokens)
        for alias, kind in sorted(aliases.items()):
            relative = path.relative_to(root).as_posix()
            failures.append(
                f"{relative}: {kind} boundary alias {alias!r} is forbidden; "
                "use the audited spelling so cross-module calls remain visible"
            )
        for index, kind, identifier in _boundary_function_item_references(tokens):
            relative = path.relative_to(root).as_posix()
            line = source.count("\n", 0, tokens[index].start) + 1
            failures.append(
                f"{relative}:{line}: {kind} boundary function item {identifier!r} "
                "is forbidden outside a direct audited call"
            )
    return failures


def torii_source_path_failures(
    root: Path,
    source_closure: tuple[list[Path], list[str]] | None = None,
    audited_paths: list[Path] | None = None,
) -> list[str]:
    """Reject source-closure indirection, escapes, and Git submodules."""

    failures: list[str] = []
    if audited_paths is None:
        audited_paths = torii_audited_files(root)
    if source_closure is None:
        source_closure = torii_rust_source_closure(root, audited_paths)
    source_paths, rust_source_failures = source_closure
    failures.extend(rust_source_failures)
    audited_directories = {root}
    for relative_root in AUDITED_SOURCE_PATHS:
        parent = (root / relative_root).parent
        while parent != root:
            if parent.exists():
                audited_directories.add(parent)
            parent = parent.parent
    for directory in sorted(audited_directories):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            failures.append(
                f"{directory.relative_to(root).as_posix()}: audited source parent "
                "is not a directory"
            )
        elif info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            relative = directory.relative_to(root).as_posix() or "."
            failures.append(
                f"{relative}: audited source parent must not be group- or "
                "world-writable"
            )
    git_entries = _git_audited_entries(root)
    if git_entries is not None:
        for mode, relative in git_entries:
            if mode == "160000":
                failures.append(
                    f"{relative.as_posix()}: gitlink/submodule is forbidden in the audited source closure"
                )
            elif mode.startswith("conflict:"):
                stage = mode.split(":", 2)[1]
                failures.append(
                    f"{relative.as_posix()}: unresolved Git index stage {stage} is forbidden in the audited source closure"
                )
    for relative_root in AUDITED_SOURCE_PATHS:
        source_root = root / relative_root
        if not source_root.exists():
            if relative_root in REQUIRED_AUDITED_SOURCE_PATHS:
                failures.append(f"missing audited source root {relative_root.as_posix()}")
            continue
        candidates = [source_root]
        if source_root.is_dir():
            candidates.extend(source_root.rglob("*"))
        for path in candidates:
            if path.is_symlink():
                failures.append(
                    f"{path.relative_to(root).as_posix()}: symlink is forbidden in the audited source closure"
                )
            elif path.is_dir() and path.stat().st_mode & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                failures.append(
                    f"{path.relative_to(root).as_posix()}: audited source parent "
                    "must not be group- or world-writable"
                )

    audited_roots = tuple((root / relative).resolve() for relative in AUDITED_SOURCE_PATHS)
    audited_files = {path.resolve() for path in audited_paths}
    if git_entries is not None:
        for source_path in source_paths:
            if source_path.resolve() not in audited_files:
                failures.append(
                    f"{source_path.relative_to(root).as_posix()}: textual module source is "
                    "outside the sealed repository-file inventory"
                )
    manifests = [path for path in audited_paths if path.name == "Cargo.toml"]
    for manifest in manifests:
        relative_manifest = manifest.relative_to(root).as_posix()
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            failures.append(f"{relative_manifest}: cannot validate Cargo targets: {error}")
            continue

        target_paths, declaration_failures = _cargo_target_source_declarations(
            manifest, data, root
        )
        failures.extend(declaration_failures)

        for label, raw_path in target_paths:
            if not isinstance(raw_path, str) or not raw_path or "\0" in raw_path:
                failures.append(
                    f"{relative_manifest}: {label} must name one static local source file"
                )
                continue
            candidate = manifest.parent / raw_path
            target = candidate.resolve()
            if not any(target.is_relative_to(source_root) for source_root in audited_roots):
                failures.append(
                    f"{relative_manifest}: {label} escapes the audited source roots: {raw_path}"
                )
                continue
            if not candidate.is_file() or candidate.is_symlink():
                failures.append(
                    f"{relative_manifest}: {label} is missing or not a regular sealed file: {raw_path}"
                )
                continue
            if target not in audited_files:
                failures.append(
                    f"{relative_manifest}: {label} is outside the sealed repository-file inventory: {raw_path}"
                )

    return failures


def closed_torii_boundary_inventory_failures(
    root: Path,
    expected_records: list[str] | None = None,
    observed_inventory: tuple[list[str], str, dict[str, int]] | None = None,
) -> list[str]:
    """Return drift from the reviewed complete Torii-source inventory."""

    if observed_inventory is None:
        observed_inventory = torii_boundary_inventory(root)
    observed_records, observed_digest, observed_counts = observed_inventory
    if expected_records is None:
        expected_records = _reviewed_inventory(root)
    expected_encoded = (
        "\n".join(expected_records) + ("\n" if expected_records else "")
    ).encode("utf-8")
    expected_digest = hashlib.sha256(expected_encoded).hexdigest()
    expected_counts = {kind: 0 for kind in BOUNDARY_IDENTIFIERS}
    for record in expected_records:
        sites = record.rsplit("\t", 1)[-1]
        for site in sites.split(","):
            if not site or "=" not in site or ":" not in site:
                continue
            kind = site.split(":", 1)[0]
            if kind in expected_counts:
                expected_counts[kind] += int(site.rsplit("=", 1)[1])

    failures: list[str] = []
    for token in sorted(BOUNDARY_IDENTIFIERS):
        expected_count = expected_counts.get(token, 0)
        observed_count = observed_counts[token]
        if observed_count != expected_count:
            failures.append(
                f"Torii {token} site count drifted "
                f"(expected {expected_count}, found {observed_count})"
            )
    if observed_digest != expected_digest:
        failures.append(
            "Torii recovery-boundary source inventory drifted "
            f"(expected {expected_digest}, found {observed_digest}); "
            "review --print-inventory output before updating the digest"
        )
        diff = list(
            difflib.unified_diff(
                expected_records,
                observed_records,
                fromfile=REVIEWED_TORII_BOUNDARY_INVENTORY.as_posix(),
                tofile="observed Torii boundary inventory",
                lineterm="",
            )
        )
        failures.extend(diff[:80])
        if len(diff) > 80:
            failures.append(f"... inventory diff truncated ({len(diff) - 80} more lines)")
    return failures


def _panic_semantic_source_fingerprints(root: Path) -> dict[str, str]:
    """Fingerprint every source read by the non-inventory semantic checks."""

    relatives = set(NO_BARE_BLOCKING) | set(NO_BARE_STD_THREAD)
    relatives.update(REQUIRED_SNIPPETS)
    relatives.update(FORBIDDEN_RECOVERY_SNIPPETS)
    return {
        relative: hashlib.sha256(_stable_read_bytes(root / relative)).hexdigest()
        for relative in sorted(relatives)
    }


def _required_recovery_marker_failures(relative: str, source: str) -> list[str]:
    """Preserve exact missing-marker diagnostics for one audited source owner."""

    return [
        f"{relative}: missing audited recovery marker {snippet!r}"
        for snippet in REQUIRED_SNIPPETS[relative]
        if snippet not in source
    ]


def _token_issuance_worker_policy_failures(source: str) -> list[str]:
    """Seal the original owned worker and its pre/post finalized-policy checks."""

    relative = "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs"
    failure = f"{relative}: token issuance lost its bounded owned pre/post policy worker"
    texts = [token.text for token in _rust_tokens(source)]

    def occurrences(sequence: str, values: list[str]) -> list[int]:
        expected = [token.text for token in _rust_tokens(sequence)]
        return [
            index for index in range(len(values) - len(expected) + 1)
            if values[index:index + len(expected)] == expected
        ]

    def body_after(opening: int, values: list[str]) -> tuple[list[str], int] | None:
        depth = 1
        for index in range(opening + 1, len(values)):
            depth += (values[index] == "{") - (values[index] == "}")
            if depth == 0:
                return values[opening + 1:index], index
        return None

    functions = occurrences("async fn issue_storage_token(", texts)
    if len(functions) != 1:
        return [failure]
    opening = next(
        (index for index in range(functions[0], len(texts)) if texts[index] == "{"),
        None,
    )
    if opening is None:
        return [failure]
    function = body_after(opening, texts)
    if function is None:
        return [failure]
    values, _ = function
    owner = """
        let worker_issuer = Arc::clone(&issuer);
        let worker_state = state.state.clone();
        let issued = match sorafs_heavy_blocking_task(
            &state, "SoraFS token issuance", move || {
    """
    workers = occurrences(owner, values)
    if len(workers) != 1:
        return [failure]
    worker_opening = workers[0] + len(_rust_tokens(owner)) - 1
    worker = body_after(worker_opening, values)
    if worker is None:
        return [failure]
    body, closing = worker
    expected_body = """
        let policy = account.as_ref().map(|account| {
            current_account_read_policy(&worker_state, account, ProviderId::new(provider_id))
        }).transpose()?;
        let issued = worker_issuer.issue_token(
            quota_subject, manifest_cid, provider_id, profile_handle, overrides, policy.as_ref(),
        );
        if let Some(account) = &account {
            if Some(current_account_read_policy(
                &worker_state, account, ProviderId::new(provider_id),
            )?) != policy {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    "account-read policy changed during token issuance",
                ));
            }
        }
        Ok(issued)
    """
    expected = [token.text for token in _rust_tokens(expected_body)]
    joined = [token.text for token in _rust_tokens("""
        }).await {
            Ok(issued) => issued,
            Err(response) => return response,
        };
    """)]
    if body != expected or values[closing:closing + len(joined)] != joined:
        return [failure]
    return []


def main() -> int:
    audited_paths = torii_audited_files(ROOT)
    source_closure = torii_rust_source_closure(ROOT, audited_paths)
    source_paths, _ = source_closure
    observed_inventory = torii_boundary_inventory(
        ROOT, source_paths=source_paths, audited_paths=audited_paths
    )
    semantic_fingerprints = _panic_semantic_source_fingerprints(ROOT)
    if "--print-inventory" in sys.argv[1:]:
        records, digest, counts = observed_inventory
        for record in records:
            print(record)
        print(f"sha256\t{digest}")
        for token in sorted(counts):
            print(f"count\t{token}\t{counts[token]}")
    failures = closed_torii_boundary_inventory_failures(
        ROOT, observed_inventory=observed_inventory
    )
    failures.extend(
        torii_source_path_failures(
            ROOT, source_closure=source_closure, audited_paths=audited_paths
        )
    )
    failures.extend(torii_boundary_alias_failures(ROOT, source_paths))
    for relative in NO_BARE_BLOCKING:
        source = (ROOT / relative).read_text(encoding="utf-8")
        lines = _bare_blocking_lines(source)
        if lines:
            rendered_lines = ", ".join(str(line) for line in lines)
            failures.append(f"{relative}: bare spawn_blocking at line(s) {rendered_lines}")
    for relative in NO_BARE_STD_THREAD:
        source = (ROOT / relative).read_text(encoding="utf-8")
        lines = _bare_std_thread_lines(source)
        if lines:
            rendered_lines = ", ".join(str(line) for line in lines)
            failures.append(f"{relative}: bare std::thread spawn at line(s) {rendered_lines}")

    for relative in REQUIRED_SNIPPETS:
        source = (ROOT / relative).read_text(encoding="utf-8")
        failures.extend(_required_recovery_marker_failures(relative, source))

    failures.extend(_token_issuance_worker_policy_failures(
        (ROOT / "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs")
        .read_text(encoding="utf-8")
    ))

    for relative, snippets in FORBIDDEN_RECOVERY_SNIPPETS.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet in source:
                failures.append(f"{relative}: unreviewed bare recovery boundary {snippet!r}")

    reviewed_raw_catch_counts = {
        "crates/iroha_core/src/executor.rs": 0,
        "crates/iroha_core_zk/src/lib.rs": 0,
    }
    for relative, expected_count in reviewed_raw_catch_counts.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        lines = _direct_raw_catch_unwind_lines(source)
        if len(lines) != expected_count:
            rendered = ", ".join(str(line) for line in lines) or "none"
            failures.append(
                f"{relative}: raw catch_unwind call count drifted "
                f"(expected {expected_count}, found {len(lines)} at {rendered})"
            )

    final_audited_paths = torii_audited_files(ROOT)
    final_source_closure = torii_rust_source_closure(ROOT, final_audited_paths)
    final_inventory = torii_boundary_inventory(
        ROOT,
        source_paths=final_source_closure[0],
        audited_paths=final_audited_paths,
    )
    if final_inventory != observed_inventory:
        failures.append(
            "panic recovery source inventory changed during guard validation; rerun "
            "against a stable source tree"
        )
    if _panic_semantic_source_fingerprints(ROOT) != semantic_fingerprints:
        failures.append(
            "panic recovery semantic sources changed during guard validation; rerun "
            "against a stable source tree"
        )

    if failures:
        print("panic recovery boundary guard failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("panic recovery boundary guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
