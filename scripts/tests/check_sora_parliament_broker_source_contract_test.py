"""Mutation coverage for retired Parliament broker exposure and operation IDs."""

from __future__ import annotations

import ast
import inspect
import re

import pytest

from scripts.formal import check_sora_parliament_source_contract as guard


BROKER_ROOT = "crates/irohad/src/runtime_provider_broker/"
PRIMITIVES = BROKER_ROOT + "protocol_primitives.rs"
VALIDATION = BROKER_ROOT + "protocol_operation_validation.rs"
DISPATCH = BROKER_ROOT + "platform_operation_dispatch.rs"
CODEC = BROKER_ROOT + "protocol_codec_and_bindings.rs"
TRANSPORT = BROKER_ROOT + "platform_server_transport.rs"


def _replace_source(path: str, changed: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Substitute an in-memory source while retaining all other actual owners."""
    original_read = guard.read
    monkeypatch.setattr(guard, "read", lambda p: changed if p == path else original_read(p))


def test_retired_broker_source_baseline_and_entrypoint() -> None:
    """Current absence and unknown IDs are checked; no replacement is qualified."""
    guard.require_retired_parliament_broker_exposure()
    calls = [node for node in ast.walk(ast.parse(inspect.getsource(guard.main)))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert sum(node.func.id == "require_retired_parliament_broker_exposure" for node in calls) == 1
    for retained in ("require_opaque_release_authorizations", "require_opaque_release_projection",
                     "require_opaque_casting_authorization", "require_threshold_signer_startup_readiness"):
        assert sum(node.func.id == retained for node in calls) == 1


@pytest.mark.parametrize("path", guard.RETIRED_PARLIAMENT_BROKER_PATHS)
@pytest.mark.parametrize("insertion", (
    "fn parliament_tle_capability_attest() {}",
    "struct ParliamentTleCapabilityAttestResultWireV1;",
    "use iroha_core::tle_release::TlePartialReleaseSignerV1;",
))
def test_retired_broker_owners_reject_resurrection(
    path: str, insertion: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The former DTO, client, server and software signer owners cannot revive TLE."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(path)
    _replace_source(path, source + "\n#[cfg(any())]\n" + insertion, monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("ordinal", (124, 125))
@pytest.mark.parametrize("mutation", ("new_name", "existing_name", "expression"))
def test_retired_operation_ids_cannot_be_renamed_or_reassigned(
    ordinal: int, mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Numeric retirement is independent of the deleted Parliament spellings."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(PRIMITIVES)
    if mutation == "new_name":
        changed = source + f"\npub(super) const OPERATION_RENAMED_V1: u16 = {ordinal};\n"
    elif mutation == "existing_name":
        changed = source.replace("OPERATION_QUALIFY_V1: u16 = 1;", f"OPERATION_QUALIFY_V1: u16 = {ordinal};", 1)
    else:
        changed = source + f"\npub(super) const OPERATION_RENAMED_V1: u16 = {ordinal - 1} + 1;\n"
    assert changed != source
    _replace_source(PRIMITIVES, changed, monkeypatch)
    with pytest.raises(RuntimeError, match="retired broker operation ID"):
        guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("mutation", ("accept_all", "accept_124", "disabled", "foreign_owner"))
def test_known_operation_predicate_cannot_accept_retired_ids(
    mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual predicate remains live and closed instead of trusting a test alone."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(VALIDATION)
    item = guard.rust_item(source, "const fn operation_is_known(", VALIDATION)
    if mutation == "accept_all":
        changed = item.replace("    matches!(", "    true || matches!(", 1)
    elif mutation == "accept_124":
        changed = item.replace("    matches!(", "    operation == 124 || matches!(", 1)
    elif mutation == "disabled":
        changed = "#[cfg(any())]\n" + item
    else:
        changed = "mod foreign {\n" + item + "\n}"
    assert changed != item
    _replace_source(VALIDATION, source.replace(item, changed, 1), monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(VALIDATION)):
        guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("before,after", (
    ("[107, 108, 109, 110, 124, 125, 131]", "[107, 108, 109, 110, 131]"),
    ("assert!(!super::super::operation_is_known(unsupported));", "assert!(true);"),
    ("assert_eq!(operation, expected);", "assert_eq!(operation, operation);"),
    ("#[cfg(test)]\nmod operation_ordinal_tests", "#[cfg(any())]\nmod operation_ordinal_tests"),
    ("    #[test]\n    fn post_soracloud_operation_ids_are_exact_and_ordered()",
     "    #[cfg(any())]\n    #[test]\n    fn post_soracloud_operation_ids_are_exact_and_ordered()"),
))
def test_actual_ordinal_test_retains_decisive_negative_assertions(
    before: str, after: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both retired IDs stay under a compiled, non-vacuous source assertion."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(PRIMITIVES)
    assert source.count(before) == 1
    _replace_source(PRIMITIVES, source.replace(before, after, 1), monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(PRIMITIVES)):
        guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("path,declaration,before,after", (
    (CODEC, "fn read_operation_request_frame_inner<",
     "!operation_is_known(operation)", "false"),
    (CODEC, "fn read_operation_request_frame_inner<",
     "return Err(BrokerError::Protocol);", "let _ignored = BrokerError::Protocol;"),
    (CODEC, "fn read_operation_request_frame_inner<",
     "let operation = u16::from_be_bytes([discriminator[2], discriminator[3]]);",
     "let operation = OPERATION_QUALIFY_V1;"),
    (CODEC, "fn read_operation_request_frame_with_budget<",
     "read_operation_request_frame_inner(reader, Some(inbound_budget), Some(decode_pool))",
     "unreviewed_reader(reader, Some(inbound_budget), Some(decode_pool))"),
    (TRANSPORT, "fn serve_client(",
     "|| request.operation != announced_operation", "|| false"),
    (TRANSPORT, "fn serve_client(",
     "|| request.operation != announced_operation", "|| request.operation != request.operation"),
    (TRANSPORT, "fn serve_client(",
     "            announced_operation,\n", "            OPERATION_QUALIFY_V1,\n"),
    (TRANSPORT, "fn serve_client(",
     "validate_operation_request_for_session(&request, &state.chain_id, &state.network_id)?;",
     "validate_operation_request_for_session(&request, &state.chain_id, &state.network_id).ok();"),
))
def test_live_broker_ingress_retains_discriminator_and_request_binding(
    path: str, declaration: str, before: str, after: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sound predicate is insufficient if live ingress bypasses or disguises it."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(path)
    item = guard.rust_item(source, declaration, path)
    assert item.count(before) == 1
    changed = item.replace(before, after, 1)
    _replace_source(path, source.replace(item, changed, 1), monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("path,declaration", (
    (CODEC, "fn read_operation_request_frame_inner<"),
    (CODEC, "fn read_operation_request_frame_with_budget<"),
    (TRANSPORT, "fn serve_client("),
))
@pytest.mark.parametrize("mutation", ("disabled", "foreign_owner"))
def test_live_broker_ingress_rejects_conditional_or_foreign_decoys(
    path: str, declaration: str, mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pinned reader, wrapper and server must remain in their actual owners."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(path)
    item = guard.rust_item(source, declaration, path)
    changed = ("#[cfg(any())]\n" + item if mutation == "disabled"
               else "mod foreign {\n" + item + "\n}")
    _replace_source(path, source.replace(item, changed, 1), monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("replacement", ("", "    requalify().ok();\n"))
def test_shared_broker_still_propagates_original_requalification(
    replacement: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retiring Parliament exposure does not remove shared pre-dispatch refusal."""
    guard.require_retired_parliament_broker_exposure()
    source = guard.read(DISPATCH)
    before = "    requalify()?;\n    let moderation_quarantine_slot"
    assert source.count(before) == 1
    _replace_source(DISPATCH, source.replace(before, replacement + "    let moderation_quarantine_slot", 1), monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(DISPATCH)):
        guard.require_retired_parliament_broker_exposure()


def test_retirement_checks_ignore_comment_only_old_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """Historical prose is not a live broker implementation."""
    source = guard.read(PRIMITIVES)
    _replace_source(PRIMITIVES, source + "\n// OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1 was removed.\n", monkeypatch)
    guard.require_retired_parliament_broker_exposure()


@pytest.mark.parametrize("path,identifier", [
    (path, identifier)
    for path, identifiers in guard.RETIRED_TLE_BROKER_SURFACES
    for identifier in identifiers
])
def test_retired_generic_provider_methods_stay_absent(
    path: str, identifier: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain the incoming provider checks even for methods without TLE in their name."""
    guard.require_retired_parliament_broker_exposure()
    _replace_source(path, guard.read(path) + f"\nfn {identifier}() {{}}\n", monkeypatch)
    with pytest.raises(RuntimeError, match=re.escape(path)):
        guard.require_retired_parliament_broker_exposure()
