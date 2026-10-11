"""Check the route-derived SDK inventory, authentication scope, and drift behavior."""

from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import sdk_operation_inventory as inventory


@pytest.fixture(scope="module")
def generated() -> bytes:
    """Execute the real std-only Rust catalog exporter once for this suite."""
    return inventory.generate(inventory.ROOT)


def test_inventory_is_exact_and_preserves_every_explicit_operation(generated: bytes) -> None:
    assert generated == (inventory.ROOT / inventory.INVENTORY).read_bytes()
    rows = list(csv.DictReader(generated.decode().splitlines()[1:], delimiter="\t"))
    ids = [row["route_id"] for row in rows]
    assert ids == sorted(set(ids))
    assert all(row["method"] not in {"HEAD", "OPTIONS"} for row in rows)
    operations = {row["route_id"]: row for row in rows}
    assert operations["aliases.resolve_index"]["authentication"] == "canonical_account_signature"
    assert operations["aliases.resolve_index"]["admission"] == "dataspace_visible"
    for exact_mapping in ("aliases.resolve", "aliases.by_account"):
        assert operations[exact_mapping]["authentication"] == "optional_canonical_account_signature"
    submission = operations["pipeline.transaction.submit"]
    assert (submission["method"], submission["authentication"], submission["admission"]) == (
        "POST", "canonical_signed_body", "authenticated_account",
    )
    assert submission["effect"] == "mutation"
    operator = operations["operator.configuration.read"]
    assert operator["authentication"] == "operator_signature"
    assert operator["admission"] == "operator"
    assert operator["private_no_store"] == "true"
    stream = operations["blocks.stream_websocket"]
    assert stream["transport"] == "websocket"
    assert stream["admission"] == "authenticated_account"
    assert stream["feature_gate"] == "feature(app_api)"
    # SDK projection flags describe the current catalog. Retain routes excluded
    # from that projection so migration can account for existing handwritten SDK calls.
    assert operations["diagnostic.status"]["sdk"] == "false"
    assert operator["sdk"] == "false"
    assert stream["sdk"] == "false"


@pytest.mark.parametrize("mutation", ["missing", "extra", "changed"])
def test_default_check_rejects_drift_without_rewriting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generated: bytes, mutation: str,
) -> None:
    path = tmp_path / inventory.INVENTORY
    path.parent.mkdir()
    modified = {
        "missing": b"\n".join(generated.splitlines()[:-1]) + b"\n",
        "extra": generated + b"invented.operation\n",
        "changed": generated.replace(b"operator_signature", b"unauthenticated", 1),
    }[mutation]
    path.write_bytes(modified)
    monkeypatch.setattr(inventory, "ROOT", tmp_path)
    monkeypatch.setattr(inventory, "generate", lambda _root: generated)
    assert inventory.main([]) == 1
    assert path.read_bytes() == modified


def test_explicit_refresh_writes_the_complete_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generated: bytes,
) -> None:
    path = tmp_path / inventory.INVENTORY
    path.parent.mkdir()
    path.write_bytes(b"stale\n")
    monkeypatch.setattr(inventory, "ROOT", tmp_path)
    monkeypatch.setattr(inventory, "generate", lambda _root: generated)
    assert inventory.main(["--write"]) == 0
    assert path.read_bytes() == generated
    assert inventory.main([]) == 0


def test_missing_inventory_is_not_created_by_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generated: bytes,
) -> None:
    monkeypatch.setattr(inventory, "ROOT", tmp_path)
    monkeypatch.setattr(inventory, "generate", lambda _root: generated)
    assert inventory.main([]) == 2
    assert not (tmp_path / inventory.INVENTORY).exists()


def test_compiler_errors_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inventory, "ROOT", tmp_path)
    assert inventory.main(["--write"]) == 2
    assert not (tmp_path / inventory.INVENTORY).exists()


def test_invalid_catalog_cannot_produce_an_inventory(tmp_path: Path) -> None:
    exporter = Path("scripts/sdk_operation_inventory.rs")
    catalog = Path("crates/iroha_torii_shared/src/route_catalog.rs")
    multisig_path = Path("crates/iroha_torii_shared/src/multisig_execution_evidence/path.rs")
    for relative in (exporter, catalog, multisig_path):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(inventory.ROOT / relative, target)
    shutil.copytree(inventory.ROOT / catalog.with_suffix(""), tmp_path / catalog.with_suffix(""))
    path = tmp_path / catalog
    source = path.read_text()
    assert source.count("    pipeline::ROUTES,") == 1
    path.write_text(source.replace("    pipeline::ROUTES,", "    pipeline::ROUTES,\n    pipeline::ROUTES,"))
    with pytest.raises(subprocess.CalledProcessError) as failure:
        inventory.generate(tmp_path)
    assert b"invalid canonical route catalog" in failure.value.stderr


def test_ledger_original_carriers_preserve_authentication_and_private_reads(generated: bytes) -> None:
    """Keep the exact signed private-read policy of the generic ledger carriers."""
    operations = {row["route_id"]: row for row in csv.DictReader(
        generated.decode().splitlines()[1:], delimiter="\t")}
    expected = {
        "ledger.resource_names_state": ("GET", "canonical_account_signature", "authenticated_account", "read", "false", "true"),
        "ledger.authority_originals": ("POST", "canonical_account_signature", "authenticated_account", "read", "false", "true"),
    }
    for route_id, policy in expected.items():
        row = operations[route_id]
        assert row["feature_gate"] == "always"
        assert row["sdk"] == row["openapi"] == "true"
        assert row["surface"] == "public" and row["transport"] == "http"
        assert tuple(row[field] for field in (
            "method", "authentication", "admission", "effect", "mcp", "private_no_store")) == policy
    assert not any(route_id.startswith("kagemusha.") for route_id in operations)
    _assert_current_wallet_load_issuance_route(operations)


@pytest.mark.parametrize(
    "route_id,method,path,feature_gate,authentication,admission,mcp,private_no_store",
    [
        ('validation_fee.retail.quote', 'POST', '/v1/validation-fee/quote', 'feature(app_api)', 'canonical_account_signature', 'authenticated_account', 'false', 'true'),
        ('validation_fee.retail.status', 'GET', '/v1/validation-fee/accounts/{account_id}/status', 'feature(app_api)', 'canonical_account_signature', 'authenticated_account', 'false', 'true'),
        ('validation_fee.retail.receipts', 'GET', '/v1/validation-fee/accounts/{account_id}/receipts', 'feature(app_api)', 'canonical_account_signature', 'authenticated_account', 'false', 'true'),
        ('validation_fee.retail.statement_head', 'GET', '/v1/validation-fee/accounts/{account_id}/statement/head', 'feature(app_api)', 'canonical_account_signature', 'authenticated_account', 'false', 'true'),
        ('validation_fee.retail.statement', 'POST', '/v1/validation-fee/accounts/{account_id}/statement', 'feature(app_api)', 'canonical_account_signature', 'authenticated_account', 'false', 'true'),
        ('multisig.execution_evidence', 'GET', '/v1/multisig/execution-evidence/{multisig_account_id}/{entrypoint_hash}/{instructions_hash}', 'always', 'torii_default', 'public', 'true', 'false'),
    ],
)
def test_current_original_reads_preserve_their_exact_route_policy(
    generated: bytes, route_id: str, method: str, path: str, feature_gate: str,
    authentication: str, admission: str, mcp: str, private_no_store: str,
) -> None:
    """Keep private signed reads distinct from public certified evidence reads."""
    operations = {row["route_id"]: row for row in csv.DictReader(
        generated.decode().splitlines()[1:], delimiter="\t")}
    row = operations[route_id]
    assert tuple(row[field] for field in (
        "method", "path", "feature_gate", "authentication", "admission",
        "mcp", "private_no_store")) == (
            method, path, feature_gate, authentication, admission, mcp, private_no_store)
    assert row["surface"] == "public" and row["transport"] == "http"
    assert row["effect"] == "read"
    assert row["sdk"] == row["openapi"] == "true"


def test_retired_hijiri_quote_is_absent_from_every_projection(generated: bytes) -> None:
    """The retail quote is the sole current quote owner, without a retired alias."""
    rows = list(csv.DictReader(generated.decode().splitlines()[1:], delimiter="\t"))
    assert all(row["route_id"] != "validation_fee.hijiri.quote" for row in rows)
    assert all(row["path"] != "/v1/validation-fee/hijiri/quote" for row in rows)


def _assert_current_wallet_load_issuance_route(operations: dict[str, dict[str, str]]) -> None:
    """Allow only the canonical private issuance read within the wallet route family."""
    route_id = "contracts.kagemusha_load_issuance_get"
    path = "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}"
    assert operations[route_id] == {
        "route_id": route_id,
        "method": "GET",
        "path": path,
        "surface": "public",
        "authentication": "canonical_account_signature",
        "admission": "authenticated_account",
        "effect": "read",
        "transport": "http",
        "feature_gate": "feature(app_api)",
        "sdk": "true",
        "openapi": "false",
        "mcp": "false",
        "private_no_store": "true",
    }
    wallet_routes = {row["route_id"]: row["path"] for row in operations.values()
                     if row["path"].startswith("/v1/kagemusha/")}
    assert wallet_routes == {route_id: path}
    assert not any(identifier.startswith("kagemusha.") for identifier in operations)
    retired_paths = {
        "/v1/kagemusha/readiness",
        "/v1/kagemusha/top-up",
        "/v1/kagemusha/redeem",
        "/v1/kagemusha/operations/{operation_id}",
        "/v1/kagemusha/ordinary/current-wallet",
    }
    assert retired_paths.isdisjoint(row["path"] for row in operations.values())


@pytest.mark.parametrize("field,value", (
    ("authentication", "torii_default"),
    ("admission", "public"),
    ("effect", "mutation"),
    ("private_no_store", "false"),
    ("path", "/v1/kagemusha/readiness"),
    ("openapi", "true"),
))
def test_current_wallet_load_route_rejects_relaxed_policy(
    generated: bytes, field: str, value: str,
) -> None:
    """The exact authenticated private read cannot drift into another service contract."""
    operations = {row["route_id"]: row for row in csv.DictReader(
        generated.decode().splitlines()[1:], delimiter="\t")}
    _assert_current_wallet_load_issuance_route(operations)
    operations["contracts.kagemusha_load_issuance_get"][field] = value
    with pytest.raises(AssertionError):
        _assert_current_wallet_load_issuance_route(operations)


@pytest.mark.parametrize("route_id,path", (
    ("kagemusha.readiness", "/v1/kagemusha/readiness"),
    ("kagemusha.top_up", "/v1/kagemusha/top-up"),
    ("kagemusha.redeem", "/v1/kagemusha/redeem"),
    ("kagemusha.operation", "/v1/kagemusha/operations/{operation_id}"),
    ("contracts.retired_wallet", "/v1/kagemusha/ordinary/current-wallet"),
))
def test_current_wallet_family_rejects_retired_route_reintroduction(
    generated: bytes, route_id: str, path: str,
) -> None:
    """The current load read grants no alias for retired readiness or monetary routes."""
    operations = {row["route_id"]: row for row in csv.DictReader(
        generated.decode().splitlines()[1:], delimiter="\t")}
    _assert_current_wallet_load_issuance_route(operations)
    operations[route_id] = dict(operations["contracts.kagemusha_load_issuance_get"],
                               route_id=route_id, path=path)
    with pytest.raises(AssertionError):
        _assert_current_wallet_load_issuance_route(operations)


@pytest.mark.parametrize("relative", (
    "crates/iroha_torii/src/kagemusha_commands.rs",
    "crates/iroha_torii/src/kagemusha_state.rs",
    "crates/iroha_torii_shared/src/kagemusha_ordinary_enrollment_http_v1.rs",
))
def test_retired_wallet_service_and_enrollment_type_paths_are_absent(relative: str) -> None:
    """Current issuance does not restore the retired service or enrollment wire types."""
    path = inventory.ROOT / relative
    assert not path.exists() and not path.is_symlink(), relative
