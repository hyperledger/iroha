"""Native-free contract checks for the ordinary-transaction NetworkId hard cut."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PYTHON_SOURCE = REPO / "python" / "iroha_python" / "src" / "iroha_python"
RUST_BRIDGE = REPO / "python" / "iroha_python" / "iroha_python_rs" / "src"

RETIRED_DOMAIN_NAMES = {
    "chain",
    "chainId",
    "chain_id",
    "canonicalGenesisHash",
    "canonical_genesis_hash",
    "genesisHash",
    "genesis_hash",
}

ORDINARY_TORII_METHODS = {
    "submit_instructions_and_wait",
    "register_domain_and_wait",
    "register_account_and_wait",
    "register_accounts_and_wait",
    "grant_account_permission_and_wait",
    "revoke_account_permission_and_wait",
    "register_asset_definition_and_wait",
    "mint_asset_quantity_and_wait",
    "mint_assets_quantity_and_wait",
    "burn_asset_quantity_and_wait",
    "transfer_asset_quantity_and_wait",
    "transfer_asset_batch_and_wait",
    "set_asset_transfer_availability_and_wait",
    "set_asset_transfer_blacklist_and_wait",
    "set_asset_transfer_control_and_wait",
    "set_asset_holding_limit_and_wait",
    "open_asset_lock_and_wait",
    "open_conditional_escrow_and_wait",
    "attest_escrow_condition_and_wait",
    "expire_conditional_escrow_and_wait",
    "drawdown_asset_lock_and_wait",
    "cancel_asset_lock_and_wait",
    "expire_asset_lock_and_wait",
    "transfer_assets_quantity_and_wait",
    "register_zk_asset_and_wait",
    "verify_proof_and_wait",
    "call_contract_batch_and_wait",
    "call_contract_and_wait",
    "build_and_submit_transaction",
}

PUBLIC_QUERY_BUILDERS = {
    "build_find_asset_escrow_query",
    "build_find_asset_escrows_by_seller_query",
    "build_find_asset_escrows_by_buyer_query",
    "build_find_committed_transaction_query",
    "build_find_block_by_hash_query",
}

PUBLIC_TORII_QUERY_METHODS = {
    "get_verified_committed_transaction",
    "get_asset_escrow",
    "list_asset_escrows_by_seller",
    "list_asset_escrows_by_buyer",
}


def _tree(name: str) -> ast.Module:
    return ast.parse((PYTHON_SOURCE / name).read_text(encoding="utf-8"))


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    return next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)


def _function(nodes: list[ast.stmt], name: str) -> ast.FunctionDef:
    return next(node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == name)


def _arguments(function: ast.FunctionDef) -> list[str]:
    return [
        argument.arg
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    ]


def _argument_annotation(function: ast.FunctionDef, name: str) -> str:
    argument = next(
        argument
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        if argument.arg == name
    )
    if isinstance(argument.annotation, ast.Constant) and isinstance(
        argument.annotation.value, str
    ):
        return argument.annotation.value
    assert argument.annotation is not None
    return ast.unparse(argument.annotation)


def _annotated_fields(class_definition: ast.ClassDef) -> list[str]:
    return [
        statement.target.id
        for statement in class_definition.body
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
    ]


def test_python_ordinary_transaction_signatures_are_network_id_only() -> None:
    crypto = _tree("crypto.py")
    tx = _tree("tx.py")
    client = _tree("client.py")

    build = _function(crypto.body, "build_signed_transaction")
    assert _arguments(build)[:3] == ["network_id", "authority", "private_key"]
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(build))

    decode_vk = _function(crypto.body, "decode_zk_vk_transaction_payload")
    assert _arguments(decode_vk)[:2] == ["payload", "network_id"]
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(decode_vk))

    transaction_config = _class(tx, "TransactionConfig")
    assert _annotated_fields(transaction_config)[0] == "network_id"
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_annotated_fields(transaction_config))
    config_post_init = _function(transaction_config.body, "__post_init__")
    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id == "_require_network_id"
        and call.args
        and ast.unparse(call.args[0]) == "self.network_id"
        for call in ast.walk(config_post_init)
        if isinstance(call, ast.Call)
    )

    transaction_draft = _class(tx, "TransactionDraft")
    draft_sign = _function(transaction_draft.body, "sign")
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(draft_sign))
    assert draft_sign.args.kwarg is None

    local_context = _class(client, "LocalSigningContext")
    assert _annotated_fields(local_context) == ["network_id"]

    torii = _class(client, "ToriiClient")
    methods = {
        method.name: method
        for method in torii.body
        if isinstance(method, ast.FunctionDef)
        and method.name in ORDINARY_TORII_METHODS | {"_transaction_draft"}
    }
    assert set(methods) == ORDINARY_TORII_METHODS | {"_transaction_draft"}
    for name, method in methods.items():
        assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(method)), name
        for call in (node for node in ast.walk(method) if isinstance(node, ast.Call)):
            assert RETIRED_DOMAIN_NAMES.isdisjoint(
                keyword.arg for keyword in call.keywords if keyword.arg is not None
            ), name
    build_and_submit = methods["build_and_submit_transaction"]
    assert _arguments(build_and_submit)[:4] == [
        "self",
        "network_id",
        "authority",
        "private_key",
    ]
    assert _argument_annotation(build_and_submit, "network_id") == "NetworkId"

    nexus_lifecycle = _function(torii.body, "nexus_lane_lifecycle")
    assert "network_id" in _arguments(nexus_lifecycle)
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(nexus_lifecycle))


def test_public_query_signatures_require_nominal_network_id_without_aliases() -> None:
    crypto = _tree("crypto.py")
    client = _tree("client.py")

    builders = {
        function.name: function
        for function in crypto.body
        if isinstance(function, ast.FunctionDef)
        and function.name in PUBLIC_QUERY_BUILDERS
    }
    assert set(builders) == PUBLIC_QUERY_BUILDERS
    for name, function in builders.items():
        assert _arguments(function)[:3] == ["authority", "private_key", "network_id"]
        assert _argument_annotation(function, "network_id") == "NetworkId"
        assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(function))
        assert function.args.kwarg is None
        assert any(
            isinstance(call.func, ast.Name)
            and call.func.id == "_require_network_id"
            and call.args
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "network_id"
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
        ), name

    torii = _class(client, "ToriiClient")
    methods = {
        method.name: method
        for method in torii.body
        if isinstance(method, ast.FunctionDef)
        and method.name in PUBLIC_TORII_QUERY_METHODS
    }
    assert set(methods) == PUBLIC_TORII_QUERY_METHODS
    for name, method in methods.items():
        assert "network_id" in _arguments(method)
        assert _argument_annotation(method, "network_id") == "NetworkId"
        assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(method))
        assert method.args.kwarg is None
        assert not any(
            isinstance(call.func, ast.Attribute) and call.func.attr == "to_bytes"
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
        ), name

    pipeline = _function(torii.body, "get_pipeline_transaction_details")
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(pipeline))
    assert pipeline.args.kwarg is None
    query_call = next(
        call
        for call in ast.walk(pipeline)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "build_find_committed_transaction_query"
    )
    assert ast.unparse(query_call.args[2]) == "signing_context.network_id"


def test_nexus_uses_exact_network_id_for_connect_and_transactions() -> None:
    nexus = _tree("nexus_app.py")
    config = _class(nexus, "NexusAppConfig")
    assert _annotated_fields(config)[0] == "network_id"
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_annotated_fields(config))
    options = _class(nexus, "NexusConnectOptions")
    assert "sid" not in _annotated_fields(options)
    session = _class(nexus, "NexusConnectSession")
    assert _annotated_fields(session)[:4] == [
        "sid",
        "network_id",
        "app_public_key",
        "nonce",
    ]

    client = _class(nexus, "NexusAppClient")
    build = _function(client.body, "build_transfer_draft")
    payload_assignment = next(
        statement
        for statement in build.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "payload_input"
            for target in statement.targets
        )
    )
    assert isinstance(payload_assignment.value, ast.Dict)
    keys = {
        key.value
        for key in payload_assignment.value.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    assert "network_id" in keys
    assert RETIRED_DOMAIN_NAMES.isdisjoint(keys)

    crypto = _tree("crypto.py")
    privacy = _function(crypto.body, "privacy_vega_device_authentication_digest_v1")
    assert "network_id" in _arguments(privacy)
    assert {"chain_id", "canonical_genesis_hash"}.isdisjoint(_arguments(privacy))


def test_confidential_proof_builders_require_exact_network_id() -> None:
    retired = (
        "build_confidential_transfer_proof_v2",
        "build_confidential_transfer_proof_v2_with_paths",
        "build_confidential_unshield_proof_v3",
        "build_confidential_unshield_proof_v3_with_paths",
    )
    crypto = (PYTHON_SOURCE / "crypto.py").read_text(encoding="utf-8")
    exports = (PYTHON_SOURCE / "__init__.py").read_text(encoding="utf-8")
    bridge = (RUST_BRIDGE / "lib.rs").read_text(encoding="utf-8")
    for name in retired:
        assert name not in crypto
        assert name not in exports
        assert name not in bridge
    wallet = _class(_tree("confidential.py"), "ConfidentialProver")
    constructor = _function(wallet.body, "__init__")
    assert "network_id" in _arguments(constructor)
    assert _argument_annotation(constructor, "network_id") == "NetworkId"
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(constructor))
    assert "_require_network_id(network_id)" in ast.unparse(constructor)
    rust = (RUST_BRIDGE / "confidential_wallet.rs").read_text(encoding="utf-8")
    start = rust.index("fn new(")
    signature = rust[start : rust.index(") -> PyResult", start)]
    assert "network_id: &PyNetworkId" in signature
    assert all(retired not in signature for retired in RETIRED_DOMAIN_NAMES)


def test_zk_x509_public_apis_require_nominal_network_id() -> None:
    crypto = _tree("crypto.py")
    client = _tree("client.py")

    inspector = _function(
        crypto.body,
        "inspect_signed_privacy_zk_x509_identity_presentation_action_v1",
    )
    assert _arguments(inspector) == ["signed_transaction_versioned", "network_id"]
    assert _argument_annotation(inspector, "network_id") == "NetworkId"
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(inspector))

    torii = _class(client, "ToriiClient")
    submit = _function(
        torii.body,
        "submit_signed_privacy_zk_x509_identity_presentation_action_v1",
    )
    assert "network_id" in _arguments(submit)
    assert _argument_annotation(submit, "network_id") == "NetworkId"
    assert RETIRED_DOMAIN_NAMES.isdisjoint(_arguments(submit))
    assert submit.args.kwarg is None


def test_pyo3_boundary_and_native_signer_revision_are_exact_abi30_v7() -> None:
    rust = (RUST_BRIDGE / "lib.rs").read_text(encoding="utf-8")
    vk_rust = (RUST_BRIDGE / "zk_vk_draft.rs").read_text(encoding="utf-8")
    native_bridge = (REPO / "crates" / "connect_norito_bridge" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )

    assert "value.parse::<NetworkId>()" in rust
    assert "canonical_network_id_literal(&inner) != value" in rust
    assert "NetworkId must carry the canonical Iroha hash marker bit" in rust
    assert "RETIRED_NETWORK_FIELDS: [&str; 7]" in rust
    for retired in RETIRED_DOMAIN_NAMES:
        assert f'"{retired}"' in rust
    assert "network_id: &super::PyNetworkId" in vk_rust
    assert "canonical_genesis_hash: &[u8]" not in vk_rust
    assert "fn parse_query_network_id" not in rust
    x509_start = rust.index(
        "fn inspect_signed_privacy_zk_x509_identity_presentation_action_v1_py("
    )
    x509_signature = rust[x509_start : rust.index(") -> PyResult", x509_start)]
    assert "network_id: &PyNetworkId" in x509_signature
    assert all(retired not in x509_signature for retired in RETIRED_DOMAIN_NAMES)
    vega_start = rust.index("fn privacy_vega_device_authentication_digest_v1_py(")
    vega_end = rust.index(
        "fn python_authenticated_privacy_action_envelope_v1", vega_start
    )
    vega = rust[vega_start:vega_end]
    assert "network_id: &PyNetworkId" in vega
    assert "network_id: network_id.inner" in vega
    assert {"chain_id", "canonical_genesis_hash"}.isdisjoint(vega)
    for function_name in (
        "build_find_asset_escrow_query_py",
        "build_find_asset_escrows_by_seller_query_py",
        "build_find_asset_escrows_by_buyer_query_py",
        "build_find_committed_transaction_query_py",
        "build_find_block_by_hash_query_py",
    ):
        start = rust.index(f"fn {function_name}(")
        signature = rust[start : rust.index(") -> PyResult", start)]
        assert "network_id: &PyNetworkId" in signature
        assert all(retired not in signature for retired in RETIRED_DOMAIN_NAMES)
    signer_start = rust.index("fn sign_query_request(")
    signer_signature = rust[signer_start : rust.index(") -> PyResult", signer_start)]
    assert "network_id: &NetworkId" in signer_signature
    assert "assert_eq!(connect_norito_bridge_abi_version_py(), 30);" in rust
    assert "const NATIVE_SIGNER_JNI_CONTRACT_REVISION: u32 = 7;" in native_bridge
    assert "native_signer_jni_contract_revision_is_the_v7_shield_verifier_hard_cut" in native_bridge
