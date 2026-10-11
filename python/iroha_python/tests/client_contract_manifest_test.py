from __future__ import annotations

import base64
import binascii
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

import pytest

import iroha_python.client as client_module
from iroha_python import (
    ContractEntrypointKind,
    ContractManifest,
    ContractManifestRecord,
    ContractArtifactId,
    ContractTriggerRepeatKind,
    EntrypointValueKindV1,
    EntrypointValueTypeNodeKindV1,
    EntrypointValueTypeV1,
)

def _hash_literal(hexadecimal: str) -> str:
    prefix = "hash:" + hexadecimal.upper()
    return f"{prefix}#{binascii.crc_hqx(prefix.encode('ascii'), 0xFFFF):04X}"


_QUERY_VIEW_LAYOUTS = {
    "AccountView": (
        ["id", "metadata"],
        ["AccountId", "Json"],
    ),
    "AssetView": (
        ["id", "amount"],
        ["AssetId", "Quantity"],
    ),
    "AssetDefinitionView": (
        [
            "id",
            "name",
            "description",
            "owned_by",
            "total_quantity",
            "numeric_scale",
            "metadata",
        ],
        [
            "AssetDefinitionId",
            "String",
            ("Option", "String"),
            "AccountId",
            "Quantity",
            ("Option", "Int"),
            "Json",
        ],
    ),
    "DomainView": (
        ["id", "owned_by", "metadata"],
        ["DomainId", "AccountId", "Json"],
    ),
    "NftView": (
        ["id", "owned_by", "content"],
        ["NftId", "AccountId", "Json"],
    ),
}


def _leaf_node(kind: str) -> Dict[str, Any]:
    return {"kind": "Leaf", "value": {"kind": kind, "value": None}}


def _query_view_nodes(name: str) -> list[Dict[str, Any]]:
    fields, children = _QUERY_VIEW_LAYOUTS[name]
    nodes: list[Dict[str, Any]] = [{"kind": "Struct", "value": {"name": f"kotodama::{name}", "fields": fields}}]
    for child in children:
        if isinstance(child, tuple):
            wrapper, leaf = child
            nodes.extend(({"kind": wrapper, "value": None}, _leaf_node(leaf)))
        else:
            nodes.append(_leaf_node(child))
    return nodes


def _query_page_payload(name: str) -> Dict[str, Any]:
    return {
        "nodes": [
            {
                "kind": "Struct",
                "value": {"name": "kotodama::QueryPage", "fields": ["items", "next_offset"]},
            },
            {"kind": "List", "value": {"capacity": 64}},
            *_query_view_nodes(name),
            {"kind": "Option", "value": None},
            _leaf_node("Int"),
        ]
    }


def _full_manifest_payload() -> Dict[str, Any]:
    return {
        "seiyaku_name": "Ledger",
        "code_hash": "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2",
        "abi_hash": "hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071",
        "compiler_fingerprint": "kotodama_lang",
        "features_bitmap": 0,
        "access_set_hints": {
            "read_keys": ["state:Balances"],
            "write_keys": ["state:Balances"],
            "dynamic_reads": [
                {
                    "base_key": "state:Balances",
                    "key_type": "AccountId",
                    "bound_kind": "take",
                    "max_keys": 64,
                }
            ],
            "dynamic_writes": [],
        },
        "events": [],
        "enum_types": [],
        "permissions": [{"name": "TransferAsset", "scope": {"kind": "Instance", "value": None}}],
        "entrypoints": [
            {
                "name": "transfer",
                "kind": {"kind": "Kotoage", "value": None},
                "params": [
                    {"name": "request", "type_name": "struct Fixture::Transfer"},
                    {"name": "tags", "type_name": "List<Name, 64>"},
                ],
                "argument_schema": {
                    "fields": [
                        {
                            "name": "request",
                            "ty": {
                                "nodes": [
                                    {
                                        "kind": "Struct",
                                        "value": {
                                            "name": "Fixture::Transfer",
                                            "fields": ["amount", "memo"],
                                        },
                                    },
                                    {
                                        "kind": "Leaf",
                                        "value": {"kind": "Quantity", "value": None},
                                    },
                                    {"kind": "Option", "value": None},
                                    {
                                        "kind": "Leaf",
                                        "value": {"kind": "String", "value": None},
                                    },
                                ]
                            },
                        },
                        {
                            "name": "tags",
                            "ty": {
                                "nodes": [
                                    {
                                        "kind": "List",
                                        "value": {"capacity": 64},
                                    },
                                    {
                                        "kind": "Leaf",
                                        "value": {
                                            "kind": "Name",
                                            "value": None,
                                        },
                                    },
                                ]
                            },
                        },
                    ]
                },
                "return_type": "Result<(bool, int), string>",
                "return_schema": {
                    "nodes": [
                        {"kind": "Result", "value": None},
                        {"kind": "Tuple", "value": 2},
                        {
                            "kind": "Leaf",
                            "value": {"kind": "Bool", "value": None},
                        },
                        {
                            "kind": "Leaf",
                            "value": {"kind": "Int", "value": None},
                        },
                        {
                            "kind": "Leaf",
                            "value": {"kind": "String", "value": None},
                        },
                    ]
                },
                "authorization": {"kind": "Permission", "value": "TransferAsset"},
                "read_keys": ["state:Balances"],
                "write_keys": ["state:Balances"],
                "access_hints_complete": True,
                "access_hints_skipped": [],
                "triggers": [
                    {
                        "id": "settle",
                        "repeats": {"Exactly": 2},
                        "filter": "TlJUMAAAl9+YQQ4oJZjALRf6FAto0QAKAAAAAAAAANzCjydU9+jNAgIAAAAFBAAAAAA=",
                        "authority": None,
                        "metadata": {"purpose": "daily-settlement", "round": 7},
                        "callback": {"namespace": None, "entrypoint": "transfer"},
                    }
                ],
            }
        ],
        "states": [{"name": "Balances", "type_name": "StateMap<AccountId, quantity>"}],
        "error_types": [{"identity": "example/transfer@1::Transfer::TransferError", "variants": [{"name": "InsufficientFunds", "code": 1001}]}],
        "kotoba": [
            {
                "msg_id": "transfer.denied",
                "translations": [
                    {"lang": "en", "text": "Transfer denied"},
                    {"lang": "ja", "text": "送金は拒否されました"},
                ],
            }
        ],
        "provenance": {"signer": "ed25519:fixture", "signature": "fixture-signature"},
    }


def _replace_dynamic_hints(
    payload: Dict[str, Any],
    field: str,
    hints: list[Dict[str, Any]],
) -> None:
    access_set_hints = payload["access_set_hints"]
    access_set_hints["dynamic_reads"] = []
    access_set_hints["dynamic_writes"] = []
    access_set_hints[field] = hints


def test_contract_manifest_keywords_match_normative_kotodama_grammar() -> None:
    root = Path(__file__).resolve().parents[3]
    grammar = (root / "crates" / "kotodama_lang" / "grammar" / "v1.lex").read_text(encoding="utf-8")
    expected = {
        line.split("\t")[1] for line in grammar.splitlines() if line.startswith("keyword\t")
    }
    assert client_module._KOTODAMA_RESERVED_IDENTIFIERS == expected | {"Amount"}
    assert client_module._KOTODAMA_RESERVED_IDENTIFIERS - expected == {"Amount"}
    assert expected.isdisjoint({"contract", "entry", "init", "upgrade"})

    semantic = (root / "crates" / "kotodama_surface" / "src" / "source_policy.rs").read_text(
        encoding="utf-8"
    )
    type_table = re.search(
        r"pub const V1_SOURCE_TYPE_NAMES: &\[&str\] = &\[(.*?)\];",
        semantic,
        re.DOTALL,
    )
    assert type_table is not None
    type_names = set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', type_table.group(1)))
    reserved_extra_table = re.search(
        r"pub const V1_DECLARATION_RESERVED_EXTRA_NAMES: &\[&str\] = &\[(.*?)\];",
        semantic,
        re.DOTALL,
    )
    assert reserved_extra_table is not None
    reserved_extra_names = set(
        re.findall(
            r'"([A-Za-z_][A-Za-z0-9_]*)"',
            reserved_extra_table.group(1),
        )
    )
    assert (
        client_module._KOTODAMA_RESERVED_DECLARATION_IDENTIFIERS
        == type_names | reserved_extra_names
    )


def test_state_map_key_type_projection_requires_one_top_level_state_map() -> None:
    assert (
        client_module._kotodama_v1_state_map_key_type_name(
            "StateMap<AccountId, quantity>"
        )
        == "AccountId"
    )
    assert (
        client_module._kotodama_v1_state_map_key_type_name(
            "StateMap<quantity, int>"
        )
        == "quantity"
    )
    for type_name in (
        "quantity",
        "Option<StateMap<AccountId, quantity>>",
        "StateMap<AccountId, Amount>",
        "StateMap<AccountId,quantity>",
    ):
        assert client_module._kotodama_v1_state_map_key_type_name(type_name) is None


def test_contract_manifest_preserves_exact_v1_interface_shape() -> None:
    payload = _full_manifest_payload()
    manifest = ContractManifest.from_payload(payload)

    assert manifest.seiyaku_name == "Ledger"
    assert manifest.code_hash == "b" * 64
    assert manifest.abi_hash == "d" * 64
    assert manifest.access_set_hints is not None
    assert manifest.access_set_hints.dynamic_reads[0].max_keys == 64
    assert manifest.entrypoints is not None
    entrypoint = manifest.entrypoints[0]
    assert entrypoint.kind is ContractEntrypointKind.KOTOAGE
    assert entrypoint.argument_schema is not None
    assert entrypoint.argument_schema.fields[0].type.word_count == 2
    assert entrypoint.argument_schema.fields[1].type.word_count == 1
    assert entrypoint.argument_schema.fields[1].type.nodes[0].kind is (
        EntrypointValueTypeNodeKindV1.LIST
    )
    assert entrypoint.argument_schema.fields[1].type.canonical_type_name == "List<Name, 64>"
    assert entrypoint.return_schema is not None
    assert entrypoint.return_schema.word_count == 1
    assert entrypoint.return_schema.nodes[2].value is EntrypointValueKindV1.BOOL
    trigger = entrypoint.triggers[0]
    assert trigger.id == "settle"
    assert trigger.repeats.kind is ContractTriggerRepeatKind.EXACTLY
    assert trigger.repeats.count == 2
    assert trigger.callback.namespace is None
    assert trigger.callback.entrypoint == "transfer"
    assert trigger.filter_bytes == base64.b64decode(trigger.filter_b64, validate=True)
    assert trigger.metadata["round"] == 7
    assert manifest.declared_triggers == (trigger,)
    assert manifest.states is not None
    assert manifest.states[0].type_name == "StateMap<AccountId, quantity>"
    assert manifest.error_types is not None
    assert manifest.error_types[0].variants[0].code == 1001
    assert manifest.kotoba is not None
    assert manifest.kotoba[0].translations[1].language == "ja"
    assert manifest.provenance is not None
    assert manifest.provenance["signer"] == "ed25519:fixture"

    payload["entrypoints"][0]["triggers"][0]["metadata"]["round"] = 99
    payload["provenance"]["signer"] = "mutated"
    assert trigger.metadata["round"] == 7
    assert manifest.provenance["signer"] == "ed25519:fixture"


def test_contract_manifest_trigger_boundaries_reject_exact_amount_source_form() -> None:
    for field in ("id", "namespace"):
        payload = _full_manifest_payload()
        trigger = payload["entrypoints"][0]["triggers"][0]
        if field == "id":
            trigger["id"] = "Amount"
        else:
            trigger["callback"]["namespace"] = "Amount"
        with pytest.raises(TypeError, match="canonical Kotodama"):
            ContractManifest.from_payload(payload)

    payload = _full_manifest_payload()
    trigger = payload["entrypoints"][0]["triggers"][0]
    trigger["id"] = "amount"
    trigger["callback"]["namespace"] = "RemoteLedger"
    parsed = ContractManifest.from_payload(payload).declared_triggers[0]
    assert parsed.id == "amount"
    assert parsed.callback.namespace == "RemoteLedger"


@pytest.mark.parametrize("view_name", tuple(_QUERY_VIEW_LAYOUTS))
def test_entrypoint_query_page_uses_each_exact_reserved_flat_schema(
    view_name: str,
) -> None:
    page = _query_page_payload(view_name)
    schema = EntrypointValueTypeV1.from_payload(page)
    assert schema.word_count == 2
    assert schema.canonical_type_name == f"QueryPage<{view_name}>"

    for mutate in (
        lambda value: value["nodes"][1]["value"].__setitem__("capacity", 32),
        lambda value: value["nodes"][2]["value"].__setitem__("name", "Fixture::UnknownView"),
        lambda value: value["nodes"][-1]["value"].__setitem__("kind", "String"),
    ):
        forged = deepcopy(page)
        mutate(forged)
        with pytest.raises(TypeError, match="forged reserved"):
            EntrypointValueTypeV1.from_payload(forged)


@pytest.mark.parametrize("view_name", tuple(_QUERY_VIEW_LAYOUTS))
def test_entrypoint_rejects_each_forged_reserved_view(view_name: str) -> None:
    canonical = {"nodes": _query_view_nodes(view_name)}
    schema = EntrypointValueTypeV1.from_payload(canonical)
    assert schema.canonical_type_name == view_name

    wrong_fields = deepcopy(canonical)
    wrong_fields["nodes"][0]["value"]["fields"][0] = "forged"
    with pytest.raises(TypeError, match="forged reserved"):
        EntrypointValueTypeV1.from_payload(wrong_fields)

    wrong_leaf = deepcopy(canonical)
    wrong_leaf["nodes"][1]["value"]["kind"] = "Bool"
    with pytest.raises(TypeError, match="forged reserved"):
        EntrypointValueTypeV1.from_payload(wrong_leaf)


@pytest.mark.parametrize("reserved_name", (*_QUERY_VIEW_LAYOUTS, "QueryPage"))
def test_entrypoint_reserved_struct_name_does_not_bypass_exact_shape_validation(
    reserved_name: str,
) -> None:
    forged = {
        "nodes": [
            {
                "kind": "Struct",
                "value": {"name": f"kotodama::{reserved_name}", "fields": ["value"]},
            },
            _leaf_node("Int"),
        ]
    }

    with pytest.raises(TypeError, match="forged reserved"):
        EntrypointValueTypeV1.from_payload(forged)


def test_asset_definition_precision_requires_optional_integer() -> None:
    valid = _query_view_nodes("AssetDefinitionView")
    schema = EntrypointValueTypeV1.from_payload({"nodes": valid})
    assert schema.word_count == 7
    assert len(schema.nodes) == 10
    retired = deepcopy(valid)
    del retired[0]["value"]["fields"][5]
    del retired[7:9]
    required = deepcopy(valid)
    del required[7]
    decimal = deepcopy(valid)
    decimal[8] = _leaf_node("Decimal")
    for nodes in (retired, required, decimal):
        page = _query_page_payload("AssetDefinitionView")
        page["nodes"] = page["nodes"][:2] + nodes + page["nodes"][-2:]
        for payload in ({"nodes": nodes}, page):
            with pytest.raises(TypeError, match="forged reserved"):
                EntrypointValueTypeV1.from_payload(payload)


def test_entrypoint_ordinary_struct_keeps_its_nominal_struct_prefix() -> None:
    pair = {
        "nodes": [
            {
                "kind": "Struct",
                "value": {"name": "Fixture::Pair", "fields": ["left", "right"]},
            },
            _leaf_node("Int"),
            _leaf_node("Bool"),
        ]
    }

    schema = EntrypointValueTypeV1.from_payload(pair)

    assert schema.canonical_type_name == "struct Fixture::Pair"


@pytest.mark.parametrize(
    ("wire_kind", "source_name"),
    [("Int", "int"), ("Decimal", "decimal"), ("Quantity", "quantity")],
)
def test_entrypoint_numeric_leaves_use_only_exact_v1_names(
    wire_kind: str, source_name: str
) -> None:
    schema = EntrypointValueTypeV1.from_payload({"nodes": [_leaf_node(wire_kind)]})
    assert schema.canonical_type_name == source_name


@pytest.mark.parametrize("retired", ["U128", "Amount", "I64", "Float"])
def test_entrypoint_rejects_retired_numeric_leaf_kinds(retired: str) -> None:
    with pytest.raises(TypeError, match="unsupported Kotodama boundary value kind"):
        EntrypointValueTypeV1.from_payload({"nodes": [_leaf_node(retired)]})


@pytest.mark.parametrize(
    "retired", ["i64", "u128", "Amount", "amount", "num", "number", "float", "money"]
)
def test_manifest_rejects_retired_numeric_type_spellings(retired: str) -> None:
    payload = _full_manifest_payload()
    payload["states"][0]["type_name"] = f"StateMap<AccountId, {retired}>"
    with pytest.raises(TypeError, match="retired Kotodama numeric type"):
        ContractManifest.from_payload(payload)


def test_manifest_allows_amount_as_struct_field_identifier() -> None:
    payload = _full_manifest_payload()
    payload["states"].append(
        {"name": "TransferShape", "type_name": "Fixture::Transfer{amount: quantity}"}
    )

    manifest = ContractManifest.from_payload(payload)

    assert manifest.states[-1].type_name == "Fixture::Transfer{amount: quantity}"


@pytest.mark.parametrize("type_name", [
    "Fixture::Empty{}", "Fixture::Other{}", "Fixture::Transfer{}", "List<Fixture::Empty{}, 2>", "List<List<Fixture::Empty{}, 2>, 2>",
    "Fixture::Envelope{empty: Fixture::Empty{}}", "StateMap<int, Fixture::Empty{}>",
    "std/math@1.0.0::Math::Empty{}",
])
def test_manifest_preserves_empty_named_state_products(type_name: str) -> None:
    payload = _full_manifest_payload()
    payload["states"].append({"name": "Stored", "type_name": type_name})
    manifest = ContractManifest.from_payload(payload)
    assert manifest.states[-1].type_name == type_name


@pytest.mark.parametrize("type_name", [
    "{}", "Fixture::Empty{", "Fixture::Empty{ }", "Fixture::Empty{,}", "Fixture::Empty{: int}",
    "Fixture::Empty{field: int, }", "Fixture::Empty{}trailing", "List<Fixture::Empty{},2>",
    "List<Fixture::Empty{}, 0>", "Fixture::Envelope{empty: Fixture::Empty{}, empty: Fixture::Empty{}}",
    "StatePage{}", "Option{}", "int{}",
])
def test_manifest_rejects_malformed_empty_state_products(type_name: str) -> None:
    payload = _full_manifest_payload()
    payload["states"].append({"name": "Stored", "type_name": type_name})
    with pytest.raises(TypeError):
        ContractManifest.from_payload(payload)


def test_manifest_allows_amount_field_in_struct_nested_under_state_map() -> None:
    payload = _full_manifest_payload()
    payload["states"][0]["type_name"] = (
        "StateMap<AccountId, Fixture::Transfer{amount: quantity}>"
    )

    manifest = ContractManifest.from_payload(payload)

    assert (
        manifest.states[0].type_name
        == "StateMap<AccountId, Fixture::Transfer{amount: quantity}>"
    )


@pytest.mark.parametrize(
    "forged",
    [
        "Amount: quantity",
        "StateMap<AccountId, Amount: quantity>",
        "Fixture::Transfer{value: Result<int, Amount: quantity>}",
        "Fixture::Transfer{amount: Amount}",
        "Amount{amount: quantity}",
    ],
)
def test_manifest_does_not_exempt_retired_types_outside_struct_field_positions(
    forged: str,
) -> None:
    payload = _full_manifest_payload()
    payload["states"][0]["type_name"] = forged

    with pytest.raises(TypeError, match="retired Kotodama numeric type"):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    "forged",
    [
        "Fixture::Transfer{amount: : quantity}",
        "Fixture::Transfer{amount:quantity}",
        "Fixture::Transfer{amount: quantity, amount: quantity}",
        "Fixture::Transfer{Amount: quantity}",
        "Fixture::Transfer{ }",
        "List<quantity, 0>",
        "List<quantity, 65>",
        "StateMap<Json, quantity>",
        "Option<StateMap<AccountId, quantity>>",
        "(quantity)",
        "StateMap<AccountId, ΩAmount>",
    ],
)
def test_manifest_rejects_noncanonical_state_type_grammar(forged: str) -> None:
    payload = _full_manifest_payload()
    payload["states"][0]["type_name"] = forged

    with pytest.raises(
        TypeError,
        match="retired Kotodama numeric type|exact canonical Kotodama V1 state type",
    ):
        ContractManifest.from_payload(payload)


def test_manifest_state_type_enforces_runtime_schema_boundary() -> None:
    def wide_type(nodes: int) -> str:
        return f"({', '.join('int' for _ in range(nodes - 1))})"

    def deep_type(nodes: int) -> str:
        return f"{'Option<' * (nodes - 1)}int{'>' * (nodes - 1)}"

    for at_limit in (wide_type(256), deep_type(256)):
        payload = _full_manifest_payload()
        payload["states"].append({"name": "Boundary", "type_name": at_limit})
        assert ContractManifest.from_payload(payload).states[-1].type_name == at_limit

    for mapped_value in (wide_type(256), deep_type(255)):
        payload = _full_manifest_payload()
        mapped = f"StateMap<AccountId, {mapped_value}>"
        payload["states"][0]["type_name"] = mapped
        assert ContractManifest.from_payload(payload).states[0].type_name == mapped

    for forged in (
        wide_type(257),
        deep_type(257),
        f"StateMap<AccountId, {wide_type(257)}>",
        f"StateMap<AccountId, {deep_type(256)}>",
        f"StateMap<AccountId, {deep_type(257)}>",
    ):
        payload = _full_manifest_payload()
        payload["states"][0]["type_name"] = forged
        with pytest.raises(TypeError, match="exact canonical Kotodama V1 state type"):
            ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    "forged",
    [
        "Json",
        "ReferendumId",
        "Int",
        "Quantity",
        "Amount",
        "amount",
        "Foo{Amount: quantity}",
        "Foo{Amount:quantity}",
        "StateMap<AccountId, int>",
        "\N{CYRILLIC CAPITAL LETTER A}mount",
    ],
)
def test_manifest_rejects_noncanonical_dynamic_key_types(forged: str) -> None:
    payload = _full_manifest_payload()
    payload["access_set_hints"]["dynamic_reads"][0]["key_type"] = forged

    with pytest.raises(TypeError, match="exact Kotodama V1 StateMap key scalar"):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    ("field", "forged", "message"),
    [
        ("max_keys", 0, r"V1 range 1\.\.64"),
        ("max_keys", 65, r"V1 range 1\.\.64"),
        ("max_keys", 0xFFFFFFFF, r"V1 range 1\.\.64"),
        ("base_key", "state:", "state declaration identifier"),
        ("base_key", "state:*", "state declaration identifier"),
        ("base_key", "state:Balances/", "state declaration identifier"),
        ("base_key", "state:Balances/suffix", "state declaration identifier"),
        ("base_key", "state:Balances:suffix", "state declaration identifier"),
        ("base_key", "state:Amount", "state declaration identifier"),
        ("base_key", "state:int", "state declaration identifier"),
        ("base_key", "account:alice", "state declaration identifier"),
        ("base_key", " state:Balances", "exact non-empty string"),
        ("base_key", "state:Balances ", "exact non-empty string"),
        ("bound_kind", "", "exact non-empty string"),
        ("bound_kind", "Take", "exactly take or page"),
        ("bound_kind", "prefix", "exactly take or page"),
        (
            "bound_kind",
            "range",
            r"^dynamic access hint\.bound_kind must be exactly take or page$",
        ),
        ("bound_kind", "range ", "exact non-empty string"),
    ],
)
def test_manifest_rejects_noncanonical_dynamic_access_hints(
    field: str,
    forged: object,
    message: str,
) -> None:
    payload = _full_manifest_payload()
    payload["access_set_hints"]["dynamic_reads"][0][field] = forged

    with pytest.raises(TypeError, match=message):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    ("base_key", "key_type", "bound_kind", "max_keys"),
    [
        ("state:Balances", "AccountId", "take", 1),
        ("state:amount", "quantity", "page", 64),
    ],
)
def test_manifest_accepts_exact_dynamic_access_hints(
    base_key: str,
    key_type: str,
    bound_kind: str,
    max_keys: int,
) -> None:
    payload = _full_manifest_payload()
    hint = payload["access_set_hints"]["dynamic_reads"][0]
    hint.update(
        base_key=base_key,
        key_type=key_type,
        bound_kind=bound_kind,
        max_keys=max_keys,
    )
    if base_key == "state:amount":
        payload["states"].append(
            {"name": "amount", "type_name": "StateMap<quantity, int>"}
        )

    parsed = ContractManifest.from_payload(payload)

    assert parsed.access_set_hints.dynamic_reads[0].base_key == base_key
    assert parsed.access_set_hints.dynamic_reads[0].key_type == key_type
    assert parsed.access_set_hints.dynamic_reads[0].bound_kind == bound_kind
    assert parsed.access_set_hints.dynamic_reads[0].max_keys == max_keys


@pytest.mark.parametrize("field", ["dynamic_reads", "dynamic_writes"])
def test_manifest_rejects_duplicate_dynamic_access_hints_per_list(field: str) -> None:
    payload = _full_manifest_payload()
    hint = deepcopy(payload["access_set_hints"]["dynamic_reads"][0])
    _replace_dynamic_hints(payload, field, [hint, deepcopy(hint)])

    with pytest.raises(TypeError, match="duplicate dynamic access hint"):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize("field", ["dynamic_reads", "dynamic_writes"])
def test_manifest_allows_distinct_dynamic_access_hints_per_list(field: str) -> None:
    payload = _full_manifest_payload()
    first = deepcopy(payload["access_set_hints"]["dynamic_reads"][0])
    second = {**first, "bound_kind": "page", "max_keys": 2}
    _replace_dynamic_hints(payload, field, [first, second])

    parsed = ContractManifest.from_payload(payload)

    assert parsed.access_set_hints is not None
    assert len(getattr(parsed.access_set_hints, field)) == 2


@pytest.mark.parametrize("field", ["dynamic_reads", "dynamic_writes"])
@pytest.mark.parametrize(
    ("state_type", "base_key", "key_type", "message"),
    [
        (
            "StateMap<AccountId, quantity>",
            "state:Missing",
            "AccountId",
            "declared top-level StateMap",
        ),
        (
            "quantity",
            "state:Balances",
            "AccountId",
            "declared top-level StateMap",
        ),
        (
            "StateMap<AccountId, quantity>",
            "state:Balances",
            "Name",
            "does not match declared StateMap key type AccountId",
        ),
    ],
)
def test_manifest_rejects_dynamic_hints_not_matching_declared_state_maps(
    field: str,
    state_type: str,
    base_key: str,
    key_type: str,
    message: str,
) -> None:
    payload = _full_manifest_payload()
    payload["states"] = [{"name": "Balances", "type_name": state_type}]
    hint = {
        "base_key": base_key,
        "key_type": key_type,
        "bound_kind": "take",
        "max_keys": 1,
    }
    _replace_dynamic_hints(payload, field, [hint])

    with pytest.raises(TypeError, match=message):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize("field", ["dynamic_reads", "dynamic_writes"])
def test_manifest_accepts_state_amount_dynamic_hint(field: str) -> None:
    payload = _full_manifest_payload()
    payload["states"] = [
        {"name": "amount", "type_name": "StateMap<quantity, int>"}
    ]
    hint = {
        "base_key": "state:amount",
        "key_type": "quantity",
        "bound_kind": "page",
        "max_keys": 64,
    }
    _replace_dynamic_hints(payload, field, [hint])

    parsed = ContractManifest.from_payload(payload)

    assert parsed.access_set_hints is not None
    assert getattr(parsed.access_set_hints, field)[0].base_key == "state:amount"


def test_manifest_allows_same_dynamic_hint_once_in_each_list() -> None:
    payload = _full_manifest_payload()
    hint = deepcopy(payload["access_set_hints"]["dynamic_reads"][0])
    payload["access_set_hints"]["dynamic_writes"] = [deepcopy(hint)]

    parsed = ContractManifest.from_payload(payload)

    assert parsed.access_set_hints is not None
    assert parsed.access_set_hints.dynamic_reads == (
        parsed.access_set_hints.dynamic_writes
    )


@pytest.mark.parametrize("retired", ["bad identity", "bad<identity>", "__kotodama_link_hidden"])
def test_manifest_rejects_malformed_error_identities(retired: str) -> None:
    payload = _full_manifest_payload()
    payload["error_types"][0]["identity"] = retired

    with pytest.raises(TypeError, match="canonical nominal identity"):
        ContractManifest.from_payload(payload)


def test_manifest_allows_amount_as_error_variant_name() -> None:
    payload = _full_manifest_payload()
    payload["error_types"][0]["variants"][0]["name"] = "amount"

    manifest = ContractManifest.from_payload(payload)

    assert manifest.error_types[0].variants[0].name == "amount"


def test_manifest_rejects_exact_amount_in_every_identifier_position() -> None:
    cases = (
        ("entrypoint", ("entrypoints", 0, "name"), "Amount"),
        ("parameter", ("entrypoints", 0, "params", 0, "name"), "Amount"),
        ("state", ("states", 0, "name"), "Amount"),
        ("struct field", ("states", 0, "type_name"), "Fixture::Transfer{Amount: quantity}"),
        ("error variant", ("error_types", 0, "variants", 0, "name"), "Amount"),
        (
            "dynamic state base",
            ("access_set_hints", "dynamic_reads", 0, "base_key"),
            "state:Amount",
        ),
    )
    for _label, path, replacement in cases:
        payload = _full_manifest_payload()
        parent = payload
        for component in path[:-1]:
            parent = parent[component]
        parent[path[-1]] = replacement
        with pytest.raises(TypeError, match="canonical|identifier|state type"):
            ContractManifest.from_payload(payload)


def test_manifest_accepts_lowercase_amount_entrypoint_and_parameter() -> None:
    payload = _full_manifest_payload()
    entrypoint = payload["entrypoints"][0]
    entrypoint["name"] = "amount"
    entrypoint["params"][0]["name"] = "amount"
    entrypoint["argument_schema"]["fields"][0]["name"] = "amount"
    entrypoint["triggers"][0]["callback"]["entrypoint"] = "amount"

    manifest = ContractManifest.from_payload(payload)

    assert manifest.entrypoints[0].name == "amount"
    assert manifest.entrypoints[0].params[0].name == "amount"


def test_entrypoint_flat_list_schema_enforces_the_exact_depth_boundary() -> None:
    at_limit = {
        "nodes": [
            *({"kind": "List", "value": {"capacity": 1}} for _ in range(255)),
            {"kind": "Leaf", "value": {"kind": "Int", "value": None}},
        ]
    }
    schema = EntrypointValueTypeV1.from_payload(at_limit)
    assert schema.word_count == 1
    assert schema.canonical_type_name.count("List<") == 255

    for malformed in (
        {"nodes": []},
        {"nodes": [{"kind": "List", "value": {"capacity": 1}}]},
        {
            "nodes": [
                _leaf_node("Int"),
                _leaf_node("Bool"),
            ]
        },
        {
            "nodes": [
                {"kind": "List", "value": {"capacity": 1, "element": {}}},
                {"kind": "Leaf", "value": {"kind": "Int", "value": None}},
            ]
        },
        {
            "nodes": [
                {"kind": "List", "value": {"capacity": 0}},
                _leaf_node("Int"),
            ]
        },
        {
            "nodes": [
                {"kind": "List", "value": {"capacity": 65}},
                _leaf_node("Int"),
            ]
        },
        {
            "nodes": [
                *({"kind": "List", "value": {"capacity": 1}} for _ in range(256)),
                {"kind": "Leaf", "value": {"kind": "Int", "value": None}},
            ]
        },
    ):
        with pytest.raises(TypeError):
            EntrypointValueTypeV1.from_payload(malformed)


@pytest.mark.parametrize(
    ("filename", "expected_name"),
    [
        ("authority_probe.manifest.json", "AuthorityProbe"),
        ("irohaswap.manifest.json", "IrohaSwap"),
        ("ivm_smoke.manifest.json", "SmokeTransfer"),
        ("prediction_market.manifest.json", "PredictionMarket"),
    ],
)
def test_contract_manifest_decodes_checked_in_canonical_kotodama_manifests(
    filename: str, expected_name: str
) -> None:
    root = Path(__file__).resolve().parents[3]
    payload = json.loads((root / "demo" / filename).read_text(encoding="utf-8"))

    manifest = ContractManifest.from_payload(payload)

    assert manifest.seiyaku_name == expected_name
    assert manifest.code_hash is not None and len(manifest.code_hash) == 64
    assert manifest.abi_hash is not None and len(manifest.abi_hash) == 64
    assert manifest.entrypoints


@pytest.mark.parametrize(
    "value",
    [
        "",
        " Ledger ",
        "seiyaku",
        "match",
        "int",
        "Amount",
        "amount",
        "state_map_get",
        "__kotodama_quantity_ratio_round",
        "__kotodama_decimal_to_int_trunc",
        "__kotodama_decimal_to_int_round",
        "__kotodama_link_forged",
        "始まり",
        7,
        [],
        {},
    ],
)
def test_contract_manifest_rejects_invalid_seiyaku_name(value: object) -> None:
    with pytest.raises(TypeError, match="seiyaku_name"):
        ContractManifest.from_payload({"seiyaku_name": value})


@pytest.mark.parametrize(
    "value",
    [
        "b" * 64,
        "hash:" + "b" * 64 + "#ABA2",
        "hash:" + "B" * 64 + "#0000",
        "hash:" + "B" * 64 + "#aba2",
        "hash:" + "A" * 64 + "#0E5B",
        "blake2b32:" + "B" * 64 + "#ABA2",
    ],
)
def test_contract_manifest_rejects_noncanonical_hash_literals(value: str) -> None:
    with pytest.raises(TypeError, match="Hash|checksum|marker"):
        ContractManifest.from_payload({"code_hash": value})


def test_contract_manifest_rejects_non_object_provenance() -> None:
    with pytest.raises(TypeError, match="provenance"):
        ContractManifest.from_payload({"provenance": "not-an-object"})


@pytest.mark.parametrize(
    "provenance",
    [
        {"signer": "ed25519:fixture"},
        {"signer": "ed25519:fixture", "signature": ""},
        {
            "signer": "ed25519:fixture",
            "signature": "fixture-signature",
            "algorithm": "ed25519",
        },
    ],
)
def test_contract_manifest_rejects_nonexact_provenance(
    provenance: Dict[str, Any],
) -> None:
    with pytest.raises(TypeError, match="provenance|unsupported fields"):
        ContractManifest.from_payload({"provenance": provenance})


def test_contract_manifest_rejects_unknown_feature_bits() -> None:
    with pytest.raises(TypeError, match="unsupported Kotodama V1 feature bits"):
        ContractManifest.from_payload({"features_bitmap": 4})


def test_contract_manifest_record_cross_checks_hash_conveniences() -> None:
    manifest_payload = _full_manifest_payload()
    record = ContractManifestRecord.from_payload(
        {
            "network_id": _hash_literal("a5" * 32),
            "artifact_id": ContractArtifactId((1 << 64) - 1, "b" * 64).to_payload(),
            "manifest": manifest_payload,
            "code_hash": "b" * 64,
            "abi_hash": "d" * 64,
        }
    )

    assert record.artifact_id.dataspace_id == (1 << 64) - 1
    assert record.network_id == _hash_literal("a5" * 32)
    assert record.code_hash == record.manifest.code_hash == "b" * 64
    assert record.abi_hash == record.manifest.abi_hash == "d" * 64


def test_contract_manifest_record_rejects_unknown_top_level_fields() -> None:
    payload: Dict[str, Any] = {
        "network_id": _hash_literal("a5" * 32),
        "artifact_id": ContractArtifactId((1 << 64) - 1, "b" * 64).to_payload(),
        "manifest": _full_manifest_payload(),
        "code_hash": "b" * 64,
        "abi_hash": "d" * 64,
        "legacy": True,
    }
    with pytest.raises(TypeError, match="unsupported fields: legacy"):
        ContractManifestRecord.from_payload(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        {"code_hash": "d" * 64, "abi_hash": "d" * 64},
        {"code_hash": "B" * 64, "abi_hash": "d" * 64},
        {"abi_hash": "d" * 64},
        {"code_hash": "b" * 64, "abi_hash": "d" * 64, "code_bytes": 12},
    ],
)
def test_contract_manifest_record_rejects_mismatched_or_noncanonical_hashes(
    mutation: Dict[str, Any],
) -> None:
    payload: Dict[str, Any] = {
        "network_id": _hash_literal("a5" * 32),
        "artifact_id": ContractArtifactId((1 << 64) - 1, "b" * 64).to_payload(),
        "manifest": _full_manifest_payload(),
    }
    payload.update(mutation)

    with pytest.raises(TypeError, match="hash|contract bytes"):
        ContractManifestRecord.from_payload(payload)


@pytest.mark.parametrize("retired", ["Public", "Init", "Upgrade", "entry"])
def test_contract_manifest_rejects_noncanonical_entrypoint_kinds(retired: str) -> None:
    payload = _full_manifest_payload()
    payload["entrypoints"][0]["kind"] = {"kind": retired, "value": None}

    with pytest.raises(TypeError, match="entrypoint kind"):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    ("label", "expected", "name"),
    [
        ("Kotoage", ContractEntrypointKind.KOTOAGE, "transfer"),
        ("View", ContractEntrypointKind.VIEW, "transfer"),
        ("Hajimari", ContractEntrypointKind.HAJIMARI, "始まり"),
        ("Kaizen", ContractEntrypointKind.KAIZEN, "kaizen"),
    ],
)
def test_contract_manifest_accepts_only_branded_v1_entrypoint_kinds(
    label: str, expected: ContractEntrypointKind, name: str
) -> None:
    payload = _full_manifest_payload()
    payload["entrypoints"][0]["kind"] = {"kind": label, "value": None}
    payload["entrypoints"][0]["name"] = name
    if expected is not ContractEntrypointKind.KOTOAGE:
        payload["entrypoints"][0]["triggers"] = []
    if expected in {ContractEntrypointKind.HAJIMARI, ContractEntrypointKind.KAIZEN}:
        payload["entrypoints"][0]["authorization"] = {"kind": "RuntimeLifecycle", "value": None}

    manifest = ContractManifest.from_payload(payload)

    assert manifest.entrypoints is not None
    assert manifest.entrypoints[0].kind is expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda entrypoint: entrypoint.update(
            {"name": "init", "kind": {"kind": "Hajimari", "value": None}}
        ),
        lambda entrypoint: entrypoint.update(
            {"name": "hajimari", "kind": {"kind": "Kotoage", "value": None}}
        ),
        lambda entrypoint: entrypoint.update({"authorization": None}),
        lambda entrypoint: entrypoint.update(
            {
                "name": "kaizen",
                "kind": {"kind": "Kaizen", "value": None},
                "authorization": {"kind": "Permission", "value": "Upgrade"},
            }
        ),
    ],
)
def test_contract_manifest_rejects_lifecycle_or_authorization_forgery(
    mutate: Any,
) -> None:
    payload = _full_manifest_payload()
    mutate(payload["entrypoints"][0])

    with pytest.raises(TypeError):
        ContractManifest.from_payload(payload)


def test_contract_manifest_rejects_retired_or_ambiguous_manifest_fields() -> None:
    for retired in (
        "contract_name",
        "contractName",
        "featuresBitmap",
        "accessSetHints",
    ):
        payload = _full_manifest_payload()
        payload[retired] = "Legacy"
        with pytest.raises(TypeError, match="unsupported fields"):
            ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload["access_set_hints"].__setitem__("legacy", True),
        lambda payload: payload["access_set_hints"]["dynamic_reads"][0].__setitem__(
            "maxKeys", 64
        ),
        lambda payload: payload["entrypoints"][0].__setitem__("returnType", None),
        lambda payload: payload["entrypoints"][0]["kind"].__setitem__("legacy", None),
        lambda payload: payload["entrypoints"][0]["params"][0].__setitem__(
            "typeName", "struct Fixture::Transfer"
        ),
        lambda payload: payload["entrypoints"][0]["argument_schema"].__setitem__(
            "legacy", True
        ),
        lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][
            0
        ].__setitem__("legacy", True),
        lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][0][
            "ty"
        ].__setitem__("legacy", True),
        lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][0][
            "ty"
        ]["nodes"][0].__setitem__("legacy", True),
        lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][0][
            "ty"
        ]["nodes"][0]["value"].__setitem__("legacy", True),
        lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][0][
            "ty"
        ]["nodes"][1]["value"].__setitem__("legacy", True),
        lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][1][
            "ty"
        ]["nodes"][0]["value"].__setitem__("legacy", True),
        lambda payload: payload["entrypoints"][0]["triggers"][0].__setitem__(
            "legacy", True
        ),
        lambda payload: payload["entrypoints"][0]["triggers"][0]["repeats"].__setitem__(
            "Legacy", None
        ),
        lambda payload: payload["entrypoints"][0]["triggers"][0]["callback"].__setitem__(
            "entryPoint", "transfer"
        ),
        lambda payload: payload["states"][0].__setitem__("typeName", "quantity"),
        lambda payload: payload["error_types"][0]["variants"][0].__setitem__("errorCode", 1001),
        lambda payload: payload["kotoba"][0].__setitem__("msgId", "transfer.denied"),
        lambda payload: payload["kotoba"][0]["translations"][0].__setitem__(
            "language", "en"
        ),
        lambda payload: payload["provenance"].__setitem__("algorithm", "ed25519"),
    ],
)
def test_contract_manifest_rejects_unknown_fields_at_every_typed_layer(
    mutate: Any,
) -> None:
    payload = _full_manifest_payload()
    mutate(payload)
    with pytest.raises(TypeError, match="unsupported fields"):
        ContractManifest.from_payload(payload)


def test_contract_manifest_rejects_duplicate_and_unsafe_trigger_metadata() -> None:
    payload = _full_manifest_payload()
    payload["entrypoints"].append(deepcopy(payload["entrypoints"][0]))
    with pytest.raises(TypeError, match="duplicate entrypoint"):
        ContractManifest.from_payload(payload)

    payload = _full_manifest_payload()
    payload["entrypoints"].insert(
        0,
        {
            "name": "read",
            "kind": {"kind": "View", "value": None},
            "params": [],
            "argument_schema": None,
            "return_type": "()",
            "return_schema": {"nodes": [{"kind": "Unit", "value": None}]},
            "authorization": {"kind": "Anyone", "value": None},
            "read_keys": [],
            "write_keys": [],
            "access_hints_complete": True,
            "access_hints_skipped": [],
            "triggers": [],
        },
    )
    payload["entrypoints"][1]["triggers"][0]["callback"]["entrypoint"] = "read"
    with pytest.raises(TypeError, match="must target kotoage/言挙げ"):
        ContractManifest.from_payload(payload)

    payload = _full_manifest_payload()
    payload["entrypoints"][0]["triggers"][0]["filter"] += "\n"
    with pytest.raises(TypeError, match="standard-base64"):
        ContractManifest.from_payload(payload)


def test_contract_manifest_rejects_non_null_enum_payloads() -> None:
    payload = _full_manifest_payload()
    payload["entrypoints"][0]["kind"]["value"] = "Kotoage"

    with pytest.raises(TypeError, match="must be null"):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][1]["ty"][
                "nodes"
            ][0]["value"].__setitem__("capacity", 65),
            "capacity",
        ),
        (
            lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][1]["ty"][
                "nodes"
            ][0]["value"].__setitem__(
                "element",
                {"nodes": [{"kind": "Leaf", "value": {"kind": "Name", "value": None}}]},
            ),
            "unsupported fields",
        ),
        (
            lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][1]["ty"][
                "nodes"
            ].pop(),
            "canonical V1 schema",
        ),
        (
            lambda payload: payload["entrypoints"][0]["return_schema"]["nodes"].append(
                {"kind": "Leaf", "value": {"kind": "Bool", "value": None}}
            ),
            "canonical V1 schema",
        ),
        (
            lambda payload: payload["entrypoints"][0]["argument_schema"]["fields"][0]["ty"][
                "nodes"
            ][0]["value"].__setitem__("fields", ["memo", "memo"]),
            "canonical V1 schema",
        ),
        (
            lambda payload: payload["error_types"][0]["variants"][0].__setitem__("code", 0),
            "non-zero u32",
        ),
        (
            lambda payload: payload["entrypoints"][0]["params"][0].__setitem__("name", "different"),
            "canonical exact V1 interface",
        ),
        (
            lambda payload: payload["entrypoints"][0].__setitem__("return_type", None),
            "canonical exact V1 interface",
        ),
    ],
)
def test_contract_manifest_rejects_invalid_v1_shapes(mutate: Any, message: str) -> None:
    payload = deepcopy(_full_manifest_payload())
    mutate(payload)

    with pytest.raises(TypeError, match=message):
        ContractManifest.from_payload(payload)


def test_contract_manifest_rejects_overwide_argument_record() -> None:
    payload = _full_manifest_payload()
    payload["entrypoints"][0]["params"] = [
        {"name": f"field_{index}", "type_name": "bool"}
        for index in range(8193)
    ]
    payload["entrypoints"][0]["argument_schema"]["fields"] = [
        {
            "name": f"field_{index}",
            "ty": {"nodes": [{"kind": "Leaf", "value": {"kind": "Bool", "value": None}}]},
        }
        for index in range(8193)
    ]

    with pytest.raises(TypeError, match="canonical V1 bounds"):
        ContractManifest.from_payload(payload)


def test_contract_manifest_rejects_return_schema_exceeding_node_bound() -> None:
    payload = _full_manifest_payload()
    payload["entrypoints"][0]["return_type"] = "(" + ", ".join(["bool"] * 256) + ")"
    payload["entrypoints"][0]["return_schema"] = {
        "nodes": [
            {"kind": "Tuple", "value": 256},
            *[{"kind": "Leaf", "value": {"kind": "Bool", "value": None}} for _ in range(256)],
        ]
    }

    with pytest.raises(TypeError, match="canonical V1 schema"):
        ContractManifest.from_payload(payload)


@pytest.mark.parametrize("dataspace", [0, (1 << 63), (1 << 64) - 1])
def test_contract_artifact_scope_has_exact_full_width_json_and_path(dataspace: int) -> None:
    artifact = ContractArtifactId(dataspace, "b" * 64)
    assert artifact.path == f"/v1/contracts/artifacts/{dataspace}/{'b' * 64}"
    assert artifact.to_payload() == {"dataspace_id": dataspace, "code_hash": _hash_literal("b" * 64)}
    assert ContractArtifactId.from_payload(artifact.to_payload()) == artifact


@pytest.mark.parametrize("dataspace", [-1, 1 << 64, True, "1", 1.0])
def test_contract_artifact_scope_rejects_non_u64(dataspace: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        ContractArtifactId(dataspace, "b" * 64)


def test_contract_manifest_record_requires_scope_and_hash_agreement() -> None:
    payload = {
        "network_id": _hash_literal("a5" * 32),
        "artifact_id": ContractArtifactId(1, "b" * 64).to_payload(),
        "manifest": _full_manifest_payload(),
        "code_hash": "b" * 64,
        "abi_hash": "d" * 64,
    }
    for field in ["network_id", "artifact_id"]:
        incomplete = dict(payload)
        del incomplete[field]
        with pytest.raises(TypeError):
            ContractManifestRecord.from_payload(incomplete)
    payload["artifact_id"] = ContractArtifactId(1, "d" * 64).to_payload()
    with pytest.raises(TypeError, match="artifact_id.code_hash"):
        ContractManifestRecord.from_payload(payload)


def test_mock_artifacts_keep_equal_hashes_in_separate_dataspaces() -> None:
    from iroha_torii_client.mock import _MockState, _artifact_fixture_key
    state = _MockState()
    digest = "b" * 64
    state.contract_manifests = {f"1/{digest}": {"scope": 1}, f"18446744073709551615/{digest}": {"scope": 2}}
    state.contract_code_bytes = {f"1/{digest}": {"code_b64": "AAAA"}}
    for scope, expected in [(1, 1), ((1 << 64) - 1, 2)]:
        response = state.handle_request("GET", f"/v1/contracts/artifacts/{scope}/{digest}", {}, b"", {})
        assert response.status == 200
        assert json.loads(response.body)["scope"] == expected
    assert state.handle_request("GET", f"/v1/contracts/artifacts/2/{digest}", {}, b"", {}).status == 404
    assert state.handle_request("GET", f"/v1/contracts/artifacts/1/{digest}/bytes", {}, b"", {}).status == 200
    assert state.handle_request("GET", f"/v1/contracts/artifacts/2/{digest}/bytes", {}, b"", {}).status == 404
    for invalid in [f"01/{digest}", f"-1/{digest}", f"18446744073709551616/{digest}", digest]:
        with pytest.raises(ValueError):
            _artifact_fixture_key(invalid)


def test_authorization_requires_canonical_declaration_table() -> None:
    payload = _full_manifest_payload()
    parsed = ContractManifest.from_payload(payload)
    assert parsed.entrypoints[0].authorization.kind == "Permission"
    assert parsed.permissions[0].scope.kind == "Instance"
    payload["permissions"][0]["scope"] = {
        "kind": "Chain", "value": {"permission_name": "SharedOperators"}
    }
    assert ContractManifest.from_payload(payload).permissions[0].scope.permission_name == "SharedOperators"
    mutations = [
        lambda value: value.pop("permissions"),
        lambda value: value.update(permissions=[]),
        lambda value: value["permissions"].append(deepcopy(value["permissions"][0])),
        lambda value: value["entrypoints"][0].update(authorization="TransferAsset"),
        lambda value: value["entrypoints"][0].update(authorization={"kind": "RuntimeLifecycle", "value": None}),
        lambda value: value["entrypoints"][0].update(permission="TransferAsset"),
        lambda value: value["permissions"][0]["scope"].update(value="unexpected"),
    ]
    for mutate in mutations:
        invalid = _full_manifest_payload()
        mutate(invalid)
        with pytest.raises(TypeError):
            ContractManifest.from_payload(invalid)


def _ordinary_enum_manifest_payload() -> Dict[str, Any]:
    payload = _full_manifest_payload()
    descriptor = {"identity": "Ledger::Status", "variants": [{"name": "Pending", "code": 1}, {"name": "Done", "code": 7}]}
    payload["enum_types"] = [descriptor]
    payload["events"] = [{"name": "Changed", "payload_type": {"nodes": [
        {"kind": "Struct", "value": {"name": "Demo::Changed", "fields": ["status"]}},
        {"kind": "Enum", "value": deepcopy(descriptor)},
    ]}}]
    payload["states"].append({"name": "status", "type_name": "Ledger::Status"})
    return payload


def test_manifest_ordinary_enums_and_events_bind_exact_nominal_descriptors() -> None:
    parsed = ContractManifest.from_payload(_ordinary_enum_manifest_payload())
    assert parsed.enum_types[0].variants[1].code == 7
    node = parsed.events[0].payload_type.nodes[1]
    assert node.kind is EntrypointValueTypeNodeKindV1.ENUM
    assert node.value == parsed.enum_types[0]
    assert parsed.events[0].payload_type.word_count == 1
    assert EntrypointValueTypeV1((node,)).canonical_type_name == "Ledger::Status"


@pytest.mark.parametrize("mutate", [
    lambda value: value.pop("enum_types"),
    lambda value: value.pop("events"),
    lambda value: value.update(enum_types=None),
    lambda value: value.update(events=None),
    lambda value: value["enum_types"].append(deepcopy(value["enum_types"][0])),
    lambda value: value["enum_types"][0]["variants"][0].update(code=0),
    lambda value: value["enum_types"][0]["variants"][1].update(code=1),
    lambda value: value["enum_types"][0]["variants"][1].update(name="Pending"),
    lambda value: value["enum_types"][0].update(extra=True),
    lambda value: value["error_types"].append(deepcopy(value["enum_types"][0])),
    lambda value: value["events"][0]["payload_type"]["nodes"][1]["value"]["variants"][1].update(code=8),
    lambda value: value["events"][0]["payload_type"]["nodes"][1].update(kind="Error"),
    lambda value: value["events"][0]["payload_type"]["nodes"][0]["value"].update(name="Other"),
    lambda value: value["events"][0]["payload_type"]["nodes"][1].update(kind="Leaf", value={"kind": "Json", "value": None}),
    lambda value: value["events"][0]["payload_type"]["nodes"][1].update(kind="StateCursor", value={"nodes": [_leaf_node("Int")]}),
    lambda value: value["events"].append(deepcopy(value["events"][0])),
])
def test_manifest_rejects_incomplete_or_forged_enum_and_event_metadata(mutate: Any) -> None:
    payload = _ordinary_enum_manifest_payload()
    mutate(payload)
    with pytest.raises(TypeError):
        ContractManifest.from_payload(payload)

def test_durable_builtin_products_require_exact_shapes() -> None:
    vectors = json.loads((Path(__file__).resolve().parents[3] / "fixtures/kotodama/durable_builtin_shapes_v1.json").read_text())
    for type_name in vectors["valid"]:
        payload = _full_manifest_payload()
        payload["states"].append({"name": "stored", "type_name": type_name})
        assert ContractManifest.from_payload(payload).states[-1].type_name == type_name
    for type_name in vectors["invalid"]:
        payload = _full_manifest_payload()
        payload["states"].append({"name": "stored", "type_name": type_name})
        with pytest.raises(TypeError):
            ContractManifest.from_payload(payload)
