"""Native-free execution of the real batch/draft/submit/sign timestamp boundary.

Preparation, native, and transport collaborators are isolated test doubles.
These checks do not qualify the native encoder, cryptography, or a live transaction.
"""

from __future__ import annotations

import ast
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import pytest
import requests

SOURCE = Path(__file__).resolve().parents[1] / "src" / "iroha_python"
PACKAGE = "_iroha_contract_batch_timestamp_test"


def _load_source(module, filename, functions, classes=None):
    tree = ast.parse((SOURCE / filename).read_text(encoding="utf-8"))
    body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            body.append(node)
        elif isinstance(node, ast.ClassDef) and node.name in (classes or {}):
            methods = classes[node.name]
            if methods is not None:
                node.bases = []
                node.body = [item for item in node.body
                             if isinstance(item, ast.FunctionDef) and item.name in methods]
            body.append(node)
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 str(SOURCE / filename), "exec"), module.__dict__)


@pytest.fixture
def boundary(monkeypatch):
    package = types.ModuleType(PACKAGE)
    package.__path__ = []
    monkeypatch.setitem(sys.modules, PACKAGE, package)
    crypto = types.ModuleType(f"{PACKAGE}.crypto")

    class Instruction:
        def to_norito_bytes(self):
            return b"prepared-native-instruction"

        def wire_id(self):
            return "instruction:test"

    crypto.Instruction = Instruction
    monkeypatch.setitem(sys.modules, crypto.__name__, crypto)
    signing_calls = []
    clock_calls = []
    envelope = types.SimpleNamespace(hash="ab" * 32)

    def sign(*args, **kwargs):
        signing_calls.append((args, kwargs))
        return envelope

    def clock():
        clock_calls.append(None)
        return 1_700_000_000.125 + len(clock_calls)

    tx = types.ModuleType(f"{PACKAGE}.tx")
    tx.__dict__.update(
        dataclass=dataclass, Mapping=Mapping, MappingProxyType=types.MappingProxyType,
        time=types.SimpleNamespace(time=clock), _U64_MAX=(1 << 64) - 1,
        _require_network_id=lambda value, context: value,
        build_signed_transaction=sign,
        authority_fee_payment=lambda **kwargs: {"payer": "authority", "value": kwargs},
    )
    monkeypatch.setitem(sys.modules, tx.__name__, tx)
    _load_source(tx, "_validation.py", {
        "_optional_uint", "_normalize_mapping_payload", "_normalize_json_value",
    })
    _load_source(tx, "tx.py", {
        "_require_non_empty_string", "_require_exact_non_empty_string",
        "_ensure_creation_time_ms", "_normalize_metadata", "_freeze_json", "_thaw_json",
    }, {
        "TransactionConfig": None,
        "TransactionDraft": {"__init__", "use_executable_batch", "add_instruction", "sign"},
    })
    client_module = types.ModuleType(f"{PACKAGE}.client")
    client_module.__package__ = PACKAGE
    client_module.__dict__.update(
        Mapping=Mapping, requests=requests,
        _require_exact_non_empty_string=tx._require_exact_non_empty_string,
        _normalize_contract_call_metadata=lambda metadata, **kwargs: dict(metadata or {}),
        _extract_pipeline_status_kind=lambda value: value["kind"],
    )
    _load_source(client_module, "client.py", set(), {"ToriiClient": {
        "_transaction_draft", "_submit_transaction_draft_result", "_sign_transaction_draft",
        "call_contract_batch_and_wait",
    }})
    client = client_module.ToriiClient( chain_discriminant=753)
    network_id = object()
    client._native_transaction_account_id = lambda value, context: value
    client._require_local_signing_context = lambda context: types.SimpleNamespace(network_id=network_id)
    client._envelope_hash_hex = lambda signed: signed.hash
    submissions = []
    client.submit_transaction_envelope = lambda signed: submissions.append(signed) or {"accepted": True}
    polls = []
    client.wait_for_transaction_status = lambda hash_hex, **kwargs: polls.append(hash_hex) or {"kind": "Applied"}
    instruction = Instruction()
    binding = {"version": 1, "items": [{"index": 0, "kind": "instruction"}]}
    client.prepare_contract_call_batch = lambda entries: types.SimpleNamespace(
        binding=binding, binding_digest_hex="cd" * 32,
        prepared_entries=(types.SimpleNamespace(
            kind="instruction", instruction=instruction.to_norito_bytes(), wire_id=instruction.wire_id(),
        ),),
    )
    return types.SimpleNamespace(
        client=client, instruction=instruction, signing_calls=signing_calls,
        clock_calls=clock_calls, submissions=submissions, polls=polls, envelope=envelope,
        binding=binding, network_id=network_id,
    )


@pytest.mark.parametrize("creation_time_ms", [None, 0, 1_725_000_000_123])
@pytest.mark.parametrize("wait", [False, True])
def test_contract_batch_stages_timestamp_before_actual_submission(boundary, creation_time_ms, wait):
    result = boundary.client.call_contract_batch_and_wait(
        authority="exact-account", entries=[boundary.instruction], private_key=b"\x11" * 32,
        creation_time_ms=creation_time_ms, ttl_ms=60_000, wait=wait,
    )
    assert len(boundary.signing_calls) == 1
    args, signed = boundary.signing_calls[0]
    assert args == (boundary.network_id, "exact-account", b"\x11" * 32)
    assert signed["creation_time_ms"] == (1_700_000_001_125 if creation_time_ms is None else creation_time_ms)
    assert len(boundary.clock_calls) == (1 if creation_time_ms is None else 0)
    assert signed["nonce"] is None
    assert signed["ttl_ms"] == 60_000
    assert signed["entries"] == [boundary.instruction]
    assert signed["metadata"]["contract_batch_binding_v1"]["binding"] == boundary.binding
    assert boundary.submissions == [boundary.envelope]
    assert boundary.polls == ([boundary.envelope.hash] if wait else [])
    assert result["hash"] == result["tx_hash_hex"] == boundary.envelope.hash
    if wait:
        assert result["terminal_kind"] == "Applied"


@pytest.mark.parametrize("creation_time_ms", [True, 1.5, -1, 1 << 64])
def test_contract_batch_rejects_invalid_timestamp_before_signing(boundary, creation_time_ms):
    with pytest.raises((TypeError, ValueError), match="TransactionConfig.creation_time_ms"):
        boundary.client.call_contract_batch_and_wait(
            authority="exact-account", entries=[boundary.instruction], private_key=b"\x11" * 32,
            creation_time_ms=creation_time_ms, wait=False,
        )
    assert boundary.signing_calls == []
    assert boundary.submissions == []


def test_draft_resigning_retains_staged_timestamp_and_nonce(boundary):
    draft = boundary.client._transaction_draft(authority="exact-account", nonce=7)
    draft.use_executable_batch().add_instruction(boundary.instruction)
    for _ in range(2):
        boundary.client._submit_transaction_draft_result(
            draft, private_key=b"\x11" * 32, wait=False,
        )
    assert len(boundary.clock_calls) == 1
    assert [(call[1]["creation_time_ms"], call[1]["nonce"])
            for call in boundary.signing_calls] == [(1_700_000_001_125, 7)] * 2
    with pytest.raises(TypeError, match="creation_time_ms"):
        boundary.client._submit_transaction_draft_result(
            draft, private_key=b"\x11" * 32, creation_time_ms=2, wait=False,
        )
