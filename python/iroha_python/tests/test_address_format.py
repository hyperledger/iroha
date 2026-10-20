from __future__ import annotations

import inspect
import json
from types import SimpleNamespace
from typing import Any, Dict, Optional, Union

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import iroha_python.address as address_module
import iroha_python.client as client_module
from client_expensive_query_test_support import authenticated_query_client
from iroha_python import (
    AggregateFn,
    AggregateMetric,
    AggregateSpec,
    F,
    ListQueryError,
    NetworkId,
    ToriiClient,
    TriggerCompletionList,
)
from iroha_python.address import AccountAddress, AccountAddressError
from iroha_python.crypto import (
    derive_ed25519_keypair_from_seed,
    ed25519_public_key_account_id,
)

CANONICAL_ED25519_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
CANONICAL_ACCOUNT_ID = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"


class StubResponse(requests.Response):
    def __init__(self, payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self.status_code = 200
        self._payload = {"items": [], "next_cursor": None} if payload is None else payload
        self.headers = CaseInsensitiveDict({"Content-Type": "application/json"})
        self._content = json.dumps(self._payload).encode("utf-8")
        self._content_consumed = True
        self.encoding = "utf-8"

    def json(self, **kwargs: Any) -> Any:
        return json.loads(self.content.decode("utf-8"))

    def close(self) -> None:
        return None

    def __enter__(self) -> "StubResponse":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
        return None


class RecordingSession(requests.Session):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[Dict[str, Any]] = []
        self._response = StubResponse()

    def request(
        self,
        method: Union[str, bytes],
        url: Union[str, bytes],
        *args: Any,
        **kwargs: Any,
    ) -> requests.Response:
        params = kwargs.get("params") or {}
        headers = kwargs.get("headers") or {}
        data = kwargs.get("data")
        self.calls.append(
            {
                "method": method,
                "url": url,
                "params": params,
                "headers": headers,
                "data": data,
            }
        )
        return self._response

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        self.calls.append(
            {
                "method": request.method,
                "url": request.url,
                "params": {},
                "headers": dict(request.headers),
                "data": request.body,
            }
        )
        return self._response


def _client_with_session() -> tuple[ToriiClient, RecordingSession]:
    session = RecordingSession()
    client = ToriiClient("http://localhost:8080", session=session, chain_discriminant=753)
    return client, session


def test_get_transaction_status_defaults_to_global_scope() -> None:
    client, session = _client_with_session()
    tx_hash = "ab" * 32
    status = {
        "hash": tx_hash,
        "status": {"kind": "Committed"},
        "scope": "global",
        "resolved_from": "queue",
    }
    session._response = StubResponse(payload=status)

    payload = client.get_transaction_status(tx_hash)

    assert payload == status
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"] == "http://localhost:8080/v1/pipeline/transactions/status"
    assert session.calls[0]["params"] == {"hash": tx_hash, "scope": "global"}


@pytest.mark.parametrize("status_code", (202, 204))
def test_get_transaction_status_rejects_non_contract_success_codes(
    status_code: int,
) -> None:
    client, session = _client_with_session()
    tx_hash = "ab" * 32
    session._response.status_code = status_code

    with pytest.raises(RuntimeError, match=rf"unexpected status {status_code}"):
        client.get_transaction_status(tx_hash)


def test_get_transaction_status_retains_explicit_local_read() -> None:
    client, session = _client_with_session()
    tx_hash = "a1" * 32
    status = {
        "hash": tx_hash,
        "status": {"kind": "Queued"},
        "scope": "local",
        "resolved_from": "queue",
    }
    session._response = StubResponse(payload=status)

    assert client.get_transaction_status(tx_hash, scope="local") == status
    assert session.calls[0]["params"] == {"hash": tx_hash, "scope": "local"}


def test_pipeline_status_requires_exact_lowercase_full_hashes() -> None:
    client, session = _client_with_session()
    invalid_hashes: tuple[Any, ...] = (
        "AB" * 32,
        "0x" + "ab" * 32,
        " " + "ab" * 32,
        "ab" * 31,
        "aa" * 32,
        b"\xab" * 32,
        "blake2b32:" + "ab" * 32,
    )

    for tx_hash in invalid_hashes:
        expected_error = TypeError if isinstance(tx_hash, bytes) else ValueError
        with pytest.raises(expected_error, match="must (be a string|match .*canonical Iroha HashOf marker)"):
            client.get_transaction_status(tx_hash)
        with pytest.raises(expected_error, match="must (be a string|match .*canonical Iroha HashOf marker)"):
            client.wait_for_transaction_status(
                tx_hash,
                interval=0,
                timeout=0,
            )

    assert session.calls == []


def test_get_transaction_status_rejects_noncanonical_response_hash() -> None:
    client, session = _client_with_session()
    tx_hash = "ab" * 32
    session._response = StubResponse(
        payload={
            "hash": tx_hash.upper(),
            "status": {"kind": "Applied", "block_height": 1},
            "scope": "global",
            "resolved_from": "state",
        }
    )

    with pytest.raises(ValueError, match="canonical Iroha HashOf marker"):
        client.get_transaction_status(tx_hash)


@pytest.mark.parametrize(
    "options",
    (
        {"interval": -1},
        {"interval": float("nan")},
        {"timeout": -1},
        {"timeout": float("inf")},
        {"max_attempts": 0},
        {"max_attempts": True},
        {"on_status": "callback"},
    ),
)
def test_wait_for_transaction_status_rejects_coerced_polling_options(
    options: Dict[str, Any],
) -> None:
    client, session = _client_with_session()

    with pytest.raises((TypeError, ValueError)):
        client.wait_for_transaction_status("ab" * 32, **options)

    assert session.calls == []


def test_wait_for_transaction_status_is_fixed_to_authoritative_global_applied() -> None:
    client, session = _client_with_session()
    tx_hash = "bb" * 32
    status = {
        "hash": tx_hash,
        "status": {"kind": "Applied", "block_height": 7},
        "scope": "global",
        "resolved_from": "state",
    }
    session._response = StubResponse(payload=status)

    payload = client.wait_for_transaction_status(
        tx_hash,
        interval=0,
        timeout=1,
    )

    assert payload == status
    assert session.calls[0]["params"] == {"hash": tx_hash, "scope": "global"}


def test_wait_for_transaction_status_treats_non_state_and_pre_applied_kinds_as_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session = _client_with_session()
    tx_hash = "bf" * 32
    responses = iter(
        [
            {
                "hash": tx_hash,
                "status": {"kind": "Committed", "block_height": 7},
                "scope": "global",
                "resolved_from": "state",
            },
            {
                "hash": tx_hash,
                "status": {"kind": "Applied", "block_height": 7},
                "scope": "global",
                "resolved_from": "cache",
            },
            {
                "hash": tx_hash,
                "status": {"kind": "Rejected", "block_height": 7},
                "scope": "global",
                "resolved_from": "cache",
            },
            {
                "hash": tx_hash,
                "status": {"kind": "Applied", "block_height": 7},
                "scope": "global",
                "resolved_from": "state",
            },
        ]
    )
    observed_scopes: list[str] = []
    callbacks: list[tuple[Optional[str], int]] = []

    def get_status(
        requested_hash: str,
        *,
        scope: str,
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        assert requested_hash == tx_hash
        assert timeout is None or timeout >= 0
        observed_scopes.append(scope)
        return next(responses)

    monkeypatch.setattr(client, "get_transaction_status", get_status)
    result = client.wait_for_transaction_status(
        tx_hash,
        interval=0,
        timeout=1,
        max_attempts=4,
        on_status=lambda kind, _payload, attempt: callbacks.append((kind, attempt)),
    )

    assert result["status"]["kind"] == "Applied"
    assert result["resolved_from"] == "state"
    assert observed_scopes == ["global"] * 4
    assert callbacks == [
        ("Committed", 1),
        ("Applied", 2),
        ("Rejected", 3),
        ("Applied", 4),
    ]


def test_wait_for_transaction_status_requires_global_response_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session = _client_with_session()
    tx_hash = "bd" * 32
    monkeypatch.setattr(
        client,
        "get_transaction_status",
        lambda *_args, **_kwargs: {
            "hash": tx_hash,
            "status": {"kind": "Applied", "block_height": 1},
            "scope": "local",
            "resolved_from": "state",
        },
    )

    with pytest.raises(ValueError, match="scope must be exactly global"):
        client.wait_for_transaction_status(tx_hash, interval=0, timeout=1)


def test_wait_for_transaction_status_has_fixed_failure_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session = _client_with_session()
    tx_hash = "b1" * 32

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        client.wait_for_transaction_status(
            tx_hash,
            interval=0,
            timeout=1,
            **{"additional_failure_statuses": ("Committed",)},
        )

    monkeypatch.setattr(
        client,
        "get_transaction_status",
        lambda *_args, **_kwargs: {
            "hash": tx_hash,
            "status": {"kind": "Committed", "block_height": 1},
            "scope": "global",
            "resolved_from": "state",
        },
    )
    with pytest.raises(TimeoutError, match="after 1 attempts"):
        client.wait_for_transaction_status(
            tx_hash,
            interval=0,
            timeout=1,
            max_attempts=1,
        )

    monkeypatch.setattr(
        client,
        "get_transaction_status",
        lambda *_args, **_kwargs: {
            "hash": tx_hash,
            "status": {"kind": "Rejected", "block_height": 1},
            "scope": "global",
            "resolved_from": "state",
        },
    )
    with pytest.raises(client_module.TransactionStatusError) as fixed:
        client.wait_for_transaction_status(
            tx_hash,
            interval=0,
            timeout=1,
        )
    assert fixed.value.status == "Rejected"


def test_transaction_status_scope_rejects_auto_and_injected_values() -> None:
    client, session = _client_with_session()
    tx_hash = "c1" * 32

    for scope in (
        "auto",
        "GLOBAL",
        " global ",
        "global&scope=local",
        "local,global",
        "../global",
    ):
        with pytest.raises(ValueError, match="must be one of: local, global"):
            client.get_transaction_status(tx_hash, scope=scope)

    with pytest.raises(TypeError, match="unexpected keyword argument 'scope'"):
        client.wait_for_transaction_status(
            tx_hash,
            interval=0,
            timeout=0,
            **{"scope": "GLOBAL\nscope=local"},
        )

    assert session.calls == []


def test_get_transaction_status_rejects_retired_sensitive_fields() -> None:
    client, session = _client_with_session()
    tx_hash = "dd" * 32
    session._response = StubResponse(
        payload={
            "hash": tx_hash,
            "status": {"kind": "Rejected", "rejection_reason": "secret"},
            "summary": "Rejected: secret",
            "diagnostics": [{"message": "secret"}],
            "scope": "global",
            "resolved_from": "state",
        }
    )

    with pytest.raises(ValueError, match="retired or unsupported fields"):
        client.get_transaction_status(tx_hash)


def test_get_transaction_status_rejects_retired_auto_response_scope() -> None:
    client, session = _client_with_session()
    tx_hash = "df" * 32
    session._response = StubResponse(
        payload={
            "hash": tx_hash,
            "status": {"kind": "Applied", "block_height": 1},
            "scope": "auto",
            "resolved_from": "state",
        }
    )

    with pytest.raises(ValueError, match="scope is unsupported"):
        client.get_transaction_status(tx_hash)


def test_build_and_submit_transaction_exposes_no_wait_scope_or_success_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session = _client_with_session()
    envelope = SimpleNamespace(hash=b"\xaa" * 32)
    captured: Dict[str, Any] = {}

    class FakeCrypto:
        @staticmethod
        def build_signed_transaction(*args: Any, **_kwargs: Any) -> Any:
            captured["network_id"] = args[0]
            return envelope

    def fake_submit_transaction_envelope_and_wait(
        submitted_envelope: Any,
        **kwargs: Any,
    ) -> Dict[str, str]:
        captured["envelope"] = submitted_envelope
        captured.update(kwargs)
        return {"status": "Committed"}

    monkeypatch.setattr(client_module, "_require_crypto", lambda: FakeCrypto)
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope_and_wait",
        fake_submit_transaction_envelope_and_wait,
    )

    network_id = NetworkId.from_bytes(b"\xA5" * 32)
    envelope_out, result = client.build_and_submit_transaction(
        network_id,
        "testuﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
        b"\x11" * 32,
        fee_payment={
            "payer": "authority",
            "value": {"charge_limits": [], "gas_limit": None},
        },
    )

    assert envelope_out is envelope
    assert result == {"status": "Committed"}
    assert captured["envelope"] is envelope
    assert captured["network_id"] == network_id
    assert "scope" not in captured
    assert "success_statuses" not in captured


def test_transaction_wait_signatures_remove_scope_and_success_statuses() -> None:
    wait_methods = (
        "wait_for_transaction_status",
        "submit_transaction_draft_and_wait",
        "submit_transaction_json_and_wait",
        "submit_transaction_envelope_and_wait",
        "build_and_submit_transaction",
        "submit_instructions_and_wait",
        "call_contract_batch_and_wait",
        "call_contract_and_wait",
        "submit_signed_privacy_zk_x509_identity_presentation_action_v1",
    )
    for method_name in wait_methods:
        parameters = inspect.signature(getattr(ToriiClient, method_name)).parameters
        assert "scope" not in parameters, method_name
        assert "success_statuses" not in parameters, method_name


def test_submit_and_wait_rejects_noncanonical_envelope_hash_before_submission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session = _client_with_session()
    submissions: list[object] = []
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope",
        lambda envelope: submissions.append(envelope),
    )

    with pytest.raises(ValueError, match="must match .*canonical Iroha HashOf marker"):
        client.submit_transaction_envelope_and_wait(
            SimpleNamespace(hash="AB" * 32),
            interval=0,
            timeout=1,
        )
    assert submissions == []


def test_transactions_collection_routes_list_queries_and_rejects_aggregates() -> None:
    session = RecordingSession()
    client = authenticated_query_client(session)
    aggregate = AggregateSpec(
        group_by=["result_ok"],
        metrics=[AggregateMetric("transactions", AggregateFn.COUNT)],
    )

    with pytest.raises(ListQueryError) as raised:
        client.transactions.rows(aggregate=aggregate)
    assert raised.value.code == "invalid_aggregate"
    assert session.calls == []

    client.transactions.rows(filter=F.result_ok == False, select=["entrypoint_hash"], limit=5)  # noqa: E712

    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://torii.example/v1/transactions/query"
    assert json.loads(call["data"].decode("utf-8")) == {
        "filter": {"op": "eq", "args": ["result_ok", False]},
        "select": ["entrypoint_hash"],
        "limit": 5,
    }


def test_list_trigger_completions_returns_typed_step_evidence() -> None:
    client, session = _client_with_session()
    session._response = StubResponse(
        payload={
            "latest_height": 42,
            "from_height": 40,
            "to_height": 42,
            "scanned_blocks": 3,
            "limit": 10,
            "completions": [
                {
                    "block_height": 41,
                    "entrypoint_index": 2,
                    "completion": {
                        "trigger_id": "minimum-liquidity",
                        "trigger_execution_hash": "hash:trigger-execution",
                        "step_index": 1,
                        "outcome": "Success",
                        "message": None,
                    },
                    "source": "execution_output",
                }
            ],
        }
    )

    result = client.list_trigger_completions(
        trigger_id="minimum-liquidity",
        entrypoint_hash="hash:trigger-execution",
        outcome="success",
        from_height=40,
        to_height=42,
        limit=10,
        scan_limit_blocks=3,
    )

    assert isinstance(result, TriggerCompletionList)
    assert result.latest_height == 42
    assert result.completions[0].completion.step_index == 1
    assert result.completions[0].source == "execution_output"
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"] == "http://localhost:8080/v1/triggers/completed"
    assert session.calls[0]["params"] == {
        "id": "minimum-liquidity",
        "entrypoint_hash": "hash:trigger-execution",
        "outcome": "success",
        "from_height": 40,
        "to_height": 42,
        "limit": 10,
        "scan_limit_blocks": 3,
    }


def test_list_trigger_completions_validates_filters_before_request() -> None:
    client, session = _client_with_session()

    with pytest.raises(ValueError, match="all, success, or failure"):
        client.list_trigger_completions(outcome="maybe")
    with pytest.raises(ValueError, match="limit"):
        client.list_trigger_completions(limit=0)
    with pytest.raises(TypeError, match="from_height"):
        client.list_trigger_completions(from_height=True)
    with pytest.raises(ValueError, match="u64"):
        client.list_trigger_completions(to_height=1 << 64)

    with pytest.raises(TypeError):
        client.list_trigger_completions(include_reconstructed=False)

    assert session.calls == []


def test_accounts_query_body_carries_only_list_query_controls() -> None:
    client, session = _client_with_session()

    client.accounts.list()

    call = session.calls[0]
    assert call["url"] == "http://localhost:8080/v1/accounts/query"
    assert json.loads(call["data"].decode("utf-8")) == {}


def test_accounts_list_rejects_removed_canonical_i105_arg() -> None:
    client, _ = _client_with_session()

    with pytest.raises(TypeError):
        client.accounts.list(canonical_i105="i105")  # type: ignore[call-arg]


def test_signed_accounts_query_body_carries_only_list_query_controls() -> None:
    session = RecordingSession()
    client = authenticated_query_client(session)

    client.accounts.list(limit=5)

    assert json.loads(session.calls[0]["data"].decode("utf-8")) == {"limit": 5}


def test_asset_holders_query_percent_encodes_the_definition_selector() -> None:
    client, session = _client_with_session()

    client.asset_definitions.holders("xor#wonderland").list()

    assert session.calls[0]["url"] == (
        "http://localhost:8080/v1/assets/xor%23wonderland/holders/query"
    )
    assert json.loads(session.calls[0]["data"].decode("utf-8")) == {}


def test_i105_roundtrip_uses_halfwidth_iroha_poem_alphabet() -> None:
    address = AccountAddress.from_account(public_key=CANONICAL_ED25519_PUBLIC_KEY)
    literal = address.to_i105(0x02F1)

    parsed = AccountAddress.parse_encoded(literal, expected_discriminant=0x02F1)

    payload = literal.removeprefix("sora")
    assert any(ch.isascii() and ch.isalnum() for ch in payload)
    assert any(ch in "ｲﾛﾊﾆﾎﾍﾄﾁﾘﾇﾙｦﾜｶﾖﾀﾚｿﾂﾈﾅﾗﾑｳヰﾉｵｸﾔﾏｹﾌｺｴﾃｱｻｷﾕﾒﾐｼヱﾋﾓｾｽ" for ch in payload)
    assert parsed.to_i105(0x02F1) == literal


@pytest.mark.parametrize(
    ("algorithm", "message"),
    [
        ("", "non-empty string"),
        ("   ", "non-empty string"),
        (" ed25519", "surrounding whitespace"),
        ("ed25519 ", "surrounding whitespace"),
        ("\u00a0ML-DSA-65\u00a0", "surrounding whitespace"),
        ("\u2003ML-DSA-65\u2003", "surrounding whitespace"),
    ],
)
def test_account_address_rejects_blank_or_padded_signing_algorithm_aliases(
    algorithm: str, message: str
) -> None:
    with pytest.raises(AccountAddressError, match=message):
        AccountAddress.from_account(
            public_key=CANONICAL_ED25519_PUBLIC_KEY,
            algorithm=algorithm,
        )


@pytest.mark.parametrize("algorithm", [0, False, b"ed25519", ["ed25519"]])
def test_account_address_rejects_non_string_signing_algorithm_aliases(algorithm: object) -> None:
    with pytest.raises(AccountAddressError, match="signing algorithm must be a string"):
        AccountAddress.from_account(
            public_key=CANONICAL_ED25519_PUBLIC_KEY,
            algorithm=algorithm,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "algorithm",
    [
        "future-curve",
        "ed 25519",
        "ed\t25519",
        "ed.25519",
        "ed/25519",
        "ed@25519",
        "ed#25519",
        "ed\u200b25519",
        "\u0435d25519",
        "ml\uff0ddsa",
        "ML-DSA-44",
        "ML_DSA_87",
        "gost256\u0430",
    ],
)
def test_account_address_rejects_confusable_signing_algorithm_aliases(algorithm: str) -> None:
    with pytest.raises(AccountAddressError, match="unsupported signing algorithm"):
        AccountAddress.from_account(
            public_key=CANONICAL_ED25519_PUBLIC_KEY,
            algorithm=algorithm,
        )


def test_mldsa_account_address_uses_extended_protocol_key_encoding() -> None:
    public_key = bytes([0xA5]) * 1_952
    for algorithm in ("mldsa", "ML-DSA-65", "ML_DSA_65", "ML_DSA-65"):
        address = AccountAddress.from_account(
            public_key=public_key,
            algorithm=algorithm,
        )
        canonical = address.canonical_bytes()
        assert canonical[1:5] == b"\x02\x02\x07\xA0"
        assert canonical[5:] == public_key
        assert AccountAddress.from_canonical_bytes(canonical).canonical_bytes() == canonical
        literal = address.to_i105(0)
        assert AccountAddress.from_i105(literal, 0).canonical_bytes() == canonical


def test_account_address_rejects_reserved_headers_and_class_mismatches() -> None:
    compact_single = AccountAddress.from_account(
        public_key=bytes.fromhex(
            "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"
        )
    ).canonical_bytes()
    for version in range(1, 8):
        reserved = bytes([(version << 5) | 0x02]) + compact_single[1:]
        with pytest.raises(AccountAddressError, match="unsupported address header version"):
            AccountAddress.from_canonical_bytes(reserved)
    for norm_version in (0, 2, 3):
        reserved = bytes([norm_version << 1]) + compact_single[1:]
        with pytest.raises(AccountAddressError, match="unsupported normalization version"):
            AccountAddress.from_canonical_bytes(reserved)

    wrong_compact_class = b"\x0a" + compact_single[1:]
    with pytest.raises(AccountAddressError, match="class does not match controller tag"):
        AccountAddress.from_canonical_bytes(wrong_compact_class)

    mldsa = AccountAddress.from_account(
        public_key=bytes([0xA5]) * 1_952,
        algorithm="ML-DSA-65",
    ).canonical_bytes()
    with pytest.raises(AccountAddressError, match="class does not match controller tag"):
        AccountAddress.from_canonical_bytes(b"\x0a" + mldsa[1:])

    wrong_class_i105 = "sora3uｵﾔDﾗﾎmXヱ5uxbｻAｸiRB1vﾚｾｿvSHﾅﾕgﾚｼUFPPﾜinｳﾆﾓRSJS4M"
    with pytest.raises(AccountAddressError, match="unsupported account address format"):
        AccountAddress.from_i105(wrong_class_i105, 753)

    with pytest.raises(AccountAddressError, match="unsupported account address header"):
        AccountAddress(
            header=address_module.AddressHeader(
                version=1,
                class_=address_module.AddressClass.SINGLE_KEY,
                norm_version=1,
            ),
            controller=AccountAddress.from_account(
                public_key=CANONICAL_ED25519_PUBLIC_KEY
            ).controller,
        )


@pytest.mark.parametrize(
    "public_key",
    [
        b"",
        bytes([0x20]) * 32,
        bytes([0x44]) * 1_312,
        bytes([0x65]) * 1_951,
        bytes([0x65]) * 1_953,
        bytes([0x87]) * 2_592,
        bytes(1_952),
    ],
)
def test_mldsa_account_address_rejects_non_protocol_key_material(
    public_key: bytes,
) -> None:
    with pytest.raises(AccountAddressError, match="1952-byte ML-DSA-65"):
        AccountAddress.from_account(public_key=public_key, algorithm="ML-DSA-65")


def test_account_address_rejects_noncanonical_short_extended_controller() -> None:
    public_key = CANONICAL_ED25519_PUBLIC_KEY
    canonical = b"\x02\x02\x01\x00\x20" + public_key
    with pytest.raises(AccountAddressError, match="compact controller tag"):
        AccountAddress.from_canonical_bytes(canonical)


def test_account_identity_constructors_expose_only_the_domainless_api() -> None:
    key_pair = derive_ed25519_keypair_from_seed(b"domainless account identity")
    public_key = key_pair.public_key
    address = AccountAddress.from_account(public_key=public_key)
    expected = address.to_i105(0x0171)

    assert ed25519_public_key_account_id(public_key, discriminant=0x0171) == expected
    assert key_pair.account_id(discriminant=0x0171) == expected
    assert not hasattr(address_module, "DomainSelector")
    assert not hasattr(address_module, "DEFAULT_DOMAIN_NAME")
    assert not hasattr(address, "domain")

    with pytest.raises(TypeError):
        AccountAddress.from_account(  # type: ignore[call-arg]
            domain="wonderland",
            public_key=public_key,
        )
    with pytest.raises(TypeError):
        ed25519_public_key_account_id(public_key, "wonderland")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        AccountAddress(  # type: ignore[call-arg]
            header=address.header,
            domain=object(),
            controller=address.controller,
        )


def test_i105_parse_without_expected_discriminant_accepts_literal_prefix() -> None:
    address = AccountAddress.from_account(public_key=CANONICAL_ED25519_PUBLIC_KEY)
    literal = address.to_i105(0x0171)

    parsed = AccountAddress.parse_encoded(literal)

    assert literal.startswith("test")
    assert parsed.to_i105(0x0171) == literal
    assert AccountAddress.from_i105(literal).to_i105(0x0171) == literal
    with pytest.raises(AccountAddressError, match="unexpected i105 chain discriminant"):
        AccountAddress.parse_encoded(literal, expected_discriminant=0x02F1)


def test_i105_numeric_discriminant_must_fit_u16() -> None:
    address = AccountAddress.from_account(public_key=CANONICAL_ED25519_PUBLIC_KEY)
    valid = address.to_i105(0xFFFF)
    payload = address.to_i105(0x02F1).removeprefix("sora")

    assert valid.startswith("n65535")
    assert AccountAddress.parse_encoded(valid).to_i105(0xFFFF) == valid
    for discriminant in (-1, 0x10000, 70000):
        with pytest.raises(AccountAddressError, match="between 0 and 65535"):
            address.to_i105(discriminant)
    for literal in (f"n65536{payload}", f"n70000{payload}"):
        with pytest.raises(AccountAddressError, match="between 0 and 65535"):
            AccountAddress.parse_encoded(literal)


def test_i105_rejects_fullwidth_sentinel_literal() -> None:
    address = AccountAddress.from_account(public_key=CANONICAL_ED25519_PUBLIC_KEY)
    literal = address.to_i105(0x02F1)
    noncanonical = literal.replace("sora", "ｓｏｒａ", 1)

    with pytest.raises(AccountAddressError, match="missing the expected"):
        AccountAddress.parse_encoded(noncanonical, expected_discriminant=0x02F1)


def test_i105_rejects_noncanonical_fullwidth_kana_payload() -> None:
    address = AccountAddress.from_account(public_key=CANONICAL_ED25519_PUBLIC_KEY)
    literal = address.to_i105(0x02F1)
    noncanonical = literal
    for halfwidth, fullwidth in (("ﾛ", "ロ"), ("ﾊ", "ハ"), ("ﾆ", "ニ"), ("ﾎ", "ホ")):
        if halfwidth in noncanonical:
            noncanonical = noncanonical.replace(halfwidth, fullwidth, 1)
            break
    assert noncanonical != literal

    with pytest.raises(AccountAddressError, match="invalid character"):
        AccountAddress.parse_encoded(noncanonical, expected_discriminant=0x02F1)


def test_asset_holders_list_rejects_removed_canonical_i105_arg() -> None:
    client, _ = _client_with_session()

    with pytest.raises(TypeError):
        client.asset_definitions.holders("xor#wonderland").list(canonical_i105="i105")  # type: ignore[call-arg]


def test_generic_multisig_proposal_is_not_inherited_by_first_release_sdk() -> None:
    client = ToriiClient("http://node.test", session=RecordingSession(), chain_discriminant=753)
    assert not hasattr(ToriiClient, "propose_multisig")
    assert not hasattr(client, "propose_multisig")
    assert not hasattr(client, "multisig_instruction_b64")
