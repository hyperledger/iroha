from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

import pytest
import requests
from client_test_support import (
    CANONICAL_OWNER,
    CANONICAL_OWNER_HEADER,
)
from client_test_support import (
    authority_fee_payment as _authority_fee_payment,
)
from client_test_support import (
    canonical_hash as _canonical_hash,
)
from client_test_support import (
    sponsor_fee_payment as _sponsor_fee_payment,
)
from sumeragi_exact_json_test_support import (
    RecordingSession,
    StubResponse,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import iroha_torii_client as torii_module  # noqa: E402
import iroha_torii_client.client as client_module  # noqa: E402
from iroha_torii_client import (  # noqa: E402  (import depends on sys.path mutation)
    ContractCallDraftIntent,
    ContractCallResponse,
    ContractOperationReceipt,
    ExplorerAccountQr,
    GovernanceContractResponse,
    GovernanceLockCustody,
    GovernanceLockRecord,
    NetworkTimeSnapshot,
    NetworkTimeStatus,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    ToriiLocalSigningContext,
    ToriiOperatorSigningContext,
    VpnQuoteCreateRequest,
    VpnReceiptSubmitRequest,
    VpnSessionCreateRequest,
    build_canonical_request_headers,
    canonical_network_request_signature_message,
    contract_payload_digest_hex,
)
from iroha_torii_client.mock import ToriiMockServer  # noqa: E402

CANONICAL_LARGE_FRACTION = "18446744073709551616.25"
OFFLINE_NETWORK_ID = _canonical_hash(0x91)
CANONICAL_ASSET_ID = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
CANONICAL_ASSET_DEFINITION_ID = "7EAD8EFYUx1aVKZPUU1fyKvr8dF1"
CHECKSUM_INVALID_ASSET_DEFINITION_ID = "7EAD8EFYUx1aVKZPUU1fyKvr8dF2"
CHECKSUM_VALID_NON_UUID_V4_ASSET_DEFINITION_ID = "7EAD8EFYV3tk2BtyQaGhqhATjFy7"
OTHER_CANONICAL_ACCOUNT = (
    "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE"
)
CHECKSUM_VALID_NON_RFC4122_ASSET_DEFINITION_ID = "7EAD8EFYUx1bhNP18PQmxXsySxi6"
_NATIVE_AMX_VALIDATOR_SET = [
    "ea013094D37A1FCA72E8734CAAD4163678D82C36FE2CA70B80F5626E6591709E0D44831BE86CBA9BD0471C6D0D73FF9C4B54E0",
    "ea01309988FA1336476987EF7F91C3EA728B7EA0556698AA0F1A294147C8D5CD43BB24C4BCD14FAE23A384D721CBF1F6A16DF7",
    "ea013099BA3FACE165941434D3238C4D5767059EBFFFB4120A9885A4EB2BAC9CD868F690660D2936B03C0214FBDAD36034D578",
    "ea0130B921EAC90D1A99EC9DA3FF8C8A29EBEE19DD1B659A4C6FC21BC8046EA30DE566668EDCCEAE4CB5932F4F860606A1E0E3",
]
_CONTRACT_DRAFT_EXECUTABLE = b"trusted contract-call executable archive"
_CONTRACT_DRAFT_METADATA = b"trusted final contract-call metadata archive"
_CONTRACT_ADDRESS = (
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
)
_OTHER_CONTRACT_ADDRESS = (
    "irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp"
)
_CONTRACT_CODE_HASH = "22" * 32


def _local_signing_context() -> ToriiLocalSigningContext:
    return ToriiLocalSigningContext(network_id=OFFLINE_NETWORK_ID)


def _contract_auth(
    captured: Optional[List[bytes]] = None,
    *,
    account_id: str = CANONICAL_OWNER,
) -> ToriiCanonicalRequestAuth:
    def signer(message: bytes) -> bytes:
        if captured is not None:
            captured.append(message)
        return b"\x44" * 64

    return ToriiCanonicalRequestAuth(
        network_id=OFFLINE_NETWORK_ID,
        account_id=account_id,
        signer=signer,
        timestamp_ms=4_102_444_801_000,
        nonce="public-contract-prepare-test",
    )




def _contract_draft_intent(
    *,
    payload: Any = None,
    contract_address: str = _CONTRACT_ADDRESS,
    code_hash_hex: str = _CONTRACT_CODE_HASH,
) -> ContractCallDraftIntent:
    return ContractCallDraftIntent(
        executable_b64=base64.b64encode(_CONTRACT_DRAFT_EXECUTABLE).decode("ascii"),
        metadata_b64=base64.b64encode(_CONTRACT_DRAFT_METADATA).decode("ascii"),
        contract_address=contract_address,
        code_hash_hex=code_hash_hex,
        payload_digest_hex=contract_payload_digest_hex(payload),
    )


def _contract_operation_receipt(
    *,
    entrypoint: str = "ping",
    gas_limit: int = 5000,
    fee_payment: Optional[Dict[str, Any]] = None,
    contract_alias: Optional[str] = "router::universal",
    contract_address: Optional[str] = _CONTRACT_ADDRESS,
    code_hash_hex: str = _CONTRACT_CODE_HASH,
    payload: Any = None,
    dataspace: str = "universal",
) -> Dict[str, Any]:
    return {
        "operation_kind": "contract_call",
        "status": "pending_signature",
        "transport": "torii",
        "dataspace": dataspace,
        "contract_alias": contract_alias,
        "contract_address": contract_address,
        "code_hash_hex": code_hash_hex,
        "abi_hash_hex": "33" * 32,
        "tx_hash_hex": None,
        "entrypoint": entrypoint,
        "entrypoint_hash_hex": None,
        "gas_limit": gas_limit,
        "gas_used": None,
        "fee_payment": fee_payment or _sponsor_fee_payment(gas_limit),
        "payload_digest_hex": contract_payload_digest_hex(payload),
    }


def _contract_call_draft(
    *,
    authority: str = CANONICAL_OWNER,
    entrypoint: str = "ping",
    contract_alias: Optional[str] = "router::universal",
    contract_address: Optional[str] = _CONTRACT_ADDRESS,
    code_hash_hex: str = _CONTRACT_CODE_HASH,
    payload: Any = None,
    fee_payment: Optional[Dict[str, Any]] = None,
    executable: bytes = _CONTRACT_DRAFT_EXECUTABLE,
    metadata: bytes = _CONTRACT_DRAFT_METADATA,
    creation_time_ms: int = 42,
    transaction_ttl_ms: Optional[int] = None,
    retired_admission_tag: Optional[int] = None,
) -> Dict[str, Any]:
    def field(value: bytes) -> bytes:
        return client_module._multisig_norito_field(value)

    normalized_fee = ToriiClient._normalize_fee_payment_intent(
        fee_payment or _sponsor_fee_payment(5000),
        context="contract fixture fee_payment",
        require_gas_limit=True,
    )
    dataspace = (
        contract_alias.split("::", 1)[1].split(".")[-1]
        if contract_alias is not None
        else "universal"
    )
    transaction_payload = b"".join(
        field(value)
        for value in (
            (0).to_bytes(4, "little")
            + field(bytes.fromhex(OFFLINE_NETWORK_ID[5:69])),
            client_module._multisig_account_id_archive(authority),
            creation_time_ms.to_bytes(8, "little"),
            executable,
            b"\x01"
            + field((transaction_ttl_ms or 100_000).to_bytes(8, "little")),
            b"\x00",
            client_module._multisig_fee_payment_archive(normalized_fee),
            *((retired_admission_tag.to_bytes(4, "little"),) if retired_admission_tag is not None else ()),
            metadata,
            b"\x00",
        )
    )
    signing_message = bytearray(hashlib.blake2b(transaction_payload, digest_size=32).digest())
    signing_message[-1] |= 1
    return {
        "ok": True,
        "submitted": False,
        "dataspace": dataspace,
        "code_hash_hex": code_hash_hex,
        "abi_hash_hex": "33" * 32,
        "creation_time_ms": creation_time_ms,
        "contract_address": contract_address,
        "tx_hash_hex": None,
        "pipeline_status": None,
        "entrypoint": entrypoint,
        "transaction_ttl_ms": transaction_ttl_ms,
        "entrypoint_hash_hex": None,
        "transaction_payload_b64": base64.b64encode(transaction_payload).decode("ascii"),
        "signing_message_b64": base64.b64encode(signing_message).decode("ascii"),
        "operation_receipt": _contract_operation_receipt(
            entrypoint=entrypoint,
            gas_limit=normalized_fee["value"]["gas_limit"],
            fee_payment=normalized_fee,
            contract_alias=contract_alias,
            contract_address=contract_address,
            code_hash_hex=code_hash_hex,
            payload=payload,
            dataspace=dataspace,
        ),
    }


GOVERNANCE_NETWORK_ID = _canonical_hash(0xA5)


def _operator_context(captured: Optional[List[bytes]] = None) -> ToriiOperatorSigningContext:
    def signer(message: bytes) -> bytes:
        if captured is not None:
            captured.append(message)
        return b"\x55" * 64

    return ToriiOperatorSigningContext(
        network_id=GOVERNANCE_NETWORK_ID,
        public_key="ed0120" + "66" * 32,
        signer=signer,
    )


def _governance_auth(captured: Optional[List[bytes]] = None) -> ToriiCanonicalRequestAuth:
    def signer(message: bytes) -> bytes:
        if captured is not None:
            captured.append(message)
        return b"\x44" * 64

    return ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=signer,
        timestamp_ms=4_102_444_801_000,
        nonce="low-python-governance-test",
    )


def _canonical_signature_base64_fixture() -> str:
    return base64.b64encode(bytes([1]) * 64).decode("ascii")


def _noncanonical_standard_base64_pad_bit_alias(encoded: str) -> str:
    assert encoded.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    chars = list(encoded)
    index = len(chars) - 3
    chars[index] = alphabet[alphabet.index(chars[index]) ^ 0x01]
    return "".join(chars)


def _sample_sorafs_orderbook_payloads() -> Dict[str, Any]:
    def fixed(seed: int) -> List[int]:
        return [seed] * 32

    cursor = {"height": 42, "block_hash": fixed(0xA0)}
    order = {
        "order_id": fixed(0x11),
        "owner": "alice@wonderland",
        "canonical_order": base64.b64encode(b"canonical-order").decode("ascii"),
        "admitted_policy_digest": fixed(0x12),
        "admitted_at_unix": 1_700_000_000,
        "admission_sequence": 7,
        "remaining_gib": 2,
        "status": {"status": "open", "value": None},
        "updated_at_unix": 1_700_000_001,
        "canonical_cancel": None,
        "cancelled_at_unix": None,
        "cancelled_policy_digest": None,
    }
    trade = {
        "trade_id": fixed(0x22),
        "maker_order_id": fixed(0x11),
        "taker_order_id": fixed(0x13),
        "trade_sequence": 3,
        "canonical_trade": base64.b64encode(b"canonical-trade").decode("ascii"),
        "channel_id": fixed(0x33),
        "book_revision": 9,
        "recorded_at_unix": 1_700_000_100,
    }
    channel = {
        "channel_id": fixed(0x33),
        "trade_id": fixed(0x22),
        "buyer": "alice@wonderland",
        "provider": "provider@storage",
        "provider_id": fixed(0x55),
        "settlement_authority": "settlement@governance",
        "total_bytes": 2_147_483_648,
        "remaining_bytes": 1_073_741_824,
        "initial_xor_locked": "340282366920938463463374607431768211456.000000001",
        "remaining_xor_locked": "1.000000001",
        "status": {"status": "open", "value": None},
        "opened_at_unix": 1_700_000_101,
        "expires_at_unix": 1_800_000_000,
        "updated_at_unix": 1_700_000_102,
    }
    receipt = {
        "receipt_id": fixed(0x44),
        "channel_id": fixed(0x33),
        "trade_id": fixed(0x22),
        "canonical_receipt": base64.b64encode(b"canonical-receipt").decode("ascii"),
        "admitted_policy_digest": fixed(0x12),
        "admitted_at_unix": 1_700_000_103,
        "recorded_by": "settlement@governance",
    }
    finalized_event = {
        "sequence": 9,
        "block_height": 42,
        "block_hash": fixed(0xA0),
        "event_index": 2,
        "event": {
            "kind": {"kind": "receipt_recorded", "detail": None},
            "order_id": None,
            "trade_id": fixed(0x22),
            "channel_id": fixed(0x33),
            "receipt_id": fixed(0x44),
            "provider_id": fixed(0x55),
            "book_revision": 10,
            "authority": "settlement@governance",
            "occurred_at_unix_ms": 1_700_000_104_000,
        },
    }
    status = {
        "open_orders": 1,
        "partially_filled_orders": 0,
        "filled_orders": 1,
        "cancelled_orders": 0,
        "expired_orders": 0,
        "trades": 1,
        "settlement_receipts": 1,
        "settlement_channels": 1,
        "open_settlement_channels": 1,
        "book_revision": 10,
        "next_admission_sequence": 8,
        "next_trade_sequence": 4,
        "updated_at_unix": 1_700_000_104,
    }
    submission_receipt = {
        "payload": {
            "entrypoint_hash": _canonical_hash(0x72),
            "signed_transaction_hash": _canonical_hash(0x73),
            "submitted_at_ms": 1_700_000_200_000,
            "submitted_at_height": 42,
            "signer": "ed0120ABCDEF",
        },
        "signature": "AB" * 64,
    }
    return {
        "fixed": fixed,
        "cursor": cursor,
        "order": order,
        "trade": trade,
        "channel": channel,
        "receipt": receipt,
        "finalized_event": finalized_event,
        "status": status,
        "submission_receipt": submission_receipt,
    }


def test_sorafs_orderbook_read_helpers_build_paths_and_normalize_payloads() -> None:
    payloads = _sample_sorafs_orderbook_payloads()
    cursor = payloads["cursor"]
    fixed = payloads["fixed"]
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "source": "finalized_chain",
                "status": payloads["status"],
                "orders": {
                    "finalized_cursor": cursor,
                    "orders": [payloads["order"]],
                    "has_more": True,
                    "next_after_order_id": fixed(0x11),
                },
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "source": "finalized_chain",
                "trades": {
                    "finalized_cursor": cursor,
                    "trades": [payloads["trade"]],
                    "has_more": False,
                    "next_after_trade_id": None,
                },
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "source": "finalized_chain",
                "channels": {
                    "finalized_cursor": cursor,
                    "channels": [payloads["channel"]],
                    "has_more": False,
                    "next_after_channel_id": None,
                },
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "source": "finalized_chain",
                "receipts": {
                    "finalized_cursor": cursor,
                    "receipts": [payloads["receipt"]],
                    "has_more": False,
                    "next_after_receipt_id": None,
                },
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "source": "finalized_chain",
                "events": {
                    "finalized_cursor": cursor,
                    "events": [payloads["finalized_event"]],
                    "has_more": True,
                    "next_after": {
                        "sequence": 9,
                        "block_height": 42,
                        "block_hash": fixed(0xA0),
                        "event_index": 2,
                    },
                },
            }
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    anchor_hex = "a0" * 32
    book = client.get_sorafs_orderbook(
        expected_finalized_height=42,
        expected_finalized_block_hash_hex=anchor_hex,
        after_id_hex="10" * 32,
        limit=25,
        headers={"X-Trace": "book"},
    )
    assert book["source"] == "finalized_chain"
    assert book["status"]["book_revision"] == 10
    assert book["orders"]["orders"][0]["order_id"] == fixed(0x11)
    assert book["orders"]["finalized_cursor"] == cursor
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"].endswith("/v1/sorafs/orderbook/book")
    assert session.calls[0]["params"] == {
        "expected_finalized_height": 42,
        "expected_finalized_block_hash_hex": anchor_hex,
        "after_id_hex": "10" * 32,
        "limit": 25,
    }
    assert session.calls[0]["headers"]["X-Trace"] == "book"
    trades = client.list_sorafs_orderbook_trades()
    assert trades["trades"]["trades"][0]["trade_id"] == fixed(0x22)
    assert session.calls[1]["url"].endswith("/v1/sorafs/orderbook/trades")
    channels = client.list_sorafs_orderbook_channels()
    assert channels["channels"]["channels"][0]["provider_id"] == fixed(0x55)
    assert channels["channels"]["channels"][0]["status"] == {
        "status": "open",
        "value": None,
    }
    assert session.calls[2]["url"].endswith("/v1/sorafs/orderbook/channels")
    receipts = client.list_sorafs_orderbook_receipts()
    assert receipts["receipts"]["receipts"][0]["receipt_id"] == fixed(0x44)
    assert session.calls[3]["url"].endswith("/v1/sorafs/orderbook/receipts")
    events = client.list_sorafs_orderbook_events(
        expected_finalized_height=42,
        expected_finalized_block_hash_hex=anchor_hex,
        after_sequence=8,
        after_block_height=41,
        after_block_hash_hex="9f" * 32,
        after_event_index=1,
        limit=10,
        if_none_match='"old-events"',
    )
    assert events is not None
    event = events["events"]["events"][0]
    assert event["event"]["kind"] == {"kind": "receipt_recorded", "detail": None}
    assert event["event"]["receipt_id"] == fixed(0x44)
    assert session.calls[4]["url"].endswith("/v1/sorafs/orderbook/events")
    assert session.calls[4]["params"] == {
        "expected_finalized_height": 42,
        "expected_finalized_block_hash_hex": anchor_hex,
        "after_sequence": 8,
        "after_block_height": 41,
        "after_block_hash_hex": "9f" * 32,
        "after_event_index": 1,
        "limit": 10,
    }
    assert session.calls[4]["headers"]["If-None-Match"] == '"old-events"'


def test_sorafs_orderbook_read_helpers_validate_options_and_cache_status() -> None:
    client = ToriiClient("http://node.test", session=RecordingSession())

    with pytest.raises(ValueError, match="1..=500"):
        client.list_sorafs_orderbook_events(limit=0)
    with pytest.raises(ValueError, match="1..=500"):
        client.list_sorafs_orderbook_events(limit=501)
    with pytest.raises(ValueError, match="requires expected_finalized_height"):
        client.get_sorafs_orderbook(expected_finalized_height=7)
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        client.get_sorafs_orderbook(
            expected_finalized_height=7,
            expected_finalized_block_hash_hex="AA" * 32,
        )
    with pytest.raises(ValueError, match="all-zero"):
        client.get_sorafs_orderbook(
            expected_finalized_height=7,
            expected_finalized_block_hash_hex="00" * 32,
        )
    with pytest.raises(ValueError, match="all four finalized event cursor"):
        client.list_sorafs_orderbook_events(after_sequence=1)
    with pytest.raises(TypeError, match="unexpected keyword argument 'since'"):
        client.list_sorafs_orderbook_events(since=0)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="unexpected keyword argument 'etag'"):
        client.list_sorafs_orderbook_events(etag='"old"')  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="headers must be a mapping"):
        client.get_sorafs_orderbook(headers="not-a-mapping")  # type: ignore[arg-type]

    session = RecordingSession()
    session.queue(StubResponse(status_code=304))
    cached_client = ToriiClient("http://node.test", session=session)

    assert cached_client.list_sorafs_orderbook_events(if_none_match='"same"') is None
    assert session.calls[0]["headers"]["If-None-Match"] == '"same"'


@pytest.mark.parametrize(
    ("parser", "payload_key", "retired_field"),
    [
        (
            ToriiClient._parse_sorafs_orderbook_order_record,
            "order",
            "price_per_gib_micro_xor",
        ),
        (
            ToriiClient._parse_sorafs_orderbook_trade_record,
            "trade",
            "maker_fee_micro_xor",
        ),
        (
            ToriiClient._parse_sorafs_orderbook_channel_record,
            "channel",
            "xor_locked_micro",
        ),
        (
            ToriiClient._parse_sorafs_orderbook_receipt_record,
            "receipt",
            "provider_credit_micro",
        ),
    ],
)
def test_sorafs_orderbook_exact_records_reject_legacy_duplicate_fields(
    parser: Callable[..., Dict[str, Any]],
    payload_key: str,
    retired_field: str,
) -> None:
    record = dict(_sample_sorafs_orderbook_payloads()[payload_key])
    record[retired_field] = "1"

    with pytest.raises(ValueError, match="unknown or retired"):
        parser(record, context=payload_key)


def test_sorafs_orderbook_exact_records_reject_unknown_fields() -> None:
    order = dict(_sample_sorafs_orderbook_payloads()["order"])
    order["unexpected_amount"] = "1"

    with pytest.raises(ValueError, match="unexpected_amount"):
        ToriiClient._parse_sorafs_orderbook_order_record(order, context="order")


def test_sorafs_orderbook_native_parsers_reject_noncanonical_wire_values() -> None:
    payloads = _sample_sorafs_orderbook_payloads()

    order = copy.deepcopy(payloads["order"])
    order["order_id"][0] = True
    with pytest.raises(TypeError, match="integer byte"):
        ToriiClient._parse_sorafs_orderbook_order_record(order, context="order")

    order = copy.deepcopy(payloads["order"])
    order["canonical_order"] = "YQ"
    with pytest.raises(ValueError, match="canonical"):
        ToriiClient._parse_sorafs_orderbook_order_record(order, context="order")

    order = copy.deepcopy(payloads["order"])
    order["status"] = {"status": "open"}
    with pytest.raises(ValueError, match="missing value"):
        ToriiClient._parse_sorafs_orderbook_order_record(order, context="order")

    page = {
        "finalized_cursor": payloads["cursor"],
        "orders": [payloads["order"]],
        "has_more": True,
        "next_after_order_id": None,
    }
    with pytest.raises(ValueError, match="presence must match has_more"):
        ToriiClient._parse_sorafs_orderbook_order_page(page, context="orders")


def test_expect_status_surfaces_error_envelope_details() -> None:
    response = StubResponse(
        429,
        {
            "code": "queue_full",
            "message": "transaction queue is at capacity",
            "details": {
                "reject_code": "TX_QUEUE_FULL",
                "retry_after_seconds": 1,
                "queue": {
                    "state": "saturated",
                    "queued": 128,
                    "capacity": 128,
                    "saturated": True,
                },
            },
        },
    )

    with pytest.raises(RuntimeError) as exc:
        ToriiClient._expect_status(response, (200,))

    message = str(exc.value)
    assert "transaction queue is at capacity" in message
    assert "reject_code=TX_QUEUE_FULL" in message


def test_expect_status_ignores_adversarial_non_string_reject_code() -> None:
    response = StubResponse(
        400,
        {
            "code": "bad_request",
            "message": "bad request",
            "details": {
                "reject_code": {"unexpected": "object"},
                "axt": {"code": ["array"]},
            },
        },
    )

    with pytest.raises(RuntimeError) as exc:
        ToriiClient._expect_status(response, (200,))

    message = str(exc.value)
    assert "bad request" in message
    assert "reject_code=" not in message
    assert "object" not in message
    assert "array" not in message


VPN_ACCOUNT = "vpn-user@paynet"
VPN_OPERATOR = "vpn-operator@paynet"
VPN_ESCROW = "vpn-escrow@paynet"
VPN_QUOTE_ID = "11" * 32
VPN_QUOTE_SESSION_ID = "44" * 16
VPN_PAYMENT_HASH = "22" * 32
VPN_METERING_KEY = "33" * 32
VPN_LEASE_ID = VPN_QUOTE_ID
VPN_HELPER_TICKET_HEX = "5356504e48543100" + "00" * 780
VPN_RELAY_ID_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
VPN_RELAY_MLDSA65_PUBLIC_KEY_HEX = "55" * 1_952


def _vpn_trust_fields(spki: str = "ab" * 32) -> Dict[str, str]:
    return {
        "relay_id_hex": VPN_RELAY_ID_HEX,
        "relay_mldsa65_public_key_hex": VPN_RELAY_MLDSA65_PUBLIC_KEY_HEX,
        "descriptor_commit_hex": "cd" * 32,
        "tls_server_name": "relay.example",
        "relay_tls_spki_sha256_hex": spki,
        "relay_certificate_sha256_hex": "ef" * 32,
        "directory_snapshot_digest_hex": "42" * 32,
    }


def _vpn_instruction(wire_id: str = "OpenVpnLeaseEscrow") -> Dict[str, str]:
    return {"wire_id": wire_id, "payload_hex": "ab" * 8}


def _vpn_profile_payload() -> Dict[str, Any]:
    return {
        "available": True,
        "relay_endpoint": "/dns4/relay.example/udp/443/quic",
        "supported_exit_classes": ["standard", "low-latency", "high-security"],
        "default_exit_class": "standard",
        "lease_secs": 3600,
        "dns_push_interval_secs": 60,
        "meter_family": "soranet.vpn.v1",
        "route_pushes": ["0.0.0.0/0"],
        "excluded_routes": ["10.0.0.0/8"],
        "dns_servers": ["1.1.1.1"],
        "tunnel_addresses": ["10.208.0.2/32"],
        "mtu_bytes": 1280,
        "display_billing_label": "standard - soranet.vpn.v1 - 100.25 XOR",
        "operator_account_id": VPN_OPERATOR,
        "lease_fee": "100.25",
        "settlement_grace_secs": 300,
        "flow_label_bits": 24,
        "padding_budget_ms": 250,
        **_vpn_trust_fields(),
    }


def _vpn_quote_payload() -> Dict[str, Any]:
    payload = _vpn_profile_payload()
    return {
        "quote_id": VPN_QUOTE_ID,
        "lease_id_hex": VPN_LEASE_ID,
        "session_id_hex": VPN_QUOTE_SESSION_ID,
        "payment_reference": VPN_QUOTE_ID,
        "account_id": VPN_ACCOUNT,
        "exit_class": "standard",
        "relay_endpoint": payload["relay_endpoint"],
        "lease_secs": payload["lease_secs"],
        "quote_expires_at_ms": 1_700_000_000_000,
        "fee_asset_id": "xor#universal",
        "escrow_account_id": VPN_ESCROW,
        "operator_account_id": VPN_OPERATOR,
        "lease_fee": payload["lease_fee"],
        "route_pushes": payload["route_pushes"],
        "excluded_routes": payload["excluded_routes"],
        "dns_servers": payload["dns_servers"],
        "tunnel_addresses": payload["tunnel_addresses"],
        "mtu_bytes": payload["mtu_bytes"],
        "meter_family": payload["meter_family"],
        "flow_label_bits": payload["flow_label_bits"],
        "padding_budget_ms": payload["padding_budget_ms"],
        **_vpn_trust_fields(payload["relay_tls_spki_sha256_hex"]),
        "metering_public_key_hex": VPN_METERING_KEY,
        "open_lease_instruction": _vpn_instruction(),
    }


def _vpn_session_payload() -> Dict[str, Any]:
    quote_payload = _vpn_quote_payload()
    return {
        "session_id": VPN_QUOTE_SESSION_ID,
        "account_id": VPN_ACCOUNT,
        "exit_class": quote_payload["exit_class"],
        "relay_endpoint": quote_payload["relay_endpoint"],
        "lease_secs": quote_payload["lease_secs"],
        "expires_at_ms": quote_payload["quote_expires_at_ms"],
        "connected_at_ms": 1_699_999_999_000,
        "meter_family": quote_payload["meter_family"],
        "quote_id": VPN_QUOTE_ID,
        "payment_reference": VPN_QUOTE_ID,
        "payment_tx_hash": VPN_PAYMENT_HASH,
        "fee_asset_id": quote_payload["fee_asset_id"],
        "escrow_account_id": VPN_ESCROW,
        "operator_account_id": VPN_OPERATOR,
        "lease_fee": quote_payload["lease_fee"],
        "flow_label_bits": quote_payload["flow_label_bits"],
        "padding_budget_ms": quote_payload["padding_budget_ms"],
        **_vpn_trust_fields(quote_payload["relay_tls_spki_sha256_hex"]),
        "route_pushes": quote_payload["route_pushes"],
        "excluded_routes": quote_payload["excluded_routes"],
        "dns_servers": quote_payload["dns_servers"],
        "tunnel_addresses": quote_payload["tunnel_addresses"],
        "mtu_bytes": quote_payload["mtu_bytes"],
        "helper_ticket_hex": VPN_HELPER_TICKET_HEX,
        "bytes_in": 0,
        "bytes_out": 0,
        "status": "active",
    }


def _vpn_receipt_payload(status: str = "settled") -> Dict[str, Any]:
    session_payload = _vpn_session_payload()
    return {
        "session_id": VPN_QUOTE_SESSION_ID,
        "account_id": VPN_ACCOUNT,
        "exit_class": session_payload["exit_class"],
        "relay_endpoint": session_payload["relay_endpoint"],
        "meter_family": session_payload["meter_family"],
        "connected_at_ms": session_payload["connected_at_ms"],
        "disconnected_at_ms": session_payload["connected_at_ms"] + 60_000,
        "duration_ms": 60_000,
        "bytes_in": 1024,
        "bytes_out": 2048,
        "status": status,
        "receipt_source": (
            "relay" if status in {"settlement_pending", "settled"} else "torii"
        ),
        "quote_id": VPN_QUOTE_ID,
        "payment_tx_hash": VPN_PAYMENT_HASH,
        "fee_asset_id": session_payload["fee_asset_id"],
        "escrow_account_id": VPN_ESCROW,
        "operator_account_id": VPN_OPERATOR,
        "lease_fee": session_payload["lease_fee"],
        "earned_fee": "25.125",
        "refunded_fee": "75.125",
        "lease_id_hex": VPN_LEASE_ID,
        "settle_lease_instruction": _vpn_instruction("SettleVpnLease"),
    }


def _vpn_auth(captured: List[bytes]) -> ToriiCanonicalRequestAuth:
    def signer(message: bytes) -> bytes:
        captured.append(message)
        return b"\x7a" * 64

    return ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=VPN_ACCOUNT,
        signer=signer,
        timestamp_ms=1_700_000_001_000,
        nonce="vpn-test-nonce",
    )


def test_signed_vpn_methods_require_canonical_auth_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    omitted_auth_calls = [
        lambda: client.create_vpn_quote(
            VpnQuoteCreateRequest(metering_public_key_hex=VPN_METERING_KEY)
        ),
        lambda: client.create_vpn_session(
            VpnSessionCreateRequest(
                quote_id=VPN_QUOTE_ID,
                payment_tx_hash=VPN_PAYMENT_HASH,
                metering_public_key_hex=VPN_METERING_KEY,
            )
        ),
        lambda: client.get_vpn_session(VPN_QUOTE_SESSION_ID),
        lambda: client.submit_vpn_receipt(
            VpnReceiptSubmitRequest(
                relay_receipt_hex="abcd",
                client_voucher_hex="beef",
            )
        ),
        client.list_vpn_receipts,
    ]

    for invoke in omitted_auth_calls:
        with pytest.raises(TypeError, match=r"canonical_auth"):
            invoke()

    explicit_none_calls = [
        lambda: client.create_vpn_quote(
            VpnQuoteCreateRequest(metering_public_key_hex=VPN_METERING_KEY),
            canonical_auth=None,  # type: ignore[arg-type]
        ),
        lambda: client.create_vpn_session(
            VpnSessionCreateRequest(
                quote_id=VPN_QUOTE_ID,
                payment_tx_hash=VPN_PAYMENT_HASH,
                metering_public_key_hex=VPN_METERING_KEY,
            ),
            canonical_auth=None,  # type: ignore[arg-type]
        ),
        lambda: client.get_vpn_session(
            VPN_QUOTE_SESSION_ID,
            canonical_auth=None,  # type: ignore[arg-type]
        ),
        lambda: client.submit_vpn_receipt(
            VpnReceiptSubmitRequest(
                relay_receipt_hex="abcd",
                client_voucher_hex="beef",
            ),
            canonical_auth=None,  # type: ignore[arg-type]
        ),
        lambda: client.list_vpn_receipts(
            canonical_auth=None,  # type: ignore[arg-type]
        ),
    ]
    for invoke in explicit_none_calls:
        with pytest.raises(ValueError, match=r"canonical_auth is required"):
            invoke()
    assert session.calls == []


def test_vpn_request_mappings_reject_unknown_fields_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    auth = _vpn_auth([])
    calls = [
        lambda: client.create_vpn_quote(
            {"metering_public_key_hex": VPN_METERING_KEY, "unexpected": True},
            canonical_auth=auth,
        ),
        lambda: client.create_vpn_session(
            {
                "quote_id": VPN_QUOTE_ID,
                "payment_tx_hash": VPN_PAYMENT_HASH,
                "metering_public_key_hex": VPN_METERING_KEY,
                "unexpected": True,
            },
            canonical_auth=auth,
        ),
        lambda: client.submit_vpn_receipt(
            {
                "relay_receipt_hex": "abcd",
                "client_voucher_hex": "beef",
                "unexpected": True,
            },
            canonical_auth=auth,
        ),
    ]

    for invoke in calls:
        with pytest.raises(RuntimeError, match=r"unsupported fields: unexpected"):
            invoke()
    assert session.calls == []


def test_vpn_requests_keep_openapi_allowed_prefixed_mixed_case_hex() -> None:
    metering_key = "ab" * 32
    payment_hash = "cd" * 32
    lease_id = "ef" * 32
    assert ToriiClient._normalize_vpn_quote_request(
        {"metering_public_key_hex": "0X" + ("aB" * 32)}
    )["metering_public_key_hex"] == metering_key
    session_payload = ToriiClient._normalize_vpn_session_request(
        {
            "quote_id": VPN_QUOTE_ID,
            "payment_tx_hash": "0x" + ("cD" * 32),
            "metering_public_key_hex": "0X" + ("aB" * 32),
        }
    )
    assert session_payload["payment_tx_hash"] == payment_hash
    assert session_payload["metering_public_key_hex"] == metering_key
    receipt_payload = ToriiClient._normalize_vpn_receipt_request(
        {
            "relay_receipt_hex": "0XABCD",
            "client_voucher_hex": "0xBEEF",
            "lease_id_hex": "0X" + ("eF" * 32),
        }
    )
    assert receipt_payload == {
        "relay_receipt_hex": "abcd",
        "client_voucher_hex": "beef",
        "lease_id_hex": lease_id,
    }
    with pytest.raises(RuntimeError, match=r"quote_id must be an exact lowercase"):
        ToriiClient._normalize_vpn_session_request(
            {
                "quote_id": "0X" + VPN_QUOTE_ID,
                "payment_tx_hash": payment_hash,
                "metering_public_key_hex": metering_key,
            }
        )
    with pytest.raises(RuntimeError, match=r"exit_class must be one of"):
        ToriiClient._normalize_vpn_quote_request(
            {
                "exit_class": "fastest",
                "metering_public_key_hex": metering_key,
            }
        )
    with pytest.raises(RuntimeError, match=r"exit_class must be one of"):
        ToriiClient._normalize_vpn_session_request(
            {
                "exit_class": "fastest",
                "quote_id": VPN_QUOTE_ID,
                "payment_tx_hash": payment_hash,
                "metering_public_key_hex": metering_key,
            }
        )


def test_create_vpn_quote_signs_body_and_parses_open_lease_instruction() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=201, payload=_vpn_quote_payload()))
    captured: List[bytes] = []
    auth = _vpn_auth(captured)
    client = ToriiClient("https://node.test", session=session)

    quote = client.create_vpn_quote(
        VpnQuoteCreateRequest(
            metering_public_key_hex=bytes.fromhex(VPN_METERING_KEY),
            exit_class="standard",
        ),
        canonical_auth=auth,
    )

    body = session.calls[0]["data"]
    assert body == (
        b'{"exit_class":"standard","metering_public_key_hex":"'
        + VPN_METERING_KEY.encode("ascii")
        + b'"}'
    )
    assert captured == [
        canonical_network_request_signature_message(
            auth.network_id,
            "POST",
            "/v1/vpn/quotes",
            body,
            timestamp_ms=auth.timestamp_ms or 0,
            nonce=auth.nonce or "",
        )
    ]
    headers = session.calls[0]["headers"]
    assert headers["X-Iroha-Account"] == VPN_ACCOUNT
    assert headers["X-Iroha-Signature"] == base64.b64encode(b"\x7a" * 64).decode("ascii")
    assert headers["X-Iroha-Timestamp-Ms"] == str(auth.timestamp_ms)
    assert headers["X-Iroha-Nonce"] == auth.nonce
    assert quote.lease_id_hex == VPN_LEASE_ID
    assert quote.open_lease_instruction.wire_id == "OpenVpnLeaseEscrow"
    assert quote.open_lease_instruction.payload_hex == "ab" * 8


def test_canonical_request_auth_rejects_padded_fields_before_send() -> None:
    def signer(message: bytes) -> bytes:
        return b"\x7a" * 64

    with pytest.raises(ValueError, match="surrounding whitespace"):
        canonical_network_request_signature_message(
            GOVERNANCE_NETWORK_ID,
            "POST",
            "/v1/vpn/quotes",
            b"{}",
            timestamp_ms=1,
            nonce=" nonce",
        )
    with pytest.raises(ValueError, match="printable ASCII"):
        canonical_network_request_signature_message(
            GOVERNANCE_NETWORK_ID,
            "POST",
            "/v1/vpn/quotes",
            b"{}",
            timestamp_ms=1,
            nonce="nonce value",
        )
    with pytest.raises(ValueError, match="printable ASCII"):
        canonical_network_request_signature_message(
            GOVERNANCE_NETWORK_ID,
            "POST",
            "/v1/vpn/quotes",
            b"{}",
            timestamp_ms=1,
            nonce="nönce",
        )
    with pytest.raises(ValueError, match="at most 256"):
        canonical_network_request_signature_message(
            GOVERNANCE_NETWORK_ID,
            "POST",
            "/v1/vpn/quotes",
            b"{}",
            timestamp_ms=1,
            nonce="n" * 257,
        )
    with pytest.raises((TypeError, ValueError), match="unsigned 64-bit"):
        canonical_network_request_signature_message(
            GOVERNANCE_NETWORK_ID,
            "POST",
            "/v1/vpn/quotes",
            b"{}",
            timestamp_ms=-1,
            nonce="nonce",
        )
    with pytest.raises(ValueError, match="non-empty string"):
        build_canonical_request_headers(
            network_id=GOVERNANCE_NETWORK_ID,
            account_id=VPN_ACCOUNT,
            signer=signer,
            method="POST",
            path="/v1/vpn/quotes",
            body=b"{}",
            timestamp_ms=1,
            nonce="",
        )
    with pytest.raises(ValueError, match="surrounding whitespace"):
        build_canonical_request_headers(
            network_id=GOVERNANCE_NETWORK_ID,
            account_id=f"{VPN_ACCOUNT} ",
            signer=signer,
            method="POST",
            path="/v1/vpn/quotes",
            body=b"{}",
            timestamp_ms=1,
            nonce="nonce",
        )
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    with pytest.raises(ValueError, match="surrounding whitespace"):
        client.create_vpn_quote(
            VpnQuoteCreateRequest(
                metering_public_key_hex=bytes.fromhex(VPN_METERING_KEY),
                exit_class="standard",
            ),
            canonical_auth=ToriiCanonicalRequestAuth(
                network_id=GOVERNANCE_NETWORK_ID,
                account_id=VPN_ACCOUNT,
                signer=signer,
                timestamp_ms=1,
                nonce="nonce ",
            ),
        )
    assert session.calls == []


def test_vpn_session_accepts_exact_lowercase_788_byte_helper_ticket() -> None:
    parsed = ToriiClient._parse_vpn_session(
        _vpn_session_payload(),
        context="vpn session response",
    )

    assert parsed.helper_ticket_hex == VPN_HELPER_TICKET_HEX
    assert len(parsed.helper_ticket_hex) == 1576
    assert parsed.relay_mldsa65_public_key_hex == VPN_RELAY_MLDSA65_PUBLIC_KEY_HEX


@pytest.mark.parametrize(
    ("parser", "payload_factory", "context"),
    [
        (ToriiClient._parse_vpn_profile, _vpn_profile_payload, "vpn profile"),
        (ToriiClient._parse_vpn_quote, _vpn_quote_payload, "vpn quote"),
        (ToriiClient._parse_vpn_session, _vpn_session_payload, "vpn session"),
    ],
)
@pytest.mark.parametrize(
    "invalid_key",
    [
        "",
        "55" * 1_951,
        "AA" * 1_952,
        "55" * 1_951 + "5\n",
        "00" * 1_952,
    ],
    ids=["empty", "wrong-length", "uppercase", "trailing-newline", "all-zero"],
)
def test_vpn_trust_responses_reject_invalid_mldsa65_public_key(
    parser: Callable[..., Any],
    payload_factory: Callable[[], Dict[str, Any]],
    context: str,
    invalid_key: str,
) -> None:
    payload = payload_factory()
    payload["relay_mldsa65_public_key_hex"] = invalid_key

    with pytest.raises(RuntimeError, match=r"relay_mldsa65_public_key_hex"):
        parser(payload, context=context)


@pytest.mark.parametrize(
    "helper_ticket_hex",
    [
        "0x" + VPN_HELPER_TICKET_HEX,
        VPN_HELPER_TICKET_HEX.upper(),
        VPN_HELPER_TICKET_HEX[:1456],
        VPN_HELPER_TICKET_HEX[:-1],
        VPN_HELPER_TICKET_HEX[:-2],
    ],
    ids=["prefix", "uppercase", "previous-728-byte-length", "odd-length", "wrong-even-length"],
)
def test_vpn_session_rejects_noncanonical_helper_ticket(helper_ticket_hex: str) -> None:
    payload = _vpn_session_payload()
    payload["helper_ticket_hex"] = helper_ticket_hex

    with pytest.raises(
        RuntimeError,
        match=r"helper_ticket_hex must contain exactly 1576 lowercase hexadecimal characters",
    ):
        ToriiClient._parse_vpn_session(payload, context="vpn session response")


def test_vpn_response_parsers_reject_unknown_fields() -> None:
    cases = [
        (ToriiClient._parse_vpn_profile, _vpn_profile_payload(), "vpn profile"),
        (ToriiClient._parse_vpn_quote, _vpn_quote_payload(), "vpn quote"),
        (ToriiClient._parse_vpn_session, _vpn_session_payload(), "vpn session"),
        (ToriiClient._parse_vpn_receipt, _vpn_receipt_payload(), "vpn receipt"),
        (
            ToriiClient._parse_vpn_receipt_list,
            {"items": [_vpn_receipt_payload()], "total": 1},
            "vpn receipts",
        ),
    ]
    for parser, payload, context in cases:
        payload["unexpected"] = True
        with pytest.raises(RuntimeError, match=r"unsupported fields: unexpected"):
            parser(payload, context=context)

    nested = _vpn_quote_payload()
    nested["open_lease_instruction"]["unexpected"] = True
    with pytest.raises(RuntimeError, match=r"unsupported fields: unexpected"):
        ToriiClient._parse_vpn_quote(nested, context="vpn quote")


def test_vpn_response_parsers_require_all_openapi_fields() -> None:
    cases = [
        (
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload,
            "relay_mldsa65_public_key_hex",
            "vpn profile",
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload,
            "relay_mldsa65_public_key_hex",
            "vpn quote",
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload,
            "relay_mldsa65_public_key_hex",
            "vpn session",
        ),
        (
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload,
            "relay_tls_spki_sha256_hex",
            "vpn profile",
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload,
            "open_lease_instruction",
            "vpn quote",
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload,
            "route_pushes",
            "vpn session",
        ),
        (
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload,
            "settle_lease_instruction",
            "vpn receipt",
        ),
        (
            ToriiClient._parse_vpn_receipt_list,
            lambda: {"items": [_vpn_receipt_payload()], "total": 1},
            "total",
            "vpn receipts",
        ),
    ]
    for parser, payload_factory, missing_field, context in cases:
        payload = payload_factory()
        payload.pop(missing_field)
        with pytest.raises(RuntimeError, match=rf"missing required fields: {missing_field}"):
            parser(payload, context=context)

    nested = _vpn_quote_payload()
    nested["open_lease_instruction"].pop("payload_hex")
    with pytest.raises(RuntimeError, match=r"missing required fields: payload_hex"):
        ToriiClient._parse_vpn_quote(nested, context="vpn quote")

    session = _vpn_session_payload()
    session["route_pushes"] = None
    with pytest.raises(RuntimeError, match=r"route_pushes must be a list"):
        ToriiClient._parse_vpn_session(session, context="vpn session")


def test_vpn_response_parsers_reject_empty_min_length_strings() -> None:
    cases = [
        (
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload,
            "vpn profile",
            (
                "relay_endpoint",
                "meter_family",
                "display_billing_label",
                "operator_account_id",
            ),
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload,
            "vpn quote",
            (
                "payment_reference",
                "account_id",
                "relay_endpoint",
                "fee_asset_id",
                "escrow_account_id",
                "operator_account_id",
                "meter_family",
            ),
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload,
            "vpn session",
            (
                "account_id",
                "relay_endpoint",
                "meter_family",
                "payment_reference",
                "fee_asset_id",
                "escrow_account_id",
                "operator_account_id",
            ),
        ),
        (
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload,
            "vpn receipt",
            (
                "account_id",
                "relay_endpoint",
                "meter_family",
                "fee_asset_id",
                "escrow_account_id",
                "operator_account_id",
            ),
        ),
    ]
    for parser, payload_factory, context, fields in cases:
        for field in fields:
            payload = payload_factory()
            payload[field] = ""
            with pytest.raises(RuntimeError, match=field):
                parser(payload, context=context)

    instruction = _vpn_quote_payload()
    instruction["open_lease_instruction"]["wire_id"] = ""
    with pytest.raises(RuntimeError, match=r"wire_id"):
        ToriiClient._parse_vpn_quote(instruction, context="vpn quote")


def test_vpn_response_parsers_enforce_openapi_enums_and_bounds() -> None:
    cases = [
        (
            "profile exit set",
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload(),
            lambda payload: payload.__setitem__(
                "supported_exit_classes",
                ["standard", "standard", "high-security"],
            ),
            "supported_exit_classes",
            "vpn profile",
        ),
        (
            "profile lease lower bound",
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload(),
            lambda payload: payload.__setitem__("lease_secs", 0),
            "lease_secs",
            "vpn profile",
        ),
        (
            "profile settlement lower bound",
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload(),
            lambda payload: payload.__setitem__("settlement_grace_secs", 0),
            "settlement_grace_secs",
            "vpn profile",
        ),
        (
            "retired quote instruction array",
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload(),
            lambda payload: payload.__setitem__("tx_instructions", []),
            "tx_instructions",
            "vpn quote",
        ),
        (
            "quote exit enum",
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload(),
            lambda payload: payload.__setitem__("exit_class", "fastest"),
            "exit_class",
            "vpn quote",
        ),
        (
            "session mtu constant",
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            lambda payload: payload.__setitem__("mtu_bytes", 1500),
            "mtu_bytes",
            "vpn session",
        ),
        (
            "session flow label constant",
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            lambda payload: payload.__setitem__("flow_label_bits", 20),
            "flow_label_bits",
            "vpn session",
        ),
        (
            "session padding lower bound",
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            lambda payload: payload.__setitem__("padding_budget_ms", 0),
            "padding_budget_ms",
            "vpn session",
        ),
        (
            "session status constant",
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            lambda payload: payload.__setitem__("status", "connected"),
            "status",
            "vpn session",
        ),
        (
            "receipt status enum",
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload(),
            lambda payload: payload.__setitem__("status", "active"),
            "status",
            "vpn receipt",
        ),
        (
            "receipt source enum",
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload(),
            lambda payload: payload.__setitem__("receipt_source", "client"),
            "receipt_source",
            "vpn receipt",
        ),
        (
            "receipt instruction count",
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload(),
            lambda payload: payload.__setitem__(
                "tx_instructions",
                [_vpn_instruction(), _vpn_instruction()],
            ),
            "tx_instructions",
            "vpn receipt",
        ),
        (
            "receipt list item count",
            ToriiClient._parse_vpn_receipt_list,
            {"items": [_vpn_receipt_payload()] * 25, "total": 24},
            lambda payload: None,
            "items",
            "vpn receipts",
        ),
        (
            "receipt list total",
            ToriiClient._parse_vpn_receipt_list,
            {"items": [], "total": 25},
            lambda payload: None,
            "total",
            "vpn receipts",
        ),
    ]
    for _case_name, parser, payload, mutate, expected_field, context in cases:
        mutate(payload)
        with pytest.raises(RuntimeError, match=expected_field):
            parser(payload, context=context)


def test_vpn_response_parsers_require_json_uint64_integers() -> None:
    cases = [
        (
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload(),
            "dns_push_interval_secs",
            "30",
            "vpn profile",
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload(),
            "quote_expires_at_ms",
            True,
            "vpn quote",
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            "bytes_in",
            -1,
            "vpn session",
        ),
        (
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload(),
            "duration_ms",
            1 << 64,
            "vpn receipt",
        ),
    ]
    for parser, payload, field, invalid_value, context in cases:
        payload[field] = invalid_value
        with pytest.raises(RuntimeError, match=field):
            parser(payload, context=context)


@pytest.mark.parametrize(
    "status",
    ["disconnected", "expired", "replaced", "settlement_pending", "settled"],
)
def test_vpn_receipt_parser_accepts_exact_status_values(status: str) -> None:
    receipt = ToriiClient._parse_vpn_receipt(
        _vpn_receipt_payload(status),
        context="vpn receipt",
    )

    assert receipt.status == status


@pytest.mark.parametrize(
    ("parser", "payload", "field", "value", "context"),
    [
        (
            ToriiClient._parse_vpn_profile,
            _vpn_profile_payload(),
            "relay_tls_spki_sha256_hex",
            "AC" * 32,
            "vpn profile",
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload(),
            "quote_id",
            "AB" * 32,
            "vpn quote",
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload(),
            "session_id_hex",
            "0x" + VPN_QUOTE_SESSION_ID,
            "vpn quote",
        ),
        (
            ToriiClient._parse_vpn_quote,
            _vpn_quote_payload(),
            "metering_public_key_hex",
            "CD" * 32,
            "vpn quote",
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            "session_id",
            "0X" + VPN_QUOTE_SESSION_ID,
            "vpn session",
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            "session_id",
            VPN_QUOTE_ID,
            "vpn session",
        ),
        (
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload(),
            "session_id",
            VPN_QUOTE_ID,
            "vpn receipt",
        ),
        (
            ToriiClient._parse_vpn_session,
            _vpn_session_payload(),
            "payment_tx_hash",
            "EF" * 32,
            "vpn session",
        ),
        (
            ToriiClient._parse_vpn_receipt,
            _vpn_receipt_payload(),
            "lease_id_hex",
            "0x" + VPN_LEASE_ID,
            "vpn receipt",
        ),
    ],
    ids=[
        "profile-uppercase-spki",
        "quote-uppercase-id",
        "quote-prefixed-session-id",
        "quote-uppercase-metering-key",
        "session-prefixed-id",
        "session-overlong-id",
        "receipt-overlong-session-id",
        "session-uppercase-payment-hash",
        "receipt-prefixed-lease-id",
    ],
)
def test_vpn_response_parsers_reject_noncanonical_ids_and_hashes(
    parser: Callable[..., Any],
    payload: Dict[str, Any],
    field: str,
    value: str,
    context: str,
) -> None:
    payload[field] = value

    with pytest.raises(RuntimeError, match=r"exact lowercase"):
        parser(payload, context=context)


def test_vpn_session_route_rejects_32_byte_ids_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)

    with pytest.raises(
        RuntimeError,
        match=r"vpn session_id must contain 32 hex characters",
    ):
        client.get_vpn_session(VPN_QUOTE_ID, canonical_auth=_vpn_auth([]))

    assert session.calls == []


def test_vpn_session_lookup_and_receipt_listing_use_native_receipts() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=201, payload=_vpn_session_payload()))
    session.queue(StubResponse(payload=_vpn_session_payload()))
    session.queue(
        StubResponse(
            payload={
                "items": [_vpn_receipt_payload("disconnected")],
                "total": 1,
            }
        )
    )
    session.queue(StubResponse(status_code=404))
    client = ToriiClient("https://node.test", session=session)
    captured: List[bytes] = []
    auth = _vpn_auth(captured)

    created = client.create_vpn_session(
        VpnSessionCreateRequest(
            quote_id=VPN_QUOTE_ID,
            payment_tx_hash=VPN_PAYMENT_HASH,
            metering_public_key_hex=VPN_METERING_KEY,
        ),
        canonical_auth=auth,
    )
    fetched = client.get_vpn_session(VPN_QUOTE_SESSION_ID, canonical_auth=auth)
    receipts = client.list_vpn_receipts(canonical_auth=auth)
    missing = client.get_vpn_session(VPN_QUOTE_SESSION_ID, canonical_auth=auth)

    assert created.session_id == VPN_QUOTE_SESSION_ID
    assert fetched is not None and fetched.payment_tx_hash == VPN_PAYMENT_HASH
    assert receipts.total == 1
    assert receipts.items[0].refunded_fee == "75.125"
    assert missing is None
    assert [call["method"] for call in session.calls] == ["POST", "GET", "GET", "GET"]


def test_submit_vpn_receipt_parses_settlement_instruction() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            status_code=201,
            payload=_vpn_receipt_payload("settlement_pending"),
        )
    )
    client = ToriiClient("https://node.test", session=session)
    captured: List[bytes] = []

    receipt = client.submit_vpn_receipt(
        VpnReceiptSubmitRequest(
            relay_receipt_hex="aa" * 12,
            client_voucher_hex="bb" * 12,
            lease_id_hex=VPN_LEASE_ID,
        ),
        canonical_auth=_vpn_auth(captured),
    )

    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload == {
        "client_voucher_hex": "bb" * 12,
        "lease_id_hex": VPN_LEASE_ID,
        "relay_receipt_hex": "aa" * 12,
    }
    assert receipt.status == "settlement_pending"
    assert receipt.earned_fee == "25.125"
    assert receipt.refunded_fee == "75.125"
    assert receipt.settle_lease_instruction is not None
    assert receipt.settle_lease_instruction.wire_id == "SettleVpnLease"


def test_list_peers_returns_typed_records() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload=[
                {"address": "127.0.0.1:1337", "id": {"public_key": "ed01"}},
                {"address": "[::1]:1337", "id": {"public_key": "ed02"}},
            ]
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )
    peers = client.list_peers()
    assert len(peers) == 2
    assert peers[0].address == "127.0.0.1:1337"
    assert peers[0].public_key_hex == "ed01"
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "http://node.test/v1/peers"
    assert call["params"] == {}
    assert call["data"] is None
    assert call["allow_redirects"] is False
    assert call["stream"] is False
    for header in (
        "X-Iroha-Operator-Public-Key",
        "X-Iroha-Operator-Timestamp-Ms",
        "X-Iroha-Operator-Nonce",
        "X-Iroha-Operator-Signature",
    ):
        assert call["headers"][header]


def _fee_quote_component(kind: str, asset: str, amount: str) -> Dict[str, Any]:
    return {
        "kind": {"kind": kind, "value": None},
        "asset_definition_id": asset,
        "max_amount": amount,
    }


def _fee_quote_capacity(
    asset: str,
    *,
    vault: str,
    reserve: str,
    remaining: str,
) -> Dict[str, Any]:
    return {
        "asset_definition_id": asset,
        "vault_balance": vault,
        "reserve_floor": reserve,
        "block_remaining": remaining,
        "program_epoch_remaining": remaining,
        "beneficiary_epoch_remaining": remaining,
    }


def _i105_display_for(account_id: str, chain_discriminant: int) -> str:
    controller = client_module._decode_canonical_i105_string(account_id)
    return client_module._account_id_codec.encode_i105_account_id(
        controller,
        chain_discriminant,
    )


def _sponsored_fee_quote_fixture() -> tuple[Dict[str, Any], Dict[str, Any]]:
    intent = _sponsor_fee_payment(100)
    intent["value"]["charge_limits"] = [
        _fee_quote_component("nexus", CANONICAL_ASSET_DEFINITION_ID, "1"),
        _fee_quote_component("pipeline_gas", CANONICAL_ASSET_ID, "2"),
    ]
    draft = {"authority": CANONICAL_OWNER, "fee_payment": copy.deepcopy(intent)}
    quote = {
        "intent": copy.deepcopy(intent),
        "observation": {
            "ledger_time_ms": 10,
            "next_block_height": 4,
            "route_dataspace_id": 0,
        },
        "components": copy.deepcopy(intent["value"]["charge_limits"]),
        "capacities": [
            _fee_quote_capacity(
                CANONICAL_ASSET_ID,
                vault="3",
                reserve="1",
                remaining="2",
            ),
            _fee_quote_capacity(
                CANONICAL_ASSET_DEFINITION_ID,
                vault="2",
                reserve="1",
                remaining="1",
            ),
        ],
        "decision": {
            "status": "accepted",
            "value": {
                "debit_source": {
                    "kind": "sponsor_program",
                    "value": copy.deepcopy(intent["value"]["program_id"]),
                },
                "program_revision": 3,
            },
        },
    }
    return draft, quote


def _authority_fee_quote_fixture() -> tuple[Dict[str, Any], Dict[str, Any]]:
    intent = _authority_fee_payment()
    draft = {"authority": CANONICAL_OWNER, "fee_payment": copy.deepcopy(intent)}
    return draft, {
        "intent": copy.deepcopy(intent),
        "observation": {
            "ledger_time_ms": 10,
            "next_block_height": 4,
            "route_dataspace_id": 0,
        },
        "components": [],
        "capacities": [],
        "decision": {
            "status": "accepted",
            "value": {
                "debit_source": {"kind": "account", "value": CANONICAL_OWNER},
                "program_revision": None,
            },
        },
    }


def test_fee_quote_posts_exact_payload_with_authority_signature() -> None:
    session = RecordingSession()
    quote = {
        "intent": _authority_fee_payment(),
        "observation": {
            "ledger_time_ms": 10,
            "next_block_height": 4,
            "route_dataspace_id": 0,
        },
        "components": [],
        "capacities": [],
        "decision": {
            "status": "accepted",
            "value": {
                "debit_source": {"kind": "account", "value": CANONICAL_OWNER},
                "program_revision": None,
            },
        },
    }
    session.queue(StubResponse(payload=quote))
    signed_messages: List[bytes] = []
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda message: signed_messages.append(message) or b"signature",
        timestamp_ms=123,
        nonce="fee-quote-nonce",
    )
    client = ToriiClient("https://node.test", session=session)
    draft = {"authority": CANONICAL_OWNER, "fee_payment": _authority_fee_payment()}

    assert client.quote_fees(draft, canonical_auth=auth) == quote

    call = session.calls[0]
    assert call["url"] == "https://node.test/v1/fees/quote"
    assert json.loads(call["data"].decode("utf-8")) == {"payload": draft}
    assert call["headers"]["X-Iroha-Account"] == CANONICAL_OWNER_HEADER
    assert call["headers"]["X-Iroha-Timestamp-Ms"] == "123"
    assert call["headers"]["X-Iroha-Nonce"] == "fee-quote-nonce"
    assert len(signed_messages) == 1


def test_fee_quote_accepts_parameterized_json_media_type() -> None:
    draft, quote = _authority_fee_quote_fixture()
    response = StubResponse(
        payload=quote,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    session = RecordingSession()
    session.queue(response)

    result = ToriiClient("https://node.test", session=session).quote_fees(
        draft,
        canonical_auth=_governance_auth(),
    )

    assert result == quote
    assert response.was_closed


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json; charset=utf-8, text/plain",
        "text/plain",
        "application/jſon",
        "applıcation/json",
        "applİcation/json",
    ],
    ids=[
        "conflicting-folded-duplicate",
        "plain-text",
        "long-s-confusable",
        "dotless-i-confusable",
        "dotted-capital-i-confusable",
    ],
)
def test_fee_quote_rejects_non_json_whole_field_media_type(
    content_type: str,
) -> None:
    draft, quote = _authority_fee_quote_fixture()
    response = StubResponse(
        payload=quote,
        headers={"Content-Type": content_type},
    )
    session = RecordingSession()
    session.queue(response)

    with pytest.raises(RuntimeError, match="Content-Type application/json"):
        ToriiClient("https://node.test", session=session).quote_fees(
            draft,
            canonical_auth=_governance_auth(),
        )
    assert response.was_closed


def test_fee_quote_uses_controller_identity_and_allows_alias_auth() -> None:
    alternate_owner = _i105_display_for(CANONICAL_OWNER, 369)
    draft, quote = _authority_fee_quote_fixture()
    quote["decision"]["value"]["debit_source"]["value"] = alternate_owner
    session = RecordingSession()
    first_response = StubResponse(payload=quote)
    second_response = StubResponse(payload=quote)
    session.queue(first_response)
    session.queue(second_response)
    client = ToriiClient("https://node.test", session=session)

    alternate_auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=alternate_owner,
        signer=lambda _message: b"signature",
    )
    assert client.quote_fees(draft, canonical_auth=alternate_auth) == quote

    alias_auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id="payer@taira",
        signer=lambda _message: b"signature",
    )
    assert client.quote_fees(draft, canonical_auth=alias_auth) == quote
    assert session.calls[1]["headers"]["X-Iroha-Account"] == "payer@taira"
    assert session.calls[0]["stream"] is True
    assert first_response.was_closed
    assert second_response.was_closed


@pytest.mark.parametrize(
    "response,pattern",
    [
        (
            StubResponse(
                raw=(
                    b'{"intent":{"payer":"authority","value":'
                    b'{"charge_limits":[],"gas_limit":null}},'
                    b'"observation":{"ledger_time_ms":1,'
                    b'"next_block_height":1,"route_dataspace_id":0},'
                    b'"components":[],"capacities":[],"decision":'
                    b'{"status":"accepted","value":{"debit_source":'
                    b'{"kind":"account","value":"'
                    + CANONICAL_OWNER.encode("utf-8")
                    + b'"},"program_revision":null,"program_revision":null}}}'
                ),
                headers={"Content-Type": "application/json"},
            ),
            "duplicate JSON object member",
        ),
        (
            StubResponse(
                raw=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(64 * 1024 + 1),
                },
            ),
            "65536-byte size bound",
        ),
    ],
)
def test_fee_quote_rejects_non_exact_bounded_json_response(
    response: StubResponse,
    pattern: str,
) -> None:
    session = RecordingSession()
    session.queue(response)
    client = ToriiClient("https://node.test", session=session)
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"signature",
    )

    with pytest.raises(RuntimeError, match=pattern):
        client.quote_fees(_authority_fee_quote_fixture()[0], canonical_auth=auth)
    assert response.was_closed


@pytest.mark.parametrize("extra_byte", [False, True])
def test_fee_quote_enforces_actual_response_body_ceiling(extra_byte: bool) -> None:
    draft, quote = _authority_fee_quote_fixture()
    encoded = json.dumps(quote, separators=(",", ":")).encode("utf-8")
    target_size = 64 * 1024 + int(extra_byte)
    response = StubResponse(
        raw=encoded + b" " * (target_size - len(encoded)),
        headers={"Content-Type": "application/json"},
    )
    session = RecordingSession()
    session.queue(response)
    client = ToriiClient("https://node.test", session=session)
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"signature",
    )

    if extra_byte:
        with pytest.raises(RuntimeError, match="65536-byte size bound"):
            client.quote_fees(draft, canonical_auth=auth)
    else:
        assert client.quote_fees(draft, canonical_auth=auth) == quote
    assert response.was_closed


def test_fee_quote_accepts_fee_free_sponsor_with_empty_capacities() -> None:
    intent = _sponsor_fee_payment()
    draft = {"authority": CANONICAL_OWNER, "fee_payment": copy.deepcopy(intent)}
    quote = {
        "intent": copy.deepcopy(intent),
        "observation": {
            "ledger_time_ms": 0,
            "next_block_height": 1,
            "route_dataspace_id": 0,
        },
        "components": [],
        "capacities": [],
        "decision": {
            "status": "accepted",
            "value": {
                "debit_source": {
                    "kind": "sponsor_program",
                    "value": copy.deepcopy(intent["value"]["program_id"]),
                },
                "program_revision": 3,
            },
        },
    }

    assert client_module.validate_fee_quote_response_for_draft(draft, quote) == quote

    alternate_owner = _i105_display_for(CANONICAL_OWNER, 369)
    alternate_quote = copy.deepcopy(quote)
    alternate_quote["intent"]["value"]["program_id"]["sponsor"] = alternate_owner
    alternate_quote["decision"]["value"]["debit_source"]["value"][
        "sponsor"
    ] = alternate_owner
    assert (
        client_module.validate_fee_quote_response_for_draft(draft, alternate_quote)
        == alternate_quote
    )


def test_fee_quote_aggregates_quantities_without_decimal_rounding() -> None:
    intent = _sponsor_fee_payment(100)
    intent["value"]["charge_limits"] = [
        _fee_quote_component("nexus", CANONICAL_ASSET_ID, "0.1"),
        _fee_quote_component("pipeline_gas", CANONICAL_ASSET_ID, "0.2"),
    ]
    draft = {"authority": CANONICAL_OWNER, "fee_payment": copy.deepcopy(intent)}
    quote = {
        "intent": copy.deepcopy(intent),
        "observation": {
            "ledger_time_ms": 10,
            "next_block_height": 4,
            "route_dataspace_id": 0,
        },
        "components": copy.deepcopy(intent["value"]["charge_limits"]),
        "capacities": [
            _fee_quote_capacity(
                CANONICAL_ASSET_ID,
                vault="0.4",
                reserve="0.1",
                remaining="0.3",
            )
        ],
        "decision": {
            "status": "accepted",
            "value": {
                "debit_source": {
                    "kind": "sponsor_program",
                    "value": copy.deepcopy(intent["value"]["program_id"]),
                },
                "program_revision": 3,
            },
        },
    }

    assert client_module.validate_fee_quote_response_for_draft(draft, quote) == quote


def test_fee_quote_may_replace_only_the_requested_charge_maxima() -> None:
    requested = _authority_fee_payment(100)
    requested["value"]["charge_limits"] = [
        _fee_quote_component("nexus", CANONICAL_ASSET_ID, "5")
    ]
    quoted = copy.deepcopy(requested)
    quoted["value"]["charge_limits"][0]["max_amount"] = "3"
    draft = {"authority": CANONICAL_OWNER, "fee_payment": requested}
    quote = _authority_fee_quote_fixture()[1]
    quote["intent"] = quoted
    quote["components"] = copy.deepcopy(quoted["value"]["charge_limits"])

    assert client_module.validate_fee_quote_response_for_draft(draft, quote) == quote


def test_fee_quote_rejects_quantity_aggregate_overflow() -> None:
    maximum = str((1 << 511) - 1)
    intent = _sponsor_fee_payment()
    intent["value"]["charge_limits"] = [
        _fee_quote_component("nexus", CANONICAL_ASSET_ID, maximum),
        _fee_quote_component("pipeline_gas", CANONICAL_ASSET_ID, maximum),
    ]
    draft = {"authority": CANONICAL_OWNER, "fee_payment": copy.deepcopy(intent)}
    quote = {
        "intent": copy.deepcopy(intent),
        "observation": {
            "ledger_time_ms": 0,
            "next_block_height": 1,
            "route_dataspace_id": 0,
        },
        "components": copy.deepcopy(intent["value"]["charge_limits"]),
        "capacities": [
            _fee_quote_capacity(
                CANONICAL_ASSET_ID,
                vault=maximum,
                reserve="0",
                remaining=maximum,
            )
        ],
        "decision": {
            "status": "accepted",
            "value": {
                "debit_source": {
                    "kind": "sponsor_program",
                    "value": copy.deepcopy(intent["value"]["program_id"]),
                },
                "program_revision": 3,
            },
        },
    }

    with pytest.raises(RuntimeError, match="signed 512-bit quantity domain"):
        client_module.validate_fee_quote_response_for_draft(draft, quote)


@pytest.mark.parametrize(
    "case,mutate",
    [
        ("unknown response field", lambda quote: quote.__setitem__("legacy", True)),
        ("missing response field", lambda quote: quote.pop("observation")),
        (
            "missing observation field",
            lambda quote: quote["observation"].pop("route_dataspace_id"),
        ),
        (
            "zero next height",
            lambda quote: quote["observation"].__setitem__("next_block_height", 0),
        ),
        (
            "non-integer observation",
            lambda quote: quote["observation"].__setitem__("ledger_time_ms", True),
        ),
        (
            "u64 overflow",
            lambda quote: quote["observation"].__setitem__(
                "route_dataspace_id", 1 << 64
            ),
        ),
        (
            "intent missing gas slot",
            lambda quote: quote["intent"]["value"].pop("gas_limit"),
        ),
        (
            "component differs from intent",
            lambda quote: quote["components"][0].__setitem__("max_amount", "2"),
        ),
        (
            "component has unknown field",
            lambda quote: quote["components"][0].__setitem__("legacy", None),
        ),
        ("capacities absent for charges", lambda quote: quote["capacities"].clear()),
        ("capacity missing for one asset", lambda quote: quote["capacities"].pop()),
        ("capacities out of order", lambda quote: quote["capacities"].reverse()),
        (
            "duplicate capacity asset",
            lambda quote: quote["capacities"][1].__setitem__(
                "asset_definition_id", CANONICAL_ASSET_ID
            ),
        ),
        (
            "unrelated capacity asset",
            lambda quote: quote["capacities"][0].__setitem__(
                "asset_definition_id", "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            ),
        ),
        (
            "insufficient vault",
            lambda quote: quote["capacities"][0].__setitem__("vault_balance", "2"),
        ),
        (
            "insufficient block window",
            lambda quote: quote["capacities"][0].__setitem__("block_remaining", "1"),
        ),
        (
            "insufficient program epoch",
            lambda quote: quote["capacities"][0].__setitem__(
                "program_epoch_remaining", "1"
            ),
        ),
        (
            "insufficient beneficiary epoch",
            lambda quote: quote["capacities"][0].__setitem__(
                "beneficiary_epoch_remaining", "1"
            ),
        ),
        (
            "capacity missing field",
            lambda quote: quote["capacities"][0].pop("reserve_floor"),
        ),
        (
            "empty debit source",
            lambda quote: quote["decision"]["value"].__setitem__("debit_source", {}),
        ),
        (
            "unsupported decision",
            lambda quote: quote["decision"].__setitem__("status", "rejected"),
        ),
        (
            "missing decision revision",
            lambda quote: quote["decision"]["value"].pop("program_revision"),
        ),
        (
            "wrong decision program",
            lambda quote: quote["decision"]["value"]["debit_source"]["value"].__setitem__(
                "name", "other"
            ),
        ),
        (
            "wrong decision revision",
            lambda quote: quote["decision"]["value"].__setitem__(
                "program_revision", 4
            ),
        ),
    ],
)
def test_fee_quote_rejects_semantic_tamper_matrix(
    case: str,
    mutate: Callable[[Dict[str, Any]], Any],
) -> None:
    draft, quote = _sponsored_fee_quote_fixture()
    mutate(quote)

    with pytest.raises(RuntimeError):
        client_module.validate_fee_quote_response_for_draft(draft, quote)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda quote: quote["decision"]["value"]["debit_source"].__setitem__(
            "value", "not-an-account"
        ),
        lambda quote: quote["decision"]["value"].__setitem__("program_revision", 1),
        lambda quote: quote["decision"]["value"].__setitem__(
            "debit_source",
            {
                "kind": "sponsor_program",
                "value": {"sponsor": CANONICAL_OWNER, "name": "retail"},
            },
        ),
        lambda quote: quote["capacities"].append(
            _fee_quote_capacity(
                CANONICAL_ASSET_ID,
                vault="0",
                reserve="0",
                remaining="0",
            )
        ),
    ],
)
def test_authority_fee_quote_requires_exact_decision_and_no_capacities(
    mutate: Callable[[Dict[str, Any]], Any],
) -> None:
    draft, quote = _authority_fee_quote_fixture()
    mutate(quote)

    with pytest.raises(RuntimeError):
        client_module.validate_fee_quote_response_for_draft(draft, quote)


def test_fee_quote_rejects_authority_substitution_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=OTHER_CANONICAL_ACCOUNT,
        signer=lambda _message: b"signature",
    )

    with pytest.raises(ValueError, match="must identify the payload authority"):
        client.quote_fees(
            {"authority": CANONICAL_OWNER},
            canonical_auth=auth,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "requested, quoted",
    [
        (_authority_fee_payment(100), _authority_fee_payment(101)),
        (_sponsor_fee_payment(100), _authority_fee_payment(100)),
        (
            _sponsor_fee_payment(100),
            {
                **_sponsor_fee_payment(100),
                "value": {
                    **_sponsor_fee_payment(100)["value"],
                    "program_revision": 4,
                },
            },
        ),
    ],
)
def test_fee_quote_rejects_substituted_selection(
    requested: Dict[str, Any],
    quoted: Dict[str, Any],
) -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "intent": quoted,
                "observation": {},
                "components": [],
                "capacities": [],
                "decision": {},
            }
        )
    )
    client = ToriiClient("https://node.test", session=session)
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"signature",
    )

    with pytest.raises(RuntimeError, match="changed the requested payer"):
        client.quote_fees(
            {"authority": CANONICAL_OWNER, "fee_payment": requested},
            canonical_auth=auth,
        )


def test_fee_sponsor_program_lookup_is_account_signed_and_exact() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "id": {"sponsor": CANONICAL_OWNER, "name": "retail"},
                "payout_account": CANONICAL_OWNER,
                "lifecycle": {"state": "active", "value": None},
            },
            headers={"Content-Type": 'Application/JSON; note="é"'},
        )
    )
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"signature",
        timestamp_ms=124,
        nonce="program-lookup-nonce",
    )
    client = ToriiClient("https://node.test", session=session)

    result = client.get_fee_sponsor_program(
        f"{CANONICAL_OWNER}/retail",
        canonical_auth=auth,
    )

    assert result["lifecycle"] == {"state": "active", "value": None}
    assert result["payout_account"] == CANONICAL_OWNER
    assert json.loads(session.calls[0]["data"].decode("utf-8")) == {
        "program_id": f"{CANONICAL_OWNER}/retail"
    }
    assert session.calls[0]["headers"]["X-Iroha-Account"] == CANONICAL_OWNER_HEADER


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json; charset=utf-8, text/plain",
        "text/plain",
    ],
    ids=["conflicting-folded-duplicate", "plain-text"],
)
def test_fee_sponsor_program_lookup_requires_json_whole_field_media_type(
    content_type: str,
) -> None:
    response = StubResponse(
        payload={
            "id": {"sponsor": CANONICAL_OWNER, "name": "retail"},
            "payout_account": CANONICAL_OWNER,
            "lifecycle": {"state": "active", "value": None},
        },
        headers={"Content-Type": content_type},
    )
    session = RecordingSession()
    session.queue(response)

    with pytest.raises(RuntimeError, match="Content-Type application/json"):
        ToriiClient("https://node.test", session=session).get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/retail",
            canonical_auth=_governance_auth(),
        )
    assert response.was_closed


def test_fee_sponsor_program_lookup_pins_sponsor_by_controller_identity() -> None:
    alternate_owner = _i105_display_for(CANONICAL_OWNER, 369)
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "id": {"sponsor": alternate_owner, "name": "retail"},
                "payout_account": CANONICAL_OWNER,
                "lifecycle": {"state": "active", "value": None},
            }
        )
    )
    client = ToriiClient("https://node.test", session=session)
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"signature",
    )

    result = client.get_fee_sponsor_program(
        f"{CANONICAL_OWNER}/retail",
        canonical_auth=auth,
    )

    assert result["id"] == {"sponsor": alternate_owner, "name": "retail"}
    assert json.loads(session.calls[0]["data"].decode("utf-8")) == {
        "program_id": f"{CANONICAL_OWNER}/retail"
    }


def test_fee_sponsor_program_lookup_rejects_substituted_response_id() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "id": {"sponsor": CANONICAL_OWNER, "name": "other"},
                "payout_account": CANONICAL_OWNER,
                "lifecycle": {"state": "active", "value": None},
            }
        )
    )
    client = ToriiClient("https://node.test", session=session)
    auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"signature",
    )

    with pytest.raises(RuntimeError, match="does not match the requested program"):
        client.get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/retail",
            canonical_auth=auth,
        )


def test_fee_sponsor_program_lookup_response_bound_precedes_status_and_decode() -> None:
    maximum_bytes = 64 * 1024
    payload = {
        "id": {"sponsor": CANONICAL_OWNER, "name": "retail"},
        "payout_account": CANONICAL_OWNER,
        "lifecycle": {"state": "active", "value": None},
    }
    prefix = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    exact = prefix + b" " * (maximum_bytes - len(prefix))
    oversized = exact + b" "

    for status_code in (200, 503):
        exact_response = StubResponse(
            status_code=status_code,
            raw=exact,
            headers={"Content-Type": "application/json"},
        )
        exact_session = RecordingSession()
        exact_session.queue(exact_response)
        exact_client = ToriiClient("https://node.test", session=exact_session)
        if status_code == 200:
            result = exact_client.get_fee_sponsor_program(
                f"{CANONICAL_OWNER}/retail",
                canonical_auth=_governance_auth(),
            )
            assert result["id"]["name"] == "retail"
        else:
            with pytest.raises(RuntimeError, match="unexpected status 503"):
                exact_client.get_fee_sponsor_program(
                    f"{CANONICAL_OWNER}/retail",
                    canonical_auth=_governance_auth(),
                )
        assert exact_response.was_closed
        assert exact_session.calls[0]["stream"] is True

        oversized_response = StubResponse(
            status_code=status_code,
            raw=oversized,
            headers={"Content-Type": "application/json"},
        )
        oversized_session = RecordingSession()
        oversized_session.queue(oversized_response)
        with pytest.raises((RuntimeError, ValueError), match="65536-byte size bound"):
            ToriiClient(
                "https://node.test", session=oversized_session
            ).get_fee_sponsor_program(
                f"{CANONICAL_OWNER}/retail",
                canonical_auth=_governance_auth(),
            )
        assert oversized_response.was_closed


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-root",
        "non-object-lifecycle",
        "unknown-lifecycle",
        "non-null-lifecycle-value",
        "zero-active-revision",
        "zero-staged-revision",
        "zero-activation-revision",
        "zero-activation-height",
        "null-active-revision",
        "null-staged-revision",
        "null-activation",
    ],
)
def test_fee_sponsor_program_lookup_rejects_noncanonical_typed_record(
    mutation: str,
) -> None:
    payload: Dict[str, Any] = {
        "id": {"sponsor": CANONICAL_OWNER, "name": "retail"},
        "payout_account": CANONICAL_OWNER,
        "lifecycle": {"state": "active", "value": None},
    }
    if mutation == "unknown-root":
        payload["legacy"] = True
    elif mutation == "non-object-lifecycle":
        payload["lifecycle"] = "active"
    elif mutation == "unknown-lifecycle":
        payload["lifecycle"] = {"state": "legacy", "value": None}
    elif mutation == "non-null-lifecycle-value":
        payload["lifecycle"] = {"state": "active", "value": {}}
    elif mutation == "zero-active-revision":
        payload["active_revision"] = 0
    elif mutation == "zero-staged-revision":
        payload["staged_revision"] = 0
    elif mutation == "zero-activation-revision":
        payload["scheduled_activation"] = {
            "revision": 0,
            "activate_at_height": 1,
        }
    elif mutation == "zero-activation-height":
        payload["scheduled_activation"] = {
            "revision": 1,
            "activate_at_height": 0,
        }
    elif mutation == "null-active-revision":
        payload["active_revision"] = None
    elif mutation == "null-staged-revision":
        payload["staged_revision"] = None
    elif mutation == "null-activation":
        payload["scheduled_activation"] = None
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))

    with pytest.raises(RuntimeError):
        ToriiClient("https://node.test", session=session).get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/retail",
            canonical_auth=_governance_auth(),
        )


@pytest.mark.parametrize(
    "raw",
    [
        (
            b'{"id":{"sponsor":"'
            + CANONICAL_OWNER.encode("utf-8")
            + b'","name":"retail","name":"retail"},'
            + b'"payout_account":"'
            + CANONICAL_OWNER.encode("utf-8")
            + b'","lifecycle":{"state":"active","value":null}}'
        ),
        b'{"id":{"sponsor":"invalid","name":"\x80"}}',
    ],
    ids=["duplicate-key", "malformed-utf8"],
)
def test_fee_sponsor_program_lookup_rejects_ambiguous_json_bytes(raw: bytes) -> None:
    response = StubResponse(
        raw=raw,
        headers={"Content-Type": "application/json"},
    )
    session = RecordingSession()
    session.queue(response)

    with pytest.raises(RuntimeError, match="invalid JSON|valid UTF-8"):
        ToriiClient("https://node.test", session=session).get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/retail",
            canonical_auth=_governance_auth(),
        )
    assert response.was_closed


def test_fee_sponsor_program_lookup_rejects_ambiguous_physical_content_type() -> None:
    class RawHeaderFields:
        def getlist(self, name: str) -> List[str]:
            assert name == "Content-Type"
            return ['application/json; profile="a', 'b"']

    class RawResponse:
        headers = RawHeaderFields()

        @staticmethod
        def close() -> None:
            return None

    response = StubResponse(
        payload={
            "id": {"sponsor": CANONICAL_OWNER, "name": "retail"},
            "payout_account": CANONICAL_OWNER,
            "lifecycle": {"state": "active", "value": None},
        },
        headers={"Content-Type": 'application/json; profile="a,b"'},
    )
    response.raw = RawResponse()
    session = RecordingSession()
    session.queue(response)

    with pytest.raises(RuntimeError, match="Content-Type application/json"):
        ToriiClient("https://node.test", session=session).get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/retail",
            canonical_auth=_governance_auth(),
        )
    assert response.was_closed


@pytest.mark.parametrize(
    "name",
    [
        "x" * 256,
        "e\u0301",
        "retail\u0091",
        "retail\u202e",
    ],
    ids=["overlong", "non-nfc", "unicode-control", "bidi-control"],
)
def test_fee_sponsor_program_lookup_rejects_noncanonical_program_name(
    name: str,
) -> None:
    client = ToriiClient("https://node.test", session=RecordingSession())
    with pytest.raises(ValueError, match="program_id must be canonical"):
        client.get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/{name}",
            canonical_auth=_governance_auth(),
        )


@pytest.mark.parametrize("name", ["x" * 256, "retail\u202e"])
def test_fee_sponsor_program_lookup_rejects_noncanonical_response_name(
    name: str,
) -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "id": {"sponsor": CANONICAL_OWNER, "name": name},
                "payout_account": CANONICAL_OWNER,
                "lifecycle": {"state": "active", "value": None},
            }
        )
    )

    with pytest.raises(RuntimeError, match="response.id is not canonical"):
        ToriiClient("https://node.test", session=session).get_fee_sponsor_program(
            f"{CANONICAL_OWNER}/retail",
            canonical_auth=_governance_auth(),
        )


@pytest.mark.parametrize(
    "call_payload",
    [
        {"value": 1, "labels": ["alpha"]},
        {"value": {"some": None}},
        {"value": {"none": True}},
        {"value": {"some": {"none": True}}},
        {"value": {"some": {"some": None}}},
    ],
    ids=["ordinary", "some-unit", "none", "some-none", "some-some-unit"],
)
def test_call_contract_posts_selector_payload_and_parses_response(call_payload: Any) -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            status_code=200,
            payload=_contract_call_draft(
                fee_payment=_authority_fee_payment(5000),
                transaction_ttl_ms=5_000,
                payload=call_payload,
            ),
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    result = client.prepare_contract_call(
            canonical_auth=_contract_auth(),
        authority=CANONICAL_OWNER,
        contract_alias="router::universal",
        entrypoint="ping",
        payload=call_payload,
        metadata={"caller_note": "trusted"},
        creation_time_ms=42,
        transaction_ttl_ms=5_000,
        fee_payment=_authority_fee_payment(5000),
        draft_intent=_contract_draft_intent(payload=call_payload),
    )

    assert isinstance(result, ContractCallResponse)
    assert result.entrypoint == "ping"
    assert result.creation_time_ms == 42
    assert result.transaction_ttl_ms == 5_000
    assert result.entrypoint_hash_hex is None
    assert isinstance(result.operation_receipt, ContractOperationReceipt)
    assert result.operation_receipt.gas_limit == 5000
    assert result.operation_receipt.payload_digest_hex == contract_payload_digest_hex(
        call_payload
    )
    assert result.submitted is False
    assert result.pipeline_status is None
    assert result.transaction_payload_b64 is not None
    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload == {
        "authority": CANONICAL_OWNER,
        "contract_alias": "router::universal",
        "entrypoint": "ping",
        "payload": call_payload,
        "metadata": {"caller_note": "trusted"},
        "creation_time_ms": 42,
        "transaction_ttl_ms": 5_000,
        "fee_payment": _authority_fee_payment(5000),
    }


def test_contract_payload_digest_uses_cross_sdk_canonical_json() -> None:
    assert contract_payload_digest_hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    )
    canonical = '{"a":[true,"é"],"b":2}'
    assert contract_payload_digest_hex({"b": 2, "a": [True, "é"]}) == (
        client_module.blake3(canonical.encode("utf-8")).hexdigest()
    )


@pytest.mark.parametrize(
    "payload",
    [
        1.5,
        1 << 53,
        {1: "non-string key"},
        {"bad": "\ud800"},
        ("tuple",),
    ],
)
def test_contract_payload_digest_rejects_ambiguous_json(payload: Any) -> None:
    with pytest.raises((TypeError, ValueError), match="contract payload"):
        contract_payload_digest_hex(payload)


def test_contract_payload_digest_rejects_cycles() -> None:
    payload: List[Any] = []
    payload.append(payload)

    with pytest.raises(ValueError, match="cycles"):
        contract_payload_digest_hex(payload)


@pytest.mark.parametrize("payload", [1.5, {1: "non-string key"}, ("tuple",)])
def test_call_contract_rejects_ambiguous_payload_before_dispatch(
    payload: Any,
) -> None:
    session = RecordingSession()
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    with pytest.raises((TypeError, ValueError), match="contract payload"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal",
            entrypoint="ping",
            payload=payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=_contract_draft_intent(),
        )

    assert session.calls == []


@pytest.mark.parametrize("mismatch", ["payload_digest", "resolved_address", "code_hash"])
def test_call_contract_rejects_untrusted_intent_before_dispatch(mismatch: str) -> None:
    call_payload = {"value": 1}
    intent = _contract_draft_intent(payload=call_payload)
    request_address: Optional[str] = None
    request_alias: Optional[str] = "router::universal"
    if mismatch == "payload_digest":
        intent = _contract_draft_intent(payload={"value": 2})
    elif mismatch == "resolved_address":
        request_address = _OTHER_CONTRACT_ADDRESS
        request_alias = None
    else:
        intent = ContractCallDraftIntent(
            executable_b64=intent.executable_b64,
            metadata_b64=intent.metadata_b64,
            contract_address=intent.contract_address,
            code_hash_hex="AA" * 32,
            payload_digest_hex=intent.payload_digest_hex,
        )
    session = RecordingSession()
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    with pytest.raises(ValueError):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_address=request_address,
            contract_alias=request_alias,
            entrypoint="ping",
            payload=call_payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=intent,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("executable", b"substituted contract executable"),
        ("metadata", b"substituted contract metadata"),
    ],
)
def test_call_contract_rejects_rehashed_unsigned_payload_substitution(
    field: str,
    replacement: bytes,
) -> None:
    call_payload = {"value": 1}
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload=_contract_call_draft(
                fee_payment=_authority_fee_payment(5000),
                payload=call_payload,
                **{field: replacement},
            )
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    with pytest.raises(RuntimeError, match=f"caller-trusted {field}"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal",
            entrypoint="ping",
            payload=call_payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=_contract_draft_intent(payload=call_payload),
        )


@pytest.mark.parametrize("admission_intent", [0, 1, 2], ids=["ordinary", "queue-plan", "unknown"])
def test_call_contract_rejects_rehashed_retired_admission_slots(
    admission_intent: int,
) -> None:
    call_payload = {"value": 1}
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload=_contract_call_draft(
                fee_payment=_authority_fee_payment(5000),
                payload=call_payload,
                retired_admission_tag=admission_intent,
            )
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    # The fixture recomputes the signing hash from the substituted payload.
    # A matching prehash cannot authorize an obsolete wire layout.
    with pytest.raises(RuntimeError, match="one canonical transaction payload"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal",
            entrypoint="ping",
            payload=call_payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=_contract_draft_intent(payload=call_payload),
        )
    assert len(session.calls) == 1


@pytest.mark.parametrize("field", ["contract_address", "code_hash_hex"])
def test_call_contract_rejects_colluding_response_and_receipt_substitution(
    field: str,
) -> None:
    call_payload = {"value": 1}
    response = _contract_call_draft(
        fee_payment=_authority_fee_payment(5000),
        payload=call_payload,
    )
    replacement = (
        _OTHER_CONTRACT_ADDRESS if field == "contract_address" else "44" * 32
    )
    response[field] = replacement
    response["operation_receipt"][field] = replacement
    session = RecordingSession()
    session.queue(StubResponse(payload=response))
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    with pytest.raises(RuntimeError, match="exact pending draft binding"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal",
            entrypoint="ping",
            payload=call_payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=_contract_draft_intent(payload=call_payload),
        )


@pytest.mark.parametrize(
    ("field", "replacement", "expected_error"),
    [
        ("status", "submitted", "exact pending draft binding"),
        ("transport", "relay", "exact pending draft binding"),
        ("dataspace", "private", "exact pending draft binding"),
        ("contract_alias", "substituted::universal", "exact pending draft binding"),
        ("contract_address", _OTHER_CONTRACT_ADDRESS, "exact pending draft binding"),
        ("code_hash_hex", "44" * 32, "exact pending draft binding"),
        ("abi_hash_hex", "44" * 32, "exact pending draft binding"),
        ("entrypoint", "substituted", "exact pending draft binding"),
        ("tx_hash_hex", "a" * 63 + "b", "exact pending draft binding"),
        ("entrypoint_hash_hex", "a" * 63 + "b", "exact pending draft binding"),
        ("gas_limit", 4999, "gas_limit does not match"),
        ("gas_used", 1, "exact pending draft binding"),
        ("fee_payment", _sponsor_fee_payment(5000), "fee_payment changed"),
        ("payload_digest_hex", "44" * 32, "payload digest"),
    ],
)
def test_call_contract_rejects_tampered_operation_receipt(
    field: str,
    replacement: Any,
    expected_error: str,
) -> None:
    call_payload = {"value": 1}
    response = _contract_call_draft(
        fee_payment=_authority_fee_payment(5000),
        payload=call_payload,
    )
    response["operation_receipt"][field] = replacement
    session = RecordingSession()
    session.queue(StubResponse(payload=response))
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    with pytest.raises(RuntimeError, match=expected_error):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal",
            entrypoint="ping",
            payload=call_payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=_contract_draft_intent(payload=call_payload),
        )


def test_contract_receipt_rejects_unknown_fields() -> None:
    receipt = _contract_operation_receipt()
    receipt["server_hint"] = "unsigned"

    with pytest.raises(RuntimeError, match="unsupported fields"):
        ToriiClient._parse_contract_operation_receipt(
            receipt,
            context="contract receipt",
        )


def test_call_contract_unsigned_draft_requires_trusted_intent() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload=_contract_call_draft(fee_payment=_authority_fee_payment(5000))
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    with pytest.raises(ValueError, match="ContractCallDraftIntent"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal",
            entrypoint="ping",
            fee_payment=_authority_fee_payment(5000),
        )

    assert session.calls == []


def test_pipeline_status_parser_exposes_only_public_metadata() -> None:
    transaction_hash = "ab" * 32
    parsed = ToriiClient._parse_pipeline_status_response(
        {
            "hash": transaction_hash,
            "status": {"kind": "Applied", "block_height": 7},
            "scope": "global",
            "resolved_from": "state",
        },
        context="pipeline status",
    )

    assert parsed.hash == transaction_hash
    assert parsed.status.kind == "Applied"
    assert parsed.status.block_height == 7
    assert parsed.scope == "global"
    assert parsed.resolved_from == "state"
    assert parsed.is_authoritatively_applied
    assert not parsed.is_authoritative_failure
    assert not hasattr(parsed, "is_terminal")
    assert not hasattr(parsed, "is_committed")
    assert not hasattr(parsed, "diagnostics")
    assert not hasattr(parsed, "summary")
    assert not hasattr(parsed, "raw")


@pytest.mark.parametrize(
    ("kind", "scope", "resolved_from", "applied", "failure"),
    [
        ("Applied", "global", "state", True, False),
        ("Committed", "global", "state", False, False),
        ("Applied", "local", "state", False, False),
        ("Applied", "global", "cache", False, False),
        ("Rejected", "global", "state", False, True),
        ("Expired", "global", "state", False, True),
        ("Rejected", "global", "cache", False, False),
    ],
)
def test_pipeline_status_finality_helpers_require_exact_authoritative_state(
    kind: str,
    scope: str,
    resolved_from: str,
    applied: bool,
    failure: bool,
) -> None:
    parsed = ToriiClient._parse_pipeline_status_response(
        {
            "hash": "cd" * 32,
            "status": {"kind": kind},
            "scope": scope,
            "resolved_from": resolved_from,
        },
        context="pipeline status",
    )

    assert parsed.is_authoritatively_applied is applied
    assert parsed.is_authoritative_failure is failure


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("summary", "Rejected: secret"),
        ("diagnostics", [{"message": "secret"}]),
        ("trigger_completions", []),
        ("batch_transfer_outcomes", []),
    ],
)
def test_pipeline_status_parser_rejects_retired_detail_fields(
    field: str,
    value: object,
) -> None:
    payload = {
        "hash": "cd" * 32,
        "status": {"kind": "Rejected"},
        "scope": "global",
        "resolved_from": "state",
        field: value,
    }

    with pytest.raises(RuntimeError, match="unsupported fields"):
        ToriiClient._parse_pipeline_status_response(
            payload,
            context="pipeline status",
        )


@pytest.mark.parametrize("block_height", [None, 0, -1, True, 1.5])
def test_pipeline_status_parser_rejects_non_positive_or_non_integer_height(
    block_height: object,
) -> None:
    payload = {
        "hash": "cd" * 32,
        "status": {"kind": "Applied", "block_height": block_height},
        "scope": "global",
        "resolved_from": "state",
    }

    with pytest.raises(RuntimeError, match="block_height"):
        ToriiClient._parse_pipeline_status_response(
            payload,
            context="pipeline status",
        )


@pytest.mark.parametrize("transaction_hash", ["ab", "AB" * 32, "gg" * 32, " ab" * 32])
def test_pipeline_status_parser_rejects_noncanonical_hash(transaction_hash: str) -> None:
    payload = {
        "hash": transaction_hash,
        "status": {"kind": "Applied", "block_height": 1},
        "scope": "global",
        "resolved_from": "state",
    }

    with pytest.raises(RuntimeError, match="canonical Iroha HashOf marker"):
        ToriiClient._parse_pipeline_status_response(
            payload,
            context="pipeline status",
        )


def test_pipeline_status_parser_rejects_hash_without_iroha_marker() -> None:
    payload = {
        "hash": "aa" * 32,
        "status": {"kind": "Applied", "block_height": 1},
        "scope": "global",
        "resolved_from": "state",
    }

    with pytest.raises(RuntimeError, match="HashOf marker"):
        ToriiClient._parse_pipeline_status_response(
            payload,
            context="pipeline status",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "Applied "),
        ("scope", " global"),
        ("resolved_from", "state "),
    ],
)
def test_pipeline_status_parser_rejects_padded_enum_values(
    field: str,
    value: str,
) -> None:
    payload = {
        "hash": "cd" * 32,
        "status": {"kind": "Applied", "block_height": 1},
        "scope": "global",
        "resolved_from": "state",
    }
    if field == "kind":
        payload["status"]["kind"] = value
    else:
        payload[field] = value

    with pytest.raises((RuntimeError, ValueError)):
        ToriiClient._parse_pipeline_status_response(
            payload,
            context="pipeline status",
        )


@pytest.mark.parametrize("field", ["tx_hash_hex", "entrypoint_hash_hex"])
def test_contract_receipt_rejects_transaction_hash_without_iroha_marker(
    field: str,
) -> None:
    receipt = _contract_operation_receipt()
    receipt[field] = "aa" * 32

    with pytest.raises(RuntimeError, match="HashOf marker"):
        ToriiClient._parse_contract_operation_receipt(
            receipt,
            context="contract receipt",
        )


def test_contract_response_rejects_entrypoint_hash_without_iroha_marker() -> None:
    payload = _contract_call_draft()
    payload["entrypoint_hash_hex"] = "aa" * 32

    with pytest.raises(RuntimeError, match="HashOf marker"):
        ToriiClient._parse_contract_call_response(
            payload,
            context="contract response",
        )


@pytest.mark.parametrize("scope", ["auto", "GLOBAL", " global ", ""])
def test_pipeline_status_parser_rejects_noncanonical_scope(scope: str) -> None:
    payload = {
        "hash": "cd" * 32,
        "status": {"kind": "Applied", "block_height": 1},
        "scope": scope,
        "resolved_from": "state",
    }

    with pytest.raises(RuntimeError, match="scope"):
        ToriiClient._parse_pipeline_status_response(
            payload,
            context="pipeline status",
        )


def test_call_contract_preserves_shared_rust_argument_record_fixture() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "kotodama"
        / "entrypoint_argument_record_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["codec"] == "EntrypointArgumentRecordV1"
    assert fixture["generator"] == "ivm_abi::arguments::encode_argument_record_from_json"
    assert re.fullmatch(
        r"[0-9a-f]{64}",
        fixture["entrypoint_argument_schema_v1"]["schema_hash_hex"],
    )
    assert re.fullmatch(
        r"(?:[0-9a-f]{2})+",
        fixture["entrypoint_argument_record_v1"]["norito_hex"],
    )

    boundary = fixture["torii_boundary"]
    assert isinstance(boundary["payload"]["exact_int"], str)
    assert boundary["payload"]["exact_int"] == (
        "1606938044258990275541962092341162602522202993782792835301376"
    )
    assert isinstance(boundary["payload"]["exact_decimal"], str)
    assert boundary["payload"]["exact_decimal"] == "-12345678901234567890.125"
    assert isinstance(boundary["payload"]["exact_quantity"], str)
    assert boundary["payload"]["exact_quantity"] == (
        "12345678901234567890.0000000000000000000000000001"
    )
    session = RecordingSession()
    session.queue(
        StubResponse(
            status_code=200,
            payload=_contract_call_draft(
                authority=boundary["authority"],
                entrypoint=boundary["entrypoint"],
                contract_alias=boundary["contract_alias"],
                fee_payment=boundary["fee_payment"],
                payload=boundary["payload"],
            ),
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    client.prepare_contract_call(
        canonical_auth=_contract_auth(account_id=boundary["authority"]),
        authority=boundary["authority"],
        contract_alias=boundary["contract_alias"],
        entrypoint=boundary["entrypoint"],
        payload=boundary["payload"],
        fee_payment=boundary["fee_payment"],
        draft_intent=_contract_draft_intent(payload=boundary["payload"]),
    )

    submitted = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert submitted == {
        "authority": boundary["authority"],
        "contract_alias": boundary["contract_alias"],
        "entrypoint": boundary["entrypoint"],
        "payload": boundary["payload"],
        "fee_payment": boundary["fee_payment"],
    }
    assert "argument_record" not in submitted
    assert "argument_record_norito_hex" not in submitted


def test_call_contract_posts_exact_sponsor_program_and_rejects_adversarial_sponsor() -> None:
    call_payload: Dict[str, Any] = {}
    session = RecordingSession()
    session.queue(
        StubResponse(
            status_code=200,
            payload=_contract_call_draft(
                contract_alias="router::is",
                fee_payment=_sponsor_fee_payment(5000),
                payload=call_payload,
            ),
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    client.prepare_contract_call(
            canonical_auth=_contract_auth(),
        authority=CANONICAL_OWNER,
        contract_alias="router::is",
        entrypoint="ping",
        payload=call_payload,
        fee_payment=_sponsor_fee_payment(5000),
        draft_intent=_contract_draft_intent(payload=call_payload),
    )

    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["fee_payment"] == _sponsor_fee_payment(5000)
    assert payload["contract_alias"] == "router::is"

    adversarial = _sponsor_fee_payment(5000)
    adversarial["value"]["program_id"]["sponsor"] = "bad sponsor"
    with pytest.raises(ValueError, match="prepare_contract_call.fee_payment.*sponsor"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::is",
            entrypoint="ping",
            fee_payment=adversarial,
        )


def test_call_contract_rejects_missing_entrypoint_and_non_positive_gas_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=_local_signing_context(),
    )

    for entrypoint in ("", "   "):
        with pytest.raises(ValueError, match="prepare_contract_call.entrypoint"):
            client.prepare_contract_call(
            canonical_auth=_contract_auth(),
                authority=CANONICAL_OWNER,
                contract_alias="router::universal",
                entrypoint=entrypoint,
                fee_payment=_authority_fee_payment(1),
            )
    for gas_limit in (None, 0, -1):
        with pytest.raises(ValueError, match="prepare_contract_call.fee_payment.*gas_limit"):
            client.prepare_contract_call(
            canonical_auth=_contract_auth(),
                authority=CANONICAL_OWNER,
                contract_alias="router::universal",
                entrypoint="ping",
                fee_payment=_authority_fee_payment(gas_limit),
            )

    assert session.calls == []


def test_call_contract_response_requires_operation_receipt() -> None:
    payload = {
        "ok": True,
        "submitted": True,
        "dataspace": "universal",
        "code_hash_hex": "22" * 32,
        "abi_hash_hex": "33" * 32,
        "creation_time_ms": 42,
        "entrypoint": "ping",
    }

    with pytest.raises(RuntimeError, match="operation_receipt response must be a JSON object"):
        ToriiClient._parse_contract_call_response(payload, context="contract call response")


def test_call_contract_rejects_ambiguous_selector() -> None:
    client = ToriiClient("http://node.test", session=RecordingSession())

    with pytest.raises(ValueError, match="exactly one of contract_address or contract_alias"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_address="irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            contract_alias="router::universal",
            entrypoint="ping",
            fee_payment=_authority_fee_payment(1),
        )


def test_call_contract_rejects_padded_selectors_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(ValueError, match="prepare_contract_call\\.contract_address must not contain surrounding whitespace"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_address=" irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            entrypoint="ping",
            fee_payment=_authority_fee_payment(1),
        )

    with pytest.raises(ValueError, match="prepare_contract_call\\.contract_alias must not contain surrounding whitespace"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias="router::universal ",
            entrypoint="ping",
            fee_payment=_authority_fee_payment(1),
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "contract_alias",
    ["router", "router::", "router::domain.dataspace.extra", "router::domain@dataspace"],
)
def test_call_contract_rejects_noncanonical_alias_before_dispatch(
    contract_alias: str,
) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(ValueError, match="contract_alias"):
        client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_alias=contract_alias,
            entrypoint="ping",
            fee_payment=_authority_fee_payment(1),
        )

    assert session.calls == []


def test_get_governance_contract_parses_response() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "found": True,
                "contract_address": "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
                "contract_subject_account": CANONICAL_OWNER,
                "dataspace": "universal",
                "active": True,
                "lifecycle": {
                    "version": 1,
                    "origin": "direct",
                    "origin_account": CANONICAL_OWNER,
                    "origin_proposal_content_id_hex": None,
                    "origin_governance_attempt_id_hex": None,
                    "owner": CANONICAL_OWNER,
                    "pending_owner": "parliament",
                    "parliament_delegated": True,
                    "active_code_hash_hex": "22" * 32,
                    "revision": 7,
                    "emergency_hold": None,
                },
                "emergency_hold_active": False,
                "code_hash_hex": "22" * 32,
                "abi_hash_hex": "33" * 32,
                "public_entrypoints": ["transfer", "view_balance"],
            },
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.get_governance_contract(
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        canonical_auth=_governance_auth(),
    )

    assert isinstance(result, GovernanceContractResponse)
    assert result.found is True
    assert result.code_hash_hex == "22" * 32
    assert result.lifecycle is not None
    assert result.lifecycle.revision == 7
    assert result.lifecycle.active_code_hash_hex == "22" * 32
    assert result.lifecycle.pending_owner == "parliament"
    assert result.public_entrypoints == ["transfer", "view_balance"]
    assert session.calls[0]["url"] == (
        "http://node.test/v1/gov/contracts/"
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
    )


def test_governance_contract_response_enforces_the_exact_lifecycle_shape() -> None:
    contract_address = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
    active = {
        "found": True,
        "contract_address": contract_address,
        "contract_subject_account": CANONICAL_OWNER,
        "dataspace": "universal",
        "active": True,
        "lifecycle": {
            "version": 1,
            "origin": "direct",
            "origin_account": CANONICAL_OWNER,
            "origin_proposal_content_id_hex": None,
            "origin_governance_attempt_id_hex": None,
            "owner": CANONICAL_OWNER,
            "pending_owner": None,
            "parliament_delegated": False,
            "active_code_hash_hex": "22" * 32,
            "revision": 7,
            "emergency_hold": None,
        },
        "emergency_hold_active": False,
        "code_hash_hex": "22" * 32,
        "abi_hash_hex": "33" * 32,
        "public_entrypoints": ["transfer", "view_balance"],
    }
    absent = ToriiClient._parse_governance_contract_response(
        {
            "found": False,
            "contract_address": contract_address,
            "dataspace": "universal",
        },
        context="governance contract response",
    )
    assert absent.found is False
    assert absent.active is None
    assert absent.lifecycle is None

    invalid_cases = []
    mismatched = copy.deepcopy(active)
    mismatched["lifecycle"]["active_code_hash_hex"] = "44" * 32
    invalid_cases.append(mismatched)
    unsorted = copy.deepcopy(active)
    unsorted["public_entrypoints"] = ["view_balance", "transfer"]
    invalid_cases.append(unsorted)
    alias_owner = copy.deepcopy(active)
    alias_owner["lifecycle"]["owner"] = "alice@universal"
    invalid_cases.append(alias_owner)
    absent_with_retired_null = {
        "found": False,
        "contract_address": contract_address,
        "dataspace": "universal",
        "code_hash_hex": None,
    }
    invalid_cases.append(absent_with_retired_null)
    for payload in invalid_cases:
        with pytest.raises((RuntimeError, ValueError)):
            ToriiClient._parse_governance_contract_response(
                payload,
                context="governance contract response",
            )


def test_governance_contract_lifecycle_requires_exact_wire_u64_values() -> None:
    lifecycle = {
        "version": 1,
        "origin": "direct",
        "origin_account": CANONICAL_OWNER,
        "origin_proposal_content_id_hex": None,
        "origin_governance_attempt_id_hex": None,
        "owner": CANONICAL_OWNER,
        "pending_owner": None,
        "parliament_delegated": False,
        "active_code_hash_hex": "22" * 32,
        "revision": (1 << 64) - 1,
        "emergency_hold": None,
    }
    parsed = ToriiClient._parse_governance_contract_lifecycle(
        lifecycle,
        context="governance contract response.lifecycle",
    )
    assert parsed.revision == (1 << 64) - 1

    for value in (True, "7", 7.0, -1, 1 << 64):
        invalid = copy.deepcopy(lifecycle)
        invalid["revision"] = value
        with pytest.raises(RuntimeError, match="unsigned 64-bit JSON integer"):
            ToriiClient._parse_governance_contract_lifecycle(
                invalid,
                context="governance contract response.lifecycle",
            )

    hold = {
        "incident_digest_hex": "44" * 32,
        "proposal_content_id_hex": "55" * 32,
        "governance_attempt_id_hex": "66" * 32,
        "reason": "containment",
        "imposed_at_height": (1 << 64) - 2,
        "expires_at_height": (1 << 64) - 1,
    }
    parsed_hold = ToriiClient._parse_governance_contract_emergency_hold(
        hold,
        context="governance contract response.lifecycle.emergency_hold",
    )
    assert parsed_hold.expires_at_height == (1 << 64) - 1

    for value in (True, "10", 10.0, -1, 1 << 64):
        invalid = copy.deepcopy(hold)
        invalid["imposed_at_height"] = value
        with pytest.raises(RuntimeError, match="unsigned 64-bit JSON integer"):
            ToriiClient._parse_governance_contract_emergency_hold(
                invalid,
                context="governance contract response.lifecycle.emergency_hold",
            )


def test_governance_contract_transport_rejects_duplicate_lifecycle_keys() -> None:
    contract_address = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
    payload = {
        "found": True,
        "contract_address": contract_address,
        "contract_subject_account": CANONICAL_OWNER,
        "dataspace": "universal",
        "active": True,
        "lifecycle": {
            "version": 1,
            "origin": "direct",
            "origin_account": CANONICAL_OWNER,
            "origin_proposal_content_id_hex": None,
            "origin_governance_attempt_id_hex": None,
            "owner": CANONICAL_OWNER,
            "pending_owner": None,
            "parliament_delegated": False,
            "active_code_hash_hex": "22" * 32,
            "revision": 7,
            "emergency_hold": None,
        },
        "emergency_hold_active": False,
        "code_hash_hex": "22" * 32,
        "abi_hash_hex": "33" * 32,
        "public_entrypoints": ["ping"],
    }
    duplicate = json.dumps(payload, separators=(",", ":")).replace(
        '"revision":7',
        '"revision":7,"revision":8',
    )
    session = RecordingSession()
    session.queue(
        StubResponse(
            raw=duplicate.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
    )
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="duplicate JSON object member `revision`"):
        client.get_governance_contract(
            contract_address,
            canonical_auth=_governance_auth(),
        )

    assert session.calls[0]["stream"] is True
    assert session.calls[0]["allow_redirects"] is False


@pytest.mark.parametrize(
    "selector",
    [
        "",
        ".",
        ".hidden",
        "selector/alias",
        "selector%2Falias",
        "selector alias",
        "selector\nalias",
        "sélector",
        "a" * 129,
    ],
)
def test_governance_selectors_reject_before_transport(selector: str) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    operations = [
        lambda: client.get_governance_locks(selector, canonical_auth=_governance_auth()),
        lambda: client.get_governance_referendum(selector, canonical_auth=_governance_auth()),
        lambda: client.get_governance_tally(selector, canonical_auth=_governance_auth()),
        lambda: client.submit_plain_ballot(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            referendum_id=selector,
            owner=CANONICAL_OWNER,
            amount="1",
            duration_blocks=1,
            direction="Aye",
            canonical_auth=_governance_auth(),
        ),
        lambda: client.submit_zk_ballot_v1(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            election_id=selector,
            backend="halo2/ipa",
            envelope_b64="AAAA",
            canonical_auth=_governance_auth(),
        ),
    ]
    for operation in operations:
        with pytest.raises(RuntimeError, match="canonical governance selector V1"):
            operation()
    assert session.calls == []


def test_governance_selector_accepts_exact_boundaries() -> None:
    for selector in ("a", "a" * 128, "A9_selector~with.dots"):
        assert (
            ToriiClient._require_governance_selector_v1(
                selector,
                context="selector",
            )
            == selector
        )


@pytest.mark.parametrize(
    "proposal_id",
    ["a" * 63, "A" * 64, "0x" + "a" * 64, "a" * 63 + "/"],
)
def test_governance_proposal_ids_reject_before_transport(proposal_id: str) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="lowercase 32-byte hex"):
        client.get_governance_proposal(
            proposal_id, canonical_auth=_governance_auth()
        )
    assert session.calls == []


def test_proposal_backed_legacy_governance_methods_are_retired() -> None:
    assert not hasattr(ToriiClient, "finalize_referendum")
    assert not hasattr(ToriiClient, "enact_proposal")


def test_first_release_exports_exclude_retired_type_aliases() -> None:
    import iroha_torii_client.client as client_module

    for name in ("GovernanceProposalStatus", "OfflineLanePrivacyWitnessJson"):
        assert name not in client_module.__all__
        assert not hasattr(client_module, name)


def _governance_locks_payload(amount: Any) -> Dict[str, Any]:
    return {
        "found": True,
        "referendum_id": "ref-1",
        "locks": {
            CANONICAL_OWNER: {
                "owner": CANONICAL_OWNER,
                "amount": amount,
                "slashed": "0.25",
                "expiry_height": 10,
                "direction": 1,
                "duration_blocks": 5,
                "custody": {
                    "escrowed": True,
                    "asset_definition_id": "xor#wonderland",
                    "bond_escrow_account": CANONICAL_OWNER,
                    "slash_receiver_account": CANONICAL_OWNER,
                },
            }
        },
    }


def test_get_governance_locks_returns_typed_lossless_quantity() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(payload=_governance_locks_payload(CANONICAL_LARGE_FRACTION))
    )
    result = ToriiClient(
        "http://node.test",
        session=session,
    ).get_governance_locks("ref-1", canonical_auth=_governance_auth())

    record = result.locks[CANONICAL_OWNER] if result.locks is not None else None
    assert isinstance(record, GovernanceLockRecord)
    assert record.amount == CANONICAL_LARGE_FRACTION
    assert record.slashed == "0.25"
    assert record.custody is not None
    assert isinstance(record.custody, GovernanceLockCustody)
    assert record.custody.escrowed is True
    assert record.custody.asset_definition_id == "xor#wonderland"


def test_get_governance_locks_accepts_explicit_null_custody() -> None:
    payload = _governance_locks_payload("1")
    payload["locks"][CANONICAL_OWNER]["custody"] = None
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))
    result = ToriiClient("http://node.test", session=session).get_governance_locks(
        "ref-1", canonical_auth=_governance_auth()
    )

    record = result.locks[CANONICAL_OWNER] if result.locks is not None else None
    assert isinstance(record, GovernanceLockRecord)
    assert record.custody is None


def test_get_governance_locks_requires_strict_nullable_custody() -> None:
    missing = _governance_locks_payload("1")
    del missing["locks"][CANONICAL_OWNER]["custody"]
    session = RecordingSession()
    session.queue(StubResponse(payload=missing))
    with pytest.raises(RuntimeError, match="custody"):
        ToriiClient("http://node.test", session=session).get_governance_locks(
            "ref-1", canonical_auth=_governance_auth()
        )

    extra = _governance_locks_payload("1")
    extra["locks"][CANONICAL_OWNER]["custody"]["legacy"] = True
    session = RecordingSession()
    session.queue(StubResponse(payload=extra))
    with pytest.raises(RuntimeError, match="exactly"):
        ToriiClient("http://node.test", session=session).get_governance_locks(
            "ref-1", canonical_auth=_governance_auth()
        )

    incomplete = _governance_locks_payload("1")
    del incomplete["locks"][CANONICAL_OWNER]["custody"]["bond_escrow_account"]
    session = RecordingSession()
    session.queue(StubResponse(payload=incomplete))
    with pytest.raises(RuntimeError, match="exactly"):
        ToriiClient("http://node.test", session=session).get_governance_locks(
            "ref-1", canonical_auth=_governance_auth()
        )

    wrong = _governance_locks_payload("1")
    wrong["locks"][CANONICAL_OWNER]["custody"]["escrowed"] = 1
    session = RecordingSession()
    session.queue(StubResponse(payload=wrong))
    with pytest.raises(RuntimeError, match="escrowed"):
        ToriiClient("http://node.test", session=session).get_governance_locks(
            "ref-1", canonical_auth=_governance_auth()
        )

    padded = _governance_locks_payload("1")
    padded["locks"][CANONICAL_OWNER]["custody"]["asset_definition_id"] = (
        "xor#wonderland "
    )
    session = RecordingSession()
    session.queue(StubResponse(payload=padded))
    with pytest.raises(RuntimeError, match="whitespace"):
        ToriiClient("http://node.test", session=session).get_governance_locks(
            "ref-1", canonical_auth=_governance_auth()
        )


@pytest.mark.parametrize(
    "amount",
    [1, 1.5, "+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", "9" * 155],
)
def test_get_governance_locks_rejects_noncanonical_quantity(amount: Any) -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload=_governance_locks_payload(amount)))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="quantity|Quantity"):
        client.get_governance_locks("ref-1", canonical_auth=_governance_auth())


@pytest.mark.parametrize(
    "slashed",
    [1, 1.5, "+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", "9" * 155],
)
def test_get_governance_locks_rejects_noncanonical_slashed_quantity(
    slashed: Any,
) -> None:
    payload = _governance_locks_payload("1")
    payload["locks"][CANONICAL_OWNER]["slashed"] = slashed
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="quantity"):
        client.get_governance_locks("ref-1", canonical_auth=_governance_auth())


def test_propose_contract_deploy_uses_canonical_first_release_contract() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "proposal_id": "11" * 32,
                "tx_instructions": [
                    {
"wire_id": "iroha.instruction.v1::governance::ProposeDeployContract",
                        "payload_hex": "00ff",
                    }
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.propose_contract_deploy(
        canonical_auth=_governance_auth(),
        contract_alias="router::universal",
        abi_version=1,
        code_hash="22" * 32,
        abi_hash="33" * 32,
        manifest_provenance={"signer": "ed25519:public", "signature": "signature"},
    )

    assert result.proposal_id == "11" * 32
    assert len(result.tx_instructions) == 1
    assert not hasattr(result, "ok")
    request = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert request == {
        "contract_alias": "router::universal",
        "abi_version": 1,
        "code_hash": "22" * 32,
        "abi_hash": "33" * 32,
        "manifest_provenance": {
            "signer": "ed25519:public",
            "signature": "signature",
        },
    }


def test_propose_contract_deploy_has_no_retired_lifecycle_parameters() -> None:
    client = ToriiClient("http://node.test", session=RecordingSession())
    base = {
        "canonical_auth": _governance_auth(),
        "contract_alias": "router::universal",
        "abi_version": 1,
        "code_hash": "22" * 32,
        "abi_hash": "33" * 32,
    }

    for field, value in (("window", (1, 2)), ("mode", "Zk"), ("limits", {})):
        with pytest.raises(TypeError, match="unexpected keyword"):
            client.propose_contract_deploy(**base, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("abi_version", "1"),
        ("abi_version", 2),
        ("code_hash", "AA" * 32),
        ("code_hash", "0x" + "22" * 32),
        ("abi_hash", "33" * 31),
    ],
)
def test_propose_contract_deploy_rejects_noncanonical_typed_fields(
    field: str, value: Any
) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)
    request = {
        "canonical_auth": _governance_auth(),
        "contract_alias": "router::universal",
        "abi_version": 1,
        "code_hash": "22" * 32,
        "abi_hash": "33" * 32,
    }
    request[field] = value

    with pytest.raises(ValueError):
        client.propose_contract_deploy(**request)

    assert session.calls == []


@pytest.mark.parametrize("payload_hex", ["", "0", "0x00", "AA", "0A", "gg"])
def test_propose_contract_deploy_rejects_noncanonical_instruction_payload(
    payload_hex: str,
) -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "proposal_id": "11" * 32,
                "tx_instructions": [
                    {
                        "wire_id": "iroha.instruction.v1::governance::ProposeDeployContract",
                        "payload_hex": payload_hex,
                    }
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="lowercase even-length hex"):
        client.propose_contract_deploy(
            canonical_auth=_governance_auth(),
            contract_alias="router::universal",
            abi_version=1,
            code_hash="22" * 32,
            abi_hash="33" * 32,
        )


def test_list_telemetry_peers_info_parses_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload=[
                {
                    "url": "https://peer-1.example",
                    "connected": True,
                    "telemetry_unsupported": False,
                    "config": {
                        "public_key": "ed011122",
                        "queue_capacity": 8,
                        "network_block_gossip_size": 32,
                        "network_block_gossip_period": {"ms": 150},
                        "network_tx_gossip_size": 16,
                        "network_tx_gossip_period": {"ms": 50},
                    },
                    "location": {"lat": 35.0, "lon": 139.7, "country": "JP", "city": "Tokyo"},
                    "connected_peers": ["peer-A", "peer-B"],
                }
            ]
        )
    )
    client = ToriiClient("http://node.test", session=session)
    peers = client.list_telemetry_peers_info()

    assert len(peers) == 1
    peer = peers[0]
    assert peer.url == "https://peer-1.example"
    assert peer.connected is True
    assert peer.telemetry_unsupported is False
    assert peer.config is not None
    assert peer.config.queue_capacity == 8
    assert peer.config.network_block_gossip_period_ms == 150
    assert peer.location is not None
    assert peer.location.country == "JP"
    assert peer.connected_peers == ["peer-A", "peer-B"]
    assert session.calls[0]["headers"] == {"Accept": "application/json"}


def test_list_telemetry_peers_info_rejects_non_list_payload() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"not": "a list"}))
    client = ToriiClient("http://node.test", session=session)

    try:
        client.list_telemetry_peers_info()
    except RuntimeError as exc:
        assert "/v1/telemetry/peers-info response must be a list" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for invalid telemetry response")


def test_list_telemetry_peers_info_rejects_camelcase_config_fields() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload=[
                {
                    "url": "https://peer-2.example",
                    "connected": True,
                    "telemetry_unsupported": False,
                    "config": {
                        "publicKey": "ed011122",
                    },
                }
            ]
        )
    )
    client = ToriiClient("http://node.test", session=session)

    try:
        client.list_telemetry_peers_info()
    except RuntimeError as exc:
        assert "missing `public_key`" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for camelCase telemetry config")


def test_get_health_status_returns_plain_text() -> None:
    session = RecordingSession()
    session.queue(StubResponse(text="Healthy"))
    client = ToriiClient("http://node.test", session=session)

    assert client.get_health_status() == "Healthy"
    assert session.calls[0]["url"].endswith("/v1/health")
    assert session.calls[0]["method"] == "GET"


def test_runtime_manifest_rejects_alias_fields() -> None:
    try:
        ToriiClient._normalize_runtime_manifest_payload(
            {
                "name": "upgrade-1",
                "description": "First upgrade",
                "abiVersion": 1,
                "abi_hash": "0" * 64,
                "start_height": 1,
                "end_height": 2,
            },
            context="runtime upgrade manifest",
        )
    except RuntimeError as exc:
        assert "abi_version is required" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for alias manifest fields")


def test_runtime_manifest_rejects_non_v1_abi_version() -> None:
    with pytest.raises(RuntimeError, match="abi_version must be 1"):
        ToriiClient._normalize_runtime_manifest_payload(
            {
                "name": "upgrade-1",
                "description": "First upgrade",
                "abi_version": 2,
                "abi_hash": "0" * 64,
                "start_height": 1,
                "end_height": 2,
            },
            context="runtime upgrade manifest",
        )


def test_runtime_manifest_rejects_non_empty_added_surfaces() -> None:
    with pytest.raises(RuntimeError, match="added_syscalls must be empty"):
        ToriiClient._normalize_runtime_manifest_payload(
            {
                "name": "upgrade-1",
                "description": "First upgrade",
                "abi_version": 1,
                "abi_hash": "0" * 64,
                "added_syscalls": [512],
                "start_height": 1,
                "end_height": 2,
            },
            context="runtime upgrade manifest",
        )


def test_get_node_version_returns_string() -> None:
    session = RecordingSession()
    session.queue(StubResponse(text="2.1.0-dev"))
    client = ToriiClient("http://node.test", session=session)

    assert client.get_node_version() == "2.1.0-dev"
    assert session.calls[0]["url"].endswith("/v1/version")
    assert session.calls[0]["method"] == "GET"


def test_get_time_now_parses_snapshot() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "now": 1_700_000,
                "offset_ms": -4,
                "confidence_ms": 9,
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    snapshot = client.get_time_now()

    assert isinstance(snapshot, NetworkTimeSnapshot)
    assert snapshot.now_ms == 1_700_000
    assert snapshot.offset_ms == -4
    assert snapshot.confidence_ms == 9
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/v1/time/now")
    assert call["headers"]["Accept"] == "application/json"


def test_get_time_status_parses_histogram_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "peers": 3,
                "samples": [
                    {"peer": "peer-1", "last_offset_ms": -2, "last_rtt_ms": 7, "count": 5}
                ],
                "rtt": {
                    "buckets": [
                        {"le": 5, "count": 10},
                        {"count": 2},
                    ],
                    "sum_ms": 42,
                    "count": 12,
                },
                "note": "ok",
            }
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    status = client.get_time_status()

    assert isinstance(status, NetworkTimeStatus)
    assert status.peers == 3
    assert len(status.samples) == 1
    sample = status.samples[0]
    assert sample.peer == "peer-1"
    assert sample.last_offset_ms == -2
    assert sample.last_rtt_ms == 7
    assert sample.count == 5
    assert len(status.rtt_buckets) == 2
    first_bucket, second_bucket = status.rtt_buckets
    assert first_bucket.upper_bound_ms == 5
    assert first_bucket.count == 10
    assert second_bucket.upper_bound_ms is None
    assert second_bucket.count == 2
    assert status.rtt_sum_ms == 42
    assert status.rtt_count == 12
    assert status.note == "ok"
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/v1/time/status")
    assert call["headers"]["Accept"] == "application/json"


def test_get_explorer_account_qr_parses_payload_and_params() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "canonical_id": CANONICAL_OWNER,
                "literal": CANONICAL_OWNER,
                "network_prefix": 26,
                "error_correction": "quartile",
                "modules": 33,
                "qr_version": 5,
                "svg": "<svg></svg>",
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    qr = client.get_explorer_account_qr(CANONICAL_OWNER)

    assert qr == ExplorerAccountQr(
        canonical_id=CANONICAL_OWNER,
        literal=CANONICAL_OWNER,
        network_prefix=26,
        error_correction="quartile",
        modules=33,
        qr_version=5,
        svg="<svg></svg>",
    )
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith(f"/v1/explorer/accounts/{quote(CANONICAL_OWNER, safe='')}/qr")
    assert call["params"] == {}
    assert call["headers"]["Accept"] == "application/json"
    assert all(not name.lower().startswith("x-iroha-") for name in call["headers"])


def test_get_explorer_account_qr_optionally_signs_exact_final_path() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "canonical_id": CANONICAL_OWNER,
                "literal": CANONICAL_OWNER,
                "network_prefix": 26,
                "error_correction": "quartile",
                "modules": 33,
                "qr_version": 5,
                "svg": "<svg></svg>",
            }
        )
    )
    captured: List[bytes] = []
    auth = _governance_auth(captured)
    client = ToriiClient("https://node.test", session=session)

    qr = client.get_explorer_account_qr(CANONICAL_OWNER, canonical_auth=auth)

    exact_path = f"/v1/explorer/accounts/{quote(CANONICAL_OWNER, safe='')}/qr"
    assert qr.canonical_id == CANONICAL_OWNER
    assert captured == [
        canonical_network_request_signature_message(
            auth.network_id,
            "GET",
            exact_path,
            b"",
            timestamp_ms=auth.timestamp_ms or 0,
            nonce=auth.nonce or "",
        )
    ]
    call = session.calls[0]
    assert call["url"].endswith(exact_path)
    assert call["allow_redirects"] is False
    assert "X-Iroha-Account" in call["headers"]
    assert "X-Iroha-Signature" in call["headers"]


def test_get_explorer_account_qr_accepts_account_alias_path_literal() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "canonical_id": CANONICAL_OWNER,
                "literal": "operator@banka.universal",
                "network_prefix": 26,
                "error_correction": "quartile",
                "modules": 33,
                "qr_version": 5,
                "svg": "<svg></svg>",
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    qr = client.get_explorer_account_qr("operator@banka.universal")

    assert qr.literal == "operator@banka.universal"
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/v1/explorer/accounts/operator%40banka.universal/qr")
    assert call["params"] == {}


def test_get_explorer_account_qr_normalizes_payload_variants() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "canonicalId": "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
                "literal": "sorabobacct",
                "networkPrefix": 27,
                "errorCorrection": "medium",
                "modules": 41,
                "qrVersion": 7,
                "svg": "<svg/>",
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    qr = client.get_explorer_account_qr("sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE")

    assert qr == ExplorerAccountQr(
        canonical_id="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
        literal="sorabobacct",
        network_prefix=27,
        error_correction="medium",
        modules=41,
        qr_version=7,
        svg="<svg/>",
    )
    call = session.calls[0]
    assert call["params"] == {}
    assert call["headers"]["Accept"] == "application/json"


def test_get_node_capabilities_parses_snapshot() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "abi_version": 1,
                "data_model_version": 1,
                "crypto": {
                    "sm": {
                        "enabled": True,
                        "default_hash": "sm3",
                        "allowed_signing": ["sm2"],
                        "sm2_distid_default": "soranet",
                        "openssl_preview": False,
                        "acceleration": {
                            "scalar": True,
                            "neon_sm3": True,
                            "neon_sm4": False,
                            "policy": "scalar",
                        },
                    },
                    "curves": {
                        "registry_version": 2,
                        "allowed_curve_ids": [1, 15],
                        "allowed_curve_bitmap": [32770],
                    },
                },
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    capabilities = client.get_node_capabilities(canonical_auth=_governance_auth())

    assert capabilities.abi_version == 1
    assert capabilities.data_model_version == 1
    assert capabilities.crypto.sm.allowed_signing == ["sm2"]
    assert capabilities.crypto.sm.acceleration.neon_sm3 is True
    assert capabilities.crypto.curves.registry_version == 2
    assert capabilities.crypto.curves.allowed_curve_bitmap == [32770]


def test_contract_helpers_against_mock_server() -> None:
    server = ToriiMockServer().start()
    contract_address = _CONTRACT_ADDRESS
    call_payload = {"value": 1}
    try:
        response = requests.post(
            f"{server.base_url.rstrip('/')}/__mock__/gov/config",
            json={
                "gov_contracts": {
                    contract_address: {
                        "found": True,
                        "contract_subject_account": CANONICAL_OWNER,
                        "dataspace": "universal",
                        "active": True,
                        "lifecycle": {
                            "version": 1,
                            "origin": "direct",
                            "origin_account": CANONICAL_OWNER,
                            "origin_proposal_content_id_hex": None,
                            "origin_governance_attempt_id_hex": None,
                            "owner": CANONICAL_OWNER,
                            "pending_owner": None,
                            "parliament_delegated": False,
                            "active_code_hash_hex": "22" * 32,
                            "revision": 1,
                            "emergency_hold": None,
                        },
                        "emergency_hold_active": False,
                        "code_hash_hex": "22" * 32,
                        "abi_hash_hex": "33" * 32,
                        "public_entrypoints": ["ping"],
                    }
                },
                "contract_call_response": _contract_call_draft(
                    contract_alias=None,
                    contract_address=contract_address,
                    fee_payment=_authority_fee_payment(5000),
                    payload=call_payload,
                ),
            },
            timeout=5.0,
        )
        response.raise_for_status()

        client = ToriiClient(
            server.base_url,
            local_signing_context=_local_signing_context(),
        )
        call = client.prepare_contract_call(
            canonical_auth=_contract_auth(),
            authority=CANONICAL_OWNER,
            contract_address=contract_address,
            entrypoint="ping",
            payload=call_payload,
            fee_payment=_authority_fee_payment(5000),
            draft_intent=_contract_draft_intent(payload=call_payload),
        )
        governed = client.get_governance_contract(
            contract_address, canonical_auth=_governance_auth()
        )

        assert call.contract_address == contract_address
        assert governed.contract_address == contract_address
        assert governed.code_hash_hex == "22" * 32
    finally:
        server.stop()


def test_mock_server_advertises_current_data_model_version() -> None:
    server = ToriiMockServer().start()
    try:
        response = requests.get(
            f"{server.base_url.rstrip('/')}/v1/node/capabilities",
            timeout=5.0,
        )
        response.raise_for_status()

        assert response.json()["data_model_version"] == 4
    finally:
        server.stop()


def test_mock_server_pipeline_receipt_keeps_explicit_signed_hash_slot() -> None:
    server = ToriiMockServer().start()
    try:
        base_url = server.base_url.rstrip("/")
        transaction_hash = "a" * 64
        config = requests.post(
            f"{base_url}/__mock__/pipeline/config",
            json={
                "hash": transaction_hash,
                "statuses": [{"kind": "Rejected"}],
            },
            timeout=5.0,
        )
        config.raise_for_status()
        response = requests.post(
            f"{base_url}/v1/pipeline/transactions",
            data=b"signed-transaction",
            timeout=5.0,
        )
        response.raise_for_status()

        payload = response.json()["payload"]
        assert payload["entrypoint_hash"] == transaction_hash
        assert "signed_transaction_hash" in payload
        assert payload["signed_transaction_hash"] is None

        status = requests.get(
            f"{base_url}/v1/pipeline/transactions/status",
            params={"hash": transaction_hash},
            timeout=5.0,
        )
        status.raise_for_status()
        assert status.json() == {
            "hash": transaction_hash,
            "status": {"kind": "Rejected"},
            "scope": "global",
            "resolved_from": "state",
        }

        retired = requests.post(
            f"{base_url}/__mock__/pipeline/config",
            json={"statuses": [{"kind": "Rejected", "summary": "retired"}]},
            timeout=5.0,
        )
        assert retired.status_code == 400
    finally:
        server.stop()


def test_mock_server_seeds_sumeragi_status_snapshot() -> None:
    server = ToriiMockServer().start()
    try:
        response = requests.get(f"{server.base_url.rstrip('/')}/v1/sumeragi/status", timeout=5.0)
        response.raise_for_status()

        payload = response.json()

        assert payload["protocol_version"] == 1
        assert payload["leader"] is None
        assert payload["height"] == 10
        assert payload["view"] == 2
        assert payload["footprint"]["pending_apply"] == 0
        assert "lane_settlement_commitments" not in payload

        diagnostics = requests.get(
            f"{server.base_url.rstrip('/')}/v1/sumeragi/diagnostics", timeout=5.0
        )
        assert diagnostics.status_code == 404
    finally:
        server.stop()


def test_mock_server_allows_sumeragi_fixture_override() -> None:
    server = ToriiMockServer().start()
    try:
        base_url = server.base_url.rstrip("/")
        fixtures = {
            "status": {"protocol_version": 1, "height": 42},
        }
        response = requests.post(
            f"{base_url}/__mock__/sumeragi/config",
            json=fixtures,
            timeout=5.0,
        )
        response.raise_for_status()

        for endpoint, expected in fixtures.items():
            response = requests.get(f"{base_url}/v1/sumeragi/{endpoint}", timeout=5.0)
            response.raise_for_status()
            assert response.json() == expected

        response = requests.post(
            f"{base_url}/__mock__/sumeragi/config",
            json={"telemetry": {"availability": {"total_votes_ingested": 7}}},
            timeout=5.0,
        )
        assert response.status_code == 400
        response = requests.get(f"{base_url}/v1/sumeragi/telemetry", timeout=5.0)
        assert response.status_code == 404

        response = requests.post(
            f"{base_url}/__mock__/sumeragi/config",
            json={"status": {"height": 99}, "leader": []},
            timeout=5.0,
        )
        assert response.status_code == 400
        response = requests.get(f"{base_url}/v1/sumeragi/status", timeout=5.0)
        response.raise_for_status()
        assert response.json() == fixtures["status"]
    finally:
        server.stop()






























































































@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("GET", "/v1/sumeragi/rbc"),
        ("GET", "/v1/sumeragi/rbc/delivered/1/0"),
        ("GET", "/v1/sumeragi/rbc/sessions"),
        ("POST", "/v1/sumeragi/rbc/sample"),
        ("GET", "/v1/sumeragi/collectors"),
        ("GET", "/v1/sumeragi/leader"),
    ),
)
def test_mock_server_rejects_retired_global_sumeragi_routes(method: str, path: str) -> None:
    server = ToriiMockServer().start()
    try:
        response = requests.request(
            method,
            f"{server.base_url.rstrip('/')}{path}",
            json={} if method == "POST" else None,
            timeout=5.0,
        )

        assert response.status_code == 404
    finally:
        server.stop()


def test_get_runtime_abi_active_parses_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "abi_version": 1,
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    snapshot = client.get_runtime_abi_active(canonical_auth=_governance_auth())

    assert snapshot.abi_version == 1


def test_get_runtime_abi_hash_parses_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "policy": "V1",
                "abi_hash_hex": "aa" * 32,
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.get_runtime_abi_hash()

    assert result.policy == "V1"
    assert result.abi_hash_hex == "aa" * 32


def test_get_runtime_metrics_parses_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "abi_version": 1,
                "upgrade_events_total": {"proposed": 5, "activated": 3, "canceled": 1},
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    metrics = client.get_runtime_metrics(canonical_auth=_governance_auth())

    assert metrics.abi_version == 1
    assert metrics.upgrade_events_total.proposed == 5
    assert metrics.upgrade_events_total.activated == 3
    assert metrics.upgrade_events_total.canceled == 1


def test_list_runtime_upgrades_parses_records() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {
                        "id_hex": "aa" * 32,
                        "record": {
                            "manifest": {
                                "name": "ABI v1 refresh",
                                "description": "scheduled rollout",
                                "abi_version": 1,
                                "abi_hash": "11" * 32,
                                "added_syscalls": [],
                                "added_pointer_types": [],
                                "start_height": 10,
                                "end_height": 20,
                            },
                            "status": {"ActivatedAt": 12},
                            "proposer": CANONICAL_OWNER,
                            "created_height": 8,
                        },
                    },
                    {
                        "id_hex": "bb" * 32,
                        "record": {
                            "manifest": {
                                "name": "ABI v1 maintenance",
                                "description": "next window",
                                "abi_version": 1,
                                "abi_hash": "22" * 32,
                                "added_syscalls": [],
                                "added_pointer_types": [],
                                "start_height": 30,
                                "end_height": 40,
                            },
                            "status": {"Proposed": None},
                            "proposer": "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
                            "created_height": 25,
                        },
                    },
                ]
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    upgrades = client.list_runtime_upgrades()

    assert len(upgrades) == 2
    assert upgrades[0].record.status.kind == "ActivatedAt"
    assert upgrades[0].record.status.activated_height == 12
    assert upgrades[1].record.status.kind == "Proposed"


def test_propose_runtime_upgrade_posts_manifest() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "ok": True,
                "tx_instructions": [{"wire_id": "ProposeRuntimeUpgrade", "payload_hex": "aa" * 32}],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.propose_runtime_upgrade(
        {
            "name": "ABI v1 maintenance",
            "description": "roll out refreshed binaries",
            "abi_version": 1,
            "abi_hash": "ff" * 32,
            "start_height": 50,
            "end_height": 60,
            "added_syscalls": [],
            "added_pointer_types": [],
        }
    )

    assert result.ok is True
    assert result.tx_instructions[0].wire_id == "ProposeRuntimeUpgrade"
    assert session.calls[0]["url"].endswith("/v1/runtime/upgrades/propose")
    body = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert body["abi_version"] == 1
    assert body["abi_hash"] == "ff" * 32


def test_activate_runtime_upgrade_posts_identifier() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "ok": True,
                "tx_instructions": [{"wire_id": "ActivateRuntimeUpgrade", "payload_hex": "cc" * 32}],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    response = client.activate_runtime_upgrade("0x" + "bb" * 32)

    assert response.tx_instructions[0].wire_id == "ActivateRuntimeUpgrade"
    assert session.calls[0]["url"].endswith("/v1/runtime/upgrades/activate/0x" + "bb" * 32)


def test_cancel_runtime_upgrade_posts_identifier() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "ok": True,
                "tx_instructions": [{"wire_id": "CancelRuntimeUpgrade", "payload_hex": "dd" * 32}],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    response = client.cancel_runtime_upgrade("aa" * 32)

    assert response.tx_instructions[0].wire_id == "CancelRuntimeUpgrade"
    assert session.calls[0]["url"].endswith("/v1/runtime/upgrades/cancel/0x" + "aa" * 32)


def test_get_uaid_portfolio_parses_payload() -> None:
    uaid_literal = "uaid:" + "ab" * 32
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "uaid": uaid_literal,
                "totals": {"accounts": 2, "positions": 3},
                "dataspaces": [
                    {
                        "dataspace_id": 7,
                        "dataspace_alias": "treasury",
                        "accounts": [
                            {
                                "account_id": CANONICAL_OWNER,
                                "label": "primary",
                                "assets": [
                                    {
                                        "asset_id": CANONICAL_ASSET_ID,
                                        "asset_definition_id": CANONICAL_ASSET_ID.split("#", 1)[0],
                                        "quantity": "42",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    response = client.get_uaid_portfolio(uaid_literal)

    assert response.uaid == uaid_literal
    assert response.totals.accounts == 2
    assert response.dataspaces[0].accounts[0].assets[0].quantity == "42"
    expected_suffix = "/v1/accounts/uaid%3A" + "ab" * 32 + "/portfolio"
    assert session.calls[0]["url"].endswith(expected_suffix)


def test_get_uaid_portfolio_rejects_noncanonical_literal_before_dispatch() -> None:
    uaid_hex = "ab" * 32
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    for literal in [
        uaid_hex,
        f"UAID:{uaid_hex}",
        f"uaid:{uaid_hex.upper()}",
        f" uaid:{uaid_hex}",
        f"uaid:{uaid_hex} ",
        f"uaid: {uaid_hex}",
    ]:
        with pytest.raises(ValueError, match="exact canonical uaid"):
            client.get_uaid_portfolio(literal)

    assert session.calls == []


def test_get_uaid_portfolio_encodes_asset_id_filter() -> None:
    uaid_literal = "uaid:" + "ab" * 32
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "uaid": uaid_literal,
                "totals": {"accounts": 0, "positions": 0},
                "dataspaces": [],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    client.get_uaid_portfolio(uaid_literal, asset_id=CANONICAL_ASSET_ID)

    assert session.calls[0]["params"]["asset_id"] == CANONICAL_ASSET_ID


def test_get_uaid_portfolio_rejects_padded_asset_id_before_dispatch() -> None:
    uaid_literal = "uaid:" + "ab" * 32
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(ValueError, match="uaid portfolio asset_id must not contain surrounding whitespace"):
        client.get_uaid_portfolio(uaid_literal, asset_id=f" {CANONICAL_ASSET_ID}")

    with pytest.raises(ValueError, match="uaid portfolio asset_id must not contain surrounding whitespace"):
        client.get_uaid_portfolio(uaid_literal, asset_id=f"{CANONICAL_ASSET_ID} ")

    assert session.calls == []


def test_get_uaid_portfolio_rejects_invalid_lsb() -> None:
    client = ToriiClient("http://node.test", session=RecordingSession())
    invalid = "uaid:" + "10" * 32
    with pytest.raises(RuntimeError, match="least significant bit"):
        client.get_uaid_portfolio(invalid)


def test_get_uaid_bindings_fetches_dataspace_accounts() -> None:
    uaid_literal = "uaid:" + "bb" * 32
    second_account = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE"
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "uaid": uaid_literal,
                "dataspaces": [
                    {
                        "dataspace_id": 9,
                        "dataspace_alias": "alpha",
                        "accounts": [
                            "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
                            second_account,
                        ],
                    }
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    bindings = client.get_uaid_bindings(uaid_literal)

    assert bindings.dataspaces[0].accounts == [
        "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
        second_account,
    ]
    assert session.calls[0]["params"] == {}


def test_get_uaid_bindings_rejects_padded_account() -> None:
    uaid_literal = "uaid:" + "bb" * 32
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "uaid": uaid_literal,
                "dataspaces": [
                    {
                        "dataspace_id": 9,
                        "dataspace_alias": "alpha",
                        "accounts": [
                            " sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"
                        ],
                    }
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(ValueError, match="must not contain surrounding whitespace"):
        client.get_uaid_bindings(uaid_literal)


def _uaid_manifests_payload(uaid_literal: str) -> Dict[str, Any]:
    return {
        "total": 1,
        "next_cursor": None,
        "items": [
            {
                "dataspace_id": 5,
                "dataspace_alias": "lane-5",
                "manifest_hash": "dd" * 32,
                "status": "Active",
                "lifecycle": {
                    "activated_epoch": 12,
                    "expired_epoch": None,
                    "revocation": {"epoch": 44, "reason": "duplicate"},
                },
                "accounts": [
                    "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"
                ],
                "manifest": {
                    "version": 1,
                    "uaid": uaid_literal,
                    "dataspace": 5,
                    "issued_ms": 123,
                    "activation_epoch": 12,
                    "entries": [
                        {
                            "scope": {"dataspace": 5, "role": "Initiator"},
                            "effect": {"Allow": {"window": "PerSlot"}},
                            "notes": "demo",
                        }
                    ],
                },
            }
        ],
    }


def test_uaid_manifest_collection_rejects_record_for_another_uaid() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload=_uaid_manifests_payload("uaid:" + "cd" * 32)))
    client = ToriiClient("http://node.test", session=session)
    with pytest.raises(ValueError, match="requested UAID"):
        client.uaid_manifests("uaid:" + "ab" * 32).list()


def test_uaid_manifests_parses_payload_and_filters() -> None:
    uaid_literal = "uaid:" + "cd" * 32
    manifest_hash = "dd" * 32
    session = RecordingSession()
    session.queue(StubResponse(payload=_uaid_manifests_payload(uaid_literal)))
    client = ToriiClient("http://node.test", session=session)

    manifests = client.uaid_manifests(uaid_literal).list(
        filter='dataspace_id = 9 and status = "Active"', limit=25,
        cursor="prior-page", include_total=True,
    )
    assert len(manifests.items) == 1
    assert manifests.total == 1
    assert manifests.next_cursor is None
    record = manifests.items[0]
    assert record.manifest_hash == manifest_hash
    assert record.lifecycle.revocation is not None
    assert record.manifest.version == 1
    assert record.manifest.expiry_epoch is None
    assert record.manifest.entries[0].notes == "demo"
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"].endswith("/manifests/query")
    body = json.loads(call["data"])
    assert body["limit"] == 25
    assert body["cursor"] == "prior-page"
    assert body["include_total"] is True


@pytest.mark.parametrize("kwargs", [{"offset": 0}, {"count_mode": "exact"}, {"dataspace_id": 9}])
def test_uaid_manifests_reject_removed_params_before_dispatch(kwargs: Dict[str, Any]) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)
    with pytest.raises(TypeError):
        client.uaid_manifests("uaid:" + "cd" * 32).list(**kwargs)
    assert session.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.pop("next_cursor"),
        lambda payload: payload.__setitem__("legacy_total", 1),
        lambda payload: payload["items"][0]["manifest"].__setitem__("version", "1"),
        lambda payload: payload["items"][0]["manifest"].__setitem__(
            "expiry_epoch", None
        ),
        lambda payload: payload["items"][0]["manifest"]["entries"][0].__setitem__(
            "legacy_action", "allow"
        ),
    ],
    ids=[
        "missing-pagination-field",
        "unknown-root-field",
        "string-version",
        "null-optional-field",
        "unknown-entry-field",
    ],
)
def test_uaid_manifests_rejects_noncanonical_response_shapes(
    mutation: Callable[[Dict[str, Any]], Any],
) -> None:
    uaid_literal = "uaid:" + "cd" * 32
    payload = _uaid_manifests_payload(uaid_literal)
    mutation(payload)
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises((TypeError, ValueError, RuntimeError)):
        client.uaid_manifests(uaid_literal).list()


def test_get_configuration_returns_snapshot() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "public_key": "ed0123",
                "logger": {"level": "Info", "filter": None},
                "network": {
                    "block_gossip_size": 32,
                    "block_gossip_period_ms": 150,
                    "transaction_gossip_size": 16,
                    "transaction_gossip_period_ms": 75,
                },
                "queue": {"capacity": 1024},
                "confidential_gas": {
                    "proof_base": 10,
                    "per_public_input": 2,
                    "per_proof_byte": 3,
                    "per_nullifier": 4,
                    "per_commitment": 5,
                },
                "transport": {
                    "norito_rpc": {
                        "enabled": True,
                        "stage": "ga",
                        "require_mtls": True,
                        "canary_allowlist_size": 3,
                    },
                },
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    snapshot = client.get_configuration()

    assert snapshot.public_key_hex == "ed0123"
    assert snapshot.logger.level == "Info"
    assert snapshot.logger.filter is None
    assert snapshot.queue is not None and snapshot.queue.capacity == 1024
    assert snapshot.confidential_gas is not None
    assert snapshot.confidential_gas.per_nullifier == 4
    transport = snapshot.transport
    assert transport is not None
    assert transport.norito_rpc is not None
    assert transport.norito_rpc.stage == "ga"
    assert transport.norito_rpc.canary_allowlist_size == 3








@pytest.mark.parametrize(
    "field_name", ["lane_commitments", "dataspace_commitments", "pipeline_execution"]
)
@pytest.mark.parametrize("value", [None, [], [{"block_height": 10}]])
def test_status_rejects_retired_commitment_projections(field_name: str, value: object) -> None:
    payload = _status_payload(queue_size=0, approved=0, rejected=0, views=0)
    payload[field_name] = value
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))
    client = ToriiClient("http://node.test", session=session)
    with pytest.raises(RuntimeError, match=f"retired field `{field_name}`"):
        client.get_status_snapshot()


def test_get_status_snapshot_parses_payload_and_computes_metrics() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload=_status_payload(queue_size=4, approved=3, rejected=1, views=2)))
    session.queue(StubResponse(payload=_status_payload(queue_size=9, approved=5, rejected=2, views=5)))
    client = ToriiClient("http://node.test", session=session)

    first = client.get_status_snapshot()
    second = client.get_status_snapshot()

    assert [call["url"] for call in session.calls] == [
        "http://node.test/status",
        "http://node.test/status",
    ]
    assert first.status.queue_size == 4
    assert first.status.queue_queued == 2
    assert first.status.queue_inflight == 2
    assert first.metrics.time_since_last_non_empty_block_ms == 1_000
    assert first.status.is_queue_stalled(999) is True
    assert first.status.is_queue_stalled(1_000) is False
    assert first.metrics.queue_delta == 0
    assert first.metrics.has_activity is False
    assert first.status.dataspace_catalog[0].alias == "alpha"
    assert not hasattr(first.status, "lane_commitments")
    assert not hasattr(first.status, "dataspace_commitments")

    assert second.status.queue_size == 9
    assert second.metrics.queue_queued == 7
    assert second.metrics.queue_inflight == 2
    assert second.metrics.queue_delta == 5
    assert second.metrics.tx_approved_delta == 2
    assert second.metrics.tx_rejected_delta == 1
    assert second.metrics.view_change_delta == 3
    assert second.metrics.has_activity is True
    lane_gov = second.status.lane_governance[0]
    assert lane_gov.alias == "lane-alpha"
    assert lane_gov.runtime_upgrade is not None
    assert lane_gov.runtime_upgrade.allowed_ids == ["alpha"]
    activation = second.status.governance.recent_manifest_activations[0]
    assert second.status.governance.proposals.proposed == 1
    assert second.status.governance.proposals.rejected == 3
    assert second.status.governance.proposals.enacted == 4
    assert second.status.governance.proposals.superseded == 2
    assert second.status.governance.proposals.execution_failed == 1
    assert (
        activation.contract_address
        == "xorc1qyqqqqqqqqqqqq9a5v7f58jgm40m0w7esnqg2pxj68d3f8a2l9ja3s"
    )
    assert second.status.lane_governance_sealed_aliases == ["sealed-one"]
    assert second.status.require_dataspace("alpha").sealed is True
    assert second.status.require_dataspace(9).manifest_required is True
    assert "peers" in second.status.raw


def _status_payload(
    *,
    queue_size: int,
    approved: int,
    rejected: int,
    views: int,
) -> Dict[str, Any]:
    governance = {
        "proposals": {
            "proposed": 1,
            "rejected": 3,
            "enacted": 4,
            "superseded": 2,
            "execution_failed": 1,
        },
        "protected_namespace": {
            "total_checks": 4,
            "allowed": 3,
            "rejected": 1,
        },
        "manifest_admission": {
            "total_checks": 5,
            "allowed": 4,
            "missing_manifest": 1,
            "non_validator_authority": 0,
            "quorum_rejected": 0,
            "protected_namespace_rejected": 0,
            "runtime_hook_rejected": 0,
        },
        "manifest_quorum": {
            "total_checks": 3,
            "satisfied": 2,
            "rejected": 1,
        },
        "recent_manifest_activations": [
            {
                "contract_address": "xorc1qyqqqqqqqqqqqq9a5v7f58jgm40m0w7esnqg2pxj68d3f8a2l9ja3s",
                "code_hash_hex": "deadbeef",
                "abi_hash_hex": "cafebabe",
                "height": 42,
                "activated_at_ms": 1_111,
            }
        ],
    }
    lane_governance = [
        {
            "lane_id": 7,
            "alias": "lane-alpha",
            "dataspace_id": 9,
            "visibility": "public",
            "storage_profile": "balanced",
            "governance": None,
            "manifest_required": True,
            "manifest_ready": False,
            "manifest_path": None,
            "validator_ids": ["val#1"],
            "quorum": 1,
            "protected_namespaces": ["alpha"],
            "runtime_upgrade": {
                "allow": True,
                "require_metadata": True,
                "metadata_key": "manifest",
                "allowed_ids": ["alpha"],
            },
        }
    ]
    dataspace_catalog = [
        {
            "lane_id": 7,
            "lane_alias": "lane-alpha",
            "dataspace_id": 9,
            "alias": "alpha",
            "visibility": "restricted",
            "storage_profile": "balanced",
            "manifest_required": True,
            "manifest_ready": False,
            "sealed": True,
            "manifest_path": None,
            "protected_namespaces": ["alpha"],
        }
    ]
    return {
        "observed_at_ms": 10_000,
        "peers": 5,
        "queue_size": queue_size,
        "queue_queued": max(0, queue_size - 2),
        "queue_inflight": min(queue_size, 2),
        "last_block_committed_at_ms": 9_900,
        "last_non_empty_block_committed_at_ms": 9_000,
        "time_since_last_block_ms": 100,
        "time_since_last_non_empty_block_ms": 1_000,
        "commit_time_ms": 250,
        "txs_approved": approved,
        "txs_rejected": rejected,
        "view_changes": views,
        "governance": governance,
        "lane_governance": lane_governance,
        "dataspace_catalog": dataspace_catalog,
        "lane_governance_sealed_total": 1,
        "lane_governance_sealed_aliases": ["sealed-one"],
    }


def test_retired_global_sumeragi_rbc_and_collectors_surfaces_are_absent() -> None:
    retired_methods = (
        "get_sumeragi_rbc",
        "get_sumeragi_rbc_sessions",
        "get_sumeragi_rbc_delivered",
        "sample_rbc_chunks",
        "get_sumeragi_collectors",
        "get_sumeragi_leader",
    )
    for name in retired_methods:
        assert not hasattr(ToriiClient, name), name

    retired_models = (
        "SumeragiRbcSnapshot",
        "SumeragiRbcSession",
        "SumeragiRbcSessionsSnapshot",
        "SumeragiRbcDeliveryStatus",
        "SumeragiCollectorEntry",
        "SumeragiCollectorsSnapshot",
        "RbcSample",
        "RbcChunkSample",
        "RbcMerkleProof",
        "SumeragiLeaderSnapshot",
        "SumeragiPrfContext",
    )
    for name in retired_models:
        assert not hasattr(client_module, name), name
        assert name not in client_module.__all__, name
        assert not hasattr(torii_module, name), name
        assert name not in torii_module.__all__, name


def test_get_sumeragi_params_parses_the_served_snapshot() -> None:
    served = {"block_cadence_ms": 2000, "max_clock_drift_ms": 20, "chain_height": 777}
    session = RecordingSession()
    session.queue(StubResponse(payload=served))
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    params = client.get_sumeragi_params()

    assert (params.block_cadence_ms, params.max_clock_drift_ms, params.chain_height) == (2000, 20, 777)
    assert session.calls[0]["url"].endswith("/v1/sumeragi/params")

    for payload, message in [
        ({**served, "collectors_k": 3}, "unsupported fields: collectors_k"),
        ({"block_time_ms": 2000, "max_clock_drift_ms": 20, "chain_height": 777}, "block_time_ms"),
        ({"block_cadence_ms": 2000, "max_clock_drift_ms": 20}, "chain_height"),
        ({**served, "block_cadence_ms": 0}, "must be nonzero"),
        ({**served, "chain_height": -1}, "chain_height"),
    ]:
        session.queue(StubResponse(payload=payload))
        with pytest.raises(RuntimeError, match=message):
            client.get_sumeragi_params()


def test_get_sumeragi_bls_keys_parses_map() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "ed01": "ff00",
                "ed02": None,
            }
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    mapping = client.get_sumeragi_bls_keys()

    assert mapping["ed01"] == "ff00"
    assert mapping["ed02"] is None
    assert session.calls[0]["url"].endswith("/v1/sumeragi/bls-keys")


def test_get_sumeragi_evidence_count_returns_int() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"count": 42}))
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    count = client.get_sumeragi_evidence_count()

    assert count == 42
    assert session.calls[0]["url"].endswith("/v1/sumeragi/evidence/count")


def test_get_sumeragi_evidence_count_rejects_non_success_with_valid_body() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=503, payload={"count": 0}))
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    with pytest.raises(RuntimeError, match="unexpected status 503"):
        client.get_sumeragi_evidence_count()


@pytest.mark.parametrize("payload", [{}, {"count": 1, "total": 1}, {"count": "1"}])
def test_get_sumeragi_evidence_count_rejects_noncanonical_envelope(
    payload: Dict[str, Any],
) -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    with pytest.raises(RuntimeError):
        client.get_sumeragi_evidence_count()


def _sumeragi_native_evidence_record(
    *, evidence_class: str = "phase_vote", penalty_status: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    return {
        "kind": "NativeSumeragiEvidence",
        "value": {
            "scope": {"kind": "root", "value": None},
            "class": evidence_class,
            "height": 31,
            "epoch": 2,
            "context_id": "11" * 32,
            "instance": "22" * 32,
            "authority_generation": "33" * 32,
            "offenders": [{"signer": 3, "peer_id": "ea0130" + "22" * 48}],
            "safety_violation": False,
            "native_frame_hash": "44" * 32,
            "recorded_height": 40,
            "recorded_view": 2,
            "recorded_ms": 1_700_000_000_000,
            "consensus_admitted_height": 41,
            "penalty_status": penalty_status
            if penalty_status is not None
            else {"status": "pending", "details": None},
        },
    }


@pytest.mark.parametrize("evidence_class", ["proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates"])
def test_sumeragi_native_evidence_accepts_exact_classes(evidence_class: str) -> None:
    parsed = ToriiClient._parse_sumeragi_evidence_record(
        _sumeragi_native_evidence_record(evidence_class=evidence_class),
        context="evidence",
    )

    assert isinstance(parsed, client_module.SumeragiEvidenceRecord)
    assert parsed.value.class_ == evidence_class


@pytest.mark.parametrize(
    ("status", "status_type"),
    [
        ("applied", client_module.SumeragiEvidenceAppliedPenaltyStatus),
    ],
)
def test_sumeragi_evidence_accepts_committed_penalty_statuses(
    status: str, status_type: type
) -> None:
    parsed = ToriiClient._parse_sumeragi_evidence_record(
        _sumeragi_native_evidence_record(
            penalty_status={"status": status, "details": {"height": 44}}
        ),
        context="evidence",
    )

    assert isinstance(parsed.value.penalty_status, status_type)
    assert parsed.value.penalty_status.details.height == 44


def test_sumeragi_evidence_rejects_unknown_record_kind() -> None:
    record = _sumeragi_native_evidence_record()
    record["kind"] = "DoublePrepare"

    with pytest.raises(RuntimeError, match=r"kind must be NativeSumeragiEvidence"):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")


@pytest.mark.parametrize(
    "payload",
    [
        {"items": []},
        {"total": 0},
        {"total": 0, "items": [], "cursor": None},
        {"total": "0", "items": []},
    ],
)
def test_sumeragi_evidence_page_rejects_noncanonical_envelope(
    payload: Dict[str, Any],
) -> None:
    with pytest.raises(RuntimeError):
        ToriiClient._parse_sumeragi_evidence_page(payload, context="evidence")


def test_sumeragi_evidence_page_rejects_impossible_or_oversized_results() -> None:
    record = _sumeragi_native_evidence_record()
    with pytest.raises(RuntimeError, match="at most 50"):
        ToriiClient._parse_sumeragi_evidence_page(
            {"total": 51, "items": [record] * 51},
            context="evidence",
        )
    with pytest.raises(RuntimeError, match="cover offset"):
        ToriiClient._parse_sumeragi_evidence_page(
            {"total": 1, "items": [record]},
            context="evidence",
            offset=1,
        )


def test_sumeragi_evidence_page_accepts_empty_page_beyond_total() -> None:
    page = ToriiClient._parse_sumeragi_evidence_page(
        {"total": 1, "items": []},
        context="evidence",
        offset=10,
    )

    assert page.total == 1
    assert page.items == []


def test_sumeragi_evidence_rejects_retired_fields() -> None:
    record = _sumeragi_native_evidence_record()
    record["value"]["penalty_applied"] = False

    with pytest.raises(RuntimeError, match=r"unexpected penalty_applied"):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("class", "Prepare", r"class must be one of"),
        ("offender_signer", "3", r"signer must increase strictly"),
        ("offender_signer", True, r"signer must increase strictly"),
        ("offender_signer", 1024, r"signer must increase strictly"),
        ("context_id", "AA" * 32, r"exact lowercase 32-byte hex"),
        ("native_frame_hash", "AA" * 32, r"exact lowercase 32-byte hex"),
        ("safety_violation", 1, r"must be a boolean"),
        ("offenders", [], r"between 1 and 1024"),
    ],
)
def test_sumeragi_native_evidence_rejects_noncanonical_fields(
    field: str, value: Any, match: str
) -> None:
    record = _sumeragi_native_evidence_record()
    if field == "offender_signer":
        record["value"]["offenders"][0]["signer"] = value
    else:
        record["value"][field] = value

    with pytest.raises(RuntimeError, match=match):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")


@pytest.mark.parametrize(("field", "match"), [(field, f"missing {field}") for field in _sumeragi_native_evidence_record()["value"]])
def test_sumeragi_native_evidence_rejects_missing_fields(
    field: str, match: str
) -> None:
    record = _sumeragi_native_evidence_record()
    del record["value"][field]

    with pytest.raises(RuntimeError, match=match):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")


@pytest.mark.parametrize(
    ("penalty_status", "match"),
    [
        ({"status": "pending", "details": {}}, r"details must be null"),
        ({"status": "applied", "details": None}, r"must be a JSON object"),
        (
            {"status": "applied", "details": {"height": 4, "note": "x"}},
            r"must contain exactly height",
        ),
        ({"status": "retired", "details": None}, r"must be pending or applied"),
    ],
)
def test_sumeragi_evidence_rejects_invalid_penalty_status(
    penalty_status: Dict[str, Any], match: str
) -> None:
    record = _sumeragi_native_evidence_record(penalty_status=penalty_status)

    with pytest.raises(RuntimeError, match=match):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")


def test_list_sumeragi_evidence_validates_limit() -> None:
    client = ToriiClient("http://node.test")

    try:
        client.list_sumeragi_evidence(limit=2000)
    except RuntimeError as exc:
        assert "limit must be in 1..=1000" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for oversized limit")


def test_list_sumeragi_evidence_validates_offset_and_kind() -> None:
    client = ToriiClient("http://node.test")

    with pytest.raises(RuntimeError, match="offset must be in 0..=10000"):
        client.list_sumeragi_evidence(offset=10_001)
    with pytest.raises(RuntimeError, match="kind must be NativeSumeragiEvidence"):
        client.list_sumeragi_evidence(kind="DoublePrepare")
    with pytest.raises(RuntimeError, match="limit must be an integer"):
        client.list_sumeragi_evidence(limit="1")
    with pytest.raises(RuntimeError, match="offset must be an integer"):
        client.list_sumeragi_evidence(offset=True)


def test_confidential_gas_schedule_has_no_runtime_setter() -> None:
    assert not hasattr(ToriiClient, "set_confidential_gas_schedule")


def test_get_time_now_parses_snapshot_alt_values() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "now": 123456789,
                "offset_ms": -5,
                "confidence_ms": 42,
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    snapshot = client.get_time_now()

    assert snapshot.now_ms == 123456789
    assert snapshot.offset_ms == -5
    assert snapshot.confidence_ms == 42


def test_get_time_status_parses_diagnostics() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "peers": 2,
                "samples": [
                    {"peer": "peer-a", "last_offset_ms": 1, "last_rtt_ms": 10, "count": 5},
                    {"peer": "peer-b", "last_offset_ms": -2, "last_rtt_ms": 15, "count": 7},
                ],
                "rtt": {
                    "buckets": [{"le": 25, "count": 3}, {"le": 50, "count": 4}],
                    "sum_ms": 28,
                    "count": 9,
                },
                "note": "NTS running",
            }
        )
    )
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    status = client.get_time_status()

    assert status.peers == 2
    assert len(status.samples) == 2
    assert status.samples[0].peer == "peer-a"
    assert status.rtt_buckets[1].upper_bound_ms == 50
    assert status.rtt_sum_ms == 28
    assert status.note == "NTS running"


def test_connect_app_registry_and_policy_helpers() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {
                        "app_id": "demo.wallet",
                        "display_name": "Demo Wallet",
                        "namespaces": ["wallets"],
                        "metadata": {"category": "wallet"},
                        "policy": {"relay_enabled": True},
                    }
                ],
                "total": 1,
                "next_cursor": "cursor-1",
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "policy": {
                    "relay_enabled": False,
                    "ws_max_sessions": 16,
                    "heartbeat_interval_ms": 15000,
                }
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "policy": {
                    "relay_enabled": True,
                    "heartbeat_interval_ms": 12000,
                }
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    page = client.list_connect_apps(limit=5, cursor="start")
    assert page.total == 1
    assert page.items[0].app_id == "demo.wallet"
    assert page.next_cursor == "cursor-1"

    policy = client.get_connect_app_policy()
    assert policy.relay_enabled is False
    assert policy.heartbeat_interval_ms == 15000

    updated = client.update_connect_app_policy({"relay_enabled": True, "heartbeat_interval_ms": 12000})
    assert updated.relay_enabled is True
    assert updated.heartbeat_interval_ms == 12000
    assert json.loads(session.calls[2]["data"]) == {
        "relay_enabled": True,
        "heartbeat_interval_ms": 12000,
    }


def test_iterate_connect_apps_pages_and_limit() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {"app_id": "demo.wallet", "namespaces": [], "metadata": {}, "policy": {}},
                    {"app_id": "demo.market", "namespaces": [], "metadata": {}, "policy": {}},
                ],
                "next_cursor": "c2",
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {"app_id": "demo.bridge", "namespaces": [], "metadata": {}, "policy": {}},
                ],
                "next_cursor": None,
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    apps = list(client.iterate_connect_apps(limit=2))

    assert [app.app_id for app in apps] == ["demo.wallet", "demo.market"]
    # Only the first page is fetched because limit was satisfied.
    assert len(session.calls) == 1
    assert session.calls[0]["params"]["limit"] == 2


def test_iterate_connect_apps_consumes_all_pages_when_unbounded() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {"app_id": "app-1", "namespaces": [], "metadata": {}, "policy": {}},
                ],
                "next_cursor": "c2",
            }
        )
    )
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {"app_id": "app-2", "namespaces": [], "metadata": {}, "policy": {}},
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    apps = list(client.iterate_connect_apps(page_size=1))

    assert [app.app_id for app in apps] == ["app-1", "app-2"]
    assert len(session.calls) == 2
    assert session.calls[0]["params"]["limit"] == 1
    assert session.calls[1]["params"]["cursor"] == "c2"


def test_iterate_connect_apps_zero_limit_does_not_request_a_page() -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    assert list(client.iterate_connect_apps(limit=0)) == []
    assert session.calls == []


@pytest.mark.parametrize(
    ("argument", "value", "error"),
    [
        ("limit", -1, ValueError),
        ("limit", True, TypeError),
        ("limit", 1.5, TypeError),
        ("limit", "2", TypeError),
        ("page_size", 0, ValueError),
        ("page_size", -1, ValueError),
        ("page_size", False, TypeError),
        ("page_size", 1.5, TypeError),
        ("page_size", "2", TypeError),
        ("cursor", [], TypeError),
        ("cursor", 1, TypeError),
    ],
)
def test_iterate_connect_apps_rejects_invalid_arguments_before_dispatch(
    argument: str, value: Any, error: type[Exception]
) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(error, match=argument):
        list(client.iterate_connect_apps(**{argument: value}))
    assert session.calls == []


def test_iterate_connect_apps_caps_each_page_to_remaining_limit() -> None:
    session = RecordingSession()
    for index, cursor in enumerate(("c2", "c3", None)):
        session.queue(
            StubResponse(
                payload={
                    "items": [{"app_id": f"app-{index}"}],
                    "next_cursor": cursor,
                }
            )
        )
    client = ToriiClient("http://node.test", session=session)

    assert len(list(client.iterate_connect_apps(limit=3, page_size=2))) == 3
    assert [call["params"]["limit"] for call in session.calls] == [2, 2, 1]


@pytest.mark.parametrize(
    ("initial_cursor", "returned_cursors"),
    [("start", ["start"]), (None, ["c1", "c1"]), (None, ["c1", "c2", "c1"])],
)
def test_iterate_connect_apps_rejects_cursor_cycles(
    initial_cursor: Optional[str], returned_cursors: List[str]
) -> None:
    session = RecordingSession()
    for cursor in returned_cursors:
        session.queue(StubResponse(payload={"items": [], "next_cursor": cursor}))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="duplicate cursor"):
        list(client.iterate_connect_apps(cursor=initial_cursor))
    assert len(session.calls) == len(returned_cursors)


def test_iterate_connect_apps_continues_after_empty_page_with_new_cursor() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"items": [], "next_cursor": "c1"}))
    session.queue(StubResponse(payload={"items": [{"app_id": "app-1"}]}))
    client = ToriiClient("http://node.test", session=session)

    assert [app.app_id for app in client.iterate_connect_apps()] == ["app-1"]
    assert len(session.calls) == 2


def test_connect_admission_manifest_helpers() -> None:
    session = RecordingSession()
    manifest_payload = {
        "version": 2,
        "manifest_hash": "abcd",
        "entries": [
            {
                "app_id": "demo.wallet",
                "namespaces": ["wallets"],
                "metadata": {"region": "global"},
                "policy": {"relay_enabled": True},
            }
        ],
    }
    session.queue(StubResponse(payload=manifest_payload))
    session.queue(StubResponse(payload=manifest_payload))
    client = ToriiClient("http://node.test", session=session)

    manifest = client.get_connect_admission_manifest()
    assert manifest.version == 2
    assert manifest.entries[0].namespaces == ["wallets"]

    updated = client.set_connect_admission_manifest(manifest_payload)
    assert updated.manifest_hash == "abcd"
    put_call = session.calls[1]
    assert put_call["method"] == "PUT"
    assert json.loads(put_call["data"]) == manifest_payload


def test_trigger_listing_and_lookup_roundtrip() -> None:
    session = RecordingSession()
    list_payload: Dict[str, Any] = {
        "items": [
            {
                "id": "daily-airdrop",
                "action": {"Mint": {"params": {"asset_id": CANONICAL_ASSET_ID}}},
                "metadata": {"cron": "0 0 * * *"},
            }
        ],
        "total": 1,
    }
    session.queue(StubResponse(payload=list_payload))
    session.queue(StubResponse(payload=list_payload["items"][0]))
    session.queue(StubResponse(status_code=404))
    client = ToriiClient("http://node.test", session=session)

    page = client.list_triggers(namespace="core", authority=CANONICAL_OWNER, limit=5, offset=10)
    trigger = client.get_trigger("daily-airdrop")
    missing = client.get_trigger("unknown-trigger")

    assert page.total == 1
    assert page.items[0].id == "daily-airdrop"
    assert trigger is not None and trigger.metadata["cron"] == "0 0 * * *"
    assert missing is None

    assert session.calls[0]["params"] == {
        "namespace": "core",
        "authority": CANONICAL_OWNER,
        "limit": 5,
        "offset": 10,
    }
    assert session.calls[0]["url"].endswith("/v1/triggers")
    assert session.calls[1]["url"].endswith("/v1/triggers/daily-airdrop")
    assert session.calls[2]["url"].endswith("/v1/triggers/unknown-trigger")


def test_trigger_registration_deletion_and_query() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=201, payload={"ok": True}))
    session.queue(StubResponse(status_code=204))
    session.queue(StubResponse(status_code=404))
    session.queue(
        StubResponse(
            payload={
                "items": [
                    {
                        "id": "hook",
                        "action": {"Grant": {"params": {}}},
                        "metadata": {},
                    }
                ],
                "total": 1,
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.register_trigger({"id": "hook", "action": {"Grant": {}}})
    deleted = client.delete_trigger("hook")
    deleted_missing = client.delete_trigger("missing")
    page = client.query_triggers(filter={"id": {"$eq": "hook"}}, fetch_size=1, query_name="named_query")

    assert result["ok"] is True
    assert deleted is True
    assert deleted_missing is False
    assert page.total == 1
    assert page.items[0].id == "hook"

    post_call = session.calls[0]
    assert post_call["method"] == "POST"
    assert post_call["url"].endswith("/v1/triggers")
    assert json.loads(post_call["data"].decode("utf-8")) == {"id": "hook", "action": {"Grant": {}}}

    query_call = session.calls[-1]
    assert query_call["url"].endswith("/v1/triggers/query")
    assert json.loads(query_call["data"].decode("utf-8")) == {
        "filter": {"id": {"$eq": "hook"}},
        "fetch_size": 1,
        "query_name": "named_query",
    }


def test_status_snapshot_parses_mode_and_consensus_caps() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "mode_tag": "iroha2-consensus::permissioned-sumeragi@v2",
                "staged_mode_tag": "iroha2-consensus::npos-sumeragi@v2",
                "staged_mode_activation_height": 10,
                "mode_activation_lag_blocks": 2,
                "consensus_caps": {
                    "collectors_k": 2,
                    "redundant_send_r": 1,
                    "da_enabled": True,
                    "rbc_chunk_max_bytes": 1024,
                    "rbc_session_ttl_ms": 5000,
                    "rbc_store_max_sessions": 64,
                    "rbc_store_soft_sessions": 32,
                    "rbc_store_max_bytes": 4096,
                    "rbc_store_soft_bytes": 2048,
                },
                "peers": 1,
                "queue_size": 2,
                "commit_time_ms": 3,
                "txs_approved": 5,
                "txs_rejected": 6,
                "view_changes": 7,
                "lane_governance": [],
                "lane_governance_sealed_total": 0,
                "lane_governance_sealed_aliases": [],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    snapshot = client.get_status_snapshot()

    assert snapshot.status.mode_tag == "iroha2-consensus::permissioned-sumeragi@v2"
    assert snapshot.status.staged_mode_tag == "iroha2-consensus::npos-sumeragi@v2"
    assert snapshot.status.staged_mode_activation_height == 10
    assert snapshot.status.mode_activation_lag_blocks == 2
    assert snapshot.status.consensus_caps is not None
    assert snapshot.status.consensus_caps.collectors_k == 2
    assert snapshot.status.consensus_caps.rbc_chunk_max_bytes == 1024


def test_contract_prepare_rejects_retired_extra_slot_before_returning_signable_draft() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=200, payload=_contract_call_draft(
        fee_payment=_authority_fee_payment(5000), retired_admission_tag=0,
    )))
    client = ToriiClient("https://node.test", session=session, local_signing_context=_local_signing_context())
    with pytest.raises(RuntimeError, match="one canonical transaction payload"):
        client.prepare_contract_call(
            authority=CANONICAL_OWNER, contract_alias="router::universal", entrypoint="ping",
            fee_payment=_authority_fee_payment(5000), draft_intent=_contract_draft_intent(),
            canonical_auth=_contract_auth(),
        )
    assert len(session.calls) == 1


def test_contract_prepare_signs_exact_public_request_and_requires_matching_authority() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=200, payload=_contract_call_draft(
        fee_payment=_authority_fee_payment(5000),
    )))
    client = ToriiClient("https://node.test", session=session, local_signing_context=_local_signing_context())
    captured: List[bytes] = []
    auth = _contract_auth(captured)
    client.prepare_contract_call(
        authority=CANONICAL_OWNER, contract_alias="router::universal", entrypoint="ping",
        fee_payment=_authority_fee_payment(5000), draft_intent=_contract_draft_intent(),
        canonical_auth=auth,
    )
    assert len(captured) == 1
    call = session.calls[0]
    expected = client_module.build_canonical_request_headers(
        account_id=auth.account_id, network_id=auth.network_id, method="POST",
        path="/v1/contracts/call", body=call["data"], signer=lambda message: b"\x44" * 64,
        timestamp_ms=auth.timestamp_ms, nonce=auth.nonce,
    )
    for field, value in expected.items():
        assert call["headers"][field] == value
    assert "private_key" not in json.loads(call["data"])
    assert call["allow_redirects"] is False
    with pytest.raises(ValueError, match="account_id must equal authority"):
        client.prepare_contract_call(
            authority=OTHER_CANONICAL_ACCOUNT, contract_alias="router::universal", entrypoint="ping",
            fee_payment=_authority_fee_payment(5000), draft_intent=_contract_draft_intent(),
            canonical_auth=auth,
        )
    assert len(session.calls) == 1


def test_mock_contract_prepare_requires_explicit_exact_payload_fixture() -> None:
    server = ToriiMockServer()
    server.start()
    try:
        response = requests.post(
            server.base_url + "/v1/contracts/call",
            json={"authority": CANONICAL_OWNER, "entrypoint": "ping",
                  "contract_alias": "router::universal", "fee_payment": _authority_fee_payment(5000)},
            timeout=5.0,
        )
        assert response.status_code == 503
        assert "canonical contract draft fixture" in response.json()["error"]
        assert "transaction_payload_b64" not in response.json()
    finally:
        server.stop()


@pytest.mark.parametrize("retired_tag", [0, 1, 2])
def test_unsigned_canonical_layout_rejects_every_retired_admission_slot(
    monkeypatch: pytest.MonkeyPatch, retired_tag: int,
) -> None:
    # This unit isolates exact canonical field count; native AccountId codec
    # and authenticated HTTP boundaries are exercised by their separate tests.
    authority_archive = bytes.fromhex("000000000100")
    monkeypatch.setattr(client_module, "_multisig_account_id_archive", lambda _: authority_archive)
    context = _local_signing_context()
    fee_payment = _authority_fee_payment(5000)
    field = client_module._multisig_norito_field
    parts = [
        client_module._network_transaction_domain_archive(context, "fixture"),
        authority_archive, (42).to_bytes(8, "little"), _CONTRACT_DRAFT_EXECUTABLE,
        b"\x01" + field((100_000).to_bytes(8, "little")), b"\x00",
        client_module._multisig_fee_payment_archive(fee_payment),
        _CONTRACT_DRAFT_METADATA, b"\x00",
    ]
    kwargs = dict(signing_context=context, authority=CANONICAL_OWNER, creation_time_ms=42,
                  fee_payment=fee_payment, executable_b64=base64.b64encode(_CONTRACT_DRAFT_EXECUTABLE).decode(),
                  metadata_b64=base64.b64encode(_CONTRACT_DRAFT_METADATA).decode(),
                  context="fixture")
    accepted = b"".join(field(value) for value in parts)
    client_module._validate_exact_unsigned_transaction_intent(
        client_module._transaction_payload_bindings(accepted), **kwargs,
    )
    parts.insert(7, retired_tag.to_bytes(4, "little"))
    rejected = b"".join(field(value) for value in parts)
    with pytest.raises(RuntimeError, match="trailing bytes"):
        client_module._validate_exact_unsigned_transaction_intent(
            client_module._transaction_payload_bindings(rejected), **kwargs,
        )
    assert accepted != rejected


@pytest.mark.parametrize("mutation", ["order", "peer_duplicate", "peer_literal", "extra", "oversize"])
def test_sumeragi_native_evidence_rejects_invalid_offender_attribution(mutation: str) -> None:
    record = _sumeragi_native_evidence_record()
    first = record["value"]["offenders"][0]
    if mutation == "order":
        record["value"]["offenders"].append({"signer": 3, "peer_id": "ea0130" + "33" * 48})
    elif mutation == "peer_duplicate":
        record["value"]["offenders"].append({"signer": 4, "peer_id": first["peer_id"]})
    elif mutation == "peer_literal":
        first["peer_id"] = "alice@test"
    elif mutation == "extra":
        first["authority"] = "unexpected"
    else:
        record["value"]["offenders"] *= 1025
    with pytest.raises(RuntimeError):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")


def test_retired_generic_multisig_proposal_has_no_shipping_base_api() -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)
    for name in ("propose_multisig", "multisig_instruction_b64", "_parse_multisig_response"):
        assert not hasattr(ToriiClient, name)
        assert not hasattr(client, name)
    assert not hasattr(torii_module, "MultisigDraftIntent")
    assert not hasattr(torii_module, "MultisigResponse")
    assert session.calls == []


@pytest.mark.parametrize("details", [{"height": 44}, None, {}, {"height": 44, "note": "x"}])
def test_sumeragi_evidence_rejects_retired_cancelled_status(details: Any) -> None:
    record = _sumeragi_native_evidence_record(
        penalty_status={"status": "cancelled", "details": details}
    )
    with pytest.raises(RuntimeError, match="status must be pending or applied"):
        ToriiClient._parse_sumeragi_evidence_record(record, context="evidence")



# Synthetic model DATA only: no signature or historical-state acceptance is claimed.
def _sccp_forgery_evidence_record() -> Dict[str, Any]:
    return {
        "kind": "SccpForgeryEvidence",
        "value": {
            "record": {
                "evidence": {
                    "qc": "A1" * 116,
                    "header": "b2" * 221,
                    "aggregate_signature": "C3" * 96,
                    "anchor": {"core_hash": "00" * 32, "result": "00" * 32, "path": ["07" * 32] * 12},
                },
                "rule": {"rule": "E4", "detail": None},
                "generation": 7,
                "start_height": 23,
                "offenders": [{"signer": 0, "lane_id": 1, "validator": CANONICAL_OWNER, "activation_height": 19}],
            },
            "attribution": {
                "scope": {"kind": "sccp_generation", "value": {"generation": 7}},
                "instance": "01" * 32, "height": 23, "epoch": 99,
                "context_id": "02" * 32, "authority_generation": "03" * 32,
                "offenders": [{"signer": 0, "peer_id": "ea0130" + "22" * 48, "lane_stake": None}],
                "safety_violation": False,
            },
            "recorded_height": 42, "recorded_view": 5, "recorded_ms": 1234,
            "consensus_admitted_height": 42,
            "penalty_status": {"status": "pending", "details": None},
        },
    }


def _lane_evidence_scope() -> Dict[str, Any]:
    return {"kind": "lane", "value": {
        "lane": 3, "incarnation": "00" * 32, "created_at": 8, "admission_parent_height": 7,
        "admission_parent_hash": _canonical_hash(0xA1),
        "admission_parent_core_hash": "Aa" * 32, "admission_parent_result": "00" * 32,
    }}


def _read_sccp_evidence(item: Dict[str, Any], kind: Optional[str] = None) -> Any:
    session = RecordingSession()
    session.queue(StubResponse(payload={"total": 1, "items": [item]}))
    client = ToriiClient("http://node.test", session=session, operator_signing_context=_operator_context())
    page = client.list_sumeragi_evidence(kind=kind)
    assert session.calls[0]["params"] == {}
    assert session.calls[0]["url"].endswith("/v1/sumeragi/evidence" + (f"?kind={kind}" if kind is not None else ""))
    assert session.calls[0]["headers"]["Accept"] == "application/json"
    return page.items[0]


@pytest.mark.parametrize("rule", ["E1", "E2", "E3", "E4"])
@pytest.mark.parametrize("anchored", [False, True])
def test_sccp_evidence_preserves_exact_model_data(rule: str, anchored: bool) -> None:
    source = _sccp_forgery_evidence_record()
    source["value"]["record"]["rule"]["rule"] = rule
    if not anchored:
        source["value"]["record"]["evidence"]["anchor"] = None
    parsed = _read_sccp_evidence(source)
    assert parsed.kind == "SccpForgeryEvidence"
    assert isinstance(parsed.value, torii_module.SccpForgeryEvidenceRecord)
    assert parsed.value.record.rule.rule == rule
    assert parsed.value.record.rule.detail is None
    assert parsed.value.record.generation == 7
    assert parsed.value.record.start_height == 23
    assert parsed.value.record.evidence.qc == source["value"]["record"]["evidence"]["qc"]
    assert parsed.value.record.evidence.header == source["value"]["record"]["evidence"]["header"]
    assert parsed.value.record.evidence.aggregate_signature == source["value"]["record"]["evidence"]["aggregate_signature"]
    if anchored:
        assert parsed.value.record.evidence.anchor.core_hash == "00" * 32
        assert parsed.value.record.evidence.anchor.result == "00" * 32
        assert parsed.value.record.evidence.anchor.path == ("07" * 32,) * 12
    else:
        assert parsed.value.record.evidence.anchor is None
    assert parsed.value.record.offenders == (torii_module.SccpForgeryOffender(0, 1, CANONICAL_OWNER, 19),)
    assert parsed.value.attribution.scope.kind == "sccp_generation"
    assert parsed.value.attribution.scope.value.generation == 7
    assert parsed.value.attribution.instance == "01" * 32
    assert parsed.value.attribution.height == 23
    assert parsed.value.attribution.epoch == 99
    assert parsed.value.attribution.context_id == "02" * 32
    assert parsed.value.attribution.authority_generation == "03" * 32
    assert parsed.value.attribution.offenders == (torii_module.SccpEvidenceOffender(0, "ea0130" + "22" * 48, None),)
    assert parsed.value.attribution.safety_violation is False
    assert parsed.value.recorded_height == 42
    assert parsed.value.recorded_view == 5
    assert parsed.value.recorded_ms == 1234
    assert parsed.value.consensus_admitted_height == 42
    assert parsed.value.penalty_status == torii_module.SumeragiEvidencePendingPenaltyStatus("pending", None)


def test_sumeragi_evidence_preserves_lane_scope_fields() -> None:
    source = _sumeragi_native_evidence_record()
    source["value"]["scope"] = _lane_evidence_scope()
    parsed = _read_sccp_evidence(source)
    assert parsed.kind == "NativeSumeragiEvidence"
    assert isinstance(parsed.value, torii_module.SumeragiNativeEvidenceRecord)
    assert parsed.value.scope.kind == "lane"
    assert parsed.value.scope.value == torii_module.SumeragiLaneEvidenceScope(**source["value"]["scope"]["value"])


@pytest.mark.parametrize("factory", [_sumeragi_native_evidence_record, _sccp_forgery_evidence_record])
@pytest.mark.parametrize("kind", [None, "NativeSumeragiEvidence", "SccpForgeryEvidence"])
def test_sumeragi_evidence_kind_filter_binds_returned_record(factory: Callable[[], Dict[str, Any]], kind: Optional[str]) -> None:
    source = factory()
    if kind is None or kind == source["kind"]:
        assert _read_sccp_evidence(source, kind).kind == source["kind"]
    else:
        with pytest.raises(RuntimeError, match="kind differs from the requested filter"):
            _read_sccp_evidence(source, kind)


@pytest.mark.parametrize("factory", [_sumeragi_native_evidence_record, _sccp_forgery_evidence_record])
def test_sumeragi_evidence_rejects_flat_retired_layout_and_unknown_kind(factory: Callable[[], Dict[str, Any]]) -> None:
    source = factory()
    with pytest.raises(RuntimeError, match="exact server fields"):
        _read_sccp_evidence({"kind": source["kind"], **source["value"]})
    for kind in ["UnknownEvidence", "sccp_forgery", "SccpForgeryEvidence ", None]:
        source["kind"] = kind
        with pytest.raises(RuntimeError):
            _read_sccp_evidence(source)
    source = factory()
    for value in [None, [], 1, "payload"]:
        source["value"] = value
        with pytest.raises(RuntimeError):
            _read_sccp_evidence(source)


def test_sccp_evidence_requires_every_closed_nested_field() -> None:
    sources = [
        (_sccp_forgery_evidence_record(), [(), ("value",), ("value", "record"), ("value", "record", "evidence"),
            ("value", "record", "evidence", "anchor"), ("value", "record", "rule"), ("value", "record", "offenders", 0),
            ("value", "attribution"), ("value", "attribution", "scope"), ("value", "attribution", "scope", "value"),
            ("value", "attribution", "offenders", 0), ("value", "penalty_status")]),
    ]
    native = _sumeragi_native_evidence_record()
    native["value"]["scope"] = _lane_evidence_scope()
    sources.append((native, [("value", "scope"), ("value", "scope", "value")]))
    for source, paths in sources:
        for path in paths:
            target = source
            for key in path:
                target = target[key]
            for field in [None, *target]:
                record = copy.deepcopy(source)
                nested = record
                for key in path:
                    nested = nested[key]
                if field is None:
                    nested["unknown"] = None
                else:
                    del nested[field]
                with pytest.raises(RuntimeError, match="exact server fields"):
                    _read_sccp_evidence(record)


@pytest.mark.parametrize(("path", "value"), [
    (("record", "evidence", "qc"), "A1" * 115),
    (("record", "evidence", "header"), [0] * 221),
    (("record", "evidence", "aggregate_signature"), "GG" * 96),
    (("record", "evidence", "anchor", "core_hash"), "0x" + "00" * 32),
    (("record", "evidence", "anchor", "result"), "00" * 31),
    (("record", "evidence", "anchor", "path"), ["00" * 32] * 11),
    (("record", "evidence", "anchor", "path"), ["00" * 32] * 13),
    (("record", "evidence", "anchor", "path", 0), []),
    (("record", "rule", "rule"), "E5"), (("record", "rule", "detail"), {}),
    (("record", "generation"), 0), (("record", "start_height"), 0),
    (("record", "generation"), "7"), (("record", "generation"), True),
    (("record", "generation"), 1 << 64),
    (("record", "offenders"), []), (("record", "offenders", 0, "signer"), 31),
    (("record", "offenders", 0, "lane_id"), 1 << 32), (("record", "offenders", 0, "validator"), "invalid"),
    (("record", "offenders", 0, "activation_height"), 0), (("record", "offenders", 0, "activation_height"), 24),
    (("attribution", "scope"), {"kind": "root", "value": None}),
    (("attribution", "scope", "value", "generation"), 8), (("attribution", "height"), 24),
    (("attribution", "offenders"), []), (("attribution", "offenders", 0, "signer"), 1),
    (("attribution", "offenders", 0, "peer_id"), "invalid"), (("attribution", "offenders", 0, "lane_stake"), {}),
    (("attribution", "instance"), []), (("attribution", "context_id"), "AA" * 31),
    (("attribution", "authority_generation"), "zz" * 32), (("attribution", "epoch"), -1),
    (("attribution", "safety_violation"), 1), (("recorded_ms",), None),
    (("penalty_status", "status"), "cancelled"), (("penalty_status", "details"), {}),
])
def test_sccp_evidence_rejects_malformed_data_and_attribution(path: tuple, value: Any) -> None:
    source = _sccp_forgery_evidence_record()
    nested = source["value"]
    for key in path[:-1]:
        nested = nested[key]
    nested[path[-1]] = value
    with pytest.raises(RuntimeError):
        _read_sccp_evidence(source)


def test_sccp_evidence_rejects_duplicate_unordered_and_oversized_liability() -> None:
    for count in [2, 32]:
        source = _sccp_forgery_evidence_record()
        offender = source["value"]["record"]["offenders"][0]
        source["value"]["record"]["offenders"] = [dict(offender, signer=signer) for signer in range(count)]
        with pytest.raises(RuntimeError, match="registration must be unique|between 1 and 31"):
            _read_sccp_evidence(source)
    source = _sccp_forgery_evidence_record()
    source["value"]["record"]["offenders"].append(dict(source["value"]["record"]["offenders"][0], lane_id=2))
    with pytest.raises(RuntimeError, match="signer must increase strictly"):
        _read_sccp_evidence(source)


@pytest.mark.parametrize("scope", [
    {"kind": "root", "value": {}}, {"kind": "sccp_generation", "value": {"generation": 7}},
    {"kind": "unknown", "value": None},
])
def test_sumeragi_evidence_rejects_wrong_native_scope(scope: Dict[str, Any]) -> None:
    source = _sumeragi_native_evidence_record()
    source["value"]["scope"] = scope
    with pytest.raises(RuntimeError):
        _read_sccp_evidence(source)


@pytest.mark.parametrize(("field", "value"), [
    ("lane", 1 << 32), ("incarnation", []), ("created_at", -1), ("admission_parent_height", True),
    ("admission_parent_hash", "hash:" + "00" * 32 + "#0000"),
    ("admission_parent_core_hash", "zz" * 32), ("admission_parent_result", "00" * 31),
])
def test_sumeragi_evidence_rejects_malformed_lane_scope(field: str, value: Any) -> None:
    source = _sumeragi_native_evidence_record()
    source["value"]["scope"] = _lane_evidence_scope()
    source["value"]["scope"]["value"][field] = value
    with pytest.raises(RuntimeError):
        _read_sccp_evidence(source)


def test_sccp_evidence_preserves_u64_fields_and_original_certificate_bytes() -> None:
    source = _sccp_forgery_evidence_record()
    maximum = (1 << 64) - 1
    value = source["value"]
    value["record"]["generation"] = maximum
    value["record"]["start_height"] = maximum
    value["record"]["offenders"][0]["activation_height"] = maximum
    value["attribution"]["scope"]["value"]["generation"] = maximum
    for field in ["height", "epoch"]:
        value["attribution"][field] = maximum
    for field in ["recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height"]:
        value[field] = maximum
    value["penalty_status"] = {"status": "applied", "details": {"height": maximum}}
    parsed = _read_sccp_evidence(source).value
    assert parsed.record.generation == maximum
    assert parsed.record.start_height == maximum
    assert parsed.record.offenders[0].activation_height == maximum
    assert parsed.attribution.scope.value.generation == maximum
    for field in ["height", "epoch"]:
        assert getattr(parsed.attribution, field) == maximum
    for field in ["recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height"]:
        assert getattr(parsed, field) == maximum
    assert parsed.penalty_status.details.height == maximum
    assert parsed.record.evidence.qc == value["record"]["evidence"]["qc"]
    assert parsed.record.evidence.header == value["record"]["evidence"]["header"]
    assert parsed.record.evidence.aggregate_signature == value["record"]["evidence"]["aggregate_signature"]


@pytest.mark.parametrize(("path", "value", "cause"), [
    (("kind",), None, TypeError),
    (("value", "record", "offenders", 0, "validator"), "invalid", ValueError),
    (("value", "attribution", "offenders", 0, "peer_id"), None, TypeError),
])
def test_sccp_evidence_response_errors_preserve_original_codec_cause(
    path: tuple, value: Any, cause: type[Exception],
) -> None:
    source = _sccp_forgery_evidence_record()
    target = source
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value
    with pytest.raises(RuntimeError, match="sumeragi evidence listing.items") as raised:
        _read_sccp_evidence(source)
    assert isinstance(raised.value.__cause__, cause)
