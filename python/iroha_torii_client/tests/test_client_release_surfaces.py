"""PDP, governance-ballot, and subscription Torii client tests."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
import requests

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from client_test_support import canonical_hash  # noqa: E402
from iroha_torii_client import (  # noqa: E402
    ToriiCanonicalRequestAuth,
    ToriiClient,
    decode_pdp_commitment_header,
)
from iroha_torii_client.mock import ToriiMockServer  # noqa: E402
from sumeragi_exact_json_test_support import RecordingSession, StubResponse  # noqa: E402

CANONICAL_OWNER = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
GOVERNANCE_NETWORK_ID = canonical_hash(0xA5)
CANONICAL_LARGE_FRACTION = "18446744073709551616.25"


def _canonical_auth() -> ToriiCanonicalRequestAuth:
    return ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda _message: b"\x44" * 64,
        timestamp_ms=4_102_444_801_000,
        nonce="low-python-release-surface-test",
    )


def _app_api_transaction_draft(payload: bytes = b"\x01\x02\x03") -> Dict[str, Any]:
    signing_message = bytearray(hashlib.blake2b(payload, digest_size=32).digest())
    signing_message[-1] |= 1
    return {
        "submitted": False,
        "transaction_payload_b64": base64.b64encode(payload).decode("ascii"),
        "signing_message_b64": base64.b64encode(signing_message).decode("ascii"),
    }


def test_decode_pdp_commitment_header_handles_mapping() -> None:
    payload = b"\x01\x02\x03"
    header_value = base64.b64encode(payload).decode("ascii")

    decoded = decode_pdp_commitment_header({"sora-pdp-commitment": header_value})

    assert decoded == payload


def test_decode_pdp_commitment_header_is_case_insensitive() -> None:
    payload = b"\xAA\xBB"
    header_value = base64.b64encode(payload).decode("ascii")

    decoded = decode_pdp_commitment_header({"Sora-PDP-Commitment": header_value})

    assert decoded == payload


def test_decode_pdp_commitment_header_rejects_invalid_payload() -> None:
    try:
        decode_pdp_commitment_header({"sora-pdp-commitment": "###"})
    except RuntimeError as exc:
        assert "Failed to decode" in str(exc)
    else:
        raise AssertionError("expected RuntimeError for invalid header")


def test_decode_pdp_commitment_header_returns_none_when_missing() -> None:
    assert decode_pdp_commitment_header({}) is None
    assert decode_pdp_commitment_header(None) is None


def test_submit_plain_ballot_requires_canonical_lossless_quantity() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "drafted": True,
                "tx_instructions": [{"wire_id": "CastPlainBallot", "payload_hex": "00"}],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    client.submit_plain_ballot(
        authority=CANONICAL_OWNER,
        network_id=GOVERNANCE_NETWORK_ID,
        canonical_auth=_canonical_auth(),
        referendum_id="ref-1",
        owner=CANONICAL_OWNER,
        amount=CANONICAL_LARGE_FRACTION,
        duration_blocks=5,
        direction="Aye",
    )
    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["amount"] == CANONICAL_LARGE_FRACTION

    overflowing = "9" * 155
    for invalid in [
        1,
        1.5,
        "+1",
        "01",
        "1.0",
        "1.2300",
        " 1",
        "1 ",
        "-1",
        overflowing,
    ]:
        with pytest.raises(RuntimeError, match="quantity|512-bit"):
            client.submit_plain_ballot(
                authority=CANONICAL_OWNER,
                network_id=GOVERNANCE_NETWORK_ID,
                canonical_auth=_canonical_auth(),
                referendum_id="ref-1",
                owner=CANONICAL_OWNER,
                amount=invalid,  # type: ignore[arg-type]
                duration_blocks=5,
                direction="Aye",
            )


@pytest.mark.parametrize(
    "amount",
    [1, 1.5, "+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", "9" * 155],
)
def test_submit_zk_ballot_v1_lock_hints_reject_noncanonical_quantity(
    amount: Any,
) -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="quantity"):
        client.submit_zk_ballot_v1(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            canonical_auth=_canonical_auth(),
            election_id="election-1",
            backend="halo2/ipa",
            envelope_b64="AAAA",
            owner=CANONICAL_OWNER,
            amount=amount,  # type: ignore[arg-type]
            duration_blocks=5,
        )


def test_legacy_zk_ballot_surface_is_absent() -> None:
    assert not hasattr(ToriiClient, "submit_zk_ballot")
    assert hasattr(ToriiClient, "submit_zk_ballot_v1")


def test_mock_server_accepts_canonical_zk_v1_ballot() -> None:
    server = ToriiMockServer().start()
    try:
        configured = requests.post(
            f"{server.base_url.rstrip('/')}/__mock__/gov/config",
            json={
                "referenda": [
                    {
                        "id": "election-1",
                        "referendum": {"id": "election-1", "mode": "Zk"},
                        "ballot_zk_response": {
                            "drafted": True,
                            "tx_instructions": [{"wire_id": "CastZkBallotV1", "payload_hex": "00"}],
                        },
                    }
                ]
            },
            timeout=5.0,
        )
        configured.raise_for_status()

        result = ToriiClient(server.base_url).submit_zk_ballot_v1(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            canonical_auth=_canonical_auth(),
            election_id="election-1",
            backend="halo2/ipa",
            envelope_b64="AAAA",
            owner=CANONICAL_OWNER,
            amount="100",
            duration_blocks=5,
        )

        assert result.drafted is True
        assert result.tx_instructions[0].wire_id == "CastZkBallotV1"
    finally:
        server.stop()


def test_mock_server_rejects_legacy_nested_payload_on_zk_v1_route() -> None:
    server = ToriiMockServer().start()
    try:
        response = requests.post(
            f"{server.base_url.rstrip('/')}/v1/gov/ballots/zk-v1",
            json={
                "authority": CANONICAL_OWNER,
                "chain_id": "chain",
                "election_id": "election-1",
                "proof_b64": "AAAA",
                "public": {},
            },
            timeout=5.0,
        )

        assert response.status_code == 400
    finally:
        server.stop()


def test_mock_server_rejects_retired_legacy_zk_ballot_route() -> None:
    server = ToriiMockServer().start()
    try:
        response = requests.post(
            f"{server.base_url.rstrip('/')}/v1/gov/ballots/zk",
            json={"proof_b64": "AAAA"},
            timeout=5.0,
        )

        assert response.status_code == 404
    finally:
        server.stop()


def test_submit_zk_ballot_v1_rejects_incomplete_lock_hints() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"ok": True}))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="owner, amount, duration_blocks"):
        client.submit_zk_ballot_v1(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            canonical_auth=_canonical_auth(),
            election_id="election-1",
            backend="halo2/ipa",
            envelope_b64="AAAA",
            owner=CANONICAL_OWNER,
        )


def test_submit_zk_ballot_v1_rejects_noncanonical_owner() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"ok": True}))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="canonical I105 account id"):
        client.submit_zk_ballot_v1(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            canonical_auth=_canonical_auth(),
            election_id="election-1",
            backend="halo2/ipa",
            envelope_b64="AAAA",
            owner="soradead",
            amount="100",
            duration_blocks=5,
        )


def test_submit_zk_ballot_v1_normalizes_hex_hints() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"drafted": True, "tx_instructions": [{"wire_id": "CastZkBallotV1", "payload_hex": "00"}]}))
    client = ToriiClient("http://node.test", session=session)

    client.submit_zk_ballot_v1(
        authority=CANONICAL_OWNER,
        network_id=GOVERNANCE_NETWORK_ID,
        canonical_auth=_canonical_auth(),
        election_id="election-1",
        backend="halo2/ipa",
        envelope_b64="AAAA",
        root_hint=f"0x{'Aa' * 32}",
        owner=CANONICAL_OWNER,
        amount=CANONICAL_LARGE_FRACTION,
        duration_blocks=5,
        nullifier=f"blake2b32:{'BB' * 32}",
    )

    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["root_hint"] == "aa" * 32
    assert payload["amount"] == CANONICAL_LARGE_FRACTION
    assert payload["nullifier"] == "bb" * 32


def test_submit_zk_ballot_v1_rejects_invalid_hex_hints() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={"ok": True}))
    client = ToriiClient("http://node.test", session=session)

    with pytest.raises(RuntimeError, match="root_hint"):
        client.submit_zk_ballot_v1(
            authority=CANONICAL_OWNER,
            network_id=GOVERNANCE_NETWORK_ID,
            canonical_auth=_canonical_auth(),
            election_id="election-1",
            backend="halo2/ipa",
            envelope_b64="AAAA",
            root_hint="not-hex",
        )


def test_subscription_plans_use_the_collection_contract() -> None:
    session = RecordingSession()
    provider = "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"
    session.queue(StubResponse(payload={
        "items": [{"id": "plan#subs", "provider": provider, "billing": {}, "pricing": {"kind": "fixed"}}],
        "next_cursor": "next-plan", "total": 1,
    }))
    client = ToriiClient("http://node.test", session=session)
    page = client.subscription_plans.list(filter=f'provider = "{provider}"', limit=10, include_total=True)
    assert page.total == 1
    assert page.next_cursor == "next-plan"
    assert page.items[0]["id"] == "plan#subs"
    assert page.items[0]["provider"] == provider
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"].endswith("/v1/subscriptions/plans/query")
    body = json.loads(call["data"])
    assert body["filter"] == f'provider = "{provider}"'
    assert body["limit"] == 10
    assert body["include_total"] is True


def test_create_subscription_plan_posts_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                **_app_api_transaction_draft(),
                "plan_id": "plan#subs",
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.create_subscription_plan(
        authority=CANONICAL_OWNER,
        canonical_auth=_canonical_auth(),
        plan_id="plan#subs",
        plan={"provider": "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"},
    )

    assert result.submitted is False
    assert result.plan_id == "plan#subs"
    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["authority"] == CANONICAL_OWNER
    assert "private_key" not in payload
    assert payload["plan_id"] == "plan#subs"
    assert payload["plan"]["provider"] == "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"


def test_subscriptions_use_flat_collection_rows_and_cursor_paging() -> None:
    session = RecordingSession()
    session.queue(StubResponse(payload={
        "items": [{"id": "sub-1$subscriptions", "status": "active", "owned_by": CANONICAL_OWNER,
                   "invoice": {"amount": "120"}, "plan": {"provider": CANONICAL_OWNER}}],
        "next_cursor": "next-subscription",
    }))
    session.queue(StubResponse(payload={"items": [], "next_cursor": None}))
    client = ToriiClient("http://node.test", session=session)
    rows = list(client.subscriptions.iter(filter='status = "active"', limit=25))
    assert rows[0]["id"] == "sub-1$subscriptions"
    assert rows[0]["status"] == "active"
    assert rows[0]["invoice"]["amount"] == "120"
    assert len(session.calls) == 2
    for call in session.calls:
        assert call["method"] == "POST"
        assert call["url"].endswith("/v1/subscriptions/query")
    assert json.loads(session.calls[1]["data"])["cursor"] == "next-subscription"


def test_subscriptions_reject_removed_paging_params() -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)
    with pytest.raises(TypeError):
        client.subscriptions.list(offset=0)
    assert session.calls == []


def test_create_subscription_posts_payload() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "version": 1,
                "authority": CANONICAL_OWNER,
                "action": "create",
                "subscription_id": "sub-1$subscriptions",
                "plan_id": "plan#subs",
                "billing_trigger_id": "sub-bill",
                "usage_trigger_id": "sub-usage",
                "first_charge_ms": 1_704_067_200_000,
                "provider_usage_grant_included": True,
                "resulting_subscription": {},
                "tx_instructions": [{"wire_id": "register", "payload_hex": "00"}],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    result = client.create_subscription(
        authority=CANONICAL_OWNER,
        canonical_auth=_canonical_auth(),
        subscription_id="sub-1$subscriptions",
        plan_id="plan#subs",
        billing_trigger_id="sub-bill",
        usage_trigger_id="sub-usage",
        first_charge_ms=1_704_067_200_000,
        grant_usage_to_provider=True,
    )

    assert result.subscription_id == "sub-1$subscriptions"
    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["authority"] == CANONICAL_OWNER
    assert "private_key" not in payload
    assert payload["billing_trigger_id"] == "sub-bill"
    assert payload["usage_trigger_id"] == "sub-usage"
    assert payload["first_charge_ms"] == 1_704_067_200_000
    assert payload["grant_usage_to_provider"] is True


def test_get_subscription_encodes_path_and_parses_response() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "subscription_id": "sub-1$subscriptions",
                "subscription": {"status": "active"},
                "plan": {"provider": "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"},
            }
        )
    )
    client = ToriiClient("http://node.test", session=session)

    record = client.get_subscription("sub-1$subscriptions")

    assert record is not None
    assert record.subscription_id == "sub-1$subscriptions"
    assert session.calls[0]["url"].endswith("/v1/subscriptions/sub-1%24subscriptions")


def test_get_subscription_returns_none_on_404() -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=404, payload=None))
    client = ToriiClient("http://node.test", session=session)

    assert client.get_subscription("sub-404$subscriptions") is None


def test_subscription_actions_post_payloads() -> None:
    session = RecordingSession()
    for action in ("pause", "resume", "cancel", "charge_now"):
        session.queue(StubResponse(payload={
            "version": 1,
            "authority": CANONICAL_OWNER,
            "action": action,
            "subscription_id": "sub-1",
            "details": {},
            "tx_instructions": [{"wire_id": "set", "payload_hex": "00"}],
        }))
    client = ToriiClient("http://node.test", session=session)

    client.pause_subscription("sub-1", authority=CANONICAL_OWNER, canonical_auth=_canonical_auth())
    client.resume_subscription(
        "sub-1",
        authority=CANONICAL_OWNER,
        canonical_auth=_canonical_auth(),
        charge_at_ms=1_704_067_200_000,
    )
    client.cancel_subscription("sub-1", authority=CANONICAL_OWNER, cancel_mode="immediate", canonical_auth=_canonical_auth())
    client.charge_subscription_now(
        "sub-1",
        authority=CANONICAL_OWNER,
        canonical_auth=_canonical_auth(),
        charge_at_ms=1_704_067_200_000,
    )

    pause_body = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert pause_body["authority"] == CANONICAL_OWNER
    resume_body = json.loads(session.calls[1]["data"].decode("utf-8"))
    assert resume_body["charge_at_ms"] == 1_704_067_200_000
    cancel_body = json.loads(session.calls[2]["data"].decode("utf-8"))
    assert "private_key" not in cancel_body
    assert cancel_body["cancel_mode"] == {"mode": "immediate", "value": None}
    charge_body = json.loads(session.calls[3]["data"].decode("utf-8"))
    assert charge_body["charge_at_ms"] == 1_704_067_200_000


def test_record_subscription_usage_uses_canonical_quantity_boundary() -> None:
    session = RecordingSession()
    client = ToriiClient("http://node.test", session=session)
    canonical_values = [
        "0",
        "12.5",
        str((1 << 511) - 1),
        f"0.{'0' * 27}1",
    ]
    for canonical in canonical_values:
        session.queue(
            StubResponse(
                payload={
                    **_app_api_transaction_draft(canonical.encode("utf-8")),
                    "subscription_id": "sub-1",
                }
            )
        )
        result = client.record_subscription_usage(
            "sub-1",
            authority=CANONICAL_OWNER,
            canonical_auth=_canonical_auth(),
            unit_key="compute_ms",
            delta=canonical,
            usage_trigger_id="sub-usage",
        )
        assert result.submitted is False
        payload = json.loads(session.calls[-1]["data"].decode("utf-8"))
        assert payload["unit_key"] == "compute_ms"
        assert payload["delta"] == canonical
        assert payload["usage_trigger_id"] == "sub-usage"
        assert "private_key" not in payload

    invalid_values: List[Any] = [
        0,
        1,
        1.25,
        "+1",
        "01",
        "00",
        "00.1",
        "1.0",
        "1.20",
        "0.0",
        "-0",
        "-1",
        str(1 << 511),
        f"0.{'0' * 28}1",
    ]
    submitted = len(session.calls)
    for invalid in invalid_values:
        with pytest.raises(RuntimeError, match="quantity"):
            client.record_subscription_usage(
                "sub-1",
                authority=CANONICAL_OWNER,
                canonical_auth=_canonical_auth(),
                unit_key="compute_ms",
                delta=invalid,  # type: ignore[arg-type]
            )
    assert len(session.calls) == submitted
