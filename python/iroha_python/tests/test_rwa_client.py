from __future__ import annotations

import json

from iroha_python import F
from iroha_python.client import ToriiClient

from .helpers import RecordingSession, StubResponse

SAMPLE_RWA_ID = "lot-001$commodities"
SAMPLE_OWNER = "ed0120111111111111111111111111111111111111111111111111111111111111@wonderland"


def test_explorer_rwas_collection_encodes_filters_and_decodes_page() -> None:
    session = RecordingSession(
        StubResponse(
            payload={
                "next_cursor": "bmV4dC1yd2EtY3Vyc29y",
                "items": [
                    {
                        "id": SAMPLE_RWA_ID,
                        "owned_by": SAMPLE_OWNER,
                        "quantity": "10",
                        "held_quantity": "2.5",
                        "primary_reference": "vault-cert-001",
                        "status": None,
                        "is_frozen": False,
                        "metadata": {"grade": "AA"},
                    }
                ],
            }
        )
    )
    client = ToriiClient("http://node.test", session=session, chain_discriminant=753)

    page = client.explorer_rwas.list(
        cursor="cHJldmlvdXMtcndhLWN1cnNvcg",
        limit=25,
        filter=(F.owned_by == SAMPLE_OWNER) & (F.domain == "commodities"),
    )

    params = json.loads(session.calls[0]["data"])
    assert params == {
        "cursor": "cHJldmlvdXMtcndhLWN1cnNvcg",
        "limit": 25,
        "filter": {"op": "and", "args": [
            {"op": "eq", "args": ["owned_by", SAMPLE_OWNER]},
            {"op": "eq", "args": ["domain", "commodities"]},
        ]},
    }
    assert page.next_cursor == "bmV4dC1yd2EtY3Vyc29y"
    assert page.has_more is True
    assert page.items[0].id == SAMPLE_RWA_ID
    assert page.items[0].status is None
    assert page.items[0].metadata == {"grade": "AA"}


def test_get_explorer_rwa_detail_typed_encodes_path_and_decodes_payload() -> None:
    session = RecordingSession(
        StubResponse(
            payload={
                "id": SAMPLE_RWA_ID,
                "owned_by": SAMPLE_OWNER,
                "quantity": "10",
                "held_quantity": "0",
                "primary_reference": "vault-cert-001",
                "status": "Active",
                "is_frozen": True,
                "metadata": {},
            }
        )
    )
    client = ToriiClient("http://node.test", session=session, chain_discriminant=753)

    detail = client.get_explorer_rwa_detail_typed(SAMPLE_RWA_ID)

    assert session.calls[0]["url"].endswith("/v1/explorer/rwas/lot-001%24commodities")
    assert detail.id == SAMPLE_RWA_ID
    assert detail.status == "Active"
    assert detail.is_frozen is True
