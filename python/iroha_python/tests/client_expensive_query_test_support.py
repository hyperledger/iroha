"""Shared exact-network client fixture for ledger query tests."""

from __future__ import annotations

from typing import Any

from iroha_python import LocalSigningContext, NetworkId, ToriiClient
from iroha_python.address import AccountAddress
from iroha_python.client import ToriiCanonicalRequestAuth
from iroha_python.crypto import Ed25519KeyPair

_NETWORK_ID = NetworkId.from_bytes(bytes([0xA5]) * 32)
_ACCOUNT_PUBLIC_KEY = Ed25519KeyPair.from_private_key(bytes([0x31]) * 32).public_key
_ACCOUNT_ID = AccountAddress.from_account(
    public_key=_ACCOUNT_PUBLIC_KEY,
).to_i105(0x02F1)


def authenticated_query_client(session: Any) -> ToriiClient:
    """Build a no-retry client with immutable exact-network query auth."""

    return ToriiClient(
        "https://torii.example",
        session=session,
        max_retries=0,
        local_signing_context=LocalSigningContext(_NETWORK_ID),
        canonical_request_auth=ToriiCanonicalRequestAuth(
            network_id=_NETWORK_ID.literal,
            account_id=_ACCOUNT_ID,
            signer=lambda _message: bytes([0x44]) * 64,
            timestamp_ms=4_102_444_801_000,
            nonce="python-ledger-query-tests",
        ),
        chain_discriminant=753,
    )
