from __future__ import annotations

import json
from typing import Any, Mapping

import pytest
import requests

from iroha_python import GovernanceLockCustody
from iroha_python.address import AccountAddress
from iroha_python.client import (
    GovernanceLockRecord,
    GovernanceManifestProvenance,
    GovernanceProposalDeployContract,
    LocalSigningContext,
    ToriiCanonicalRequestAuth,
    ToriiClient,
)
from iroha_python.crypto import Ed25519KeyPair, NetworkId
from iroha_python.sorafs import SorafsAliasPolicy

from .helpers import RecordingSession, StubResponse


def test_prebuffered_stub_response_supports_requests_streaming() -> None:
    response = StubResponse(payload={"drafted": True, "tx_instructions": []})
    assert response.raw is None
    assert response._content_consumed
    assert b"".join(response.iter_content(chunk_size=3)) == response.content
    assert response.json() == {"drafted": True, "tx_instructions": []}


def _canonical_owner_literal() -> str:
    public_key = Ed25519KeyPair.from_private_key(bytes([0x11]) * 32).public_key
    address = AccountAddress.from_account(public_key=public_key)
    return address.to_i105(0x02F1)


CANONICAL_AUTHORITY = _canonical_owner_literal()
CANONICAL_AUTHORITY_HEADER = AccountAddress.parse_encoded(
    CANONICAL_AUTHORITY, expected_discriminant=0x02F1
).canonical_hex()
GOVERNANCE_NETWORK_ID = NetworkId.from_bytes(bytes([0xA5]) * 32)
FOREIGN_GOVERNANCE_NETWORK_ID = NetworkId.from_bytes(bytes([0xA7]) * 32)
GOVERNANCE_AUTH = ToriiCanonicalRequestAuth(
    network_id=GOVERNANCE_NETWORK_ID.literal,
    account_id=CANONICAL_AUTHORITY,
    signer=lambda _message: bytes([0x44]) * 64,
    timestamp_ms=4_102_444_801_000,
    nonce="python-governance-ballot-test",
)
CANONICAL_LARGE_FRACTION = "18446744073709551616.25"
GOVERNANCE_PRIVATE_KEY_ALIASES = (
    "private_key",
    "privateKey",
    "private_key_hex",
    "privateKeyHex",
    "private_key_bytes",
    "privateKeyBytes",
    "private_key_seed",
    "privateKeySeed",
    "private_key_multihash",
    "privateKeyMultihash",
    "private_key_algorithm",
    "privateKeyAlgorithm",
)
TEST_SORAFS_ALIAS_POLICY = SorafsAliasPolicy(
    positive_ttl_secs=60,
    refresh_window_secs=30,
    hard_expiry_secs=120,
    negative_ttl_secs=30,
    revocation_ttl_secs=30,
    rotation_max_age_secs=60,
    successor_grace_secs=0,
    governance_grace_secs=0,
)


def _noncanonical_owner_literal() -> str:
    public_key = Ed25519KeyPair.from_private_key(bytes([0x22]) * 32).public_key
    address = AccountAddress.from_account(public_key=public_key)
    return address.canonical_hex()


def _governance_lock_payload(amount: object) -> dict[str, Any]:
    return {
        "owner": CANONICAL_AUTHORITY,
        "amount": amount,
        "slashed": "0.25",
        "expiry_height": 10,
        "direction": 1,
        "duration_blocks": 5,
        "custody": {
            "escrowed": True,
            "asset_definition_id": "xor#wonderland",
            "bond_escrow_account": CANONICAL_AUTHORITY,
            "slash_receiver_account": CANONICAL_AUTHORITY,
        },
    }


def _governance_mutation_payloads() -> tuple[tuple[str, str, dict[str, Any]], ...]:
    return (
        (
            "governance_deploy_contract_proposal",
            "/v1/gov/proposals/deploy-contract",
            {
                "contract_alias": "router::universal",
                "abi_version": 1,
                "code_hash": "11" * 32,
                "abi_hash": "22" * 32,
                "manifest_provenance": {
                    "signer": "ed25519:public",
                    "signature": "signature",
                },
            },
        ),
        (
            "governance_submit_plain_ballot",
            "/v1/gov/ballots/plain",
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "referendum_id": "referendum-1",
                "owner": CANONICAL_AUTHORITY,
                "amount": CANONICAL_LARGE_FRACTION,
                "duration_blocks": 5,
                "direction": "Aye",
            },
        ),
        (
            "governance_submit_zk_ballot_v1",
            "/v1/gov/ballots/zk-v1",
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "backend": "halo2/ipa",
                "envelope_b64": "AAAA",
            },
        ),
        (
            "governance_submit_zk_ballot_proof_v1",
            "/v1/gov/ballots/zk-v1/ballot-proof",
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "ballot": {
                    "backend": "halo2/ipa",
                    "envelope_bytes": "AAE=",
                },
            },
        ),
    )


def _governance_deploy_draft_response() -> dict[str, Any]:
    return {
        "proposal_id": "11" * 32,
        "tx_instructions": [
            {
"wire_id": "iroha.instruction.v1::governance::ProposeDeployContract",
                "payload_hex": "00ff",
            }
        ],
    }


def _governance_ballot_draft_response() -> dict[str, Any]:
    return {
        "drafted": True,
        "tx_instructions": [
            {
                "wire_id": "CastZkBallot",
                "payload_hex": "00",
            }
        ],
    }


def _governance_client(session: RecordingSession) -> ToriiClient:
    return ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=LocalSigningContext(GOVERNANCE_NETWORK_ID),
        sorafs_alias_policy=TEST_SORAFS_ALIAS_POLICY,
        chain_discriminant=753,
    )


_GOVERNANCE_BALLOT_METHODS = frozenset(
    {
        "governance_submit_plain_ballot",
        "governance_submit_zk_ballot_v1",
        "governance_submit_zk_ballot_proof_v1",
    }
)
_GOVERNANCE_CANONICAL_AUTH_METHODS = _GOVERNANCE_BALLOT_METHODS | {
    "governance_deploy_contract_proposal",
}


def _invoke_governance(client: ToriiClient, method_name: str, payload: Mapping[str, Any]) -> Any:
    method = getattr(client, method_name)
    if method_name in _GOVERNANCE_CANONICAL_AUTH_METHODS:
        return method(payload, canonical_auth=GOVERNANCE_AUTH)
    return method(payload)


def test_governance_legacy_zk_ballot_surface_is_absent() -> None:
    assert not hasattr(ToriiClient, "governance_submit_zk_ballot")
    assert hasattr(ToriiClient, "governance_submit_zk_ballot_v1")
    assert hasattr(ToriiClient, "governance_submit_zk_ballot_proof_v1")


def test_proposal_backed_legacy_governance_surfaces_are_absent() -> None:
    for method in (
        "governance_submit_parliament_ballot",
        "governance_finalize_referendum",
        "governance_enact_proposal",
    ):
        assert not hasattr(ToriiClient, method)


def test_high_level_parliament_request_preserves_credential_free_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        requests.sessions,
        "get_netrc_auth",
        lambda _url: ("ambient-user", "ambient-password"),
    )
    session = RecordingSession(StubResponse(payload={}))
    client = _governance_client(session)

    with pytest.raises(TypeError, match="governance capabilities response"):
        client.get_governance_capabilities_v1(canonical_auth=GOVERNANCE_AUTH)

    assert len(session.calls) == 1
    assert "Authorization" not in session.calls[0]["headers"]


@pytest.mark.parametrize(
    "credential_kind",
    ["auth_token", "api_token", "session_auth", "session_cookie", "proxy_auth"],
)
def test_high_level_parliament_request_rejects_ambient_credentials(
    credential_kind: str,
) -> None:
    session = RecordingSession(StubResponse(payload={}))
    client = _governance_client(session)
    if credential_kind == "auth_token":
        client.set_auth_token("ambient-bearer")
    elif credential_kind == "api_token":
        client.set_api_token("ambient-api-token")
    elif credential_kind == "session_auth":
        session.auth = ("ambient-user", "ambient-password")
    elif credential_kind == "session_cookie":
        session.cookies.set("session", "ambient-cookie")
    else:
        session.proxies["http"] = "http://ambient-user:ambient-password@proxy.test:8080"

    with pytest.raises(ValueError, match=r"(?:credential|ambient|proxy)"):
        client.get_governance_capabilities_v1(canonical_auth=GOVERNANCE_AUTH)

    assert session.calls == []


def test_governance_ballot_rejects_foreign_network_and_retired_identity_before_dispatch() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[1][2]

    with pytest.raises(ValueError, match="local_signing_context"):
        client.governance_submit_plain_ballot(
            {**payload, "network_id": FOREIGN_GOVERNANCE_NETWORK_ID},
            canonical_auth=GOVERNANCE_AUTH,
        )
    for retired in ("chain_id", "chainId", "genesis_hash", "genesisHash"):
        with pytest.raises(ValueError, match="is retired"):
            client.governance_submit_plain_ballot(
                {**payload, retired: "legacy"},
                canonical_auth=GOVERNANCE_AUTH,
            )
    assert session.calls == []


def test_governance_ballot_binds_canonical_principal_before_dispatch() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    other_public_key = Ed25519KeyPair.from_private_key(bytes([0x33]) * 32).public_key
    other = AccountAddress.from_account(
        public_key=other_public_key,
    ).to_i105(0x02F1)
    mismatched_auth = ToriiCanonicalRequestAuth(
        network_id=GOVERNANCE_NETWORK_ID.literal,
        account_id=other,
        signer=lambda _message: bytes([0x55]) * 64,
    )
    with pytest.raises(ValueError, match="must equal payload authority"):
        client.governance_submit_plain_ballot(
            _governance_mutation_payloads()[1][2],
            canonical_auth=mismatched_auth,
        )
    assert session.calls == []


def test_governance_ballot_307_is_one_shot_even_when_post_retries_are_configured() -> None:
    session = RecordingSession(StubResponse(status_code=307, payload={"redirect": True}))
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=LocalSigningContext(GOVERNANCE_NETWORK_ID),
        retry_on_methods=["POST"],
        max_retries=4,
        sorafs_alias_policy=TEST_SORAFS_ALIAS_POLICY,
        chain_discriminant=753,
    )
    with pytest.raises(RuntimeError, match="unexpected status 307"):
        client.governance_submit_plain_ballot(
            _governance_mutation_payloads()[1][2],
            canonical_auth=GOVERNANCE_AUTH,
        )
    assert len(session.calls) == 1


def test_governance_get_identifiers_are_canonical_unreserved_path_segments() -> None:
    session = RecordingSession(StubResponse(status_code=404))
    client = _governance_client(session)
    proposal_id = "ab" * 32

    assert client.get_governance_proposal(
        proposal_id, canonical_auth=GOVERNANCE_AUTH
    ) is None
    assert client.get_governance_referendum(
        "ref.one~1", canonical_auth=GOVERNANCE_AUTH
    ) is None
    assert client.get_governance_tally(
        "ref_two-2", canonical_auth=GOVERNANCE_AUTH
    ) is None
    assert client.get_governance_locks(
        "Ref3", canonical_auth=GOVERNANCE_AUTH
    ) is None

    assert [call["url"] for call in session.calls] == [
        f"http://node.test/v1/gov/proposals/{proposal_id}",
        "http://node.test/v1/gov/referenda/ref.one~1",
        "http://node.test/v1/gov/tally/ref_two-2",
        "http://node.test/v1/gov/locks/Ref3",
    ]


@pytest.mark.parametrize(
    ("method_name", "identifier"),
    [
        ("get_governance_proposal", "AB" * 32),
        ("get_governance_proposal", "0x" + "ab" * 32),
        ("get_governance_proposal", " " + "ab" * 32),
        ("get_governance_proposal", "proposal/segment"),
        ("get_governance_referendum", " ref-1"),
        ("get_governance_referendum", "ref 1"),
        ("get_governance_referendum", "ref/1"),
        ("get_governance_referendum", ".hidden"),
        ("get_governance_referendum", "ref%31"),
        ("get_governance_referendum", "投票"),
        ("get_governance_tally", "ref\t1"),
        ("get_governance_tally", "ref\u20031"),
        ("get_governance_tally", "a" * 129),
        ("get_governance_locks", "ref\x001"),
    ],
)
def test_governance_get_identifiers_fail_before_dispatch(
    method_name: str,
    identifier: str,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises((TypeError, ValueError)):
        getattr(client, method_name)(identifier)

    assert session.calls == []


@pytest.mark.parametrize("selector", ["ref/1", ".hidden", "ref%31", "投票", "a" * 129])
@pytest.mark.parametrize("payload_index", [1, 2, 3])
def test_governance_draft_identifiers_share_canonical_selector_grammar(
    selector: str,
    payload_index: int,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    method_name, _path, payload = _governance_mutation_payloads()[payload_index]
    selector_field = "referendum_id" if payload_index == 1 else "election_id"

    with pytest.raises(ValueError, match="RFC 3986"):
        _invoke_governance(client, method_name, {**payload, selector_field: selector})

    assert session.calls == []


@pytest.mark.parametrize(
    ("method_name", "_path", "payload"),
    _governance_mutation_payloads(),
)
@pytest.mark.parametrize("secret_field", GOVERNANCE_PRIVATE_KEY_ALIASES)
def test_governance_mutations_reject_all_private_key_aliases_before_dispatch(
    method_name: str,
    _path: str,
    payload: dict[str, Any],
    secret_field: str,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="does not accept private-key fields"):
        _invoke_governance(client, method_name, {**payload, secret_field: "must-not-cross-torii"})

    assert session.calls == []


@pytest.mark.parametrize(
    ("method_name", "_path", "payload"),
    _governance_mutation_payloads(),
)
@pytest.mark.parametrize("secret_field", GOVERNANCE_PRIVATE_KEY_ALIASES)
def test_governance_mutations_reject_all_nested_private_key_aliases_before_dispatch(
    method_name: str,
    _path: str,
    payload: dict[str, Any],
    secret_field: str,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    nested = {"items": [{secret_field: "must-not-cross-torii"}]}

    with pytest.raises(ValueError, match="does not accept private-key fields"):
        _invoke_governance(client, method_name, {**payload, "nested": nested})

    assert session.calls == []


@pytest.mark.parametrize(
    ("method_name", "_path", "payload"),
    _governance_mutation_payloads(),
)
def test_governance_mutations_reject_unknown_fields_before_dispatch(
    method_name: str,
    _path: str,
    payload: dict[str, Any],
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="unknown field `future_signing_policy`"):
        _invoke_governance(client, method_name, {**payload, "future_signing_policy": None})

    assert session.calls == []


@pytest.mark.parametrize("secret_field", GOVERNANCE_PRIVATE_KEY_ALIASES)
def test_governance_ballot_proof_rejects_nested_private_key_aliases_before_dispatch(
    secret_field: str,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[3][2]
    ballot = {**payload["ballot"], secret_field: "must-not-cross-torii"}

    with pytest.raises(ValueError, match="does not accept private-key fields"):
        client.governance_submit_zk_ballot_proof_v1(
            {**payload, "ballot": ballot},
            canonical_auth=GOVERNANCE_AUTH,
        )

    assert session.calls == []


def test_governance_ballot_proof_rejects_unknown_nested_field_before_dispatch() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[3][2]
    ballot = {**payload["ballot"], "future_proof_format": None}

    with pytest.raises(ValueError, match="unknown field `future_proof_format`"):
        client.governance_submit_zk_ballot_proof_v1(
            {**payload, "ballot": ballot},
            canonical_auth=GOVERNANCE_AUTH,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "ballot",
    [
        {"envelope_bytes": "AAE="},
        {"backend": "halo2/ipa"},
        {"backend": None, "envelope_bytes": "AAE="},
        {"backend": "", "envelope_bytes": "AAE="},
        {"backend": " halo2/ipa", "envelope_bytes": "AAE="},
        {"backend": "halo2/ipa", "envelope_bytes": None},
        {"backend": "halo2/ipa", "envelope_bytes": ""},
        {"backend": "halo2/ipa", "envelope_bytes": "%%%"},
        {"backend": "halo2/ipa", "envelope_bytes": 1},
    ],
)
def test_governance_ballot_proof_requires_typed_nonempty_proof_fields(
    ballot: dict[str, Any],
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[3][2]

    with pytest.raises((TypeError, ValueError)):
        client.governance_submit_zk_ballot_proof_v1(
            {**payload, "ballot": ballot},
            canonical_auth=GOVERNANCE_AUTH,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "backend",
    ["", " halo2/ipa", "halo2/ipa ", "halo2 ipa", "halo2\nipa", "halo2\x00ipa"],
)
@pytest.mark.parametrize(
    "method_name",
    ["governance_submit_zk_ballot_v1", "governance_submit_zk_ballot_proof_v1"],
)
def test_governance_zk_v1_requires_exact_backend_tokens_before_dispatch(
    method_name: str,
    backend: str,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    if method_name == "governance_submit_zk_ballot_v1":
        payload = {**_governance_mutation_payloads()[2][2], "backend": backend}
    else:
        base = _governance_mutation_payloads()[3][2]
        payload = {
            **base,
            "ballot": {**base["ballot"], "backend": backend},
        }

    with pytest.raises((TypeError, ValueError), match="backend"):
        _invoke_governance(client, method_name, payload)

    assert session.calls == []


@pytest.mark.parametrize(
    ("method_name", "payload"),
    [
        ("governance_submit_zk_ballot_v1", {"envelope_b64": ""}),
        ("governance_submit_zk_ballot_v1", {"envelope_b64": "%%%"}),
        ("governance_submit_zk_ballot_v1", {"chain_id": " chain"}),
        ("governance_submit_zk_ballot_proof_v1", {"election_id": "election 1"}),
    ],
)
def test_governance_zk_routes_validate_context_and_envelope_before_dispatch(
    method_name: str,
    payload: dict[str, Any],
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    index = {
        "governance_submit_zk_ballot_v1": 2,
        "governance_submit_zk_ballot_proof_v1": 3,
    }[method_name]
    base = _governance_mutation_payloads()[index][2]

    with pytest.raises((TypeError, ValueError)):
        _invoke_governance(client, method_name, {**base, **payload})

    assert session.calls == []


@pytest.mark.parametrize("namespace", ["", " system", "system ", "system namespace", "systèm", 7])
def test_protected_namespaces_require_exact_ascii_tokens_before_dispatch(
    namespace: Any,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises((TypeError, ValueError)):
        client.set_protected_namespaces([namespace])

    assert session.calls == []


@pytest.mark.parametrize(
    ("method_name", "path", "payload"),
    _governance_mutation_payloads(),
)
def test_governance_mutations_preserve_supported_canonical_payloads(
    method_name: str,
    path: str,
    payload: dict[str, Any],
) -> None:
    response_payload = (
        _governance_deploy_draft_response()
        if method_name == "governance_deploy_contract_proposal"
        else _governance_ballot_draft_response()
    )
    session = RecordingSession(StubResponse(payload=response_payload))
    client = _governance_client(session)

    _invoke_governance(client, method_name, payload)

    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "POST"
    assert session.calls[0]["url"] == f"http://node.test{path}"
    expected = dict(payload)
    if method_name in _GOVERNANCE_BALLOT_METHODS:
        expected["network_id"] = GOVERNANCE_NETWORK_ID.literal
        assert "chain_id" not in expected
    if method_name in _GOVERNANCE_CANONICAL_AUTH_METHODS:
        assert session.calls[0]["headers"]["X-Iroha-Account"] == CANONICAL_AUTHORITY_HEADER
        assert "X-Iroha-Signature" in session.calls[0]["headers"]
    if method_name == "governance_submit_plain_ballot":
        expected["duration_blocks"] = str(payload["duration_blocks"])
    assert json.loads(session.calls[0]["data"].decode("utf-8")) == expected


def test_governance_deploy_rejects_retired_controls_and_unknown_nested_objects() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[0][2]

    with pytest.raises(ValueError, match="unknown field `limits`"):
        client.governance_deploy_contract_proposal(
            {**payload, "limits": {"fuel": 100}}, canonical_auth=GOVERNANCE_AUTH
        )
    with pytest.raises(ValueError, match="unknown field `algorithm`"):
        client.governance_deploy_contract_proposal(
            {
                **payload,
                "manifest_provenance": {
                    **payload["manifest_provenance"],
                    "algorithm": "ed25519",
                },
            },
            canonical_auth=GOVERNANCE_AUTH,
        )
    for retired_field, retired_value in (
        ("window", {"lower": 10, "upper": 20}),
        ("mode", "Zk"),
    ):
        with pytest.raises(ValueError, match=f"unknown field `{retired_field}`"):
            client.governance_deploy_contract_proposal(
                {**payload, retired_field: retired_value},
                canonical_auth=GOVERNANCE_AUTH,
            )

    assert session.calls == []


def test_governance_deploy_preserves_exact_manifest_provenance_wire_object() -> None:
    session = RecordingSession(
        StubResponse(payload=_governance_deploy_draft_response())
    )
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[0][2]

    draft = client.governance_deploy_contract_proposal(
        payload, canonical_auth=GOVERNANCE_AUTH
    )

    encoded = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert encoded["manifest_provenance"] == payload["manifest_provenance"]
    assert draft.proposal_id == "11" * 32
    assert len(draft.tx_instructions) == 1


@pytest.mark.parametrize(
    "response_payload",
    [
        {"ok": True},
        {
            **_governance_deploy_draft_response(),
            "ok": True,
        },
        {
            "proposal_id": "11" * 32,
            "tx_instructions": [
                {
                    "wire_id": "ProposeDeployContract",
                    "payload_hex": "00ff",
                }
            ],
        },
    ],
)
def test_governance_deploy_rejects_noncanonical_draft_response(
    response_payload: dict[str, Any],
) -> None:
    session = RecordingSession(StubResponse(payload=response_payload))
    client = _governance_client(session)

    with pytest.raises(RuntimeError):
        client.governance_deploy_contract_proposal(
            _governance_mutation_payloads()[0][2],
            canonical_auth=GOVERNANCE_AUTH,
        )


@pytest.mark.parametrize(
    "manifest_provenance",
    [
        {"signer": "ed25519:public"},
        {"signature": "signature"},
        {"signer": "", "signature": "signature"},
        {"signer": "ed25519:public", "signature": ""},
        {"signer": " ed25519:public", "signature": "signature"},
        {"signer": "ed25519:public", "signature": "signature "},
        {"signer": 1, "signature": "signature"},
        {"signer": "ed25519:public", "signature": b"signature"},
    ],
)
def test_governance_deploy_rejects_incomplete_or_non_string_provenance(
    manifest_provenance: dict[str, Any],
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = _governance_mutation_payloads()[0][2]

    with pytest.raises((TypeError, ValueError)):
        client.governance_deploy_contract_proposal(
            {**payload, "manifest_provenance": manifest_provenance},
            canonical_auth=GOVERNANCE_AUTH,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        {"contract_address": "addr"},
        {"contract_alias": None},
        {"abi_version": None},
        {"abi_version": "1"},
        {"abi_version": 2},
        {"abi_version": True},
        {"code_hash": None},
        {"abi_hash": None},
        {"code_hash": ":" + "11" * 32},
        {"code_hash": " " + "11" * 32},
        {"code_hash": "11" * 32 + " "},
        {"code_hash": "AA" * 32},
        {"code_hash": "blake2b32:" + "11" * 32 + ":ignored"},
        {"code_hash": "sha256:" + "11" * 32},
        {"code_hash_hex": "11" * 32},
        {"abi_hash_hex": "22" * 32},
    ],
)
def test_governance_deploy_rejects_invalid_required_contract_before_dispatch(
    mutation: dict[str, Any],
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    payload = {**_governance_mutation_payloads()[0][2], **mutation}

    with pytest.raises((TypeError, ValueError)):
        client.governance_deploy_contract_proposal(
            payload, canonical_auth=GOVERNANCE_AUTH
        )

    assert session.calls == []


def test_governance_deploy_requires_exactly_one_target() -> None:
    session = RecordingSession(
        StubResponse(payload=_governance_deploy_draft_response())
    )
    client = _governance_client(session)
    base = _governance_mutation_payloads()[0][2]

    without_target = dict(base)
    without_target.pop("contract_alias")
    with pytest.raises(ValueError, match="exactly one"):
        client.governance_deploy_contract_proposal(
            without_target, canonical_auth=GOVERNANCE_AUTH
        )
    with pytest.raises(ValueError, match="exactly one"):
        client.governance_deploy_contract_proposal(
            {**base, "contract_address": "contract-address"},
            canonical_auth=GOVERNANCE_AUTH,
        )
    assert session.calls == []

    client.governance_deploy_contract_proposal(base, canonical_auth=GOVERNANCE_AUTH)
    encoded = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert "window" not in encoded
    assert "mode" not in encoded


def test_governance_deploy_proposal_read_model_uses_typed_field_names() -> None:
    payload = {
        "contract_address": "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        "code_hash": "11" * 32,
        "abi_hash": "22" * 32,
        "abi_version": 1,
        "manifest_provenance": {
            "signer": "ed25519:public",
            "signature": "signature",
        },
    }

    proposal = GovernanceProposalDeployContract.from_payload(payload)

    assert proposal.code_hash == payload["code_hash"]
    assert proposal.abi_hash == payload["abi_hash"]
    assert proposal.abi_version == 1
    assert proposal.manifest_provenance == GovernanceManifestProvenance(
        signer="ed25519:public",
        signature="signature",
    )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "contract_address": "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            "code_hash_hex": "11" * 32,
            "abi_hash": "22" * 32,
            "abi_version": 1,
        },
        {
            "contract_address": "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            "code_hash": "11" * 32,
            "abi_hash": "22" * 32,
            "abi_version": "1",
        },
        {
            "contract_address": "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            "code_hash": "11" * 32,
            "abi_hash": "22" * 32,
            "abi_version": 1,
        },
    ],
)
def test_governance_deploy_proposal_read_model_rejects_old_shapes(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(TypeError):
        GovernanceProposalDeployContract.from_payload(payload)


def test_governance_lock_record_preserves_fraction_above_u64() -> None:
    record = GovernanceLockRecord.from_payload(_governance_lock_payload(CANONICAL_LARGE_FRACTION))
    assert record.amount == CANONICAL_LARGE_FRACTION
    assert record.slashed == "0.25"
    assert record.custody is not None
    assert isinstance(record.custody, GovernanceLockCustody)
    assert record.custody.escrowed is True
    assert record.custody.asset_definition_id == "xor#wonderland"


def test_governance_lock_record_accepts_explicit_null_custody() -> None:
    payload = _governance_lock_payload("1")
    payload["custody"] = None
    assert GovernanceLockRecord.from_payload(payload).custody is None


def test_governance_lock_record_requires_strict_nullable_custody() -> None:
    missing = _governance_lock_payload("1")
    del missing["custody"]
    with pytest.raises(TypeError, match="custody"):
        GovernanceLockRecord.from_payload(missing)

    extra = _governance_lock_payload("1")
    assert isinstance(extra["custody"], dict)
    extra["custody"]["legacy"] = True
    with pytest.raises(TypeError, match="exactly"):
        GovernanceLockRecord.from_payload(extra)

    incomplete = _governance_lock_payload("1")
    assert isinstance(incomplete["custody"], dict)
    del incomplete["custody"]["bond_escrow_account"]
    with pytest.raises(TypeError, match="exactly"):
        GovernanceLockRecord.from_payload(incomplete)

    wrong = _governance_lock_payload("1")
    assert isinstance(wrong["custody"], dict)
    wrong["custody"]["escrowed"] = 1
    with pytest.raises(TypeError, match="escrowed"):
        GovernanceLockRecord.from_payload(wrong)

    padded = _governance_lock_payload("1")
    assert isinstance(padded["custody"], dict)
    padded["custody"]["asset_definition_id"] = " xor#wonderland"
    with pytest.raises(TypeError, match="whitespace"):
        GovernanceLockRecord.from_payload(padded)


@pytest.mark.parametrize(
    "amount",
    [1, 1.5, "+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", "9" * 155],
)
def test_governance_lock_record_rejects_noncanonical_quantity(amount: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        GovernanceLockRecord.from_payload(_governance_lock_payload(amount))


@pytest.mark.parametrize(
    "slashed",
    [1, 1.5, "+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", "9" * 155],
)
def test_governance_lock_record_rejects_noncanonical_slashed_quantity(
    slashed: object,
) -> None:
    payload = _governance_lock_payload("1")
    payload["slashed"] = slashed
    with pytest.raises((TypeError, ValueError)):
        GovernanceLockRecord.from_payload(payload)


def test_governance_submit_plain_ballot_requires_canonical_quantity() -> None:
    session = RecordingSession(StubResponse(payload=_governance_ballot_draft_response()))
    client = _governance_client(session)
    payload = {
        "authority": CANONICAL_AUTHORITY,
        "network_id": GOVERNANCE_NETWORK_ID,
        "referendum_id": "ref-1",
        "owner": CANONICAL_AUTHORITY,
        "amount": CANONICAL_LARGE_FRACTION,
        "duration_blocks": 5,
        "direction": "Aye",
    }

    client.governance_submit_plain_ballot(payload, canonical_auth=GOVERNANCE_AUTH)
    encoded = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert encoded["amount"] == CANONICAL_LARGE_FRACTION
    assert encoded["duration_blocks"] == "5"

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
        with pytest.raises((TypeError, ValueError)):
            client.governance_submit_plain_ballot(
                {**payload, "amount": invalid},
                canonical_auth=GOVERNANCE_AUTH,
            )


def test_governance_submit_plain_ballot_dispatches_zero_as_canonical_decimal() -> None:
    session = RecordingSession(StubResponse(payload=_governance_ballot_draft_response()))
    client = _governance_client(session)

    client.governance_submit_plain_ballot(
        {
            "authority": CANONICAL_AUTHORITY,
            "network_id": GOVERNANCE_NETWORK_ID,
            "referendum_id": "ref-zero",
            "owner": CANONICAL_AUTHORITY,
            "amount": "1",
            "duration_blocks": 0,
            "direction": "Abstain",
        },
        canonical_auth=GOVERNANCE_AUTH,
    )

    assert len(session.calls) == 1
    encoded = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert encoded["duration_blocks"] == "0"


@pytest.mark.parametrize("direction", ["aye", "Approve", " Aye", "Aye ", "", 1])
def test_governance_ballot_directions_reject_noncanonical_values_before_dispatch(
    direction: Any,
) -> None:
    base_payloads = _governance_mutation_payloads()
    cases = (
        (
            "governance_submit_plain_ballot",
            {**base_payloads[1][2], "direction": direction},
        ),
        (
            "governance_submit_zk_ballot_v1",
            {**base_payloads[2][2], "direction": direction},
        ),
        (
            "governance_submit_zk_ballot_proof_v1",
            {
                **base_payloads[3][2],
                "ballot": {**base_payloads[3][2]["ballot"], "direction": direction},
            },
        ),
    )

    for method_name, payload in cases:
        session = RecordingSession(StubResponse(payload={"ok": True}))
        client = _governance_client(session)
        with pytest.raises((TypeError, ValueError), match="Aye, Nay, or Abstain"):
            _invoke_governance(client, method_name, payload)
        assert session.calls == []


@pytest.mark.parametrize(
    "amount",
    [1, 1.5, "+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", "9" * 155],
)
def test_governance_zk_v1_lock_hints_reject_noncanonical_quantity(
    amount: object,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises((TypeError, ValueError)):
        client.governance_submit_zk_ballot_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "backend": "halo2/ipa",
                "envelope_b64": "AAAA",
                "owner": CANONICAL_AUTHORITY,
                "amount": amount,
                "duration_blocks": 5,
            },
            canonical_auth=GOVERNANCE_AUTH,
        )
    with pytest.raises((TypeError, ValueError)):
        client.governance_submit_zk_ballot_proof_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "ballot": {
                    "backend": "halo2/ipa",
                    "envelope_bytes": "AAE=",
                    "owner": CANONICAL_AUTHORITY,
                    "amount": amount,
                    "duration_blocks": 5,
                },
            },
            canonical_auth=GOVERNANCE_AUTH,
        )


def test_governance_submit_zk_ballot_v1_rejects_incomplete_lock_hints() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="owner, amount, duration_blocks"):
        client.governance_submit_zk_ballot_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "backend": "halo2/ipa",
                "envelope_b64": "AAAA",
                "owner": _canonical_owner_literal(),
            },
            canonical_auth=GOVERNANCE_AUTH,
        )


def test_governance_submit_zk_ballot_v1_rejects_noncanonical_owner() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="canonical I105"):
        client.governance_submit_zk_ballot_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "backend": "halo2/ipa",
                "envelope_b64": "AAAA",
                "owner": _noncanonical_owner_literal(),
                "amount": "100",
                "duration_blocks": 5,
            },
            canonical_auth=GOVERNANCE_AUTH,
        )


def test_governance_submit_zk_ballot_proof_v1_rejects_incomplete_lock_hints() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="owner, amount, duration_blocks"):
        client.governance_submit_zk_ballot_proof_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "ballot": {
                    "backend": "halo2/ipa",
                    "envelope_bytes": "AAE=",
                    "owner": _canonical_owner_literal(),
                },
            },
            canonical_auth=GOVERNANCE_AUTH,
        )


def test_governance_submit_zk_ballot_proof_v1_rejects_noncanonical_owner() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="canonical I105"):
        client.governance_submit_zk_ballot_proof_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "ballot": {
                    "backend": "halo2/ipa",
                    "envelope_bytes": "AAE=",
                    "owner": _noncanonical_owner_literal(),
                    "amount": "100",
                    "duration_blocks": 5,
                },
            },
            canonical_auth=GOVERNANCE_AUTH,
        )


def test_governance_submit_zk_ballot_proof_v1_normalizes_hex_hints() -> None:
    session = RecordingSession(StubResponse(payload=_governance_ballot_draft_response()))
    client = _governance_client(session)

    client.governance_submit_zk_ballot_proof_v1(
        {
            "authority": CANONICAL_AUTHORITY,
            "network_id": GOVERNANCE_NETWORK_ID,
            "election_id": "election-1",
            "ballot": {
                "backend": "halo2/ipa",
                "envelope_bytes": "AAE=",
                "root_hint": f"blake2b32:{'Aa' * 32}",
                "nullifier": bytes.fromhex("BB" * 32),
                "owner": CANONICAL_AUTHORITY,
                "amount": CANONICAL_LARGE_FRACTION,
                "duration_blocks": 5,
            },
        },
        canonical_auth=GOVERNANCE_AUTH,
    )

    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    ballot = payload["ballot"]
    assert ballot["root_hint"] == "aa" * 32
    assert ballot["nullifier"] == "bb" * 32
    assert ballot["amount"] == CANONICAL_LARGE_FRACTION


@pytest.mark.parametrize("duration_blocks", [0, "0", (1 << 64) - 1, str((1 << 64) - 1)])
@pytest.mark.parametrize(
    "method_name",
    [
        "governance_submit_zk_ballot_v1",
        "governance_submit_zk_ballot_proof_v1",
    ],
)
def test_governance_zk_v1_durations_emit_full_u64_json_integers(
    method_name: str,
    duration_blocks: Any,
) -> None:
    session = RecordingSession(StubResponse(payload=_governance_ballot_draft_response()))
    client = _governance_client(session)
    direction = "Nay" if method_name == "governance_submit_zk_ballot_v1" else "Abstain"
    lock_hints = {
        "owner": CANONICAL_AUTHORITY,
        "amount": "1",
        "duration_blocks": duration_blocks,
        "direction": direction,
    }
    if method_name == "governance_submit_zk_ballot_v1":
        payload = {**_governance_mutation_payloads()[2][2], **lock_hints}
    else:
        base = _governance_mutation_payloads()[3][2]
        payload = {**base, "ballot": {**base["ballot"], **lock_hints}}

    _invoke_governance(client, method_name, payload)

    encoded = json.loads(session.calls[0]["data"].decode("utf-8"))
    wire = encoded if method_name == "governance_submit_zk_ballot_v1" else encoded["ballot"]
    assert wire["duration_blocks"] == int(duration_blocks)
    assert isinstance(wire["duration_blocks"], int)
    assert wire["direction"] == direction


@pytest.mark.parametrize(
    "duration_blocks",
    [-1, 1 << 64, str(1 << 64), "01", "+1", True, 1.0],
)
@pytest.mark.parametrize(
    "method_name",
    [
        "governance_submit_zk_ballot_v1",
        "governance_submit_zk_ballot_proof_v1",
    ],
)
def test_governance_zk_v1_durations_reject_non_u64_values_before_dispatch(
    method_name: str,
    duration_blocks: Any,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)
    lock_hints = {
        "owner": CANONICAL_AUTHORITY,
        "amount": "1",
        "duration_blocks": duration_blocks,
    }
    if method_name == "governance_submit_zk_ballot_v1":
        payload = {**_governance_mutation_payloads()[2][2], **lock_hints}
    else:
        base = _governance_mutation_payloads()[3][2]
        payload = {**base, "ballot": {**base["ballot"], **lock_hints}}

    with pytest.raises((TypeError, ValueError)):
        _invoke_governance(client, method_name, payload)

    assert session.calls == []


def test_governance_submit_zk_ballot_v1_normalizes_hex_hints() -> None:
    session = RecordingSession(StubResponse(payload=_governance_ballot_draft_response()))
    client = _governance_client(session)

    client.governance_submit_zk_ballot_v1(
        {
            "authority": CANONICAL_AUTHORITY,
            "network_id": GOVERNANCE_NETWORK_ID,
            "election_id": "election-1",
            "backend": "halo2/ipa",
            "envelope_b64": "AAAA",
            "root_hint": f"0x{'Aa' * 32}",
            "nullifier": f"blake2b32:{'BB' * 32}",
        },
        canonical_auth=GOVERNANCE_AUTH,
    )

    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["root_hint"] == "aa" * 32
    assert payload["nullifier"] == "bb" * 32


@pytest.mark.parametrize(
    "root_hint",
    [
        "not-hex",
        ":" + "aa" * 32,
        " " + "aa" * 32,
        "aa" * 32 + " ",
        "blake2b32:" + "aa" * 32 + ":ignored",
        "sha256:" + "aa" * 32,
    ],
)
def test_governance_submit_zk_ballot_v1_rejects_invalid_hex_hints(
    root_hint: str,
) -> None:
    session = RecordingSession(StubResponse(payload={"ok": True}))
    client = _governance_client(session)

    with pytest.raises(ValueError, match="root_hint"):
        client.governance_submit_zk_ballot_v1(
            {
                "authority": CANONICAL_AUTHORITY,
                "network_id": GOVERNANCE_NETWORK_ID,
                "election_id": "election-1",
                "backend": "halo2/ipa",
                "envelope_b64": "AAAA",
                "root_hint": root_hint,
            },
            canonical_auth=GOVERNANCE_AUTH,
        )

    assert session.calls == []
