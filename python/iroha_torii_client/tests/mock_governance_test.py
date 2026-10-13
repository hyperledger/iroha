"""Canonical governance request checks used by compiled CLI smoke tests."""

from __future__ import annotations

import json

import pytest
from iroha_torii_client.mock import _canonical_hash, _MockState

OWNER = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
CONTRACT_ADDRESS = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"


def test_proposal_mock_requires_the_canonical_operator_field() -> None:
    state = _MockState()
    payload = {
        "proposal_operator": OWNER,
        "contract_address": CONTRACT_ADDRESS,
        "abi_version": 1,
        "code_hash": "11" * 32,
        "abi_hash": "22" * 32,
    }
    assert state._gov_propose_deploy(json.dumps(payload).encode()).status == 200

    missing = dict(payload)
    del missing["proposal_operator"]
    with pytest.raises(ValueError, match="proposal_operator is required"):
        state._gov_propose_deploy(json.dumps(missing).encode())
    with pytest.raises(ValueError, match="unknown field"):
        state._gov_propose_deploy(json.dumps({**payload, "chain_id": "retired"}).encode())


@pytest.mark.parametrize("mode", ["plain", "zk"])
def test_ballot_mock_binds_every_expected_request_field(mode: str) -> None:
    payload = {
        "authority": OWNER,
        "network_id": _canonical_hash(0xA5),
        "owner": OWNER,
        "amount": "700",
        "duration_blocks": 256,
        "direction": "Nay",
    }
    if mode == "zk":
        payload.update(election_id="ref-test", backend="halo2/ipa", envelope_b64="AAA=")
    else:
        payload["referendum_id"] = "ref-test"
    state = _MockState()
    state._gov_config(json.dumps({
        "referenda": [{
            "id": "ref-test",
            "referendum": {"id": "ref-test", "mode": mode},
            f"ballot_{mode}_request": payload,
            f"ballot_{mode}_response": {"ok": True},
        }],
    }).encode())
    endpoint = state._gov_ballot_zk_v1 if mode == "zk" else state._gov_ballot_plain
    assert endpoint(json.dumps(payload).encode()).status == 200
    for changed in [
        {**payload, "network_id": _canonical_hash(0xA7)},
        {**payload, "authority": "another-authority"},
        {**payload, "amount": "701"},
        {**payload, "chain_id": "retired"},
    ]:
        with pytest.raises(ValueError, match="exact configured request|unknown field"):
            endpoint(json.dumps(changed).encode())
    missing_network = dict(payload)
    del missing_network["network_id"]
    with pytest.raises(ValueError, match="exact configured request|network_id"):
        endpoint(json.dumps(missing_network).encode())
