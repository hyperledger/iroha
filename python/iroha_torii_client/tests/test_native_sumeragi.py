"""Protocol-1 JSON codec controls, not generated finality or execution captures."""
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest
from iroha_torii_client.native_sumeragi import SumeragiStatus, parse_native_status_json

BASE = {'protocol_version': 1, 'config_fingerprint': 'hash:0101010101010101010101010101010101010101010101010101010101010101#B86C', 'beacon_horizon': None, 'instance': '0000000000000000000000000000000000000000000000000000000000000000', 'height': 1, 'view': 0, 'stage': 0, 'leader': None, 'proxy_tail': None, 'high_qc_view': None, 'level': 0, 'start_level': 0, 't_retx_ms': 1, 'committed_height': 0, 'applied_height': 0, 'awaiting': False, 'signer': None, 'unanchored': True, 'abstaining': True, 'halted': None, 'footprint': {'votes': 0, 'timeouts': 0, 'blocks': 0, 'exec_entries': 0, 'wants': 0, 'pending_apply': 0, 'sync_entries': 0, 'sync_bytes': 0, 'peers': 0, 'recent_headers': 0, 'configs': 0, 'cert_cache': 0, 'evidence_keys': 0, 'probe': 0}}

def parse(value):
    return SumeragiStatus.from_payload(parse_native_status_json(json.dumps(value).encode()))

def test_exact_observer_and_owned_native_values():
    value=deepcopy(BASE)
    status=parse(value)
    value["footprint"]["votes"]=123
    assert status.protocol_version==1 and status.leader is None
    assert status.footprint.votes==0
    with pytest.raises(FrozenInstanceError):
        status.height=9

@pytest.mark.parametrize("field", list(BASE))
def test_every_field_including_nullables_is_mandatory(field):
    value=deepcopy(BASE)
    del value[field]
    with pytest.raises((ValueError,TypeError)):
        parse(value)

@pytest.mark.parametrize("field", list(BASE["footprint"]))
def test_every_footprint_field_is_mandatory(field):
    value=deepcopy(BASE)
    del value["footprint"][field]
    with pytest.raises((ValueError,TypeError)):
        parse(value)

@pytest.mark.parametrize("field", ["height","view","t_retx_ms","committed_height","applied_height"])
def test_full_u64_and_overflow(field):
    value=deepcopy(BASE)
    value[field]=(1<<64)-1
    assert getattr(parse(value),field)==(1<<64)-1
    for bad in [(1<<64),-1,True,1.0,"1"]:
        value[field]=bad
        with pytest.raises((ValueError,TypeError)):
            parse(value)

@pytest.mark.parametrize("token", ["-0","-1","1.0","1e0","NaN","Infinity"])
def test_noncanonical_unsigned_tokens_fail(token):
    wire=json.dumps(BASE).replace('"height": 1','"height": '+token)
    with pytest.raises((ValueError,TypeError)):
        SumeragiStatus.from_payload(parse_native_status_json(wire.encode()))

@pytest.mark.parametrize("reason", ["safety_record_corrupt","safety_record_inconsistent","driver_anomaly","safety_violation","apply_diverged","publication_recovery_required"])
def test_all_native_halt_tags_and_explicit_details(reason):
    unit=reason in ["safety_record_corrupt","safety_record_inconsistent","driver_anomaly"]
    value=deepcopy(BASE)
    value["halted"]={"reason":reason,"details":None if unit else (1<<64)-1}
    assert parse(value).halted.reason==reason
    value["halted"]["details"]=1 if unit else None
    with pytest.raises((ValueError,TypeError)):
        parse(value)

def test_beacon_readiness_and_nested_shape():
    value=deepcopy(BASE)
    value["beacon_horizon"]={"epoch_length_blocks":10,"next_required_pulse_height":20,"active_session_id":"AB"*32,"session_covers_next_pulse":True,"local_provider_ready":True}
    assert parse(value).beacon_horizon.active_session_id=="AB"*32
    for field in list(value["beacon_horizon"]):
        bad=deepcopy(value)
        del bad["beacon_horizon"][field]
        with pytest.raises((ValueError,TypeError)):
            parse(bad)
    for field in ["active_session_id","next_required_pulse_height"]:
        bad=deepcopy(value)
        bad["beacon_horizon"][field]=None
        with pytest.raises((ValueError,TypeError)):
            parse(bad)

def test_duplicate_unknown_encoding_bound_and_retired_schema_rejected():
    wire=json.dumps(BASE)
    for raw in [b"\xff",b"",b" "*(1024*1024+1),wire.replace('"height": 1','"height": 1, "height": 1').encode(),b'{"protocol_version":4}']:
        with pytest.raises((ValueError,TypeError)):
            SumeragiStatus.from_payload(parse_native_status_json(raw))
    value=deepcopy(BASE)
    value["execution_commitment"]={}
    with pytest.raises((ValueError,TypeError)):
        parse(value)
    for field in ["config_fingerprint","instance"]:
        value=deepcopy(BASE)
        value[field]="00"
        with pytest.raises((ValueError,TypeError)):
            parse(value)


@pytest.mark.parametrize("field", ["leader", "proxy_tail", "signer"])
def test_public_keys_require_admitted_canonical_material(field):
    ed = "ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A"
    bls = "ea013097F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB"
    value = deepcopy(BASE)
    for key in [ed, bls]:
        value[field] = key
        assert getattr(parse(value), field) == key
    for key in [ed.lower(), bls.lower(), "ed0120" + "00" * 32,
                "ea0130" + "C0" + "00" * 47, "ea0130" + "00" * 48,
                "bls_normal:" + bls, "ed810020" + ed[6:], ed[:-2]]:
        value[field] = key
        with pytest.raises((ValueError, TypeError)):
            parse(value)


def test_native_status_transport_is_signed_bounded_and_closes_every_response():
    from iroha_torii_client import ToriiClient, ToriiOperatorSigningContext
    from sumeragi_exact_json_test_support import RecordingSession, StubResponse
    captured = []
    def signer(message):
        captured.append(message)
        return bytes([0x55]) * 64
    context = ToriiOperatorSigningContext(
        network_id=BASE["config_fingerprint"],
        public_key="ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A",
        signer=signer,
    )
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session, operator_signing_context=context)
    response = StubResponse(payload=BASE)
    session.queue(response)
    assert client.get_sumeragi_status().protocol_version == 1
    assert response.was_closed
    call = session.calls[-1]
    assert call["method"] == "GET" and call["url"] == "https://node.test/v1/sumeragi/status"
    assert call["stream"] is True and call["allow_redirects"] is False
    assert len(captured) == 1 and b"/v1/sumeragi/status" in captured[0]
    assert bytes.fromhex(BASE["config_fingerprint"][5:69]) in captured[0]
    assert not hasattr(client, "get_sumeragi_qc") and not hasattr(client, "get_sumeragi_diagnostics")
    bad_responses = [
        StubResponse(raw=b"{}", headers={"Content-Type": "text/plain"}),
        StubResponse(raw=b"\xff", headers={"Content-Type": "application/json"}),
        StubResponse(raw=json.dumps(BASE).replace('"height": 1', '"height": -0').encode(), headers={"Content-Type": "application/json"}),
        StubResponse(raw=b"{}", headers={"Content-Type": "application/json", "Content-Length": str(1024 * 1024 + 1)}),
        StubResponse(raw=b" " * (1024 * 1024 + 1), headers={"Content-Type": "application/json"}),
    ]
    for response in bad_responses:
        session.queue(response)
        with pytest.raises((ValueError, TypeError, RuntimeError)):
            client.get_sumeragi_status()
        assert response.was_closed


@pytest.mark.parametrize("version", [0, 2, 4, 8])
def test_first_release_status_rejects_other_protocol_versions(version):
    value = deepcopy(BASE)
    value["protocol_version"] = version
    with pytest.raises(ValueError):
        SumeragiStatus.from_payload(value)


def _status_corpus() -> dict[str, str]:
    """Rows of the shared Rust-produced `GET /v1/sumeragi/status` corpus."""
    from pathlib import Path

    for directory in Path(__file__).resolve().parents:
        path = directory / "fixtures" / "sumeragi" / "native_status_v1.tsv"
        if path.is_file():
            rows: dict[str, str] = {}
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith("#"):
                    continue
                name, payload, norito_hex = line.split("\t")
                assert name not in rows
                assert norito_hex.startswith("4e525430"), "producer must retain its Norito archive"
                rows[name] = payload
            return rows
    raise FileNotFoundError("fixtures/sumeragi/native_status_v1.tsv")


def test_rust_status_corpus_parses_every_served_field_and_halt_reason():
    from dataclasses import fields

    rows = _status_corpus()
    halts = {"safety_record_corrupt", "safety_record_inconsistent", "safety_violation",
             "apply_diverged", "publication_recovery_required", "driver_anomaly"}
    assert set(rows) == {"validator", "observer"} | halts
    model_fields = {field.name for field in fields(SumeragiStatus)}
    for name, payload in rows.items():
        served = json.loads(payload)
        assert set(served) == model_fields, name
        status = SumeragiStatus.from_payload(parse_native_status_json(payload.encode()))
        assert status.protocol_version == 1
        assert status.view == (1 << 64) - 1 and status.level == (1 << 32) - 1
        assert status.footprint.votes == (1 << 64) - 1
        assert set(served["footprint"]) == {field.name for field in fields(status.footprint)}
        if name in halts:
            assert status.halted is not None and status.halted.reason == name
            assert status.halted.details == served["halted"]["details"]
        else:
            assert status.halted is None
    validator = SumeragiStatus.from_payload(parse_native_status_json(rows["validator"].encode()))
    assert validator.leader is not None and validator.leader.startswith("ea0130")
    assert validator.beacon_horizon is not None and validator.beacon_horizon.local_provider_ready
    observer = SumeragiStatus.from_payload(parse_native_status_json(rows["observer"].encode()))
    assert (observer.leader, observer.proxy_tail, observer.signer, observer.beacon_horizon) == (None,) * 4
    assert observer.awaiting and observer.abstaining
