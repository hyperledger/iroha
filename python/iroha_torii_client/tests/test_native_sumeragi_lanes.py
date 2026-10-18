"""`GET /v1/sumeragi/lanes` parsing against the shared Rust-generated lane corpus."""
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from iroha_torii_client.native_sumeragi import (
    LANES_MAX_BYTES,
    SumeragiDataAvailabilityLayout,
    SumeragiLaneStatus,
    parse_native_lanes,
    parse_native_lanes_json,
)

U64_MAX = (1 << 64) - 1
U32_MAX = (1 << 32) - 1


def _fixture_rows() -> dict[str, str]:
    for directory in Path(__file__).resolve().parents:
        path = directory / "fixtures" / "sumeragi" / "native_lanes_v1.tsv"
        if path.is_file():
            rows: dict[str, str] = {}
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith("#"):
                    continue
                name, payload, norito_hex = line.split("\t")
                assert name not in rows
                assert norito_hex.startswith("4e525430"), "producer must retain its Norito archive"
                rows[name] = payload
            assert set(rows) == {"empty", "running_lane", "mixed_lanes"}
            return rows
    raise FileNotFoundError("fixtures/sumeragi/native_lanes_v1.tsv")


ROWS = _fixture_rows()


def _lanes() -> list:
    return json.loads(ROWS["mixed_lanes"])


def _parse(value) -> list[SumeragiLaneStatus]:
    return parse_native_lanes_json(json.dumps(value).encode())


def test_rust_corpus_keeps_every_lane_state_and_unsigned_range():
    assert parse_native_lanes_json(ROWS["empty"].encode()) == []
    [running] = parse_native_lanes_json(ROWS["running_lane"].encode())
    record = running.record
    assert (record.lane, record.dataspace, record.incarnation) == (1, 0, "11" * 32)
    assert len(record.committee) == 4
    assert all(member.peer.startswith("ea0130") and len(member.pop) == 96 for member in record.committee)
    assert record.closing is None
    assert (record.created_at, record.active_from) == (40, 42)
    assert (record.merged.height, record.merged.block_hash, record.merged.result) == (7, "22" * 32, "33" * 32)
    assert record.params.key_allowed_algorithms == ("bls_normal",)
    assert record.params.due_work_max_lag_ms == 60_000
    assert record.da_layout == SumeragiDataAvailabilityLayout("reed_solomon16", 262144, 4, 2, 16777216, 1024)
    assert running.instance is not None and running.instance.protocol_version == 1
    assert running.instance.leader == record.committee[0].peer
    assert running.instance.footprint.probe == U64_MAX
    with pytest.raises(FrozenInstanceError):
        record.lane = 2

    running_again, pending, closing = parse_native_lanes_json(ROWS["mixed_lanes"].encode())
    assert running_again == running
    assert pending.instance is None
    assert (pending.record.lane, pending.record.dataspace, pending.record.rescued) == (16, U64_MAX, U64_MAX)
    assert (pending.record.merged.height, pending.record.merged.block_hash) == (0, "00" * 32)
    assert (closing.record.lane, closing.record.closing) == (U32_MAX, U64_MAX)
    assert (closing.record.anchor_freshness, closing.record.merged.height) == (U64_MAX, U64_MAX)
    assert closing.instance.halted.reason == "publication_recovery_required"
    assert closing.instance.halted.details == U64_MAX


def test_every_lane_field_is_required_and_unknown_fields_fail_closed():
    assert len(_parse(_lanes())) == 3
    lane = _lanes()[0]
    for field in list(lane):
        value = _lanes()
        del value[0][field]
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    for field in list(lane["record"]) + ["committee_member"]:
        value = _lanes()
        if field == "committee_member":
            del value[0]["record"]["committee"][0]["pop"]
        else:
            del value[0]["record"][field]
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    for owner in ["params", "da_layout", "merged"]:
        for field in list(lane["record"][owner]):
            value = _lanes()
            del value[0]["record"][owner][field]
            with pytest.raises((ValueError, TypeError)):
                _parse(value)
        value = _lanes()
        value[0]["record"][owner]["legacy"] = 0
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    for field in ["encoding", "details"]:
        value = _lanes()
        del value[0]["record"]["da_layout"]["encoding"][field]
        with pytest.raises(ValueError):
            _parse(value)
    value = _lanes()
    value[0]["record"]["da_layout"]["encoding"]["legacy"] = None
    with pytest.raises(ValueError):
        _parse(value)
    for retired in ["lane_finality_manifest", "merge_carrier", "queue_plan", "relay_envelope"]:
        value = _lanes()
        value[0]["record"][retired] = None
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    with pytest.raises((ValueError, TypeError)):
        parse_native_lanes({})


@pytest.mark.parametrize("bad", [-1, "1", 1.5, None, True, U32_MAX + 1])
def test_lane_identifier_is_an_exact_u32(bad):
    value = _lanes()
    value[0]["record"]["lane"] = bad
    with pytest.raises((ValueError, TypeError)):
        parse_native_lanes(value)


def test_data_availability_keeps_compact_final_stripes_and_rejects_invalid_geometry():
    layout = _lanes()[0]["record"]["da_layout"]
    compact = dict(layout, max_payload_size_bytes=4194305, max_chunk_count=30)
    assert SumeragiDataAvailabilityLayout.from_payload(compact).max_payload_size_bytes == 4194305
    for field, bad in [
        ("chunk_size_bytes", 0), ("chunk_size_bytes", 1), ("chunk_size_bytes", 3), ("chunk_size_bytes", 262146),
        ("data_shards", 0), ("data_shards", 17), ("data_shards", 65536), ("parity_shards", 0), ("parity_shards", 17),
        ("max_payload_size_bytes", 0), ("max_payload_size_bytes", 16777217), ("max_chunk_count", 0),
        ("max_chunk_count", 1025), ("max_chunk_count", 95),
    ]:
        with pytest.raises(ValueError):
            SumeragiDataAvailabilityLayout.from_payload(dict(layout, **{field: bad}))
    for bad in [
        dict(layout, data_shards=1, parity_shards=2),
        dict(layout, encoding={"encoding": "plain", "details": None}),
        dict(layout, encoding={"encoding": "reed_solomon16", "details": {}}),
        dict(compact, max_chunk_count=29),
    ]:
        with pytest.raises(ValueError):
            SumeragiDataAvailabilityLayout.from_payload(bad)
    value = _lanes()
    value[0]["record"]["params"]["max_block_bytes"] = 16777217
    with pytest.raises(ValueError):
        _parse(value)


@pytest.mark.parametrize("field", ["block_cadence_ms", "due_work_max_lag_ms", "payload_retry_interval_ms", "exec_budget_ms",
                                   "apply_budget_ms", "max_block_bytes", "epoch_length_blocks", "demotion_window"])
def test_nonzero_lane_parameters_reject_zero(field):
    value = _lanes()
    value[0]["record"]["params"][field] = 0
    with pytest.raises(ValueError):
        _parse(value)


def test_due_work_lag_preserves_nonzero_u64_and_requires_the_current_field():
    for lag in (1, 65_537, U64_MAX):
        value = _lanes()
        value[0]["record"]["params"]["due_work_max_lag_ms"] = lag
        direct = parse_native_lanes(value)
        encoded = _parse(value)
        assert encoded == direct
        assert encoded[0].record.params.due_work_max_lag_ms == lag
        assert type(encoded[0].record.params.due_work_max_lag_ms) is int
    value = _lanes()
    del value[0]["record"]["params"]["due_work_max_lag_ms"]
    for parse in (parse_native_lanes, _parse):
        with pytest.raises(ValueError, match="native lane parameters requires exactly its native fields"):
            parse(value)


@pytest.mark.parametrize("bad", [0, -1, U64_MAX + 1, True, None, "60000", 60000.5])
def test_due_work_lag_rejects_non_native_numeric_values(bad):
    value = _lanes()
    value[0]["record"]["params"]["due_work_max_lag_ms"] = bad
    for parse in (parse_native_lanes, _parse):
        with pytest.raises(ValueError):
            parse(value)


def test_due_work_lag_rejects_signed_zero_and_duplicate_json_fields():
    current = '"due_work_max_lag_ms":60000'
    running = ROWS["running_lane"]
    assert running.count(current) == 1
    for invalid in ('"due_work_max_lag_ms":-0', current + ',' + current):
        raw = running.replace(current, invalid).encode()
        with pytest.raises(ValueError):
            parse_native_lanes_json(raw)


def test_malformed_hashes_keys_proofs_and_bodies_are_rejected():
    for bad in ["11" * 31, "aa" * 32, "11" * 33, 17]:
        value = _lanes()
        value[0]["record"]["incarnation"] = bad
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    for algorithms in [["bls"], ["BLS_NORMAL"], "bls_normal", [1]]:
        value = _lanes()
        value[0]["record"]["params"]["key_allowed_algorithms"] = algorithms
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    member = _lanes()[0]["record"]["committee"][0]
    for field, bad in [("peer", member["peer"].lower()), ("peer", "bls_normal:" + member["peer"]),
                       ("peer", "ed0120" + "AB" * 32), ("pop", member["pop"][:-4]),
                       ("pop", member["pop"] + "AAAA"), ("pop", "-" + member["pop"][1:]),
                       ("pop", member["pop"] + "="), ("pop", "")]:
        value = _lanes()
        value[0]["record"]["committee"][0][field] = bad
        with pytest.raises((ValueError, TypeError)):
            _parse(value)
    running = ROWS["running_lane"]
    for raw in [running.replace('"rescued":0', '"rescued":-0').encode(),
                running.replace('"rescued":0', '"rescued":0,"rescued":0').encode(),
                running.replace('"rescued":0', '"rescued":0.0').encode(),
                b"\xff", b"", b" " * (LANES_MAX_BYTES + 1)]:
        with pytest.raises((ValueError, TypeError)):
            parse_native_lanes_json(raw)


def test_lane_transport_is_signed_bounded_and_closes_every_response():
    from iroha_torii_client import ToriiClient, ToriiOperatorSigningContext
    from sumeragi_exact_json_test_support import RecordingSession, StubResponse
    captured = []

    def signer(message):
        captured.append(message)
        return bytes([0x55]) * 64

    context = ToriiOperatorSigningContext(
        network_id="hash:0101010101010101010101010101010101010101010101010101010101010101#B86C",
        public_key="ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A",
        signer=signer,
    )
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session, operator_signing_context=context)
    response = StubResponse(raw=ROWS["mixed_lanes"].encode(), headers={"Content-Type": "application/json"})
    session.queue(response)
    lanes = client.get_sumeragi_lanes()
    assert [lane.record.lane for lane in lanes] == [1, 16, U32_MAX]
    assert response.was_closed
    call = session.calls[-1]
    assert call["method"] == "GET" and call["url"] == "https://node.test/v1/sumeragi/lanes"
    assert call["stream"] is True and call["allow_redirects"] is False
    assert len(captured) == 1 and b"/v1/sumeragi/lanes" in captured[0]
    for bad in [
        StubResponse(raw=ROWS["mixed_lanes"].encode(), headers={"Content-Type": "text/plain"}),
        StubResponse(raw=b'{"protocol_version":1}', headers={"Content-Type": "application/json"}),
        StubResponse(raw=b" " * (LANES_MAX_BYTES + 1), headers={"Content-Type": "application/json"}),
    ]:
        session.queue(bad)
        with pytest.raises((ValueError, TypeError, RuntimeError)):
            client.get_sumeragi_lanes()
        assert bad.was_closed
    assert deepcopy(lanes) == lanes
