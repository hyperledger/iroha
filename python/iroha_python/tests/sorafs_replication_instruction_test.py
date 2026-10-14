"""Focused parity tests for native SoraFS replication-order instructions."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from iroha_native import load_crypto_extension

from iroha_python import (
    SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1,
    CompleteReplicationOrderInstruction,
    ExpireReplicationOrderInstruction,
    Instruction,
    IssueReplicationOrderInstruction,
    ProviderIngestCompletionAuthorityV1,
    ProviderIngestCompletionSignerPolicyV1,
    ProviderIngestFinalizedAnchorV1,
    decode_replication_order_instruction,
)

_ORDER_ID = "2b" * 32
_MUSUBI_ARCHIVE_ID = "cd" * 32
_PROVIDER_ID = "10" * 32
_PROVIDER_OWNER = (
    "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
)
_COMPLETION_SIGNER = (
    "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
)
_POLICY_ID = "21" * 32
_PREDECESSOR_DIGEST = "32" * 32
_POLICY_DIGEST = "43" * 32
_BLOCK_HASH = "54" * 32
_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "sorafs_manifest"
    / "replication_order"
    / "order_v1.to"
).read_bytes()
_CRC64_POLY = 0xC96C5795D7870F42
_U64_MASK = (1 << 64) - 1


def _crc64(payload: bytes) -> int:
    crc = _U64_MASK
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ _CRC64_POLY) if crc & 1 else crc >> 1
    return (crc ^ _U64_MASK) & _U64_MASK


def _mutated_payload(needle: bytes, replacement: bytes) -> str:
    assert len(needle) == len(replacement)
    payload = bytearray(_FIXTURE)
    offset = payload.find(needle, 40)
    assert offset >= 40
    assert payload.find(needle, offset + 1) == -1
    payload[offset : offset + len(needle)] = replacement
    payload[31:39] = _crc64(bytes(payload[40:])).to_bytes(8, "little")
    return base64.b64encode(payload).decode("ascii")


def _authority(
    *,
    revision: int = 2,
    predecessor_digest: str | None = _PREDECESSOR_DIGEST,
    provider_owner: str = _PROVIDER_OWNER,
    completion_signer: str = _COMPLETION_SIGNER,
) -> ProviderIngestCompletionAuthorityV1:
    return ProviderIngestCompletionAuthorityV1(
        provider_owner=provider_owner,
        completion_signer=completion_signer,
        signer_policy=ProviderIngestCompletionSignerPolicyV1(
            policy_id=_POLICY_ID,
            revision=revision,
            predecessor_digest=predecessor_digest,
            policy_digest=_POLICY_DIGEST,
        ),
    )


def _completion(
    *,
    completion_signer: str = _COMPLETION_SIGNER,
) -> CompleteReplicationOrderInstruction:
    return CompleteReplicationOrderInstruction(
        _ORDER_ID,
        _PROVIDER_ID,
        27,
        _authority(completion_signer=completion_signer),
        3,
        ProviderIngestFinalizedAnchorV1(height=41, block_hash=_BLOCK_HASH),
    )


def test_replication_instruction_payloads_use_exact_rust_fields() -> None:
    issue = IssueReplicationOrderInstruction(
        _ORDER_ID,
        base64.b64encode(_FIXTURE).decode("ascii"),
        20,
        28,
    )
    assert issue.to_payload() == {
        "IssueReplicationOrder": {
            "order_id": _ORDER_ID,
            "order_payload": base64.b64encode(_FIXTURE).decode("ascii"),
            "issued_epoch": 20,
            "deadline_epoch": 28,
            "musubi_archive": None,
        }
    }
    assert IssueReplicationOrderInstruction.from_payload(issue.to_payload()) == issue

    bound = IssueReplicationOrderInstruction(
        _ORDER_ID,
        base64.b64encode(_FIXTURE).decode("ascii"),
        20,
        28,
        _MUSUBI_ARCHIVE_ID,
    )
    assert bound.to_payload()["IssueReplicationOrder"]["musubi_archive"] == _MUSUBI_ARCHIVE_ID
    assert IssueReplicationOrderInstruction.from_payload(bound.to_payload()) == bound

    complete = _completion()
    assert complete.to_payload() == {
        "CompleteReplicationOrder": {
            "order_id": _ORDER_ID,
            "provider_id": _PROVIDER_ID,
            "completion_epoch": 27,
            "expected_authority": {
                "provider_owner": _PROVIDER_OWNER,
                "completion_signer": _COMPLETION_SIGNER,
                "signer_policy": {
                    "policy_id": _POLICY_ID,
                    "revision": 2,
                    "predecessor_digest": _PREDECESSOR_DIGEST,
                    "policy_digest": _POLICY_DIGEST,
                },
            },
            "expected_assignment_revision": 3,
            "finalized_anchor": {
                "height": 41,
                "block_hash": _BLOCK_HASH,
            },
        }
    }
    assert decode_replication_order_instruction(complete.to_payload()) == complete

    expire = ExpireReplicationOrderInstruction(_ORDER_ID, 29)
    assert decode_replication_order_instruction(expire.to_payload()) == expire


def test_completion_authority_requires_its_exact_registered_signer() -> None:
    authority = _authority()
    assert authority.provider_owner != authority.completion_signer
    assert ProviderIngestCompletionAuthorityV1.from_payload(authority.to_payload()) == authority
    native = load_crypto_extension()
    finalized_anchor = ProviderIngestFinalizedAnchorV1(41, _BLOCK_HASH).to_payload()
    native.Instruction.complete_replication_order(
        _ORDER_ID, _PROVIDER_ID, 27, authority.to_payload(), 3, finalized_anchor
    )
    missing_signer = authority.to_payload()
    del missing_signer["completion_signer"]
    with pytest.raises(ValueError, match="completion_signer"):
        ProviderIngestCompletionAuthorityV1.from_payload(missing_signer)
    with pytest.raises(ValueError):
        native.Instruction.complete_replication_order(
            _ORDER_ID, _PROVIDER_ID, 27, missing_signer, 3, finalized_anchor
        )
    malformed_signer = authority.to_payload()
    malformed_signer["completion_signer"] = f" {_COMPLETION_SIGNER}"
    with pytest.raises(ValueError, match="exact canonical I105"):
        ProviderIngestCompletionAuthorityV1.from_payload(malformed_signer)
    with pytest.raises(ValueError):
        native.Instruction.complete_replication_order(
            _ORDER_ID, _PROVIDER_ID, 27, malformed_signer, 3, finalized_anchor
        )


def test_replication_instruction_decoders_are_schema_closed() -> None:
    with pytest.raises(TypeError):
        Instruction.complete_replication_order(  # type: ignore[call-arg]
            _ORDER_ID,
            _PROVIDER_ID,
            27,
        )
    with pytest.raises(ValueError, match="expected_authority"):
        CompleteReplicationOrderInstruction.from_payload(
            {
                "CompleteReplicationOrder": {
                    "order_id": _ORDER_ID,
                    "provider_id": _PROVIDER_ID,
                    "completion_epoch": 27,
                }
            }
        )
    with pytest.raises(ValueError, match="relayer"):
        CompleteReplicationOrderInstruction.from_payload(
            {
                "CompleteReplicationOrder": {
                    "order_id": _ORDER_ID,
                    "provider_id": _PROVIDER_ID,
                    "completion_epoch": 27,
                    "expected_authority": _authority().to_payload(),
                    "expected_assignment_revision": 3,
                    "finalized_anchor": {
                        "height": 41,
                        "block_hash": _BLOCK_HASH,
                    },
                    "relayer": "confused-deputy",
                }
            }
        )
    with pytest.raises(ValueError, match="zero identifier"):
        CompleteReplicationOrderInstruction(
            _ORDER_ID,
            "00" * 32,
            27,
            _authority(),
            3,
            ProviderIngestFinalizedAnchorV1(41, _BLOCK_HASH),
        )
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        CompleteReplicationOrderInstruction(
            _ORDER_ID.upper(),
            _PROVIDER_ID,
            27,
            _authority(),
            3,
            ProviderIngestFinalizedAnchorV1(41, _BLOCK_HASH),
        )
    with pytest.raises(ValueError, match="required after revision one"):
        _authority(revision=2, predecessor_digest=None)
    with pytest.raises(ValueError, match="absent at revision one"):
        _authority(revision=1, predecessor_digest=_PREDECESSOR_DIGEST)
    with pytest.raises(ValueError, match="greater than zero"):
        CompleteReplicationOrderInstruction(
            _ORDER_ID,
            _PROVIDER_ID,
            27,
            _authority(),
            0,
            ProviderIngestFinalizedAnchorV1(41, _BLOCK_HASH),
        )
    with pytest.raises(ValueError, match="greater than zero"):
        ProviderIngestFinalizedAnchorV1(0, _BLOCK_HASH)
    with pytest.raises(ValueError, match="exact canonical I105"):
        _authority(provider_owner=f" {_PROVIDER_OWNER}")
    with pytest.raises(ValueError, match="non-negative u64"):
        ExpireReplicationOrderInstruction(_ORDER_ID, -1)
    with pytest.raises(ValueError, match="greater than issued_epoch"):
        IssueReplicationOrderInstruction(
            _ORDER_ID,
            base64.b64encode(_FIXTURE).decode("ascii"),
            20,
            20,
        )
    with pytest.raises(ValueError, match="zero identifier"):
        IssueReplicationOrderInstruction(
            _ORDER_ID,
            base64.b64encode(_FIXTURE).decode("ascii"),
            20,
            28,
            "00" * 32,
        )
    with pytest.raises(ValueError, match="must contain exactly"):
        IssueReplicationOrderInstruction.from_payload(
            {
                "IssueReplicationOrder": {
                    "order_id": _ORDER_ID,
                    "order_payload": base64.b64encode(_FIXTURE).decode("ascii"),
                    "issued_epoch": 20,
                    "deadline_epoch": 28,
                }
            }
        )


def test_issue_rejects_invalid_embedded_replication_order_policy() -> None:
    canonical = base64.b64encode(_FIXTURE).decode("ascii")
    with pytest.raises(ValueError, match="canonical standard base64"):
        IssueReplicationOrderInstruction(_ORDER_ID, canonical + "\n", 1, 2)
    with pytest.raises(ValueError, match="must match"):
        IssueReplicationOrderInstruction("ac" * 32, canonical, 1, 2)
    with pytest.raises(ValueError, match="decoded limit"):
        IssueReplicationOrderInstruction(
            _ORDER_ID,
            base64.b64encode(
                bytes(SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1 + 1)
            ).decode("ascii"),
            1,
            2,
        )

    duplicate_provider = _mutated_payload(bytes([0x11]) * 32, bytes([0x10]) * 32)
    with pytest.raises(ValueError):
        IssueReplicationOrderInstruction(_ORDER_ID, duplicate_provider, 1, 2)

    zero_target = _mutated_payload(b"\x02\x02\x00", b"\x02\x00\x00")
    with pytest.raises(ValueError):
        IssueReplicationOrderInstruction(_ORDER_ID, zero_target, 1, 2)

    invalid_deadline = _mutated_payload(
        (1_700_086_400).to_bytes(8, "little"),
        (1_700_000_000).to_bytes(8, "little"),
    )
    with pytest.raises(ValueError):
        IssueReplicationOrderInstruction(_ORDER_ID, invalid_deadline, 1, 2)


def test_replication_payloads_convert_to_native_instructions() -> None:
    issue = IssueReplicationOrderInstruction(
        _ORDER_ID,
        base64.b64encode(_FIXTURE).decode("ascii"),
        20,
        28,
    )
    bound_issue = IssueReplicationOrderInstruction(
        _ORDER_ID,
        base64.b64encode(_FIXTURE).decode("ascii"),
        20,
        28,
        _MUSUBI_ARCHIVE_ID,
    )
    complete = _completion()
    expire = ExpireReplicationOrderInstruction(_ORDER_ID, 29)
    encoded = (
        issue.to_instruction().to_json(),
        bound_issue.to_instruction().to_json(),
        complete.to_instruction().to_json(),
        expire.to_instruction().to_json(),
    )
    for payload in encoded:
        encoded_archive = json.loads(payload)
        assert isinstance(encoded_archive, str)
        archive = base64.b64decode(encoded_archive, validate=True)
        assert archive.startswith(b"NRT0")
        assert base64.b64encode(archive).decode("ascii") == encoded_archive
        assert Instruction.from_json(payload).to_json() == payload

    assert (
        Instruction.complete_replication_order(
            _ORDER_ID,
            _PROVIDER_ID,
            27,
            _authority(),
            3,
            ProviderIngestFinalizedAnchorV1(41, _BLOCK_HASH),
        ).to_json()
        == encoded[2]
    )

    assert (
        _completion(completion_signer=_PROVIDER_OWNER).to_instruction().to_json()
        != encoded[2]
    ), "native completion bytes must bind the independently selected signer"


def test_completion_authority_preserves_independent_signer() -> None:
    authority = _authority()
    assert authority.provider_owner != authority.completion_signer
    assert authority.provider_owner == _PROVIDER_OWNER
    assert authority.completion_signer == _COMPLETION_SIGNER
    assert set(authority.to_payload()) == {
        "provider_owner",
        "completion_signer",
        "signer_policy",
    }
    assert (
        ProviderIngestCompletionAuthorityV1.from_payload(authority.to_payload())
        == authority
    )
    changed = _authority(completion_signer=_PROVIDER_OWNER)
    assert changed.provider_owner == authority.provider_owner
    assert changed.signer_policy == authority.signer_policy
    assert changed != authority
    assert changed.to_payload() != authority.to_payload()


def test_completion_authority_requires_schema_closed_three_fields() -> None:
    retired = _authority().to_payload()
    retired.pop("completion_signer")
    with pytest.raises(ValueError, match="completion_signer"):
        ProviderIngestCompletionAuthorityV1.from_payload(retired)
    substituted = {**retired, "signer": _COMPLETION_SIGNER}
    with pytest.raises(ValueError, match="must contain exactly"):
        ProviderIngestCompletionAuthorityV1.from_payload(substituted)
    extended = {**_authority().to_payload(), "relayer": _COMPLETION_SIGNER}
    with pytest.raises(ValueError, match="must contain exactly"):
        ProviderIngestCompletionAuthorityV1.from_payload(extended)
    with pytest.raises(TypeError):
        ProviderIngestCompletionAuthorityV1(  # type: ignore[call-arg]
            provider_owner=_PROVIDER_OWNER,
            signer_policy=_authority().signer_policy,
        )


@pytest.mark.parametrize(
    "signer",
    [None, 7, "", "merchant@bank", "00" * 32, f" {_COMPLETION_SIGNER}"],
)
def test_completion_authority_refuses_invalid_signer(signer: object) -> None:
    with pytest.raises(ValueError, match="completion_signer.*exact canonical I105"):
        _authority(completion_signer=signer)  # type: ignore[arg-type]
    payload = {**_authority().to_payload(), "completion_signer": signer}
    with pytest.raises(ValueError, match="completion_signer.*exact canonical I105"):
        ProviderIngestCompletionAuthorityV1.from_payload(payload)
