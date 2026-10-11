"""Closed first-release governance proposal reader tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from client_test_support import CANONICAL_OWNER
from iroha_torii_client.governance_proposals import (
    GovernanceContractLifecycleActionKind,
    GovernanceContractLifecycleEmergencyHoldRetrospective,
    GovernanceGlobalDataTriggerPermissionAction,
    GovernanceProposalContractEmergencyHold,
    GovernanceProposalContractLifecycleGovernance,
    GovernanceProposalDeployContract,
    GovernanceProposalGlobalDataTriggerPermissionGovernance,
    GovernanceProposalKind,
    GovernanceProposalKindTag,
    GovernanceProposalMusubiRegistryGovernance,
    GovernanceProposalRecord,
    GovernanceProposalRuntimeUpgrade,
    GovernanceProposalSccpRouteGovernance,
    GovernanceProposalSorafsProviderGovernance,
    GovernanceProposalValidationFeePayoutLifecycle,
    GovernanceProposalValidationFeePolicy,
)

CONTRACT_ADDRESS = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
NETWORK_ID = "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"


@pytest.mark.parametrize(
    "tag",
    [
        "KagemushaVerifierPolicyInstall",
        "KagemushaVerifierReleaseInstall",
        "KagemushaVerifierReleaseActivate",
        "KagemushaVerifierReleaseRetire",
    ],
)
@pytest.mark.parametrize("payload", [None, {}, {"proposal_operator": "invalid account"}])
def test_retired_kagemusha_proposal_kinds_reject_before_payload_validation(
    tag: str, payload: object
) -> None:
    with pytest.raises(TypeError, match="ten first-release variants"):
        GovernanceProposalKind.from_payload({"kind": tag, "payload": payload})


def _bsc_network() -> dict[str, object]:
    return {"network": "bsc_mainnet", "profile": None}


def _retired_payout_binding() -> dict[str, object]:
    return {
        "contract_address": CONTRACT_ADDRESS,
        "code_hash": [17] * 32,
        "entrypoint": "autonomous_validation_fee_tick",
        "treasury_account_id": CANONICAL_OWNER,
        "ds_asset_id": "xor#wonderland",
        "xor_asset_id": "xor#sora",
        "pool_vault_account_id": CANONICAL_OWNER,
        "batch_ds": "10",
        "min_xor_out": "4",
        "max_xor_out": "100",
        "recipients": [
            {"account_id": CANONICAL_OWNER, "share": "0.25"} for _ in range(4)
        ],
    }


def _retired_policy() -> dict[str, object]:
    return {
        "schema_version": 1,
        "network_id": NETWORK_ID,
        "policy_version": "1",
        "previous_policy_hash": None,
        "ds_asset_id": "xor#wonderland",
        "ds_scale": 0,
        "fee": "0",
        "treasury_account_id": CANONICAL_OWNER,
        "charging_mode": {"charging_mode": "DISABLED", "value": None},
        "effective_from_height": "1",
        "expires_after_height": None,
        "exemption_classes": [],
        "treasury_payout_binding": None,
    }


# Unsigned mathematical TESTDATA controllers derived by Node's built-in Ed25519
# key derivation from five distinct fixed seeds 0x51..0x55. Only the real installed
# Rust account codec renders/adopts them; these do not represent provider grants.
_TESTDATA_PROVIDER_CONTROLLERS = (
    "02000120c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    "020001202012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7",
    "02000120f80cccdce4ae1c07ae208a2adf99a310ae4207e0306fa0236110b06827bbb8d0",
    "020001209f49439e9db095bc4111ed25d35795d831bc55a047f4b1d7f6aee3777bb41220",
    "02000120c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242",
)


# Current maintained SDK DATA identifiers, not registered-asset or policy grants.
_TESTDATA_SBD_ASSET_ID = "7ZepsJTHCVLKsrFFNZGSRGZgvBhv"
_TESTDATA_XOR_ASSET_ID = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
_TESTDATA_OTHER_ASSET_ID = "7EAD8EFYUx1aVKZPUU1fyKvr8dF1"


def _providers() -> list[str]:
    from iroha_torii_client._account_id import encode_i105_account_id
    return [encode_i105_account_id(bytes.fromhex(raw), 753) for raw in _TESTDATA_PROVIDER_CONTROLLERS]


def _payout_binding() -> dict[str, object]:
    providers = _providers()
    return {
        "contract_address": CONTRACT_ADDRESS, "code_hash": "11" * 32,
        "entrypoint": "autonomous_validation_fee_tick", "treasury_account_id": CANONICAL_OWNER,
        "ds_asset_id": _TESTDATA_SBD_ASSET_ID, "xor_asset_id": _TESTDATA_XOR_ASSET_ID,
        "pool_contract_address": CONTRACT_ADDRESS, "pool_code_hash": "13" * 32,
        "pool_vault_account_id": providers[0], "reward_pool_account_id": providers[1],
        "reference_feed_id": ["xor-per-sbd"], "reference_feed_config_version": 1,
        "reference_provider_accounts": providers,
        "max_sbd_per_attempt_minor": 1000, "max_sbd_per_day_minor": 100000,
        "min_interval_ms": 60000, "max_source_age_ms": 300000, "max_slippage_bps": 100,
        "validator_lane_id": 0, "min_reward_claim_xor_minor": 1,
    }


def _policy() -> dict[str, object]:
    return {
        "schema_version": 1, "network_id": NETWORK_ID, "policy_version": "1",
        "previous_policy_hash": None, "ds_asset_id": _TESTDATA_SBD_ASSET_ID, "ds_scale": 2,
        "retail_schedule": {"included_payments": 50, "overage_minor": 10,
                            "maintenance_tiers": [{"minimum_average_balance_minor": 0, "monthly_fee_minor": 100},
                                                  {"minimum_average_balance_minor": 50000, "monthly_fee_minor": 200}]},
        "effective_from_ms": 1798722000000, "notice_published_at_ms": 1796129999999,
        "fee": "0.1", "treasury_account_id": CANONICAL_OWNER,
        "charging_mode": {"charging_mode": "RETAIL_MONTHLY_ALLOWANCE", "value": None},
        "exemption_classes": ["TREASURY_PAYOUT"],
        "reward_custody": {"contract_address": CONTRACT_ADDRESS, "treasury_account_id": CANONICAL_OWNER,
                           "ds_asset_id": _TESTDATA_SBD_ASSET_ID, "xor_asset_id": _TESTDATA_XOR_ASSET_ID,
                           "reward_pool_account_id": _providers()[1], "validator_lane_id": 0},
    }


def _variants() -> list[tuple[str, dict[str, object], type[object]]]:
    return [
        (
            "DeployContract",
            {
                "contract_address": CONTRACT_ADDRESS,
                "code_hash": "11" * 32,
                "abi_hash": "22" * 32,
                "abi_version": 1,
                "manifest_provenance": None,
            },
            GovernanceProposalDeployContract,
        ),
        (
            "RuntimeUpgrade",
            {
                "manifest": {
                    "name": "runtime-v1",
                    "description": "first release",
                    "abi_version": 1,
                    "abi_hash": [34] * 32,
                    "added_syscalls": [],
                    "added_pointer_types": [],
                    "start_height": 10,
                    "end_height": 20,
                    "sbom_digests": [],
                    "slsa_attestation": "",
                    "provenance": [],
                }
            },
            GovernanceProposalRuntimeUpgrade,
        ),
        (
            "SccpRouteGovernance",
            {
                "proposal": {
                    "network_id": NETWORK_ID,
                    "base_revisions": [
                        {
                            "subject": {"subject": "route", "key": _bsc_network()},
                            "revision": 1,
                        }
                    ],
                    "actions": [
                        {
                            "action": "remove_staged",
                            "payload": {"network": _bsc_network(), "revision": 1},
                        }
                    ],
                }
            },
            GovernanceProposalSccpRouteGovernance,
        ),
        (
            "ValidationFeePolicy",
            {
                "proposal_operator": CANONICAL_OWNER,
                "policy": _policy(),
            },
            GovernanceProposalValidationFeePolicy,
        ),
        (
            "ValidationFeePayoutLifecycle",
            {
                "proposal_operator": CANONICAL_OWNER,
                "payout_binding": _payout_binding(),
            },
            GovernanceProposalValidationFeePayoutLifecycle,
        ),
        (
            "MusubiRegistryGovernance",
            {
                "kind": "RetargetAlias",
                "value": {
                    "alias": ["wallet"],
                    "target": {
                        "home_dataspace": 1,
                        "scope": {"kind": "DataspaceRoot", "value": None},
                        "name": ["wallet"],
                    },
                    "expected_revision": 1,
                },
            },
            GovernanceProposalMusubiRegistryGovernance,
        ),
        (
            "SorafsProviderGovernance",
            {
                "action": {
                    "action": "establish",
                    "value": {"provider_id": [[51] * 32], "owner": CANONICAL_OWNER},
                }
            },
            GovernanceProposalSorafsProviderGovernance,
        ),
        (
            "ContractLifecycleGovernance",
            {
                "contract_address": CONTRACT_ADDRESS,
                "expected_revision": 3,
                "action": {
                    "action": "CompleteEmergencyHoldRetrospective",
                    "payload": {
                        "hold_proposal_content_id": [81] * 32,
                        "hold_governance_attempt_id": [82] * 32,
                        "incident_digest": [83] * 32,
                        "retrospective_finding_root": [84] * 32,
                    },
                },
            },
            GovernanceProposalContractLifecycleGovernance,
        ),
        (
            "ContractEmergencyHold",
            {
                "contract_address": CONTRACT_ADDRESS,
                "expected_revision": 2,
                "expected_code_hash": "33" * 32,
                "incident_digest": [85] * 32,
                "reason": "contain active exploit",
                "duration_blocks": 3_600,
            },
            GovernanceProposalContractEmergencyHold,
        ),
        (
            "GlobalDataTriggerPermissionGovernance",
            {
                "authority": CANONICAL_OWNER,
                "action": {"action": "grant", "value": None},
            },
            GovernanceProposalGlobalDataTriggerPermissionGovernance,
        ),
    ]


def test_shared_fixture_pins_closed_proposal_and_lifecycle_action_inventories() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "governance"
        / "parliament_api_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert fixture["proposal_kinds"] == [kind.value for kind in GovernanceProposalKindTag]
    assert fixture["contract_lifecycle_actions"] == [
        action.value for action in GovernanceContractLifecycleActionKind
    ]


def test_contract_lifecycle_action_inventory_admits_exactly_six_wire_tags() -> None:
    action_payloads: dict[GovernanceContractLifecycleActionKind, object] = {
        GovernanceContractLifecycleActionKind.ACTIVATE: {
            "code_hash": "11" * 32,
            "abi_hash": "22" * 32,
            "abi_version": 1,
            "manifest_provenance": None,
        },
        GovernanceContractLifecycleActionKind.DEACTIVATE: {
            "expected_code_hash": "33" * 32,
        },
        GovernanceContractLifecycleActionKind.OFFER_OWNERSHIP: {
            "new_owner": CANONICAL_OWNER,
        },
        GovernanceContractLifecycleActionKind.CANCEL_OWNERSHIP_OFFER: None,
        GovernanceContractLifecycleActionKind.ACCEPT_PARLIAMENT_OWNERSHIP: None,
        GovernanceContractLifecycleActionKind.COMPLETE_EMERGENCY_HOLD_RETROSPECTIVE: {
            "hold_proposal_content_id": [0x42] * 32,
            "hold_governance_attempt_id": [0x43] * 32,
            "incident_digest": [0x44] * 32,
            "retrospective_finding_root": [0x45] * 32,
        },
    }
    assert list(action_payloads) == list(GovernanceContractLifecycleActionKind)
    for action, payload in action_payloads.items():
        lifecycle = copy.deepcopy(_variants()[7][1])
        lifecycle["action"] = {"action": action.value, "payload": payload}
        proposal = GovernanceProposalKind.from_payload(
            {"kind": "ContractLifecycleGovernance", "payload": lifecycle}
        )
        assert proposal.payload.action.action is action  # type: ignore[union-attr]

    lifecycle = copy.deepcopy(_variants()[7][1])
    lifecycle["action"] = {"action": "Unknown", "payload": None}
    with pytest.raises(TypeError, match="not a first-release lifecycle action"):
        GovernanceProposalKind.from_payload(
            {"kind": "ContractLifecycleGovernance", "payload": lifecycle}
        )


@pytest.mark.parametrize(("tag", "payload", "payload_type"), _variants())
def test_proposal_kind_accepts_each_closed_v1_variant(
    tag: str, payload: dict[str, object], payload_type: type[object]
) -> None:
    proposal = GovernanceProposalKind.from_payload({"kind": tag, "payload": payload})

    assert proposal.kind is GovernanceProposalKindTag(tag)
    assert isinstance(proposal.payload, payload_type)


@pytest.mark.parametrize(
    "payload",
    [
        {"DeployContract": _variants()[0][1]},
        {"kind": "ApproveGovernanceProposal", "payload": {}},
        {"kind": "DeployContract", "payload": {**_variants()[0][1], "window": {}}},
        {"kind": "DeployContract", "payload": _variants()[0][1], "legacy": True},
    ],
)
def test_proposal_kind_rejects_unknown_and_retired_shapes(payload: object) -> None:
    with pytest.raises(TypeError):
        GovernanceProposalKind.from_payload(payload)


def test_attempt_proposal_u64_numbers_obey_the_exact_json_boundary() -> None:
    maximum = (1 << 53) - 1
    runtime = copy.deepcopy(_variants()[1][1])
    runtime["manifest"]["start_height"] = maximum - 1  # type: ignore[index]
    runtime["manifest"]["end_height"] = maximum  # type: ignore[index]
    GovernanceProposalKind.from_payload({"kind": "RuntimeUpgrade", "payload": runtime})

    runtime["manifest"]["end_height"] = maximum + 1  # type: ignore[index]
    with pytest.raises(TypeError, match="9007199254740991"):
        GovernanceProposalKind.from_payload(
            {"kind": "RuntimeUpgrade", "payload": runtime}
        )

    musubi = copy.deepcopy(_variants()[5][1])
    musubi["value"]["target"]["home_dataspace"] = maximum + 1  # type: ignore[index]
    with pytest.raises(TypeError, match="9007199254740991"):
        GovernanceProposalKind.from_payload(
            {"kind": "MusubiRegistryGovernance", "payload": musubi}
        )


def test_closed_nested_action_tags_reject_unknown_values() -> None:
    variants = _variants()
    musubi = copy.deepcopy(variants[5][1])
    musubi["kind"] = "LegacyRecovery"
    with pytest.raises(TypeError, match="Musubi action"):
        GovernanceProposalKind.from_payload({"kind": "MusubiRegistryGovernance", "payload": musubi})

    sorafs = copy.deepcopy(variants[6][1])
    sorafs["action"]["action"] = "replace"  # type: ignore[index]
    with pytest.raises(TypeError, match="provider action"):
        GovernanceProposalKind.from_payload({"kind": "SorafsProviderGovernance", "payload": sorafs})

    direct_provider_id = copy.deepcopy(variants[6][1])
    direct_provider_id["action"]["value"]["provider_id"] = [51] * 32  # type: ignore[index]
    with pytest.raises(TypeError, match="one-field ProviderId tuple"):
        GovernanceProposalKind.from_payload(
            {"kind": "SorafsProviderGovernance", "payload": direct_provider_id}
        )

    scalar_musubi_newtypes = copy.deepcopy(variants[5][1])
    scalar_musubi_newtypes["value"]["alias"] = "wallet"  # type: ignore[index]
    with pytest.raises(TypeError, match="one-field string tuple"):
        GovernanceProposalKind.from_payload(
            {"kind": "MusubiRegistryGovernance", "payload": scalar_musubi_newtypes}
        )

    scalar_package_name = copy.deepcopy(variants[5][1])
    scalar_package_name["value"]["target"]["name"] = "wallet"  # type: ignore[index]
    with pytest.raises(TypeError, match="one-field string tuple"):
        GovernanceProposalKind.from_payload(
            {"kind": "MusubiRegistryGovernance", "payload": scalar_package_name}
        )


def test_contract_lifecycle_retrospective_and_unit_actions_are_closed() -> None:
    lifecycle = copy.deepcopy(_variants()[7][1])
    proposal = GovernanceProposalKind.from_payload(
        {"kind": "ContractLifecycleGovernance", "payload": lifecycle}
    )
    assert proposal.payload.action.action is (  # type: ignore[union-attr]
        GovernanceContractLifecycleActionKind.COMPLETE_EMERGENCY_HOLD_RETROSPECTIVE
    )
    assert isinstance(  # type: ignore[union-attr]
        proposal.payload.action.payload,
        GovernanceContractLifecycleEmergencyHoldRetrospective,
    )

    for action in ("CancelOwnershipOffer", "AcceptParliamentOwnership"):
        lifecycle["action"] = {"action": action, "payload": None}
        GovernanceProposalKind.from_payload(
            {"kind": "ContractLifecycleGovernance", "payload": lifecycle}
        )
        del lifecycle["action"]["payload"]  # type: ignore[index]
        with pytest.raises(TypeError, match="missing required field `payload`"):
            GovernanceProposalKind.from_payload(
                {"kind": "ContractLifecycleGovernance", "payload": lifecycle}
            )


def test_contract_hold_bounds_and_retrospective_root_fail_closed() -> None:
    lifecycle = copy.deepcopy(_variants()[7][1])
    lifecycle["action"]["payload"]["retrospective_finding_root"] = [0] * 32  # type: ignore[index]
    with pytest.raises(TypeError, match="must be non-zero"):
        GovernanceProposalKind.from_payload(
            {"kind": "ContractLifecycleGovernance", "payload": lifecycle}
        )

    emergency = copy.deepcopy(_variants()[8][1])
    emergency["duration_blocks"] = 3_601
    with pytest.raises(TypeError, match=r"1\.\.3600"):
        GovernanceProposalKind.from_payload(
            {"kind": "ContractEmergencyHold", "payload": emergency}
        )


def test_global_data_trigger_permission_is_exact_account_and_closed_action() -> None:
    proposal = GovernanceProposalKind.from_payload(
        {
            "kind": "GlobalDataTriggerPermissionGovernance",
            "payload": _variants()[9][1],
        }
    )
    assert proposal.payload.action is GovernanceGlobalDataTriggerPermissionAction.GRANT  # type: ignore[union-attr]

    malformed = copy.deepcopy(_variants()[9][1])
    malformed["action"]["value"] = {}  # type: ignore[index]
    with pytest.raises(TypeError, match="must be null"):
        GovernanceProposalKind.from_payload(
            {"kind": "GlobalDataTriggerPermissionGovernance", "payload": malformed}
        )


def test_sccp_route_governance_keeps_the_exact_proposal_object() -> None:
    payload = _variants()[2][1]
    proposal = GovernanceProposalKind.from_payload(
        {"kind": "SccpRouteGovernance", "payload": payload}
    ).payload
    assert isinstance(proposal, GovernanceProposalSccpRouteGovernance)
    assert proposal.proposal["network_id"] == NETWORK_ID
    assert proposal.proposal["actions"][0]["action"] == "remove_staged"

    anchor = {"anchor": {"network_id": NETWORK_ID, "action": {}}}
    with pytest.raises(TypeError, match="missing required field `proposal`"):
        GovernanceProposalSccpRouteGovernance.from_payload(anchor)

    extra = copy.deepcopy(payload)
    extra["proposal"]["expected_head"] = None  # type: ignore[index]
    with pytest.raises(TypeError, match="unknown field `expected_head`"):
        GovernanceProposalSccpRouteGovernance.from_payload(extra)

    for actions in ([], [payload["proposal"]["actions"][0]] * 17):  # type: ignore[index]
        bounded = copy.deepcopy(payload)
        bounded["proposal"]["actions"] = actions  # type: ignore[index]
        with pytest.raises(TypeError, match=r"1\.\.16 actions"):
            GovernanceProposalSccpRouteGovernance.from_payload(bounded)

    malformed_network = copy.deepcopy(payload)
    malformed_network["proposal"]["network_id"] = "chain"  # type: ignore[index]
    with pytest.raises(TypeError, match="proposal.network_id must use canonical"):
        GovernanceProposalSccpRouteGovernance.from_payload(malformed_network)


def test_proposal_record_is_exact_and_rejects_retired_wrapper_fields() -> None:
    record = {
        "proposer": CANONICAL_OWNER,
        "kind": {"kind": _variants()[0][0], "payload": _variants()[0][1]},
        "created_height": 7,
        "status": "Superseded",
    }
    parsed = GovernanceProposalRecord.from_payload(record)
    assert parsed.created_height == 7

    for old_field in ("pipeline", "parliament_snapshot", "finalization_evidence"):
        with pytest.raises(TypeError, match="unknown field"):
            GovernanceProposalRecord.from_payload({**record, old_field: None})


@pytest.mark.parametrize(
    "status",
    ["Proposed", "Rejected", "Enacted", "Superseded", "ExecutionFailed"],
)
def test_proposal_record_accepts_only_first_release_statuses(status: str) -> None:
    record = {
        "proposer": CANONICAL_OWNER,
        "kind": {"kind": _variants()[0][0], "payload": _variants()[0][1]},
        "created_height": 7,
        "status": status,
    }

    assert GovernanceProposalRecord.from_payload(record).status.value == status

    record["status"] = "Approved"
    with pytest.raises(TypeError, match="status is unsupported"):
        GovernanceProposalRecord.from_payload(record)


@pytest.mark.parametrize("retired", ["DISABLED", "PER_QUALIFYING_TRANSFER_INSTRUCTION"])
def test_current_fee_policy_rejects_retired_charging_modes(retired: str) -> None:
    value = _policy()
    value["charging_mode"] = {"charging_mode": retired, "value": None}
    with pytest.raises(TypeError, match="RETAIL_MONTHLY_ALLOWANCE"):
        GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": value})


def test_retired_policy_payout_and_proposal_shapes_are_rejected() -> None:
    for policy in [_retired_policy(), {**_policy(), "expires_after_height": None}, {**_policy(), "effective_from_height": "1"}, {**_policy(), "treasury_payout_binding": None}]:
        with pytest.raises(TypeError):
            GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})
    with pytest.raises(TypeError, match="unknown field"):
        GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": _policy(), "payout_lifecycle_proposal_id": None})
    with pytest.raises(TypeError):
        GovernanceProposalValidationFeePayoutLifecycle.from_payload({"proposal_operator": CANONICAL_OWNER, "payout_binding": _retired_payout_binding()})


@pytest.mark.parametrize("path,value", [
    (("fee",), "0"), (("fee",), "0.001"), (("ds_scale",), 0),
    (("exemption_classes",), []), (("previous_policy_hash",), [1] * 32),
    (("retail_schedule", "included_payments"), 0),
    (("retail_schedule", "overage_minor"), True),
    (("retail_schedule", "maintenance_tiers"), []),
    (("effective_from_ms",), 1798722000001),
    (("notice_published_at_ms",), 1798722000000),
    (("reward_custody", "ds_asset_id"), _TESTDATA_OTHER_ASSET_ID),
    (("reward_custody", "treasury_account_id"), OTHER_PROPOSER),
])
def test_current_fee_policy_rejects_malformed_tariff_activation_or_custody(path: tuple[str, ...], value: object) -> None:
    policy = _policy()
    current = policy
    for field in path[:-1]:
        current = current[field]  # type: ignore[assignment]
    current[path[-1]] = value
    with pytest.raises(TypeError):
        GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})


@pytest.mark.parametrize("field,value", [
    ("code_hash", [17] * 32), ("pool_code_hash", [19] * 32),
    ("code_hash", "ab" * 32), ("pool_code_hash", "CD" * 31),
    ("code_hash", "00" * 32), ("pool_code_hash", " CD" * 32),
    ("reference_feed_id", "xor-per-sbd"), ("reference_feed_config_version", 0),
    ("max_sbd_per_attempt_minor", 0), ("max_sbd_per_day_minor", 1),
    ("min_interval_ms", 0), ("max_source_age_ms", 0), ("max_slippage_bps", 10000),
    ("validator_lane_id", 1 << 32), ("min_reward_claim_xor_minor", 0),
])
def test_current_conversion_rejects_missing_freshness_or_invalid_native_bounds(field: str, value: object) -> None:
    binding = _payout_binding()
    binding[field] = value
    with pytest.raises(TypeError):
        GovernanceProposalValidationFeePayoutLifecycle.from_payload({"proposal_operator": CANONICAL_OWNER, "payout_binding": binding})


def test_conversion_requires_independent_single_provider_controllers() -> None:
    from iroha_torii_client._account_id import encode_i105_account_id
    binding = _payout_binding()
    providers = list(binding["reference_provider_accounts"])
    providers[1] = encode_i105_account_id(bytes.fromhex(_TESTDATA_PROVIDER_CONTROLLERS[0]), 369)
    binding["reference_provider_accounts"] = providers
    with pytest.raises(TypeError, match="distinct single-signature provider controllers"):
        GovernanceProposalValidationFeePayoutLifecycle.from_payload({"proposal_operator": CANONICAL_OWNER, "payout_binding": binding})


def test_current_fee_payloads_keep_canonical_model_asset_identifiers() -> None:
    policy = GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": _policy()}).policy
    binding = GovernanceProposalValidationFeePayoutLifecycle.from_payload({"proposal_operator": CANONICAL_OWNER, "payout_binding": _payout_binding()}).payout_binding
    assert policy.ds_asset_id == policy.reward_custody.ds_asset_id == binding.ds_asset_id == _TESTDATA_SBD_ASSET_ID
    assert policy.reward_custody.xor_asset_id == binding.xor_asset_id == _TESTDATA_XOR_ASSET_ID


@pytest.mark.parametrize("invalid", [
    "sbd#sora", "xor#sora", " " + _TESTDATA_SBD_ASSET_ID,
    _TESTDATA_SBD_ASSET_ID + "#dataspace:1",
    "7EAD8EFYUx1aVKZPUU1fyKvr8dF2",  # bad checksum
    "7EAD8EFYV3tk2BtyQaGhqhATjFy7",  # valid checksum, wrong UUID version
    "7EAD8EFYUx1bhNP18PQmxXsySxi6",  # valid checksum, wrong RFC4122 variant
])
def test_fee_asset_readers_reject_retired_or_noncanonical_model_ids(invalid: str) -> None:
    for path in [("ds_asset_id",), ("reward_custody", "ds_asset_id"), ("reward_custody", "xor_asset_id")]:
        policy = _policy()
        target = policy
        for field in path[:-1]:
            target = target[field]  # type: ignore[assignment]
        target[path[-1]] = invalid
        with pytest.raises(TypeError):
            GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})
    for field in ["ds_asset_id", "xor_asset_id"]:
        binding = _payout_binding()
        binding[field] = invalid
        with pytest.raises(TypeError):
            GovernanceProposalValidationFeePayoutLifecycle.from_payload({"proposal_operator": CANONICAL_OWNER, "payout_binding": binding})


@pytest.mark.parametrize("fee", [str((1 << 511) - 1), f"{((1 << 511) - 1) // 100}.{((1 << 511) - 1) % 100:02d}"])
def test_fee_quantity_accepts_the_exact_model_mantissa_boundary(fee: str) -> None:
    policy = _policy()
    policy["fee"] = fee
    admitted = GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})
    assert admitted.policy.fee == fee


@pytest.mark.parametrize("fee", [
    str(1 << 511), f"{(1 << 511) // 100}.{(1 << 511) % 100:02d}",
    "9" * 200, "1.00", "01", "-1", "1e2", "0.00000000000000000000000000001",
])
def test_fee_quantity_rejects_model_overflow_and_noncanonical_spellings(fee: str) -> None:
    policy = _policy()
    policy["fee"] = fee
    with pytest.raises(TypeError):
        GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})


def test_fee_activation_accepts_zero_notice_original_when_calendar_window_is_satisfied() -> None:
    policy = _policy()
    policy["notice_published_at_ms"] = 0
    policy["effective_from_ms"] = 31 * 86_400_000 - 39_600_000  # Honiara 1970-02-01
    admitted = GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})
    assert admitted.policy.notice_published_at_ms == 0


def test_fee_activation_requires_the_model_next_month_endpoint() -> None:
    from datetime import date
    policy = _policy()
    policy["notice_published_at_ms"] = 0
    policy["effective_from_ms"] = (date(9999, 12, 1) - date(1970, 1, 1)).days * 86_400_000 - 39_600_000
    with pytest.raises(TypeError, match="supported calendar"):
        GovernanceProposalValidationFeePolicy.from_payload({"proposal_operator": CANONICAL_OWNER, "policy": policy})
