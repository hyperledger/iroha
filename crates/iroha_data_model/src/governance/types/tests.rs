//! Governance wire, identity and lifecycle contract regressions.

use super::*;
use crate::AccountId;
use iroha_crypto::KeyPair;
use iroha_crypto::blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use norito::core::DecodeFromSlice;
fn checked_random_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked governance fixture keypair")
}
fn checked_account_id() -> AccountId {
    AccountId::new(checked_random_keypair().public_key().clone())
}
#[test]
fn parliament_expected_head_root_keeps_the_length_prefixed_domain_preimage() {
    const HEAD_DOMAIN: &[u8] = b"iroha.governance.parliament.expected_head.root.v1";
    // Every Parliament compare-and-set subject hashes its exact predecessor
    // under this length-prefixed domain.
    assert_eq!(
        crate::governance_fingerprint::PARLIAMENT_EXPECTED_HEAD_ROOT_V1,
        HEAD_DOMAIN
    );
    let predecessor: (u64, [u8; 32]) = (7, [0x51; 32]);
    let head = parliament_expected_head_root_v1(&predecessor);
    let mut hasher = Blake2bVar::new(32).expect("32-byte head digest");
    hasher.update(&u64::try_from(HEAD_DOMAIN.len()).unwrap().to_le_bytes());
    hasher.update(HEAD_DOMAIN);
    hasher.update(&predecessor.encode());
    let mut expected = [0; 32];
    hasher
        .finalize_variable(&mut expected)
        .expect("32-byte head output");
    assert_eq!(head, expected);
    assert_ne!(head, [0; 32]);
    assert_ne!(
        head,
        parliament_expected_head_root_v1(&(8_u64, [0x51_u8; 32]))
    );
}

#[test]
fn governance_subject_preimage_tags_are_closed_and_dense() {
    assert_eq!(
        &GovernanceSubjectPreimageV1::SorafsAdmissionCouncil.encode()[..4],
        &11_u32.to_le_bytes()
    );
    assert_eq!(
        &GovernanceSubjectPreimageV1::SorafsProviderAdmission(crate::sorafs::capacity::ProviderId(
            [7; 32]
        ))
        .encode()[..4],
        &12_u32.to_le_bytes()
    );
}
#[test]
fn timed_ovn_required_chunk_blocks_round_up_at_the_wire_bound() {
    assert_eq!(parliament_timed_ovn_required_chunk_blocks_v1(0), 0);
    assert_eq!(parliament_timed_ovn_required_chunk_blocks_v1(1), 1);
    assert_eq!(parliament_timed_ovn_required_chunk_blocks_v1(32), 1);
    assert_eq!(parliament_timed_ovn_required_chunk_blocks_v1(33), 2);
    assert_eq!(parliament_timed_ovn_required_chunk_blocks_v1(1_000), 32);
}
#[test]
fn contract_hash_roundtrips_hex() {
    let raw = [0xAAu8; 32];
    let hash = ContractCodeHash::new(raw);
    let encoded = hash.to_hex();
    let parsed = ContractCodeHash::from_hex_str(&encoded).expect("parse hex");
    assert_eq!(parsed, hash);
}

#[test]
fn parliament_hash_identifiers_are_canonical_json_object_keys() {
    fn assert_key<T>(value: T, expected: &str)
    where
        T: json::JsonObjectKey
            + json::JsonObjectKeyOwned
            + JsonSerialize
            + Clone
            + core::fmt::Debug
            + Ord
            + PartialEq,
    {
        let mut visited = String::new();
        json::JsonObjectKey::visit_json_key_text(&value, |chunk| {
            visited.push_str(chunk);
            Ok::<_, core::convert::Infallible>(())
        })
        .expect("infallible key visitor");
        assert_eq!(visited, expected);
        assert_eq!(
            json::to_json(&value).expect("identifier JSON string"),
            format!("\"{expected}\"")
        );
        assert_eq!(
            <T as json::JsonObjectKeyOwned>::from_json_key_text(expected)
                .expect("canonical identifier key"),
            value
        );
        let uppercase = expected.to_ascii_uppercase();
        if uppercase != expected {
            assert!(
                <T as json::JsonObjectKeyOwned>::from_json_key_text(&uppercase).is_err(),
                "uppercase aliases must fail closed"
            );
        }
        for invalid in [
            expected[..63].to_owned(),
            format!("{expected}00"),
            format!("0x{expected}"),
            format!("g{}", &expected[1..]),
        ] {
            assert!(<T as json::JsonObjectKeyOwned>::from_json_key_text(&invalid).is_err());
        }
        let limits =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits, || {
            <T as json::JsonObjectKeyOwned>::from_json_key_text(expected)
        });
        assert_eq!(
            decoded.expect("fixed-size key with no allocation budget"),
            value
        );
        assert_eq!(usage.total_allocated_bytes(), 0);

        let mut calls = 0;
        let stopped = json::JsonObjectKey::visit_json_key_text(&value, |_| {
            calls += 1;
            Err("key visitor stopped")
        });
        assert_eq!(stopped, Err("key visitor stopped"));
        assert_eq!(calls, 1);

        let map = std::collections::BTreeMap::from([(value, 1_u8)]);
        let encoded = format!("{{\"{expected}\":1}}");
        assert_eq!(
            json::to_json_bounded(&map, encoded.len()).expect("exact identifier-key bound"),
            encoded
        );
        assert_eq!(
            json::from_json::<std::collections::BTreeMap<T, u8>>(&encoded)
                .expect("identifier-key map roundtrip"),
            map
        );
        assert!(matches!(
            json::to_json_bounded(&map, encoded.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        ));
    }

    assert_key(AssignmentId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(BeaconPulseId::new([0xB2; 32]), &"b2".repeat(32));
    assert_key(BodyElectionAttemptId::new([0xC3; 32]), &"c3".repeat(32));
    assert_key(BodyInstanceId::new([0xD4; 32]), &"d4".repeat(32));
    assert_key(TleSessionId::new([0xE5; 32]), &"e5".repeat(32));
    assert_key(ContractCodeHash::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(ContractAbiHash::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(AgendaItemId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(DraftId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(ProposalContentId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(GovernanceAttemptId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(SortitionRequestId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(BallotAttemptId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(BeaconSessionId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(TleKeySessionId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(GovernanceCertificateId::new([0xA1; 32]), &"a1".repeat(32));
    assert_key(AssignmentId::new([0; 32]), &"00".repeat(32));
    assert_key(AssignmentId::new([0xFF; 32]), &"ff".repeat(32));
}

#[test]
fn every_parliament_body_has_one_json_object_key_label() {
    let labels = [
        "rules-committee",
        "agenda-council",
        "interest-panel",
        "review-panel",
        "coordination-council",
        "mpc-committee",
        "fma-committee",
        "oversight-committee",
        "policy-jury",
        "confirmation-jury",
    ];
    for (body, label) in PARLIAMENT_BODIES_V1.into_iter().zip(labels) {
        let mut visited = String::new();
        json::JsonObjectKey::visit_json_key_text(&body, |chunk| {
            visited.push_str(chunk);
            Ok::<_, core::convert::Infallible>(())
        })
        .expect("infallible key visitor");
        assert_eq!(visited, label);
        assert_eq!(
            <ParliamentBody as json::JsonObjectKeyOwned>::from_json_key_text(label)
                .expect("canonical Parliament body key"),
            body
        );
        assert_eq!(
            json::to_json(&body).expect("Parliament body JSON"),
            format!("\"{label}\"")
        );
        assert_eq!(
            json::from_json::<ParliamentBody>(&format!("\"{label}\""))
                .expect("Parliament body JSON roundtrip"),
            body
        );

        let map = std::collections::BTreeMap::from([(body, 1_u8)]);
        let encoded = format!("{{\"{label}\":1}}");
        assert_eq!(
            json::to_json_bounded(&map, encoded.len()).expect("exact body-key bound"),
            encoded
        );
        assert_eq!(
            json::from_json::<std::collections::BTreeMap<ParliamentBody, u8>>(&encoded)
                .expect("body-key map roundtrip"),
            map
        );
        let mut calls = 0;
        let stopped = json::JsonObjectKey::visit_json_key_text(&body, |_| {
            calls += 1;
            Err("body visitor stopped")
        });
        assert_eq!(stopped, Err("body visitor stopped"));
        assert_eq!(calls, 1);
        assert!(matches!(
            json::to_json_bounded(&map, encoded.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        ));
    }
    for invalid in [
        "RulesCommittee",
        "rules_committee",
        "Rules-Committee",
        " rules-committee",
        "rules-committee ",
        "unknown",
    ] {
        assert!(<ParliamentBody as json::JsonObjectKeyOwned>::from_json_key_text(invalid).is_err());
        assert!(json::from_json::<ParliamentBody>(&format!("\"{invalid}\"")).is_err());
    }
}
#[test]
fn contract_lifecycle_and_emergency_fingerprints_are_kind_separated() {
    let owner = checked_account_id();
    let network: NetworkId =
        "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("network id");
    let address = ContractAddress::derive(
        &network,
        &owner,
        9,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let lifecycle =
        ProposalKind::ContractLifecycleGovernance(ContractLifecycleGovernanceProposalV1 {
            proposal_operator: owner,
            contract_address: address.clone(),
            expected_revision: 1,
            action: ContractLifecycleGovernanceActionV1::CancelOwnershipOffer,
        });
    let emergency = ProposalKind::ContractEmergencyHold(ContractEmergencyHoldProposalV1 {
        contract_address: address,
        expected_revision: 1,
        expected_code_hash: ContractCodeHash::new([7; 32]),
        incident_digest: [8; 32],
        reason: "containment".to_owned(),
        duration_blocks: 10,
    });
    assert_ne!(lifecycle.fingerprint(), emergency.fingerprint());
    assert_eq!(
        lifecycle.governed_subject_id_v1().expect("subject"),
        emergency.governed_subject_id_v1().expect("subject")
    );
}
#[test]
fn global_data_trigger_permission_proposals_are_account_scoped_and_append_only() {
    assert_eq!(
        GlobalDataTriggerPermissionGovernanceActionV1::Grant.encode(),
        0_u32.to_le_bytes()
    );
    assert_eq!(
        GlobalDataTriggerPermissionGovernanceActionV1::Revoke.encode(),
        1_u32.to_le_bytes()
    );
    let authority = checked_account_id();
    let authority_literal = authority.to_string();
    let grant = ProposalKind::GlobalDataTriggerPermissionGovernance(
        GlobalDataTriggerPermissionGovernanceProposalV1 {
            authority: authority.clone(),
            action: GlobalDataTriggerPermissionGovernanceActionV1::Grant,
        },
    );
    let revoke = ProposalKind::GlobalDataTriggerPermissionGovernance(
        GlobalDataTriggerPermissionGovernanceProposalV1 {
            authority,
            action: GlobalDataTriggerPermissionGovernanceActionV1::Revoke,
        },
    );

    assert_ne!(grant.fingerprint(), revoke.fingerprint());
    assert_eq!(
        grant.governed_subject_id_v1().expect("grant subject"),
        revoke.governed_subject_id_v1().expect("revoke subject")
    );
    assert_eq!(
        grant.encode().get(..4),
        Some(9_u32.to_le_bytes().as_slice()),
        "the proposal kind must retain its append-only Norito index"
    );
    let framed = norito::to_bytes(&grant).expect("encode permission proposal");
    assert_eq!(
        norito::decode_from_bytes::<ProposalKind>(&framed).expect("decode permission proposal"),
        grant
    );
    for (proposal, action) in [(&grant, "grant"), (&revoke, "revoke")] {
        let expected = format!(
            "{{\"kind\":\"GlobalDataTriggerPermissionGovernance\",\"payload\":{{\"authority\":\"{authority_literal}\",\"action\":{{\"action\":\"{action}\",\"value\":null}}}}}}"
        );
        let json = norito::json::to_json(proposal)
            .expect("encode canonical global data-trigger permission proposal JSON");
        assert_eq!(json, expected);
        assert_eq!(
            norito::json::from_json::<ProposalKind>(&json)
                .expect("decode canonical global data-trigger permission proposal JSON"),
            *proposal
        );
    }
}
#[test]
fn emergency_hold_retrospective_action_is_append_only_and_binding_complete() {
    let action = ContractLifecycleGovernanceActionV1::CompleteEmergencyHoldRetrospective(
        CompleteContractEmergencyHoldRetrospectiveGovernanceActionV1 {
            hold_proposal_content_id: [0x11; 32],
            hold_governance_attempt_id: [0x22; 32],
            incident_digest: [0x33; 32],
            retrospective_finding_root: [0x44; 32],
        },
    );
    let encoded = action.encode();
    assert_eq!(
        encoded.get(..4),
        Some(5_u32.to_le_bytes().as_slice()),
        "the retrospective action must retain its append-only Norito index"
    );
    let framed = norito::to_bytes(&action).expect("encode retrospective action");
    assert_eq!(
        norito::decode_from_bytes::<ContractLifecycleGovernanceActionV1>(&framed)
            .expect("decode retrospective action"),
        action
    );
}
#[test]
fn hash_parse_rejects_wrong_length() {
    let err = ContractAbiHash::from_hex_str("deadbeef").expect_err("length mismatch should error");
    match err {
        HashParseError::InvalidLength { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 4);
        }
        _ => panic!("unexpected error variant"),
    }
}
#[test]
fn contract_hash_from_hex_roundtrip() {
    let raw = "aa".repeat(ContractCodeHash::LENGTH);
    let parsed = ContractCodeHash::from_hex_str(&raw).expect("parse contract hash");
    assert_eq!(parsed.to_hex(), raw);
}
#[test]
fn contract_hash_rejects_uppercase_hex_alias() {
    let err = ContractCodeHash::from_hex_str(&"AA".repeat(ContractCodeHash::LENGTH))
        .expect_err("uppercase hash aliases must fail closed");
    assert!(matches!(err, HashParseError::InvalidHex { .. }));
    assert!(err.to_string().contains("lowercase hexadecimal"));
}
#[test]
fn hash_decode_rejects_non_canonical_vec_layout() {
    let mut non_canonical = Vec::new();
    non_canonical.extend_from_slice(&32u64.to_le_bytes());
    for idx in 0..=32u64 {
        non_canonical.extend_from_slice(&idx.to_le_bytes());
    }
    non_canonical.extend_from_slice(&[0x11u8; 32]);
    let mut encoded = Vec::new();
    norito::core::serialize_to_buffer(&non_canonical, &mut encoded).expect("encode vec");
    let result = <ContractCodeHash as DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(result.is_err());
}

#[test]
fn logical_beacon_session_id_is_stable_nonzero_and_network_scoped() {
    let network = |marker| {
        NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([marker; iroha_crypto::Hash::LENGTH]),
            ),
        )
    };
    let first = network(0x51);
    let second = network(0x52);
    let first_id = BeaconSessionId::for_network_v1(&first);
    assert_eq!(first_id, BeaconSessionId::for_network_v1(&first));
    assert_ne!(first_id, BeaconSessionId::for_network_v1(&second));
    assert!(first_id.as_bytes().iter().any(|byte| *byte != 0));
}
#[test]
fn hash_decode_rejects_versioned_payload_with_trailing_bytes() {
    let mut payload = Vec::with_capacity(4 + ContractCodeHash::LENGTH + 1);
    payload.extend_from_slice(&HASH_WIRE_VERSION_V1.to_le_bytes());
    payload.extend_from_slice(
        &u16::try_from(ContractCodeHash::LENGTH)
            .expect("contract hash length fits u16")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&[0x11; ContractCodeHash::LENGTH]);
    payload.push(0xFF);
    let mut encoded = Vec::new();
    norito::core::serialize_to_buffer(&payload, &mut encoded)
        .expect("encode hostile versioned vector payload");
    assert!(<ContractCodeHash as DecodeFromSlice>::decode_from_slice(&encoded).is_err());
}
#[test]
fn parliament_body_default_is_agenda() {
    assert_eq!(ParliamentBody::default(), ParliamentBody::AgendaCouncil);
}
#[test]
fn ballot_failures_map_exhaustively_to_bounded_no_result_classes() {
    let cases = [
        (
            ParliamentBallotFailureKindV1::RegistrationDeadlineExpired,
            ParliamentNoResultKindV1::BallotRegistrationDeadlineExpired,
        ),
        (
            ParliamentBallotFailureKindV1::SurvivorDeadlineExpired,
            ParliamentNoResultKindV1::BallotSurvivorDeadlineExpired,
        ),
        (
            ParliamentBallotFailureKindV1::CommitmentDeadlineExpired,
            ParliamentNoResultKindV1::BallotCommitmentDeadlineExpired,
        ),
        (
            ParliamentBallotFailureKindV1::ReleasePulseUnavailable,
            ParliamentNoResultKindV1::BallotReleasePulseUnavailable,
        ),
        (
            ParliamentBallotFailureKindV1::OpeningDeadlineExpired,
            ParliamentNoResultKindV1::BallotOpeningDeadlineExpired,
        ),
        (
            ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable,
            ParliamentNoResultKindV1::ConfirmationJuryCapacityUnavailable,
        ),
        (
            ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted,
            ParliamentNoResultKindV1::RandomnessRedrawBudgetExhausted,
        ),
    ];
    for (index, (ballot, audit)) in cases.into_iter().enumerate() {
        assert_eq!(ParliamentNoResultKindV1::from(ballot), audit);
        assert_eq!(
            ballot.encode(),
            u32::try_from(index)
                .expect("ballot failure index fits u32")
                .to_le_bytes()
        );
        let expected_audit_index = if index >= 5 { index + 3 } else { index + 2 };
        assert_eq!(
            audit.encode(),
            u32::try_from(expected_audit_index)
                .expect("audit failure index fits u32")
                .to_le_bytes()
        );
    }
}
#[test]
fn governance_types_encode() {
    let code_hash = ContractCodeHash::from_hex_str(&"aa".repeat(32)).expect("code hash");
    let abi_hash = ContractAbiHash::from_hex_str(&"bb".repeat(32)).expect("abi hash");
    let proposal = DeployContractProposal {
        proposal_operator: checked_account_id(),
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address"),
        code_hash,
        abi_hash,
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    };
    let payload = ProposalKind::DeployContract(proposal.clone());
    assert_ne!(payload.fingerprint(), payload.effect_preimage_hash_v1());
    assert_ne!(
        payload.fingerprint(),
        payload
            .governed_subject_id_v1()
            .expect("derive governed subject")
    );
    let framed = norito::to_bytes(&payload).expect("encode proposal kind");
    let decoded = norito::decode_from_bytes::<ProposalKind>(&framed).expect("decode proposal kind");
    match decoded {
        ProposalKind::DeployContract(inner) => {
            assert_eq!(inner.contract_address, proposal.contract_address);
            assert_eq!(inner.code_hash.to_hex(), proposal.code_hash.to_hex());
        }
        ProposalKind::RuntimeUpgrade(_) => panic!("unexpected runtime-upgrade proposal"),
        ProposalKind::SccpRouteGovernance(_) => {
            panic!("unexpected sccp-route-governance proposal")
        }
        ProposalKind::ValidationFeePolicy(_) => {
            panic!("unexpected validation-fee policy proposal")
        }
        ProposalKind::ValidationFeePayoutLifecycle(_) => {
            panic!("unexpected validation-fee payout lifecycle proposal")
        }
        ProposalKind::MusubiRegistryGovernance(_) => {
            panic!("unexpected Musubi registry proposal")
        }
        ProposalKind::SorafsProviderGovernance(_) => {
            panic!("unexpected SoraFS provider-governance proposal")
        }
        ProposalKind::ContractLifecycleGovernance(_) => {
            panic!("unexpected contract-lifecycle proposal")
        }
        ProposalKind::ContractEmergencyHold(_) => {
            panic!("unexpected contract emergency-hold proposal")
        }
        ProposalKind::GlobalDataTriggerPermissionGovernance(_) => {
            panic!("unexpected global data-trigger permission proposal")
        }
    }
}

#[test]
fn effect_sensitive_proposals_bind_the_operator_into_both_hashes() {
    let first_operator = checked_account_id();
    let second_operator = checked_account_id();
    assert_ne!(first_operator, second_operator);
    let contract_address: ContractAddress =
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address");
    let manifest = RuntimeUpgradeManifest {
        name: "operator-bound runtime upgrade".to_owned(),
        description: "operator binding fixture".to_owned(),
        abi_version: 1,
        abi_hash: ivm_abi::syscalls::compute_abi_hash(ivm_abi::SyscallPolicy::AbiV1),
        added_syscalls: Vec::new(),
        added_pointer_types: Vec::new(),
        start_height: 42,
        end_height: 99,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let pairs = [
        (
            ProposalKind::DeployContract(DeployContractProposal {
                proposal_operator: first_operator.clone(),
                contract_address: contract_address.clone(),
                code_hash: ContractCodeHash::new([0x11; 32]),
                abi_hash: ContractAbiHash::new([0x22; 32]),
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            ProposalKind::DeployContract(DeployContractProposal {
                proposal_operator: second_operator.clone(),
                contract_address: contract_address.clone(),
                code_hash: ContractCodeHash::new([0x11; 32]),
                abi_hash: ContractAbiHash::new([0x22; 32]),
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
        ),
        (
            ProposalKind::ContractLifecycleGovernance(ContractLifecycleGovernanceProposalV1 {
                proposal_operator: first_operator.clone(),
                contract_address: contract_address.clone(),
                expected_revision: 1,
                action: ContractLifecycleGovernanceActionV1::CancelOwnershipOffer,
            }),
            ProposalKind::ContractLifecycleGovernance(ContractLifecycleGovernanceProposalV1 {
                proposal_operator: second_operator.clone(),
                contract_address,
                expected_revision: 1,
                action: ContractLifecycleGovernanceActionV1::CancelOwnershipOffer,
            }),
        ),
        (
            ProposalKind::RuntimeUpgrade(RuntimeUpgradeProposal {
                proposal_operator: first_operator.clone(),
                manifest: manifest.clone(),
            }),
            ProposalKind::RuntimeUpgrade(RuntimeUpgradeProposal {
                proposal_operator: second_operator.clone(),
                manifest,
            }),
        ),
    ];

    for (first, second) in pairs {
        assert_eq!(first.proposal_operator_v1(), Some(&first_operator));
        assert_eq!(second.proposal_operator_v1(), Some(&second_operator));
        assert_ne!(first.fingerprint(), second.fingerprint());
        assert_ne!(
            first.effect_preimage_hash_v1(),
            second.effect_preimage_hash_v1()
        );
        assert_eq!(
            first.governed_subject_id_v1().expect("first subject"),
            second.governed_subject_id_v1().expect("second subject")
        );
    }
}

#[test]
fn competing_contract_effects_share_one_governed_subject() {
    let proposal_operator = checked_account_id();
    let contract_address: ContractAddress =
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address");
    let first = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: proposal_operator.clone(),
        contract_address: contract_address.clone(),
        code_hash: ContractCodeHash::new([0x11; 32]),
        abi_hash: ContractAbiHash::new([0x22; 32]),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let second = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator,
        contract_address,
        code_hash: ContractCodeHash::new([0x33; 32]),
        abi_hash: ContractAbiHash::new([0x44; 32]),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });

    assert_ne!(first.fingerprint(), second.fingerprint());
    assert_eq!(
        first
            .governed_subject_id_v1()
            .expect("derive first governed subject"),
        second
            .governed_subject_id_v1()
            .expect("derive second governed subject")
    );
}

#[test]
fn deploy_proposal_json_rejects_unknown_payload_fields() {
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: checked_account_id(),
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address"),
        code_hash: ContractCodeHash::new([0x11; 32]),
        abi_hash: ContractAbiHash::new([0x22; 32]),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let canonical =
        norito::json::to_json(&proposal).expect("canonical governance proposal JSON encodes");
    let hostile = canonical.replacen("\"payload\":{", "\"payload\":{\"legacy\":true,", 1);
    assert_ne!(hostile, canonical);
    assert!(
        norito::json::from_json::<ProposalKind>(&hostile).is_err(),
        "governance proposal JSON must reject unknown payload fields"
    );

    let missing_provenance = canonical.replacen(",\"manifest_provenance\":null", "", 1);
    assert_ne!(
        missing_provenance, canonical,
        "canonical proposal JSON must carry the explicit optional provenance field"
    );
    assert!(
        norito::json::from_json::<ProposalKind>(&missing_provenance).is_err(),
        "governance proposal JSON must reject an omitted manifest_provenance field"
    );
}

#[test]
fn proposal_kind_json_rejects_unknown_fields_through_musubi_action() {
    let proposal =
        ProposalKind::MusubiRegistryGovernance(MusubiParliamentActionV1::SetRegistryPolicy(
            crate::musubi::MusubiSetRegistryPolicyActionV1 {
                policy: crate::musubi::MusubiRegistryPolicyV1::default(),
                expected_revision: 1,
            },
        ));
    let canonical =
        norito::json::to_json(&proposal).expect("canonical governance proposal JSON encodes");
    assert_eq!(
        norito::json::from_json::<ProposalKind>(&canonical)
            .expect("canonical governance proposal JSON decodes"),
        proposal
    );
    for (prefix, depth) in [
        ("{", "the proposal envelope"),
        ("\"payload\":{", "the Musubi action envelope"),
        ("\"value\":{", "the Musubi action payload"),
    ] {
        let replacement = format!("{prefix}\"legacy\":true,");
        let hostile = canonical.replacen(prefix, &replacement, 1);
        assert_ne!(
            hostile, canonical,
            "canonical governance proposal JSON must contain {depth}"
        );
        assert!(
            norito::json::from_json::<ProposalKind>(&hostile).is_err(),
            "governance proposal JSON must reject an unknown field at {depth}"
        );
    }
}
#[test]
fn runtime_upgrade_proposal_roundtrip() {
    let manifest = RuntimeUpgradeManifest {
        name: "gov runtime upgrade".to_owned(),
        description: "runtime proposal roundtrip".to_owned(),
        abi_version: 1,
        abi_hash: ivm_abi::syscalls::compute_abi_hash(ivm_abi::SyscallPolicy::AbiV1),
        added_syscalls: Vec::new(),
        added_pointer_types: Vec::new(),
        start_height: 42,
        end_height: 99,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let payload = ProposalKind::RuntimeUpgrade(RuntimeUpgradeProposal {
        proposal_operator: checked_account_id(),
        manifest,
    });
    let framed = norito::to_bytes(&payload).expect("encode runtime-upgrade proposal");
    let decoded = norito::decode_from_bytes::<ProposalKind>(&framed)
        .expect("decode runtime-upgrade proposal");
    match decoded {
        ProposalKind::RuntimeUpgrade(inner) => {
            assert_eq!(inner.manifest.abi_version, 1);
            assert_eq!(inner.manifest.start_height, 42);
        }
        ProposalKind::DeployContract(_) => panic!("unexpected deploy-contract proposal"),
        ProposalKind::SccpRouteGovernance(_) => {
            panic!("unexpected sccp-route-governance proposal")
        }
        ProposalKind::ValidationFeePolicy(_) => {
            panic!("unexpected validation-fee policy proposal")
        }
        ProposalKind::ValidationFeePayoutLifecycle(_) => {
            panic!("unexpected validation-fee payout lifecycle proposal")
        }
        ProposalKind::MusubiRegistryGovernance(_) => {
            panic!("unexpected Musubi registry proposal")
        }
        ProposalKind::SorafsProviderGovernance(_) => {
            panic!("unexpected SoraFS provider-governance proposal")
        }
        ProposalKind::ContractLifecycleGovernance(_) => {
            panic!("unexpected contract-lifecycle proposal")
        }
        ProposalKind::ContractEmergencyHold(_) => {
            panic!("unexpected contract emergency-hold proposal")
        }
        ProposalKind::GlobalDataTriggerPermissionGovernance(_) => {
            panic!("unexpected global data-trigger permission proposal")
        }
    }
}
#[test]
fn runtime_upgrade_proposal_bounds_number_encoded_heights() {
    let proposal = |start_height, end_height| {
        ProposalKind::RuntimeUpgrade(RuntimeUpgradeProposal {
            proposal_operator: checked_account_id(),
            manifest: RuntimeUpgradeManifest {
                name: "bounded runtime upgrade".to_owned(),
                description: "exact JSON height fixture".to_owned(),
                abi_version: 1,
                abi_hash: ivm_abi::syscalls::compute_abi_hash(ivm_abi::SyscallPolicy::AbiV1),
                added_syscalls: Vec::new(),
                added_pointer_types: Vec::new(),
                start_height,
                end_height,
                sbom_digests: Vec::new(),
                slsa_attestation: Vec::new(),
                provenance: Vec::new(),
            },
        })
    };
    let maximum = FIRST_RELEASE_MAX_EXACT_JSON_U64;
    assert_eq!(
        proposal(maximum - 1, maximum).first_release_exact_json_u64_invariant_error(),
        None
    );
    assert!(
        proposal(maximum + 1, maximum + 1)
            .first_release_exact_json_u64_invariant_error()
            .is_some()
    );
    assert!(
        proposal(maximum, maximum + 1)
            .first_release_exact_json_u64_invariant_error()
            .is_some()
    );
}
fn sccp_proposal(
    base_revision: u64,
    actions: Vec<crate::sccp::governance::SccpGovernanceActionV1>,
) -> ProposalKind {
    let mut subjects = actions
        .iter()
        .map(crate::sccp::governance::SccpGovernanceActionV1::subject)
        .collect::<Vec<_>>();
    subjects.sort();
    subjects.dedup();
    ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
        proposal: Box::new(crate::sccp::governance::SccpGovernanceProposalV1 {
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                crate::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"SCCP governance proposal-kind fixture network"),
            )),
            base_revisions: subjects
                .into_iter()
                .map(|subject| (subject, base_revision).into())
                .collect(),
            actions,
        }),
    })
}
fn sccp_set_parameters_action() -> crate::sccp::governance::SccpGovernanceActionV1 {
    crate::sccp::governance::SccpGovernanceActionV1::SetParameters(
        crate::sccp::governance::SccpSetParametersActionV1 {
            next: crate::sccp::params::SccpParametersV1::taira_default(),
        },
    )
}
fn sccp_freeze_action(
    network: crate::bridge::SccpNetworkV1,
) -> crate::sccp::governance::SccpGovernanceActionV1 {
    crate::sccp::governance::SccpGovernanceActionV1::FreezeLightClient(
        crate::sccp::governance::SccpFreezeLightClientActionV1 { network },
    )
}
#[test]
fn sccp_route_governance_proposal_is_boxed_out_of_proposal_kind() {
    assert_eq!(
        core::mem::size_of::<SccpRouteGovernanceProposal>(),
        core::mem::size_of::<Box<crate::sccp::governance::SccpGovernanceProposalV1>>()
    );
}
#[test]
fn sccp_governed_subject_id_is_scoped_to_the_proposal_subject_set() {
    use crate::{bridge::SccpNetworkV1, sccp::governance::SccpGovernanceSubjectV1};
    let parameters = sccp_proposal(0, vec![sccp_set_parameters_action()]);
    let parameters_later = sccp_proposal(7, vec![sccp_set_parameters_action()]);
    assert_ne!(parameters.fingerprint(), parameters_later.fingerprint());
    assert_eq!(
        parameters.governed_subject_id_v1().expect("subject id"),
        parameters_later
            .governed_subject_id_v1()
            .expect("subject id"),
        "base revisions and action content never change the governed subject"
    );
    assert_eq!(
        parameters.governed_subject_id_v1().expect("subject id"),
        crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::GOVERNANCE_SUBJECT_ID_V1,
            &GovernanceSubjectPreimageV1::Sccp(vec![SccpGovernanceSubjectV1::Parameters]),
        )
    );
    let ethereum = sccp_proposal(0, vec![sccp_freeze_action(SccpNetworkV1::EthereumMainnet)]);
    let ton = sccp_proposal(0, vec![sccp_freeze_action(SccpNetworkV1::TonMainnet)]);
    let both = sccp_proposal(
        0,
        vec![
            sccp_freeze_action(SccpNetworkV1::TonMainnet),
            sccp_set_parameters_action(),
        ],
    );
    let ids = [&parameters, &ethereum, &ton, &both]
        .map(|proposal| proposal.governed_subject_id_v1().expect("subject id"));
    for (index, id) in ids.iter().enumerate() {
        for other in &ids[index + 1..] {
            assert_ne!(id, other, "distinct subject sets must not share a head");
        }
    }
    assert_eq!(
        both.governed_subject_id_v1().expect("subject id"),
        crate::governance_fingerprint::fingerprint(
            crate::governance_fingerprint::GOVERNANCE_SUBJECT_ID_V1,
            &GovernanceSubjectPreimageV1::Sccp(vec![
                SccpGovernanceSubjectV1::LightClient(SccpNetworkV1::TonMainnet),
                SccpGovernanceSubjectV1::Parameters,
            ]),
        ),
        "the SCCP subject preimage is the sorted, deduplicated subject list"
    );
}
#[test]
fn sccp_exact_json_u64_arm_uses_the_proposal_check() {
    let maximum = FIRST_RELEASE_MAX_EXACT_JSON_U64;
    assert!(
        sccp_proposal(maximum, vec![sccp_set_parameters_action()])
            .first_release_exact_json_u64_invariant_error()
            .is_none()
    );
    assert!(
        sccp_proposal(maximum + 1, vec![sccp_set_parameters_action()])
            .first_release_exact_json_u64_invariant_error()
            .is_some()
    );
}
#[test]
fn proposal_fingerprint_matches_manual_derivation() {
    let proposal = DeployContractProposal {
        proposal_operator: checked_account_id(),
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address"),
        code_hash: ContractCodeHash::from_hex_str(&"11".repeat(32)).expect("code hash"),
        abi_hash: ContractAbiHash::from_hex_str(&"22".repeat(32)).expect("abi hash"),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    };
    let kind = ProposalKind::DeployContract(proposal);
    let fp = kind.fingerprint();
    let manual_bytes = Encode::encode(&kind);
    let domain = crate::governance_fingerprint::DEPLOY_CONTRACT_V1;
    let domain_len = u64::try_from(domain.len())
        .expect("test domain fits in u64")
        .to_le_bytes();
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar length");
    hasher.update(&domain_len);
    hasher.update(domain);
    hasher.update(&manual_bytes);
    let mut manual_arr = [0u8; 32];
    hasher
        .finalize_variable(&mut manual_arr)
        .expect("finalize Blake2bVar");
    assert_eq!(fp, manual_arr);
    assert_ne!(fp, [0; 32]);
}
#[test]
fn vote_choice_roundtrip() {
    let vote = Vote {
        referendum_id: ProposalId([0x42; 32]),
        voter: AccountId::new(
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key"),
        ),
        conviction: 3,
        choice: VoteChoice::Aye,
    };
    let framed = norito::to_bytes(&vote).expect("encode vote");
    let decoded = norito::decode_from_bytes::<Vote>(&framed).expect("decode vote");
    assert_eq!(decoded.choice, VoteChoice::Aye);
}
#[test]

fn proposal_id_json_roundtrip() {
    let id = ProposalId([0xAB; 32]);
    let json = norito::json::to_json(&id).expect("serialize proposal id");
    let decoded: ProposalId = norito::json::from_json(&json).expect("deserialize proposal id");
    assert_eq!(decoded, id);
}
#[test]
fn canonical_governance_ids_roundtrip_and_reject_legacy_vec_wire() {
    let content_id = ProposalContentId::new([0x41; 32]);
    let attempt_id = GovernanceAttemptId::new([0x42; 32]);
    let content_bytes = norito::to_bytes(&content_id).expect("encode proposal content id");
    let attempt_bytes = norito::to_bytes(&attempt_id).expect("encode governance attempt id");
    assert_eq!(
        norito::decode_from_bytes::<ProposalContentId>(&content_bytes)
            .expect("decode proposal content id"),
        content_id
    );
    assert_eq!(
        norito::decode_from_bytes::<GovernanceAttemptId>(&attempt_bytes)
            .expect("decode governance attempt id"),
        attempt_id
    );

    let mut legacy_vec = Vec::new();
    norito::core::serialize_to_buffer(&vec![0x41_u8; 32], &mut legacy_vec)
        .expect("encode legacy byte vector");
    assert!(
        <ProposalContentId as DecodeFromSlice>::decode_from_slice(&legacy_vec).is_err(),
        "new governance ids must accept only the versioned HashWire32 layout"
    );
}
#[test]
fn risk_tier_only_allows_upward_escalation() {
    assert!(RiskTierV1::Routine.can_escalate_to(RiskTierV1::Routine));
    assert!(RiskTierV1::Routine.can_escalate_to(RiskTierV1::Constitutional));
    assert!(RiskTierV1::Constitutional.can_escalate_to(RiskTierV1::Emergency));
    assert!(!RiskTierV1::Constitutional.can_escalate_to(RiskTierV1::Standard));
    assert!(!RiskTierV1::Emergency.can_escalate_to(RiskTierV1::Constitutional));
}
fn checked_sortition_request(
    candidate_count: u32,
    target_seats: u32,
    request_height: u64,
    pulse_height: u64,
    last_consumed_pulse_height: Option<u64>,
) -> Result<SortitionRequestV1, SortitionRequestErrorV1> {
    let governance_attempt_id = GovernanceAttemptId::new([0x32; 32]);
    let body_election_attempt_id =
        BodyElectionAttemptId::derive_v1(governance_attempt_id, ParliamentBody::PolicyJury, 2);
    SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        body_election_attempt_id,
        ParliamentBody::PolicyJury,
        [0x34; 32],
        candidate_count,
        target_seats,
        request_height,
        pulse_height,
        BeaconSessionId::new([0x35; 32]),
        last_consumed_pulse_height,
    )
}
#[test]
fn sortition_request_rejects_zero_and_reused_heights() {
    assert_eq!(
        checked_sortition_request(500, 500, 0, 0, None),
        Err(SortitionRequestErrorV1::ZeroRequestHeight)
    );
    assert_eq!(
        checked_sortition_request(500, 500, 1, 0, None),
        Err(SortitionRequestErrorV1::ZeroPulseHeight)
    );
    assert_eq!(
        checked_sortition_request(500, 500, 40, 40, None),
        Err(SortitionRequestErrorV1::PulseNotStrictlyFuture {
            request_height: 40,
            pulse_height: 40,
        })
    );
    assert_eq!(
        checked_sortition_request(500, 500, 40, 50, Some(50)),
        Err(SortitionRequestErrorV1::PulseAlreadyConsumed {
            pulse_height: 50,
            last_consumed_pulse_height: 50,
        })
    );
}
#[test]
fn sortition_request_enforces_candidate_and_target_bounds() {
    assert_eq!(
        checked_sortition_request(0, 500, 40, 50, None),
        Err(SortitionRequestErrorV1::EmptyCandidateSnapshot)
    );
    assert_eq!(
        checked_sortition_request(MAX_PARLIAMENT_CITIZENS_V1 + 1, 500, 40, 50, None),
        Err(SortitionRequestErrorV1::CandidateCountExceedsMaximum {
            candidate_count: MAX_PARLIAMENT_CITIZENS_V1 + 1,
            maximum: MAX_PARLIAMENT_CITIZENS_V1,
        })
    );
    assert_eq!(
        checked_sortition_request(500, 0, 40, 50, None),
        Err(SortitionRequestErrorV1::ZeroTargetSeats)
    );
    assert_eq!(
        checked_sortition_request(1_001, MAX_PARLIAMENT_BODY_TARGET_SEATS_V1 + 1, 40, 50, None,),
        Err(SortitionRequestErrorV1::TargetSeatsExceedMaximum {
            target_seats: MAX_PARLIAMENT_BODY_TARGET_SEATS_V1 + 1,
            maximum: MAX_PARLIAMENT_BODY_TARGET_SEATS_V1,
        })
    );
    let undersubscribed =
        checked_sortition_request(1, MAX_PARLIAMENT_BODY_TARGET_SEATS_V1, 40, 50, Some(49))
            .expect("a nonempty tiny electorate remains binding");
    undersubscribed
        .validate(Some(49))
        .expect("valid sortition request revalidates");
}
#[cfg(feature = "governance")]
#[test]
fn empty_sortition_capacity_intent_preserves_every_other_invariant() {
    let governance_attempt_id = GovernanceAttemptId::new([0x73; 32]);
    let body = ParliamentBody::PolicyJury;
    let mut request = SortitionRequestV1 {
        id: SortitionRequestId::new([0; 32]),
        governance_attempt_id,
        body_election_attempt_id: BodyElectionAttemptId::derive_v1(governance_attempt_id, body, 0),
        body,
        candidate_root: [0x74; 32],
        candidate_count: 0,
        target_seats: 3,
        request_height: 40,
        pulse_height: 50,
        beacon_session_id: BeaconSessionId::new([0x75; 32]),
    };
    request.id = request.canonical_id();
    assert_eq!(
        request.validate(None),
        Err(SortitionRequestErrorV1::EmptyCandidateSnapshot)
    );
    request
        .validate_capacity_intent(None)
        .expect("canonical empty snapshot remains a valid capacity intent");

    for (mut invalid, expected) in [
        (
            SortitionRequestV1 {
                target_seats: 0,
                ..request
            },
            SortitionRequestErrorV1::ZeroTargetSeats,
        ),
        (
            SortitionRequestV1 {
                target_seats: MAX_PARLIAMENT_BODY_TARGET_SEATS_V1 + 1,
                ..request
            },
            SortitionRequestErrorV1::TargetSeatsExceedMaximum {
                target_seats: MAX_PARLIAMENT_BODY_TARGET_SEATS_V1 + 1,
                maximum: MAX_PARLIAMENT_BODY_TARGET_SEATS_V1,
            },
        ),
        (
            SortitionRequestV1 {
                request_height: 0,
                ..request
            },
            SortitionRequestErrorV1::ZeroRequestHeight,
        ),
        (
            SortitionRequestV1 {
                pulse_height: request.request_height,
                ..request
            },
            SortitionRequestErrorV1::PulseNotStrictlyFuture {
                request_height: request.request_height,
                pulse_height: request.request_height,
            },
        ),
    ] {
        invalid.id = invalid.canonical_id();
        assert_eq!(invalid.validate_capacity_intent(None), Err(expected));
    }
}
#[test]
fn sortition_request_rejects_zero_digest_bindings() {
    let request =
        checked_sortition_request(500, 500, 40, 50, None).expect("baseline sortition request");
    for invalid in [
        SortitionRequestV1 {
            id: SortitionRequestId::new([0; 32]),
            ..request
        },
        SortitionRequestV1 {
            governance_attempt_id: GovernanceAttemptId::new([0; 32]),
            ..request
        },
        SortitionRequestV1 {
            body_election_attempt_id: BodyElectionAttemptId::new([0; 32]),
            ..request
        },
        SortitionRequestV1 {
            candidate_root: [0; 32],
            ..request
        },
        SortitionRequestV1 {
            beacon_session_id: BeaconSessionId::new([0; 32]),
            ..request
        },
    ] {
        assert_eq!(
            invalid.validate(None),
            Err(SortitionRequestErrorV1::ZeroBinding)
        );
    }
}
#[test]
fn body_election_attempt_enforces_request_bindings_and_roundtrips() {
    let request =
        checked_sortition_request(500, 500, 40, 50, None).expect("valid future-pulse request");
    assert_eq!(
        BodyElectionAttemptV1::try_new(
            request.body_election_attempt_id,
            GovernanceAttemptId::new([0xFF; 32]),
            0,
            request,
            BodyElectionAttemptStatusV1::AwaitingPulse,
        ),
        Err(BodyElectionAttemptErrorV1::GovernanceAttemptMismatch)
    );
    assert_eq!(
        BodyElectionAttemptV1::try_new(
            BodyElectionAttemptId::new([0xFE; 32]),
            request.governance_attempt_id,
            0,
            request,
            BodyElectionAttemptStatusV1::AwaitingPulse,
        ),
        Err(BodyElectionAttemptErrorV1::ElectionAttemptMismatch)
    );
    let attempt = BodyElectionAttemptV1::try_new(
        request.body_election_attempt_id,
        request.governance_attempt_id,
        2,
        request,
        BodyElectionAttemptStatusV1::Drawing,
    )
    .expect("matching request bindings");
    let bytes = norito::to_bytes(&attempt).expect("encode body-election attempt");
    assert_eq!(
        norito::decode_from_bytes::<BodyElectionAttemptV1>(&bytes)
            .expect("decode body-election attempt"),
        attempt
    );

    let mut invalid_request = request;
    invalid_request.candidate_count += 1;
    assert!(matches!(
        BodyElectionAttemptV1::try_new(
            request.body_election_attempt_id,
            request.governance_attempt_id,
            2,
            invalid_request,
            BodyElectionAttemptStatusV1::AwaitingPulse,
        ),
        Err(BodyElectionAttemptErrorV1::InvalidSortitionRequest(
            SortitionRequestErrorV1::NonCanonicalIdentifier
        ))
    ));

    let sequence = MAX_PARLIAMENT_SORTITION_RETRIES_V1 + 1;
    let governance_attempt_id = request.governance_attempt_id;
    let body_election_attempt_id = BodyElectionAttemptId::derive_v1(
        governance_attempt_id,
        ParliamentBody::PolicyJury,
        sequence,
    );
    let request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        body_election_attempt_id,
        ParliamentBody::PolicyJury,
        [0x36; 32],
        500,
        500,
        40,
        50,
        BeaconSessionId::new([0x35; 32]),
        None,
    )
    .expect("structurally valid over-limit request");
    assert_eq!(
        BodyElectionAttemptV1::try_new(
            body_election_attempt_id,
            governance_attempt_id,
            sequence,
            request,
            BodyElectionAttemptStatusV1::AwaitingPulse,
        ),
        Err(BodyElectionAttemptErrorV1::RetryLimitExceeded {
            sequence,
            maximum: MAX_PARLIAMENT_SORTITION_RETRIES_V1,
        })
    );
}
#[test]
fn parliament_body_v1_includes_every_separate_body() {
    for body in PARLIAMENT_BODIES_V1 {
        let bytes = norito::to_bytes(&body).expect("encode Parliament body");
        assert_eq!(
            norito::decode_from_bytes::<ParliamentBody>(&bytes).expect("decode Parliament body"),
            body
        );
    }
}
#[test]
fn parliament_quorum_is_ceil_two_thirds_without_overflow() {
    assert_eq!(parliament_quorum_seats_v1(0), 0);
    assert_eq!(parliament_quorum_seats_v1(1), 1);
    assert_eq!(parliament_quorum_seats_v1(2), 2);
    assert_eq!(parliament_quorum_seats_v1(3), 2);
    assert_eq!(parliament_quorum_seats_v1(4), 3);
    assert_eq!(parliament_quorum_seats_v1(500), 334);
    assert_eq!(parliament_quorum_seats_v1(u32::MAX), 2_863_311_530);
}
#[test]
fn parliament_tally_validation_enforces_corpus_conservation() {
    let mismatched = ParliamentAggregateTallyV1 {
        original_seats: 5,
        accepted_ballots: 4,
        aye: 2,
        nay: 1,
        abstain: 0,
    };
    assert!(matches!(
        mismatched.validate(),
        Err(ParliamentTallyErrorV1::CountSumMismatch {
            accepted_ballots: 4,
            counted_ballots: 3
        })
    ));
    let oversized = ParliamentAggregateTallyV1 {
        original_seats: 2,
        accepted_ballots: 3,
        aye: 2,
        nay: 1,
        abstain: 0,
    };
    assert!(matches!(
        oversized.validate(),
        Err(ParliamentTallyErrorV1::CorpusExceedsOriginalSeats {
            accepted_ballots: 3,
            original_seats: 2
        })
    ));
    let privacy_unsafe = ParliamentAggregateTallyV1 {
        original_seats: 3,
        accepted_ballots: 2,
        aye: 1,
        nay: 1,
        abstain: 0,
    };
    assert_eq!(
        privacy_unsafe.validate(),
        Err(ParliamentTallyErrorV1::CorpusBelowAnonymityFloor {
            accepted_ballots: 2,
            minimum: MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
        })
    );
}
#[test]
fn parliament_decision_counts_abstain_for_quorum_and_requires_aye_majority() {
    let approved = ParliamentAggregateTallyV1 {
        original_seats: 6,
        accepted_ballots: 4,
        aye: 2,
        nay: 1,
        abstain: 1,
    };
    assert_eq!(
        approved.decision().expect("well-formed approved tally"),
        ParliamentAggregateOutcomeV1::Approved
    );
    let tied = ParliamentAggregateTallyV1 {
        aye: 1,
        nay: 1,
        abstain: 2,
        ..approved
    };
    assert_eq!(
        tied.decision().expect("well-formed tied tally"),
        ParliamentAggregateOutcomeV1::Rejected
    );
    let no_quorum = ParliamentAggregateTallyV1 {
        original_seats: 6,
        accepted_ballots: 3,
        aye: 3,
        nay: 0,
        abstain: 0,
    };
    assert_eq!(
        no_quorum.decision().expect("well-formed low-turnout tally"),
        ParliamentAggregateOutcomeV1::NoQuorum
    );
    assert_eq!(
        ParliamentAggregateTallyV1::default().decision(),
        Err(ParliamentTallyErrorV1::CorpusBelowAnonymityFloor {
            accepted_ballots: 0,
            minimum: MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
        })
    );
}
#[test]
fn confirmation_margin_is_strictly_below_five_percent() {
    assert_eq!(
        ParliamentAggregateTallyV1::default().requires_confirmation(),
        Err(ParliamentTallyErrorV1::CorpusBelowAnonymityFloor {
            accepted_ballots: 0,
            minimum: MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
        })
    );
    let below_five = ParliamentAggregateTallyV1 {
        original_seats: 41,
        accepted_ballots: 41,
        aye: 21,
        nay: 20,
        abstain: 0,
    };
    assert!(
        below_five
            .requires_confirmation()
            .expect("well-formed narrow tally")
    );
    let exactly_five = ParliamentAggregateTallyV1 {
        original_seats: 40,
        accepted_ballots: 40,
        aye: 21,
        nay: 19,
        abstain: 0,
    };
    assert!(
        !exactly_five
            .requires_confirmation()
            .expect("well-formed exact-boundary tally")
    );
}
#[test]
fn assignment_plan_root_binds_rank_and_cross_body_cap() {
    let governance_attempt_id = GovernanceAttemptId::new([0x4A; 32]);
    let election_attempt_id =
        BodyElectionAttemptId::derive_v1(governance_attempt_id, ParliamentBody::RulesCommittee, 0);
    let first = checked_account_id();
    let second = checked_account_id();
    let primary = vec![ParliamentSeatAssignmentV1 {
        assignment_id: AssignmentId::derive_v1(election_attempt_id, &first),
        member: first,
    }];
    let alternates = vec![ParliamentSeatAssignmentV1 {
        assignment_id: AssignmentId::derive_v1(election_attempt_id, &second),
        member: second,
    }];
    let root = parliament_assignment_plan_root_v1(election_attempt_id, &primary, &alternates, 1);
    assert_ne!(root, [0; 32]);
    assert_ne!(
        root,
        parliament_assignment_plan_root_v1(election_attempt_id, &alternates, &primary, 1,)
    );
    assert_ne!(
        root,
        parliament_assignment_plan_root_v1(election_attempt_id, &primary, &alternates, 2,)
    );
}

#[test]
fn ballot_participant_hash_binds_authenticated_member_and_attempt() {
    let member = checked_account_id();
    let other_member = checked_account_id();
    let first_ballot = BallotAttemptId::new([0xA1; 32]);
    let other_ballot = BallotAttemptId::new([0xA2; 32]);
    let participant_hash = parliament_ballot_participant_hash_v1(first_ballot, &member);
    assert_ne!(participant_hash, [0; 32]);
    assert_eq!(
        participant_hash,
        parliament_ballot_participant_hash_v1(first_ballot, &member)
    );
    assert_ne!(
        participant_hash,
        parliament_ballot_participant_hash_v1(first_ballot, &other_member)
    );
    assert_ne!(
        participant_hash,
        parliament_ballot_participant_hash_v1(other_ballot, &member)
    );
}
#[test]
fn parliament_lifecycle_snapshots_roundtrip() {
    let governance_attempt_id = GovernanceAttemptId::new([0x51; 32]);
    let body_instance_id = BodyInstanceId::new([0x52; 32]);
    let attempt = GovernanceAttemptV1 {
        id: governance_attempt_id,
        proposal_content_id: ProposalContentId::new([0x50; 32]),
        sequence: 2,
        risk_tier: RiskTierV1::Constitutional,
        stage: GovernanceStageV1::PolicyJury,
        status: GovernanceAttemptStatusV1::Active,
    };
    let body = ParliamentBodyInstanceV1 {
        id: body_instance_id,
        governance_attempt_id,
        election_attempt_id: BodyElectionAttemptId::new([0x53; 32]),
        body: ParliamentBody::PolicyJury,
        target_seats: 500,
        original_seats: 497,
        status: BodyInstanceStatusV1::Deliberating(DeliberationPhaseV1::Reflection),
    };
    let ballot = ParliamentBallotAttemptV1 {
        id: BallotAttemptId::new([0x54; 32]),
        body_instance_id,
        sequence: 1,
        original_seats: 497,
        status: BallotAttemptStatusV1::TimedCommitment,
    };
    for (name, encoded, expected) in [
        (
            "attempt",
            norito::to_bytes(&attempt).expect("encode attempt"),
            norito::to_bytes(&attempt).expect("encode expected attempt"),
        ),
        (
            "body",
            norito::to_bytes(&body).expect("encode body"),
            norito::to_bytes(&body).expect("encode expected body"),
        ),
        (
            "ballot",
            norito::to_bytes(&ballot).expect("encode ballot"),
            norito::to_bytes(&ballot).expect("encode expected ballot"),
        ),
    ] {
        assert_eq!(encoded, expected, "{name} encoding must be deterministic");
    }
    assert_eq!(
        norito::decode_from_bytes::<GovernanceAttemptV1>(
            &norito::to_bytes(&attempt).expect("encode governance attempt")
        )
        .expect("decode governance attempt"),
        attempt
    );
    assert_eq!(
        norito::decode_from_bytes::<ParliamentBodyInstanceV1>(
            &norito::to_bytes(&body).expect("encode body instance")
        )
        .expect("decode body instance"),
        body
    );
    assert_eq!(
        norito::decode_from_bytes::<ParliamentBallotAttemptV1>(
            &norito::to_bytes(&ballot).expect("encode ballot attempt")
        )
        .expect("decode ballot attempt"),
        ballot
    );
}
fn policy_jury_ballot(body_instance_id: BodyInstanceId) -> ParliamentBallotCertificateBindingV1 {
    let tally = ParliamentAggregateTallyV1 {
        original_seats: 500,
        accepted_ballots: 334,
        aye: 200,
        nay: 100,
        abstain: 34,
    };
    let ballot_attempt_sequence = 0;
    let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, ballot_attempt_sequence);
    let release_beacon_session_id = BeaconSessionId::new([0x85; 32]);
    let tle_key_session_id = TleKeySessionId::new([0x8E; 32]);
    let release_height = 1_757;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    let opening_root = [0x7E; 32];
    let outcome = ParliamentAggregateOutcomeV1::Approved;
    ParliamentBallotCertificateBindingV1 {
        ballot_attempt_id,
        ballot_attempt_sequence,
        tle_session_id,
        tle_key_session_id,
        registration_root: [0x81; 32],
        dropout_root: [0x82; 32],
        survivor_root: [0x83; 32],
        corpus_root: [0x6D; 32],
        no_recovery_root: [0x6E; 32],
        timed_commitment_root: [0x84; 32],
        release_beacon_session_id,
        registered_at_height: 140,
        registration_close_height: 641,
        survivor_freeze_height: 1_141,
        commitment_close_height: 1_157,
        registration_closed_at_height: 641,
        survivors_frozen_at_height: 1_141,
        commitment_closed_at_height: 1_157,
        max_ballot_retries: 3,
        max_corpus_entries: 500,
        release_height,
        opening_deadline_height: 2_357,
        release_pulse_id: BeaconPulseId::new([0x7D; 32]),
        opening_height: release_height,
        opening_root,
        tally,
        outcome,
    }
}

fn policy_jury_body(
    governance_attempt_id: GovernanceAttemptId,
) -> ParliamentBodyCertificateBindingV1 {
    let election_attempt_sequence = 0;
    let election_attempt_id = BodyElectionAttemptId::derive_v1(
        governance_attempt_id,
        ParliamentBody::PolicyJury,
        election_attempt_sequence,
    );
    let sortition_request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        election_attempt_id,
        ParliamentBody::PolicyJury,
        [0x80; 32],
        1_000,
        500,
        100,
        101,
        BeaconSessionId::new([0x66; 32]),
        None,
    )
    .expect("canonical Policy Jury request");
    let roster_root = [0x68; 32];
    let body_instance_id = BodyInstanceId::derive_v1(election_attempt_id, roster_root);
    let ballot = policy_jury_ballot(body_instance_id);
    let result_height = 1_800;
    let result_root = parliament_ballot_result_root_v1(
        governance_attempt_id,
        body_instance_id,
        ballot.ballot_attempt_id,
        ballot.opening_root,
        ballot.tally,
        ballot.outcome,
        result_height,
    );
    ParliamentBodyCertificateBindingV1 {
        body_instance_id,
        election_attempt_id,
        election_attempt_sequence,
        sortition_request_id: sortition_request.id,
        sortition_request,
        body: ParliamentBody::PolicyJury,
        original_seats: ballot.tally.original_seats,
        beacon_session_id: BeaconSessionId::new([0x66; 32]),
        beacon_pulse_id: BeaconPulseId::new([0x67; 32]),
        roster_root,
        assignment_root: [0x69; 32],
        result_root,
        result_height,
        public_finding: None,
        ballot: Some(ballot),
    }
}

fn policy_jury_certificate() -> GovernanceCertificateV1 {
    let proposal_content_id = ProposalContentId::new([0x61; 32]);
    let governance_attempt_sequence = 0;
    let governance_attempt_id =
        GovernanceAttemptId::derive_v1(proposal_content_id, governance_attempt_sequence);
    let body = policy_jury_body(governance_attempt_id);
    let result_height = body.result_height;
    GovernanceCertificateV1 {
        proposal_content_id,
        governance_attempt_id,
        governance_attempt_sequence,
        risk_tier: RiskTierV1::Standard,
        body_bindings: vec![body],
        policy_version: PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
        effect_preimage_hash: [0x6F; 32],
        expected_head: GovernanceExpectedHeadV1::Present(GovernanceExpectedHeadPresentV1 {
            subject_id: [0x70; 32],
            version: 3,
            head_root: [0x71; 32],
        }),
        certified_at_height: result_height,
        enact_at_height: result_height + 1,
    }
}

fn public_finding_body(
    governance_attempt_id: GovernanceAttemptId,
) -> ParliamentBodyCertificateBindingV1 {
    let public_election_attempt_sequence = 0;
    let public_election_attempt_id = BodyElectionAttemptId::derive_v1(
        governance_attempt_id,
        ParliamentBody::RulesCommittee,
        public_election_attempt_sequence,
    );
    let public_request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        public_election_attempt_id,
        ParliamentBody::RulesCommittee,
        [0xB0; 32],
        3,
        3,
        80,
        81,
        BeaconSessionId::new([0xB1; 32]),
        None,
    )
    .expect("canonical public-finding request");
    let public_roster_root = [0xB2; 32];
    let public_body_instance_id =
        BodyInstanceId::derive_v1(public_election_attempt_id, public_roster_root);
    let public_result_root = [0xB3; 32];
    let endorsing_assignments = vec![AssignmentId::new([0xB4; 32]), AssignmentId::new([0xB5; 32])];
    let public_endorsement_root = parliament_public_finding_endorsement_root_v1(
        governance_attempt_id,
        public_body_instance_id,
        public_result_root,
        &endorsing_assignments,
    );
    ParliamentBodyCertificateBindingV1 {
        body_instance_id: public_body_instance_id,
        election_attempt_id: public_election_attempt_id,
        election_attempt_sequence: public_election_attempt_sequence,
        sortition_request_id: public_request.id,
        sortition_request: public_request,
        body: ParliamentBody::RulesCommittee,
        original_seats: 3,
        beacon_session_id: BeaconSessionId::new([0xB1; 32]),
        beacon_pulse_id: BeaconPulseId::new([0xB6; 32]),
        roster_root: public_roster_root,
        assignment_root: [0xB7; 32],
        result_root: public_result_root,
        result_height: 90,
        public_finding: Some(ParliamentPublicFindingCertificateBindingV1 {
            endorsement_root: public_endorsement_root,
            endorsing_assignments,
            endorsements: 2,
            quorum: 2,
        }),
        ballot: None,
    }
}

fn confirmation_jury_ballot(
    body_instance_id: BodyInstanceId,
) -> ParliamentBallotCertificateBindingV1 {
    let confirmation_ballot_attempt_sequence = 0;
    let confirmation_ballot_attempt_id =
        BallotAttemptId::derive_v1(body_instance_id, confirmation_ballot_attempt_sequence);
    let confirmation_release_beacon_session_id = BeaconSessionId::new([0x8B; 32]);
    let confirmation_tle_key_session_id = TleKeySessionId::new([0x8F; 32]);
    let confirmation_release_height = 3_457;
    ParliamentBallotCertificateBindingV1 {
        ballot_attempt_id: confirmation_ballot_attempt_id,
        ballot_attempt_sequence: confirmation_ballot_attempt_sequence,
        tle_session_id: TleSessionId::derive_v1(
            confirmation_ballot_attempt_id,
            confirmation_tle_key_session_id,
            confirmation_release_beacon_session_id,
            confirmation_release_height,
        ),
        tle_key_session_id: confirmation_tle_key_session_id,
        registration_root: [0x87; 32],
        dropout_root: [0x88; 32],
        survivor_root: [0x89; 32],
        corpus_root: [0x7B; 32],
        no_recovery_root: [0x7C; 32],
        timed_commitment_root: [0x8A; 32],
        release_beacon_session_id: confirmation_release_beacon_session_id,
        registered_at_height: 1_840,
        registration_close_height: 2_341,
        survivor_freeze_height: 2_841,
        commitment_close_height: 2_857,
        registration_closed_at_height: 2_341,
        survivors_frozen_at_height: 2_841,
        commitment_closed_at_height: 2_857,
        max_ballot_retries: 3,
        max_corpus_entries: 500,
        release_height: confirmation_release_height,
        opening_deadline_height: 4_057,
        release_pulse_id: BeaconPulseId::new([0x8C; 32]),
        opening_height: confirmation_release_height,
        opening_root: [0x8D; 32],
        tally: ParliamentAggregateTallyV1 {
            original_seats: 500,
            accepted_ballots: 500,
            aye: 300,
            nay: 150,
            abstain: 50,
        },
        outcome: ParliamentAggregateOutcomeV1::Approved,
    }
}

fn confirmation_jury_body(
    policy: &ParliamentBodyCertificateBindingV1,
    governance_attempt_id: GovernanceAttemptId,
) -> ParliamentBodyCertificateBindingV1 {
    let mut confirmation = policy.clone();
    confirmation.body = ParliamentBody::ConfirmationJury;
    confirmation.election_attempt_sequence = 0;
    confirmation.election_attempt_id = BodyElectionAttemptId::derive_v1(
        governance_attempt_id,
        ParliamentBody::ConfirmationJury,
        confirmation.election_attempt_sequence,
    );
    confirmation.sortition_request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        confirmation.election_attempt_id,
        ParliamentBody::ConfirmationJury,
        [0x86; 32],
        500,
        500,
        1_800,
        1_802,
        BeaconSessionId::new([0x66; 32]),
        None,
    )
    .expect("canonical Confirmation Jury request");
    confirmation.sortition_request_id = confirmation.sortition_request.id;
    confirmation.beacon_pulse_id = BeaconPulseId::new([0x75; 32]);
    confirmation.roster_root = [0x76; 32];
    confirmation.body_instance_id =
        BodyInstanceId::derive_v1(confirmation.election_attempt_id, confirmation.roster_root);
    confirmation.assignment_root = [0x77; 32];
    confirmation.result_root = [0x78; 32];
    confirmation.result_height = 3_500;
    confirmation.ballot = Some(confirmation_jury_ballot(confirmation.body_instance_id));
    let confirmation_ballot = confirmation.ballot.expect("confirmation ballot");
    confirmation.result_root = parliament_ballot_result_root_v1(
        governance_attempt_id,
        confirmation.body_instance_id,
        confirmation_ballot.ballot_attempt_id,
        confirmation_ballot.opening_root,
        confirmation_ballot.tally,
        confirmation_ballot.outcome,
        confirmation.result_height,
    );
    confirmation
}

fn assert_governance_certificate_limits(certificate: &GovernanceCertificateV1) {
    let mut delayed_certificate = certificate.clone();
    delayed_certificate.certified_at_height += 1;
    delayed_certificate.enact_at_height += 1;
    assert_eq!(
        delayed_certificate.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle),
        "certification must be atomic with the final body result"
    );

    let mut unsupported_policy = certificate.clone();
    unsupported_policy.policy_version = PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 + 1;
    assert_eq!(
        unsupported_policy.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle)
    );

    let mut zero_version_head = certificate.clone();
    let GovernanceExpectedHeadV1::Present(ref mut head) = zero_version_head.expected_head else {
        unreachable!("fixture uses a present compare-and-set head")
    };
    head.version = 0;
    assert_eq!(
        zero_version_head.validate(),
        Err(GovernanceCertificateErrorV1::InvalidExpectedHead)
    );

    let mut over_limit_attempt = certificate.clone();
    over_limit_attempt.governance_attempt_sequence =
        MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 + 1;
    over_limit_attempt.governance_attempt_id = GovernanceAttemptId::derive_v1(
        over_limit_attempt.proposal_content_id,
        over_limit_attempt.governance_attempt_sequence,
    );
    assert_eq!(
        over_limit_attempt.validate(),
        Err(GovernanceCertificateErrorV1::RetryLimitExceeded)
    );

    let mut impossible_seat_count = certificate.clone();
    impossible_seat_count.body_bindings[0].original_seats = impossible_seat_count.body_bindings[0]
        .sortition_request
        .target_seats
        + 1;
    assert_eq!(
        impossible_seat_count.validate(),
        Err(GovernanceCertificateErrorV1::InvalidSeatCount)
    );

    let mut ballot_predates_sortition = certificate.clone();
    let request_pulse_height = ballot_predates_sortition.body_bindings[0]
        .sortition_request
        .pulse_height;
    ballot_predates_sortition.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .registered_at_height = request_pulse_height;
    assert_eq!(
        ballot_predates_sortition.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle)
    );
}

fn assert_governance_emergency_threshold(certificate: &GovernanceCertificateV1) {
    let governance_attempt_id = certificate.governance_attempt_id;
    let body = &certificate.body_bindings[0];
    let body_instance_id = body.body_instance_id;
    let ballot = body.ballot.expect("fixture ballot");
    let ballot_attempt_id = ballot.ballot_attempt_id;
    let opening_root = ballot.opening_root;
    let outcome = ballot.outcome;
    let result_height = body.result_height;
    let mut emergency = certificate.clone();
    emergency.risk_tier = RiskTierV1::Emergency;
    assert_eq!(
        emergency.validate(),
        Err(GovernanceCertificateErrorV1::EmergencyPolicyJuryThreshold)
    );
    let below_emergency_threshold_tally = ParliamentAggregateTallyV1 {
        original_seats: 500,
        accepted_ballots: 334,
        aye: 333,
        nay: 1,
        abstain: 0,
    };
    emergency.body_bindings[0].result_root = parliament_ballot_result_root_v1(
        governance_attempt_id,
        body_instance_id,
        ballot_attempt_id,
        opening_root,
        below_emergency_threshold_tally,
        outcome,
        result_height,
    );
    emergency.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .tally = below_emergency_threshold_tally;
    assert_eq!(
        emergency.validate(),
        Err(GovernanceCertificateErrorV1::EmergencyPolicyJuryThreshold),
        "one aye below two-thirds of original seats must reject an emergency hold"
    );
    let emergency_tally = ParliamentAggregateTallyV1 {
        original_seats: 500,
        accepted_ballots: 334,
        aye: 334,
        nay: 0,
        abstain: 0,
    };
    let emergency_root = parliament_ballot_result_root_v1(
        governance_attempt_id,
        body_instance_id,
        ballot_attempt_id,
        opening_root,
        emergency_tally,
        outcome,
        result_height,
    );
    emergency.body_bindings[0].result_root = emergency_root;
    emergency.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .tally = emergency_tally;
    emergency
        .validate()
        .expect("exact two-thirds original-seat aye threshold must approve emergency hold");
}

fn assert_governance_commitment_window(certificate: &GovernanceCertificateV1) {
    let mut underprovisioned_commitment_window = certificate.clone();
    underprovisioned_commitment_window.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .max_corpus_entries = 513;
    assert_eq!(
        underprovisioned_commitment_window.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle)
    );

    let mut early_completion = certificate.clone();
    early_completion.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .commitment_closed_at_height = 1_156;
    early_completion
        .validate()
        .expect("corpus completion may occur before the scheduled window close");
    let mut completion_at_freeze = early_completion.clone();
    completion_at_freeze.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .commitment_closed_at_height = 1_141;
    assert_eq!(
        completion_at_freeze.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle)
    );
    let mut completion_after_close = early_completion;
    completion_after_close.body_bindings[0]
        .ballot
        .as_mut()
        .expect("fixture ballot")
        .commitment_closed_at_height = 1_158;
    assert_eq!(
        completion_after_close.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle)
    );
}

fn assert_governance_public_finding(certificate: &GovernanceCertificateV1) {
    let mut with_public_finding = certificate.clone();
    with_public_finding
        .body_bindings
        .insert(0, public_finding_body(certificate.governance_attempt_id));
    with_public_finding
        .validate()
        .expect("public finding carries a self-contained exact quorum binding");
    assert_eq!(
        norito::decode_from_bytes::<GovernanceCertificateV1>(
            &norito::to_bytes(&with_public_finding).expect("encode public-finding certificate")
        )
        .expect("decode public-finding certificate"),
        with_public_finding
    );

    let mut reordered_endorsers = with_public_finding.clone();
    reordered_endorsers.body_bindings[0]
        .public_finding
        .as_mut()
        .expect("public binding")
        .endorsing_assignments
        .swap(0, 1);
    assert_eq!(
        reordered_endorsers.validate(),
        Err(GovernanceCertificateErrorV1::InvalidPublicFinding)
    );
    let mut missing_endorser = with_public_finding.clone();
    missing_endorser.body_bindings[0]
        .public_finding
        .as_mut()
        .expect("public binding")
        .endorsing_assignments
        .pop();
    assert_eq!(
        missing_endorser.validate(),
        Err(GovernanceCertificateErrorV1::InvalidPublicFinding)
    );
}

fn assert_governance_execution_failure(certificate: &GovernanceCertificateV1) {
    let execution_failure_root =
        parliament_execution_failure_root_v1(certificate, certificate.enact_at_height);
    assert_ne!(execution_failure_root, [0; 32]);
    assert_ne!(
        execution_failure_root,
        parliament_execution_failure_root_v1(certificate, certificate.enact_at_height + 1)
    );
    let mut different_certificate = certificate.clone();
    different_certificate.effect_preimage_hash[0] ^= 1;
    assert_ne!(
        execution_failure_root,
        parliament_execution_failure_root_v1(&different_certificate, certificate.enact_at_height,)
    );
    let mut noncanonical_result = certificate.clone();
    noncanonical_result.body_bindings[0].result_root[0] ^= 1;
    assert_eq!(
        noncanonical_result.validate(),
        Err(GovernanceCertificateErrorV1::BallotResultRootMismatch)
    );
}

fn assert_governance_confirmation_jury(certificate: &GovernanceCertificateV1) {
    let governance_attempt_id = certificate.governance_attempt_id;
    let mut narrow = certificate.clone();
    let policy = narrow
        .body_bindings
        .first_mut()
        .expect("fixture has one Policy Jury binding");
    policy.ballot.as_mut().expect("policy ballot").tally = ParliamentAggregateTallyV1 {
        original_seats: 500,
        accepted_ballots: 500,
        aye: 251,
        nay: 249,
        abstain: 0,
    };
    let policy_ballot = policy.ballot.expect("policy ballot");
    policy.result_root = parliament_ballot_result_root_v1(
        governance_attempt_id,
        policy.body_instance_id,
        policy_ballot.ballot_attempt_id,
        policy_ballot.opening_root,
        policy_ballot.tally,
        policy_ballot.outcome,
        policy.result_height,
    );
    assert_eq!(
        narrow.validate(),
        Err(GovernanceCertificateErrorV1::ConfirmationJuryMismatch)
    );

    let confirmation = confirmation_jury_body(&narrow.body_bindings[0], governance_attempt_id);
    let confirmation_result_height = confirmation.result_height;
    narrow.body_bindings.push(confirmation);
    narrow.certified_at_height = confirmation_result_height;
    narrow.enact_at_height = confirmation_result_height + 1;
    narrow
        .validate()
        .expect("narrow Policy Jury approval has a fresh Confirmation Jury result");

    assert_confirmation_sortition_binding(&mut narrow);
}

fn assert_confirmation_sortition_binding(narrow: &mut GovernanceCertificateV1) {
    let mut delayed_initial_confirmation = narrow.clone();
    let confirmation = &mut delayed_initial_confirmation.body_bindings[1];
    let request = confirmation.sortition_request;
    confirmation.sortition_request = SortitionRequestV1::try_new_canonical(
        request.governance_attempt_id,
        request.body_election_attempt_id,
        request.body,
        request.candidate_root,
        request.candidate_count,
        request.target_seats,
        request.request_height + 1,
        request.pulse_height,
        request.beacon_session_id,
        None,
    )
    .expect("one-block-delayed initial Confirmation request is structurally valid");
    confirmation.sortition_request_id = confirmation.sortition_request.id;
    assert_eq!(
        delayed_initial_confirmation.validate(),
        Err(GovernanceCertificateErrorV1::ConfirmationJuryMismatch),
        "sequence-zero Confirmation sortition must be atomic with the Policy result"
    );

    let policy_pulse_id = narrow.body_bindings[0].beacon_pulse_id;
    let confirmation = &mut narrow.body_bindings[1];
    let request = confirmation.sortition_request;
    let different_session_id = BeaconSessionId::new([0x97; 32]);
    confirmation.sortition_request = SortitionRequestV1::try_new_canonical(
        request.governance_attempt_id,
        request.body_election_attempt_id,
        request.body,
        request.candidate_root,
        request.candidate_count,
        request.target_seats,
        request.request_height,
        request.pulse_height,
        different_session_id,
        None,
    )
    .expect("different-session Confirmation request is structurally valid");
    confirmation.sortition_request_id = confirmation.sortition_request.id;
    confirmation.beacon_session_id = different_session_id;
    confirmation.beacon_pulse_id = policy_pulse_id;
    assert_eq!(
        narrow.validate(),
        Err(GovernanceCertificateErrorV1::ConfirmationJuryMismatch),
        "Confirmation must use a fresh pulse id even when the session id differs"
    );
}

#[test]
fn governance_certificate_v1_roundtrip_binds_body_and_ballot_roots() {
    let certificate = policy_jury_certificate();
    let bytes = norito::to_bytes(&certificate).expect("encode GovernanceCertificateV1");
    assert_eq!(
        norito::decode_from_bytes::<GovernanceCertificateV1>(&bytes)
            .expect("decode GovernanceCertificateV1"),
        certificate
    );
    certificate
        .validate()
        .expect("wide Policy Jury approval is a complete structural certificate");
    assert_certificate_coordinate_bindings(&certificate);
    assert_certificate_lifecycle_boundaries(&certificate);

    assert_governance_certificate_limits(&certificate);
    assert_governance_emergency_threshold(&certificate);
    assert_governance_commitment_window(&certificate);
    assert_governance_public_finding(&certificate);
    assert_governance_execution_failure(&certificate);
    assert_governance_confirmation_jury(&certificate);
}

#[test]
fn private_ballot_result_root_binds_every_final_component() {
    let attempt = GovernanceAttemptId::new([0x91; 32]);
    let body = BodyInstanceId::new([0x92; 32]);
    let ballot = BallotAttemptId::new([0x93; 32]);
    let opening = [0x94; 32];
    let tally = ParliamentAggregateTallyV1 {
        original_seats: 5,
        accepted_ballots: 4,
        aye: 3,
        nay: 1,
        abstain: 0,
    };
    let outcome = ParliamentAggregateOutcomeV1::Approved;
    let height = 200;
    let expected =
        parliament_ballot_result_root_v1(attempt, body, ballot, opening, tally, outcome, height);
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(
            GovernanceAttemptId::new([0x95; 32]),
            body,
            ballot,
            opening,
            tally,
            outcome,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(
            attempt,
            BodyInstanceId::new([0x96; 32]),
            ballot,
            opening,
            tally,
            outcome,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(
            attempt,
            body,
            BallotAttemptId::new([0x97; 32]),
            opening,
            tally,
            outcome,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(attempt, body, ballot, [0x98; 32], tally, outcome, height,)
    );
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(
            attempt,
            body,
            ballot,
            opening,
            ParliamentAggregateTallyV1 {
                aye: 2,
                nay: 2,
                ..tally
            },
            outcome,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(
            attempt,
            body,
            ballot,
            opening,
            tally,
            ParliamentAggregateOutcomeV1::Rejected,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_result_root_v1(
            attempt,
            body,
            ballot,
            opening,
            tally,
            outcome,
            height + 1,
        )
    );
}

#[test]
fn public_finding_endorsement_root_binds_exact_ordered_supporters() {
    let attempt = GovernanceAttemptId::new([0xA1; 32]);
    let body = BodyInstanceId::new([0xA2; 32]);
    let result = [0xA3; 32];
    let first = AssignmentId::new([0xA4; 32]);
    let second = AssignmentId::new([0xA5; 32]);
    let supporters = [first, second];
    let expected =
        parliament_public_finding_endorsement_root_v1(attempt, body, result, &supporters);

    assert_ne!(expected, [0; 32]);
    assert_ne!(
        expected,
        parliament_public_finding_endorsement_root_v1(
            GovernanceAttemptId::new([0xA6; 32]),
            body,
            result,
            &supporters,
        )
    );
    assert_ne!(
        expected,
        parliament_public_finding_endorsement_root_v1(
            attempt,
            BodyInstanceId::new([0xA7; 32]),
            result,
            &supporters,
        )
    );
    assert_ne!(
        expected,
        parliament_public_finding_endorsement_root_v1(attempt, body, [0xA8; 32], &supporters,)
    );
    assert_ne!(
        expected,
        parliament_public_finding_endorsement_root_v1(attempt, body, result, &[second, first],)
    );
    assert_ne!(
        expected,
        parliament_public_finding_endorsement_root_v1(attempt, body, result, &[first],)
    );
}

#[test]
fn private_ballot_failure_root_binds_the_derived_failure_identity() {
    let attempt = GovernanceAttemptId::new([0xA1; 32]);
    let ballot = BallotAttemptId::new([0xA2; 32]);
    let kind = ParliamentBallotFailureKindV1::RegistrationDeadlineExpired;
    let height = 200;
    let expected = parliament_ballot_failure_root_v1(attempt, ballot, kind, height);

    assert_ne!(expected, [0; 32]);
    assert_ne!(
        expected,
        parliament_ballot_failure_root_v1(
            GovernanceAttemptId::new([0xA3; 32]),
            ballot,
            kind,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_failure_root_v1(attempt, BallotAttemptId::new([0xA4; 32]), kind, height,)
    );
    assert_ne!(
        expected,
        parliament_ballot_failure_root_v1(
            attempt,
            ballot,
            ParliamentBallotFailureKindV1::SurvivorDeadlineExpired,
            height,
        )
    );
    assert_ne!(
        expected,
        parliament_ballot_failure_root_v1(attempt, ballot, kind, height + 1)
    );
}

fn assert_certificate_coordinate_bindings(certificate: &GovernanceCertificateV1) {
    for coordinate in 0..5 {
        let mut changed = certificate.clone();
        let binding = &mut changed.body_bindings[0];
        match coordinate {
            0 => binding.sortition_request_id = SortitionRequestId::new([0xA1; 32]),
            1 => {
                binding.sortition_request.governance_attempt_id =
                    GovernanceAttemptId::new([0xA2; 32]);
                binding.sortition_request.id = binding.sortition_request.canonical_id();
                binding.sortition_request_id = binding.sortition_request.id;
            }
            2 => binding.election_attempt_id = BodyElectionAttemptId::new([0xA3; 32]),
            3 => binding.body = ParliamentBody::ReviewPanel,
            4 => binding.beacon_session_id = BeaconSessionId::new([0xA4; 32]),
            _ => unreachable!(),
        }
        binding
            .sortition_request
            .validate(None)
            .expect("request remains independently canonical");
        assert_eq!(
            changed.validate(),
            Err(GovernanceCertificateErrorV1::SortitionRequestMismatch),
            "coordinate {coordinate} must fail before derived body identifiers or lifecycle checks"
        );
    }
}

fn assert_certificate_lifecycle_boundaries(certificate: &GovernanceCertificateV1) {
    let pulse = certificate.body_bindings[0].sortition_request.pulse_height;
    for registered in [0, pulse, pulse + 1] {
        let mut changed = certificate.clone();
        changed.body_bindings[0]
            .ballot
            .as_mut()
            .unwrap()
            .registered_at_height = registered;
        let expected = if registered > pulse {
            Ok(())
        } else {
            Err(GovernanceCertificateErrorV1::InvalidLifecycle)
        };
        assert_eq!(
            changed.validate(),
            expected,
            "registration height {registered}"
        );
    }
    let mut changed = certificate.clone();
    let original_seats = changed.body_bindings[0].original_seats;
    changed.body_bindings[0]
        .ballot
        .as_mut()
        .unwrap()
        .max_corpus_entries = original_seats;
    assert_eq!(changed.validate(), Ok(()));
    changed.body_bindings[0]
        .ballot
        .as_mut()
        .unwrap()
        .max_corpus_entries -= 1;
    assert_eq!(
        changed.validate(),
        Err(GovernanceCertificateErrorV1::InvalidLifecycle)
    );
    changed.body_bindings[0].election_attempt_id = BodyElectionAttemptId::new([0xA3; 32]);
    assert_eq!(
        changed.validate(),
        Err(GovernanceCertificateErrorV1::SortitionRequestMismatch)
    );
}

#[path = "tests/certificate_validation.rs"]
mod certificate_validation;
