//! Public finality-authenticated automatic-reward evidence regressions.
//!
//! Fixed public fixture keys certify synthetic accounting statements here. These
//! tests qualify the independent verifier, not execution or a deployed network.
#![cfg(all(feature = "test-fixtures", feature = "transparent_api"))]

use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    block::consensus::{ExecKv, ExecWitness},
    fee_evidence::*,
    governance::types::*,
    oracle::{
        FeedConfigVersion, Observation, ObservationBody, ObservationOutcome, ObservationValue,
    },
    smart_contract::ContractAddress,
    sumeragi_finality::{
        SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiLaneStateCommitment,
        test_fixtures::NativeFinalityFixture,
    },
    sumeragi_lanes::SumeragiLaneState,
    validation_fee::*,
    validation_fee_rewards::*,
};
use iroha_model_base::{
    domain::DomainId,
    name::Name,
    state_path::StatePath,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::numeric::Quantity;
use std::collections::BTreeMap;

const NOW: u64 = 1_793_451_600_000;
fn keypair(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn account(seed: u8) -> AccountId {
    AccountId::new(keypair(seed).public_key().clone())
}
fn binding(network: &NetworkId) -> ValidationFeeTreasuryPayoutBindingV1 {
    let address = |nonce| {
        ContractAddress::derive(network, &account(1), nonce, DataSpaceId::UNIVERSAL).unwrap()
    };
    let asset = |name: &str| {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "paynet").unwrap(),
            name.parse::<Name>().unwrap(),
        )
    };
    ValidationFeeTreasuryPayoutBindingV1 {
        contract_address: address(1),
        code_hash: [1; 32],
        entrypoint: "autonomous_validation_fee_tick".parse().unwrap(),
        treasury_account_id: address(1).subject_id(),
        ds_asset_id: asset("sbd"),
        xor_asset_id: asset("xor"),
        pool_contract_address: address(2),
        pool_code_hash: [2; 32],
        pool_vault_account_id: address(2).subject_id(),
        reward_pool_account_id: address(3).subject_id(),
        reference_feed_id: "xor_per_sbd".parse().unwrap(),
        reference_feed_config_version: 1,
        reference_provider_accounts: (10..15).map(account).collect(),
        max_sbd_per_attempt_minor: 1_000,
        max_sbd_per_day_minor: 100_000,
        min_interval_ms: 60_000,
        max_source_age_ms: 300_000,
        max_slippage_bps: 100,
        validator_lane_id: LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    }
}
fn policy_jury_body(
    governance_attempt_id: GovernanceAttemptId,
    marker: u8,
    base: u64,
) -> ParliamentBodyCertificateBindingV1 {
    let root = |offset: u8| [marker.wrapping_add(offset); 32];
    let election_attempt_sequence = 0;
    let election_attempt_id = BodyElectionAttemptId::derive_v1(
        governance_attempt_id,
        ParliamentBody::PolicyJury,
        election_attempt_sequence,
    );
    let beacon_session_id = BeaconSessionId::new(root(2));
    let sortition_request = SortitionRequestV1::try_new_canonical(
        governance_attempt_id,
        election_attempt_id,
        ParliamentBody::PolicyJury,
        root(1),
        3,
        3,
        base + 1,
        base + 2,
        beacon_session_id,
        None,
    )
    .expect("canonical validation-fee Policy Jury request");
    let roster_root = root(4);
    let body_instance_id = BodyInstanceId::derive_v1(election_attempt_id, roster_root);
    let ballot_attempt_sequence = 0;
    let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, ballot_attempt_sequence);
    let release_beacon_session_id = BeaconSessionId::new(root(7));
    let tle_key_session_id = TleKeySessionId::new(root(8));
    let release_height = base + 12;
    let tle_session_id = TleSessionId::derive_v1(
        ballot_attempt_id,
        tle_key_session_id,
        release_beacon_session_id,
        release_height,
    );
    let opening_root = root(16);
    let tally = ParliamentAggregateTallyV1 {
        original_seats: 3,
        accepted_ballots: 3,
        aye: 2,
        nay: 1,
        abstain: 0,
    };
    let outcome = ParliamentAggregateOutcomeV1::Approved;
    let result_height = base + 13;
    let result_root = parliament_ballot_result_root_v1(
        governance_attempt_id,
        body_instance_id,
        ballot_attempt_id,
        opening_root,
        tally,
        outcome,
        result_height,
    );
    ParliamentBodyCertificateBindingV1 {
        body_instance_id,
        election_attempt_id,
        election_attempt_sequence,
        sortition_request_id: sortition_request.id,
        sortition_request,
        body: ParliamentBody::PolicyJury,
        original_seats: tally.original_seats,
        beacon_session_id,
        beacon_pulse_id: BeaconPulseId::new(root(3)),
        roster_root,
        assignment_root: root(5),
        result_root,
        result_height,
        public_finding: None,
        ballot: Some(ParliamentBallotCertificateBindingV1 {
            ballot_attempt_id,
            ballot_attempt_sequence,
            tle_session_id,
            tle_key_session_id,
            registration_root: root(9),
            dropout_root: root(10),
            survivor_root: root(11),
            corpus_root: root(12),
            no_recovery_root: root(13),
            timed_commitment_root: root(14),
            release_beacon_session_id,
            registered_at_height: base + 3,
            registration_close_height: base + 7,
            survivor_freeze_height: base + 10,
            commitment_close_height: base + 11,
            registration_closed_at_height: base + 7,
            survivors_frozen_at_height: base + 10,
            commitment_closed_at_height: base + 11,
            max_ballot_retries: 3,
            max_corpus_entries: 3,
            release_height,
            opening_deadline_height: result_height,
            release_pulse_id: BeaconPulseId::new(root(15)),
            opening_height: release_height,
            opening_root,
            tally,
            outcome,
        }),
    }
}
fn registry(binding: &ValidationFeeTreasuryPayoutBindingV1) -> ValidationFeePolicyRegistryV1 {
    let proposal_operator = account(7);
    let proposal =
        ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
            proposal_operator: proposal_operator.clone(),
            payout_binding: binding.clone(),
        });
    let proposal_fingerprint = proposal.fingerprint();
    let proposal_content_id = ProposalContentId::new(proposal_fingerprint);
    let governance_attempt_id = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let body = policy_jury_body(governance_attempt_id, 20, 0);
    let governance_certificate = GovernanceCertificateV1 {
        proposal_content_id,
        governance_attempt_id,
        governance_attempt_sequence: 0,
        risk_tier: RiskTierV1::Standard,
        certified_at_height: body.result_height,
        body_bindings: vec![body],
        policy_version: 1,
        effect_preimage_hash: [44; 32],
        expected_head: GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
            subject_id: [45; 32],
        }),
        enact_at_height: 15,
    };
    governance_certificate.validate().unwrap();
    let authorization = ValidationFeeParliamentAuthorizationV1 {
        proposal_operator,
        proposal_fingerprint,
        governance_certificate_id: GovernanceCertificateId::derive_v1(&governance_certificate),
        governance_certificate,
        enacted_at_height: 15,
    };
    let registry = ValidationFeePolicyRegistryV1 {
        registered_policies: vec![],
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![ValidationFeePayoutPolicyEntryV1 {
                revision: 1,
                proposal_id: proposal_fingerprint,
                lifecycle_seal: binding.lifecycle_seal().unwrap(),
                payout_binding: binding.clone(),
                parliament_authorization: authorization,
            }],
        },
    };
    registry.validate().unwrap();
    registry
}
fn record(height: u64, key: StatePath, payload: FeeEvidencePayloadV1) -> FeeEvidenceRecordV1 {
    FeeEvidenceRecordV1 {
        key,
        recorded_at_height: height,
        payload,
    }
}
fn custody(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    height: u64,
    state: ValidationFeeRewardsState,
) -> FeeEvidenceRecordV1 {
    record(
        height,
        validation_fee_reward_state_key(binding, "State").unwrap(),
        FeeEvidencePayloadV1::RewardCustody(FeeRewardCustodySnapshotV1 {
            binding: binding.clone(),
            treasury_sbd_minor: state.pending_sbd_total,
            reward_pool_xor_minor: state.reserved_xor,
            state,
            xor_scale: 2,
        }),
    )
}
fn alias(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    height: u64,
    owner: u8,
    beneficiary: u8,
) -> FeeEvidenceRecordV1 {
    record(
        height,
        validation_fee_beneficiary_alias_key(binding, &account(owner)).unwrap(),
        FeeEvidencePayloadV1::RewardBeneficiaryAlias(ValidationFeeRewardBeneficiaryAlias {
            account_id: account(owner),
            beneficiary_id: account(beneficiary),
        }),
    )
}
fn revision(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    height: u64,
    beneficiary: u8,
    owner: u8,
    previous: Option<u8>,
    number: u64,
) -> FeeEvidenceRecordV1 {
    record(
        height,
        validation_fee_beneficiary_revision_key(binding, &account(beneficiary), number).unwrap(),
        FeeEvidencePayloadV1::RewardBeneficiaryRevision(ValidationFeeRewardBeneficiaryRevision {
            beneficiary_id: account(beneficiary),
            revision: number,
            account_id: account(owner),
            previous_account_id: previous.map(account),
            authorized_at_height: if number == 0 { 18 } else { height },
        }),
    )
}
fn vectors(binding: &ValidationFeeTreasuryPayoutBindingV1) -> Vec<Vec<FeeEvidenceRecordV1>> {
    let period = honiara_month_bounds(NOW - 40 * 86_400_000).unwrap().0;
    let seal = binding.lifecycle_seal().unwrap();
    let mut state = ValidationFeeRewardsState {
        pending_sbd_total: 100,
        ..Default::default()
    };
    let opening = vec![custody(binding, 16, state)];
    let reference_observations = (10..13)
        .map(|seed| {
            let body = ObservationBody {
                feed_id: binding.reference_feed_id.clone(),
                feed_config_version: FeedConfigVersion(1),
                slot: 1,
                provider_id: account(seed),
                connector_id: "signed_xor_per_sbd".into(),
                connector_version: 1,
                request_hash: Hash::new(b"automatic reward evidence"),
                outcome: ObservationOutcome::Value(ObservationValue::new(1, 0)),
                timestamp_ms: Some(NOW),
            };
            ValidationFeeReferenceObservation {
                observation: Observation {
                    signature: SignatureOf::try_new(keypair(seed).private_key(), &body).unwrap(),
                    body,
                },
                admitted_height: 16,
                admitted_at_ms: NOW,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reference_minimum(binding, &reference_observations, NOW + 1, 17, 100, 2).unwrap(),
        Some(99)
    );
    let allocation = ValidationFeeRewardAllocation {
        sequence: 0,
        lifecycle_seal: seal,
        earning_period_start_ms: period,
        sbd_minor: 100,
        xor_minor: 100,
        converted_at_height: 17,
        converted_at_ms: NOW + 1,
        min_xor_minor: 99,
        reference_observations: reference_observations.clone(),
        service_blocks: BTreeMap::from([(account(1), 1)]),
        gross_shares: BTreeMap::from([(account(1), 100)]),
    };
    state.pending_sbd_total = 0;
    state.reserved_xor = 100;
    state.next_allocation = 1;
    state.last_attempt_height = 17;
    state.last_attempt_ms = Some(NOW + 1);
    state.last_conversion_ms = Some(NOW + 1);
    state.conversion_day = (NOW + 1 + 39_600_000) / 86_400_000;
    state.converted_today_sbd = 100;
    let allocation_record = record(
        17,
        validation_fee_reward_state_key(binding, "Allocation/0").unwrap(),
        FeeEvidencePayloadV1::RewardAllocation(allocation.clone()),
    );
    let converted = vec![
        custody(binding, 17, state),
        allocation_record,
        record(
            17,
            validation_fee_reward_state_key(binding, "Attempt/17").unwrap(),
            FeeEvidencePayloadV1::RewardAttempt(ValidationFeeConversionAttempt {
                attempted_at_height: 17,
                attempted_at_ms: NOW + 1,
                earning_period_start_ms: period,
                sbd_minor: 100,
                min_xor_minor: 99,
                lifecycle_seal: seal,
                reference_observations,
            }),
        ),
        record(
            17,
            validation_fee_reward_state_key(binding, &format!("Service/{period:020}")).unwrap(),
            FeeEvidencePayloadV1::RewardService(ValidationFeeServiceSnapshot {
                earning_period_start_ms: period,
                service_blocks: allocation.service_blocks.clone(),
            }),
        ),
    ];
    let page = ValidationFeeExposurePage {
        earning_period_start_ms: period,
        validator: account(1),
        page_index: 0,
        exposure: vec![ValidationFeeRewardExposure {
            service_blocks: 1,
            stakes: BTreeMap::from([
                (account(1), Quantity::from(20u32)),
                (account(2), Quantity::from(30u32)),
                (account(3), Quantity::from(50u32)),
            ]),
        }],
    };
    let entitlement = ValidationFeeRewardEntitlement {
        allocation_sequence: 0,
        validator: account(1),
        page_index: 0,
        service_start: 0,
        service_end: 1,
        recorded_at_height: 18,
        shares: BTreeMap::from([(account(1), 20), (account(2), 30), (account(3), 50)]),
        beneficiaries: (1..4).map(|seed| (account(seed), account(seed))).collect(),
    };
    let mut accrued = vec![
        custody(binding, 18, state),
        record(
            18,
            validation_fee_reward_state_key(binding, "Allocation/0").unwrap(),
            FeeEvidencePayloadV1::RewardAllocationSource(allocation.clone()),
        ),
        record(
            18,
            validation_fee_exposure_page_key(binding, period, &account(1), 0).unwrap(),
            FeeEvidencePayloadV1::RewardExposure(page),
        ),
        record(
            18,
            validation_fee_entitlement_key(binding, 0, &account(1), 0).unwrap(),
            FeeEvidencePayloadV1::RewardEntitlement(entitlement),
        ),
    ];
    accrued.extend((1..4).map(|seed| alias(binding, 18, seed, seed)));
    state.reserved_xor = 0;
    state.next_claim = 3;
    let mut claimed = vec![
        custody(binding, 19, state),
        // Reattaching the same original receipt cannot allocate or reserve again.
        record(
            19,
            validation_fee_reward_state_key(binding, "Allocation/0").unwrap(),
            FeeEvidencePayloadV1::RewardAllocationSource(allocation),
        ),
    ];
    for (sequence, beneficiary, owner, number, amount) in
        [(0, 1, 1, 0, 20), (1, 2, 8, 1, 30), (2, 3, 3, 0, 50)]
    {
        claimed.push(record(
            19,
            validation_fee_reward_state_key(binding, &format!("Claim/{sequence}")).unwrap(),
            FeeEvidencePayloadV1::RewardClaim(ValidationFeeRewardClaim {
                beneficiary_id: account(beneficiary),
                beneficiary_revision: number,
                sequence,
                account_id: account(owner),
                xor_minor: amount,
                claimed_at_height: 19,
                claimed_at_ms: NOW + 3,
                lifecycle_seal: seal,
            }),
        ));
        claimed.push(alias(binding, 19, owner, beneficiary));
        claimed.push(revision(binding, 19, beneficiary, beneficiary, None, 0));
    }
    claimed.push(alias(binding, 19, 2, 2));
    claimed.push(revision(binding, 19, 2, 8, Some(2), 1));
    vec![opening, converted, accrued, claimed]
}

// Independent three-leaf sparse-tree construction. All writes are genuinely
// included in the exact native finality commitment created by the public fixture.
fn siblings(writes: &[ExecKv], key: &[u8]) -> Vec<Hash> {
    let mut nodes: BTreeMap<[u8; 32], Hash> = writes
        .iter()
        .map(|write| {
            let path = Hash::new(&write.key);
            let value = Hash::new(&write.value);
            (
                path.into(),
                Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()]),
            )
        })
        .collect();
    let mut path: [u8; 32] = Hash::new(key).into();
    let empty = Hash::new([]);
    let mut result = Vec::new();
    for level in 0..256 {
        let bit = 255 - level;
        let byte = bit / 8;
        let mask = 1 << (bit % 8);
        let mut sibling = path;
        sibling[byte] ^= mask;
        result.push(nodes.get(&sibling).copied().unwrap_or(empty));
        let mut parents = BTreeMap::new();
        for (node, hash) in &nodes {
            let mut other = *node;
            other[byte] ^= mask;
            let right = node[byte] & mask != 0;
            if right && nodes.contains_key(&other) {
                continue;
            }
            let other_hash = nodes.get(&other).copied().unwrap_or(empty);
            let (left, right) = if right {
                (other_hash, *hash)
            } else {
                (*hash, other_hash)
            };
            let mut parent = *node;
            parent[byte] &= !mask;
            parents.insert(
                parent,
                Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()]),
            );
        }
        path[byte] &= !mask;
        nodes = parents;
    }
    result
}
fn prefix() -> NativeFinalityFixture {
    let mut fixture = NativeFinalityFixture::start("automatic-reward-evidence");
    while fixture.latest().height() < 15 {
        let block = fixture.block_with_submitted_work(fixture.next_header());
        fixture.certify(block);
    }
    fixture
}
fn prove(
    mut fixture: NativeFinalityFixture,
    records: Vec<Vec<FeeEvidenceRecordV1>>,
) -> (FeeEvidenceWindowProofV1, FeeEvidenceTrustAnchorV1) {
    let registry = registry(&binding(&fixture.network_id()));
    let mut blocks = Vec::new();
    let mut checkpoint = None;
    for (index, mut records) in records.into_iter().enumerate() {
        let height = 16 + index as u64;
        let at_ms = NOW + index as u64;
        records.push(record(
            height,
            "native_fee_registry_v1".parse().unwrap(),
            FeeEvidencePayloadV1::PolicyRegistry(registry.clone()),
        ));
        records.sort_by(|a, b| a.key.cmp(&b.key));
        let snapshot = FeeEvidenceSnapshotV1::from_records(height, &records).unwrap();
        let policy =
            ValidationFeePolicySnapshotCommitmentV1::from_registry(height, at_ms, Some(&registry));
        let lane = SumeragiLaneStateCommitment::from_state(
            fixture.network_id(),
            height,
            &SumeragiLaneState::default(),
        )
        .unwrap();
        let writes = vec![
            ExecKv {
                key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
                value: norito::encode_canonical(&snapshot).unwrap(),
            },
            ExecKv {
                key: VALIDATION_FEE_POLICY_WITNESS_KEY_V1.to_vec(),
                value: norito::encode_canonical(&policy).unwrap(),
            },
            ExecKv {
                key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
                value: norito::encode_canonical(&lane).unwrap(),
            },
        ];
        let evidence = FeeEvidenceBlockProofV1 {
            snapshot_witness: FeeEvidenceWitnessProofV1 {
                key: writes[0].key.clone(),
                value: writes[0].value.clone(),
                siblings: siblings(&writes, &writes[0].key),
            },
            records,
        };
        let policy_witness = ValidationFeePolicyWitnessProofV1 {
            key: writes[1].key.clone(),
            value: writes[1].value.clone(),
            siblings: siblings(&writes, &writes[1].key),
        };
        let mut header = fixture.next_header();
        header.creation_time_ms = at_ms;
        let block = fixture.block_with_submitted_work(header);
        let finality = fixture.certify_with_witness(
            block,
            &ExecWitness {
                writes,
                ..Default::default()
            },
        );
        let root = finality
            .decode_checked()
            .unwrap()
            .execution()
            .ordinary_writes_root;
        assert!(evidence.verify(root));
        assert!(policy_witness.verify(root));
        if checkpoint.is_none() {
            checkpoint = Some(fixture.checkpoint());
        }
        blocks.push(FeeEvidenceFinalizedBlockV1 {
            finality,
            evidence,
            policy_witness,
            registry: Some(registry.clone()),
        });
    }
    let anchor = FeeEvidenceTrustAnchorV1 {
        network_id: fixture.network_id(),
        opening_checkpoint: checkpoint.unwrap(),
        closing_height: fixture.latest().height(),
        closing_block_hash: fixture.latest().block_header.hash(),
    };
    (FeeEvidenceWindowProofV1 { version: 1, blocks }, anchor)
}
fn entitlement(records: &mut [FeeEvidenceRecordV1]) -> &mut ValidationFeeRewardEntitlement {
    records
        .iter_mut()
        .find_map(|record| {
            if let FeeEvidencePayloadV1::RewardEntitlement(value) = &mut record.payload {
                Some(value)
            } else {
                None
            }
        })
        .unwrap()
}

#[test]
fn fee_evidence_checked_verification_preserves_decode_refusal_and_exact_retry() {
    let (window, _) = prove(prefix(), vec![Vec::new()]);
    let block = &window.blocks[0];
    let root = block
        .finality
        .decode_checked()
        .unwrap()
        .execution()
        .ordinary_writes_root;
    let original = block.evidence.clone();
    let snapshot = original.snapshot_witness.commitment().unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX);
    norito::with_decode_limits_scope(limits, || {
        let expected =
            norito::decode_canonical::<FeeEvidenceSnapshotV1>(&original.snapshot_witness.value)
                .unwrap_err();
        let actual = block.evidence.verify_checked(root).unwrap_err();
        assert!(norito::core::decode_error_matches_active_limits(&expected));
        assert!(norito::core::decode_error_matches_active_limits(&actual));
        assert_eq!(
            actual.decode_resource_error(),
            expected.decode_resource_error()
        );
    });
    assert_eq!(block.evidence, original);
    assert_eq!(block.evidence.verify_checked(root).unwrap(), Some(snapshot));
    assert!(block.evidence.verify(root));
    assert_eq!(
        block
            .evidence
            .verify_checked(Hash::new(b"other-root"))
            .unwrap(),
        None
    );

    let mut omitted = original.clone();
    omitted.records.clear();
    assert_eq!(omitted.verify_checked(root).unwrap(), None);
    let mut wrong_path = original.clone();
    wrong_path.snapshot_witness.siblings[0] = Hash::new(b"other-sibling");
    assert_eq!(wrong_path.verify_checked(root).unwrap(), None);
    let mut malformed = original;
    malformed.snapshot_witness.value = b"malformed snapshot".to_vec();
    let error = malformed.verify_checked(root).unwrap_err();
    assert!(error.decode_resource_error().is_none());
}

#[test]
fn certified_automatic_rewards_verify_delayed_funding_sources_and_recovered_claims() {
    let prefix = prefix();
    let binding = binding(&prefix.network_id());
    let validator = account(2);
    let archive_key = validation_fee_exposure_archive_key(&binding, 123, &validator, 0).unwrap();
    assert_eq!(
        archive_key,
        validation_fee_reward_state_key(
            &binding,
            &format!(
                "ExposureArchive/{:020}/{}/{:020}",
                123,
                hex::encode(Hash::new(validator.to_string().as_bytes()).as_ref()),
                0,
            )
        )
        .unwrap()
    );
    for changed_key in [
        validation_fee_exposure_archive_key(&binding, 124, &validator, 0).unwrap(),
        validation_fee_exposure_archive_key(&binding, 123, &account(3), 0).unwrap(),
        validation_fee_exposure_archive_key(&binding, 123, &validator, 1).unwrap(),
    ] {
        assert_ne!(
            validation_fee_exposure_archive_witness_key(&archive_key),
            validation_fee_exposure_archive_witness_key(&changed_key)
        );
    }
    let (proof, anchor) = prove(prefix, vectors(&binding));
    proof
        .verify(&anchor)
        .expect("funded 20/30/50 entitlements and recovered withdrawal conserve every unit");
    let bytes = norito::to_bytes(&proof).unwrap();
    let decoded: FeeEvidenceWindowProofV1 = norito::decode_from_bytes(&bytes).unwrap();
    assert_eq!(decoded, proof);
    decoded.verify(&anchor).unwrap();
    // A separately pinned opening can begin after gross conversion but before
    // automatic accrual, and observes the same remaining allocation only once.
    let mut verifier =
        iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier::from_trusted_checkpoint(
            &anchor.opening_checkpoint,
            &anchor.network_id,
            anchor.opening_checkpoint.chain_id(),
        )
        .unwrap();
    verifier.verify(&proof.blocks[1].finality).unwrap();
    let later_anchor = FeeEvidenceTrustAnchorV1 {
        opening_checkpoint: verifier
            .export_checkpoint(&proof.blocks[1].finality)
            .unwrap(),
        ..anchor.clone()
    };
    FeeEvidenceWindowProofV1 {
        version: 1,
        blocks: proof.blocks[1..].to_vec(),
    }
    .verify(&later_anchor)
    .unwrap();
}

#[test]
fn certified_claim_then_refill_preserves_full_width_reserve() {
    let prefix = prefix();
    let binding = binding(&prefix.network_id());
    let mut records = vectors(&binding);
    records.truncate(2);
    for record in &mut records[0] {
        if let FeeEvidencePayloadV1::RewardCustody(custody) = &mut record.payload {
            custody.state.reserved_xor = u128::MAX;
            custody.state.next_allocation = 1;
            custody.reward_pool_xor_minor = u128::MAX;
        }
    }
    for record in &mut records[1] {
        match &mut record.payload {
            FeeEvidencePayloadV1::RewardCustody(custody) => {
                custody.state.reserved_xor = u128::MAX;
                custody.state.next_allocation = 2;
                custody.state.next_claim = 1;
                custody.reward_pool_xor_minor = u128::MAX;
            }
            FeeEvidencePayloadV1::RewardAllocation(allocation) => {
                allocation.sequence = 1;
                allocation.xor_minor = u128::MAX;
                allocation.gross_shares = BTreeMap::from([(account(1), u128::MAX)]);
                record.key = validation_fee_reward_state_key(&binding, "Allocation/1").unwrap();
            }
            _ => (),
        }
    }
    // The trusted opening owns the previously earned balance. Its claim runs
    // before the scheduled replacement funding in the same authenticated block.
    records[1].push(record(
        17,
        validation_fee_reward_state_key(&binding, "Claim/0").unwrap(),
        FeeEvidencePayloadV1::RewardClaim(ValidationFeeRewardClaim {
            beneficiary_id: account(1),
            beneficiary_revision: 0,
            sequence: 0,
            account_id: account(1),
            xor_minor: u128::MAX,
            claimed_at_height: 17,
            claimed_at_ms: NOW + 1,
            lifecycle_seal: binding.lifecycle_seal().unwrap(),
        }),
    ));
    records[1].push(alias(&binding, 17, 1, 1));
    let mut owner = revision(&binding, 17, 1, 1, None, 0);
    if let FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision) = &mut owner.payload {
        revision.authorized_at_height = 16;
    }
    records[1].push(owner);
    let (proof, anchor) = prove(prefix.clone(), records.clone());
    proof
        .verify(&anchor)
        .expect("claim then refill never exceeds the live u128 reserve bound");
    for record in &mut records[1] {
        if let FeeEvidencePayloadV1::RewardCustody(custody) = &mut record.payload {
            custody.state.reserved_xor -= 1;
            custody.reward_pool_xor_minor -= 1;
        }
    }
    let (invalid, anchor) = prove(prefix, records);
    assert!(
        invalid
            .verify(&anchor)
            .unwrap_err()
            .contains("complete-window conservation")
    );
}

#[test]
fn certified_automatic_rewards_reject_reassigned_missing_or_replayed_sources() {
    let prefix = prefix();
    let binding = binding(&prefix.network_id());
    let original = vectors(&binding);
    let reject = |records, expected: &str| {
        let (proof, anchor) = prove(prefix.clone(), records);
        let error = proof.verify(&anchor).unwrap_err();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error:?}"
        );
    };
    let mut changed = original.clone();
    entitlement(&mut changed[2]).shares.insert(account(1), 21);
    entitlement(&mut changed[2]).shares.insert(account(2), 29);
    reject(changed, "differs from funded historical exposure");
    let mut missing = original.clone();
    missing[2].retain(|record| !matches!(record.payload, FeeEvidencePayloadV1::RewardExposure(_)));
    reject(missing, "no historical exposure source");
    let mut missing = original.clone();
    missing[2].retain(|record| {
        !matches!(
            record.payload,
            FeeEvidencePayloadV1::RewardAllocationSource(_)
        )
    });
    reject(missing, "no funded allocation source");
    let mut wrong_owner = original.clone();
    entitlement(&mut wrong_owner[2])
        .beneficiaries
        .insert(account(2), account(3));
    reject(wrong_owner, "differs from authenticated alias source");
    let mut changed_source = original.clone();
    for record in &mut changed_source[2] {
        if let FeeEvidencePayloadV1::RewardAllocationSource(source) = &mut record.payload {
            source.converted_at_ms -= 1;
        }
    }
    reject(
        changed_source,
        "immutable fee record is replayed or changed",
    );
    let mut overspent = original.clone();
    for record in &mut overspent[3] {
        if let FeeEvidencePayloadV1::RewardClaim(claim) = &mut record.payload {
            if claim.beneficiary_id == account(2) {
                claim.xor_minor = 31;
            } else if claim.beneficiary_id == account(3) {
                claim.xor_minor = 49;
            }
        }
    }
    reject(overspent, "claim exceeds automatic entitlement");
    let mut double_funded = original.clone();
    for record in &mut double_funded[2] {
        if let FeeEvidencePayloadV1::RewardCustody(custody) = &mut record.payload {
            custody.state.reserved_xor = 200;
            custody.reward_pool_xor_minor = 200;
        }
    }
    reject(double_funded, "complete-window conservation");
    let mut gap = original.clone();
    for record in &mut gap[2] {
        match &mut record.payload {
            FeeEvidencePayloadV1::RewardExposure(page) => {
                page.page_index = 1;
                record.key = validation_fee_exposure_page_key(
                    &binding,
                    page.earning_period_start_ms,
                    &page.validator,
                    1,
                )
                .unwrap();
            }
            FeeEvidencePayloadV1::RewardEntitlement(entitlement) => {
                entitlement.page_index = 1;
                record.key =
                    validation_fee_entitlement_key(&binding, 0, &entitlement.validator, 1).unwrap();
            }
            _ => (),
        }
    }
    reject(gap, "replay or exposure page gap");
    let mut replay = original.clone();
    let mut repeated = original[2].clone();
    for record in &mut repeated {
        record.recorded_at_height = 20;
        match &mut record.payload {
            FeeEvidencePayloadV1::RewardEntitlement(entitlement) => {
                entitlement.recorded_at_height = 20;
            }
            FeeEvidencePayloadV1::RewardCustody(custody) => {
                custody.state.reserved_xor = 0;
                custody.state.next_claim = 3;
                custody.reward_pool_xor_minor = 0;
            }
            _ => (),
        }
    }
    replay.push(repeated);
    reject(replay, "immutable fee record is replayed or changed");
    let mut recovery = original.clone();
    for record in &mut recovery[3] {
        if let FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision) = &mut record.payload {
            if revision.revision == 1 {
                revision.previous_account_id = Some(account(3));
            }
        }
    }
    reject(recovery, "changes the original owner lineage");
}
