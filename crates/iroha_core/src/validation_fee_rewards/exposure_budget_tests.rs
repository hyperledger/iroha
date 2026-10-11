//! Worst admitted automatic reward corpus, including its independently copied sources.

use super::*;
use iroha_data_model::{
    fee_evidence::{
        FEE_EVIDENCE_WITNESS_KEY_V1, FeeEvidenceBlockProofV1, FeeEvidencePayloadV1,
        FeeEvidenceSnapshotV1, FeeEvidenceWitnessProofV1, MAX_FEE_EVIDENCE_BLOCK_BYTES_V1,
        MAX_FEE_EVIDENCE_RECORDS_V1,
    },
    validation_fee::MAX_VALIDATION_FEE_REGISTRY_BYTES,
    validation_fee_rewards::{MAX_REWARD_ALLOCATION_BYTES, MAX_REWARD_IDENTITY_BYTES},
};

#[test]
fn maximum_mandatory_page_corpus_fits_reserved_evidence_budget() {
    let member_count = (1..16)
        .filter(|count| ensure_reward_identity(&super::tests::multisig(0, *count)).is_ok())
        .last()
        .unwrap();
    let validators = (0..MAX_REWARD_VALIDATORS)
        .map(|index| (super::tests::multisig(index as u32, member_count), 1))
        .collect::<BTreeMap<_, _>>();
    let validator = validators.first_key_value().unwrap().0.clone();
    let recipients = (MAX_REWARD_VALIDATORS..MAX_REWARD_VALIDATORS + MAX_REWARD_RECIPIENTS)
        .map(|index| {
            (
                super::tests::multisig(index as u32, member_count),
                Quantity::one(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let identity_bytes = norito::to_bytes(recipients.first_key_value().unwrap().0)
        .unwrap()
        .len();
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
        let binding = active_bindings(stx).unwrap().remove(0);
        let period = earning_month(stx.block_unix_timestamp_ms() - 60 * DAY_MS).unwrap();
        record_service(stx, &binding, period, &validator, recipients).unwrap();
        write(
            stx,
            service_key(&binding, period).unwrap(),
            &ValidationFeeServiceSnapshot {
                earning_period_start_ms: period,
                service_blocks: validators,
            },
        )
        .unwrap();
        super::super::tests::fund_test_conversion(
            stx,
            &binding,
            period,
            (MAX_REWARD_VALIDATORS * MAX_REWARD_RECIPIENTS) as u128,
        );
        settlement::accrue_next_page(stx, &binding).unwrap();
        let mut records = pending_fee_evidence_records(stx).unwrap();
        // The real mandatory page reads an earlier block's funded allocation;
        // conversion's service snapshot is therefore absent from that corpus.
        records.retain(|record| !matches!(record.payload, FeeEvidencePayloadV1::RewardService(_)));
        let mut allocation_bytes = 0;
        let mut page_bytes = 0;
        let mut registry_bytes = 0;
        for record in &mut records {
            match &record.payload {
                FeeEvidencePayloadV1::RewardAllocation(allocation) => {
                    allocation_bytes = norito::to_bytes(allocation).unwrap().len();
                    record.payload =
                        FeeEvidencePayloadV1::RewardAllocationSource(allocation.clone());
                }
                FeeEvidencePayloadV1::RewardExposure(page) => {
                    page_bytes = norito::to_bytes(page).unwrap().len();
                }
                FeeEvidencePayloadV1::PolicyRegistry(registry) => {
                    registry_bytes = norito::to_bytes(registry).unwrap().len();
                }
                _ => (),
            }
        }
        assert_eq!(records.len(), 2 * MAX_REWARD_RECIPIENTS + 5);
        assert!(records.len() <= MAX_FEE_EVIDENCE_RECORDS_V1 as usize);
        let snapshot = FeeEvidenceSnapshotV1::from_records(stx.block_height(), &records).unwrap();
        let proof = FeeEvidenceBlockProofV1 {
            snapshot_witness: FeeEvidenceWitnessProofV1 {
                key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
                value: norito::to_bytes(&snapshot).unwrap(),
                siblings: vec![Hash::new([]); 256],
            },
            records,
        };
        let measured = norito::to_bytes(&proof).unwrap().len();
        // Exact serialization exercises every record and its 256-sibling witness.
        // Top up all variable source payloads to enforced admission limits. A
        // binding is a subobject of the capped complete registry. Outside those
        // payloads, each new beneficiary occurs twice in its alias, twice in its
        // initial owner revision and three times in the entitlement maps; the
        // entitlement also names its validator once. The final 16 KiB covers
        // nested length-prefix growth and longer scalar/key representations.
        // Include another 31 initial alias/revision pairs as a conservative
        // allowance for the largest supported authenticated service committee,
        // even though current service capture only reads existing aliases.
        let upper_bound = measured
            + (MAX_REWARD_ALLOCATION_BYTES - allocation_bytes)
            + (MAX_REWARD_EXPOSURE_BYTES - page_bytes)
            + (MAX_VALIDATION_FEE_REGISTRY_BYTES - registry_bytes)
            + (MAX_VALIDATION_FEE_REGISTRY_BYTES - norito::to_bytes(&binding).unwrap().len())
            + (7 * MAX_REWARD_RECIPIENTS + 1) * (MAX_REWARD_IDENTITY_BYTES - identity_bytes)
            + 31 * (4 * MAX_REWARD_IDENTITY_BYTES + 2 * 512)
            + 16 * 1024;
        eprintln!("mandatory reward evidence measured={measured} conservative_max={upper_bound}");
        assert!(upper_bound < MAX_FEE_EVIDENCE_BLOCK_BYTES_V1);
    });
}

#[test]
fn oversized_reference_is_refused_before_retention_or_conversion_mutations() {
    use iroha_data_model::{
        oracle::{FeedConfigVersion, ObservationBody, ObservationOutcome, ObservationValue},
        validation_fee_rewards::{
            MAX_REWARD_REFERENCE_BYTES, validate_reference_observation_bytes,
        },
    };
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
        let binding = active_bindings(stx).unwrap().remove(0);
        let body = ObservationBody {
            feed_id: binding.reference_feed_id.clone(),
            feed_config_version: FeedConfigVersion(binding.reference_feed_config_version),
            slot: 50,
            provider_id: binding.reference_provider_accounts[0].clone(),
            connector_id: "x".repeat(MAX_REWARD_REFERENCE_BYTES),
            connector_version: 1,
            request_hash: Hash::prehashed([3; 32]),
            outcome: ObservationOutcome::Value(ObservationValue::new(2, 0)),
            timestamp_ms: Some(stx.block_unix_timestamp_ms()),
        };
        // Native oracle admission authenticates the signature before this hook;
        // the isolated hook test exercises the additional retained-byte refusal.
        let key = iroha_crypto::KeyPair::from_seed(vec![42; 32], iroha_crypto::Algorithm::Ed25519);
        let record = ValidationFeeReferenceObservation {
            observation: Observation {
                signature: iroha_crypto::SignatureOf::new(key.private_key(), &body),
                body,
            },
            admitted_height: stx.block_height(),
            admitted_at_ms: stx.block_unix_timestamp_ms(),
        };
        assert!(validate_reference_observation_bytes(&record).is_err());
        let oracle_key = state_key(
            &binding,
            &format!(
                "Oracle/{}",
                hex::encode(
                    Hash::new(record.observation.body.provider_id.to_string().as_bytes()).as_ref()
                )
            ),
        )
        .unwrap();
        assert!(retain_authenticated_observation(stx, &record.observation).is_err());
        assert!(stx.world.smart_contract_state.get(&oracle_key).is_none());
        let period = earning_month(stx.block_unix_timestamp_ms() - 60 * DAY_MS).unwrap();
        let validator = super::super::tests::account(2);
        super::super::tests::record_test_service(stx, &binding, period, &validator, &[(2, 1)]);
        let state = ValidationFeeRewardsState {
            pending_sbd_total: 100,
            ..Default::default()
        };
        save_state(stx, &binding, &state).unwrap();
        write(stx, pending_key(&binding, period).unwrap(), &100u64).unwrap();
        // A malformed restored reference must not consume any funded state even
        // if it reaches conversion independently of ordinary oracle admission.
        write(stx, oracle_key, &record).unwrap();
        let offer = ConversionOffer {
            earning_period_start_ms: period,
            sbd_minor: 100,
            min_xor_minor: 100,
            sequence: 0,
        };
        assert!(reserve_conversion(stx, &binding, &offer, 100).is_err());
        assert_eq!(read_state(stx, &binding).unwrap(), state);
        assert_eq!(
            read::<u64>(stx, &pending_key(&binding, period).unwrap()).unwrap(),
            Some(100)
        );
        assert!(
            stx.world
                .smart_contract_state
                .get(&state_key(&binding, "AllocationCursor").unwrap())
                .is_none()
        );
        assert!(reconciliation::validate(&stx.world, &binding).is_err());
    });
}

#[test]
fn live_stake_backing_does_not_rescan_history_but_restore_requires_it() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
        let binding = active_bindings(stx).unwrap().remove(0);
        crate::state::validate_public_lane_stake_reserves_for_restore(&stx.world).unwrap();
        stx.world
            .smart_contract_state
            .insert(state_key(&binding, "Allocation/0").unwrap(), vec![0xff]);
        // Selection checks current indexed backing only; immutable history was
        // checked on restore and each new receipt is checked before admission.
        crate::state::validate_public_lane_stake_reserves(&stx.world).unwrap();
        assert!(crate::state::validate_public_lane_stake_reserves_for_restore(&stx.world).is_err());
    });
}

#[test]
fn maximum_committee_tail_archive_fits_independent_source_budget() {
    use iroha_data_model::{
        block::consensus::ExecWitness, execution_witness::REWARD_EXPOSURE_ARCHIVE_TAG_V1,
        validation_fee_rewards::MAX_REWARD_EXPOSURE_ARCHIVE_BYTES,
    };
    crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, _| {
        {
            let mut stx = block.transaction();
            let binding = active_bindings(&stx).unwrap().remove(0);
            let period = earning_month(stx.block_unix_timestamp_ms()).unwrap();
            let stakes = (0..MAX_REWARD_RECIPIENTS)
                .map(|index| {
                    (
                        super::tests::multisig(index as u32 + 100, 1),
                        Quantity::one(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            for index in 0..31 {
                record_service(
                    &mut stx,
                    &binding,
                    period,
                    &super::tests::multisig(index, 1),
                    stakes.clone(),
                )
                .unwrap();
            }
            stx.apply();
        }
        let mut witness = ExecWitness::default();
        capture_archive(block, &mut witness).unwrap();
        assert_eq!(witness.writes.len(), 31);
        assert!(
            witness
                .writes
                .iter()
                .all(|row| row.key.first() == Some(&REWARD_EXPOSURE_ARCHIVE_TAG_V1))
        );
        let bytes = norito::to_bytes(&witness).unwrap().len();
        let top_up = witness
            .writes
            .iter()
            .map(|row| MAX_REWARD_EXPOSURE_ARCHIVE_BYTES - row.value.len())
            .sum::<usize>();
        let upper_bound = bytes + top_up + 4 * 1024;
        assert!(
            upper_bound < 4 * 1024 * 1024,
            "encoded source wrappers and framing fit four MiB"
        );
        assert!(
            upper_bound + MAX_FEE_EVIDENCE_BLOCK_BYTES_V1
                < iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES.get()
        );
    });
}
