//! Public automatic validator and nominator reward allocation contracts.

use iroha_data_model::{account::AccountId, validation_fee_rewards::*};
use iroha_primitives::numeric::Quantity;
use std::collections::BTreeMap;

fn account(seed: u32) -> AccountId {
    AccountId::new(
        iroha_crypto::KeyPair::from_seed(
            seed.to_le_bytes().to_vec(),
            iroha_crypto::Algorithm::Ed25519,
        )
        .public_key()
        .clone(),
    )
}
fn cohort(
    service_blocks: u64,
    stakes: impl IntoIterator<Item = (AccountId, Quantity)>,
) -> ValidationFeeRewardExposure {
    ValidationFeeRewardExposure {
        service_blocks,
        stakes: stakes.into_iter().collect(),
    }
}
fn page(
    validator: &AccountId,
    page_index: u64,
    exposure: Vec<ValidationFeeRewardExposure>,
) -> ValidationFeeExposurePage {
    ValidationFeeExposurePage {
        earning_period_start_ms: 0,
        validator: validator.clone(),
        page_index,
        exposure,
    }
}

#[test]
fn automatic_reward_shares_preserve_twenty_thirty_fifty() {
    let validator = account(1);
    let a = account(2);
    let b = account(3);
    let source = page(
        &validator,
        0,
        vec![cohort(
            7,
            [
                (validator.clone(), Quantity::from(20u32)),
                (a.clone(), Quantity::from(30u32)),
                (b.clone(), Quantity::from(50u32)),
            ],
        )],
    );
    assert_eq!(
        allocate_page(100, 7, 0, &source).unwrap(),
        BTreeMap::from([(validator, 20), (a, 30), (b, 50)])
    );
}

#[test]
fn reward_page_allocation_and_entitlement_norito_json_roundtrip() {
    let validator = account(1);
    let source = page(
        &validator,
        0,
        vec![cohort(1, [(validator.clone(), Quantity::one())])],
    );
    let bytes = norito::to_bytes(&source).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeExposurePage>(&bytes).unwrap(),
        source
    );
    assert_eq!(
        norito::json::from_str::<ValidationFeeExposurePage>(
            &norito::json::to_json(&source).unwrap()
        )
        .unwrap(),
        source
    );
    let allocation = ValidationFeeRewardAllocation {
        sequence: 0,
        lifecycle_seal: [1; 32],
        earning_period_start_ms: 0,
        sbd_minor: 1,
        xor_minor: 100,
        converted_at_height: 2,
        converted_at_ms: 1,
        min_xor_minor: 100,
        reference_observations: vec![],
        service_blocks: BTreeMap::from([(validator.clone(), 1)]),
        gross_shares: BTreeMap::from([(validator.clone(), 100)]),
    };
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeRewardAllocation>(
            &norito::to_bytes(&allocation).unwrap()
        )
        .unwrap(),
        allocation
    );
    assert_eq!(
        norito::json::from_str::<ValidationFeeRewardAllocation>(
            &norito::json::to_json(&allocation).unwrap()
        )
        .unwrap(),
        allocation
    );
    let entitlement = ValidationFeeRewardEntitlement {
        allocation_sequence: 0,
        validator: validator.clone(),
        page_index: 0,
        service_start: 0,
        service_end: 1,
        recorded_at_height: 3,
        shares: BTreeMap::from([(validator.clone(), 100)]),
        beneficiaries: BTreeMap::from([(validator.clone(), validator.clone())]),
    };
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeRewardEntitlement>(
            &norito::to_bytes(&entitlement).unwrap()
        )
        .unwrap(),
        entitlement
    );
    assert_eq!(
        norito::json::from_str::<ValidationFeeRewardEntitlement>(
            &norito::json::to_json(&entitlement).unwrap()
        )
        .unwrap(),
        entitlement
    );
    let snapshot = ValidationFeeServiceSnapshot {
        earning_period_start_ms: 0,
        service_blocks: allocation.service_blocks,
    };
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeServiceSnapshot>(
            &norito::to_bytes(&snapshot).unwrap()
        )
        .unwrap(),
        snapshot
    );
    let state = ValidationFeeRewardsState {
        pending_sbd_total: 100,
        reserved_xor: 43,
        ..Default::default()
    };
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeRewardsState>(&norito::to_bytes(&state).unwrap())
            .unwrap(),
        state
    );
}

#[test]
fn archived_exposure_binds_predecessors_and_roundtrips_canonically() {
    let validator = account(1);
    let first = ValidationFeeExposureArchive {
        page: page(
            &validator,
            0,
            vec![cohort(3, [(validator.clone(), Quantity::one())])],
        ),
        previous: None,
    };
    validate_exposure_archive(&first).unwrap();
    let first_bytes = norito::to_bytes(&first).unwrap();
    let previous = ValidationFeeExposureArchiveRef {
        recorded_at_height: 2,
        page_index: 0,
        service_start: 0,
        archive_hash: iroha_crypto::Hash::new(&first_bytes),
    };
    let archive = ValidationFeeExposureArchive {
        page: page(
            &validator,
            1,
            vec![cohort(2, [(validator.clone(), Quantity::from(2_u32))])],
        ),
        previous: Some(previous),
    };
    validate_exposure_archive(&archive).unwrap();
    let bytes = norito::to_bytes(&archive).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeExposureArchive>(&bytes).unwrap(),
        archive
    );
    assert_eq!(
        norito::json::from_str::<ValidationFeeExposureArchive>(
            &norito::json::to_json(&archive).unwrap()
        )
        .unwrap(),
        archive
    );
    let head = ValidationFeeExposureHead {
        page_count: 2,
        service_total: 5,
        latest: ValidationFeeExposureArchiveRef {
            recorded_at_height: 3,
            page_index: 1,
            service_start: 3,
            archive_hash: iroha_crypto::Hash::new(&bytes),
        },
        tail_resident: true,
    };
    assert_eq!(
        norito::decode_from_bytes::<ValidationFeeExposureHead>(&norito::to_bytes(&head).unwrap())
            .unwrap(),
        head
    );
    assert_eq!(
        norito::json::from_str::<ValidationFeeExposureHead>(&norito::json::to_json(&head).unwrap())
            .unwrap(),
        head
    );
    let mut substituted = archive.clone();
    substituted.previous.as_mut().unwrap().archive_hash =
        iroha_crypto::Hash::new(b"different original predecessor");
    assert_ne!(
        iroha_crypto::Hash::new(norito::to_bytes(&substituted).unwrap()),
        head.latest.archive_hash
    );
    for bad_previous in [
        None,
        Some(ValidationFeeExposureArchiveRef {
            recorded_at_height: 0,
            ..archive.previous.unwrap()
        }),
        Some(ValidationFeeExposureArchiveRef {
            page_index: 1,
            ..archive.previous.unwrap()
        }),
    ] {
        substituted.previous = bad_previous;
        assert!(validate_exposure_archive(&substituted).is_err());
    }
    let key: iroha_model_base::state_path::StatePath =
        "sc/archive/ExposureArchive/00000000000000000000/validator/00000000000000000001"
            .parse()
            .unwrap();
    let witness = validation_fee_exposure_archive_witness_key(&key);
    assert_eq!(
        witness[0],
        iroha_data_model::execution_witness::REWARD_EXPOSURE_ARCHIVE_TAG_V1
    );
    assert_eq!(
        &witness[1..],
        iroha_crypto::Hash::new(key.as_ref().as_bytes()).as_ref()
    );
    assert_ne!(
        witness[0],
        iroha_data_model::execution_witness::FEE_EVIDENCE_RECORD_TAG_V1
    );
}

#[test]
fn maximum_single_cohort_fits_archive_page_without_stake_narrowing() {
    use iroha_primitives::{bigint::BigInt, numeric::Numeric};
    let mut maximum_mantissa = [0xff; 64];
    maximum_mantissa[63] = 0x7f;
    let quantity = Quantity::try_from_numeric(Numeric::new(
        BigInt::from_twos_bytes(&maximum_mantissa).unwrap(),
        28,
    ))
    .unwrap();
    assert_eq!(quantity.mantissa().to_twos_bytes().len(), 64);
    let validator = account(10_000);
    let stakes: BTreeMap<_, _> = (0..MAX_REWARD_RECIPIENTS)
        .map(|index| {
            (
                account(u32::try_from(index).expect("fixture recipient index fits u32")),
                quantity.clone(),
            )
        })
        .collect();
    let source = page(&validator, u64::MAX, vec![cohort(u64::MAX, stakes.clone())]);
    validate_exposure_page(&source).unwrap();
    let allocated = allocate_page(u128::MAX, u64::MAX, 0, &source).unwrap();
    assert_eq!(allocated.len(), MAX_REWARD_RECIPIENTS);
    assert_eq!(allocated.values().copied().sum::<u128>(), u128::MAX);
    let base = u128::MAX / MAX_REWARD_RECIPIENTS as u128;
    let remainder = (u128::MAX % MAX_REWARD_RECIPIENTS as u128) as usize;
    assert!(
        allocated
            .values()
            .enumerate()
            .all(|(index, share)| *share == base + u128::from(index < remainder))
    );
    // Replace every measured identity payload by its largest admitted encoded
    // size and include conservative per-entry framing growth. This upper bound
    // covers variable-length controllers without inventing invalid accounts.
    let extra_identity_bytes: usize = stakes
        .keys()
        .chain(std::iter::once(&validator))
        .map(|identity| MAX_REWARD_IDENTITY_BYTES - norito::to_bytes(identity).unwrap().len() + 16)
        .sum();
    let worst_case = norito::to_bytes(&source).unwrap().len() + extra_identity_bytes;
    assert!(
        worst_case <= MAX_REWARD_EXPOSURE_BYTES,
        "full-width cohort requires at most {worst_case} bytes"
    );
    let archive = ValidationFeeExposureArchive {
        page: source,
        previous: Some(ValidationFeeExposureArchiveRef {
            recorded_at_height: u64::MAX - 1,
            page_index: u64::MAX - 1,
            service_start: u64::MAX,
            archive_hash: iroha_crypto::Hash::new(b"archive predecessor"),
        }),
    };
    validate_exposure_archive(&archive).unwrap();
    assert!(
        norito::to_bytes(&archive).unwrap().len() + extra_identity_bytes
            <= MAX_REWARD_EXPOSURE_ARCHIVE_BYTES
    );
    assert_eq!(MAX_REWARD_RECIPIENTS, 256);
    assert_eq!(MAX_REWARD_EXPOSURE_BYTES, 128 * 1024);
}

#[test]
fn changed_stake_and_multiple_validators_preserve_historical_cohorts() {
    let first = account(1);
    let second = account(2);
    let nominator = account(3);
    let late = account(4);
    let gross = allocate(
        80,
        &BTreeMap::from([(first.clone(), 2), (second.clone(), 6)]),
    )
    .unwrap();
    let first_page = page(
        &first,
        0,
        vec![
            cohort(1, [(nominator.clone(), Quantity::one())]),
            cohort(1, [(late.clone(), Quantity::one())]),
        ],
    );
    let second_page = page(
        &second,
        0,
        vec![cohort(
            6,
            [
                (second.clone(), Quantity::one()),
                (nominator.clone(), Quantity::from(2u32)),
            ],
        )],
    );
    let mut credited = allocate_page(gross[&first], 2, 0, &first_page).unwrap();
    for (account, amount) in allocate_page(gross[&second], 6, 0, &second_page).unwrap() {
        *credited.entry(account).or_default() += amount;
    }
    assert_eq!(
        credited,
        BTreeMap::from([(nominator, 50), (late, 10), (second, 20)])
    );
}

#[test]
fn contiguous_pages_conserve_prefix_rounding_and_cannot_reassign_previous_service() {
    let validator = account(1);
    let a = account(2);
    let b = account(3);
    let c = account(4);
    let cohorts = vec![
        cohort(1, [(a.clone(), Quantity::one())]),
        cohort(1, [(b.clone(), Quantity::one())]),
        cohort(2, [(c.clone(), Quantity::one())]),
    ];
    let complete = allocate_page(3, 4, 0, &page(&validator, 0, cohorts.clone())).unwrap();
    let mut split = allocate_page(3, 4, 0, &page(&validator, 0, cohorts[..1].to_vec())).unwrap();
    split.extend(allocate_page(3, 4, 1, &page(&validator, 1, cohorts[1..].to_vec())).unwrap());
    assert_eq!(split, complete);
    assert_eq!(split, BTreeMap::from([(a, 0), (b, 1), (c, 2)]));
    assert!(allocate_page(3, 4, 3, &page(&validator, 1, cohorts.clone())).is_err());
    assert!(allocate_page(3, 0, 0, &page(&validator, 0, cohorts)).is_err());
}

#[test]
fn reverse_page_traversal_preserves_overlapping_beneficiaries_and_rounding() {
    let validator = account(1);
    let a = account(2);
    let b = account(3);
    let cohorts = vec![
        cohort(
            1,
            [
                (validator.clone(), Quantity::one()),
                (a.clone(), Quantity::one()),
            ],
        ),
        cohort(
            2,
            [
                (a.clone(), Quantity::one()),
                (b.clone(), Quantity::from(2u32)),
            ],
        ),
        cohort(
            4,
            [
                (validator.clone(), Quantity::from(3u32)),
                (b, Quantity::one()),
            ],
        ),
    ];
    let complete = page(&validator, 0, cohorts.clone());
    for gross in [0, 1, 7, 101, u128::MAX] {
        let expected = allocate_page(gross, 7, 0, &complete).unwrap();
        let mut reverse = BTreeMap::<AccountId, u128>::new();
        for (index, start) in [(2, 3), (1, 1), (0, 0)] {
            let source = page(&validator, index as u64, vec![cohorts[index].clone()]);
            for (account, amount) in allocate_page(gross, 7, start, &source).unwrap() {
                let balance = reverse.entry(account).or_default();
                *balance = balance.checked_add(amount).unwrap();
            }
        }
        assert_eq!(reverse, expected);
        assert_eq!(reverse.values().copied().sum::<u128>(), gross);
    }
}

#[test]
fn exact_wide_stakes_and_reward_products_do_not_narrow() {
    let validator = account(1);
    let nominator = account(2);
    let huge: Quantity = format!("1{}", "0".repeat(100)).parse().unwrap();
    let double: Quantity = format!("2{}", "0".repeat(100)).parse().unwrap();
    assert!(huge.mantissa().try_to_u128().is_none());
    let source = page(
        &validator,
        0,
        vec![cohort(
            u64::MAX,
            [(validator.clone(), huge), (nominator.clone(), double)],
        )],
    );
    assert_eq!(
        allocate_page(u128::MAX, u64::MAX, 0, &source).unwrap(),
        BTreeMap::from([
            (validator.clone(), u128::MAX / 3),
            (nominator.clone(), (u128::MAX / 3) * 2)
        ])
    );
    let gross = allocate(
        u128::MAX,
        &BTreeMap::from([(validator, u64::MAX), (nominator, u64::MAX)]),
    )
    .unwrap();
    assert_eq!(gross.values().copied().sum::<u128>(), u128::MAX);
}

#[test]
fn variable_length_account_identity_cannot_bypass_reward_work_bounds() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let members = (0..16)
        .map(|seed: u32| {
            MultisigMember::new(
                iroha_crypto::KeyPair::from_seed(
                    seed.to_le_bytes().to_vec(),
                    iroha_crypto::Algorithm::Ed25519,
                )
                .public_key()
                .clone(),
                1,
            )
            .unwrap()
        })
        .collect();
    let oversized = AccountId::new_multisig(MultisigPolicy::new(1, members).unwrap());
    assert!(norito::to_bytes(&oversized).unwrap().len() > MAX_REWARD_IDENTITY_BYTES);
    validate_reward_identity(&account(1)).unwrap();
    assert!(validate_reward_identity(&oversized).is_err());
    assert!(allocate(1, &BTreeMap::from([(oversized.clone(), 1)])).is_err());
    assert!(
        validate_exposure_page(&page(
            &account(1),
            0,
            vec![cohort(1, [(oversized, Quantity::one())])]
        ))
        .is_err()
    );
}

#[test]
fn mixed_scale_stakes_and_remainders_preserve_every_minor_unit() {
    let validator = account(1);
    let accounts = [account(2), account(3), account(4)];
    let source = page(
        &validator,
        0,
        vec![cohort(
            1,
            [
                (accounts[0].clone(), "0.1".parse().unwrap()),
                (accounts[1].clone(), "0.3".parse().unwrap()),
                (accounts[2].clone(), Quantity::one()),
            ],
        )],
    );
    assert_eq!(
        allocate_page(14, 1, 0, &source).unwrap(),
        BTreeMap::from([
            (accounts[0].clone(), 1),
            (accounts[1].clone(), 3),
            (accounts[2].clone(), 10)
        ])
    );
    let equal = BTreeMap::from([
        (accounts[0].clone(), 1u64),
        (accounts[1].clone(), 1u64),
        (accounts[2].clone(), 1u64),
    ]);
    assert_eq!(
        allocate(2, &equal)
            .unwrap()
            .values()
            .copied()
            .collect::<Vec<_>>(),
        vec![1, 1, 0]
    );
    assert!(allocate(1, &BTreeMap::new()).is_err());
}

#[test]
fn page_validation_bounds_work_without_bounding_monthly_stake_churn() {
    let validator = account(1);
    let valid = cohort(1, [(validator.clone(), Quantity::one())]);
    for exposure in [
        vec![],
        vec![cohort(0, [(validator.clone(), Quantity::one())])],
        vec![cohort(1, [(validator.clone(), Quantity::zero())])],
        vec![valid.clone(), valid],
    ] {
        assert!(validate_exposure_page(&page(&validator, 0, exposure)).is_err());
    }
    let excessive_cohorts = (1..=MAX_REWARD_EXPOSURE_COHORTS + 1)
        .map(|value| cohort(1, [(validator.clone(), Quantity::from(value as u64))]))
        .collect();
    assert!(validate_exposure_page(&page(&validator, 0, excessive_cohorts)).is_err());
    let excessive_recipients = (0..=MAX_REWARD_RECIPIENTS).map(|index| {
        (
            account(u32::try_from(index).expect("fixture recipient index fits u32")),
            Quantity::one(),
        )
    });
    assert!(
        validate_exposure_page(&page(&validator, 0, vec![cohort(1, excessive_recipients)]))
            .is_err()
    );
    let recipients = (0..MAX_REWARD_RECIPIENTS)
        .map(|index| account(u32::try_from(index).expect("fixture recipient index fits u32")))
        .collect::<Vec<_>>();
    let excessive_entries = (1..=MAX_REWARD_EXPOSURE_ENTRIES / MAX_REWARD_RECIPIENTS + 1)
        .map(|value| {
            cohort(
                1,
                recipients.iter().cloned().map(|account| {
                    (
                        account,
                        Quantity::from(
                            u32::try_from(value).expect("fixture exposure value fits u32"),
                        ),
                    )
                }),
            )
        })
        .collect();
    assert!(validate_exposure_page(&page(&validator, 0, excessive_entries)).is_err());
    let mut sum = 0u128;
    for index in 0..=MAX_REWARD_EXPOSURE_COHORTS {
        let source = page(
            &validator,
            index as u64,
            vec![cohort(
                1,
                [(
                    account(u32::try_from(index).expect("fixture recipient index fits u32")),
                    Quantity::one(),
                )],
            )],
        );
        validate_exposure_page(&source).unwrap();
        sum += allocate_page(
            100,
            (MAX_REWARD_EXPOSURE_COHORTS + 1) as u64,
            index as u64,
            &source,
        )
        .unwrap()
        .values()
        .sum::<u128>();
    }
    assert_eq!(
        sum, 100,
        "total monthly exposure may exceed every single-page bound"
    );
}
