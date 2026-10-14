//! Public automatic validator and nominator reward allocation contracts.

use iroha_data_model::{account::AccountId, validation_fee_rewards::*};
use iroha_primitives::numeric::Quantity;
use std::collections::BTreeMap;

// The oracle never constructs amount * weight. Binary long division keeps each
// remainder below the denominator, including when both operands span u128.
fn reference_fraction(amount: u128, weight: u128, denominator: u128) -> (u128, u128) {
    assert!(denominator > 0 && weight <= denominator);
    let add_mod = |left: u128, right: u128| {
        if left >= denominator - right {
            (left - (denominator - right), 1_u128)
        } else {
            (left + right, 0_u128)
        }
    };
    let (mut quotient, mut remainder) = (0_u128, 0_u128);
    for bit in (0..128).rev() {
        let (doubled, carry) = add_mod(remainder, remainder);
        let (next, extra) = if (amount >> bit) & 1 == 0 {
            (doubled, 0)
        } else {
            add_mod(doubled, weight)
        };
        quotient = quotient.checked_mul(2).unwrap() + carry + extra;
        remainder = next;
    }
    (quotient, remainder)
}

// Pairwise remainder ranks express the specified tie rule without the production
// sorting routine, wide products, decimal normalization, or allocation helper.
fn reference_allocation(
    amount: u128,
    weights: &BTreeMap<AccountId, u128>,
) -> BTreeMap<AccountId, u128> {
    let total = weights
        .values()
        .try_fold(0_u128, |sum, weight| sum.checked_add(*weight))
        .unwrap();
    let fractions: BTreeMap<_, _> = weights
        .iter()
        .filter(|(_, weight)| **weight > 0)
        .map(|(account, weight)| (account.clone(), reference_fraction(amount, *weight, total)))
        .collect();
    let floors: u128 = fractions.values().map(|(floor, _)| floor).sum();
    let remaining = amount - floors;
    fractions
        .iter()
        .map(|(account, (floor, remainder))| {
            let rank = fractions
                .iter()
                .filter(|(other, (_, other_remainder))| {
                    other_remainder > remainder
                        || (other_remainder == remainder && *other < account)
                })
                .count();
            (
                account.clone(),
                floor + u128::from((rank as u128) < remaining),
            )
        })
        .collect()
}

fn next_sample(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn add_shares(target: &mut BTreeMap<AccountId, u128>, source: BTreeMap<AccountId, u128>) {
    for (recipient, amount) in source {
        let balance = target.entry(recipient).or_default();
        *balance = balance.checked_add(amount).unwrap();
    }
}

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

#[test]
fn exhaustive_small_allocations_match_independent_minimum_error_oracle() {
    let mut identities = [account(11), account(12), account(13)];
    identities.sort();
    for weights in (0_u64..4)
        .flat_map(|a| (0..4).flat_map(move |b| (0..4).map(move |c| [a, b, c])))
        .filter(|weights| weights.iter().sum::<u64>() > 0)
    {
        let total = weights.iter().sum::<u64>();
        // Reverse insertion makes the canonical AccountId order, rather than
        // caller insertion order or the fixture seed, decide exact ties.
        let service: BTreeMap<_, _> = identities.iter().cloned().zip(weights).rev().collect();
        let stakes = service
            .iter()
            .filter(|(_, weight)| **weight != 0)
            .map(|(identity, weight)| (identity.clone(), Quantity::from(*weight)))
            .collect::<BTreeMap<_, _>>();
        let source = page(&identities[0], 0, vec![cohort(1, stakes)]);
        for amount in 0_u128..18 {
            // Exhaust all integer compositions of the funded amount. Minimizing
            // squared distance to the exact ideal quotas independently derives
            // largest remainder; the lexicographically greatest tied vector
            // gives the earliest canonical account its minor unit first.
            let mut best: Option<(i128, [u128; 3])> = None;
            for first in 0..=amount {
                for second in 0..=amount - first {
                    let candidate = [first, second, amount - first - second];
                    if candidate
                        .iter()
                        .zip(weights)
                        .any(|(share, weight)| weight == 0 && *share != 0)
                    {
                        continue;
                    }
                    let error = candidate
                        .iter()
                        .zip(weights)
                        .map(|(share, weight)| {
                            let deviation = i128::try_from(*share).unwrap() * i128::from(total)
                                - i128::try_from(amount).unwrap() * i128::from(weight);
                            deviation * deviation
                        })
                        .sum();
                    if best.is_none_or(|(old_error, old)| {
                        error < old_error || (error == old_error && candidate > old)
                    }) {
                        best = Some((error, candidate));
                    }
                }
            }
            let expected: BTreeMap<_, _> = identities
                .iter()
                .cloned()
                .zip(best.unwrap().1)
                .zip(weights)
                .filter_map(|((identity, share), weight)| (weight > 0).then_some((identity, share)))
                .collect();
            assert_eq!(
                allocate(amount, &service).unwrap(),
                expected,
                "{weights:?}/{amount}"
            );
            assert_eq!(allocate_page(amount, 1, 0, &source).unwrap(), expected);
            assert_eq!(expected.values().sum::<u128>(), amount);
            for (identity, weight) in service.iter().filter(|(_, weight)| **weight > 0) {
                let numerator = amount * u128::from(*weight);
                let lower = numerator / u128::from(total);
                let upper = lower + u128::from(numerator % u128::from(total) != 0);
                assert!((lower..=upper).contains(&expected[identity]));
            }
            assert_eq!(
                reference_allocation(
                    amount,
                    &service
                        .iter()
                        .map(|(id, weight)| (id.clone(), u128::from(*weight)))
                        .collect(),
                ),
                expected,
                "cross-check the independent wide oracle on every exhaustive small case",
            );
        }
    }
}

#[test]
fn seeded_full_width_stakes_and_service_match_native_integer_oracle() {
    use iroha_primitives::{bigint::BigInt, numeric::Numeric};
    let identities: Vec<_> = (100..109).map(account).collect();
    // Multiplying 2^499 by any twelve-bit positive weight stays in the signed
    // 512-bit Quantity domain, while intermediate reward products exceed u128.
    let mut bytes = [0_u8; 64];
    bytes[62] = 8;
    let factor = BigInt::from_twos_bytes(&bytes).unwrap();
    let mut seed = 0xb7e1_5162_8aed_2a6b_u64;
    for case in 0..64 {
        let count = 2 + usize::try_from(next_sample(&mut seed) % 8).unwrap();
        let weights: BTreeMap<_, _> = identities[..count]
            .iter()
            .enumerate()
            .map(|(index, identity)| {
                let weight = if index == 0 {
                    4_095_u128
                } else {
                    u128::from(1 + next_sample(&mut seed) % 4_095)
                };
                (identity.clone(), weight)
            })
            .collect();
        let stakes: BTreeMap<_, _> = weights
            .iter()
            .map(|(identity, weight)| {
                let mantissa = factor.checked_mul(&BigInt::from(*weight)).unwrap();
                let quantity =
                    Quantity::try_from_numeric(Numeric::new(mantissa, case % 29)).unwrap();
                assert!(quantity.mantissa().try_to_u128().is_none());
                (identity.clone(), quantity)
            })
            .collect();
        let source = page(&identities[0], 0, vec![cohort(u64::MAX, stakes)]);
        let random =
            (u128::from(next_sample(&mut seed)) << 64) | u128::from(next_sample(&mut seed));
        for amount in [0, 1, random, u128::MAX - u128::from(case), u128::MAX] {
            let actual = allocate_page(amount, u64::MAX, 0, &source).unwrap();
            assert_eq!(
                actual,
                reference_allocation(amount, &weights),
                "seeded case {case}"
            );
            assert_eq!(actual.values().sum::<u128>(), amount);
        }
        // Service totals may exceed u64 even though each authenticated count is
        // u64. The native-u128 oracle accommodates the complete validator sum.
        let service: BTreeMap<_, _> = identities[..count]
            .iter()
            .map(|identity| (identity.clone(), next_sample(&mut seed) | (1_u64 << 63)))
            .collect();
        let oracle_weights = service
            .iter()
            .map(|(id, weight)| (id.clone(), u128::from(*weight)))
            .collect();
        assert_eq!(
            allocate(random, &service).unwrap(),
            reference_allocation(random, &oracle_weights)
        );
        assert_eq!(
            allocate(u128::MAX, &service).unwrap(),
            reference_allocation(u128::MAX, &oracle_weights)
        );
    }

    // The same full-width mantissa at opposite scale boundaries represents an
    // exact 10^28:1 ratio, exercising normalization beyond the Quantity domain.
    let mut maximum = [0xff; 64];
    maximum[63] = 0x7f;
    let maximum = BigInt::from_twos_bytes(&maximum).unwrap();
    let source = page(
        &identities[0],
        0,
        vec![cohort(
            1,
            [
                (
                    identities[0].clone(),
                    Quantity::try_from_numeric(Numeric::new(maximum.clone(), 0)).unwrap(),
                ),
                (
                    identities[1].clone(),
                    Quantity::try_from_numeric(Numeric::new(maximum, 28)).unwrap(),
                ),
            ],
        )],
    );
    let weights = BTreeMap::from([
        (identities[0].clone(), 10_u128.pow(28)),
        (identities[1].clone(), 1),
    ]);
    for amount in [1, 10_u128.pow(28), u128::MAX - 1, u128::MAX] {
        assert_eq!(
            allocate_page(amount, 1, 0, &source).unwrap(),
            reference_allocation(amount, &weights)
        );
    }
}

#[test]
fn seeded_every_cohort_boundary_partition_preserves_independent_entitlements() {
    use iroha_primitives::{bigint::BigInt, numeric::Numeric};
    let identities: Vec<_> = (200..206).map(account).collect();
    let mut seed = 0x243f_6a88_85a3_08d3_u64;
    for case in 0..24 {
        let count = 2 + usize::try_from(next_sample(&mut seed) % 4).unwrap();
        let mut cohorts = Vec::new();
        let mut oracle_weights = Vec::new();
        let mut starts = vec![0_u64];
        for index in 0..count {
            let mut stakes = BTreeMap::new();
            let mut weights = BTreeMap::new();
            for (recipient, identity) in identities.iter().enumerate() {
                if recipient > 0 && next_sample(&mut seed).is_multiple_of(3) {
                    continue;
                }
                // The first recipient changes monotonically, guaranteeing
                // distinct adjacent maps without repairing generated cases.
                let (mantissa, scale) = if recipient == 0 {
                    (10_000 + u64::try_from(index).unwrap(), 0)
                } else {
                    (
                        1 + next_sample(&mut seed) % 999,
                        u32::try_from(next_sample(&mut seed) % 5).unwrap(),
                    )
                };
                stakes.insert(
                    identity.clone(),
                    Quantity::try_from_numeric(Numeric::new(BigInt::from(mantissa), scale))
                        .unwrap(),
                );
                weights.insert(
                    identity.clone(),
                    u128::from(mantissa) * 10_u128.pow(4 - scale),
                );
            }
            let service = if case % 2 == 0 && index + 1 == count {
                u64::MAX - starts[index]
            } else {
                1 + next_sample(&mut seed) % 11
            };
            starts.push(starts[index].checked_add(service).unwrap());
            cohorts.push(cohort(service, stakes));
            oracle_weights.push(weights);
        }
        let total = *starts.last().unwrap();
        let random =
            (u128::from(next_sample(&mut seed)) << 64) | u128::from(next_sample(&mut seed));
        for gross in [0, 1, random, u128::MAX] {
            let mut expected = BTreeMap::new();
            for index in 0..count {
                let end =
                    reference_fraction(gross, u128::from(starts[index + 1]), u128::from(total)).0;
                let start =
                    reference_fraction(gross, u128::from(starts[index]), u128::from(total)).0;
                add_shares(
                    &mut expected,
                    reference_allocation(end - start, &oracle_weights[index]),
                );
            }
            assert_eq!(
                allocate_page(gross, total, 0, &page(&identities[0], 0, cohorts.clone())).unwrap(),
                expected
            );
            assert_eq!(expected.values().sum::<u128>(), gross);
            // Page boundaries may move only BETWEEN complete cohorts. Splitting
            // a coalesced cohort would repeat Hamilton rounding and is not an
            // invariant of this protocol; no such equivalence is asserted.
            for cuts in 0..1_usize << (count - 1) {
                let mut ranges = Vec::new();
                let mut start = 0;
                for end in 1..=count {
                    if end == count || cuts & (1 << (end - 1)) != 0 {
                        ranges.push((start, end));
                        start = end;
                    }
                }
                let mut actual = BTreeMap::new();
                for (page_index, (start, end)) in ranges.into_iter().enumerate().rev() {
                    add_shares(
                        &mut actual,
                        allocate_page(
                            gross,
                            total,
                            starts[start],
                            &page(
                                &identities[0],
                                page_index as u64,
                                cohorts[start..end].to_vec(),
                            ),
                        )
                        .unwrap(),
                    );
                }
                assert_eq!(actual, expected, "case {case}, cuts {cuts}, gross {gross}");
            }
        }
    }
}

#[test]
fn service_coordinates_and_union_cardinality_reject_before_allocation() {
    let validator = account(300);
    let first = cohort(u64::MAX, [(validator.clone(), Quantity::one())]);
    let source = page(&validator, 0, vec![first.clone()]);
    assert_eq!(
        allocate_page(u128::MAX, u64::MAX, 0, &source).unwrap()[&validator],
        u128::MAX
    );
    for (total, start) in [(0, 0), (1, 1), (u64::MAX, u64::MAX), (u64::MAX, 1)] {
        assert!(
            allocate_page(u128::MAX, total, start, &source).is_err(),
            "total={total}, start={start}"
        );
    }
    let overflowing = page(
        &validator,
        0,
        vec![
            first,
            cohort(1, [(validator.clone(), Quantity::from(2_u32))]),
        ],
    );
    assert_eq!(
        validate_exposure_page(&overflowing).unwrap_err(),
        "reward exposure service count overflow"
    );
    assert!(allocate_page(u128::MAX, u64::MAX, 0, &overflowing).is_err());
    let recipients: Vec<_> = (0..=MAX_REWARD_RECIPIENTS)
        .map(|index| account(30_000 + u32::try_from(index).unwrap()))
        .collect();
    let union = page(
        &validator,
        0,
        vec![
            cohort(
                1,
                recipients[..128]
                    .iter()
                    .cloned()
                    .map(|id| (id, Quantity::one())),
            ),
            cohort(
                1,
                recipients[128..]
                    .iter()
                    .cloned()
                    .map(|id| (id, Quantity::one())),
            ),
        ],
    );
    assert_eq!(
        validate_exposure_page(&union).unwrap_err(),
        "reward exposure page beneficiary bound exceeded"
    );
    assert!(allocate_page(1, 2, 0, &union).is_err());
    for amount in [0, 1, u128::MAX] {
        assert!(allocate(amount, &BTreeMap::from([(validator.clone(), 0)])).is_err());
    }
}

#[test]
fn canonical_page_bytes_and_validator_count_enforce_exact_admission_boundaries() {
    use iroha_primitives::{bigint::BigInt, numeric::Numeric};
    let identities: Vec<_> = (400..404).map(account).collect();
    let mut bytes = [0xff; 64];
    bytes[63] = 0x7f;
    let maximum = BigInt::from_twos_bytes(&bytes).unwrap();
    let mut source = page(&identities[0], 0, Vec::new());
    loop {
        let index = u32::try_from(source.exposure.len()).unwrap();
        source.exposure.push(cohort(
            1,
            identities.iter().enumerate().map(|(recipient, identity)| {
                let delta = if recipient == 0 { index } else { 0 };
                (
                    identity.clone(),
                    Quantity::try_from_numeric(Numeric::new(
                        maximum.checked_sub(&BigInt::from(delta)).unwrap(),
                        0,
                    ))
                    .unwrap(),
                )
            }),
        ));
        let encoded = norito::to_bytes(&source).unwrap();
        if encoded.len() > MAX_REWARD_EXPOSURE_BYTES {
            assert!(source.exposure.len() < MAX_REWARD_EXPOSURE_COHORTS);
            assert!(source.exposure.len() * identities.len() < MAX_REWARD_EXPOSURE_ENTRIES);
            assert_eq!(
                validate_exposure_page(&source).unwrap_err(),
                "reward exposure page encoded byte bound exceeded"
            );
            assert!(
                allocate_page(1, u64::try_from(source.exposure.len()).unwrap(), 0, &source)
                    .is_err()
            );
            source.exposure.pop();
            break;
        }
        validate_exposure_page(&source).unwrap();
    }
    let canonical = norito::to_bytes(&source).unwrap();
    let decoded: ValidationFeeExposurePage = norito::decode_from_bytes(&canonical).unwrap();
    assert_eq!(decoded, source);
    assert_eq!(norito::to_bytes(&decoded).unwrap(), canonical);
    assert_eq!(
        allocate_page(u128::MAX, source.exposure.len() as u64, 0, &decoded)
            .unwrap()
            .values()
            .sum::<u128>(),
        u128::MAX
    );

    let mut validators: BTreeMap<_, _> = (0..MAX_REWARD_VALIDATORS)
        .map(|index| (account(40_000 + u32::try_from(index).unwrap()), u64::MAX))
        .collect();
    let admitted = allocate(u128::MAX, &validators).unwrap();
    let count = MAX_REWARD_VALIDATORS as u128;
    let base = u128::MAX / count;
    let remainder = u128::MAX % count;
    assert_eq!(admitted.len(), MAX_REWARD_VALIDATORS);
    assert!(
        admitted
            .values()
            .enumerate()
            .all(|(rank, amount)| *amount == base + u128::from((rank as u128) < remainder))
    );
    validators.insert(
        account(40_000 + u32::try_from(MAX_REWARD_VALIDATORS).unwrap()),
        1,
    );
    assert_eq!(
        allocate(0, &validators).unwrap_err(),
        "monthly reward validator bound exceeded"
    );
}
