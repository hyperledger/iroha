//! Exact historical prefix work at maximum service fanout and retained index scale.

use super::*;
use iroha_data_model::nexus::PublicLaneStakeShare;
use mv::storage::Storage;
use std::{cell::Cell, time::Instant};

const LANES: usize = 1_024;
const VALIDATORS_PER_LANE: usize = 128;
const MAX_SERVICE_SIGNERS: usize = 31;

fn account(seed: u32) -> AccountId {
    let mut material = b"reward-exposure-scale/".to_vec();
    material.extend_from_slice(&seed.to_le_bytes());
    AccountId::new(
        iroha_crypto::KeyPair::from_seed(material, iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn share(key: &StakeKey, bonded: Quantity) -> PublicLaneStakeShare {
    PublicLaneStakeShare {
        lane_id: key.0,
        validator: key.1.clone(),
        staker: key.2.clone(),
        bonded,
        pending_unbonds: BTreeMap::new(),
        metadata: Default::default(),
    }
}

#[test]
fn maximum_service_capture_visits_only_exact_current_and_undo_prefixes() {
    let started = Instant::now();
    let validators: Vec<_> = (0..VALIDATORS_PER_LANE as u32).map(account).collect();
    let stakers: Vec<_> = (10_000..10_000 + MAX_REWARD_RECIPIENTS as u32)
        .map(account)
        .collect();
    let late: Vec<_> = (20_000..20_256).map(account).collect();
    let lane = LaneId::new(512);
    let selected = BTreeMap::from([(
        lane,
        validators[..MAX_SERVICE_SIGNERS].iter().cloned().collect(),
    )]);
    let quantity = Quantity::from(u128::from(u64::MAX) + 100);
    // This fixture materializes every retained (lane, validator) prefix, with
    // all 256 real AccountId positions in each of the 31 serviced prefixes.
    // Non-serviced prefixes have one row, not a pretend 33-million-row table.
    let rows = (0..LANES).flat_map(|lane_index| {
        let validators = &validators;
        let stakers = &stakers;
        let quantity = &quantity;
        (0..VALIDATORS_PER_LANE).flat_map(move |validator_index| {
            let count = if lane_index == 512 && validator_index < MAX_SERVICE_SIGNERS {
                MAX_REWARD_RECIPIENTS
            } else {
                1
            };
            (0..count).map(move |staker_index| {
                let key = (
                    LaneId::new(lane_index as u32),
                    validators[validator_index].clone(),
                    stakers[staker_index].clone(),
                );
                let row = share(&key, quantity.clone());
                (key, row)
            })
        })
    });
    let storage: Storage<_, _> = rows.collect();
    let mut block = storage.block();
    let total_rows =
        LANES * VALIDATORS_PER_LANE + MAX_SERVICE_SIGNERS * (MAX_REWARD_RECIPIENTS - 1);
    assert_eq!(block.len(), total_rows);
    let expected: HistoricalStake = validators[..MAX_SERVICE_SIGNERS]
        .iter()
        .map(|validator| {
            (
                (lane, validator.clone()),
                stakers
                    .iter()
                    .cloned()
                    .map(|staker| (staker, quantity.clone()))
                    .collect(),
            )
        })
        .collect();
    let setup_elapsed = started.elapsed();
    let mut visits = [0_usize; 3];
    let measured = Instant::now();
    assert_eq!(
        capture_stakes(&block, &selected, |v| visits[v as usize] += 1).unwrap(),
        expected
    );
    assert_eq!(visits, [31 * 256, 0, 31 * 256]);
    let pristine_elapsed = measured.elapsed();

    // Populate undo in every unrelated retained prefix. None may be walked by
    // capture. The selected prefixes also contain exits/recoveries, changed
    // bonded balances and 256 transient deposits that never existed at parent.
    for lane_index in 0..LANES {
        for (validator_index, validator) in validators.iter().enumerate() {
            if lane_index == 512 && validator_index < MAX_SERVICE_SIGNERS {
                continue;
            }
            block.remove((
                LaneId::new(lane_index as u32),
                validator.clone(),
                stakers[0].clone(),
            ));
        }
    }
    for validator in &validators[..MAX_SERVICE_SIGNERS] {
        for staker in &stakers[..16] {
            block.remove((lane, validator.clone(), staker.clone()));
        }
        let changed = (lane, validator.clone(), stakers[16].clone());
        block.insert(changed.clone(), share(&changed, Quantity::zero()));
        for staker in &late {
            let key = (lane, validator.clone(), staker.clone());
            block.insert(key.clone(), share(&key, Quantity::from(9_000_000u32)));
            block.remove(key);
        }
        for staker in &late[..16] {
            let key = (lane, validator.clone(), staker.clone());
            block.insert(key.clone(), share(&key, Quantity::one()));
        }
    }
    let all_undo = block.revert_map().len();
    let measured = Instant::now();
    visits.fill(0);
    assert_eq!(
        capture_stakes(&block, &selected, |v| visits[v as usize] += 1).unwrap(),
        expected
    );
    assert_eq!(visits, [31 * 256, 31 * (17 + 256), 31 * 256]);
    assert!(all_undo > 131_072);
    eprintln!(
        "reward exposure real_account_rows={total_rows} setup_ms={} pristine_capture_us={} mutated_capture_us={} current_rows={} selected_undo_rows={} all_undo_rows={all_undo} parent_rows={}",
        setup_elapsed.as_millis(),
        pristine_elapsed.as_micros(),
        measured.elapsed().as_micros(),
        visits[0],
        visits[1],
        visits[2]
    );
}

#[test]
fn prefix_capture_handles_identity_extremes_rollback_and_replacement() {
    let single = account(1);
    let multisig = super::tests::multisig(2, 2);
    let lane = LaneId::new(u32::MAX);
    let selected = BTreeMap::from([(lane, BTreeSet::from([multisig.clone()]))]);
    let keys = [
        (LaneId::new(0), multisig.clone(), single.clone()),
        (lane, single.clone(), multisig.clone()),
        (lane, multisig.clone(), single.clone()),
        (lane, multisig.clone(), multisig.clone()),
    ];
    let storage: Storage<_, _> = keys
        .iter()
        .map(|key| (key.clone(), share(key, Quantity::one())))
        .collect();
    let expected = BTreeMap::from([(
        (lane, multisig.clone()),
        BTreeMap::from([(single, Quantity::one()), (multisig, Quantity::one())]),
    )]);
    let mut block = storage.block();
    {
        let mut transaction = block.transaction();
        transaction.remove(keys[2].clone());
        // Drop the un-applied child; it must contribute no undo and no change.
    }
    assert_eq!(capture_stakes(&block, &selected, |_| {}).unwrap(), expected);
    assert!(block.revert_map().is_empty());
    block.remove(keys[2].clone());
    block.commit();
    let replaced = storage.block_and_revert();
    assert_eq!(
        capture_stakes(&replaced, &selected, |_| {}).unwrap(),
        expected
    );
    assert_eq!(
        replaced
            .range::<dyn ranges::AsStakePrefix>(ranges::StakeBounds::new(&lane, &keys[3].1))
            .count(),
        2
    );
    assert_eq!(
        replaced
            .revert_map()
            .range::<_, dyn ranges::AsStakePrefix>(ranges::StakeBounds::new(&lane, &keys[3].1))
            .count(),
        0
    );

    // The separate validator lookup shares the original tuple order and must
    // exclude every account in the adjacent lane, including multisig keys.
    let registry: Storage<_, _> = keys
        .iter()
        .map(|key| ((key.0, key.1.clone()), ()))
        .collect();
    let mut validators = registry.block();
    let selected_keys: Vec<_> = validators
        .range::<dyn ranges::AsValidatorPrefix>(ranges::ValidatorBounds::new(&lane))
        .map(|(key, _)| key.clone())
        .collect();
    assert_eq!(selected_keys.len(), 2);
    assert!(selected_keys.iter().all(|key| key.0 == lane));
    validators.remove(selected_keys[0].clone());
    assert_eq!(
        validators
            .revert_map()
            .range::<_, dyn ranges::AsValidatorPrefix>(ranges::ValidatorBounds::new(&lane))
            .count(),
        1
    );
}

#[test]
fn malformed_parent_identity_and_excess_recipient_count_are_rejected() {
    let validator = account(1);
    let lane = LaneId::new(0);
    let selected = BTreeMap::from([(lane, BTreeSet::from([validator.clone()]))]);
    let key = (lane, validator.clone(), validator.clone());
    let mut malformed = share(&key, Quantity::one());
    malformed.lane_id = LaneId::new(1);
    let storage: Storage<_, _> = [(key, malformed)].into_iter().collect();
    assert!(capture_stakes(&storage.block(), &selected, |_| {}).is_err());
    let storage: Storage<_, _> = (0..=MAX_REWARD_RECIPIENTS)
        .map(|index| {
            let key = (lane, validator.clone(), account(index as u32 + 100));
            (key.clone(), share(&key, Quantity::one()))
        })
        .collect();
    let mut visits = 0_usize;
    assert!(capture_stakes(&storage.block(), &selected, |_| visits += 1).is_err());
    assert_eq!(
        visits,
        MAX_REWARD_RECIPIENTS + 1,
        "oversized current prefixes stop at the first impossible recipient"
    );
}

thread_local! {
    static INDEX_COMPARISONS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexKey(u32);

impl Ord for IndexKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        INDEX_COMPARISONS.with(|count| count.set(count.get() + 1));
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for IndexKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
#[ignore = "materializes all 33,554,432 compact index rows; run explicitly for scale qualification"]
fn maximum_retained_universe_range_seek_has_bounded_work() {
    // This uses the exact MV/Concread tree and range implementation, but compact
    // index keys and unit values. It measures maximum index cardinality, not
    // the memory or serialization cost of 33m full production stake records.
    let total = LANES * VALIDATORS_PER_LANE * MAX_REWARD_RECIPIENTS;
    let build_started = Instant::now();
    let storage: Storage<_, _> = (0..total as u32).map(|key| (IndexKey(key), ())).collect();
    let block = storage.block();
    assert_eq!(block.len(), 33_554_432);
    let build_elapsed = build_started.elapsed();
    INDEX_COMPARISONS.with(|count| count.set(0));
    let measured = Instant::now();
    let mut visited = 0;
    // Include both end leaves and many distinct interior paths at full depth.
    for prefix in (0..31).map(|index| index * (LANES * VALIDATORS_PER_LANE - 1) / 30) {
        let start = prefix as u32 * 256;
        let mut expected = start;
        for (key, ()) in block.range(IndexKey(start)..IndexKey(start + 256)) {
            assert_eq!(key.0, expected);
            expected += 1;
            visited += 1;
        }
        assert_eq!(expected, start + 256);
    }
    let comparisons = INDEX_COMPARISONS.with(Cell::get);
    assert_eq!(visited, 31 * 256);
    // Generous deterministic work bound, independent of wall-clock timing.
    // A scan of 33m keys cannot meet it; no benchmark timing is a test oracle.
    assert!(
        comparisons < 31 * (2 * 128 + 256),
        "comparisons={comparisons}"
    );
    eprintln!(
        "reward exposure compact_index_rows={total} build_ms={} capture_us={} visited={visited} comparisons={comparisons}",
        build_elapsed.as_millis(),
        measured.elapsed().as_micros()
    );
}
