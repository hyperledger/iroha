//! Fixed observation custody and the absence of a raw Prepare signing path.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use std::time::Duration;

#[test]
fn sccp_prepare_clock_original_pool_funds_shared_lifetime_and_refuses_empty_pool() {
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    assert!(matches!(
        PrepareClock::new(&AllocationBudget::new(0), time.clone()),
        Err(PrepareClockError::Admission(_))
    ));
    let budget = AllocationBudget::new(1 << 20);
    let clock = PrepareClock::new(&budget, time).unwrap();
    let exact = ChargedShared::<SharedClock>::allocation_layout().size();
    assert_eq!(budget.reserved_bytes(), exact);
    let copy = clock.clone();
    drop(clock);
    assert_eq!(budget.reserved_bytes(), exact);
    drop(copy);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn sccp_prepare_clock_raw_prepare_and_missing_observations_refuse() {
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    let clock = PrepareClock::new(&AllocationBudget::new(1 << 20), time).unwrap();
    let instance = Hash32([1; 32]);
    let epoch = EpochId {
        epoch: 2,
        context: Hash32([3; 32]),
    };
    let block_hash = Hash32([4; 32]);
    let result = Hash32([5; 32]);
    assert_eq!(
        clock.authorize(instance, epoch, 7, block_hash, result, false),
        Err(SigningError::Refused)
    );
    let key = KeyPair::from_seed(vec![8; 32], Algorithm::BlsNormal);
    let signer = NativePrepareSigner::new(KeyPairSigner::new(&key).unwrap(), clock);
    let prepare = iroha_sumeragi::preimage::vote_preimage(
        iroha_sumeragi::message::VoteKind::Prepare,
        &instance,
        &epoch,
        7,
        0,
        &block_hash,
        &result,
    );
    assert_eq!(signer.sign(&prepare), Err(SigningError::Refused));
    let commit = iroha_sumeragi::preimage::vote_preimage(
        iroha_sumeragi::message::VoteKind::Commit,
        &instance,
        &epoch,
        7,
        0,
        &block_hash,
        &result,
    );
    assert_eq!(
        signer.public_key(),
        &super::super::core_key(key.public_key()).unwrap()
    );
    assert_eq!(
        signer.sign(&commit).unwrap(),
        KeyPairSigner::new(&key).unwrap().sign(&commit).unwrap()
    );
}

#[test]
fn sccp_prepare_clock_fixed_slots_reuse_admission_and_retire_other_heights() {
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    let budget = AllocationBudget::new(1 << 20);
    let guard = PrepareClock::new(&budget, time).unwrap();
    let occupied = budget.reserved_bytes();
    let mut header = BlockHeader {
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 2,
            context: Hash32([3; 32]),
        },
        height: 7,
        origin_view: 0,
        parent_hash: Hash32([4; 32]),
        parent_result: Hash32([5; 32]),
        payload_hash: Hash32([6; 32]),
        availability_digest: Hash32([7; 32]),
        payload_len: 1,
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: iroha_sumeragi::types::ControlWitness::default(),
    };
    let result = Hash32([9; 32]);
    for number in 1..=OBSERVATIONS + 1 {
        let hash = Hash32([u8::try_from(number).unwrap(); 32]);
        guard.record(&header, hash, result, None);
        assert_eq!(
            guard.authorize_uncertified_for_test(&header, hash, result),
            Ok(())
        );
        assert_eq!(budget.reserved_bytes(), occupied);
    }
    assert_eq!(
        guard.authorize_uncertified_for_test(&header, Hash32([1; 32]), result),
        Err(SigningError::Refused)
    );
    let last = Hash32([u8::try_from(OBSERVATIONS + 1).unwrap(); 32]);
    header.height += 1;
    guard.record(&header, last, result, None);
    assert_eq!(
        guard.authorize_uncertified_for_test(&header, last, result),
        Ok(())
    );
    header.height -= 1;
    assert_eq!(
        guard.authorize_uncertified_for_test(&header, last, result),
        Err(SigningError::Refused)
    );
    assert_eq!(budget.reserved_bytes(), occupied);
}
