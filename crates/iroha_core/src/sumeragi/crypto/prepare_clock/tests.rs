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
