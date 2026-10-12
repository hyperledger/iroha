//! Exact real compact-key/wire/committee charges and original refusal cleanup.
use super::*;
use crate::{
    state::World,
    sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};

#[test]
fn original_proof_destination_charges_each_actual_compact_key_before_clone_and_refunds() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let certified = reader.certified(2).unwrap();
    let members = &certified.commitment().schedule.current.committee;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let wire = norito::canonical_frame_len(certified.block().as_ref()).unwrap() + 1;
    let demand = Layout::array::<AllocationCharge>(2 + 2 * members.len())
        .unwrap()
        .size()
        + wire
        + Layout::array::<FinalityValidator>(members.len())
            .unwrap()
            .size()
        + members
            .iter()
            .map(|member| {
                member.proof_of_possession.len()
                    + member
                        .validator
                        .public_key()
                        .retained_allocation_layout()
                        .size()
            })
            .sum::<usize>();
    let pool = AllocationBudget::new(demand);
    let deadline = Instant::now() + std::time::Duration::from_secs(900);
    let retained = OwnedProof::new(certified.block(), members, &pool, deadline).unwrap();
    assert_eq!(
        pool.reserved_bytes(),
        demand,
        "original destination charges actual compact-key backing, not only Vec shells"
    );
    assert_eq!(retained._charges.as_slice().len(), 2 + 2 * members.len());
    assert!(
        retained
            ._charges
            .as_slice()
            .iter()
            .all(|charge| charge.belongs_to(&pool))
    );
    for (original, actual) in members.iter().zip(&retained.proof.committee) {
        assert_eq!(&actual.public_key, original.validator.public_key());
        assert_eq!(actual.proof_of_possession, original.proof_of_possession);
        assert_eq!(
            actual.public_key.retained_allocation_layout(),
            original.validator.public_key().retained_allocation_layout()
        );
    }
    assert_eq!(
        retained.proof.block_wire,
        certified.block().encode_wire().unwrap()
    );
    retained
        .proof
        .decode_checked(chain.root_scope().into())
        .unwrap();
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);

    let short = AllocationBudget::new(demand - 1);
    let key_demand = members
        .last()
        .unwrap()
        .validator
        .public_key()
        .retained_allocation_layout()
        .size();
    for _ in 0..2 {
        let error = OwnedProof::new(certified.block(), members, &short, deadline)
            .err()
            .unwrap();
        let ProofDestinationError::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            ..
        }) = error
        else {
            panic!("last actual compact key must preserve original finite pool Capacity");
        };
        assert_eq!(requested_bytes, key_demand);
        assert_eq!(reserved_bytes, demand - key_demand);
        assert_eq!(limit_bytes, demand - 1);
        assert_eq!(
            short.reserved_bytes(),
            0,
            "all actual values retire before original charges refund on refusal"
        );
    }
}

#[test]
fn retained_proof_preparation_binds_original_source_and_refunds_partial_key_unwind() {
    use iroha_allocation::release::ReleaseRegistration;
    use std::{
        future::Future,
        task::{Context, Poll},
    };
    let _retirement_pin = crossbeam_epoch::pin();
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let certified = reader.certified(2).unwrap();
    let members = &certified.commitment().schedule.current.committee;
    let foreign_members = members.to_vec();
    let genesis = chain.committed(1);
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let wire = norito::canonical_frame_len(certified.block().as_ref()).unwrap() + 1;
    let demand = Layout::array::<AllocationCharge>(2 + 2 * members.len())
        .unwrap()
        .size()
        + wire
        + Layout::array::<FinalityValidator>(members.len())
            .unwrap()
            .size()
        + members
            .iter()
            .map(|m| {
                m.proof_of_possession.len()
                    + m.validator.public_key().retained_allocation_layout().size()
            })
            .sum::<usize>();
    let key_bytes = members
        .last()
        .unwrap()
        .validator
        .public_key()
        .retained_allocation_layout()
        .size();
    let registration_bytes = ReleaseRegistration::allocation_layout().size();
    for mode in 0..3 {
        let pool = AllocationBudget::new(demand + registration_bytes);
        let mut prepaid = pool.try_reserve_bytes(registration_bytes).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let pressure = pool.try_reserve_bytes(1).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let mut attempt = ProofPreparation::default();
        let error = attempt
            .complete(certified.block(), members, &pool, deadline)
            .err()
            .unwrap();
        let ProofDestinationError::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = error
        else {
            panic!(
                "last actual compact key refuses while earlier original payload remains retained"
            );
        };
        assert_eq!(requested_bytes, key_bytes);
        assert_eq!(reserved_bytes, demand - key_bytes + registration_bytes + 1);
        assert_eq!(limit_bytes, demand + registration_bytes);
        assert_eq!(pool.reserved_bytes(), reserved_bytes);
        let mut wait = Box::pin(release.wait_for_release(&mut registration));
        let mut poll = Context::from_waker(std::task::Waker::noop());
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
        let original = attempt.construction.as_ref().unwrap();
        assert_eq!(original.owned.proof.committee.len(), members.len() - 1);
        assert_eq!(
            original.pop.as_ref().unwrap().as_slice(),
            members.last().unwrap().proof_of_possession
        );
        let wire_pointer = original.owned.proof.block_wire.as_ptr();
        let key_pointer = original.owned.proof.committee[0]
            .public_key
            .to_bytes()
            .1
            .as_ptr();
        assert_ne!(
            key_pointer,
            members[0].validator.public_key().to_bytes().1.as_ptr()
        );
        let foreign = AllocationBudget::new(pool.limit_bytes());
        assert!(matches!(
            attempt.complete(certified.block(), members, &foreign, deadline),
            Err(ProofDestinationError::Source)
        ));
        assert!(matches!(
            attempt.complete(certified.block(), &foreign_members, &pool, deadline),
            Err(ProofDestinationError::Source)
        ));
        assert!(matches!(
            attempt.complete(genesis.block(), members, &pool, deadline),
            Err(ProofDestinationError::Source)
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), reserved_bytes);
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
        if mode == 0 {
            drop(pressure);
            assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
            drop(wait);
            let complete = attempt
                .complete(certified.block(), members, &pool, deadline)
                .unwrap();
            assert_eq!(complete.proof.block_wire.as_ptr(), wire_pointer);
            assert_eq!(
                complete.proof.committee[0].public_key.to_bytes().1.as_ptr(),
                key_pointer
            );
            assert_eq!(complete.proof.committee.len(), members.len());
            assert_eq!(
                complete.proof.block_wire,
                certified.block().encode_wire().unwrap()
            );
            complete
                .proof
                .decode_checked(chain.root_scope().into())
                .unwrap();
            assert_eq!(pool.reserved_bytes(), demand + registration_bytes);
            drop(attempt);
        } else {
            if mode == 1 {
                drop(attempt);
            } else {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _original = attempt;
                    panic!("controlled unwind after real nested key and pending PoP allocation");
                }));
                assert!(result.is_err());
            }
            assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
            drop(wait);
            assert_eq!(pool.reserved_bytes(), registration_bytes + 1);
            drop(pressure);
        }
        assert_eq!(pool.reserved_bytes(), registration_bytes);
        drop(registration);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
