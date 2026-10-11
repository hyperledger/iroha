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
    retained.proof.decode_checked().unwrap();
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
