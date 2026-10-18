//! Exact original-pool credential custody; these fixtures grant no source authority.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_allocation::{ChargedBufferFromChargeError, release::ReleaseRegistration};
use iroha_crypto::bls_normal_pop_prove;
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::types::EpochId;
use std::{
    future::Future as _,
    pin::Pin,
    task::{Context, Waker},
};

fn fixture() -> (Vec<ValidatorCommitteeMemberV1>, Vec<KeyPairSigner>) {
    let pairs: Vec<_> = (31..35)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    let members = pairs
        .iter()
        .map(|pair| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(pair.public_key().clone()),
            proof_of_possession: bls_normal_pop_prove(pair.private_key()).unwrap(),
        })
        .collect();
    let signers = pairs
        .iter()
        .map(|pair| KeyPairSigner::new(pair).unwrap())
        .collect();
    (members, signers)
}
fn message(view: u64) -> Vec<u8> {
    iroha_sumeragi::preimage::vote_preimage(
        iroha_sumeragi::message::VoteKind::Commit,
        &Hash32([0x42; 32]),
        &EpochId {
            epoch: 7,
            context: Hash32([0x51; 32]),
        },
        7,
        view,
        &Hash32([1; 32]),
        &Hash32([2; 32]),
    )
}
fn observed<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let mut result = None;
    let count = allocations_during(|| result = Some(operation()));
    (result.unwrap(), count)
}

#[test]
fn complete_committee_graph_prepaid_once_and_verification_allocates_nothing() {
    let (members, signers) = fixture();
    let (demand, planning_allocations) =
        observed(|| FundedBlsCommittee::allocation_demand(&members).unwrap());
    assert_eq!(planning_allocations, 0);
    let budget = AllocationBudget::new(demand);
    let (owned, allocations) = observed(|| FundedBlsCommittee::admit(&members, &budget).unwrap());
    assert_eq!(
        allocations,
        members.len() + 2,
        "only exact compact keys, credential array and original pairing backing"
    );
    assert_eq!(budget.reserved_bytes(), demand);
    assert!(owned.belongs_to(&budget));
    assert!(!owned.belongs_to(&AllocationBudget::new(demand)));
    let pointers: Vec<_> = owned
        .credentials
        .as_slice()
        .iter()
        .map(|key| key.verified.payload().as_ptr())
        .collect();
    let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
    let preimage = message(1);
    let shares: Vec<_> = signers
        .iter()
        .map(|signer| signer.sign(&preimage).unwrap())
        .collect();
    let aggregate = BlsCrypto::new().aggregate(&shares).unwrap();
    // Source deletion cannot retire the privately retained credential graph.
    drop(members);
    // Core enables parking_lot's thread-local deadlock tracker. Initialize that
    // instrumentation with an unrelated lock, leaving the first crypto verification cold.
    drop(parking_lot::Mutex::new(()).lock());
    let (verdict, verification_allocations) =
        observed(|| owned.verify_aggregate(&keys, &preimage, &aggregate));
    assert!(verdict);
    assert_eq!(verification_allocations, 0);
    assert_eq!(budget.reserved_bytes(), demand);
    for (credential, original) in owned.credentials.as_slice().iter().zip(pointers) {
        assert_eq!(credential.verified.payload().as_ptr(), original);
        assert!(credential.charge.belongs_to(&budget));
    }
    drop(owned);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn full_pool_refusal_keeps_original_release_and_fresh_retry_uses_same_source() {
    let (members, signers) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let waiter_bytes = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(demand + waiter_bytes);
    let mut reserved = budget.try_reserve_bytes(waiter_bytes).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reserved).unwrap();
    drop(reserved);
    let held = budget.try_reserve_bytes(demand).unwrap();
    let (failure, allocations) =
        observed(|| FundedBlsCommittee::admit(&members, &budget).err().unwrap());
    assert_eq!(
        allocations, 0,
        "capacity refusal precedes every candidate physical allocation"
    );
    let CommitteeAdmissionError::Admission(AllocationRefusal::Capacity {
        release,
        requested_bytes,
        ..
    }) = failure
    else {
        panic!("original capacity refusal required")
    };
    assert_eq!(requested_bytes, demand);
    let mut wait = release.wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let unrelated = AllocationBudget::new(demand);
    drop(unrelated.try_reserve_bytes(demand).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    assert_eq!(budget.reserved_bytes(), demand + waiter_bytes);
    drop(held);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    drop(wait);
    let retry = FundedBlsCommittee::admit(&members, &budget).unwrap();
    assert!(
        retry
            .lookup(signers[0].public_key())
            .unwrap()
            .proof_of_possession_matches(&members[0].proof_of_possession)
    );
    drop(retry);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn complete_original_reservation_is_split_without_reacquisition_or_foreign_pool() {
    let (members, _) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let budget = AllocationBudget::new(demand + 13);
    let other = AllocationBudget::new(demand + 13);
    let mut reservation = budget.try_reserve_bytes(demand + 13).unwrap();
    let (failure, allocations) = observed(|| {
        FundedBlsCommittee::from_reservation(&members, &other, &mut reservation)
            .err()
            .unwrap()
    });
    assert!(matches!(failure, CommitteeAdmissionError::ForeignPool));
    assert_eq!(allocations, 0);
    assert_eq!(reservation.remaining_bytes(), demand + 13);
    let owned = FundedBlsCommittee::from_reservation(&members, &budget, &mut reservation).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        demand + 13,
        "no second pool acquisition or double charge"
    );
    assert_eq!(reservation.remaining_bytes(), 13);
    assert!(owned.belongs_to(&budget));
    drop(owned);
    assert_eq!(budget.reserved_bytes(), 13);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut short = budget.try_reserve_bytes(demand - 1).unwrap();
    let (failure, allocations) = observed(|| {
        FundedBlsCommittee::from_reservation(&members, &budget, &mut short)
            .err()
            .unwrap()
    });
    assert!(matches!(failure, CommitteeAdmissionError::Reservation(_)));
    assert_eq!(allocations, 0);
    assert_eq!(short.remaining_bytes(), demand - 1);
}

#[test]
fn changed_late_pop_refuses_exact_member_and_preserves_original_credential() {
    let (mut members, signers) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let budget = AllocationBudget::new(demand * 2);
    let original = FundedBlsCommittee::admit(&members, &budget).unwrap();
    let key = signers[3].public_key();
    let original_pointer = original.lookup(key).unwrap().payload().as_ptr();
    let proof = members[3].proof_of_possession.clone();
    members[3].proof_of_possession[10] ^= 0x80;
    let failure = FundedBlsCommittee::admit(&members, &budget).err().unwrap();
    assert!(matches!(
        failure,
        CommitteeAdmissionError::Proof { index: 3, .. }
    ));
    assert_eq!(
        budget.reserved_bytes(),
        demand,
        "all rejected candidate backing retired"
    );
    let retained = original.lookup(key).unwrap();
    assert_eq!(retained.payload().as_ptr(), original_pointer);
    assert!(retained.proof_of_possession_matches(&proof));
    assert!(!retained.proof_of_possession_matches(&members[3].proof_of_possession));
    members[3].proof_of_possession = proof;
    let retry = FundedBlsCommittee::admit(&members, &budget).unwrap();
    drop(retry);
    assert_eq!(budget.reserved_bytes(), demand);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn partial_key_credential_and_complete_unwinds_refund_only_retired_candidate() {
    let (members, signers) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let budget = AllocationBudget::new(demand * 2);
    let original = FundedBlsCommittee::admit(&members, &budget).unwrap();
    let pointer = original
        .lookup(signers[0].public_key())
        .unwrap()
        .payload()
        .as_ptr();
    for stage in [
        Checkpoint::Key(2),
        Checkpoint::Credential(2),
        Checkpoint::Complete,
    ] {
        UNWIND_AT.with(|selected| selected.set(Some(stage)));
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _candidate = FundedBlsCommittee::admit(&members, &budget).unwrap();
        }));
        assert!(failed.is_err());
        assert!(
            UNWIND_AT.with(|selected| selected.get().is_none()),
            "actual partial allocation stage reached"
        );
        assert_eq!(
            budget.reserved_bytes(),
            demand,
            "partial construction cannot leak original credit"
        );
        assert_eq!(
            original
                .lookup(signers[0].public_key())
                .unwrap()
                .payload()
                .as_ptr(),
            pointer
        );
    }
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn physical_key_refusal_refunds_candidate_and_retains_typed_cause() {
    let (members, _) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let budget = AllocationBudget::new(demand);
    let layout = members[0]
        .validator
        .public_key()
        .retained_allocation_layout();
    let (result, observed) =
        refuse_one_layout_during(layout, || FundedBlsCommittee::admit(&members, &budget));
    assert!(observed);
    assert!(
        matches!(result, Err(CommitteeAdmissionError::KeyAllocation(PublicKeyAllocationError::Allocation(ChargedBufferFromChargeError::Allocator { layout: actual }))) if actual == layout)
    );
    assert_eq!(budget.reserved_bytes(), 0);
    drop(FundedBlsCommittee::admit(&members, &budget).unwrap());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn shared_node_and_funded_kernels_preserve_grouped_and_invalid_verdicts() {
    let (members, signers) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let budget = AllocationBudget::new(demand);
    let funded = FundedBlsCommittee::admit(&members, &budget).unwrap();
    let node = BlsCrypto::new();
    node.admit_committee(
        members
            .iter()
            .map(|m| (m.validator.public_key(), m.proof_of_possession.as_slice())),
    )
    .unwrap();
    let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
    let a = message(1);
    let b = message(2);
    let shares: Vec<_> = signers
        .iter()
        .map(|signer| signer.sign(&a).unwrap())
        .collect();
    let aggregate = node.aggregate(&shares).unwrap();
    let pair = KeyPair::from_seed(vec![93; 32], Algorithm::BlsNormal);
    let unadmitted = KeyPairSigner::new(&pair).unwrap();
    for (selected, preimage, expected) in [
        (keys.as_slice(), a.as_slice(), true),
        (keys.as_slice(), b.as_slice(), false),
        (&keys[..3], a.as_slice(), false),
        (&[][..], a.as_slice(), false),
        (&[keys[0], keys[0]][..], a.as_slice(), false),
        (&[unadmitted.public_key()][..], a.as_slice(), false),
        (keys.as_slice(), &[][..], false),
    ] {
        assert_eq!(
            node.verify_aggregate(selected, preimage, &aggregate),
            expected
        );
        let (verdict, allocations) =
            observed(|| funded.verify_aggregate(selected, preimage, &aggregate));
        assert_eq!(verdict, expected);
        assert_eq!(allocations, 0);
    }
    let grouped = vec![
        (keys[..2].to_vec(), a.clone()),
        (keys[2..].to_vec(), b.clone()),
    ];
    let grouped_shares: Vec<_> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| s.sign(if i < 2 { &a } else { &b }).unwrap())
        .collect();
    let combined = node.aggregate(&grouped_shares).unwrap();
    assert!(node.verify_aggregate_multi(&grouped, &combined));
    let (verdict, allocations) = observed(|| funded.verify_aggregate_multi(&grouped, &combined));
    assert!(verdict);
    assert_eq!(allocations, 0);
    let invalid = vec![(keys[..2].to_vec(), a.clone()), (keys[2..].to_vec(), a)];
    assert!(!node.verify_aggregate_multi(&invalid, &combined));
    let (verdict, allocations) = observed(|| funded.verify_aggregate_multi(&invalid, &combined));
    assert!(!verdict);
    assert_eq!(allocations, 0);
    assert_eq!(budget.reserved_bytes(), demand);
}

#[test]
fn shared_aggregation_refuses_invalid_shares_without_allocating_or_consuming_inputs() {
    let (members, signers) = fixture();
    let demand = FundedBlsCommittee::allocation_demand(&members).unwrap();
    let budget = AllocationBudget::new(demand);
    let funded = FundedBlsCommittee::admit(&members, &budget).unwrap();
    let node = BlsCrypto::new();
    let preimage = message(1);
    let shares: Vec<_> = signers
        .iter()
        .map(|signer| signer.sign(&preimage).unwrap())
        .collect();
    let original = shares.clone();
    let expected =
        AggregateSignature(consensus::aggregate(shares.iter().map(|sig| &sig.0)).unwrap());
    let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
    let mut identity = [0; iroha_sumeragi::types::SIGNATURE_LEN];
    identity[0] = 0xc0;
    let zero = [Signature([0; iroha_sumeragi::types::SIGNATURE_LEN])];
    let identity = [Signature(identity)];
    let malformed = [Signature([0xff; iroha_sumeragi::types::SIGNATURE_LEN])];
    let invalid_tail = [shares[0], malformed[0]];

    // The original credentials stay funded even when new pool admissions are disabled.
    budget.set_limit_bytes(0);
    let readers: [&dyn Crypto; 2] = [&node, &funded];
    for crypto in readers {
        for invalid in [
            &[][..],
            &zero[..],
            &identity[..],
            &malformed[..],
            &invalid_tail[..],
        ] {
            let (result, allocations) = observed(|| crypto.aggregate(invalid));
            assert_eq!(result, Err(AggregationError::Refused));
            assert_eq!(allocations, 0);
            assert_eq!(budget.reserved_bytes(), demand);
        }
        let (result, allocations) = observed(|| crypto.aggregate(&shares));
        assert_eq!(result, Ok(expected));
        assert_eq!(allocations, 0);
        assert_eq!(shares, original);
        assert!(funded.verify_aggregate(&keys, &preimage, &result.unwrap()));
        assert_eq!(budget.reserved_bytes(), demand);
    }
    drop(funded);
    assert_eq!(budget.reserved_bytes(), 0);
}
