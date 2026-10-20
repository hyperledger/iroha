//! Exact graph geometry, source identity, allocator refusal and unwind controls.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_crypto::{Algorithm, KeyPair};

fn source() -> (PeerId, AccountId, Quantity) {
    let peer = KeyPair::from_seed(vec![41; 32], Algorithm::BlsNormal);
    let account = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519);
    (
        PeerId::new(peer.public_key().clone()),
        AccountId::new(account.public_key().clone()),
        "18446744073709551616.001".parse().unwrap(),
    )
}

fn fields<'a>(peer: &'a PeerId, validator: &'a AccountId) -> SlashFields<'a> {
    SlashFields {
        evidence_key: Hash::prehashed([11; 32]),
        signer: 1,
        peer_id: peer,
        lane_id: LaneId::SINGLE,
        validator,
        slash_id: Hash::prehashed([11; 32]),
    }
}

fn demand(validator: &AccountId) -> ActionDemand {
    let mut demand = ActionDemand::default();
    demand.slash(validator).unwrap();
    demand.marker().unwrap();
    demand
}

fn collect(
    peer: &PeerId,
    validator: &AccountId,
    amount: &Quantity,
    pool: &AllocationBudget,
) -> Result<FundedPenaltyActions, EvidencePreparationError> {
    let mut builder = ActionBuilder::new(demand(validator), pool)?;
    builder.slash(
        fields(peer, validator),
        ChargedQuantity::try_copy(amount, pool).map_err(EvidencePreparationError::from)?,
    )?;
    builder.marker(Hash::prehashed([11; 32]), 2)?;
    builder.finish()
}

#[test]
fn action_graph_retains_exact_layouts_pointers_and_original_pool_through_moves() {
    let (peer, validator, amount) = source();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let mut expected = demand(&validator).backing_bytes().unwrap()
        + peer.public_key().retained_allocation_layout().size()
        + amount.admission_clone_layout().unwrap().size();
    validator
        .for_each_admission_clone_layout(|layout| expected += layout.size())
        .unwrap();
    let graph = collect(&peer, &validator, &amount, &pool).unwrap();
    assert_eq!(
        pool.reserved_bytes(),
        expected,
        "HC911 funded actions must retain every original quantity allocation until graph destruction"
    );
    assert_eq!(graph.allocation_bytes(), expected);
    assert!(graph.belongs_to(&pool));
    assert!(!graph.belongs_to(&foreign));
    let vector = graph.as_slice().as_ptr();
    let NposPenaltyAction::ConsensusSlash(slash) = &graph.as_slice()[0] else {
        panic!("canonical slash first");
    };
    let key = slash
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    // Keeping the identical Quantity object inside the identical Vec backing,
    // while the move allocates nothing, proves no magnitude is reconstructed.
    // Native-digit addresses themselves remain private to the primitives owner.
    let quantity = std::ptr::from_ref(&slash.amount);
    let account_key = slash
        .validator
        .expect_single_signatory()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let mut moved = None;
    assert_eq!(allocations_during(|| moved = Some(graph)), 0);
    let moved = moved.unwrap();
    assert_eq!(moved.as_slice().as_ptr(), vector);
    let NposPenaltyAction::ConsensusSlash(slash) = &moved.as_slice()[0] else {
        panic!("canonical slash first");
    };
    assert_eq!(
        slash
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        key
    );
    assert_eq!(std::ptr::from_ref(&slash.amount), quantity);
    assert_eq!(
        slash
            .validator
            .expect_single_signatory()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        account_key
    );
    assert_eq!(&slash.amount, &amount);
    drop(moved);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn action_backing_rejects_foreign_reservation_before_allocation() {
    let (_, validator, _) = source();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let demand = demand(&validator);
    let original = pool
        .try_reserve_bytes(demand.backing_bytes().unwrap())
        .unwrap();
    let result = ActionBuilder::from_reservation(demand, &foreign, original);
    assert!(
        matches!(result, Err(EvidencePreparationError::Invariant)),
        "HC910 funded action backing must reject a foreign reservation before allocating"
    );
    drop(result);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn action_graph_refuses_every_physical_layout_without_capacity_wait() {
    use iroha_data_model::account::controller::{MultisigMember, MultisigPolicy};
    let (peer, validator, amount) = source();
    let pool = AllocationBudget::new(1 << 20);
    let first = KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519);
    let second = KeyPair::from_seed(vec![44; 32], Algorithm::Secp256k1);
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(first.public_key().clone(), 1).unwrap(),
                MultisigMember::new(second.public_key().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    for validator in [validator, multisig] {
        let demand = demand(&validator);
        let mut layouts = vec![
            Layout::array::<NposPenaltyAction>(demand.actions).unwrap(),
            Layout::array::<AllocationCharge>(demand.ledger_capacity().unwrap()).unwrap(),
            peer.public_key().retained_allocation_layout(),
            amount.admission_clone_layout().unwrap(),
        ];
        validator
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
        // These fixtures deliberately use distinct physical layouts, so each
        // first-match fault reaches one different actual nested allocation.
        for (index, layout) in layouts.iter().enumerate() {
            assert!(!layouts[..index].contains(layout));
        }
        let expected: usize = layouts.iter().map(Layout::size).sum();
        let graph = collect(&peer, &validator, &amount, &pool).unwrap();
        assert_eq!(pool.reserved_bytes(), expected);
        assert_eq!(graph.allocation_bytes(), expected);
        drop(graph);
        for layout in layouts {
            let (result, refused) =
                refuse_one_layout_during(layout, || collect(&peer, &validator, &amount, &pool));
            assert!(
                refused,
                "actual graph layout {layout:?} must reach the allocator"
            );
            let error = result.unwrap_err();
            let physical = match &error {
                EvidencePreparationError::Allocator { requested_bytes } => {
                    *requested_bytes == layout.size()
                }
                EvidencePreparationError::DecodeResource(original) => {
                    original.kind() == norito::core::DecodeLocalRefusalKind::Allocator
                        && original.allocation_bytes() == Some(layout.size() as u64)
                }
                _ => false,
            };
            assert!(
                physical,
                "exact physical layout must retain its typed cause: {error:?}"
            );
            assert!(
                error.release_wait().is_none(),
                "physical allocator refusal cannot wait for capacity"
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn action_graph_keeps_original_capacity_observation_and_cleans_partial_unwind() {
    let (peer, validator, amount) = source();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let blocker = pool.try_reserve_bytes(pool.limit_bytes()).unwrap();
    let expected = pool
        .try_reserve_bytes(demand(&validator).backing_bytes().unwrap())
        .unwrap_err();
    let error = collect(&peer, &validator, &amount, &pool).unwrap_err();
    assert!(matches!(&error, EvidencePreparationError::Admission(actual) if actual == &expected));
    let wait = error.release_wait().unwrap();
    let waiter_pool = AllocationBudget::new(1024);
    let mut waiter = iroha_allocation::release::ReleaseRegistration::from_reservation(
        &mut waiter_pool.try_reserve_bytes(1024).unwrap(),
    )
    .unwrap();
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let unrelated = foreign.try_reserve_bytes(1).unwrap();
    drop(unrelated);
    assert!(waiter.poll_wait(wait, &mut context).is_pending());
    drop(blocker);
    assert!(waiter.poll_wait(wait, &mut context).is_ready());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut builder = ActionBuilder::new(demand(&validator), &pool).unwrap();
        builder
            .slash(
                fields(&peer, &validator),
                ChargedQuantity::try_copy(&amount, &pool).unwrap(),
            )
            .unwrap();
        panic!("partial action producer unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    let mut empty = None;
    assert_eq!(
        allocations_during(|| empty = Some(FundedPenaltyActions::empty(&pool).unwrap())),
        0
    );
    let empty = empty.unwrap();
    assert!(empty.as_slice().is_empty());
    assert!(empty.belongs_to(&pool));
    assert!(!empty.belongs_to(&foreign));
    assert_eq!(empty.allocation_bytes(), 0);
}

#[test]
fn funded_slash_amount_matches_shared_arithmetic_and_deduplicates_without_new_graphs() {
    let (peer, validator, amount) = source();
    let pool = AllocationBudget::new(1 << 20);
    for bps in [0, 1, 3_333, 10_000, u16::MAX] {
        let actual = slash_amount(&amount, bps, &pool).unwrap();
        let expected = crate::smartcontracts::isi::staking::max_slash_amount(&amount, bps).unwrap();
        assert_eq!(actual.get(), &expected);
    }
    let mut builder = ActionBuilder::new(demand(&validator), &pool).unwrap();
    for _ in 0..2 {
        let original = ChargedQuantity::try_copy(&amount, &pool).unwrap();
        if builder.values.as_slice().len() == builder.values.capacity() {
            let mut outcome = None;
            assert_eq!(
                allocations_during(|| {
                    outcome = Some(builder.slash(fields(&peer, &validator), original));
                }),
                0,
                "an exact duplicate needs no allocation even when backing is full"
            );
            outcome.unwrap().unwrap();
        } else {
            builder.slash(fields(&peer, &validator), original).unwrap();
        }
        builder.marker(Hash::prehashed([11; 32]), 2).unwrap();
    }
    let foreign = AllocationBudget::new(1 << 20);
    assert!(matches!(
        builder.slash(
            fields(&peer, &validator),
            ChargedQuantity::try_copy(&amount, &foreign).unwrap(),
        ),
        Err(EvidencePreparationError::Invariant)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let graph = builder.finish().unwrap();
    assert_eq!(graph.as_slice().len(), 2);
    assert_eq!(pool.reserved_bytes(), graph.allocation_bytes());
    drop(graph);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn duplicate_suppression_reads_only_the_ordered_current_key_run() {
    let (peer, validator, amount) = source();
    let pool = AllocationBudget::new(1 << 20);
    let (earlier, later) = (Hash::prehashed([1; 32]), Hash::prehashed([11; 32]));
    assert!(earlier < later);
    let mut geometry = demand(&validator);
    // Spare slots: refusal must come from key order, never from full backing.
    geometry.marker().unwrap();
    geometry.marker().unwrap();
    let mut builder = ActionBuilder::new(geometry, &pool).unwrap();
    builder.marker(earlier, 2).unwrap();
    for _ in 0..2 {
        // The second pass is an exact duplicate inside the current key's run.
        builder
            .slash(
                fields(&peer, &validator),
                ChargedQuantity::try_copy(&amount, &pool).unwrap(),
            )
            .unwrap();
        builder.marker(later, 2).unwrap();
    }
    assert_eq!(builder.values.as_slice().len(), 3);
    let reserved = pool.reserved_bytes();
    assert!(
        matches!(
            builder.marker(earlier, 2),
            Err(EvidencePreparationError::Invariant)
        ),
        "HC916 an out-of-order evidence key must not escape duplicate suppression"
    );
    let mut stale = fields(&peer, &validator);
    stale.evidence_key = earlier;
    stale.slash_id = earlier;
    let quantity = ChargedQuantity::try_copy(&amount, &pool).unwrap();
    let mut outcome = None;
    assert_eq!(
        allocations_during(|| outcome = Some(builder.slash(stale, quantity))),
        0,
        "an out-of-order slash is refused before any nested allocation"
    );
    assert!(matches!(
        outcome.unwrap(),
        Err(EvidencePreparationError::Invariant)
    ));
    assert_eq!(builder.values.as_slice().len(), 3);
    assert_eq!(pool.reserved_bytes(), reserved);
    let graph = builder.finish().unwrap();
    let marker = |evidence_key| {
        NposPenaltyAction::MarkConsensusEvidenceApplied(NposMarkConsensusEvidenceAppliedAction {
            evidence_key,
            height: 2,
        })
    };
    let mut expected = vec![
        NposPenaltyAction::ConsensusSlash(NposConsensusSlashAction {
            evidence_key: later,
            signer: 1,
            peer_id: peer.clone(),
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            slash_id: later,
            amount: amount.clone(),
        }),
        marker(earlier),
        marker(later),
    ];
    expected.sort();
    assert_eq!(graph.as_slice(), expected.as_slice());
    assert_eq!(pool.reserved_bytes(), graph.allocation_bytes());
    drop(graph);
    assert_eq!(pool.reserved_bytes(), 0);
}
