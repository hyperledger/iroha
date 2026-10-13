//! Exact staged snapshot fields and persisted endorsement append-order controls.

use super::*;
use iroha_data_model::nexus::{DOMAIN_ENDORSEMENT_VERSION_V1, DomainEndorsementScope};

#[test]
fn staged_world_retains_every_committed_field_owned_by_its_snapshot() {
    let world = World::default();
    let committed: json::Value = json::from_str(&json::to_json(&world).unwrap()).unwrap();
    let block = world.block();
    let staged: json::Value = json::from_str(&json::to_json(&block).unwrap()).unwrap();
    let committed = committed.as_object().unwrap();
    let staged = staged.as_object().unwrap();
    assert!(committed.contains_key("external_event_buf"));
    assert!(!staged.contains_key("external_event_buf"));
    // This process-owned cell already has an exact State-level projection.
    // Every other committed World field must be carried by the original block.
    let expected = committed
        .keys()
        .filter(|key| key.as_str() != "external_event_buf")
        .collect::<BTreeSet<_>>();
    assert_eq!(staged.keys().collect::<BTreeSet<_>>(), expected);
    assert!(staged.contains_key("domain_endorsements_by_domain"));
}

fn endorsement(
    domain: &DomainId,
    marker: u8,
    height: u64,
) -> (HashOf<DomainEndorsement>, DomainEndorsementRecord) {
    let endorsement = DomainEndorsement {
        version: DOMAIN_ENDORSEMENT_VERSION_V1,
        domain_id: domain.clone(),
        committee_id: "staged-snapshot-order".to_owned(),
        statement_hash: Hash::new([marker]),
        issued_at_height: height,
        expires_at_height: height + 10,
        scope: DomainEndorsementScope::default(),
        signatures: Vec::new(),
        metadata: Metadata::default(),
    };
    (
        endorsement.body_hash(),
        DomainEndorsementRecord {
            endorsement,
            accepted_at_height: height,
        },
    )
}

#[test]
fn staged_state_snapshot_preserves_nonempty_current_and_predecessor_append_order() {
    let (state, _) = fixture();
    let domain = DomainId::try_new("staged-endorsement", "universal").unwrap();
    let mut earlier = [endorsement(&domain, 1, 0), endorsement(&domain, 2, 0)];
    earlier.sort_by_key(|(hash, _)| std::cmp::Reverse(*hash));
    let before = earlier.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
    assert!(before[0] > before[1], "retained order is not hash order");
    {
        // Component setup creates exact committed primary/index records. It
        // supplies no consensus endorsement or finalized carrier authority.
        let mut world = state.world.block();
        for (hash, record) in earlier {
            world.domain_endorsements.insert(hash, record);
        }
        world
            .domain_endorsements_by_domain
            .insert(domain.clone(), before.clone());
        world.commit();
    }
    let (third_hash, third) = endorsement(&domain, 3, 1);
    let mut after = before.clone();
    after.push(third_hash);
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1,
        0,
    ));
    block.world.domain_endorsements.insert(third_hash, third);
    block
        .world
        .domain_endorsements_by_domain
        .insert(domain.clone(), after.clone());
    assert_eq!(
        block
            .world
            .domain_endorsements_by_domain
            .revert_map()
            .get(&domain),
        Some(&Some(before.clone()))
    );
    // Finish these existing deterministic block-boundary owners before taking
    // the expected cut; the publication calls are idempotent afterwards.
    block.finalize_axt_asset_incarnations().unwrap();
    block.finalize_axt_policy_transition_ratchets().unwrap();
    let expected_bytes = crate::snapshot::canonical_staged_state_snapshot_bytes(&block);
    let expected_hash = crate::snapshot::canonical_staged_state_snapshot_hash(&block);
    assert_eq!(expected_hash, Hash::new(&expected_bytes));
    let expected_value: json::Value = json::from_slice(&expected_bytes).unwrap();
    let staged_index = json::from_str::<json::Value>(
        &json::to_json(&block.world.domain_endorsements_by_domain).unwrap(),
    )
    .unwrap();
    assert_eq!(
        expected_value
            .get("world")
            .unwrap()
            .get("domain_endorsements_by_domain"),
        Some(&staged_index)
    );
    block.commit_world_overlay_for_testing().unwrap();
    assert_eq!(
        expected_hash,
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap()
    );
    assert_eq!(
        expected_bytes,
        crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state)
    );
    assert_eq!(
        state
            .world
            .domain_endorsements_by_domain
            .view()
            .get(&domain),
        Some(&after)
    );
    let predecessor = state.world.domain_endorsements_by_domain.block_and_revert();
    assert_eq!(predecessor.get(&domain), Some(&before));
}

#[test]
fn staged_sccp_snapshot_preserves_single_envelope_with_current_and_predecessor() {
    use crate::smartcontracts::isi::sccp::test_support::populate_every_sccp_map;
    use crate::state::sccp_snapshot_state::{
        SnapshotSccpState, serialize_block_envelope, serialize_envelope,
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{
            inbound::SccpPendingReasonV1,
            outbound::{
                SccpOutboundMessageRecordV1, SccpOutboundStatusV1, SccpVoidKindV1, SccpVoidStatusV1,
            },
        },
    };

    fn populate_added_fields(
        world: &mut WorldBlock<'_>,
        seed: u8,
        budget: &iroha_allocation::AllocationBudget,
    ) {
        // Serialization DATA owns real admitted keys and both MV cuts. These records
        // confer no authenticated offence, certificate, or execution authority.
        let key = sccp_forgery_custody::OffenceKey::try_copy(
            u64::from(seed),
            LaneId::SINGLE,
            &iroha_test_samples::ALICE_ID,
            budget,
        )
        .unwrap();
        assert!(key.belongs_to(budget));
        world
            .sccp_forgery_offences
            .try_insert_admitted(key, [seed; 32])
            .unwrap();
        *world.sccp_forgery_max_generation.get_mut() = Some(u64::from(seed));
        let network = SccpNetworkV1::EthereumMainnet;
        let key = (network, 1);
        let amount = u128::from(seed) * 10;
        let pending = world
            .sccp_pending_refund_amount
            .get(&key)
            .copied()
            .unwrap_or(0);
        world
            .sccp_pending_refund_amount
            .try_insert_admitted(key, pending.checked_add(amount).unwrap())
            .unwrap();
        world.sccp_outbound_messages.insert(
            [seed | 0x80; 32],
            SccpOutboundMessageRecordV1 {
                network,
                revision: 1,
                nonce: u64::from(seed) + 100,
                height: u64::from(seed),
                commitment_index: 0,
                deadline_ms: 1,
                sender: iroha_test_samples::ALICE_ID.clone(),
                amount,
                payload: Vec::new(),
                leaf: [seed | 0x80; 32],
                status: SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
                    kind: SccpVoidKindV1::Expired,
                    proven_at_height: u64::from(seed) + 1,
                    refund_pending: Some(SccpPendingReasonV1::LiabilityShortfall),
                }),
            },
        );
    }

    let (state, _) = fixture();
    let budget = state.ivm_execution_budget();
    {
        // Exact SCCP component setup carries no certified chain authority.
        let mut world = state.world.block();
        populate_every_sccp_map(&mut world, 1, &budget);
        populate_added_fields(&mut world, 1, &budget);
        world.commit();
    }
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1,
        0,
    ));
    populate_every_sccp_map(&mut block.world, 2, &budget);
    populate_added_fields(&mut block.world, 2, &budget);
    block.finalize_axt_asset_incarnations().unwrap();
    block.finalize_axt_policy_transition_ratchets().unwrap();
    let mut envelope = String::new();
    serialize_block_envelope(&block.world, &mut envelope);
    let envelope_value: json::Value = json::from_str(&envelope).unwrap();
    assert_eq!(envelope_value.as_object().unwrap().len(), 34);
    for (field, before, after) in [
        ("sccp_committee_current", 1_u64, 2_u64),
        ("sccp_liability_clock", 1_000, 2_000),
        ("sccp_degraded_run", 1, 2),
    ] {
        let cell = envelope_value.get(field).unwrap();
        // Norito represents the present predecessor as the exact Option payload.
        assert_eq!(
            cell.get("revert").unwrap().get("value").unwrap().as_u64(),
            Some(before),
        );
        assert_eq!(cell.get("blocks").unwrap().as_u64(), Some(after));
    }
    // Decode these serialization claims into the same original finite pool. This is
    // field-custody coverage; full authenticated restoration has its own signed tests.
    let decoded: SnapshotSccpState = json::from_str(&envelope).unwrap();
    let offences = decoded
        .sccp_forgery_offences
        .decode_forgery_offences(&budget)
        .unwrap();
    assert!(offences.allocation_budget().same_pool(&budget));
    assert_eq!(offences.view().len(), 2);
    for seed in [1_u8, 2] {
        let key = sccp_forgery_custody::OffenceKey::try_copy(
            u64::from(seed),
            LaneId::SINGLE,
            &iroha_test_samples::ALICE_ID,
            &budget,
        )
        .unwrap();
        assert_eq!(offences.view().get(&key), Some(&[seed; 32]));
    }
    budget.with_deferred_refund_notifications(|scope| {
        let mut slot = offences.try_block_acquisition_admitted(scope).unwrap();
        slot.try_initialize(mv::BlockMode::Replace).unwrap();
        let predecessor = slot.into_block();
        for seed in [1_u8, 2] {
            let key = sccp_forgery_custody::OffenceKey::try_copy(
                u64::from(seed),
                LaneId::SINGLE,
                &iroha_test_samples::ALICE_ID,
                &budget,
            )
            .unwrap();
            assert_eq!(predecessor.get(&key), (seed == 1).then_some(&[seed; 32]));
        }
    });
    assert_eq!(*decoded.sccp_forgery_max_generation.view().get(), Some(2));
    assert_eq!(
        *decoded.sccp_forgery_max_generation.predecessor_view().get(),
        Some(Some(1))
    );
    let refunds = decoded
        .sccp_pending_refund_amount
        .decode_reconciliation_fixed::<(SccpNetworkV1, u32), u128>(
            "sccp_pending_refund_amount",
            &budget,
            |_, _| true,
        )
        .unwrap();
    assert!(refunds.allocation_budget().same_pool(&budget));
    let refund_key = (SccpNetworkV1::EthereumMainnet, 1);
    assert_eq!(refunds.view().get(&refund_key), Some(&30));
    budget.with_deferred_refund_notifications(|scope| {
        let mut slot = refunds.try_block_acquisition_admitted(scope).unwrap();
        slot.try_initialize(mv::BlockMode::Replace).unwrap();
        let predecessor = slot.into_block();
        assert_eq!(predecessor.get(&refund_key), Some(&10));
    });
    let staged_bytes = crate::snapshot::canonical_staged_state_snapshot_bytes(&block);
    let staged_hash = crate::snapshot::canonical_staged_state_snapshot_hash(&block);
    let staged: json::Value = json::from_slice(&staged_bytes).unwrap();
    for field in [
        "sccp_committee_generations",
        "sccp_committee_current",
        "sccp_liability_clock",
        "sccp_degraded_run",
        "sccp_anchor_open",
        "sccp_anchor_chunks",
        "sccp_forgery_offences",
        "sccp_forgery_max_generation",
        "sccp_pending_refund_amount",
    ] {
        assert!(
            staged.get("world").unwrap().get(field).is_none(),
            "{field} must have one envelope"
        );
        assert!(
            staged.get("sccp").unwrap().get(field).is_some(),
            "{field} must be retained"
        );
    }
    block.commit_world_overlay_for_testing().unwrap();
    assert_eq!(
        staged_bytes,
        crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state)
    );
    assert_eq!(
        staged_hash,
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap()
    );
    let mut committed_envelope = String::new();
    serialize_envelope(&state.world, &mut committed_envelope);
    assert_eq!(
        committed_envelope, envelope,
        "all 34 current/undo owners survive publication exactly"
    );
    let predecessor = state.world.block_and_revert();
    assert_eq!(*predecessor.sccp_committee_current.get(), 1);
    assert_eq!(*predecessor.sccp_liability_clock.get(), 1_000);
    assert_eq!(*predecessor.sccp_degraded_run.get(), 1);
    assert_eq!(*predecessor.sccp_forgery_max_generation.get(), Some(1));
    assert_eq!(predecessor.sccp_forgery_offences.len(), 1);
    assert_eq!(
        predecessor.sccp_pending_refund_amount.get(&refund_key),
        Some(&10)
    );
    assert_eq!(predecessor.sccp_committee_generations.len(), 1);
    assert_eq!(predecessor.sccp_anchor_chunks.len(), 1);
    assert_eq!(
        predecessor.sccp_anchor_open.get().as_slice()[0].core_hash,
        [1; 32]
    );
}
