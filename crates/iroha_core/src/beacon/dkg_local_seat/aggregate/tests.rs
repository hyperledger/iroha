//! Genuine H4 aggregate authority, retained contribution retirement and small original-bank restart.

use super::*;
use crate::{
    beacon::{
        AdaptiveGlobalThresholdBeaconDkgCryptoV1, GlobalThresholdBeaconDkgStateV1,
        GlobalThresholdBeaconSessionBindingV1, validate_global_threshold_beacon_session_v1,
    },
    sumeragi::{native_journal::NativeJournalCursor, test_chain::CertifiedTestChain},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_data_model::sumeragi::finality::{
    NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits,
};

fn advance(chain: &CertifiedTestChain, clock: &mut NativeJournalCursor, height: u64) {
    let limits = NativeFinalityLimits {
        block_bytes: 1024 * 1024,
        journal_bytes: 4 * 1024 * 1024,
        block_count: 4,
        allocated_bytes: 64 * 1024 * 1024,
    };
    let journal = NativeFinalityJournal {
        blocks: (1..=height)
            .map(|h| {
                NativeFinalityArtifact::from_block(chain.committed(h).block(), limits).unwrap()
            })
            .collect(),
    };
    clock.advance((&journal).into()).unwrap();
    assert_eq!(clock.tip().unwrap().height(), height);
}
fn phase_context(
    authority: &AuthenticatedGlobalBeaconDkgAttemptV1,
    clock: &NativeJournalCursor,
    phase: u16,
    signer: &KeyPair,
    output: &[u8],
    input: [u8; 32],
    previous: &[u8],
) -> VerifiedGlobalBeaconDkgCheckpointContextV1 {
    // Component-only immutable intent bytes. Actual file/dir durability is a
    // distinct daemon production control and is not inferred from this fixture.
    let intent =
        norito::encode_canonical(&(authority.session().attempt_id, phase, 1_u16, input)).unwrap();
    authority
        .checkpoint_context(
            clock,
            phase,
            1,
            signer,
            "software-provider",
            7,
            Hash::new(output).into(),
            input,
            if phase == 1 {
                [0; 32]
            } else {
                Hash::new(previous).into()
            },
            Hash::new(intent).into(),
        )
        .unwrap()
}
struct Original {
    local: Vec<LocalGlobalThresholdBeaconDkgSeatV1>,
    public: super::super::super::ValidatedGlobalThresholdBeaconSessionV1,
    authority: AuthenticatedGlobalBeaconDkgAttemptV1,
    clock: NativeJournalCursor,
    keys: Vec<KeyPair>,
    budget: AllocationBudget,
    accepted_hash: [u8; 32],
    accepted_head: [u8; 32],
    intent_hash: [u8; 32],
    chain: CertifiedTestChain,
}
impl Original {
    fn context(&self, intent: [u8; 32]) -> VerifiedGlobalBeaconDkgAggregateContextV1 {
        self.authority
            .aggregate_context(
                &self.clock,
                &self.public,
                1,
                &self.keys[0],
                "software-provider",
                7,
                self.accepted_hash,
                self.accepted_head,
                intent,
            )
            .unwrap()
    }
}
fn original() -> Original {
    let (source, authority, mut clock, roster, budget) =
        super::super::ownership_tests::authenticated_source(4, 1000);
    let keys = source.validator_keys.clone();
    let mut chain = CertifiedTestChain::from_prepared(source).unwrap();
    let session = authority.session();
    let mut local = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                session,
                &roster,
                u16::try_from(i + 1).expect("bounded fixture seat fits u16"),
                key,
                &budget,
            )
            .unwrap()
            .generate(key)
            .unwrap()
        })
        .collect::<Vec<_>>();
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    let mut reducer = GlobalThresholdBeaconDkgStateV1::new(session, &crypto, &budget).unwrap();
    for seat in &local {
        let (recipient, dealer) = seat.publication();
        reducer.record_recipient_key(1, recipient).unwrap();
        reducer
            .record_dealer_commitment(1, dealer, &crypto)
            .unwrap();
    }
    let commitments = reducer.public_snapshot().unwrap().record().clone();
    let public1 = local[0].publication_frame().unwrap().to_vec();
    let context1 = phase_context(&authority, &clock, 1, &keys[0], &public1, [0; 32], &[]);
    let private1 = local[0]
        .seal_private_checkpoint(&context1, &keys[0])
        .unwrap()
        .to_vec();
    chain.commit(Vec::new());
    advance(&chain, &mut clock, 2);
    for (seat, key) in local.iter_mut().zip(&keys) {
        let _ = seat
            .deliver(
                &commitments.recipient_keys,
                &commitments.dealer_commitments,
                2,
                key,
            )
            .unwrap();
        for edge in seat.outputs.outgoing.as_slice() {
            reducer.record_encrypted_share(2, edge.get()).unwrap();
        }
    }
    let deliveries = reducer.public_snapshot().unwrap().record().clone();
    let public2 = local[0].delivery_frame(&commitments).unwrap().to_vec();
    let input2 = local[0].checkpoint_input_hash(2, &commitments).unwrap();
    let context2 = phase_context(&authority, &clock, 2, &keys[0], &public2, input2, &private1);
    let private2 = local[0]
        .seal_private_checkpoint(&context2, &keys[0])
        .unwrap()
        .to_vec();
    for seat in &mut local {
        seat.retire_durably_published_dealer().unwrap();
    }
    chain.commit(Vec::new());
    advance(&chain, &mut clock, 3);
    for (seat, key) in local.iter_mut().zip(&keys) {
        let _ = seat.accept(&deliveries, 3, key).unwrap();
        for row in seat.outputs.acceptances.as_slice() {
            reducer.record_share_acceptance(3, row.get()).unwrap();
        }
    }
    let public3 = local[0].acceptance_frame(&deliveries).unwrap().to_vec();
    let input3 = local[0].checkpoint_input_hash(3, &deliveries).unwrap();
    let context3 = phase_context(&authority, &clock, 3, &keys[0], &public3, input3, &private2);
    let private3 = local[0]
        .seal_private_checkpoint(&context3, &keys[0])
        .unwrap()
        .to_vec();
    let accepted_hash = Hash::new(&private3).into();
    let accepted_head_bytes =
        norito::encode_canonical(&(*context3.binding(), accepted_hash)).unwrap();
    let accepted_head = Hash::new(&accepted_head_bytes).into();
    chain.commit(Vec::new());
    advance(&chain, &mut clock, 4);
    let record = reducer.finalize(4, &crypto).unwrap();
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: record.network_id,
        session_id: record.session_id,
        roster_hash: record.roster_hash,
        transcript_hash: record.transcript_hash,
    };
    let public = validate_global_threshold_beacon_session_v1(record, &binding, &budget).unwrap();
    let intent = norito::encode_canonical(&(
        authority.session().attempt_id,
        4_u16,
        1_u16,
        accepted_hash,
        accepted_head,
        Hash::new(norito::encode_canonical(public.record()).unwrap()),
    ))
    .unwrap();
    let intent_hash = Hash::new(intent).into();
    drop(reducer);
    Original {
        local,
        public,
        authority,
        clock,
        keys,
        budget,
        accepted_hash,
        accepted_head,
        intent_hash,
        chain,
    }
}

#[test]
fn actual_native_h4_aggregate_stays_original_until_explicit_retirement_and_restores_small_owner() {
    let mut original = original();
    let context = original.context(original.intent_hash);
    let budget = original.budget.clone();
    let local = &mut original.local[0];
    let contribution_pointer = local.outputs.shares.as_slice().as_ptr();
    let acceptance_pointer = local.outputs.acceptances.as_slice().as_ptr();
    // Each original acceptance owns its signature leaf and physical charge ledger.
    // Retirement drops those exact owners while retaining both typed row buffers.
    let retired_acceptance_bytes = local
        .outputs
        .acceptances
        .as_slice()
        .iter()
        .try_fold(0usize, |bytes, acceptance| {
            assert!(acceptance.belongs_to(&budget));
            bytes.checked_add(acceptance.allocation_bytes().unwrap())
        })
        .unwrap();
    assert!(retired_acceptance_bytes > 0);
    let parts = local
        .outputs
        .shares
        .as_slice()
        .iter()
        .map(|share| share.components_for_authenticated_encryption())
        .collect::<Vec<_>>();

    let before = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - before)
        .unwrap();
    let mut cipher_hash = None;
    assert_eq!(
        allocations_during(|| {
            let bytes = local
                .produce_aggregate_checkpoint(&context, &original.public, &original.keys[0])
                .unwrap();
            cipher_hash = Some(Hash::new(bytes));
        }),
        0
    );
    assert_eq!(
        local.outputs.shares.as_slice().as_ptr(),
        contribution_pointer
    );
    assert_eq!(
        local.outputs.acceptances.as_slice().as_ptr(),
        acceptance_pointer
    );
    assert_eq!(local.outputs.shares.as_slice().len(), 4);
    assert_eq!(local.outputs.acceptances.as_slice().len(), 4);
    assert!(!local.extracted);
    assert_eq!(
        local
            .outputs
            .shares
            .as_slice()
            .iter()
            .map(|share| share.components_for_authenticated_encryption())
            .collect::<Vec<_>>(),
        parts
    );
    assert_eq!(
        allocations_during(|| assert_eq!(
            Hash::new(
                local
                    .produce_aggregate_checkpoint(&context, &original.public, &original.keys[0])
                    .unwrap()
            ),
            cipher_hash.unwrap()
        )),
        0
    );
    let aggregate_pointer = local
        .aggregate_checkpoint
        .as_ref()
        .unwrap()
        .encrypted_record()
        .unwrap()
        .as_ptr();
    let before_retirement = budget.reserved_bytes();
    assert_eq!(before_retirement, budget.limit_bytes());
    let mut owned = None;
    assert_eq!(
        allocations_during(|| owned = Some(
            local
                .retire_durably_published_aggregate(&context, &original.public, &original.keys[0])
                .unwrap()
        )),
        0
    );
    let owned = owned.unwrap();
    assert_eq!(owned.encrypted_checkpoint().as_ptr(), aggregate_pointer);
    assert!(owned.belongs_to(&budget));
    assert_eq!(owned.signer_index(), 1);
    assert!(local.extracted);
    assert!(local.outputs.shares.as_slice().is_empty());
    assert!(local.outputs.acceptances.as_slice().is_empty());
    assert_eq!(
        local.outputs.shares.as_slice().as_ptr(),
        contribution_pointer
    );
    assert_eq!(
        local.outputs.acceptances.as_slice().as_ptr(),
        acceptance_pointer
    );
    assert_eq!(
        budget.reserved_bytes(),
        before_retirement
            .checked_sub(retired_acceptance_bytes)
            .unwrap()
    );
    drop(blocker);
    let expected = zeroize::Zeroizing::new(*owned.secret.components_for_runtime_custody());
    let encrypted = owned.encrypted_checkpoint().to_vec();
    // Original native cursor and validated public owner stay retained; every
    // private ceremony producer and its aggregate are destroyed before reload.
    drop(original.local);
    drop(owned);
    let (layouts, preparation_allocations) = {
        let mut prepared = None;
        let count = allocations_during(|| {
            prepared = Some(
                PreparedGlobalBeaconAggregateRestoreV1::new(&original.public, 1, &budget).unwrap(),
            )
        });
        (prepared.unwrap(), count)
    };
    assert_eq!(
        preparation_allocations, 5,
        "aggregate reload constructs no Hybrid/polynomial/contribution graph"
    );

    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(layouts.restore(
            &context,
            &encrypted,
            &original.keys[0],
            norito::canonical_decode_limits(encrypted.len())
        ))),
        0
    );
    let owned = result
        .unwrap()
        .unwrap_or_else(|(_, error)| panic!("original aggregate restore: {error}"));
    assert_eq!(owned.encrypted_checkpoint(), encrypted);
    assert_eq!(owned.secret.components_for_runtime_custody(), &*expected);
    let source = owned.credential_source();
    assert_eq!(source.signer_index(), 1);
    assert_eq!(
        source.authenticated_session().record(),
        original.public.record()
    );
    let mut pending = [0_u8; 96];
    let mut destination = &mut pending[..];
    assert_eq!(
        allocations_during(|| owned
            .write_pending_share_for_runtime_custody(&mut destination)
            .unwrap()),
        0
    );
    assert!(destination.is_empty());
    for i in 0..3 {
        assert_eq!(&pending[i * 32..(i + 1) * 32], &expected[i]);
    }
    let physical = owned.original_backing_bytes();
    let before = budget.reserved_bytes();
    drop(owned);
    assert_eq!(budget.reserved_bytes(), before - physical);
    drop(blocker);
    drop(original.public);
    drop(original.clock);
    drop(original.chain);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn aggregate_checked_context_refuses_nonfinal_native_tip_zero_intent_and_changed_original_checkpoint()
 {
    let mut original = original();
    let context = original.context(original.intent_hash);
    let earlier_pool = crate::beacon::fixtures::fixture_budget();
    let mut earlier = NativeJournalCursor::new(
        original.clock.chain_id().clone(),
        original.clock.network_id(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        NativeFinalityLimits {
            block_bytes: 1024 * 1024,
            journal_bytes: 4 * 1024 * 1024,
            block_count: 4,
            allocated_bytes: 64 * 1024 * 1024,
        },
        &earlier_pool,
    )
    .unwrap();
    advance(&original.chain, &mut earlier, 3);
    assert_eq!(earlier.network_id(), original.clock.network_id());
    assert!(
        original
            .authority
            .aggregate_context(
                &earlier,
                &original.public,
                1,
                &original.keys[0],
                "software-provider",
                7,
                original.accepted_hash,
                original.accepted_head,
                original.intent_hash
            )
            .is_err()
    );
    let preparatory = original.context([0; 32]);
    assert_eq!(preparatory.binding().extraction_intent_hash, [0; 32]);
    let before = original.budget.reserved_bytes();
    let local = &mut original.local[0];
    assert!(matches!(
        local.produce_aggregate_checkpoint(&preparatory, &original.public, &original.keys[0]),
        Err(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Binding
        ))
    ));
    assert_eq!(local.outputs.shares.as_slice().len(), 4);
    assert!(!local.extracted);
    assert!(
        local
            .aggregate_checkpoint
            .as_ref()
            .unwrap()
            .encrypted_record()
            .is_none()
    );
    assert_eq!(original.budget.reserved_bytes(), before);
    let changed = original
        .authority
        .aggregate_context(
            &original.clock,
            &original.public,
            1,
            &original.keys[0],
            "software-provider",
            7,
            [0x77; 32],
            original.accepted_head,
            original.intent_hash,
        )
        .unwrap();
    assert!(
        local
            .produce_aggregate_checkpoint(&changed, &original.public, &original.keys[0])
            .is_err()
    );
    assert!(!local.extracted);
    local
        .produce_aggregate_checkpoint(&context, &original.public, &original.keys[0])
        .unwrap();
    let encrypted = local
        .aggregate_checkpoint
        .as_ref()
        .unwrap()
        .encrypted_record()
        .unwrap()
        .to_vec();
    let prepared =
        PreparedGlobalBeaconAggregateRestoreV1::new(&original.public, 1, &original.budget).unwrap();
    let physical = prepared.checkpoint.original_backing_bytes();
    let (prepared, error) = prepared
        .restore(
            &preparatory,
            &encrypted,
            &original.keys[0],
            norito::canonical_decode_limits(encrypted.len()),
        )
        .err()
        .unwrap();
    assert!(matches!(
        error,
        LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Binding)
    ));
    assert_eq!(prepared.checkpoint.original_backing_bytes(), physical);
    assert!(
        prepared
            .restore(
                &context,
                &encrypted,
                &original.keys[0],
                norito::canonical_decode_limits(encrypted.len())
            )
            .is_ok()
    );
}

#[test]
fn aggregate_restore_actual_enclosing_refusal_returns_original_preparer_and_same_pool_retry() {
    let mut original = original();
    let context = original.context(original.intent_hash);
    let encrypted = original.local[0]
        .produce_aggregate_checkpoint(&context, &original.public, &original.keys[0])
        .unwrap()
        .to_vec();
    let pool = &original.budget;
    let prepared = PreparedGlobalBeaconAggregateRestoreV1::new(&original.public, 1, pool).unwrap();
    let before = pool.reserved_bytes();
    let result =
        norito::core::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            prepared.restore(
                &context,
                &encrypted,
                &original.keys[0],
                norito::canonical_decode_limits(encrypted.len()),
            )
        });
    let (prepared, error) = result.err().unwrap();
    let LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Decode(
        norito::core::PreparedDecodeError::Codec(cause),
    )) = error
    else {
        panic!("retain original nested codec cause")
    };
    assert_eq!(
        cause.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(pool.reserved_bytes(), before);
    let pointer = prepared
        .checkpoint
        .original_encrypted_source()
        .unwrap()
        .as_ptr();
    assert_eq!(
        prepared.checkpoint.original_encrypted_source().unwrap(),
        encrypted
    );
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - before).unwrap();
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(prepared.restore(
            &context,
            &encrypted,
            &original.keys[0],
            norito::canonical_decode_limits(encrypted.len())
        ))),
        0
    );
    let owned = result
        .unwrap()
        .unwrap_or_else(|(_, error)| panic!("same original aggregate retry: {error}"));
    assert_eq!(owned.encrypted_checkpoint().as_ptr(), pointer);
    // Original opaque scope custody survives the successful retry; its actual
    // charged reader must retire before the complete private graph comparison.
    drop(cause);
    drop(owned);
    drop(blocker);
    assert_eq!(
        pool.reserved_bytes(),
        before
            - PreparedDkgAggregateCheckpointV1::<BeaconPurpose>::allocation_layouts()
                .unwrap()
                .iter()
                .map(Layout::size)
                .sum::<usize>()
    );
}

#[test]
fn aggregate_restore_refuses_foreign_public_pool_and_actual_scalar_allocator_before_private_adoption()
 {
    let original = original();
    let pool = &original.budget;
    let before = pool.reserved_bytes();
    let foreign = AllocationBudget::new(64 * 1024 * 1024);
    assert!(matches!(
        PreparedGlobalBeaconAggregateRestoreV1::new(&original.public, 1, &foreign),
        Err(LocalGlobalThresholdBeaconDkgErrorV1::Session(
            GlobalThresholdBeaconSessionError::ForeignReservation
        ))
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let mut result = None;
    let (_, refused) = refuse_one_layout_during(
        Layout::array::<zeroize::Zeroizing<[[u8; 32]; 3]>>(1).unwrap(),
        || {
            result = Some(PreparedGlobalBeaconAggregateRestoreV1::new(
                &original.public,
                1,
                pool,
            ))
        },
    );
    assert!(refused);
    assert!(result.unwrap().is_err());
    assert_eq!(pool.reserved_bytes(), before);
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - before).unwrap();
    assert!(PreparedGlobalBeaconAggregateRestoreV1::new(&original.public, 1, pool).is_err());
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), before);
}
