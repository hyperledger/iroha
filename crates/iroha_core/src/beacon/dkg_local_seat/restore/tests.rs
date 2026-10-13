//! Genuine native-source sequential restart, immutable signed output and prepaid refusal controls.

use super::*;
use crate::{
    beacon::{
        AdaptiveGlobalThresholdBeaconDkgCryptoV1, GlobalThresholdBeaconDkgStateV1,
        PreparedGlobalThresholdBeaconDkgPublicationV1,
    },
    sumeragi::{native_journal::NativeJournalCursor, test_chain::CertifiedTestChain},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_crypto::Signature;
use iroha_data_model::sumeragi::finality::{
    NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits,
};

fn original_clock(chain: &CertifiedTestChain, clock: &mut NativeJournalCursor, height: u64) {
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

fn context(
    authority: &AuthenticatedGlobalBeaconDkgAttemptV1,
    clock: &NativeJournalCursor,
    phase: u16,
    seat: u16,
    signer: &KeyPair,
    output: &[u8],
    input: [u8; 32],
    previous: &[u8],
) -> VerifiedGlobalBeaconDkgCheckpointContextV1 {
    // Canonical component-only intent commitment. Daemon write-ahead/fsync and
    // descriptor-bound input replay are tested in its separate production owner.
    let intent =
        norito::encode_canonical(&(authority.session().attempt_id, phase, seat, input)).unwrap();
    authority
        .checkpoint_context(
            clock,
            phase,
            seat,
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
    authority: AuthenticatedGlobalBeaconDkgAttemptV1,
    contexts: [VerifiedGlobalBeaconDkgCheckpointContextV1; 3],
    public: [Vec<u8>; 3],
    private: [Vec<u8>; 3],
    commitments: GlobalThresholdBeaconDkgSnapshotV1,
    deliveries: GlobalThresholdBeaconDkgSnapshotV1,
    roster: Vec<PeerId>,
    signer: KeyPair,
}

fn original() -> Original {
    original_with_capsule_corruption(false)
}

fn original_with_capsule_corruption(corrupt_capsule: bool) -> Original {
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
                u16::try_from(i + 1).expect("fixture value fits u16"),
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
    let ctx1 = context(&authority, &clock, 1, 1, &keys[0], &public1, [0; 32], &[]);
    let private1 = local[0]
        .seal_private_checkpoint(&ctx1, &keys[0])
        .unwrap()
        .to_vec();
    chain.commit(Vec::new());
    original_clock(&chain, &mut clock, 2);
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
    let mut deliveries = reducer.public_snapshot().unwrap().record().clone();
    let public2 = local[0].delivery_frame(&commitments).unwrap().to_vec();
    let input2 = local[0].checkpoint_input_hash(2, &commitments).unwrap();
    let ctx2 = context(
        &authority, &clock, 2, 1, &keys[0], &public2, input2, &private1,
    );
    let private2 = local[0]
        .seal_private_checkpoint(&ctx2, &keys[0])
        .unwrap()
        .to_vec();
    for seat in &mut local {
        seat.retire_durably_published_dealer().unwrap();
    }
    chain.commit(Vec::new());
    original_clock(&chain, &mut clock, 3);
    let _ = local[0].accept(&deliveries, 3, &keys[0]).unwrap();
    let mut public3 = local[0].acceptance_frame(&deliveries).unwrap().to_vec();
    if corrupt_capsule {
        // A completed malicious relation fixture, not a successful forward
        // producer: the actual dealer and recipient sign a corrupted capsule
        // and its exact acknowledgment while the original correct private
        // shares remain independently authenticated by the checked checkpoint.
        let edge = deliveries
            .encrypted_shares
            .iter_mut()
            .find(|edge| edge.dealer_index == 2 && edge.recipient_index == 1)
            .unwrap();
        edge.encrypted_share[0] ^= 1;
        edge.signature = Signature::new(
            keys[1].private_key(),
            &crate::beacon::global_threshold_beacon_dkg_encrypted_share_preimage_v1(&session, edge),
        );
        let changed_edge_hash =
            crate::beacon::global_threshold_beacon_dkg_encrypted_share_hash_v1(&session, edge);
        let mut publication: GlobalThresholdBeaconDkgSnapshotV1 =
            norito::decode_canonical(&public3).unwrap();
        publication.encrypted_shares = deliveries.encrypted_shares.clone();
        let row = publication
            .share_acceptances
            .iter_mut()
            .find(|row| row.dealer_index == 2)
            .unwrap();
        row.encrypted_share_hash = changed_edge_hash;
        row.signature = Signature::new(
            keys[0].private_key(),
            &crate::beacon::global_threshold_beacon_dkg_share_acceptance_preimage_v1(&session, row),
        );
        DkgSnapshotRef::from(&deliveries)
            .validate_with_verifier(&mut local[0].workspace)
            .unwrap();
        DkgSnapshotRef::from(&publication)
            .validate_with_verifier(&mut local[0].workspace)
            .unwrap();
        public3 = norito::encode_canonical(&publication).unwrap();
    }
    let input3 = local[0].checkpoint_input_hash(3, &deliveries).unwrap();
    let ctx3 = context(
        &authority, &clock, 3, 1, &keys[0], &public3, input3, &private2,
    );
    let private3 = if corrupt_capsule {
        // Deliberately use the component seal API: the forward local producer
        // did not accept this changed capsule. The source authority is still
        // checked against the same original actual native height and cutoff.
        let seat = &mut local[0];
        seat.checkpoints[2]
            .seal(
                ctx3.binding(),
                &keys[0],
                &seat.encryption,
                None,
                seat.outputs.shares.as_slice(),
            )
            .unwrap();
        seat.checkpoints[2].encrypted_record().unwrap().to_vec()
    } else {
        local[0]
            .seal_private_checkpoint(&ctx3, &keys[0])
            .unwrap()
            .to_vec()
    };
    // Every private producer is destroyed before restoring from its actual heads.
    drop(local);
    drop(reducer);
    drop(clock);
    drop(chain);
    assert_eq!(budget.reserved_bytes(), 0);
    Original {
        authority,
        contexts: [ctx1, ctx2, ctx3],
        public: [public1, public2, public3],
        private: [private1, private2, private3],
        commitments,
        deliveries,
        roster,
        signer: keys[0].clone(),
    }
}

fn restore_generation(
    original: &Original,
    budget: &AllocationBudget,
) -> LocalGlobalThresholdBeaconDkgSeatV1 {
    let mut bank = PreparedGlobalThresholdBeaconDkgPublicationV1::new(
        original.authority.session(),
        &original.roster,
        1,
        budget,
    )
    .unwrap();
    bank.decode(
        &original.public[0],
        norito::canonical_decode_limits(original.public[0].len()),
    )
    .unwrap();
    PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
        original.authority.session(),
        &original.roster,
        1,
        &original.signer,
        budget,
    )
    .unwrap()
    .restore_generated(
        &original.contexts[0],
        bank.publication().unwrap(),
        &original.public[0],
        &original.private[0],
        &original.signer,
        norito::canonical_decode_limits(original.private[0].len()),
    )
    .map_err(|(_, error)| error)
    .unwrap()
}

#[test]
fn actual_native_heads_restore_original_delivery_then_acceptance_without_signing_or_growth() {
    let original = original();
    let budget = crate::beacon::fixtures::fixture_budget();
    let mut delivery = PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery(
        original.authority.session(),
        &original.roster,
        1,
        &budget,
    )
    .unwrap();
    let mut acceptance = PreparedGlobalThresholdBeaconDkgPublicationV1::new_acceptance(
        original.authority.session(),
        &original.roster,
        1,
        &budget,
    )
    .unwrap();
    let retirement_bytes =
        delivery.decode_retirement_bytes().unwrap() + acceptance.decode_retirement_bytes().unwrap();
    let mut local = Some(restore_generation(&original, &budget));
    let original_backing = local.as_ref().unwrap().public_frame.backing();
    let pending_edge = local.as_ref().unwrap().outputs.pending_edges.as_slice()[0]
        .as_ref()
        .unwrap()
        .restoration_backing()
        .0;
    let pending_acceptance = local
        .as_ref()
        .unwrap()
        .outputs
        .pending_acceptances
        .as_slice()[0]
        .as_ref()
        .unwrap()
        .restoration_backing()
        .0;
    let retained = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    assert_eq!(
        allocations_during(|| delivery
            .decode(
                &original.public[1],
                norito::canonical_decode_limits(original.public[1].len())
            )
            .unwrap()),
        0
    );
    assert_eq!(
        allocations_during(|| acceptance
            .decode(
                &original.public[2],
                norito::canonical_decode_limits(original.public[2].len())
            )
            .unwrap()),
        0
    );
    assert_eq!(
        allocations_during(|| {
            local = Some(
                local
                    .take()
                    .unwrap()
                    .restore_delivered(
                        &original.contexts[1],
                        &original.commitments,
                        delivery.publication().unwrap(),
                        &original.public[1],
                        &original.private[1],
                        &original.signer,
                        norito::canonical_decode_limits(original.private[1].len()),
                    )
                    .map_err(|(_, error)| error)
                    .unwrap(),
            );
        }),
        0
    );
    let owner = local.as_mut().unwrap();
    assert!(owner.delivered && !owner.accepted && owner.dealer_secret.is_some());
    assert_eq!(
        owner.outputs.outgoing.as_slice()[0]
            .get()
            .signature
            .payload()
            .as_ptr(),
        pending_edge
    );
    assert_eq!(owner.public_frame.backing(), original_backing);
    assert_eq!(owner.encoded_public_frame(), original.public[1]);
    for phase in 0..2 {
        assert_eq!(
            owner.checkpoints[phase].encrypted_record().unwrap(),
            original.private[phase]
        );
    }
    assert!(
        owner
            .accept(&original.deliveries, 3, &original.signer)
            .is_err(),
        "durability-owned polynomial cannot retire implicitly"
    );
    let (held, error) = local
        .take()
        .unwrap()
        .restore_accepted(
            &original.contexts[2],
            &original.deliveries,
            acceptance.publication().unwrap(),
            &original.public[2],
            &original.private[2],
            &original.signer,
            norito::canonical_decode_limits(original.private[2].len()),
        )
        .err()
        .unwrap();
    assert!(matches!(
        error,
        LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
            GlobalThresholdBeaconError::InvalidDkgSession
        )
    ));
    assert!(held.dealer_secret.is_some() && !held.accepted);
    assert!(held.checkpoints[2].encrypted_record().is_none());
    local = Some(held);
    local
        .as_mut()
        .unwrap()
        .retire_durably_published_dealer()
        .unwrap();
    assert_eq!(
        allocations_during(|| {
            local = Some(
                local
                    .take()
                    .unwrap()
                    .restore_accepted(
                        &original.contexts[2],
                        &original.deliveries,
                        acceptance.publication().unwrap(),
                        &original.public[2],
                        &original.private[2],
                        &original.signer,
                        norito::canonical_decode_limits(original.private[2].len()),
                    )
                    .map_err(|(_, error)| error)
                    .unwrap(),
            );
        }),
        0
    );
    let owner = local.as_mut().unwrap();
    assert!(owner.delivered && owner.accepted && owner.dealer_secret.is_none());
    assert_eq!(
        owner.outputs.acceptances.as_slice()[0]
            .get()
            .signature
            .payload()
            .as_ptr(),
        pending_acceptance
    );
    assert_eq!(owner.public_frame.backing(), original_backing);
    assert_eq!(owner.encoded_public_frame(), original.public[2]);
    assert_eq!(owner.outputs.shares.as_slice().len(), 4);
    for phase in 0..3 {
        assert_eq!(
            owner.checkpoints[phase].encrypted_record().unwrap(),
            original.private[phase]
        );
    }
    assert_eq!(
        budget.reserved_bytes(),
        budget.limit_bytes() - retirement_bytes
    );
    drop(local);
    drop(acceptance);
    drop(delivery);
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_local_output_banks_refuse_real_capacity_and_allocator_before_claim() {
    for n in [4, 31] {
        let (session, _, roster) = super::super::tests::signed_session(n);
        for prepare in [
            PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery,
            PreparedGlobalThresholdBeaconDkgPublicationV1::new_acceptance,
        ] {
            let budget = crate::beacon::fixtures::fixture_budget();
            let blocker = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
            assert!(prepare(session, &roster, 1, &budget).is_err());
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            drop(blocker);
            let layout =
                Layout::array::<GlobalThresholdBeaconDkgRecipientKeyV1>(usize::from(n)).unwrap();
            let (result, refused) =
                refuse_one_layout_during(layout, || prepare(session, &roster, 1, &budget));
            assert!(refused);
            assert!(result.is_err());
            assert_eq!(budget.reserved_bytes(), 0);
            let same_pool = prepare(session, &roster, 1, &budget).unwrap();
            assert!(same_pool.belongs_to(&budget));
            drop(same_pool);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn exact_local_output_banks_keep_real_full_committee_rows_at_four_and_thirty_one_without_growth() {
    for n in [4, 31] {
        let (session, keys, roster) = super::super::tests::signed_session(n);
        let source_pool = crate::beacon::fixtures::fixture_budget();
        let fixture = crate::beacon::fixtures::adaptive_beacon_fixture_for_session_and_keys(
            session,
            &keys,
            &source_pool,
        );
        let transcript = &fixture.session.record().adaptive_dkg;
        let delivery = GlobalThresholdBeaconDkgSnapshotV1 {
            session,
            generator_h: transcript.generator_h,
            generator_v: transcript.generator_v,
            recipient_keys: transcript.recipient_keys.clone(),
            dealer_commitments: transcript.dealer_commitments.clone(),
            encrypted_shares: transcript
                .encrypted_shares
                .iter()
                .filter(|edge| edge.dealer_index == n)
                .cloned()
                .collect(),
            share_acceptances: vec![],
            last_updated_height: session.commitments_end_height,
        };
        let acceptance = GlobalThresholdBeaconDkgSnapshotV1 {
            session,
            generator_h: transcript.generator_h,
            generator_v: transcript.generator_v,
            recipient_keys: transcript.recipient_keys.clone(),
            dealer_commitments: transcript.dealer_commitments.clone(),
            encrypted_shares: transcript.encrypted_shares.clone(),
            share_acceptances: transcript
                .share_acceptances
                .iter()
                .filter(|row| row.recipient_index == n)
                .cloned()
                .collect(),
            last_updated_height: session.deliveries_end_height,
        };
        let wires = [
            norito::encode_canonical(&delivery).unwrap(),
            norito::encode_canonical(&acceptance).unwrap(),
        ];
        let pool = crate::beacon::fixtures::fixture_budget();
        let mut banks = [
            PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery(session, &roster, n, &pool)
                .unwrap(),
            PreparedGlobalThresholdBeaconDkgPublicationV1::new_acceptance(
                session, &roster, n, &pool,
            )
            .unwrap(),
        ];
        let max_message = DkgSignaturePreimage::RecipientKey(&session, &delivery.recipient_keys[0])
            .encoded_len()
            .max(
                DkgSignaturePreimage::DealerCommitment(&session, &delivery.dealer_commitments[0])
                    .encoded_len(),
            )
            .max(
                DkgSignaturePreimage::EncryptedShare(&session, &delivery.encrypted_shares[0])
                    .encoded_len(),
            )
            .max(
                DkgSignaturePreimage::ShareAcceptance(&session, &acceptance.share_acceptances[0])
                    .encoded_len(),
            );
        let mut verifier = DkgMessageWorkspace::new(max_message, &pool).unwrap();
        let source_identity = wires
            .iter()
            .map(|wire| (wire.as_ptr(), wire.len(), Hash::new(wire)))
            .collect::<Vec<_>>();
        let retirement_bytes = banks
            .iter()
            .map(|bank| bank.decode_retirement_bytes().unwrap())
            .sum::<usize>();
        let blockers = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        for (bank, wire) in banks.iter_mut().zip(&wires) {
            assert_eq!(
                allocations_during(|| bank
                    .decode(wire, norito::canonical_decode_limits(wire.len()))
                    .unwrap()),
                0
            );
            assert_eq!(
                allocations_during(|| DkgSnapshotRef::from(bank.publication().unwrap())
                    .validate_with_verifier(&mut verifier)
                    .unwrap()),
                0
            );
            assert!(bank.belongs_to(&pool));
            let retained = bank.publication().unwrap().recipient_keys.as_ptr();
            assert_eq!(
                allocations_during(|| bank
                    .decode(wire, norito::canonical_decode_limits(wire.len()))
                    .unwrap()),
                0
            );
            assert_eq!(
                bank.publication().unwrap().recipient_keys.as_ptr(),
                retained
            );
        }
        assert_eq!(banks[0].publication().unwrap(), &delivery);
        assert_eq!(banks[1].publication().unwrap(), &acceptance);
        assert_eq!(
            banks[0].publication().unwrap().encrypted_shares.len(),
            usize::from(n)
        );
        assert_eq!(
            banks[1].publication().unwrap().encrypted_shares.len(),
            usize::from(n) * usize::from(n)
        );
        assert_eq!(
            banks[1].publication().unwrap().share_acceptances.len(),
            usize::from(n)
        );
        for (wire, (pointer, len, hash)) in wires.iter().zip(source_identity) {
            assert_eq!(wire.as_ptr(), pointer);
            assert_eq!(wire.len(), len);
            assert_eq!(Hash::new(wire), hash);
        }
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes() - retirement_bytes);
        drop(verifier);
        drop(banks);
        drop(blockers);
        assert_eq!(pool.reserved_bytes(), 0);
        drop(fixture);
        assert_eq!(source_pool.reserved_bytes(), 0);
    }
}

#[test]
fn original_delivery_refusal_keeps_public_prefix_source_chain_and_same_private_bank_for_retry() {
    let original = original();
    let budget = crate::beacon::fixtures::fixture_budget();
    let mut bank = PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery(
        original.authority.session(),
        &original.roster,
        1,
        &budget,
    )
    .unwrap();
    let actual_source = original.public[1].as_ptr();
    let actual_hash = Hash::new(&original.public[1]);
    let narrow = norito::DecodeLimits::new(1, 1, 1, 1, 1);
    assert!(bank.decode(&original.public[1], narrow).is_err());
    let substituted = original.public[1].clone();
    assert!(matches!(
        bank.decode(
            &substituted,
            norito::canonical_decode_limits(substituted.len())
        ),
        Err(crate::beacon::GlobalThresholdBeaconInputErrorV1::SourceChanged)
    ));
    bank.decode(
        &original.public[1],
        norito::canonical_decode_limits(original.public[1].len()),
    )
    .unwrap();
    let mut local = restore_generation(&original, &budget);
    let pointer = local.outputs.pending_edges.as_slice()[0]
        .as_ref()
        .unwrap()
        .restoration_backing();
    let floor = budget.reserved_bytes();
    let (owner, original_private_refusal) = local
        .restore_delivered(
            &original.contexts[1],
            &original.commitments,
            bank.publication().unwrap(),
            &original.public[1],
            &original.private[1],
            &original.signer,
            narrow,
        )
        .err()
        .unwrap();
    local = owner;
    let assert_original_refusal = |error: &LocalGlobalThresholdBeaconDkgErrorV1| {
        let LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            iroha_crypto::threshold_bls::checkpoint::DkgCheckpointErrorV1::Decode(
                norito::core::PreparedDecodeError::Codec(cause),
            ),
        ) = error
        else {
            panic!("original private decoder must retain its exact typed resource refusal");
        };
        // The explicit limits belong to this protocol attempt, rather than an
        // enclosing caller. Preserve that distinction and its opaque original
        // scope after the decoder is reused and ultimately retired.
        assert_eq!(cause.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
        let original = std::error::Error::source(cause)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap();
        assert!(matches!(original, norito::Error::ScopedDecodeResource(_)));
        assert!(matches!(
            original.decode_resource_error(),
            Some(norito::core::DecodeResourceError::FieldLengthExceeded { length, limit: 1 }) if length > 1
        ));
    };
    assert_original_refusal(&original_private_refusal);
    assert!(!local.delivered && local.outputs.outgoing.as_slice().is_empty());
    assert_eq!(
        local.outputs.pending_edges.as_slice()[0]
            .as_ref()
            .unwrap()
            .restoration_backing(),
        pointer
    );
    assert_eq!(budget.reserved_bytes(), floor);
    let mut restored = None;
    assert_eq!(
        allocations_during(|| {
            restored = Some(local.restore_delivered(
                &original.contexts[1],
                &original.commitments,
                bank.publication().unwrap(),
                &original.public[1],
                &original.private[1],
                &original.signer,
                norito::canonical_decode_limits(original.private[1].len()),
            ));
        }),
        0
    );
    local = restored.unwrap().map_err(|(_, error)| error).unwrap();
    assert_eq!(budget.reserved_bytes(), floor);
    assert_original_refusal(&original_private_refusal);
    assert_eq!(original.public[1].as_ptr(), actual_source);
    assert_eq!(Hash::new(&original.public[1]), actual_hash);
    assert_eq!(
        local.outputs.outgoing.as_slice()[0]
            .get()
            .signature
            .payload()
            .as_ptr(),
        pointer.0
    );
    drop(local);
    drop(bank);
    // The original typed refusal remains the last reader of this decoder's
    // actual derived control. Its layout is funded until that reader retires.
    let counter_bytes = norito::core::PreparedDecodeWorkspace::allocation_layouts()[0].size();
    assert_original_refusal(&original_private_refusal);
    assert_eq!(budget.reserved_bytes(), counter_bytes);
    drop(original_private_refusal);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_signed_output_corruption_is_refused_before_consuming_any_prepaid_row() {
    let original = original();
    let budget = crate::beacon::fixtures::fixture_budget();
    let mut bank = PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery(
        original.authority.session(),
        &original.roster,
        1,
        &budget,
    )
    .unwrap();
    bank.decode(
        &original.public[1],
        norito::canonical_decode_limits(original.public[1].len()),
    )
    .unwrap();
    // A fixture copy is mutated outside measured work. The actual admitted wire,
    // checked native context and private head retain their complete original bytes.
    let mut corrupted = bank.publication().unwrap().clone();
    corrupted.encrypted_shares[0].signature = iroha_crypto::Signature::from_bytes(&[0; 96]);
    let local = restore_generation(&original, &budget);
    let signature_pointer = local.outputs.pending_edges.as_slice()[0]
        .as_ref()
        .unwrap()
        .restoration_backing();
    let bytes = budget.reserved_bytes();
    let (local, _error) = local
        .restore_delivered(
            &original.contexts[1],
            &original.commitments,
            &corrupted,
            &original.public[1],
            &original.private[1],
            &original.signer,
            norito::canonical_decode_limits(original.private[1].len()),
        )
        .err()
        .unwrap();
    assert!(!local.delivered && local.outputs.outgoing.as_slice().is_empty());
    assert!(local.checkpoints[1].encrypted_record().is_none());
    assert_eq!(
        local.outputs.pending_edges.as_slice()[0]
            .as_ref()
            .unwrap()
            .restoration_backing(),
        signature_pointer
    );
    assert_eq!(budget.reserved_bytes(), bytes);
    let local = local
        .restore_delivered(
            &original.contexts[1],
            &original.commitments,
            bank.publication().unwrap(),
            &original.public[1],
            &original.private[1],
            &original.signer,
            norito::canonical_decode_limits(original.private[1].len()),
        )
        .map_err(|(_, error)| error)
        .unwrap();
    assert_eq!(
        local.outputs.outgoing.as_slice()[0]
            .get()
            .signature
            .payload()
            .as_ptr(),
        signature_pointer.0
    );
    drop(local);
    drop(bank);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_signed_capsule_relation_is_checked_before_any_accepted_owner_or_row_moves() {
    let original = original_with_capsule_corruption(true);
    let pool = crate::beacon::fixtures::fixture_budget();
    let mut delivery = PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery(
        original.authority.session(),
        &original.roster,
        1,
        &pool,
    )
    .unwrap();
    let mut acceptance = PreparedGlobalThresholdBeaconDkgPublicationV1::new_acceptance(
        original.authority.session(),
        &original.roster,
        1,
        &pool,
    )
    .unwrap();
    delivery
        .decode(
            &original.public[1],
            norito::canonical_decode_limits(original.public[1].len()),
        )
        .unwrap();
    acceptance
        .decode(
            &original.public[2],
            norito::canonical_decode_limits(original.public[2].len()),
        )
        .unwrap();
    let mut local = restore_generation(&original, &pool)
        .restore_delivered(
            &original.contexts[1],
            &original.commitments,
            delivery.publication().unwrap(),
            &original.public[1],
            &original.private[1],
            &original.signer,
            norito::canonical_decode_limits(original.private[1].len()),
        )
        .map_err(|(_, error)| error)
        .unwrap();
    local.retire_durably_published_dealer().unwrap();
    let pending = local.outputs.pending_acceptances.as_slice()[1]
        .as_ref()
        .unwrap()
        .restoration_backing();
    let shares = local.outputs.shares.as_slice().as_ptr();
    let source = (
        original.public[2].as_ptr(),
        original.private[2].as_ptr(),
        Hash::new(&original.public[2]),
        Hash::new(&original.private[2]),
    );
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let mut held = Some(local);
    assert_eq!(
        allocations_during(|| {
            let (owner, error) = held
                .take()
                .unwrap()
                .restore_accepted(
                    &original.contexts[2],
                    &original.deliveries,
                    acceptance.publication().unwrap(),
                    &original.public[2],
                    &original.private[2],
                    &original.signer,
                    norito::canonical_decode_limits(original.private[2].len()),
                )
                .err()
                .unwrap();
            assert!(matches!(
                error,
                LocalGlobalThresholdBeaconDkgErrorV1::Threshold(
                    iroha_crypto::threshold_bls::ThresholdBlsError::PrivateShareDecryption
                )
            ));
            held = Some(owner);
        }),
        0
    );
    let owner = held.as_ref().unwrap();
    assert!(!owner.accepted && owner.outputs.acceptances.as_slice().is_empty());
    assert!(owner.outputs.shares.as_slice().is_empty());
    assert_eq!(owner.outputs.shares.as_slice().as_ptr(), shares);
    assert_eq!(
        owner.outputs.pending_acceptances.as_slice()[1]
            .as_ref()
            .unwrap()
            .restoration_backing(),
        pending
    );
    assert_eq!(
        owner.checkpoints[2].encrypted_record().unwrap(),
        original.private[2]
    );
    assert_eq!(
        (
            original.public[2].as_ptr(),
            original.private[2].as_ptr(),
            Hash::new(&original.public[2]),
            Hash::new(&original.private[2])
        ),
        source
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(held);
    drop(delivery);
    drop(acceptance);
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_accepted_share_and_ciphertext_owners_refund_exact_pool_after_consumer_unwind() {
    let original = original();
    let pool = crate::beacon::fixtures::fixture_budget();
    let mut delivery = PreparedGlobalThresholdBeaconDkgPublicationV1::new_delivery(
        original.authority.session(),
        &original.roster,
        1,
        &pool,
    )
    .unwrap();
    let mut acceptance = PreparedGlobalThresholdBeaconDkgPublicationV1::new_acceptance(
        original.authority.session(),
        &original.roster,
        1,
        &pool,
    )
    .unwrap();
    delivery
        .decode(
            &original.public[1],
            norito::canonical_decode_limits(original.public[1].len()),
        )
        .unwrap();
    acceptance
        .decode(
            &original.public[2],
            norito::canonical_decode_limits(original.public[2].len()),
        )
        .unwrap();
    let mut local = restore_generation(&original, &pool)
        .restore_delivered(
            &original.contexts[1],
            &original.commitments,
            delivery.publication().unwrap(),
            &original.public[1],
            &original.private[1],
            &original.signer,
            norito::canonical_decode_limits(original.private[1].len()),
        )
        .map_err(|(_, error)| error)
        .unwrap();
    local.retire_durably_published_dealer().unwrap();
    let local = local
        .restore_accepted(
            &original.contexts[2],
            &original.deliveries,
            acceptance.publication().unwrap(),
            &original.public[2],
            &original.private[2],
            &original.signer,
            norito::canonical_decode_limits(original.private[2].len()),
        )
        .map_err(|(_, error)| error)
        .unwrap();
    assert_eq!(local.outputs.shares.as_slice().len(), 4);
    for (bank, source) in local.checkpoints.iter().zip(&original.private) {
        assert_eq!(bank.encrypted_record().unwrap(), source);
    }
    let identities = original
        .public
        .iter()
        .chain(&original.private)
        .map(|source| (source.as_ptr(), source.len(), Hash::new(source)))
        .collect::<Vec<_>>();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        // These are the actual exchanged private allocation, original canonical
        // row ledgers and retained encrypted heads; no substitute owner is made.
        let _original_owners = (local, delivery, acceptance);
        panic!("consumer unwinds after original accepted checkpoint restoration");
    }));
    assert!(unwind.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    for (source, identity) in original
        .public
        .iter()
        .chain(&original.private)
        .zip(identities)
    {
        assert_eq!((source.as_ptr(), source.len(), Hash::new(source)), identity);
    }
}
