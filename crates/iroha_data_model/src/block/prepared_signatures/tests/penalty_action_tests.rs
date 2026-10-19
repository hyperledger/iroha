//! Real field-5 canonical traversal, original action refusal and immutable handoff custody.
use super::*;
use crate::{
    account::{AccountId, MultisigMember, MultisigPolicy},
    consensus::{
        NposConsensusSlashAction, NposMarkConsensusEvidenceAppliedAction, NposPenaltyAction,
    },
};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::{peer::PeerId, topology::LaneId};
use norito::core::{DecodeFlagsGuard, Encoder};

fn penalty_fixture() -> SignedBlock {
    let key = |seed| {
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone()
    };
    let mut block = fixture(0);
    let validator = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(key(8), 1).unwrap(),
                MultisigMember::new(key(9), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    block.payload.npos_consensus_effects = Some(NposConsensusEffects {
        parent_service_commit_qc: None,
        evidence_admissions: Vec::new(),
        penalty_actions: NposPenaltyActions::from_untrusted(vec![
            NposPenaltyAction::MarkConsensusEvidenceApplied(
                NposMarkConsensusEvidenceAppliedAction {
                    evidence_key: Hash::new([3]),
                    height: 17,
                },
            ),
            NposPenaltyAction::ConsensusSlash(NposConsensusSlashAction {
                evidence_key: Hash::new([1]),
                signer: 2,
                peer_id: PeerId::new(key(7)),
                lane_id: LaneId::new(3),
                validator,
                slash_id: Hash::new([2]),
                amount: "123456789012345678901234567890.123".parse().unwrap(),
            }),
        ]),
    });
    block
}
fn actions(block: &SignedBlock) -> &NposPenaltyActions {
    &block.npos_consensus_effects().unwrap().penalty_actions
}
#[test]
fn field5_penalty_actions_keep_canonical_wire_and_original_shared_graph() {
    for populated in [false, true] {
        let mut original = penalty_fixture();
        if !populated {
            original
                .payload
                .npos_consensus_effects
                .as_mut()
                .unwrap()
                .penalty_actions = NposPenaltyActions::default();
        }
        let wire = original.encode_wire().unwrap();
        let pool = AllocationBudget::new(1 << 20);
        let (source, span) = source_for(&original, &pool);
        let floor = pool.reserved_bytes();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let admitted = decoder
            .decode(&source, span, norito::canonical_decode_limits(wire.len()))
            .unwrap();
        assert_eq!(admitted, original);
        assert_eq!(admitted.encode_wire().unwrap(), wire);
        assert!(
            actions(&admitted).admitted_to(&pool),
            "field 5 must retain the original admitted action graph"
        );
        assert!(
            decoder
                .retains_npos_penalty_action_custody(&source, &admitted)
                .unwrap()
        );
        assert!(NposPenaltyActions::ptr_eq(
            actions(&admitted),
            decoder
                .retained_npos_penalty_actions(&source)
                .unwrap()
                .unwrap()
        ));
        let pointer = actions(&admitted).as_slice().as_ptr();
        let clone = admitted.clone();
        let retry = decoder
            .decode(&source, span, norito::canonical_decode_limits(wire.len()))
            .unwrap();
        assert!(NposPenaltyActions::ptr_eq(actions(&clone), actions(&retry)));
        drop(retry);
        drop(admitted);
        decoder.clear_consumed();
        assert!(
            !decoder
                .retains_npos_penalty_action_custody(&source, &clone)
                .unwrap()
        );
        drop(decoder);
        assert!(actions(&clone).admitted_to(&pool));
        assert_eq!(actions(&clone).as_slice().as_ptr(), pointer);
        drop(clone);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn field5_penalty_refusal_retains_original_prefix_pool_and_exact_retry() {
    let original = penalty_fixture();
    let wire = original.encode_wire().unwrap();
    let flags = norito::core::Header::read(&wire[1..]).unwrap().flags;
    let _flags = DecodeFlagsGuard::enter(flags);
    // Measure the actual sequence's declared array geometry before constructing
    // the destination. This separate measurement never supplies decode authority.
    let measured = AllocationBudget::new(1 << 20);
    let mut bare = Vec::new();
    actions(&original)
        .serialize(&mut Encoder::for_buffer(&mut bare))
        .unwrap();
    let mut measured_source = ChargedBuffer::new(bare.len(), &measured).unwrap();
    measured_source.append(&bare).unwrap();
    let plan = PreparedNposPenaltyActions::from_source(
        &measured_source,
        SequenceSpan {
            start: 0,
            end: bare.len(),
        },
        &measured,
    )
    .unwrap();
    let action_arrays = plan
        .backing_layouts()
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    drop(plan);
    drop(measured_source);
    assert_eq!(measured.reserved_bytes(), 0);
    let NposPenaltyAction::ConsensusSlash(slash) = &actions(&original).as_slice()[1] else {
        panic!("original slash")
    };
    let first_key = slash
        .peer_id
        .public_key()
        .retained_allocation_layout()
        .size();
    let prefix = BlockSignatures::allocation_layout().size()
        + action_arrays
        + std::alloc::Layout::array::<SequenceSpan>(actions(&original).len())
            .unwrap()
            .size()
        + first_key;
    let pool = AllocationBudget::new(1 << 20);
    let limit = pool.limit_bytes();
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let blocker = pool
        .try_reserve_bytes(limit - pool.reserved_bytes() - prefix)
        .unwrap();
    let error = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap_err();
    let PreparedSignatureBlockError::PenaltyActions(NposPenaltyActionsCustodyError::Buffer(
        ChargedBufferError::Admission(first),
    )) = error
    else {
        panic!("actual field-5 account backing must retain its original capacity cause: {error:?}")
    };
    let AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    } = &first
    else {
        panic!("actual retained credit must cause Capacity")
    };
    assert!(*requested_bytes > 0);
    assert_eq!((*reserved_bytes, *limit_bytes), (limit, limit));
    assert_eq!(
        pool.try_reserve_bytes(*requested_bytes).err().unwrap(),
        first
    );
    let prefix_pointer = {
        // The outer frame owns its decode scope. A direct child observation
        // outside that scope must reinstall the flags read from this same wire.
        let _flags = DecodeFlagsGuard::enter(flags);
        let pending = decoder.penalty_pending.as_ref().unwrap();
        assert_eq!(
            pending.initialized(&source).unwrap(),
            &actions(&original).as_slice()[..1]
        );
        pending.initialized(&source).unwrap().as_ptr()
    };
    let source_pointer = source.as_slice().as_ptr();
    let source_hash = Hash::new(source.as_slice());
    let repeat = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap_err();
    let PreparedSignatureBlockError::PenaltyActions(NposPenaltyActionsCustodyError::Buffer(
        ChargedBufferError::Admission(repeat),
    )) = repeat
    else {
        panic!("same original field-5 refusal: {repeat:?}")
    };
    assert_eq!(
        repeat, first,
        "field 5 retry must retain the original partial action owner and release cut"
    );
    {
        let _flags = DecodeFlagsGuard::enter(flags);
        assert_eq!(
            decoder
                .penalty_pending
                .as_ref()
                .unwrap()
                .initialized(&source)
                .unwrap()
                .as_ptr(),
            prefix_pointer
        );
    }
    assert_eq!(pool.reserved_bytes(), limit);
    drop(blocker);
    let admitted = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert_eq!(actions(&admitted).as_slice().as_ptr(), prefix_pointer);
    assert_eq!(admitted.encode_wire().unwrap(), wire);
    assert!(actions(&admitted).admitted_to(&pool));
    assert_eq!(source.as_slice().as_ptr(), source_pointer);
    assert_eq!(Hash::new(source.as_slice()), source_hash);
    assert_eq!(pool.limit_bytes(), limit);
    drop(admitted);
    drop(decoder);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn field5_penalty_custody_rejects_changed_source_and_distinct_equal_owner() {
    let original = penalty_fixture();
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (mut source, span) = source_for(&original, &pool);
    let (copy, _) = source_for(&original, &pool);
    let foreign_pool = AllocationBudget::new(1 << 20);
    let (foreign, _) = source_for(&original, &foreign_pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let admitted = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    let mut other = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let distinct = other
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert_eq!(
        admitted.encode_wire().unwrap(),
        distinct.encode_wire().unwrap()
    );
    assert!(actions(&distinct).admitted_to(&pool));
    assert!(
        !decoder
            .retains_npos_penalty_action_custody(&source, &distinct)
            .unwrap()
    );
    assert!(matches!(
        decoder.retained_npos_penalty_actions(&copy),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    assert!(matches!(
        decoder.retained_npos_penalty_actions(&foreign),
        Err(PreparedSignatureBlockError::Source)
    ));
    source.as_mut_slice()[0] ^= 1;
    assert!(matches!(
        decoder.retained_npos_penalty_actions(&source),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    assert!(matches!(
        decoder.decode(&source, span, norito::canonical_decode_limits(wire.len())),
        Err(PreparedSignatureBlockError::SourceChanged)
    ));
    source.as_mut_slice()[0] ^= 1;
    assert!(
        decoder
            .retains_npos_penalty_action_custody(&source, &admitted)
            .unwrap()
    );
    for end in [0, 1, wire.len() - 1] {
        let mut bad = ChargedBuffer::new(end, &pool).unwrap();
        bad.append(&wire[..end]).unwrap();
        let mut fresh = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        assert!(
            fresh
                .decode(
                    &bad,
                    SequenceSpan { start: 0, end },
                    norito::canonical_decode_limits(end)
                )
                .is_err()
        );
    }
    let mut wrong = wire.clone();
    wrong[norito::core::Header::SIZE] ^= 0x80;
    let mut bad = ChargedBuffer::new(wrong.len(), &pool).unwrap();
    bad.append(&wrong).unwrap();
    let mut fresh = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    assert!(
        fresh
            .decode(
                &bad,
                SequenceSpan {
                    start: 0,
                    end: wrong.len()
                },
                norito::canonical_decode_limits(wrong.len())
            )
            .is_err()
    );
    drop((
        bad, fresh, admitted, distinct, decoder, other, copy, source, foreign,
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign_pool.reserved_bytes(), 0);
}
#[test]
fn absent_field5_actions_require_same_source_and_never_claim_retired_custody() {
    let original = fixture(0);
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source_for(&original, &pool);
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    assert!(
        !decoder
            .retains_npos_penalty_action_custody(&source, &original)
            .unwrap()
    );
    let admitted = decoder
        .decode(
            &source,
            span,
            norito::canonical_decode_limits(span.end - span.start),
        )
        .unwrap();
    assert!(
        decoder
            .retains_npos_penalty_action_custody(&source, &admitted)
            .unwrap()
    );
    assert!(
        decoder
            .retained_npos_penalty_actions(&source)
            .unwrap()
            .is_none()
    );
    decoder.clear_consumed();
    assert!(
        !decoder
            .retains_npos_penalty_action_custody(&source, &admitted)
            .unwrap()
    );
}
