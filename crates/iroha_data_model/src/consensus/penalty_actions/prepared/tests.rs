//! Canonical sequence parity, exact original source and retained partial graph controls.

use super::*;
use crate::account::{MultisigMember, MultisigPolicy};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_schema::{IntoSchema, MetaMap, TypeId};
use norito::{
    SerializePayload,
    core::{DecodeFlagsGuard, Encoder, header_flags},
};

fn key(seed: u8) -> PublicKey {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
        .public_key()
        .clone()
}
fn fixture() -> NposPenaltyActions {
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(key(8), 1).unwrap(),
                MultisigMember::new(key(9), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    let slash = |validator| {
        NposPenaltyAction::ConsensusSlash(NposConsensusSlashAction {
            evidence_key: Hash::new([1]),
            signer: 2,
            peer_id: PeerId::new(key(7)),
            lane_id: LaneId::new(3),
            validator,
            slash_id: Hash::new([2]),
            amount: "123456789012345678901234567890.123".parse().unwrap(),
        })
    };
    NposPenaltyActions::from_untrusted(vec![
        NposPenaltyAction::MarkConsensusEvidenceApplied(NposMarkConsensusEvidenceAppliedAction {
            evidence_key: Hash::new([3]),
            height: 17,
        }),
        slash(multisig),
        slash(AccountId::new(key(10))),
    ])
}
fn bytes(value: &impl SerializePayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut bytes))
        .unwrap();
    bytes
}
fn source(
    value: &NposPenaltyActions,
    pool: &AllocationBudget,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let bytes = bytes(value);
    let mut input = ChargedBuffer::new(bytes.len() + 9, pool).unwrap();
    input.append(&[0xa5; 9]).unwrap();
    input.append(&bytes).unwrap();
    (
        input,
        SequenceSpan {
            start: 9,
            end: 9 + bytes.len(),
        },
    )
}
fn admit(pending: PreparedNposPenaltyActions, input: &ChargedBuffer<u8>) -> NposPenaltyActions {
    pending
        .finish(input)
        .unwrap_or_else(|(_, e)| panic!("complete original action graph: {e}"))
}

#[test]
fn penalty_action_owner_preserves_sole_wire_schema_json_and_original_shared_graph() {
    use crate::consensus::NposConsensusEffects;
    #[derive(norito::Encode)]
    struct SoleEffectsWire {
        parent_service_commit_qc: Option<Vec<u8>>,
        evidence_admissions: Vec<crate::block::consensus::Evidence>,
        penalty_actions: Vec<NposPenaltyAction>,
    }
    for flags in [0, header_flags::COMPACT_LEN] {
        for original in [NposPenaltyActions::default(), fixture()] {
            // Whole-block wire encoding resets decode state. Each bare-payload
            // case must install its own explicitly selected layout again.
            let _flags = DecodeFlagsGuard::enter(flags);
            let independent = original.as_slice().to_vec();
            assert_eq!(bytes(&original), bytes(&independent));
            let payload = bytes(&original);
            let (decoded, used) = NposPenaltyActions::decode_from_slice(&payload).unwrap();
            assert_eq!(used, payload.len());
            assert_eq!(decoded, original);
            assert_eq!(bytes(&decoded), payload);
            assert_eq!(
                <NposPenaltyActions as TypeId>::id(),
                <Vec<NposPenaltyAction> as TypeId>::id()
            );
            assert_eq!(
                <NposPenaltyActions as IntoSchema>::type_name(),
                <Vec<NposPenaltyAction> as IntoSchema>::type_name()
            );
            let mut schema = MetaMap::new();
            NposPenaltyActions::update_schema_map(&mut schema);
            Vec::<NposPenaltyAction>::update_schema_map(&mut schema);
            assert_eq!(
                schema.get::<NposPenaltyActions>(),
                schema.get::<Vec<NposPenaltyAction>>()
            );
            assert!(schema.get::<NposPenaltyAction>().is_some());
            let pool = AllocationBudget::new(1 << 20);
            let (input, span) = source(&original, &pool);
            let floor = pool.reserved_bytes();
            let mut pending = PreparedNposPenaltyActions::from_source(&input, span, &pool).unwrap();
            pending.prepare(&input).unwrap();
            assert_eq!(pending.initialized(&input).unwrap(), original.as_slice());
            let admitted = admit(pending, &input);
            assert_eq!(admitted, original);
            assert!(admitted.admitted_to(&pool));
            assert!(!original.admitted_to(&pool));
            let json = norito::json::to_json(&original).unwrap();
            assert_eq!(norito::json::to_json(&admitted).unwrap(), json);
            assert_eq!(
                norito::json::from_json::<NposPenaltyActions>(&json).unwrap(),
                original
            );
            assert_eq!(json, norito::json::to_json(&independent).unwrap());
            assert_eq!(
                norito::json::to_json_bounded(&admitted, json.len()).unwrap(),
                json
            );
            assert_eq!(
                norito::json::to_json_bounded(&admitted, json.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
            let json_value = norito::json::to_value(&admitted).unwrap();
            assert_eq!(
                <NposPenaltyActions as norito::json::JsonDeserialize>::json_from_value(&json_value)
                    .unwrap(),
                original
            );
            let payload = bytes(&admitted);
            let (decoded, used) = NposPenaltyActions::decode_from_slice(&payload).unwrap();
            assert_eq!(used, payload.len());
            assert_eq!(decoded, original);
            let before = pool.reserved_bytes();
            let pointer = admitted.as_slice().as_ptr();
            let shared = admitted.clone();
            assert!(
                NposPenaltyActions::ptr_eq(&admitted, &shared),
                "admitted penalty action clone must retain the original graph"
            );
            assert_eq!(shared.as_slice().as_ptr(), pointer);
            assert_eq!(pool.reserved_bytes(), before);
            let effects = NposConsensusEffects {
                parent_service_commit_qc: Some(
                    crate::consensus::NposParentServiceCommitQc::from_untrusted(vec![1, 2, 3]),
                ),
                evidence_admissions: vec![],
                penalty_actions: shared,
            };
            let wire = SoleEffectsWire {
                parent_service_commit_qc: Some(vec![1, 2, 3]),
                evidence_admissions: vec![],
                penalty_actions: independent,
            };
            assert_eq!(bytes(&effects), bytes(&wire));
            // The actual public wire remains SignedBlockWire; these children have no
            // separate root-frame contract. Compare admitted and ordinary transport.
            use crate::block::{BlockHeader, BlockSignature, SignedBlock};
            use iroha_crypto::{Signature, SignatureOf};
            let mut block = SignedBlock::presigned(
                BlockSignature::new(
                    0,
                    SignatureOf::from_signature(Signature::try_from_bytes(&[1; 64]).unwrap()),
                ),
                BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, 1_000, 0),
                Vec::new(),
            );
            block.set_npos_consensus_effects(Some(effects.clone()));
            let framed = block.encode_wire().unwrap();
            let decoded_block = crate::block::decode_framed_signed_block(&framed).unwrap();
            assert_eq!(decoded_block, block);
            assert_eq!(decoded_block.encode_wire().unwrap(), framed);
            let mut ordinary = block.clone();
            ordinary.set_npos_consensus_effects(Some(NposConsensusEffects {
                parent_service_commit_qc: wire
                    .parent_service_commit_qc
                    .map(crate::consensus::NposParentServiceCommitQc::from_untrusted),
                evidence_admissions: wire.evidence_admissions,
                penalty_actions: NposPenaltyActions::from_untrusted(wire.penalty_actions),
            }));
            assert_eq!(ordinary.encode_wire().unwrap(), framed);
            drop((ordinary, block, decoded_block));
            let effect_clone = effects.clone();
            assert!(NposPenaltyActions::ptr_eq(
                &effects.penalty_actions,
                &effect_clone.penalty_actions
            ));
            drop(effects);
            drop(admitted);
            assert!(effect_clone.penalty_actions.admitted_to(&pool));
            assert_eq!(pool.reserved_bytes(), before);
            drop(effect_clone);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(input);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
#[test]
fn penalty_action_original_partial_refusal_retains_exact_prefix_pool_and_retry() {
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (input, span) = source(&original, &pool);
    let floor = pool.reserved_bytes();
    let address = input.as_slice().as_ptr();
    let hash = Hash::new(input.as_slice());
    let mut pending = PreparedNposPenaltyActions::from_source(&input, span, &pool).unwrap();
    let NposPenaltyAction::ConsensusSlash(slash) = &original.as_slice()[1] else {
        panic!("original slash fixture")
    };
    let first_key_bytes = slash
        .peer_id
        .public_key()
        .retained_allocation_layout()
        .size();
    let prefix = pending
        .backing_layouts()
        .unwrap()
        .iter()
        .map(Layout::size)
        .sum::<usize>()
        + Layout::array::<SequenceSpan>(original.len())
            .unwrap()
            .size()
        + first_key_bytes;
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - floor - prefix)
        .unwrap();
    let error = pending.prepare(&input).unwrap_err();
    let Error::Buffer(ChargedBufferError::Admission(first)) = error else {
        panic!("actual original account backing must refuse: {error:?}")
    };
    assert!(
        matches!(&first,AllocationRefusal::Capacity{requested_bytes,reserved_bytes,limit_bytes,..} if *requested_bytes>0&&*reserved_bytes==pool.limit_bytes()&&*limit_bytes==pool.limit_bytes())
    );
    assert_eq!(
        pending.initialized(&input).unwrap(),
        &original.as_slice()[..1]
    );
    assert!(pending.current.peer.is_some());
    assert!(pending.current.account.complete.is_none());
    assert!(pending.current.quantity.is_none());
    let values = pending.values.as_ref().unwrap().as_slice().as_ptr();
    let custody = pending.custody.as_ref().unwrap().as_slice().as_ptr();
    let key = pending
        .current
        .peer
        .as_ref()
        .unwrap()
        .get()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let repeat = pending.prepare(&input).unwrap_err();
    let Error::Buffer(ChargedBufferError::Admission(repeat)) = repeat else {
        panic!("same original account backing must refuse: {repeat:?}")
    };
    assert_eq!(
        repeat, first,
        "partial penalty retry must retain exact original refusal and release cut"
    );
    assert_eq!(
        pending
            .current
            .peer
            .as_ref()
            .unwrap()
            .get()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        key
    );
    assert_eq!(pending.values.as_ref().unwrap().as_slice().as_ptr(), values);
    assert_eq!(
        pending.custody.as_ref().unwrap().as_slice().as_ptr(),
        custody
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    assert!(pending.belongs_to(&pool));
    assert_eq!(input.as_slice().as_ptr(), address);
    assert_eq!(Hash::new(input.as_slice()), hash);
    drop(blocker);
    let retained = pool.reserved_bytes();
    assert_eq!(retained, floor + prefix);
    pending.prepare(&input).unwrap();
    assert_eq!(pending.initialized(&input).unwrap(), original.as_slice());
    let complete = admit(pending, &input);
    assert_eq!(complete, original);
    assert!(complete.admitted_to(&pool));
    let NposPenaltyAction::ConsensusSlash(slash) = &complete.as_slice()[1] else {
        panic!("same original slash")
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
    drop(complete);
    assert_eq!(pool.reserved_bytes(), floor);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn penalty_action_source_binds_full_original_frame_pool_and_layout() {
    let _flags = DecodeFlagsGuard::enter(0);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (mut input, span) = source(&original, &pool);
    let mut pending = PreparedNposPenaltyActions::from_source(&input, span, &pool).unwrap();
    pending.prepare(&input).unwrap();
    let held = pool.reserved_bytes();
    let values = pending.initialized(&input).unwrap().as_ptr();
    input.as_mut_slice()[0] ^= 1;
    assert!(
        matches!(pending.prepare(&input), Err(Error::SourceChanged)),
        "penalty action custody must bind the full original source"
    );
    assert_eq!(pool.reserved_bytes(), held);
    input.as_mut_slice()[0] ^= 1;
    assert_eq!(pending.initialized(&input).unwrap().as_ptr(), values);
    let (substitute, _) = source(&original, &pool);
    assert!(matches!(
        pending.prepare(&substitute),
        Err(Error::SourceChanged)
    ));
    let foreign = AllocationBudget::new(1 << 20);
    let (foreign_input, _) = source(&original, &foreign);
    assert!(matches!(
        pending.prepare(&foreign_input),
        Err(Error::ForeignPool)
    ));
    {
        let _changed = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
        assert!(matches!(pending.prepare(&input), Err(Error::LayoutChanged)));
    }
    let complete = admit(pending, &input);
    assert_eq!(complete, original);
    drop(complete);
    drop(substitute);
    drop(input);
    drop(foreign_input);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}
#[test]
fn penalty_action_control_refusal_retains_complete_graph_and_rejects_truncated_source() {
    let _flags = DecodeFlagsGuard::enter(0);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (input, span) = source(&original, &pool);
    let floor = pool.reserved_bytes();
    let mut pending = PreparedNposPenaltyActions::from_source(&input, span, &pool).unwrap();
    pending.prepare(&input).unwrap();
    let pointer = pending.initialized(&input).unwrap().as_ptr();
    let held = pool.reserved_bytes();
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - held).unwrap();
    let (pending, error) = pending
        .finish(&input)
        .err()
        .expect("occupied original shell capacity");
    assert!(
        matches!(error,Error::ControlAdmission(AllocationRefusal::Capacity{requested_bytes,..}) if requested_bytes==NposPenaltyActions::allocation_layout().size())
    );
    assert_eq!(pending.initialized(&input).unwrap().as_ptr(), pointer);
    drop(blocker);
    let complete = admit(pending, &input);
    assert_eq!(complete.as_slice().as_ptr(), pointer);
    drop(complete);
    assert_eq!(pool.reserved_bytes(), floor);
    let wire = bytes(&original);
    for end in 0..wire.len() {
        let mut short = ChargedBuffer::new(end, &pool).unwrap();
        short.append(&wire[..end]).unwrap();
        if let Ok(mut pending) =
            PreparedNposPenaltyActions::from_source(&short, SequenceSpan { start: 0, end }, &pool)
        {
            assert!(pending.prepare(&short).is_err());
        }
        drop(short);
        assert_eq!(pool.reserved_bytes(), floor);
    }
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn penalty_action_json_write_refusal_balances_its_container_and_retains_original_owner() {
    use norito::json::{BoundedJsonError, JsonSerialize, JsonWriteSink};
    struct RefusingSink {
        depth: usize,
    }
    impl JsonWriteSink for RefusingSink {
        fn push(&mut self, _: char) -> Result<(), BoundedJsonError> {
            Err(BoundedJsonError::BodyTooLarge)
        }
        fn push_str(&mut self, _: &str) -> Result<(), BoundedJsonError> {
            Err(BoundedJsonError::BodyTooLarge)
        }
        fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
            self.depth += 1;
            Ok(())
        }
        fn end_container(&mut self) {
            self.depth -= 1;
        }
    }
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    for original in [NposPenaltyActions::default(), fixture()] {
        let pool = AllocationBudget::new(1 << 20);
        let (input, span) = source(&original, &pool);
        let mut pending = PreparedNposPenaltyActions::from_source(&input, span, &pool).unwrap();
        pending.prepare(&input).unwrap();
        let admitted = admit(pending, &input);
        let retained = admitted.clone();
        let occupied = pool.reserved_bytes();
        let mut sink = RefusingSink { depth: 0 };
        assert_eq!(
            admitted.json_serialize_to(&mut sink),
            Err(BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(sink.depth, 0);
        assert!(NposPenaltyActions::ptr_eq(&admitted, &retained));
        assert!(admitted.admitted_to(&pool));
        assert_eq!(pool.reserved_bytes(), occupied);
        assert_eq!(
            norito::json::to_json(&admitted).unwrap(),
            norito::json::to_json(&original).unwrap()
        );
        drop((retained, admitted, input));
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
