//! Real enclosing field-5 parent-QC custody, later sibling refusal and source-bound retry.
use super::*;
use iroha_allocation::AllocationRefusal;
fn parent_fixture(parent: Option<Vec<u8>>) -> SignedBlock {
    let mut block = fixture(0);
    block.payload.npos_consensus_effects = Some(NposConsensusEffects {
        parent_service_commit_qc: parent.map(NposParentServiceCommitQc::from_untrusted),
        ..Default::default()
    });
    block
}
#[test]
fn field5_parent_service_preserves_absence_empty_bytes_wire_and_original_control() {
    for parent in [None, Some(Vec::new()), Some(vec![0x11; 31])] {
        let original = parent_fixture(parent.clone());
        let wire = original.encode_wire().unwrap();
        let pool = AllocationBudget::new(1 << 20);
        let (source, span) = source_for(&original, &pool);
        let floor = pool.reserved_bytes();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        assert!(
            !decoder
                .retains_parent_service_custody(&source, &original)
                .unwrap()
        );
        let admitted = decoder
            .decode(&source, span, norito::canonical_decode_limits(wire.len()))
            .unwrap();
        assert_eq!(admitted, original);
        assert_eq!(admitted.encode_wire().unwrap(), wire);
        assert!(
            decoder
                .retains_parent_service_custody(&source, &admitted)
                .unwrap()
        );
        let clone = admitted.clone();
        if let Some(original) = decoder.retained_parent_service(&source).unwrap() {
            let offered = clone
                .npos_consensus_effects()
                .unwrap()
                .parent_service_commit_qc
                .as_ref()
                .unwrap();
            assert!(original.admitted_to(&pool));
            assert!(NposParentServiceCommitQc::ptr_eq(original, offered));
        } else {
            assert!(parent.is_none());
        }
        decoder.clear_consumed();
        assert!(
            !decoder
                .retains_parent_service_custody(&source, &clone)
                .unwrap()
        );
        drop((decoder, admitted, clone));
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn field5_parent_service_survives_later_action_refusal_with_exact_original_cut_and_retry() {
    let original = parent_fixture(Some(vec![0x11; 31]));
    let wire = original.encode_wire().unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let prefix = BlockSignatures::allocation_layout().size()
        + 31
        + NposParentServiceCommitQc::allocation_layout().size();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - prefix)
        .unwrap();
    let Err(PreparedSignatureBlockError::PenaltyActions(
        NposPenaltyActionsCustodyError::ControlAdmission(first),
    )) = decoder.decode(&source, span, norito::canonical_decode_limits(wire.len()))
    else {
        panic!("later original empty-action control must refuse")
    };
    assert!(
        matches!(&first, AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. } if *requested_bytes==NposPenaltyActions::allocation_layout().size() && *reserved_bytes==pool.limit_bytes() && *limit_bytes==pool.limit_bytes())
    );
    let parent = decoder.retained_parent_service(&source).unwrap().unwrap();
    let pointer = parent.as_slice().as_ptr();
    assert_eq!(parent.as_slice(), &[0x11; 31]);
    assert!(parent.admitted_to(&pool));
    let Err(PreparedSignatureBlockError::PenaltyActions(
        NposPenaltyActionsCustodyError::ControlAdmission(repeat),
    )) = decoder.decode(&source, span, norito::canonical_decode_limits(wire.len()))
    else {
        panic!("same later action refusal")
    };
    assert_eq!(
        repeat, first,
        "outer retry must retain parent-QC custody and original release cut"
    );
    assert_eq!(
        decoder
            .retained_parent_service(&source)
            .unwrap()
            .unwrap()
            .as_slice()
            .as_ptr(),
        pointer
    );
    let retained = decoder
        .retained_parent_service(&source)
        .unwrap()
        .unwrap()
        .clone();
    drop(blocker);
    let admitted = decoder
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert_eq!(admitted.encode_wire().unwrap(), wire);
    let offered = admitted
        .npos_consensus_effects()
        .unwrap()
        .parent_service_commit_qc
        .as_ref()
        .unwrap();
    assert_eq!(offered.as_slice().as_ptr(), pointer);
    assert!(NposParentServiceCommitQc::ptr_eq(&retained, offered));
    let mut second = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let different = second
        .decode(&source, span, norito::canonical_decode_limits(wire.len()))
        .unwrap();
    assert_eq!(different.encode_wire().unwrap(), wire);
    assert!(
        !decoder
            .retains_parent_service_custody(&source, &different)
            .unwrap()
    );
    drop((retained, admitted, different, decoder, second));
    assert_eq!(pool.reserved_bytes(), floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
