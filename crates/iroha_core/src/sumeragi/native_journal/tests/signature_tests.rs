//! Actual ordered signature allocations/refusal and unchanged native finality over prepared owners.
use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{Signature, SignatureOf};
use iroha_data_model::block::{
    BlockSignature, BlockSignatureCustodyError, BlockSignatures, PreparedBlockSignatures,
    PreparedSignedBlockSignaturesDecode,
};
use norito::{
    SerializePayload,
    core::{DecodeFlagsGuard, Encoder, PreparedDecodeWorkspace, SequenceSpan},
};
use std::alloc::Layout;
fn signature(index: u64, width: usize) -> BlockSignature {
    BlockSignature::new(
        index,
        SignatureOf::from_signature(
            Signature::try_from_bytes(&vec![index as u8 + 1; width]).unwrap(),
        ),
    )
}
fn source_for(
    values: &BlockSignatures,
    pool: &AllocationBudget,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let _flags = DecodeFlagsGuard::enter(0);
    let mut wire = Vec::new();
    values
        .serialize(&mut Encoder::for_buffer(&mut wire))
        .unwrap();
    let mut source = ChargedBuffer::new(wire.len() + 8, pool).unwrap();
    source.append(&[0xe1; 8]).unwrap();
    source.append(&wire).unwrap();
    (
        source,
        SequenceSpan {
            start: 8,
            end: 8 + wire.len(),
        },
    )
}
fn plan(
    source: &ChargedBuffer<u8>,
    span: SequenceSpan,
    pool: &AllocationBudget,
) -> PreparedBlockSignatures {
    let _flags = DecodeFlagsGuard::enter(0);
    PreparedBlockSignatures::from_source(source, span, pool).unwrap()
}
#[test]
fn retained_ordered_signatures_have_exact_actual_backing_for_all_supported_committee_extremes() {
    for count in [0, 4, 31] {
        let pool = AllocationBudget::new(1024 * 1024);
        let original =
            BlockSignatures::try_from_iter((0..count).map(|index| signature(index as u64, 64)))
                .unwrap();
        let (source, span) = source_for(&original, &pool);
        let mut reservation = pool
            .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
            .unwrap();
        let mut workspace =
            PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
        drop(reservation);
        let floor = pool.reserved_bytes();
        let mut result = None;
        let allocations = allocations_during(|| {
            result = Some(workspace.with_limits(
                limits().decode_limits().unwrap(),
                limits().decode_limits().unwrap(),
                || plan(&source, span, &pool),
            ))
        });
        assert_eq!(allocations, 0);
        let mut prepared = result.unwrap().unwrap();
        assert_eq!(pool.reserved_bytes(), floor);
        let mut result = None;
        let allocations = allocations_during(|| result = Some(prepared.prepare(&source)));
        result.unwrap().unwrap();
        assert_eq!(allocations, if count == 0 { 0 } else { count + 2 });
        let backing: usize = BlockSignatures::backing_layouts(count)
            .unwrap()
            .iter()
            .map(Layout::size)
            .sum();
        assert_eq!(pool.reserved_bytes(), floor + backing + 64 * count);
        let pointers = prepared
            .initialized(&source)
            .unwrap()
            .iter()
            .map(|sig| sig.signature().payload().as_ptr())
            .collect::<Vec<_>>();
        let mut result = None;
        assert_eq!(
            allocations_during(|| result = Some(prepared.finish(&source))),
            1
        );
        let owner = result
            .unwrap()
            .unwrap_or_else(|(_, error)| panic!("{error}"));
        assert!(owner.admitted_to(&pool));
        assert_eq!(owner, original);
        let mut wire = Vec::with_capacity(span.end - span.start);
        let _flags = DecodeFlagsGuard::enter(0);
        let mut serialized = None;
        assert_eq!(
            allocations_during(
                || serialized = Some(owner.serialize(&mut Encoder::for_buffer(&mut wire)))
            ),
            0
        );
        serialized.unwrap().unwrap();
        assert_eq!(wire, span.get(source.as_slice()).unwrap());
        let mut shared = None;
        assert_eq!(allocations_during(|| shared = Some(owner.clone())), 0);
        let shared = shared.unwrap();
        drop(owner);
        assert_eq!(
            shared
                .iter()
                .map(|sig| sig.signature().payload().as_ptr())
                .collect::<Vec<_>>(),
            pointers
        );
        assert_eq!(
            pool.reserved_bytes(),
            floor + backing + 64 * count + BlockSignatures::allocation_layout().size()
        );
        drop(shared);
        assert_eq!(pool.reserved_bytes(), floor);
    }
}
#[test]
fn retained_signature_actual_byte_and_control_allocator_refusal_preserves_original_prefix() {
    let pool = AllocationBudget::new(65536);
    let original = BlockSignatures::try_from_iter([signature(0, 37), signature(1, 43)])
        .expect("at most 31 block signatures");
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let mut prepared = plan(&source, span, &pool);
    let (result, refused) = refuse_one_layout_during(Layout::array::<u8>(43).unwrap(), || {
        prepared.prepare(&source)
    });
    assert!(refused);
    assert!(matches!(
        result,
        Err(BlockSignatureCustodyError::Buffer(
            ChargedBufferError::Allocator {
                requested_bytes: 43
            }
        ))
    ));
    assert_eq!(prepared.initialized(&source).unwrap().len(), 1);
    let pointer = prepared.initialized(&source).unwrap()[0]
        .signature()
        .payload()
        .as_ptr();
    let backing: usize = BlockSignatures::backing_layouts(2)
        .unwrap()
        .iter()
        .map(Layout::size)
        .sum();
    assert_eq!(pool.reserved_bytes(), floor + backing + 37);
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(prepared.prepare(&source))),
        1
    );
    result.unwrap().unwrap();
    let (result, refused) = refuse_one_layout_during(BlockSignatures::allocation_layout(), || {
        prepared.finish(&source)
    });
    assert!(refused);
    let (prepared, error) = match result {
        Ok(_) => panic!("actual control refusal"),
        Err(value) => value,
    };
    assert!(matches!(
        error,
        BlockSignatureCustodyError::ControlAllocation(_)
    ));
    assert_eq!(
        prepared.initialized(&source).unwrap()[0]
            .signature()
            .payload()
            .as_ptr(),
        pointer
    );
    assert_eq!(pool.reserved_bytes(), floor + backing + 80);
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(prepared.finish(&source))),
        1
    );
    let owner = result
        .unwrap()
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert_eq!(owner.as_slice()[0].signature().payload().as_ptr(), pointer);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), floor);
}
#[test]
fn original_prepared_signature_graphs_keep_genesis_and_successor_native_finality_unchanged() {
    let (chain, journal) = fixture();
    // Prepared signature graphs belong to this original offline-reader pool;
    // unrelated chain fixture epoch reclamation cannot count as their refunds.
    let pool = AllocationBudget::new(limits().allocated_bytes);
    let original_blocks = [
        chain.committed(1).block().clone(),
        chain.committed(2).block().clone(),
        chain.committed(3).block().clone(),
    ];
    let floor = pool.reserved_bytes();
    let mut frames = Vec::new();
    for artifact in &journal.blocks {
        let mut source = ChargedBuffer::new(artifact.block_wire.len(), &pool).unwrap();
        source.append(&artifact.block_wire).unwrap();
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
        let block = decoder
            .decode(
                &source,
                SequenceSpan {
                    start: 0,
                    end: source.as_slice().len(),
                },
                limits().decode_limits().unwrap(),
            )
            .unwrap();
        assert!(block.signatures_admitted_to(&pool));
        assert_eq!(block.encode_wire().unwrap(), artifact.block_wire);
        frames.push(SharedSignedBlock::reserve(&pool).unwrap().initialize(block));
    }
    let pointers = frames
        .iter()
        .flat_map(|block| {
            block
                .signatures()
                .map(|sig| sig.signature().payload().as_ptr())
        })
        .collect::<Vec<_>>();
    let hashes = frames.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let network = chain.network_id();
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let reader = CertifiedChain::from_frames(&chain_id, &network, &hashes, &frames).unwrap();
    assert_eq!(
        reader.certified(1).unwrap().verification(),
        QcVerification::Genesis
    );
    assert_eq!(
        reader.certified(3).unwrap().verification(),
        QcVerification::Verified
    );
    let retained = frames.iter().map(Clone::clone).collect::<Vec<_>>();
    drop(reader);
    drop(frames);
    assert_eq!(
        retained
            .iter()
            .flat_map(|block| block
                .signatures()
                .map(|sig| sig.signature().payload().as_ptr()))
            .collect::<Vec<_>>(),
        pointers
    );
    for (prepared, original) in retained.iter().zip(&original_blocks) {
        assert_eq!(prepared.hash(), original.hash());
        assert!(prepared.signatures_admitted_to(&pool));
    }
    drop(retained);
    assert_eq!(pool.reserved_bytes(), floor);
}

#[test]
fn actual_typed_signature_and_ledger_allocator_refusals_keep_prior_original_backings() {
    let pool = AllocationBudget::new(65536);
    let original = BlockSignatures::try_from_iter([signature(0, 37), signature(1, 43)])
        .expect("at most 31 block signatures");
    let (source, span) = source_for(&original, &pool);
    let floor = pool.reserved_bytes();
    let layouts = BlockSignatures::backing_layouts(2).unwrap();
    for (index, layout) in layouts.into_iter().enumerate() {
        let mut prepared = plan(&source, span, &pool);
        let original_values_pointer = if index == 1 {
            // Typed collection and charge-ledger layouts can coincide (both
            // 48 bytes on this host). Refusal by layout alone would hit the
            // first typed allocation again. Reach the ledger through a real
            // capacity refusal while preserving the original typed backing.
            let blocker = pool
                .try_reserve_bytes(pool.limit_bytes() - floor - layouts[0].size())
                .unwrap();
            assert!(matches!(
                prepared.prepare(&source),
                Err(BlockSignatureCustodyError::Buffer(ChargedBufferError::Admission(
                    AllocationRefusal::Capacity { requested_bytes, .. }
                ))) if requested_bytes == layouts[1].size()
            ));
            assert!(prepared.initialized(&source).unwrap().is_empty());
            let pointer = prepared.initialized(&source).unwrap().as_ptr();
            drop(blocker);
            assert_eq!(pool.reserved_bytes(), floor + layouts[0].size());
            Some(pointer)
        } else {
            None
        };
        let (result, refused) = refuse_one_layout_during(layout, || prepared.prepare(&source));
        assert!(refused);
        assert!(
            matches!(result, Err(BlockSignatureCustodyError::Buffer(ChargedBufferError::Allocator { requested_bytes })) if requested_bytes == layout.size())
        );
        assert!(prepared.initialized(&source).unwrap().is_empty());
        if let Some(pointer) = original_values_pointer {
            assert_eq!(
                prepared.initialized(&source).unwrap().as_ptr(),
                pointer,
                "allocator refusal retains the exact already funded typed backing"
            );
        }
        assert_eq!(
            pool.reserved_bytes(),
            floor + if index == 0 { 0 } else { layouts[0].size() }
        );
        let mut result = None;
        assert_eq!(
            allocations_during(|| result = Some(prepared.prepare(&source))),
            4 - index
        );
        result.unwrap().unwrap();
        let owner = prepared
            .finish(&source)
            .unwrap_or_else(|(_, error)| panic!("{error}"));
        assert!(owner.admitted_to(&pool));
        assert_eq!(owner, original);
        if let Some(pointer) = original_values_pointer {
            assert_eq!(
                owner.as_slice().as_ptr(),
                pointer,
                "successful retry and immutable publication move the same original typed backing"
            );
        }
        drop(owner);
        assert_eq!(pool.reserved_bytes(), floor);
    }
}
