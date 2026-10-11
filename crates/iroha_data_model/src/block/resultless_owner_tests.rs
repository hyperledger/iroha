//! Original block custody across consuming resultless-proposal projection.
//!
//! These component fixtures fund the original signature graph with the sole prepared
//! decoder. They establish physical owner/error retention, not consensus authority
//! or funding of every transaction child.

use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use norito::core::{EncodeValueDepthGuard, SequenceSpan};

fn sole_prepared_original() -> (SignedBlock, AllocationBudget) {
    let selected = output_test_support::proposal(1);
    let wire = selected.encode_wire().unwrap();
    let pool = AllocationBudget::new(1024 * 1024);
    let mut source = ChargedBuffer::new(wire.len(), &pool).unwrap();
    source.append(&wire).unwrap();
    let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).unwrap();
    let block = decoder
        .decode(
            &source,
            SequenceSpan {
                start: 0,
                end: wire.len(),
            },
            norito::canonical_decode_limits(wire.len()),
        )
        .unwrap();
    drop(decoder);
    drop(source);
    assert!(block.signatures_admitted_to(&pool));
    assert!(
        pool.reserved_bytes() > 0,
        "the sole block owns real original charges"
    );
    (block, pool)
}

fn install_impossible_suffix(block: &mut SignedBlock) {
    let mut context = BlockExecutionContextBundle::new(Vec::new());
    context.lane_merge = Some(crate::sumeragi_lanes::SumeragiLaneMergeSection {
        merges: Vec::new(),
        time_floor_ms: 0,
        merged_count: 2,
    });
    assert_eq!(block.external_entrypoint_count(), 1);
    block.payload.execution_context = Some(context);
}

/// Real inherited encoder levels, restored in exact reverse acquisition order.
struct EncoderParents(Vec<EncodeValueDepthGuard>);
impl EncoderParents {
    fn full() -> Self {
        Self(
            (0..norito::core::MAX_VALUE_NESTING_DEPTH)
                .map(|_| EncodeValueDepthGuard::enter().unwrap())
                .collect(),
        )
    }
}
impl Drop for EncoderParents {
    fn drop(&mut self) {
        while self.0.pop().is_some() {}
    }
}

#[test]
fn resultless_projection_malformed_suffix_keeps_original_funded_block() {
    let (mut block, pool) = sole_prepared_original();
    let wire = block.encode_wire().unwrap();
    let original_header = block.header();
    let original_entries = block.external_entrypoints_slice().as_ptr();
    let original_signatures = block.signatures.as_slice().as_ptr();
    let original_context = block.payload.execution_context.take();
    install_impossible_suffix(&mut block);
    let retained = pool.reserved_bytes();
    let (mut returned, error) = block.into_resultless_proposal().unwrap_err();
    assert!(
        matches!(&error, NoritoFrameError::Message(reason) if reason == "merged suffix exceeds block entrypoints")
    );
    assert_eq!(returned.header(), original_header);
    assert_eq!(
        returned.external_entrypoints_slice().as_ptr(),
        original_entries
    );
    assert_eq!(returned.signatures.as_slice().as_ptr(), original_signatures);
    assert_eq!(returned.lane_merge().unwrap().merged_count, 2);
    assert!(returned.signatures_admitted_to(&pool));
    assert_eq!(pool.reserved_bytes(), retained);
    // Repair only the deliberately malformed component fixture; no source is recreated.
    returned.payload.execution_context = original_context;
    let retried = returned.into_resultless_proposal().unwrap();
    assert_eq!(
        retried.external_entrypoints_slice().as_ptr(),
        original_entries
    );
    assert_eq!(retried.signatures.as_slice().as_ptr(), original_signatures);
    assert_eq!(retried.encode_wire().unwrap(), wire);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(retried);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn resultless_projection_encoder_refusal_keeps_original_funded_block() {
    let (block, pool) = sole_prepared_original();
    let wire = block.encode_wire().unwrap();
    let original_header = block.header();
    let original_entries = block.external_entrypoints_slice().as_ptr();
    let original_signatures = block.signatures.as_slice().as_ptr();
    let retained = pool.reserved_bytes();
    let parents = EncoderParents::full();
    let (returned, error) = block.into_resultless_proposal().unwrap_err();
    assert!(
        matches!(&error, NoritoFrameError::NestingDepthExceeded { depth, limit, context }
        if *depth == norito::core::MAX_VALUE_NESTING_DEPTH + 1
            && *limit == norito::core::MAX_VALUE_NESTING_DEPTH
            && *context == "encode budget")
    );
    assert_eq!(returned.header(), original_header);
    assert_eq!(
        returned.external_entrypoints_slice().as_ptr(),
        original_entries
    );
    assert_eq!(returned.signatures.as_slice().as_ptr(), original_signatures);
    assert_eq!(pool.reserved_bytes(), retained);
    assert!(returned.signatures_admitted_to(&pool));
    drop(parents);
    let retried = returned.into_resultless_proposal().unwrap();
    assert_eq!(
        retried.external_entrypoints_slice().as_ptr(),
        original_entries
    );
    assert_eq!(retried.signatures.as_slice().as_ptr(), original_signatures);
    assert_eq!(retried.encode_wire().unwrap(), wire);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(retried);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn resultless_projection_moves_merged_prefix_without_detaching_original_children() {
    let (mut block, pool) = sole_prepared_original();
    let own_hash = block.external_entrypoints_slice()[0].hash();
    let mut context = BlockExecutionContextBundle::new(vec![ExternalExecutionContext::new(
        own_hash,
        iroha_model_base::topology::LaneId::new(0),
        iroha_model_base::topology::DataSpaceId::new(0),
    )]);
    context.lane_merge = Some(crate::sumeragi_lanes::SumeragiLaneMergeSection {
        merges: Vec::new(),
        time_floor_ms: 0,
        merged_count: 0,
    });
    block.set_execution_context(Some(context));
    let original_wire = block.encode_wire().unwrap();
    let mut merged_source = output_test_support::proposal(2);
    let merged = merged_source.payload.external_entrypoints.pop().unwrap();
    assert_ne!(merged.hash(), own_hash);
    let merged_context = ExternalExecutionContext::new(
        merged.hash(),
        iroha_model_base::topology::LaneId::new(1),
        iroha_model_base::topology::DataSpaceId::new(7),
    );
    let expanded = block
        .with_merged_entrypoints(vec![merged], vec![merged_context])
        .unwrap();
    let original_entries = expanded.external_entrypoints_slice().as_ptr();
    let original_contexts = expanded.execution_context().unwrap().external.as_ptr();
    let original_signatures = expanded.signatures.as_slice().as_ptr();
    let retained = pool.reserved_bytes();
    let restored = expanded.into_resultless_proposal().unwrap();
    assert_eq!(restored.external_entrypoint_count(), 1);
    assert_eq!(restored.merged_entrypoint_count(), 0);
    assert_eq!(
        restored.external_entrypoints_slice().as_ptr(),
        original_entries
    );
    assert_eq!(
        restored.execution_context().unwrap().external.as_ptr(),
        original_contexts
    );
    assert_eq!(restored.signatures.as_slice().as_ptr(), original_signatures);
    assert!(restored.signatures_admitted_to(&pool));
    assert_eq!(restored.encode_wire().unwrap(), original_wire);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(restored);
    assert_eq!(pool.reserved_bytes(), 0);
}
