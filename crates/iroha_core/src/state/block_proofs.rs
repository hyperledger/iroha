//! Bounded proof serving from one WSV-selected, exact finalized block body.

use std::{num::NonZeroU64, num::NonZeroUsize};

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    block::{
        BlockHeader,
        proofs::{
            AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1, BlockProofs, BlockReceiptProof,
            ExecutionReceiptProof,
        },
    },
    query::error::QueryExecutionFail,
    transaction::TransactionEntrypoint,
};

use super::BlockProofError;
use crate::{
    kura::Kura,
    smartcontracts::isi::query::{BorrowedSingularStruct, bounded_bare_encoded_len},
    sumeragi::certified_chain::{
        NativeExecutionReadError, NativeExecutionReadLimits, NativeExecutionReadResource,
        read_authenticated_execution,
    },
};

/// Finite per-request admission for finalized block and Network proof serving.
///
/// Wire bytes are admitted before body I/O. Source, output, and transcript rows
/// are admitted before structural validation and tree construction. The complete
/// response is measured before cloning selected output/transcript values.
/// These ceilings do not reserve the Norito decoder's complete resident graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockProofLimits {
    /// Maximum source heights authenticated from genesis, including H2 for a genesis request.
    pub max_source_blocks: u64,
    /// Aggregate bytes of the native source prefix, admitted before each frame read.
    pub max_source_wire_bytes: u64,
    /// Maximum exact executed block wire bytes, also capped by the proof protocol.
    pub max_block_wire_bytes: u64,
    /// Maximum aggregate source, output, transcript-owner and transcript rows.
    pub max_work_items: u64,
    /// Maximum complete canonical Norito proof frame or exact executed wire response.
    pub max_response_bytes: u64,
}

/// Resource refused by finalized proof serving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockProofResource {
    /// Native source heights, before source body reads or cryptographic verification.
    SourceBlocks,
    /// Aggregate native source frame bytes, before the corresponding body read.
    SourceWireBytes,
    /// QC-authenticated body bytes, refused before reading the body.
    BlockWireBytes,
    /// Source/output/transcript rows, refused before validating or constructing trees.
    WorkItems,
    /// Complete response bytes, refused before copying its large owned values.
    ResponseBytes,
}

impl BlockProofLimits {
    fn limit(self, resource: BlockProofResource) -> u64 {
        match resource {
            BlockProofResource::SourceBlocks => self.max_source_blocks,
            BlockProofResource::SourceWireBytes => self.max_source_wire_bytes,
            BlockProofResource::BlockWireBytes => self
                .max_block_wire_bytes
                .min(AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1 as u64),
            BlockProofResource::WorkItems => self.max_work_items,
            BlockProofResource::ResponseBytes => self.max_response_bytes,
        }
    }

    fn admit(
        self,
        block_height: NonZeroU64,
        resource: BlockProofResource,
        actual: u64,
    ) -> Result<(), BlockProofError> {
        let limit = self.limit(resource);
        if actual > limit {
            return Err(BlockProofError::CapacityExceeded {
                block_height,
                resource,
                actual,
                limit,
            });
        }
        Ok(())
    }
}

fn invalid_outputs(block_height: NonZeroU64, reason: impl ToString) -> BlockProofError {
    BlockProofError::InvalidOutputs {
        block_height,
        reason: reason.to_string(),
    }
}

/// Independently configured chain identity and original immutable hash journal cut.
#[derive(Clone, Copy)]
pub(super) struct NativeProofSource<'a> {
    pub(super) kura: &'a Kura,
    pub(super) chain_id: &'a iroha_model_base::chain::ChainId,
    pub(super) network: iroha_data_model::NetworkId,
    pub(super) hashes: &'a dyn super::BlockHashRead,
    pub(super) budget: &'a iroha_allocation::AllocationBudget,
}

fn read_finalized_body(
    source: NativeProofSource<'_>,
    block_height: NonZeroU64,
    expected_hash: HashOf<BlockHeader>,
    limits: BlockProofLimits,
    wire_response: bool,
) -> Result<
    (
        iroha_data_model::block::SharedSignedBlock,
        crate::kura::NativeFrameBytes,
        Hash,
    ),
    BlockProofError,
> {
    let kura = source.kura;
    let height = usize::try_from(block_height.get())
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or(BlockProofError::HeightOutOfRange(block_height))?;
    // A zero resource allowance is a refusal, never an unlimited sentinel.
    for resource in [
        BlockProofResource::SourceBlocks,
        BlockProofResource::SourceWireBytes,
        BlockProofResource::BlockWireBytes,
        BlockProofResource::WorkItems,
        BlockProofResource::ResponseBytes,
    ] {
        limits.admit(block_height, resource, 1)?;
    }
    if let Some(actual) = kura.get_block_hash(height)
        && actual != expected_hash
    {
        return Err(BlockProofError::BlockHashMismatch {
            block_height,
            expected: expected_hash,
            actual,
        });
    }
    let storage_error =
        |error| match crate::execution_attempt::kura_read_attempt_error(error, |error| {
            BlockProofError::Storage {
                block_height,
                reason: error.to_string(),
            }
        }) {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
            crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                BlockProofError::Deferred(original)
            }
        };
    let target = kura
        .native_frame_read(block_height.get(), expected_hash)
        .map_err(storage_error)?
        .ok_or_else(|| BlockProofError::Storage {
            block_height,
            reason: "committed native body is unavailable".into(),
        })?;
    let wire_len = target.wire_len();
    limits.admit(block_height, BlockProofResource::BlockWireBytes, wire_len)?;
    if wire_response {
        limits.admit(block_height, BlockProofResource::ResponseBytes, wire_len)?;
    }
    // Native prefix authority reads every source under its own finite allowance. The original
    // hash cut is retained, not a full World view; an unsigned result-only H1 is never enough.
    let verified = read_authenticated_execution(
        kura,
        source.chain_id,
        source.network,
        source.hashes,
        block_height.get(),
        NativeExecutionReadLimits {
            admitted_target_wire_bytes: wire_len,
            max_source_blocks: limits.max_source_blocks,
            max_source_wire_bytes: limits.max_source_wire_bytes,
            max_frame_wire_bytes: crate::kura::STRICT_INIT_MAX_BLOCK_BYTES,
        },
        source.budget,
    )
    .map_err(|error| match error {
        NativeExecutionReadError::Capacity {
            resource,
            actual,
            limit,
        } => BlockProofError::CapacityExceeded {
            block_height,
            resource: match resource {
                NativeExecutionReadResource::SourceBlocks => BlockProofResource::SourceBlocks,
                NativeExecutionReadResource::SourceWireBytes => BlockProofResource::SourceWireBytes,
                NativeExecutionReadResource::FrameWireBytes => BlockProofResource::BlockWireBytes,
            },
            actual,
            limit,
        },
        NativeExecutionReadError::Deferred(reason) => BlockProofError::Deferred(reason),
        error => BlockProofError::Storage {
            block_height,
            reason: error.to_string(),
        },
    })?;
    // Target metadata was admitted independently before the prefix's first body read. Refuse
    // any changed length rather than silently extending its response/output allowance.
    if verified.wire.len() as u64 != wire_len {
        return Err(BlockProofError::Storage {
            block_height,
            reason: "native target length changed after admission".into(),
        });
    }
    // R authenticates certificate-free execution bytes. The stored transport also carries
    // this node's independently verified quorum certificate, which is not part of that hash.
    let executed_block_wire_hash = verified
        .authority
        .committed()
        .commitment()
        .execution
        .executed_block_wire_hash;
    let block = verified.authority.block().clone();
    let wire = verified.wire;
    if block.header().height() != block_height {
        return Err(BlockProofError::BlockHeightMismatch {
            requested: block_height,
            actual: block.header().height(),
        });
    }
    if block.hash() != expected_hash {
        return Err(BlockProofError::BlockHashMismatch {
            block_height,
            expected: expected_hash,
            actual: block.hash(),
        });
    }
    if !block.has_results() {
        return Err(BlockProofError::MissingResults(block_height));
    }
    let mut work = 0_u64;
    for rows in std::iter::once(block.network_entrypoint_count())
        .chain(std::iter::once(block.execution_outputs().len()))
        .chain(std::iter::once(block.fastpq_transcripts().len()))
        .chain(block.fastpq_transcripts().values().map(Vec::len))
    {
        work = work
            .checked_add(rows as u64)
            .ok_or(BlockProofError::CapacityExceeded {
                block_height,
                resource: BlockProofResource::WorkItems,
                actual: u64::MAX,
                limit: limits.max_work_items,
            })?;
        limits.admit(block_height, BlockProofResource::WorkItems, work.max(1))?;
    }
    // TODO: reserve decoded graph, validation scratch and retained response memory
    // from the common query owner; wire/work ceilings alone are not that reservation.
    if block
        .execution_context()
        .is_some_and(|context| !context.has_current_version())
    {
        return Err(invalid_outputs(
            block_height,
            "retired merge carrier is not a canonical Network source",
        ));
    }
    block
        .validate_output_merkle_cache()
        .map_err(|error| invalid_outputs(block_height, error))?;
    Ok((block, wire, executed_block_wire_hash))
}

pub(super) fn executed_block_wire_from_kura(
    source: NativeProofSource<'_>,
    block_height: NonZeroU64,
    expected_hash: HashOf<BlockHeader>,
    limits: BlockProofLimits,
) -> Result<crate::kura::NativeFrameBytes, BlockProofError> {
    read_finalized_body(source, block_height, expected_hash, limits, true).map(|(_, wire, _)| wire)
}

pub(super) fn block_proofs_for_entry_from_kura(
    source: NativeProofSource<'_>,
    block_height: NonZeroU64,
    expected_hash: HashOf<BlockHeader>,
    entry_hash: HashOf<TransactionEntrypoint>,
    limits: BlockProofLimits,
) -> Result<BlockProofs, BlockProofError> {
    let (block, wire, executed_block_wire_hash) =
        read_finalized_body(source, block_height, expected_hash, limits, false)?;
    // The original wire served its authentication purpose. Do not retain this
    // second representation while materializing the proof response.
    drop(wire);
    let input_index = block
        .network_input_hashes()
        .position(|hash| hash == entry_hash)
        .ok_or(BlockProofError::EntrypointNotFound {
            entry_hash,
            block_height,
        })?;
    let input_index = u32::try_from(input_index)
        .map_err(|_| invalid_outputs(block_height, "Network input index exceeds proof width"))?;
    let (output_index, _) = block
        .network_output_at(input_index)
        .ok_or_else(|| invalid_outputs(block_height, "Network input has no exact output join"))?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or_else(|| invalid_outputs(block_height, "joined output is absent"))?;
    let inputs = block.network_input_merkle_tree();
    let entry_commitment = inputs
        .commitment()
        .ok_or_else(|| invalid_outputs(block_height, "Network input commitment is absent"))?;
    let input_path = inputs
        .get_proof(input_index)
        .ok_or_else(|| invalid_outputs(block_height, "Network input proof is absent"))?;
    let entry_proof = BlockReceiptProof::new(entry_hash, input_path);
    let output_commitment = block
        .output_merkle_commitment()
        .ok_or_else(|| invalid_outputs(block_height, "output commitment is absent"))?;
    let output_path = block
        .output_proof(output_index)
        .ok_or_else(|| invalid_outputs(block_height, "output proof is absent"))?;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let output_fields: [&dyn norito::core::SerializePayload; 2] = [output, &output_path];
    let borrowed_output = BorrowedSingularStruct::new(output_fields);
    let fields: [&dyn norito::core::SerializePayload; 9] = [
        &block_height,
        &expected_hash,
        &executed_block_wire_hash,
        &entry_hash,
        &entry_commitment,
        &entry_proof,
        &output_commitment,
        &borrowed_output,
        block.fastpq_transcripts(),
    ];
    let borrowed = BorrowedSingularStruct::new(fields);
    let align = norito::core::archived_payload_align::<BlockProofs>().max(1);
    let padding = (align - norito::core::Header::SIZE % align) % align;
    let overhead = (norito::core::Header::SIZE + padding) as u64;
    limits.admit(block_height, BlockProofResource::ResponseBytes, overhead)?;
    let payload_limit = limits.max_response_bytes - overhead;
    let payload_len = bounded_bare_encoded_len(&borrowed, payload_limit).map_err(|error| {
        if matches!(error, QueryExecutionFail::GasBudgetExceeded) {
            BlockProofError::CapacityExceeded {
                block_height,
                resource: BlockProofResource::ResponseBytes,
                actual: limits.max_response_bytes.saturating_add(1),
                limit: limits.max_response_bytes,
            }
        } else {
            invalid_outputs(block_height, error)
        }
    })?;
    let proofs = BlockProofs {
        block_height,
        block_hash: expected_hash,
        executed_block_wire_hash,
        entry_hash,
        entry_commitment,
        entry_proof,
        output_commitment,
        output_proof: ExecutionReceiptProof::new(output.clone(), output_path),
        fastpq_transcripts: block.fastpq_transcripts().clone(),
    };
    let actual = norito::canonical_frame_len(&proofs)
        .map_err(|error| invalid_outputs(block_height, error))? as u64;
    if actual != overhead + payload_len {
        return Err(invalid_outputs(
            block_height,
            "borrowed and owned proof lengths differ",
        ));
    }
    Ok(proofs)
}

#[cfg(test)]
mod native_proof_reader_tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };

    #[test]
    fn native_block_proof_preserves_original_cumulative_metadata_refusal() {
        use ivm::error::ExecutionDeferral;
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let target = chain.committed(2);
        let entry = target.block().network_entrypoint_at(0).unwrap().hash();
        let height = NonZeroU64::new(2).unwrap();
        let bound = |allocation| {
            norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, allocation, 64)
        };
        let probe = norito::core::DecodeBudgetContext::new(bound(48 * 1024 * 1024));
        probe.with(|| {
            chain
                .kura()
                .native_frame_read(2, target.block_hash())
                .unwrap()
                .unwrap();
        });
        let marker_work = probe.consumed_allocated_bytes();
        assert!(marker_work > 0);
        let context =
            norito::core::DecodeBudgetContext::new(bound(usize::try_from(marker_work).unwrap()));
        context.with(|| {
            chain
                .kura()
                .native_frame_read(2, target.block_hash())
                .unwrap()
                .unwrap();
        });
        let pool = chain.state().ivm_execution_budget();
        let charge = pool.reserved_bytes();
        chain.kura().reset_canonical_query_reads_for_test();
        for _ in 0..2 {
            let error = context
                .with(|| {
                    chain
                        .state()
                        .block_proofs_for_entry(height, entry, limits())
                })
                .expect_err("the original metadata context cannot admit proof body I/O");
            let BlockProofError::Deferred(ref original) = error else {
                panic!("original native block proof metadata refusal must remain local: {error:?}");
            };
            assert_eq!(original.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert!(original.allocation_refusal().is_none());
            assert_eq!(context.consumed_allocated_bytes(), marker_work);
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            assert_eq!(pool.reserved_bytes(), charge);
        }
        let proof = chain
            .state()
            .block_proofs_for_entry(height, entry, limits())
            .unwrap();
        let anchor =
            iroha_data_model::block::proofs::TrustedBlockProofAnchor::from_committed_execution(
                target.block(),
                target.commitment().execution.executed_block_wire_len,
                target.commitment().execution.executed_block_wire_hash,
                &entry,
            )
            .unwrap();
        assert!(proof.verify(&anchor));
        assert_eq!(context.consumed_allocated_bytes(), marker_work);
        assert_eq!(pool.reserved_bytes(), charge);
    }

    fn limits() -> BlockProofLimits {
        BlockProofLimits {
            max_source_blocks: 8,
            max_source_wire_bytes: 16 * 1024 * 1024,
            max_block_wire_bytes: 4 * 1024 * 1024,
            max_work_items: 1_024,
            max_response_bytes: 4 * 1024 * 1024,
        }
    }

    #[test]
    fn serves_only_actual_native_execution_and_original_wire() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let target = chain.committed(2);
        let height = NonZeroU64::new(2).unwrap();
        let hash = target.block().network_entrypoint_at(0).unwrap().hash();
        let proofs = chain
            .state()
            .block_proofs_for_entry(height, hash, limits())
            .unwrap();
        let anchor =
            iroha_data_model::block::proofs::TrustedBlockProofAnchor::from_committed_execution(
                target.block(),
                target.commitment().execution.executed_block_wire_len,
                target.commitment().execution.executed_block_wire_hash,
                &hash,
            )
            .unwrap();
        assert_eq!(
            proofs.executed_block_wire_hash,
            target.commitment().execution.executed_block_wire_hash
        );
        assert_eq!(
            proofs.executed_block_wire_hash,
            target.block().executed_block_wire_hash().unwrap()
        );
        assert_ne!(
            proofs.executed_block_wire_hash,
            Hash::new(target.block().encode_wire().unwrap())
        );
        assert!(proofs.verify(&anchor));
        let mut substituted = proofs;
        substituted.executed_block_wire_hash = Hash::new(target.block().encode_wire().unwrap());
        assert!(
            !substituted.verify(&anchor),
            "the transport certificate cannot replace R's executed identity"
        );
        assert_eq!(
            chain
                .state()
                .executed_block_wire(height, limits())
                .unwrap()
                .as_slice(),
            target.block().encode_wire().unwrap()
        );
        assert_eq!(
            chain
                .state()
                .executed_block_wire(NonZeroU64::new(1).unwrap(), limits())
                .unwrap()
                .as_slice(),
            chain.committed(1).block().encode_wire().unwrap()
        );
    }

    #[test]
    fn proof_serving_counts_all_native_source_heights_and_bytes() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let height = NonZeroU64::new(2).unwrap();
        for (bounds, resource) in [
            (
                BlockProofLimits {
                    max_source_blocks: 1,
                    ..limits()
                },
                BlockProofResource::SourceBlocks,
            ),
            (
                BlockProofLimits {
                    max_source_wire_bytes: 1,
                    ..limits()
                },
                BlockProofResource::SourceWireBytes,
            ),
        ] {
            assert!(matches!(chain.state().executed_block_wire(height, bounds),
                Err(BlockProofError::CapacityExceeded { resource: actual, .. }) if actual == resource));
        }
    }

    #[test]
    fn proof_serving_does_not_accept_genesis_result_before_h2() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        assert!(matches!(
            chain
                .state()
                .executed_block_wire(NonZeroU64::new(1).unwrap(), limits()),
            Err(BlockProofError::Storage { .. })
        ));
    }
}
