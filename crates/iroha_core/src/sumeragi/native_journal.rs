//! One bounded native history source for offline evidence and disposable qualification.
//!
//! The journal owns original canonical frames; this adapter decodes them once and lends the
//! existing CertifiedChain verifier their exact contiguous hash cut. No projected context,
//! fabricated genesis QC, alternate verifier, storage database or mutable World is introduced.

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};

use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, SharedSignedBlock, SignedBlock},
    sumeragi::finality::{
        NativeFinalityDecodeError, NativeFinalityLimits, NativeFinalitySource,
        decode_native_finality_block,
    },
};
use iroha_model_base::chain::ChainId;

use super::certified_chain::{CertifiedChain, ChainReadError};
use crate::execution_attempt::ExecutionAttemptError;
use crate::state::StateView;

/// A native proof read, keeping deterministic invalidity and original resource custody distinct.
#[derive(Debug, thiserror::Error)]
pub enum NativeJournalError {
    /// A complete source, bound or authority check failed.
    #[error("native journal: {0}")]
    Invalid(String),
    /// Canonical source decoding retained its original admission classification.
    #[error(transparent)]
    Decode(#[from] NativeFinalityDecodeError),
    /// A canonical prepared frame belongs to a different original operation pool.
    #[error("native journal prepared source belongs to another original pool")]
    SourcePool,
    /// Original cumulative decoder allowance refused index/control accounting.
    #[error("native journal index admission failed")]
    DecodeAllocation(#[source] norito::Error),
    /// Original caller pool or physical allocator refused the block control.
    #[error(transparent)]
    Block(#[from] iroha_data_model::block::SharedBlockAdmissionError),
    /// The original pool or physical allocator refused exact index backing.
    #[error("native journal index allocation failed")]
    Index(#[source] ChargedBufferError),
    /// Original authenticated history read failed or was deferred.
    #[error(transparent)]
    History(#[from] ExecutionAttemptError<ChainReadError>),
    /// Signed-genesis decoding and authority retains its own original source.
    #[error(transparent)]
    Genesis(#[from] iroha_data_model::sumeragi_finality::GenesisReadError),
}
impl From<String> for NativeJournalError {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}
impl From<&str> for NativeJournalError {
    fn from(value: &str) -> Self {
        Self::Invalid(value.into())
    }
}

/// Exact fixed arrays borrowed by the existing native history verifier.
/// Nested block graphs are separate obligations; these owners cover only index backing.
struct NativeJournalIndex {
    frames: ChargedBuffer<SharedSignedBlock>,
    hashes: ChargedBuffer<HashOf<BlockHeader>>,
}
impl NativeJournalIndex {
    /// Admit each actual backing before allocation from the unchanged operation pool.
    fn new(count: usize, budget: &AllocationBudget) -> Result<Self, NativeJournalError> {
        let frames = ChargedBuffer::new(count, budget).map_err(NativeJournalError::Index)?;
        let hashes = ChargedBuffer::new(count, budget).map_err(NativeJournalError::Index)?;
        Ok(Self { frames, hashes })
    }
}

/// Run an offline read against one complete independently pinned native journal.
///
/// The configured `network` is the expected signed-genesis hash, supplied independently of
/// evidence. `chain_id` pins the native instance. Every frame is decoded and every native
/// certificate/parent/result/epoch link through the tip is verified before `read` executes.
/// Every ordinary certificate requires its exact authenticated BLS quorum. A single H1
/// journal still proves only signed-body authority; its unsigned result never acquires a QC.
///
/// The same cumulative Norito allocation scope covers decoding and certificate verification.
/// This is bounded offchain memory admission, not production execution allocation custody.
///
/// # Errors
/// Rejects malformed bounds, excessive source/decoded size, noncanonical frames, noncontiguous
/// heights, wrong network/instance, altered execution results, quorum or signature failures.
pub fn with_verified_native_journal<T>(
    journal: NativeFinalitySource<'_>,
    chain_id: &ChainId,
    network: &NetworkId,
    limits: NativeFinalityLimits,
    budget: &AllocationBudget,
    read: impl FnOnce(&CertifiedChain<'_, StateView<'_>>) -> Result<T, NativeJournalError>,
) -> Result<T, NativeJournalError> {
    journal.validate(limits)?;
    if !cfg!(all(test, sumeragi_core_mutation = "HC118"))
        && journal.frames().any(|frame| {
            frame
                .charged_source()
                .is_some_and(|source| !source.belongs_to(budget))
        })
    {
        return Err(NativeJournalError::SourcePool);
    }
    // The caller owns one operation pool; shared controls and both actual index backings
    // retain their original charges for their entire physical lifetime.
    // Prepared sources borrow original funded bytes and range backing. An owning DTO's
    // source allocations remain its caller's obligation.
    // TODO: decoded nested block/result graphs still use source limits and cumulative
    // decoder counters, not full retained pool ledgers.
    norito::core::with_decode_limits_scope(limits.decode_limits()?, || {
        // Admission precedes each concrete side allocation; canonical blocks themselves use
        // the same active Norito counters. No per-block scope resets the aggregate counter.
        let count = journal.len();
        let side_bytes = count
            .checked_mul(
                core::mem::size_of::<iroha_data_model::block::SharedSignedBlock>()
                    + core::mem::size_of::<HashOf<BlockHeader>>(),
            )
            .ok_or("native journal index allocation overflow")?;
        norito::core::reserve_decode_allocation(side_bytes)
            .map_err(NativeJournalError::DecodeAllocation)?;
        let reserve_shell = || {
            SharedSignedBlock::reserve(budget).map_err(|error| {
                if cfg!(all(test, sumeragi_core_mutation = "HC90")) {
                    NativeJournalError::Invalid("mutated journal control refusal".into())
                } else {
                    NativeJournalError::Block(error)
                }
            })
        };
        // Source validation established a nonempty prefix. Retain its first control before
        // index admission, preserving original control refusal precedence under saturation.
        let mut first_shell = Some(reserve_shell()?);
        let mut index = NativeJournalIndex::new(count, budget)?;
        for (offset, source) in journal.frames().enumerate() {
            // The opaque frame keeps the actual charged source and canonical span
            // through this read. Owning offchain DTOs cannot manufacture this
            // provenance. TODO: consume this owner in a completely physically
            // funded SignedBlock payload/result/DA decoder; the current ordinary
            // nested block decode remains a separate unfunded graph obligation.
            let wire = source.wire();
            let shell = match first_shell.take() {
                Some(shell) => shell,
                None => reserve_shell()?,
            };
            let block = decode_native_finality_block(wire, limits)?;
            let expected = u64::try_from(offset)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or("native journal height overflow")?;
            if block.header().height().get() != expected {
                return Err("native journal is not a complete consecutive prefix".into());
            }
            norito::core::reserve_decode_allocation(SharedSignedBlock::allocation_layout().size())
                .map_err(NativeJournalError::DecodeAllocation)?;
            // Each source contributes exactly one entry to the fixed count admitted above.
            index.hashes.push_reserved(block.hash());
            index.frames.push_reserved(shell.initialize(block));
        }
        let reader = CertifiedChain::from_frames(
            chain_id,
            network,
            index.hashes.as_slice(),
            index.frames.as_slice(),
        )?;
        let height = u64::try_from(count).map_err(|_| "native journal height overflow")?;
        reader.certified(height)?;
        read(&reader)
    })
}

/// One source-owned phase clock for a bounded offline committee operation.
///
/// Each advancement is verified by the same native journal reader. The retained tip is
/// only a continuity pin; it never supplies a new epoch roster.
/// Refusal leaves the previous tip intact. Initial genesis authority has no finalized receipt:
/// at least H2 must genuinely certify its parent result before this clock can advance.
pub struct NativeJournalCursor {
    chain_id: ChainId,
    network: NetworkId,
    limits: NativeFinalityLimits,
    budget: AllocationBudget,
    tip: Option<super::certified_chain::CommittedBlock>,
}
impl NativeJournalCursor {
    /// Pin an operation to independently configured chain/network and explicit resource caps.
    pub fn new(
        chain_id: ChainId,
        network: NetworkId,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        limits: NativeFinalityLimits,
        budget: &AllocationBudget,
    ) -> Result<Self, NativeJournalError> {
        limits.validate()?;
        // The configured root scope must derive this operation's native instance.
        root_scope
            .instance_id(&super::crypto::BlsCrypto::new(), network, chain_id.as_str())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            chain_id,
            network,
            limits,
            budget: budget.clone(),
            tip: None,
        })
    }

    /// Original operation pool retained across unchanged-source retries.
    pub fn allocation_budget(&self) -> &AllocationBudget {
        &self.budget
    }
    /// The last genuinely certified ordinary tip, absent before the first H2+ prefix.
    pub fn tip(&self) -> Option<&super::certified_chain::CommittedBlock> {
        self.tip.as_ref()
    }
    /// Immutable configured chain; never inferred from a remote proof.
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }
    /// Immutable signed-genesis network pin.
    pub fn network_id(&self) -> NetworkId {
        self.network
    }
    /// Exact operation limits used for every phase frame.
    pub fn limits(&self) -> NativeFinalityLimits {
        self.limits
    }

    /// Authenticate a strictly advancing complete prefix and retain its exact native tip.
    pub fn advance(
        &mut self,
        journal: NativeFinalitySource<'_>,
    ) -> Result<&super::certified_chain::CommittedBlock, NativeJournalError> {
        let height = u64::try_from(journal.len()).map_err(|_| "native phase height overflow")?;
        if height < 2 || self.tip.as_ref().is_some_and(|tip| height <= tip.height()) {
            return Err("native phase journal does not advance a certified ordinary height".into());
        }
        let next = with_verified_native_journal(
            journal,
            &self.chain_id,
            &self.network,
            self.limits,
            &self.budget,
            |reader| {
                if let Some(tip) = &self.tip {
                    let retained = reader.certified(tip.height())?;
                    if retained.block_hash() != tip.block_hash()
                        || retained.core_hash() != tip.core_hash()
                        || retained.result() != tip.result()
                    {
                        return Err("native phase journal replaces its retained source tip".into());
                    }
                }
                reader
                    .certified(height)
                    .map(|value| value.into_committed())
                    .map_err(NativeJournalError::History)
            },
        )?;
        self.tip = Some(next);
        self.tip
            .as_ref()
            .ok_or_else(|| "native phase tip publication failed".into())
    }
}

/// Authenticate only a signed-genesis body and its complete native signing epoch.
///
/// No execution preimage or height-one QC is accepted as authority here. This is the initial
/// DKG authorization root; phase clocks require a genuine H2+ journal before any advancement.
pub fn authenticate_signed_genesis(
    wire: &[u8],
    network: NetworkId,
    limits: NativeFinalityLimits,
) -> Result<
    (
        SignedBlock,
        iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
    ),
    NativeJournalError,
> {
    limits.validate()?;
    if wire.is_empty() || wire.len() > limits.block_bytes {
        return Err("signed genesis exceeds its configured source bound".into());
    }
    let block = iroha_data_model::sumeragi::finality::decode_native_finality_block(wire, limits)?;
    if block.hash() != network.into_genesis_hash() {
        return Err("foreign signed genesis".into());
    }
    let epoch =
        super::epoch::authenticated_genesis(&block).map(|genesis| genesis.into_parts().0)?;
    Ok((block, epoch))
}

#[cfg(test)]
mod tests {
    mod signature_tests;
    use super::*;
    mod index_tests;
    mod source_tests;
    use crate::{
        state::World,
        sumeragi::{
            certified_chain::QcVerification,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };
    use iroha_data_model::sumeragi::finality::{NativeFinalityArtifact, NativeFinalityJournal};

    fn limits() -> NativeFinalityLimits {
        NativeFinalityLimits {
            block_bytes: 1024 * 1024,
            journal_bytes: 4 * 1024 * 1024,
            block_count: 16,
            allocated_bytes: 64 * 1024 * 1024,
        }
    }
    fn fixture() -> (CertifiedTestChain, NativeFinalityJournal) {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
        chain.commit_at(2000, Vec::new());
        chain.commit_at(3000, Vec::new());
        let blocks = (1..=3)
            .map(|height| {
                NativeFinalityArtifact::from_block(chain.committed(height).block(), limits())
                    .unwrap()
            })
            .collect();
        (chain, NativeFinalityJournal { blocks })
    }
    #[test]
    fn actual_native_journal_authenticates_source_and_keeps_genesis_scope_explicit() {
        let (chain, journal) = fixture();
        let chain_id = ChainId::from("sumeragi-certified-test-chain");
        // The same production reader verifies every exact BLS quorum and source link.
        with_verified_native_journal(
            (&journal).into(),
            &chain_id,
            &chain.network_id(),
            limits(),
            &chain.state().ivm_execution_budget(),
            |reader| {
                assert_eq!(
                    reader.certified(1).unwrap().verification(),
                    QcVerification::Genesis
                );
                assert_eq!(
                    reader.certified(3).unwrap().verification(),
                    QcVerification::Verified
                );
                assert_eq!(
                    reader.certified(3).unwrap().result(),
                    chain.committed(3).result()
                );
                Ok(())
            },
        )
        .unwrap();
    }
    #[test]
    fn source_caps_foreign_instance_and_truncated_prefix_are_refused_before_callback() {
        let (chain, journal) = fixture();
        let chain_id = ChainId::from("sumeragi-certified-test-chain");
        let verify = |source: &NativeFinalityJournal, id: &ChainId, bounds| {
            with_verified_native_journal(
                source.into(),
                id,
                &chain.network_id(),
                bounds,
                &chain.state().ivm_execution_budget(),
                |_| Err::<(), _>("callback must not run".into()),
            )
            .unwrap_err()
            .to_string()
        };
        let suffix = NativeFinalityJournal {
            blocks: journal.blocks[1..].to_vec(),
        };
        assert!(verify(&suffix, &chain_id, limits()).contains("complete consecutive prefix"));
        assert!(!verify(&journal, &ChainId::from("foreign"), limits()).contains("callback"));
        assert!(
            !verify(
                &journal,
                &chain_id,
                NativeFinalityLimits {
                    allocated_bytes: 1,
                    ..limits()
                }
            )
            .contains("callback")
        );
        assert!(
            !verify(
                &journal,
                &chain_id,
                NativeFinalityLimits {
                    block_count: 2,
                    ..limits()
                }
            )
            .contains("callback")
        );
        let mut changed = journal;
        changed.blocks[1].block_wire.push(0);
        assert!(!verify(&changed, &chain_id, limits()).contains("callback"));
    }
    #[test]
    fn native_cursor_preserves_tip_on_refusal_and_genesis_has_no_finalized_clock() {
        let (chain, journal) = fixture();
        let mut cursor = NativeJournalCursor::new(
            ChainId::from("sumeragi-certified-test-chain"),
            chain.network_id(),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            limits(),
            &chain.state().ivm_execution_budget(),
        )
        .unwrap();
        let initial = NativeFinalityJournal {
            blocks: journal.blocks[..1].to_vec(),
        };
        assert!(cursor.advance((&initial).into()).is_err());
        assert!(cursor.tip().is_none());
        let (_, epoch) = authenticate_signed_genesis(
            &initial.blocks[0].block_wire,
            chain.network_id(),
            limits(),
        )
        .unwrap();
        assert_eq!(epoch.authorization.epoch, 0);
        let h2 = NativeFinalityJournal {
            blocks: journal.blocks[..2].to_vec(),
        };
        assert_eq!(cursor.advance((&h2).into()).unwrap().height(), 2);
        let result = cursor.tip().unwrap().result();
        assert!(cursor.advance((&h2).into()).is_err());
        let mut malformed = journal.clone();
        malformed.blocks[2].block_wire.push(0);
        assert!(cursor.advance((&malformed).into()).is_err());
        assert_eq!(cursor.tip().unwrap().result(), result);
        assert_eq!(cursor.advance((&journal).into()).unwrap().height(), 3);
        assert_eq!(
            cursor.chain_id(),
            &ChainId::from("sumeragi-certified-test-chain")
        );
        assert_eq!(cursor.network_id(), chain.network_id());
        assert_eq!(cursor.limits(), limits());
        let wrong = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"wrong genesis"),
        ));
        assert!(
            authenticate_signed_genesis(&initial.blocks[0].block_wire, wrong, limits()).is_err()
        );
    }

    #[test]
    fn native_cursor_preserves_original_pool_refusal_and_retries_identical_prefix() {
        use iroha_allocation::AllocationRefusal;
        use std::task::{Context, Waker};
        let (chain, journal) = fixture();
        // Keep the independent Kura read outside this operation's accounting
        // window; only the cursor and its refusal observer are under test here.
        let expected_tip = chain.committed(3).block_hash();
        // This offline reader owns one finite operation pool. The fixture's
        // committed State has independently retired MV generations whose epoch
        // reclamation must not be counted as journal-reader refunds.
        let pool = AllocationBudget::new(limits().allocated_bytes);
        let floor = pool.reserved_bytes();
        let mut observer = crate::unit_test_support::release_registration(&pool);
        let mut cursor = NativeJournalCursor::new(
            ChainId::from("sumeragi-certified-test-chain"),
            chain.network_id(),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            limits(),
            &pool,
        )
        .unwrap();
        let h2 = NativeFinalityJournal {
            blocks: journal.blocks[..2].to_vec(),
        };
        cursor.advance((&h2).into()).unwrap();
        let retained = cursor.tip().unwrap().block_hash();
        let blocker = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let expected = pool
            .try_reserve(SharedSignedBlock::allocation_layout())
            .unwrap_err();
        let error = cursor.advance((&journal).into()).unwrap_err();
        let NativeJournalError::Block(
            iroha_data_model::block::SharedBlockAdmissionError::Admission(actual),
        ) = error
        else {
            panic!("{error:?}");
        };
        assert_eq!(actual, expected);
        assert_eq!(cursor.tip().unwrap().block_hash(), retained);
        let AllocationRefusal::Capacity { release, .. } = actual else {
            panic!("actual occupied pool");
        };
        let mut context = Context::from_waker(Waker::noop());
        assert!(observer.poll_wait(&release, &mut context).is_pending());
        let foreign = AllocationBudget::new(1);
        drop(foreign.try_reserve_bytes(1).unwrap());
        assert!(observer.poll_wait(&release, &mut context).is_pending());
        drop(blocker);
        assert!(observer.poll_wait(&release, &mut context).is_ready());
        observer.cancel();
        assert_eq!(
            cursor.advance((&journal).into()).unwrap().block_hash(),
            expected_tip,
        );
        drop(cursor);
        drop(observer);
        assert_eq!(pool.reserved_bytes(), floor);
    }

    #[test]
    fn native_journal_decoder_refusal_never_runs_reader_or_replaces_cursor_tip() {
        let (chain, journal) = fixture();
        // Keep refusal accounting within the one original offline operation.
        let pool = AllocationBudget::new(limits().allocated_bytes);
        let mut cursor = NativeJournalCursor::new(
            ChainId::from("sumeragi-certified-test-chain"),
            chain.network_id(),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            limits(),
            &pool,
        )
        .unwrap();
        cursor
            .advance(
                (&NativeFinalityJournal {
                    blocks: journal.blocks[..2].to_vec(),
                })
                    .into(),
            )
            .unwrap();
        let prior = cursor.tip().unwrap().block_hash();
        let credits = pool.reserved_bytes();
        let error = norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                with_verified_native_journal(
                    (&journal).into(),
                    cursor.chain_id(),
                    &chain.network_id(),
                    limits(),
                    &pool,
                    |_| -> Result<(), NativeJournalError> {
                        panic!("refused source must not reach reader");
                    },
                )
            },
        )
        .unwrap_err();
        let NativeJournalError::DecodeAllocation(original) = error else {
            panic!("{error:?}");
        };
        assert!(matches!(
            original.decode_resource_error(),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
        ));
        assert_eq!(cursor.tip().unwrap().block_hash(), prior);
        assert_eq!(pool.reserved_bytes(), credits);
        let mut malformed = journal.clone();
        malformed.blocks[2].block_wire.push(0);
        assert!(matches!(
            cursor.advance((&malformed).into()),
            Err(NativeJournalError::Decode(
                NativeFinalityDecodeError::Malformed(_)
            ))
        ));
        assert_eq!(cursor.tip().unwrap().block_hash(), prior);
        assert_eq!(
            cursor.advance((&journal).into()).unwrap().block_hash(),
            chain.committed(3).block_hash()
        );
    }
}
