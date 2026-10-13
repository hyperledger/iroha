//! Execution-read authority from the native quorum or the actual genesis successor anchor.
use super::*;

/// An original block whose execution result, not only its header, has been authenticated.
///
/// This receipt is never decoded or publicly constructed. Ordinary blocks require their native
/// quorum; genesis requires its verified H2 successor because genesis signatures do not bind R.
#[derive(Debug)]
pub struct AuthenticatedExecutionBlock {
    committed: CommittedBlock,
}
impl AuthenticatedExecutionBlock {
    /// Original authenticated block graph, including the exact node-local certificate.
    #[must_use]
    pub fn block(&self) -> &iroha_data_model::block::SharedSignedBlock {
        self.committed.block()
    }

    /// The authenticated execution result and exact source identity.
    #[must_use]
    pub fn committed(&self) -> &CommittedBlock {
        &self.committed
    }
}
impl CertifiedBlock {
    /// Retain execution-read authority from the native quorum without cloning the block graph.
    ///
    /// # Errors
    /// A genesis body signature alone cannot authenticate its subsequently added execution R.
    pub fn into_authenticated_execution(
        self,
    ) -> Result<AuthenticatedExecutionBlock, ChainReadError> {
        if self.verification != QcVerification::Verified {
            return Err(ChainReadError::Malformed {
                height: self.height(),
                reason: "genesis execution requires its verified height-two successor".into(),
            });
        }
        Ok(AuthenticatedExecutionBlock {
            committed: self.committed,
        })
    }
}
impl GenesisExecutionAnchor {
    /// Consume the actual H2 anchor while retaining the exact authenticated genesis graph.
    #[must_use]
    pub fn into_authenticated_execution(self) -> AuthenticatedExecutionBlock {
        AuthenticatedExecutionBlock {
            committed: self.committed,
        }
    }
}
impl<V: StateReadOnly + ?Sized> CertifiedChain<'_, V> {
    /// Authenticate the original execution at one committed height, including H1's H2 anchor.
    ///
    /// # Errors
    /// Missing or substituted history, invalid native certificates, or unavailable H2 for H1.
    pub fn authenticated_execution(
        &self,
        height: u64,
    ) -> Result<AuthenticatedExecutionBlock, ExecutionAttemptError<ChainReadError>> {
        if height == GENESIS_HEIGHT {
            self.authenticated_genesis_execution()
        } else {
            self.authenticated_successor_execution(height)
        }
    }

    // Ordinary-height certificate return slots must not remain on the genesis
    // branch's active stack while it decodes and authenticates the H1/H2 prefix.
    #[inline(never)]
    fn authenticated_successor_execution(
        &self,
        height: u64,
    ) -> Result<AuthenticatedExecutionBlock, ExecutionAttemptError<ChainReadError>> {
        self.certified(height)?
            .into_authenticated_execution()
            .map_err(Into::into)
    }

    // The complete H1/H2 prefix owners belong to the genesis read only. Keep them
    // in a separate frame so ordinary height reads do not retain their stack slots
    // while decoding and authenticating the native certificate chain.
    #[inline(never)]
    fn authenticated_genesis_execution(
        &self,
    ) -> Result<AuthenticatedExecutionBlock, ExecutionAttemptError<ChainReadError>> {
        let mut prefix = CertifiedPrefix::new(
            self.source.chain_id(),
            *self.source.network_id(),
            self.source.block(GENESIS_HEIGHT)?,
        )?;
        let (_, genesis) = prefix
            .push(self.source.block(GENESIS_HEIGHT + 1)?)?
            .into_parts();
        genesis
            .map(GenesisExecutionAnchor::into_authenticated_execution)
            .ok_or_else(|| {
                ChainReadError::Malformed {
                    height: GENESIS_HEIGHT,
                    reason: "native successor did not authenticate genesis execution".into(),
                }
                .into()
            })
    }
}

/// Explicit finite ceilings for an off-chain native prefix read.
///
/// Every source frame, including signed genesis and H2 for a genesis request, counts. These
/// logical byte/work bounds are not a reservation of decoded resident graphs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeExecutionReadLimits {
    /// Exact requested target length admitted by its consumer before source verification.
    /// A changed occupied target is refused before its body is read, even below the frame cap.
    pub admitted_target_wire_bytes: u64,
    /// Maximum number of source blocks authenticated, counted before any body I/O.
    pub max_source_blocks: u64,
    /// Aggregate canonical frame bytes across all source blocks.
    pub max_source_wire_bytes: u64,
    /// Maximum single source frame, also capped by Kura's native full-frame bound.
    pub max_frame_wire_bytes: u64,
}

/// Finite source allowance which was exhausted before reading the refused body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeExecutionReadResource {
    /// Number of source blocks.
    SourceBlocks,
    /// Aggregate source frame bytes.
    SourceWireBytes,
    /// One frame's wire length.
    FrameWireBytes,
}

/// Failure to acquire a fully authenticated native execution under explicit source limits.
#[derive(Debug, thiserror::Error)]
pub enum NativeExecutionReadError {
    /// A source limit was refused before the corresponding body read or decode.
    #[error("native execution source {resource:?} requires {actual}, limit {limit}")]
    Capacity {
        /// Refused finite resource.
        resource: NativeExecutionReadResource,
        /// Required quantity, saturated on arithmetic overflow.
        actual: u64,
        /// Caller-supplied allowance.
        limit: u64,
    },
    /// Bounded metadata, body I/O or exact canonical decoding failed.
    #[error("native execution storage at height {height}: {reason}")]
    Storage {
        /// Exact source height, which may precede the requested execution.
        height: u64,
        /// Underlying storage or decoder refusal.
        reason: String,
    },
    /// The actual native prefix, including the genesis successor anchor, did not authenticate.
    #[error(transparent)]
    Chain(#[from] ChainReadError),
    /// The original decoder or allocator refused this local attempt.
    #[error(transparent)]
    Deferred(ExecutionDeferred),
}

impl From<ExecutionAttemptError<ChainReadError>> for NativeExecutionReadError {
    fn from(error: ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(error) => Self::Chain(error),
            ExecutionAttemptError::Deferred(local) => Self::Deferred(local),
        }
    }
}

/// Original authenticated graph and its exact canonical source bytes.
#[derive(Debug)]
pub struct NativeExecutionRead {
    /// Execution authority from the original native quorum or real H2 anchor.
    pub authority: AuthenticatedExecutionBlock,
    /// Exact bytes decoded once and used by that verification.
    pub wire: crate::kura::NativeFrameBytes,
    /// Number of source frames consumed by the verifier.
    pub source_blocks: u64,
    /// Aggregate canonical source frame bytes admitted before reading them.
    pub source_wire_bytes: u64,
}

fn admit_source(
    resource: NativeExecutionReadResource,
    actual: u64,
    limit: u64,
) -> Result<(), NativeExecutionReadError> {
    if actual > limit {
        return Err(NativeExecutionReadError::Capacity {
            resource,
            actual,
            limit,
        });
    }
    Ok(())
}

/// Verify the actual native prefix from a borrowed immutable hash cut under explicit limits.
///
/// This is an off-chain proof/read boundary. Deterministic instruction execution must not
/// depend on local certificate bytes. It holds no World view or all-history frame vector,
/// does not consult the old finality sidecars, and never replaces missing bytes from a cache.
/// Every source length is admitted before body I/O and canonical decode. A genesis request
/// must include the actual H2 successor; a signed genesis body alone cannot authenticate Rg.
///
/// # Errors
/// Zero/insufficient allowances, unavailable or substituted history, invalid canonical frames
/// or native certificates. No partial execution authority escapes on failure.
pub fn read_authenticated_execution(
    kura: &Kura,
    chain_id: &ChainId,
    network: NetworkId,
    hashes: &dyn crate::state::BlockHashRead,
    height: u64,
    limits: NativeExecutionReadLimits,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<NativeExecutionRead, NativeExecutionReadError> {
    if height == 0 {
        return Err(ChainReadError::NotCommitted { height }.into());
    }
    let end = height.max(GENESIS_HEIGHT + 1);
    admit_source(
        NativeExecutionReadResource::SourceBlocks,
        end,
        limits.max_source_blocks,
    )?;
    if usize::try_from(end)
        .ok()
        .is_none_or(|end| end > hashes.hash_count())
    {
        return Err(ChainReadError::NotCommitted { height: end }.into());
    }
    let mut total = 0_u64;
    let mut prefix = None;
    let mut retained_wire = None;
    for current in GENESIS_HEIGHT..=end {
        let expected = *hashes
            .hash_at(
                usize::try_from(current - 1)
                    .map_err(|_| ChainReadError::NotCommitted { height: current })?,
            )
            .ok_or(ChainReadError::NotCommitted { height: current })?;
        let (block, wire, next) =
            read_admitted_execution_frame(kura, current, expected, height, limits, total, budget)?;
        total = next;
        if current == GENESIS_HEIGHT {
            prefix = Some(CertifiedPrefix::new(chain_id, network, block)?);
            if height == GENESIS_HEIGHT {
                retained_wire = Some(wire);
            }
            continue;
        }
        let authority = advance_execution_read_prefix(
            prefix.as_mut().expect("genesis verified first"),
            block,
            height,
            current == end,
        )?;
        if let Some(authority) = authority {
            let wire = if height == GENESIS_HEIGHT {
                retained_wire.take().expect("original genesis wire")
            } else {
                wire
            };
            // The original frame backing and block control retain their physical charges.
            // TODO: retain partially decoded nested graphs and authenticated-prefix progress
            // across decoder refusal; this source owner does not complete that obligation.
            return Ok(NativeExecutionRead {
                authority,
                wire,
                source_blocks: end,
                source_wire_bytes: total,
            });
        }
    }
    unreachable!("the admitted prefix always includes H2")
}

// One original source/frame owner is shared by one-shot reads and durable replay.
// Its bytes and shell survive a later refusal; ordinary nested decoder destinations
// still retire on decode failure. TODO: complete deep nested graph custody separately.
struct PendingExecutionFrame<'source> {
    source: crate::kura::NativeFrameRead<'source>,
    current: u64,
    expected: HashOf<IrohaHeader>,
    length: u64,
    next: u64,
    wire: Option<crate::kura::NativeFrameBytes>,
    shell: Option<iroha_data_model::block::ReservedSharedSignedBlock>,
    block: Option<iroha_data_model::block::SharedSignedBlock>,
}
impl<'source> PendingExecutionFrame<'source> {
    fn new(
        kura: &'source Kura,
        current: u64,
        expected: HashOf<IrohaHeader>,
        height: u64,
        limits: NativeExecutionReadLimits,
        total: u64,
    ) -> Result<Self, NativeExecutionReadError> {
        let source = kura
            .native_frame_read(current, expected)
            .map_err(|error| execution_frame_storage_error(error, current))?
            .ok_or(ChainReadError::NotInView { height: current })?;
        let length = source.wire_len();
        if current == height && length != limits.admitted_target_wire_bytes {
            return Err(NativeExecutionReadError::Storage {
                height: current,
                reason: "native target length changed after consumer admission".into(),
            });
        }
        admit_source(
            NativeExecutionReadResource::FrameWireBytes,
            length,
            limits
                .max_frame_wire_bytes
                .min(crate::kura::STRICT_INIT_MAX_BLOCK_BYTES),
        )?;
        let next = total
            .checked_add(length)
            .ok_or(NativeExecutionReadError::Capacity {
                resource: NativeExecutionReadResource::SourceWireBytes,
                actual: u64::MAX,
                limit: limits.max_source_wire_bytes,
            })?;
        admit_source(
            NativeExecutionReadResource::SourceWireBytes,
            next,
            limits.max_source_wire_bytes,
        )?;

        Ok(Self {
            source,
            current,
            expected,
            length,
            next,
            wire: None,
            shell: None,
            block: None,
        })
    }

    // Keep the large ordinary decode temporary off the retained operation's stack.
    #[inline(never)]
    fn read_block(
        &mut self,
        kura: &Kura,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<iroha_data_model::block::SharedSignedBlock, NativeExecutionReadError> {
        if self.wire.is_some() {
            let current = kura
                .native_frame_read(self.current, self.expected)
                .map_err(|error| execution_frame_storage_error(error, self.current))?
                .ok_or(ChainReadError::NotInView {
                    height: self.current,
                })?;
            if !self.source.same_original_slot(&current) {
                return Err(ChainReadError::NotInView {
                    height: self.current,
                }
                .into());
            }
        }
        if let Some(block) = &self.block {
            return Ok(block.clone());
        }
        if self.wire.is_none() {
            self.wire = Some(
                self.source
                    .read_original(self.length, budget)
                    .map_err(|error| execution_frame_storage_error(error, self.current))?
                    .ok_or(ChainReadError::NotInView {
                        height: self.current,
                    })?,
            );
        }
        if self.shell.is_none() {
            self.shell = Some(
                iroha_data_model::block::SharedSignedBlock::reserve(budget)
                    .map_err(|error| NativeExecutionReadError::Deferred(error.into()))?,
            );
        }
        let wire = self.wire.as_ref().expect("original frame retained");
        let block = iroha_data_model::block::decode_framed_signed_block(wire).map_err(|error| {
            match crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
                NativeExecutionReadError::Storage {
                    height: self.current,
                    reason: error.to_string(),
                }
            }) {
                ExecutionAttemptError::Rejected(error) => error,
                ExecutionAttemptError::Deferred(local) => NativeExecutionReadError::Deferred(local),
            }
        })?;
        if block.header().height().get() != self.current || block.hash() != self.expected {
            return Err(ChainReadError::NotInView {
                height: self.current,
            }
            .into());
        }
        let identity =
            block
                .canonical_wire_identity()
                .map_err(|error| NativeExecutionReadError::Storage {
                    height: self.current,
                    reason: error.to_string(),
                })?;
        if identity != (self.length, Hash::new(wire)) {
            return Err(ChainReadError::Malformed {
                height: self.current,
                reason: "stored native execution is not the exact canonical frame".into(),
            }
            .into());
        }
        let block = self
            .shell
            .take()
            .expect("original shared shell retained")
            .initialize(block);
        self.block = Some(block.clone());
        Ok(block)
    }
}

fn execution_frame_storage_error(
    error: crate::kura::Error,
    current: u64,
) -> NativeExecutionReadError {
    let rejected = |error: crate::kura::Error| NativeExecutionReadError::Storage {
        height: current,
        reason: error.to_string(),
    };
    let attempt = match error {
        crate::kura::Error::NoritoFrame(error) => norito_decode_attempt_error(error, |error| {
            rejected(crate::kura::Error::NoritoFrame(error))
        }),
        crate::kura::Error::BlockDecode(error) => {
            crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
                rejected(crate::kura::Error::BlockDecode(error))
            })
        }
        crate::kura::Error::NativeFrameAllocation(error) => {
            let deferred = match error {
                iroha_allocation::ChargedBufferError::Admission(original) => original.into(),
                iroha_allocation::ChargedBufferError::Allocator { .. } => {
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                }
            };
            ExecutionAttemptError::Deferred(deferred)
        }
        completed => ExecutionAttemptError::Rejected(rejected(completed)),
    };
    match attempt {
        ExecutionAttemptError::Rejected(error) => error,
        ExecutionAttemptError::Deferred(local) => NativeExecutionReadError::Deferred(local),
    }
}

// Decode only the original admitted physical frame. The same owner/kernel serves
// the existing one-shot boundary; its returned success and abandonment remain unchanged.
#[inline(never)]
fn read_admitted_execution_frame(
    kura: &Kura,
    current: u64,
    expected: HashOf<IrohaHeader>,
    height: u64,
    limits: NativeExecutionReadLimits,
    total: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    (
        iroha_data_model::block::SharedSignedBlock,
        crate::kura::NativeFrameBytes,
        u64,
    ),
    NativeExecutionReadError,
> {
    let mut original = PendingExecutionFrame::new(kura, current, expected, height, limits, total)?;
    let block = original.read_block(kura, budget)?;
    Ok((
        block,
        original.wire.take().expect("original canonical wire"),
        original.next,
    ))
}

/// One durable replay operation over its caller's retained immutable hash cut.
/// The current original wire/shell, prefix and intermediate verification slots
/// remain owned on local refusal. Admission grants no new source authority.
/// TODO: complete deep nested decoder and cryptographic scratch custody.
pub(crate) struct NativeExecutionReadAttempt<'source> {
    kura: &'source Kura,
    chain_id: &'source ChainId,
    network: NetworkId,
    height: u64,
    end: u64,
    current: u64,
    total: u64,
    limits: NativeExecutionReadLimits,
    budget: iroha_allocation::AllocationBudget,
    prefix: Option<iroha_allocation::ChargedBuffer<CertifiedPrefix>>,
    genesis_frame: super::AdmittedFrameRead,
    pending: Option<PendingExecutionFrame<'source>>,
    retained_wire: Option<crate::kura::NativeFrameBytes>,
    completed: bool,
}
impl<'source> NativeExecutionReadAttempt<'source> {
    pub(crate) fn new(
        kura: &'source Kura,
        chain_id: &'source ChainId,
        network: NetworkId,
        hashes: &dyn crate::state::BlockHashRead,
        height: u64,
        limits: NativeExecutionReadLimits,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, NativeExecutionReadError> {
        if height == 0 {
            return Err(ChainReadError::NotCommitted { height }.into());
        }
        let end = height.max(GENESIS_HEIGHT + 1);
        admit_source(
            NativeExecutionReadResource::SourceBlocks,
            end,
            limits.max_source_blocks,
        )?;
        if usize::try_from(end)
            .ok()
            .is_none_or(|end| end > hashes.hash_count())
        {
            return Err(ChainReadError::NotCommitted { height: end }.into());
        }
        Ok(Self {
            kura,
            chain_id,
            network,
            height,
            end,
            current: GENESIS_HEIGHT,
            total: 0,
            limits,
            budget: budget.clone(),
            prefix: None,
            genesis_frame: super::AdmittedFrameRead::default(),
            pending: None,
            retained_wire: None,
            completed: false,
        })
    }

    pub(crate) const fn is_completed(&self) -> bool {
        self.completed
    }

    pub(crate) fn advance(
        &mut self,
        hashes: &dyn crate::state::BlockHashRead,
    ) -> Result<NativeExecutionRead, NativeExecutionReadError> {
        if self.completed {
            return Err(NativeExecutionReadError::Storage {
                height: self.height,
                reason: "native execution read attempt already completed".into(),
            });
        }
        while self.current <= self.end {
            let expected = *hashes
                .hash_at(usize::try_from(self.current - 1).map_err(|_| {
                    ChainReadError::NotCommitted {
                        height: self.current,
                    }
                })?)
                .ok_or(ChainReadError::NotCommitted {
                    height: self.current,
                })?;
            if self.pending.is_none() {
                self.pending = Some(PendingExecutionFrame::new(
                    self.kura,
                    self.current,
                    expected,
                    self.height,
                    self.limits,
                    self.total,
                )?);
            }
            let original = self.pending.as_mut().expect("same current original frame");
            if original.expected != expected {
                return Err(ChainReadError::NotInView {
                    height: self.current,
                }
                .into());
            }
            let block = original.read_block(self.kura, &self.budget)?;
            if self.current == GENESIS_HEIGHT {
                if self.prefix.is_none() {
                    self.prefix = Some(
                        iroha_allocation::ChargedBuffer::new(1, &self.budget).map_err(|error| {
                            match error {
                                iroha_allocation::ChargedBufferError::Admission(original) => {
                                    NativeExecutionReadError::Deferred(original.into())
                                }
                                iroha_allocation::ChargedBufferError::Allocator { .. } => {
                                    NativeExecutionReadError::Deferred(
                                        ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                                    )
                                }
                            }
                        })?,
                    );
                }
                initialize_execution_read_prefix(
                    self.prefix.as_mut().expect("original prepaid prefix slot"),
                    &mut self.genesis_frame,
                    self.chain_id,
                    self.network,
                    block,
                    &self.budget,
                )?;
                if self.height == GENESIS_HEIGHT {
                    self.retained_wire = original.wire.take();
                }
            } else {
                let authority = advance_execution_read_prefix(
                    &mut self
                        .prefix
                        .as_mut()
                        .expect("genesis verified first")
                        .as_mut_slice()[0],
                    block,
                    self.height,
                    self.current == self.end,
                )?;
                if let Some(authority) = authority {
                    let wire = if self.height == GENESIS_HEIGHT {
                        self.retained_wire.take().expect("original genesis wire")
                    } else {
                        original.wire.take().expect("original target wire")
                    };
                    self.total = original.next;
                    self.pending = None;
                    self.completed = true;
                    return Ok(NativeExecutionRead {
                        authority,
                        wire,
                        source_blocks: self.end,
                        source_wire_bytes: self.total,
                    });
                }
            }
            self.total = original.next;
            self.pending = None;
            self.current += 1;
        }
        unreachable!("admitted original prefix includes H2")
    }
}

// Reuse the existing stack-safe admitted construction in the original retained
// slot. Its backing survives refusal; no complete prefix temporary is introduced.
#[inline(never)]
fn initialize_execution_read_prefix(
    slot: &mut iroha_allocation::ChargedBuffer<CertifiedPrefix>,
    frame: &mut super::AdmittedFrameRead,
    chain_id: &ChainId,
    network: NetworkId,
    block: iroha_data_model::block::SharedSignedBlock,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(), NativeExecutionReadError> {
    if slot.as_slice().is_empty() {
        CertifiedPrefix::initialize_admitted(slot, frame, chain_id, network, block, budget)?;
    }
    Ok(())
}

// Borrow the verified cursor while its original complete push validates this frame.
// The large unused pair is consumed after decoding, never on the active caller stack.
#[inline(never)]
fn advance_execution_read_prefix(
    prefix: &mut CertifiedPrefix,
    block: iroha_data_model::block::SharedSignedBlock,
    requested_height: u64,
    at_end: bool,
) -> Result<Option<AuthenticatedExecutionBlock>, NativeExecutionReadError> {
    prefix
        .push_with_finish(block, None, |step| {
            select_execution_read_receipt(step, requested_height, at_end)
        })?
        .map_err(Into::into)
}

#[inline(never)]
fn select_execution_read_receipt(
    step: CertifiedPrefixStep,
    requested_height: u64,
    at_end: bool,
) -> Result<Option<AuthenticatedExecutionBlock>, ChainReadError> {
    if !at_end {
        return Ok(None);
    }
    let (certified, genesis) = step.into_parts();
    let authority = if requested_height == GENESIS_HEIGHT {
        genesis
            .ok_or_else(|| ChainReadError::Malformed {
                height: requested_height,
                reason: "H2 did not supply the genesis execution anchor".into(),
            })?
            .into_authenticated_execution()
    } else {
        certified.into_authenticated_execution()?
    };
    Ok(Some(authority))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };

    #[test]
    fn signed_genesis_cannot_supply_execution_authority_without_h2() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let view = chain.state().view();
        let source = CertifiedChain::new(&view).unwrap();
        assert!(
            source
                .certified(1)
                .unwrap()
                .into_authenticated_execution()
                .is_err()
        );
        assert!(source.authenticated_execution(1).is_err());
    }

    #[test]
    fn genuine_successor_authenticates_both_original_execution_graphs() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        assert_independent_execution_reads(&chain);
        assert_consumed_execution_graphs(&chain);
    }

    fn assert_independent_execution_reads(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let source = CertifiedChain::new(&view).unwrap();
        for height in 1..=2 {
            let authenticated = source.authenticated_execution(height).unwrap();
            assert_eq!(authenticated.committed().height(), height);
            let original = source.committed(height).unwrap();
            // Independent reads may decode separate owned graphs. Their exact
            // canonical carrier, header identity and execution result must agree.
            assert_eq!(
                authenticated.block().encode_wire().unwrap(),
                original.block().encode_wire().unwrap(),
                "independent source reads retain the same exact certified frame"
            );
            assert_eq!(
                authenticated.committed().block_hash(),
                original.block_hash()
            );
            assert_eq!(authenticated.committed().core_hash(), original.core_hash());
            assert_eq!(authenticated.committed().result(), original.result());
        }
    }

    fn assert_consumed_execution_graphs(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let source = CertifiedChain::new(&view).unwrap();
        // Consuming each verification receipt must retain its original graph. Separate
        // physical reads above need not share one allocation or a process-local cache.
        let original_genesis = Clone::clone(chain.committed(GENESIS_HEIGHT).block());
        let original_successor = Clone::clone(chain.committed(GENESIS_HEIGHT + 1).block());
        let mut prefix = CertifiedPrefix::new(
            view.chain_id(),
            *view.network_id(),
            Clone::clone(&original_genesis),
        )
        .unwrap();
        let (certified, genesis) = prefix
            .push(Clone::clone(&original_successor))
            .unwrap()
            .into_parts();
        let genesis = genesis.expect("actual H2 authenticates genesis execution");
        let authenticated_genesis = genesis.into_authenticated_execution();
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            authenticated_genesis.block(),
            &original_genesis
        ));
        let authenticated_successor = certified.into_authenticated_execution().unwrap();
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            authenticated_successor.block(),
            &original_successor
        ));
        for (height, authenticated) in [(1, &authenticated_genesis), (2, &authenticated_successor)]
        {
            assert_eq!(authenticated.committed().height(), height);
            assert_eq!(
                authenticated.block().encode_wire().unwrap(),
                source
                    .committed(height)
                    .unwrap()
                    .block()
                    .encode_wire()
                    .unwrap()
            );
        }
    }
    #[test]
    fn bounded_native_source_authenticates_original_h1_and_h2_frames() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let frames = (1..=2)
            .map(|height| chain.committed(height).block().encode_wire().unwrap())
            .collect::<Vec<_>>();
        let total = frames.iter().map(|wire| wire.len() as u64).sum::<u64>();
        let limits = NativeExecutionReadLimits {
            admitted_target_wire_bytes: frames[0].len() as u64,
            max_source_blocks: 2,
            max_source_wire_bytes: total,
            max_frame_wire_bytes: frames.iter().map(|wire| wire.len() as u64).max().unwrap(),
        };
        for height in 1..=2 {
            let read = read_authenticated_execution(
                chain.kura(),
                view.chain_id(),
                *view.network_id(),
                view.block_hashes(),
                height,
                NativeExecutionReadLimits {
                    admitted_target_wire_bytes: frames[(height - 1) as usize].len() as u64,
                    ..limits
                },
                &chain.state().ivm_execution_budget(),
            )
            .unwrap();
            assert_eq!(read.wire.as_slice(), frames[(height - 1) as usize]);
            assert_eq!(read.authority.committed().height(), height);
            assert_eq!(read.source_blocks, 2);
            assert_eq!(read.source_wire_bytes, total);
        }
        for (limits, resource) in [
            (
                NativeExecutionReadLimits {
                    max_source_blocks: 1,
                    ..limits
                },
                NativeExecutionReadResource::SourceBlocks,
            ),
            (
                NativeExecutionReadLimits {
                    max_source_wire_bytes: total - 1,
                    ..limits
                },
                NativeExecutionReadResource::SourceWireBytes,
            ),
            (
                NativeExecutionReadLimits {
                    max_frame_wire_bytes: 0,
                    ..limits
                },
                NativeExecutionReadResource::FrameWireBytes,
            ),
        ] {
            assert!(
                matches!(read_authenticated_execution(chain.kura(), view.chain_id(), *view.network_id(), view.block_hashes(), 1, limits,
&chain.state().ivm_execution_budget(),),
                Err(NativeExecutionReadError::Capacity { resource: found, .. }) if found == resource)
            );
        }
    }

    #[test]
    fn bounded_source_refuses_foreign_cut_and_genesis_without_actual_h2() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let limits = NativeExecutionReadLimits {
            admitted_target_wire_bytes: 0,
            max_source_blocks: 2,
            max_source_wire_bytes: 8 * 1024 * 1024,
            max_frame_wire_bytes: 8 * 1024 * 1024,
        };
        {
            let view = chain.state().view();
            assert!(matches!(
                read_authenticated_execution(
                    chain.kura(),
                    view.chain_id(),
                    *view.network_id(),
                    view.block_hashes(),
                    1,
                    limits,
                    &chain.state().ivm_execution_budget(),
                ),
                Err(NativeExecutionReadError::Chain(
                    ChainReadError::NotCommitted { height: 2 }
                ))
            ));
        }
        chain.commit(Vec::new());
        let view = chain.state().view();
        let target_wire = chain
            .kura()
            .get_block(
                NonZeroUsize::new(2).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .expect("original block read attempt")
            .unwrap()
            .encode_wire()
            .unwrap();
        let limits = NativeExecutionReadLimits {
            admitted_target_wire_bytes: target_wire.len() as u64,
            ..limits
        };
        let mut hashes = view.block_hashes().iter().copied().collect::<Vec<_>>();
        hashes[1] = HashOf::from_untyped_unchecked(Hash::new(b"foreign committed cut"));
        assert!(matches!(
            read_authenticated_execution(
                chain.kura(),
                view.chain_id(),
                *view.network_id(),
                &hashes,
                2,
                limits,
                &chain.state().ivm_execution_budget(),
            ),
            Err(NativeExecutionReadError::Storage { height: 2, .. })
        ));
        assert!(matches!(
            read_authenticated_execution(
                chain.kura(),
                &ChainId::from("foreign-chain"),
                *view.network_id(),
                view.block_hashes(),
                2,
                limits,
                &chain.state().ivm_execution_budget(),
            ),
            Err(NativeExecutionReadError::Chain(
                ChainReadError::WrongInstance { height: 2 }
            ))
        ));
    }
    #[test]
    fn staged_native_h3_read_preserves_complete_prefix_and_exact_source_ceilings() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let view = chain.state().view();
        let frames = (1..=3)
            .map(|height| chain.committed(height).block().encode_wire().unwrap())
            .collect::<Vec<_>>();
        let total = frames.iter().map(|wire| wire.len() as u64).sum::<u64>();
        let maximum = frames.iter().map(|wire| wire.len() as u64).max().unwrap();
        let limits = NativeExecutionReadLimits {
            admitted_target_wire_bytes: frames[2].len() as u64,
            max_source_blocks: 3,
            max_source_wire_bytes: total,
            max_frame_wire_bytes: maximum,
        };
        let read = read_authenticated_execution(
            chain.kura(),
            view.chain_id(),
            *view.network_id(),
            view.block_hashes(),
            3,
            limits,
            &chain.state().ivm_execution_budget(),
        )
        .unwrap();
        let original = chain.committed(3);
        assert_eq!(read.wire.as_slice(), frames[2]);
        assert_eq!(read.authority.block().encode_wire().unwrap(), frames[2]);
        assert_eq!(
            read.authority.committed().block_hash(),
            original.block_hash()
        );
        assert_eq!(read.authority.committed().core_hash(), original.core_hash());
        assert_eq!(read.authority.committed().result(), original.result());
        assert_eq!(read.source_blocks, 3);
        assert_eq!(read.source_wire_bytes, total);
        for (limited, resource) in [
            (
                NativeExecutionReadLimits {
                    max_source_blocks: 2,
                    ..limits
                },
                NativeExecutionReadResource::SourceBlocks,
            ),
            (
                NativeExecutionReadLimits {
                    max_source_wire_bytes: total - 1,
                    ..limits
                },
                NativeExecutionReadResource::SourceWireBytes,
            ),
            (
                NativeExecutionReadLimits {
                    max_frame_wire_bytes: maximum - 1,
                    ..limits
                },
                NativeExecutionReadResource::FrameWireBytes,
            ),
        ] {
            assert!(matches!(
                read_authenticated_execution(chain.kura(), view.chain_id(), *view.network_id(), view.block_hashes(), 3, limited, &chain.state().ivm_execution_budget()),
                Err(NativeExecutionReadError::Capacity { resource: actual, .. }) if actual == resource
            ));
        }
        // The exact H3 target remains unchanged: both earlier source identities are
        // independently mandatory, even if the target and complete budgets still agree.
        for changed_height in [1, 2] {
            let mut cut = view.block_hashes().iter().copied().collect::<Vec<_>>();
            cut[changed_height - 1] = HashOf::from_untyped_unchecked(Hash::new(
                b"substituted intermediate execution source",
            ));
            assert!(matches!(
                read_authenticated_execution(chain.kura(), view.chain_id(), *view.network_id(), &cut, 3, limits, &chain.state().ivm_execution_budget()),
                Err(NativeExecutionReadError::Storage { height, .. }) if height == changed_height as u64
            ));
        }
    }

    #[test]
    fn target_length_substitution_is_refused_under_an_otherwise_sufficient_budget() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let original = chain.committed(2).block().encode_wire().unwrap();
        for admitted in [0, original.len() as u64 - 1, original.len() as u64 + 1] {
            let limits = NativeExecutionReadLimits {
                admitted_target_wire_bytes: admitted,
                max_source_blocks: 2,
                max_source_wire_bytes: 8 * 1024 * 1024,
                max_frame_wire_bytes: 8 * 1024 * 1024,
            };
            assert!(matches!(
                read_authenticated_execution(
                    chain.kura(),
                    view.chain_id(),
                    *view.network_id(),
                    view.block_hashes(),
                    2,
                    limits,
                    &chain.state().ivm_execution_budget(),
                ),
                Err(NativeExecutionReadError::Storage { height: 2, .. })
            ));
        }
    }
}
