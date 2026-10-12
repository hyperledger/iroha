//! Original execution-walk custody with separate initialization and successor decode frames.
//!
//! The iterator borrows one captured State source and one source-admission callback. Its parent,
//! optional genesis successor and charged original coordinates retain exactly their old owners.
//! Separate work stages keep their large decoded temporaries off each other's native stack;
//! this changes neither the canonical decoder nor the resource and proof admission rules.

use super::*;

type Coordinate = (HashOf<IrohaHeader>, Hash32, Hash32, HeightContextId);

pub(super) struct OriginalExecutionWalk<'r, 'v, V: StateReadOnly + ?Sized, F> {
    chain: &'r CertifiedChain<'v, V>,
    from: NonZeroUsize,
    to: NonZeroUsize,
    before_read: F,
    next: Option<usize>,
    parent: Option<CommittedBlock>,
    successor: Option<CertifiedBlock>,
    originals: Option<iroha_allocation::ChargedBuffer<Coordinate>>,
    initialized: bool,
}

impl<'r, 'v, V, F> OriginalExecutionWalk<'r, 'v, V, F>
where
    V: StateReadOnly + ?Sized,
    F: FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
{
    pub(super) fn new(
        chain: &'r CertifiedChain<'v, V>,
        from: NonZeroUsize,
        to: NonZeroUsize,
        before_read: F,
    ) -> Self {
        Self {
            chain,
            from,
            to,
            before_read,
            next: Some(from.get()),
            parent: None,
            successor: None,
            originals: None,
            initialized: false,
        }
    }

    fn original_view(&self) -> Result<&'v V, ExecutionAttemptError<QueryExecutionFail>> {
        let ChainSource::State(view) = &self.chain.source else {
            return Err(invalid(
                "certificate walk requires original State authority",
            ));
        };
        if self.from > self.to || self.to.get() > view.height() {
            return Err(invalid("certificate interval is outside original State"));
        }
        Ok(*view)
    }

    // Keep reverse-source decoding separate from all ascending-successor temporaries. In a
    // debug build the former single branch-heavy closure used almost half a MiB on its own.
    #[inline(never)]
    fn initialize(&mut self, view: &V) -> Result<(), ExecutionAttemptError<QueryExecutionFail>> {
        let count = self.to.get() - self.from.get() + 1;
        if count > iroha_data_model::sumeragi::finality::NATIVE_FINALITY_MAX_BLOCK_COUNT {
            return Err(ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ));
        }
        let bytes = core::alloc::Layout::array::<Coordinate>(count)
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                )
            })?
            .size();
        // Preserve the inherited cumulative admission before actual original-pool funding.
        // Neither limit is replenished by starting another source frame.
        norito::core::reserve_decode_allocation(bytes).map_err(|error| {
            crate::execution_attempt::norito_decode_attempt_error(error, |error| {
                QueryExecutionFail::Conversion(error.to_string())
            })
        })?;
        self.originals = Some(
            iroha_allocation::ChargedBuffer::new(count, &view.execution_budget()).map_err(
                |error| {
                    ExecutionAttemptError::Deferred(match error {
                        iroha_allocation::ChargedBufferError::Admission(original) => {
                            original.into()
                        }
                        iroha_allocation::ChargedBufferError::Allocator { .. } => {
                            ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                        }
                    })
                },
            )?,
        );
        let parent_height = self.from.get().saturating_sub(1).max(1);
        let from = self.from;
        let originals = &mut self.originals;
        let parent = &mut self.parent;
        view.canonical_history().visit_executed_backwards(
            NonZeroUsize::new(parent_height).expect("nonzero parent"),
            self.to,
            &mut self.before_read,
            |receipt| {
                if receipt.height() >= from.get() as u64 {
                    originals
                        .as_mut()
                        .expect("coordinates admitted before source I/O")
                        .push_reserved((
                            receipt.block_hash(),
                            receipt.core_hash(),
                            receipt.result(),
                            receipt.id(),
                        ));
                }
                if receipt.height() == parent_height as u64 {
                    *parent = Some(receipt);
                }
                Ok(())
            },
        )?;
        if self
            .originals
            .as_ref()
            .expect("admitted coordinates")
            .as_slice()
            .len()
            != count
        {
            return Err(invalid("original certificate interval is incomplete"));
        }
        self.initialized = true;
        Ok(())
    }

    #[inline(never)]
    fn read_successor(
        &mut self,
        view: &V,
        height: usize,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>> {
        let block = view.canonical_history().block_with_admission(
            NonZeroUsize::new(height).expect("nonzero successor"),
            &mut self.before_read,
        )?;
        let current = read_frame(block, height as u64, self.chain.root_scope())
            .map_err(|error| verification_attempt_failure(VerificationReadError::from(error)))?;
        self.chain
            .verify_executed_successor(self.parent.as_ref().unwrap(), current)
            .map_err(verification_attempt_failure)
    }

    #[inline(never)]
    fn genesis(
        &mut self,
        view: &V,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>> {
        // A local signed genesis body cannot authenticate its result on its own. Retain its
        // authenticated H2 successor in the same iterator before yielding the original H1.
        self.successor = Some(self.read_successor(view, 2)?);
        let committed = self.parent.take().unwrap();
        let certificate_len = norito::canonical_frame_len(
            committed
                .block()
                .commit_certificate()
                .ok_or_else(|| invalid("original genesis result certificate is absent"))?,
        )
        .map_err(|error| verification_attempt_failure(verification_codec_error(1, error)))?;
        Ok(CertifiedBlock {
            committed,
            commit_qc: None,
            verification: QcVerification::Genesis,
            certificate_len,
        })
    }

    #[inline(never)]
    fn successor(
        &mut self,
        view: &V,
        height: usize,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>> {
        let certified = if let Some(successor) = self.successor.take() {
            successor
        } else {
            self.read_successor(view, height)?
        };
        self.check_successor(&certified, height)?;
        Ok(certified)
    }

    // Borrow the completed receipt so the initial successor decoder does not overlap with
    // the independent parent-refresh decoder's fixed temporaries. Neither stage clones the
    // receipt or changes its original source/allowance owner.
    #[inline(never)]
    fn check_successor(
        &mut self,
        certified: &CertifiedBlock,
        height: usize,
    ) -> Result<(), ExecutionAttemptError<QueryExecutionFail>> {
        if self
            .originals
            .as_ref()
            .expect("admitted coordinates")
            .as_slice()
            .get(self.to.get() - height)
            != Some(&(
                certified.block_hash(),
                certified.core_hash(),
                certified.result(),
                certified.id(),
            ))
        {
            return Err(invalid(
                "certificate differs from its original execution result",
            ));
        }
        if height < self.to.get() {
            // Retain through the existing bounded original codec, not an infallible deep clone.
            // No source I/O or QC verification is repeated, and the same cumulative scope funds it.
            self.parent = Some(
                read_frame(
                    certified.block().clone(),
                    height as u64,
                    self.chain.root_scope(),
                )
                .map_err(|error| {
                    verification_attempt_failure(VerificationReadError::from(error))
                })?,
            );
        }
        Ok(())
    }

    fn advance(
        &mut self,
        height: usize,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>> {
        let view = self.original_view()?;
        if !self.initialized {
            self.initialize(view)?;
        }
        if height == 1 {
            self.genesis(view)
        } else {
            self.successor(view, height)
        }
    }
}

impl<V, F> Iterator for OriginalExecutionWalk<'_, '_, V, F>
where
    V: StateReadOnly + ?Sized,
    F: FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
{
    type Item = Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>>;

    fn next(&mut self) -> Option<Self::Item> {
        let height = self.next?;
        let result = self.advance(height);
        self.next = if result.is_ok() && height < self.to.get() {
            height.checked_add(1)
        } else {
            None
        };
        if self.next.is_none() {
            // Refund scratch on success or failure even while the exhausted iterator survives.
            // Returned receipts retain only their own owners; drop also releases a partial walk.
            self.originals = None;
            self.parent = None;
            self.successor = None;
        }
        Some(result)
    }
}

fn invalid(message: &str) -> ExecutionAttemptError<QueryExecutionFail> {
    ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message.into()))
}
