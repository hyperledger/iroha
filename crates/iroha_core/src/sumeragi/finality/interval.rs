//! Finite original-owner contiguous full proofs with one native prefix and source join.
//!
//! This Core producer is a request-sized custody primitive, not a cache or HTTP
//! admission. Configured identity and an immutable captured State hash generation
//! come from its caller. Signed genesis and every original authority/QC/availability
//! check remain in CertifiedChain. A digest only joins freshly read physical bytes
//! to those completed checks; it never authenticates a frame independently.

use super::{NativeFinalityProofBudget, ProofDestinationError, proof_destination::OwnedProof};
use crate::{
    execution_attempt::ExecutionAttemptError,
    kura::Kura,
    state::{BlockHashRead, StateView},
    sumeragi::certified_chain::{CertifiedChain, ChainReadError, QcVerification},
};
#[cfg(not(all(test, sumeragi_core_mutation = "HC211")))]
use crate::{
    execution_attempt::kura_read_attempt_error,
    sumeragi::certified_chain::{proof_source_append, proof_source_start},
};
use iroha_allocation::{ChargedBuffer, ChargedBufferError};
#[cfg(not(all(test, sumeragi_core_mutation = "HC211")))]
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    sumeragi_finality::{MAX_FINALITY_BLOCK_BYTES, SumeragiFinalityProof},
};
use iroha_model_base::chain::ChainId;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

/// Borrowed configured identity, original immutable State hash cut and durable source.
///
/// The caller retains the actual frozen/versioned hash owner, never World or a writer
/// guard. These inputs grant no execution/epoch authority; the sole native kernel
/// authenticates the complete signed-genesis prefix. Latest Kura metadata cannot
/// substitute for the captured configured network/chain and hash generation.
#[derive(Clone, Copy)]
pub struct NativeFinalityProofSource<'source> {
    chain_id: &'source ChainId,
    network: &'source NetworkId,
    hashes: &'source dyn BlockHashRead,
    kura: &'source Kura,
}
impl<'source> NativeFinalityProofSource<'source> {
    /// Borrow the original caller-owned cut without cloning history or authority.
    pub fn new(
        chain_id: &'source ChainId,
        network: &'source NetworkId,
        hashes: &'source dyn BlockHashRead,
        kura: &'source Kura,
    ) -> Self {
        Self {
            chain_id,
            network,
            hashes,
            kura,
        }
    }
}

/// Explicit finite request bounds supplied by the original admission owner.
///
/// At most 64 consecutive outputs are retained. Neither wire extents nor these
/// bounds create allocation credits or extend the original absolute deadline.
/// The response extent sums canonical individual proof frames; a future HTTP batch
/// must separately admit/count its exact outer framing and actual response body.
#[derive(Clone, Copy, Debug)]
pub struct NativeFinalityProofIntervalLimits {
    from: u64,
    to: u64,
    maximum_wire_bytes: usize,
    maximum_response_bytes: usize,
    deadline: Instant,
}
impl NativeFinalityProofIntervalLimits {
    /// Exact final historical membership checked by the State wrapper.
    pub(crate) fn final_height(&self) -> u64 {
        self.to
    }
    /// Check the original stop policy without entering State or native I/O.
    pub(crate) fn check(
        &self,
        cancelled: &AtomicBool,
    ) -> Result<(), NativeFinalityProofIntervalError> {
        check(self.deadline, cancelled)
    }

    /// Validate the finite interval and existing independent canonical block ceiling.
    ///
    /// # Errors
    /// Rejects reversed intervals, more than 64 outputs or a larger native block cap.
    pub fn new(
        from: NonZeroU64,
        to: NonZeroU64,
        maximum_wire_bytes: NonZeroUsize,
        maximum_response_bytes: NonZeroUsize,
        deadline: Instant,
    ) -> Result<Self, NativeFinalityProofIntervalError> {
        let count = to
            .get()
            .checked_sub(from.get())
            .and_then(|count| count.checked_add(1))
            .ok_or(NativeFinalityProofIntervalError::Request)?;
        if count > 64 || maximum_wire_bytes.get() > MAX_FINALITY_BLOCK_BYTES {
            return Err(NativeFinalityProofIntervalError::Request);
        }
        Ok(Self {
            from: from.get(),
            to: to.get(),
            maximum_wire_bytes: maximum_wire_bytes.get(),
            maximum_response_bytes: maximum_response_bytes.get(),
            deadline,
        })
    }
}

/// Heapless native refusal retained after the verifier's funded graphs retire.
///
/// Dynamic diagnostic text belongs to the active verifier phase. The finite
/// producer preserves the failed native relation and height without transferring
/// a String out of that phase's physical custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeFinalityProofRefusal {
    /// The requested height is outside the captured chain.
    #[error("height {height} is not committed in this view")]
    NotCommitted {
        /// Original requested height.
        height: u64,
    },
    /// The captured original is unavailable.
    #[error("Kura does not hold the block this view committed at {height}")]
    NotInView {
        /// Original requested height.
        height: u64,
    },
    /// The original has no embedded certificate.
    #[error("the block at {height} carries no commit certificate")]
    MissingCertificate {
        /// Original requested height.
        height: u64,
    },
    /// An original certificate field is not canonical or well formed.
    #[error("the commit certificate at {height} is malformed")]
    Malformed {
        /// Original requested height.
        height: u64,
    },
    /// The certified header differs from the original.
    #[error("the certified header does not match the block at {height}")]
    HeaderMismatch {
        /// Original requested height.
        height: u64,
    },
    /// The certified result digest differs.
    #[error("the result preimage at {height} does not hash to the certified result")]
    ResultMismatch {
        /// Original requested height.
        height: u64,
    },
    /// The result does not commit the original execution.
    #[error("the certified result at {height} does not commit the stored block")]
    ExecutionMismatch {
        /// Original requested height.
        height: u64,
    },
    /// The certificate belongs to a different instance.
    #[error("the block at {height} is certified for another chain instance")]
    WrongInstance {
        /// Original requested height.
        height: u64,
    },
    /// The original does not extend its parent.
    #[error("the block at {height} does not extend its parent")]
    Discontinuous {
        /// Original requested height.
        height: u64,
    },
    /// Signed genesis does not authenticate the configured network.
    #[error("Kura's genesis is not this view's network genesis")]
    ForeignGenesis,
    /// The scheduled authority cannot be formed.
    #[error("no committee for height {height}")]
    Committee {
        /// Original requested height.
        height: u64,
    },
    /// Preserve the exact typed native certificate check.
    #[error("the commit certificate at {height} does not verify: {error:?}")]
    Certificate {
        /// Original requested height.
        height: u64,
        /// Exact failed certificate relation.
        error: iroha_sumeragi::crypto::CertError,
    },
    /// Projection requires completed native certification.
    #[error("height {0} lacks an independently verified commit certificate")]
    UnverifiedCommittee(u64),
}

impl From<ChainReadError> for NativeFinalityProofRefusal {
    fn from(error: ChainReadError) -> Self {
        match error {
            ChainReadError::NotCommitted { height } => Self::NotCommitted { height },
            ChainReadError::NotInView { height } => Self::NotInView { height },
            ChainReadError::MissingCertificate { height } => Self::MissingCertificate { height },
            ChainReadError::Malformed { height, reason: _ } => Self::Malformed { height },
            ChainReadError::HeaderMismatch { height } => Self::HeaderMismatch { height },
            ChainReadError::ResultMismatch { height } => Self::ResultMismatch { height },
            ChainReadError::ExecutionMismatch { height } => Self::ExecutionMismatch { height },
            ChainReadError::WrongInstance { height } => Self::WrongInstance { height },
            ChainReadError::Discontinuous { height } => Self::Discontinuous { height },
            ChainReadError::ForeignGenesis => Self::ForeignGenesis,
            ChainReadError::Committee { height, reason: _ } => Self::Committee { height },
            ChainReadError::Certificate { height, error } => Self::Certificate { height, error },
        }
    }
}

/// Closed failure of one finite original-owner proof operation.
#[derive(Debug, thiserror::Error)]
pub enum NativeFinalityProofIntervalError {
    /// Invalid finite interval or explicit source/response extent.
    #[error("finite finality interval bound is invalid")]
    Request,
    /// Original absolute deadline expired between bounded physical operations.
    #[error("finite finality interval deadline expired")]
    Deadline,
    /// The original request owner withdrew before the next operation.
    #[error("finite finality interval was cancelled")]
    Cancelled,
    /// Fresh canonical source bytes no longer join the verified original prefix.
    #[error("finite finality interval source changed at height {height}")]
    Source {
        /// Original height whose source or complete journal image differs.
        height: u64,
    },
    /// Original native verifier refused.
    #[error(transparent)]
    Native(#[from] NativeFinalityProofRefusal),
    /// Retain the original local refusal and physical release provenance.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Exact original response graph destination refused.
    #[error(transparent)]
    Destination(#[from] ProofDestinationError),
    /// Actual retained cursor or response-array backing refused.
    #[error(transparent)]
    Backing(#[from] ChargedBufferError),
}
impl From<ExecutionAttemptError<ChainReadError>> for NativeFinalityProofIntervalError {
    fn from(error: ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(error) => Self::Native(error.into()),
            ExecutionAttemptError::Deferred(local) => Self::Deferred(local),
        }
    }
}

/// Move-only full proofs whose actual response allocations retain the original pool.
///
/// Safe access borrows only. A cloned public DTO is separate storage and requires its
/// own admission. Prefix owners retire before return; the final fresh source join
/// covers the complete authenticated prefix. This does not confer continued source
/// availability after return or authenticate a remotely supplied response trust root.
pub struct NativeFinalityProofInterval {
    proofs: ChargedBuffer<OwnedProof>,
    from: u64,
    // Proof allocations/control retire before the original request pool handles.
    _owner: NativeFinalityProofBudget,
}
impl NativeFinalityProofInterval {
    /// First exact historical height represented by this response.
    pub fn from_height(&self) -> u64 {
        self.from
    }
    /// Number of consecutive full proofs, always between 1 and 64.
    pub fn len(&self) -> usize {
        self.proofs.as_slice().len()
    }
    /// Whether this owner has no proofs; successful construction is always nonempty.
    pub fn is_empty(&self) -> bool {
        self.proofs.as_slice().is_empty()
    }
    /// Borrow one full proof under its unchanged original response charge ledger.
    pub fn proof(&self, index: usize) -> Option<&SumeragiFinalityProof> {
        self.proofs.as_slice().get(index).map(|proof| &proof.proof)
    }
}

/// Produce a contiguous finite full-proof interval with one original native prefix.
///
/// Every target uses the shared target-before-gap kernel and complete native
/// certificate, committee, schedule and signed-availability checks. Work stops
/// between physical reads/decodes/crypto stages; an individual storage lock, allocator
/// or crypto call is not forcibly cancelled. The integrating physical worker must
/// keep its admission until it actually retires, including after HTTP cancellation.
/// No State view or replacement pool is constructed here. The original request
/// prepays the closed live-graph working set; only its bounded stage controls are
/// reusable after a physical phase retires. Truly inherited limits still apply.
/// Portable proofs are exact projections of this one native authority path;
/// consumers independently verify them, as the genuine producer regressions do.
///
/// # Errors
/// Preserves native typed refusals and completed authentication errors. Deadline,
/// cancellation, source change and response bound return no partial response.
pub fn build_proof_interval(
    source: &NativeFinalityProofSource<'_>,
    owner: &NativeFinalityProofBudget,
    limits: &NativeFinalityProofIntervalLimits,
    cancelled: &AtomicBool,
) -> Result<NativeFinalityProofInterval, NativeFinalityProofIntervalError> {
    build_interval(source, owner, limits, cancelled, || {})
}

fn build_interval(
    source: &NativeFinalityProofSource<'_>,
    owner: &NativeFinalityProofBudget,
    limits: &NativeFinalityProofIntervalLimits,
    cancelled: &AtomicBool,
    after_verified: impl FnOnce(),
) -> Result<NativeFinalityProofInterval, NativeFinalityProofIntervalError> {
    let budget = owner.frames();
    budget.with_deferred_refund_notifications(|_| {
        {
            let workspace = owner.workspace()?;
            let mut progress = || check(limits.deadline, cancelled);
            progress()?;
            // The backing covers the original inline cursor/control, not its nested
            // authority graph. No Box, additional pool or policy copy is introduced.
            let mut cursor = ChargedBuffer::<CertifiedChain<'_, StateView<'_>>>::new(1, budget)?;
            let mut chain = workspace.stage(|| {
                CertifiedChain::from_pinned_history_query(
                    source.chain_id,
                    source.network,
                    source.hashes,
                    source.kura,
                    budget,
                    limits.maximum_wire_bytes,
                )
            })?;
            progress()?;
            chain.enable_proof_source_cut();
            cursor.push_reserved(chain);
            let count = usize::try_from(limits.to - limits.from + 1)
                .map_err(|_| NativeFinalityProofIntervalError::Request)?;
            let mut proofs = ChargedBuffer::new(count, budget)?;
            let mut response_bytes = 0usize;
            let reader = &cursor.as_slice()[0];
            for height in limits.from..=limits.to {
                progress()?;
                let retained = reader.with_certified_workspace(
                    height,
                    &mut progress,
                    &workspace,
                    |certified| {
                        if !matches!(
                            (height, certified.verification()),
                            (1, QcVerification::Genesis) | (2.., QcVerification::Verified)
                        ) {
                            return Err(NativeFinalityProofIntervalError::Native(
                                NativeFinalityProofRefusal::UnverifiedCommittee(height),
                            ));
                        }
                        OwnedProof::new(
                            certified.block(),
                            &certified.commitment().schedule.current.committee,
                            budget,
                            limits.deadline,
                        )
                        .map_err(NativeFinalityProofIntervalError::from)
                    },
                )?;
                progress()?;
                let length = norito::canonical_frame_len(&retained.proof)
                    .map_err(|_| NativeFinalityProofIntervalError::Request)?;
                response_bytes = response_bytes
                    .checked_add(length)
                    .ok_or(NativeFinalityProofIntervalError::Request)?;
                if response_bytes > limits.maximum_response_bytes {
                    return Err(NativeFinalityProofIntervalError::Request);
                }
                proofs.push_reserved(retained);
            }
            let (verified_height, original_digest) = reader
                .proof_source_cut()
                .ok_or(NativeFinalityProofIntervalError::Source { height: limits.to })?;
            if verified_height != limits.to {
                return Err(NativeFinalityProofIntervalError::Source { height: limits.to });
            }
            // Test hooks can alter the physical source only after actual full native
            // verification. No graph or scalar from this hook authenticates output.
            after_verified();
            progress()?;
            #[cfg(all(test, sumeragi_core_mutation = "HC211"))]
            let _ = original_digest;
            #[cfg(not(all(test, sumeragi_core_mutation = "HC211")))]
            join_source(
                source,
                owner,
                limits,
                original_digest,
                &mut progress,
                &workspace,
            )?;
            progress()?;
            // Cursor/result/authority graphs retire after their physical guards, still
            // inside the original pool's refund fence, before exposing any response.
            drop(cursor);
            Ok(NativeFinalityProofInterval {
                proofs,
                from: limits.from,
                _owner: owner.clone(),
            })
        }
    })
}

fn check(
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(), NativeFinalityProofIntervalError> {
    #[cfg(all(test, sumeragi_core_mutation = "HC212"))]
    {
        let _ = (deadline, cancelled);
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC212")))]
    {
        if Instant::now() >= deadline {
            return Err(NativeFinalityProofIntervalError::Deadline);
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(NativeFinalityProofIntervalError::Cancelled);
        }
    }
    Ok(())
}

// One complete byte pass, with original namespace/index/object/start/length checks
// and a coherent journal-image bracket. Loss never selects another source/pool or
// returns previously verified graphs. This constant digest is only a local join.
#[cfg(not(all(test, sumeragi_core_mutation = "HC211")))]
fn join_source(
    source: &NativeFinalityProofSource<'_>,
    owner: &NativeFinalityProofBudget,
    limits: &NativeFinalityProofIntervalLimits,
    original: Hash,
    progress: &mut impl FnMut() -> Result<(), NativeFinalityProofIntervalError>,
    workspace: &super::FinalityDecodeWorkspace,
) -> Result<(), NativeFinalityProofIntervalError> {
    let unavailable = |height| NativeFinalityProofIntervalError::Source { height };
    let get = |height: u64| {
        let index = usize::try_from(height)
            .ok()
            .and_then(|at| at.checked_sub(1))
            .ok_or_else(|| unavailable(height))?;
        let expected = source
            .hashes
            .get(index)
            .ok_or_else(|| unavailable(height))?;
        source
            .kura
            .native_frame_read(height, *expected)
            .map_err(|error| {
                NativeFinalityProofIntervalError::from(kura_read_attempt_error(error, |_| {
                    ChainReadError::NotInView { height }
                }))
            })?
            .ok_or_else(|| unavailable(height))
    };
    progress()?;
    let first = get(1)?;
    let mut digest = proof_source_start();
    for height in 1..=limits.to {
        progress()?;
        let current = get(height)?;
        if !first.same_journal_image(&current) {
            return Err(unavailable(height));
        }
        let length = current.wire_len();
        if usize::try_from(length).map_or(true, |length| {
            length == 0 || length > limits.maximum_wire_bytes
        }) {
            return Err(unavailable(height));
        }
        let bytes = workspace.stage(|| {
            current
                .read_original(length, owner.frames())
                .map_err(|error| {
                    NativeFinalityProofIntervalError::from(kura_read_attempt_error(error, |_| {
                        ChainReadError::NotInView { height }
                    }))
                })?
                .ok_or_else(|| unavailable(height))
        })?;
        progress()?;
        digest = proof_source_append(digest, height, length, Hash::new(bytes.as_slice()));
    }
    progress()?;
    let after = get(1)?;
    if !first.same_journal_image(&after) || digest != original {
        return Err(unavailable(limits.to));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
