//! One original certified carrier and archive acquisition, retained across local refusal.
//!
//! The portable proof's complete backing is prepaid before copying its authenticated fields.
//! A final namespace refusal retains that complete graph; delivery still requires every
//! original source guard. The actual certified reader retains completed terminal target/gap
//! work across local refusal. Constructor genesis bytes/body survive initial refusal and
//! prefix retries; partial genesis-result/authority, certificate/schedule work and full
//! native-prefix graph funding remain distinct custody boundaries.
//! TODO(S8): connect this owned acquisition to the durable validator-relay owner; detachment
//! supplies no transaction-signing, fee, permission or restart-publication authority.

use std::{fmt, ops::Range};

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedBuffer, PrepaidBufferError, RetainedPayload,
};
use iroha_data_model::{
    block::consensus::ExecWitness,
    sumeragi_amx::{AllocatedAmxRecordProofV1, AmxProofAllocationErrorV1, AmxRecordKind},
    sumeragi_finality::{NativeLaneStateProof, NativeLaneStateProofError},
};

use super::ordinary_writes::{self, CastingOwner, WriteDecodeError};
use crate::{
    execution_attempt::ExecutionAttemptError,
    query::native_context_archive::{
        NativeContextArchive, NativeContextArchiveError, NativeContextRead,
    },
    state::StateReadOnly,
    sumeragi::certified_chain::{
        AmxChainInitialization, CertifiedBlock, CertifiedChain, ChainReadError,
    },
};

/// Exact source, canonical or physical cause; none becomes record absence.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxRecordProofErrorV1 {
    /// Original native certificate or prefix verification refused.
    #[error(transparent)]
    Chain(#[from] ExecutionAttemptError<ChainReadError>),
    /// Retained descriptor, namespace, I/O or original-pool archive read refused.
    #[error(transparent)]
    Archive(#[from] NativeContextArchiveError),
    /// Original complete write graph demand was not admitted.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// A prepaid original write allocation refused materialization.
    #[error(transparent)]
    Materialization(#[from] PrepaidBufferError),
    /// Canonical frame or the caller's unchanged cumulative allowance refused.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Complete lane commitment or its actual same-pool scratch refused.
    #[error(transparent)]
    Lane(#[from] NativeLaneStateProofError),
    /// Exact portable proof fields or same-pool tree scratch refused.
    #[error(transparent)]
    Proof(#[from] AmxProofAllocationErrorV1),
    /// The immutable carrier, source or private allocation plan is inconsistent.
    #[error("native AMX proof source: {0}")]
    Source(&'static str),
}
impl From<WriteDecodeError> for NativeAmxRecordProofErrorV1 {
    fn from(cause: WriteDecodeError) -> Self {
        match cause {
            WriteDecodeError::ForeignPool => Self::Source("foreign original write pool"),
            WriteDecodeError::PlanChanged => Self::Source("original write allocation plan changed"),
            WriteDecodeError::Codec(cause) => Self::Codec(cause),
            WriteDecodeError::Admission(cause) => {
                #[cfg(all(test, sumeragi_core_mutation = "HC147"))]
                {
                    let _ = cause;
                    Self::Source("mutated original write admission")
                }
                #[cfg(not(all(test, sumeragi_core_mutation = "HC147")))]
                {
                    Self::Admission(cause)
                }
            }
            WriteDecodeError::Materialization(cause) => Self::Materialization(cause),
        }
    }
}

/// Bounded acquisition is distinct from authenticated absence or a completed proof.
#[derive(Debug)]
pub enum NativeAmxRecordProofPollV1 {
    /// The original descriptor acquired at most one 4096-byte prefix.
    Pending,
    /// All carrier/archive checks completed; `None` means authenticated absence.
    Complete(Option<AllocatedAmxRecordProofV1>),
}

/// Issuance is distinct from completing a proof or authenticating record absence.
///
/// A refused issuance still owns the exact certified carrier and first selected archive
/// descriptor. Its original cause is returned unchanged; further polling must pass every
/// original namespace, decoder, pool and proof check. No variant grants relay authority.
#[derive(Debug)]
#[must_use = "retain the issued job and its exact refusal until explicit recovery or retirement"]
pub enum NativeAmxRecordProofIssuedV1 {
    /// The same acquired job moved without a new read or allocation.
    Acquired(NativeAmxRecordProofOwnedV1),
    /// A genuine archive poll selected the original descriptor but could not complete.
    Refused {
        /// Exact pending carrier, descriptor and any acquired backing, never a replacement.
        original: NativeAmxRecordProofOwnedV1,
        /// Exact first refusal, including a source or permanent failure requiring recovery.
        cause: NativeAmxRecordProofErrorV1,
    },
}

#[cfg(test)]
type PortableProofProbe<'v> = Box<dyn FnOnce(&Option<AllocatedAmxRecordProofV1>) + 'v>;

struct Projection {
    lane_range: Range<usize>,
    witness: RetainedPayload<ExecWitness>,
    _casting: CastingOwner,
}

// The sole proof engine has no State reference. Its carrier is issued only by the existing
// CertifiedChain reader; its descriptor, charged frame and all later stages move unchanged.
struct OriginalAmxSource {
    network_id: iroha_data_model::NetworkId,
    height: u64,
    kind: AmxRecordKind,
    transaction: [u8; 32],
    budget: AllocationBudget,
    certified: Option<CertifiedBlock>,
    read: Option<NativeContextRead>,
    bytes: Option<ChargedBuffer<u8>>,
    projection: Option<Projection>,
    // None: not built; Some(None): authenticated absence; Some(Some(_)): exact funded graph.
    // Delivery takes this slot only after every original namespace check succeeds.
    portable: Option<Option<AllocatedAmxRecordProofV1>>,
    authenticated: bool,
    completed: bool,
    source_started: bool,
}

/// Original State cut retained until its certified carrier and archive descriptor detach.
/// No Clone, replacement-source installation or payload extraction exists.
#[must_use = "dropping this owner abandons the exact pending native AMX proof"]
pub struct NativeAmxRecordProofReadV1<'v, V: StateReadOnly> {
    view: &'v V,
    initialization: Option<AmxChainInitialization<'v, V>>,
    chain: Option<CertifiedChain<'v, V>>,
    source: Option<OriginalAmxSource>,
    #[cfg(test)]
    portable_probe: Option<PortableProofProbe<'v>>,
}
impl<V: StateReadOnly> fmt::Debug for NativeAmxRecordProofReadV1<'_, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("NativeAmxRecordProofReadV1");
        if let Some(source) = &self.source {
            source.debug_fields(&mut debug);
        }
        debug
            .field("detached", &self.source.is_none())
            .finish_non_exhaustive()
    }
}

/// Move-only original native carrier/archive job, independent of the source State borrow.
///
/// Only the existing borrowed reader can issue this owner after prefix certification and a
/// genuine first bounded archive poll. It retains the same pool, descriptor, partial bytes,
/// witness and completed portable graph. No public constructor accepts a claimed carrier.
/// The caller keeps its original refund/publication scope through normal retirement of this
/// job and its delivered proof; detachment creates no new scope or release authority.
/// Native-prefix graph funding and durable relay/signing remain separate boundaries.
#[must_use = "dropping this owner abandons the exact pending native AMX proof"]
pub struct NativeAmxRecordProofOwnedV1 {
    source: OriginalAmxSource,
}
impl fmt::Debug for NativeAmxRecordProofOwnedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("NativeAmxRecordProofOwnedV1");
        self.source.debug_fields(&mut debug);
        debug.finish_non_exhaustive()
    }
}
impl NativeAmxRecordProofOwnedV1 {
    /// Resume the exact detached source; refusal retains every completed acquisition stage.
    ///
    /// # Errors
    /// The same typed source, namespace, pool, decoder or proof refusal as the borrowed reader.
    pub fn poll(&mut self) -> Result<NativeAmxRecordProofPollV1, NativeAmxRecordProofErrorV1> {
        #[cfg(test)]
        let mut probe = None;
        self.source.poll(
            #[cfg(test)]
            &mut probe,
        )
    }

    /// Deliver the original proof or authenticated absence once, without a StateView borrow.
    ///
    /// # Errors
    /// Original source/resource refusal; the mutable owner retains all unfinished stages.
    pub fn complete(
        &mut self,
    ) -> Result<Option<AllocatedAmxRecordProofV1>, NativeAmxRecordProofErrorV1> {
        loop {
            match self.poll()? {
                NativeAmxRecordProofPollV1::Pending => {}
                NativeAmxRecordProofPollV1::Complete(proof) => return Ok(proof),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn acquired_frame(&self) -> Option<&[u8]> {
        self.source.acquired_frame()
    }
}

impl<'v, V: StateReadOnly> NativeAmxRecordProofReadV1<'v, V> {
    pub(super) fn new(
        view: &'v V,
        height: u64,
        kind: AmxRecordKind,
        transaction: [u8; 32],
    ) -> Self {
        Self {
            view,
            initialization: None,
            chain: None,
            source: Some(OriginalAmxSource {
                network_id: *view.network_id(),
                height,
                kind,
                transaction,
                budget: view.prepared_contract_cache().execution_budget().clone(),
                certified: None,
                read: None,
                bytes: None,
                projection: None,
                portable: None,
                authenticated: false,
                completed: false,
                source_started: false,
            }),
            #[cfg(test)]
            portable_probe: None,
        }
    }

    // The same acquisition used by borrowed polling and detach. A refusal leaves every field
    // in this reader; already issued carrier/namespace owners are never reacquired.
    fn acquire_original_source(&mut self) -> Result<(), NativeAmxRecordProofErrorV1> {
        let source = self
            .source
            .as_mut()
            .ok_or(NativeAmxRecordProofErrorV1::Source(
                "native AMX proof already completed",
            ))?;
        source.require_pending()?;
        if self.chain.is_none() {
            if self.initialization.is_none() {
                self.initialization = Some(AmxChainInitialization::new(self.view)?);
            }
            self.chain = Some(
                self.initialization
                    .as_mut()
                    .expect("original constructor acquisition")
                    .complete()?,
            );
            // All charged source/body owners moved into the same chain. Retiring this
            // empty stage neither refunds backing nor releases an original decoder.
            self.initialization = None;
        }
        if source.certified.is_none() {
            source.certified = Some(
                self.chain
                    .as_mut()
                    .expect("original native reader")
                    .certified_terminal_amx(source.height)?,
            );
        }
        if source.read.is_none() {
            source.read = Some(
                NativeContextArchive::open_existing(
                    self.view.kura(),
                    source.budget.clone(),
                    self.view.kura().native_context_archive_max_bytes(),
                )?
                .read_job(
                    source.height,
                    source
                        .certified
                        .as_ref()
                        .expect("verified original carrier")
                        .block_hash(),
                ),
            );
        }
        Ok(())
    }

    /// Move the original acquired source into an independent owner exactly once.
    ///
    /// A genuine first archive poll pins the original record descriptor before detach. No
    /// extra read occurs if the caller already acquired a partial prefix, full frame, witness
    /// or portable proof. On refusal this reader retains its exact acquisition; retry does not
    /// construct a new source. Success retires this borrowed wrapper, which may then be dropped
    /// under its existing caller scope before its StateView. Its completed prefix verifier stays
    /// here until that normal drop: detachment does not refund prefix/genesis owners while the
    /// original State borrow is still live. In tests only, an armed borrowed portable probe prevents detach
    /// until it fires; a borrowed callback never escapes into an independent owner.
    ///
    /// # Errors
    /// Original certification/archive refusal, completed/detached selection, or an armed test
    /// observer. No failure consumes the caller's original acquisition or renews its limits.
    pub fn try_detach(
        &mut self,
    ) -> Result<NativeAmxRecordProofOwnedV1, NativeAmxRecordProofErrorV1> {
        #[cfg(test)]
        if self.portable_probe.is_some() {
            return Err(NativeAmxRecordProofErrorV1::Source(
                "borrowed portable observer must finish before detach",
            ));
        }
        self.acquire_original_source()?;
        let source = self.source.as_mut().expect("original source acquired");
        source
            .read
            .as_ref()
            .expect("original archive job")
            .recheck_namespace()?;
        if !source.source_started {
            source.acquire_bytes()?;
        }
        source
            .read
            .as_ref()
            .expect("original archive job")
            .recheck_namespace()?;
        #[cfg(all(test, sumeragi_core_mutation = "HC182"))]
        {
            source.bytes = None;
        }
        let source = self.source.take().expect("original source moves once");
        // The issued target carrier moves into the owned engine. Retain the completed prefix
        // in this retired wrapper until its normal scoped drop: uncached prefix/genesis bodies
        // can own original-pool charges which the target carrier alone does not retain.
        // No prefix refund/notification is introduced inside detachment.
        Ok(NativeAmxRecordProofOwnedV1 { source })
    }

    /// Issue the same independent job even when its genuine first archive poll refuses.
    ///
    /// Delegates once to `try_detach`; certification, descriptor selection, byte acquisition
    /// and all completed stages are the same owners. A refusal before native certification or
    /// actual file/length selection remains an error with this borrower intact. Once selected,
    /// a refused job and its exact cause move together; this is never a completed proof or
    /// authenticated absence. The completed prefix verifier remains in this retired borrowed
    /// wrapper until its normal scoped drop, as for `try_detach`.
    ///
    /// No extra poll occurs after a previous successful source poll. Namespace failure may
    /// move as an explicit refused outcome; restoring the original namespace remains mandatory
    /// before this same owned engine can deliver. Permanent source/limit failures do not gain
    /// a retry interval or alternate source. An armed borrowed test observer stays in its
    /// original borrower until it fires and can never escape into an independent owner.
    ///
    /// # Errors
    /// Original pre-issuance certification/archive refusal, completed selection, or an armed
    /// test observer; the exact acquisition remains with this borrower.
    pub fn try_issue(
        &mut self,
    ) -> Result<NativeAmxRecordProofIssuedV1, NativeAmxRecordProofErrorV1> {
        match self.try_detach() {
            Ok(original) => Ok(NativeAmxRecordProofIssuedV1::Acquired(original)),
            Err(cause) => {
                #[cfg(test)]
                if self.portable_probe.is_some() {
                    return Err(cause);
                }
                let Some(source) = self.source.as_mut() else {
                    return Err(cause);
                };
                if source.completed
                    || source.certified.is_none()
                    || !source
                        .read
                        .as_ref()
                        .is_some_and(NativeContextRead::has_pinned_source)
                {
                    return Err(cause);
                }
                #[cfg(all(test, sumeragi_core_mutation = "HC185"))]
                {
                    // Deliberately forget only the selected descriptor after a refused poll.
                    // Native certification and later authentication still run unchanged.
                    let read = source.read.take().expect("actual selected archive job");
                    source.read = Some(
                        read.into_archive().read_job(
                            source.height,
                            source
                                .certified
                                .as_ref()
                                .expect("actual certified carrier")
                                .block_hash(),
                        ),
                    );
                }
                let source = self
                    .source
                    .take()
                    .expect("original refused source moves once");
                Ok(NativeAmxRecordProofIssuedV1::Refused {
                    original: NativeAmxRecordProofOwnedV1 { source },
                    cause,
                })
            }
        }
    }

    /// Observe one actual completed portable construction, before its final namespace guard.
    /// This test-only seam cannot replace a source, proof, allocation pool or guard result.
    ///
    /// # Errors
    /// Refuses a second observation or an already prepared/delivered selection.
    #[cfg(test)]
    pub(crate) fn probe_portable_prepared_once(
        &mut self,
        probe: impl FnOnce(&Option<AllocatedAmxRecordProofV1>) + 'v,
    ) -> Result<(), NativeAmxRecordProofErrorV1> {
        let source = self
            .source
            .as_ref()
            .ok_or(NativeAmxRecordProofErrorV1::Source(
                "native AMX proof already completed",
            ))?;
        if source.completed || source.portable.is_some() || self.portable_probe.is_some() {
            return Err(NativeAmxRecordProofErrorV1::Source(
                "portable proof observation already selected",
            ));
        }
        self.portable_probe = Some(Box::new(probe));
        Ok(())
    }

    // Borrow the same authenticated complete write graph; no count supplied by .ami
    // can substitute for the original certified witness.
    #[cfg(not(all(test, sumeragi_core_mutation = "HC218")))]
    pub(super) fn authenticated_prepared_count(
        &self,
    ) -> Result<usize, NativeAmxRecordProofErrorV1> {
        let source = self
            .source
            .as_ref()
            .filter(|source| source.completed && source.authenticated)
            .ok_or(NativeAmxRecordProofErrorV1::Source(
                "Prepared count needs completed original verification",
            ))?;
        let projection = source
            .projection
            .as_ref()
            .ok_or(NativeAmxRecordProofErrorV1::Source(
                "original complete writes missing",
            ))?;
        crate::query::native_context_archive::prepared_intents::count(
            &projection.witness.get().writes,
        )
        .map_err(NativeAmxRecordProofErrorV1::Archive)
    }

    // Only this sibling reader can join an intent to the actual completed verification
    // engine. No caller-supplied hash/root receipt can assert certification.
    pub(super) fn matches_completed_execution(
        &self,
        carrier: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
        root: iroha_crypto::Hash,
    ) -> bool {
        self.source.as_ref().is_some_and(|source| {
            source.completed
                && source.authenticated
                && source.certified.as_ref().is_some_and(|certified| {
                    certified.block_hash() == carrier
                        && certified.commitment().execution.ordinary_writes_root == root
                })
        })
    }

    #[cfg(test)]
    pub(crate) fn acquired_frame(&self) -> Option<&[u8]> {
        self.source.as_ref()?.acquired_frame()
    }

    /// Resume the same source, retaining acquired bytes through every failed decode.
    ///
    /// # Errors
    /// Original source/resource refusal; all pending owners remain with this mutable borrow.
    pub fn poll(&mut self) -> Result<NativeAmxRecordProofPollV1, NativeAmxRecordProofErrorV1> {
        self.acquire_original_source()?;
        self.source
            .as_mut()
            .expect("original source acquired")
            .poll(
                #[cfg(test)]
                &mut self.portable_probe,
            )
    }

    /// Attempt completion without replacing the source on refusal.
    ///
    /// # Errors
    /// Original source/resource refusal; the exact pending job remains with this mutable borrow.
    pub fn complete(
        &mut self,
    ) -> Result<Option<AllocatedAmxRecordProofV1>, NativeAmxRecordProofErrorV1> {
        loop {
            match self.poll()? {
                NativeAmxRecordProofPollV1::Pending => {}
                NativeAmxRecordProofPollV1::Complete(proof) => return Ok(proof),
            }
        }
    }
}

impl OriginalAmxSource {
    #[cfg(test)]
    fn acquired_frame(&self) -> Option<&[u8]> {
        self.bytes
            .as_ref()
            .map(ChargedBuffer::as_slice)
            .or_else(|| self.read.as_ref()?.acquired_prefix())
    }

    fn debug_fields(&self, debug: &mut fmt::DebugStruct<'_, '_>) {
        debug
            .field("height", &self.height)
            .field("kind", &self.kind)
            .field("transaction", &self.transaction)
            .field("authenticated", &self.authenticated)
            .field("completed", &self.completed);
    }

    fn require_pending(&self) -> Result<(), NativeAmxRecordProofErrorV1> {
        if self.completed {
            return Err(NativeAmxRecordProofErrorV1::Source(
                "native AMX proof already completed",
            ));
        }
        if self.height < 2 {
            return Err(NativeAmxRecordProofErrorV1::Source(
                "AMX proof requires a certified non-genesis execution",
            ));
        }
        Ok(())
    }

    // This sole bounded read retains partial bytes inside NativeContextRead; a complete
    // frame moves into this same engine. A refused poll never acknowledges source_started.
    fn acquire_bytes(&mut self) -> Result<(), NativeAmxRecordProofErrorV1> {
        if let Some(bytes) = self
            .read
            .as_mut()
            .expect("original namespace and descriptor")
            .poll()?
        {
            self.bytes = Some(bytes);
        }
        self.source_started = true;
        Ok(())
    }

    fn poll(
        &mut self,
        #[cfg(test)] portable_probe: &mut Option<PortableProofProbe<'_>>,
    ) -> Result<NativeAmxRecordProofPollV1, NativeAmxRecordProofErrorV1> {
        use NativeAmxRecordProofErrorV1 as Error;
        self.require_pending()?;
        self.read
            .as_ref()
            .expect("original namespace and descriptor")
            .recheck_namespace()?;
        if self.bytes.is_none() {
            self.acquire_bytes()?;
            return Ok(NativeAmxRecordProofPollV1::Pending);
        }
        let certified = self.certified.as_ref().expect("verified original carrier");
        let read = self
            .read
            .as_mut()
            .expect("original namespace and descriptor");
        let bytes = self.bytes.as_ref().expect("original complete frame");
        if self.projection.is_none() {
            let projection = match ordinary_writes::decode_projection(bytes, &self.budget) {
                Ok(projection) => projection,
                Err(cause) => {
                    #[cfg(all(test, sumeragi_core_mutation = "HC148"))]
                    {
                        self.bytes = None;
                    }
                    return Err(cause.into());
                }
            };
            if projection.carrier_height != self.height
                || projection.carrier_hash != certified.block_hash()
                || !projection.witness.belongs_to(&self.budget)
                || !projection.casting_bindings.belongs_to(&self.budget)
            {
                return Err(Error::Source(
                    "archive differs from the certified carrier or original pool",
                ));
            }
            let start = (projection.lane_payload.as_ptr() as usize)
                .checked_sub(bytes.as_slice().as_ptr() as usize)
                .ok_or(Error::Source("original lane range"))?;
            let end = start
                .checked_add(projection.lane_payload.len())
                .ok_or(Error::Source("original lane range"))?;
            if bytes.as_slice().get(start..end) != Some(projection.lane_payload) {
                return Err(Error::Source(
                    "lane field does not borrow the original archive frame",
                ));
            }
            self.projection = Some(Projection {
                lane_range: start..end,
                witness: projection.witness,
                _casting: projection.casting_bindings,
            });
        }
        let projection = self
            .projection
            .as_ref()
            .expect("complete prepaid original writes");
        let root = certified.commitment().execution.ordinary_writes_root;
        if !self.authenticated {
            let path = NativeLaneStateProof::from_witness(projection.witness.get(), &self.budget)?;
            if !path.verify(self.network_id, self.height, root)
                || !path.matches_state_payload(
                    self.network_id,
                    self.height,
                    &bytes.as_slice()[projection.lane_range.clone()],
                )?
            {
                return Err(Error::Source(
                    "archive differs from complete certified execution",
                ));
            }
            self.authenticated = true;
        }
        read.recheck_namespace()?;
        if self.portable.is_none() {
            let certificate = certified
                .certificate()
                .ok_or(Error::Source("original carrier has no native certificate"))?;
            self.portable = Some(AllocatedAmxRecordProofV1::from_original_witness(
                certificate,
                projection.witness.get(),
                self.kind,
                self.transaction,
                root,
                &self.budget,
            )?);
            #[cfg(test)]
            if let Some(probe) = portable_probe.take() {
                probe(
                    self.portable
                        .as_ref()
                        .expect("actual completed portable construction"),
                );
            }
        }
        let namespace = read.recheck_namespace();
        #[cfg(all(test, sumeragi_core_mutation = "HC159"))]
        if namespace.is_err() {
            self.portable = None;
        }
        namespace?;
        let proof = self
            .portable
            .take()
            .ok_or(Error::Source("completed portable proof is not retained"))?;
        self.completed = true;
        Ok(NativeAmxRecordProofPollV1::Complete(proof))
    }
}

#[cfg(test)]
mod issuer_tests;

#[cfg(test)]
mod certification_tests;

#[cfg(test)]
mod certification_retry_tests;
