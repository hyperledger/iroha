//! Streaming original SCCP archive cut for restart reauthentication.
//!
//! The decoded snapshot supplies no historical authority. This owner walks the original
//! signed genesis and every native successor, then joins each exact archive delta to its
//! complete ordinary-write root. No historical NativeExecutionTip is constructed. All
//! pending archive backing belongs to the captured State's original pool. Ordinary carrier
//! bytes are released after one successful consume; no height-sized descriptor is allocated.

use super::*;
use crate::sumeragi::certified_chain::{CertifiedPrefix, CommittedBlock};
use iroha_data_model::block::{SharedSignedBlock, consensus::SumeragiRootScope};
use iroha_sumeragi::types::Hash32;

struct Pending {
    source: SharedSignedBlock,
    core: Hash32,
    result: Hash32,
    read: LanePayloadRead,
}
impl Pending {
    fn new(source: CommittedBlock, bytes: ChargedBuffer<u8>, capture: &HistoryCapture) -> Self {
        let read = LanePayloadRead::new(bytes, capture.budget.clone(), capture.network, &source);
        Self {
            source: source.block().clone(),
            core: source.core_hash(),
            result: source.result(),
            read,
        }
    }
}
/// One original committed carrier and exact funded archived preimage. No public constructor.
pub(crate) struct SccpCarrier {
    source: SharedSignedBlock,
    core: Hash32,
    result: Hash32,
    payload: LanePayload,
}
impl SccpCarrier {
    pub(crate) fn block(&self) -> &SharedSignedBlock {
        &self.source
    }
    pub(crate) fn core(&self) -> Hash32 {
        self.core
    }
    pub(crate) fn result(&self) -> Hash32 {
        self.result
    }
    #[cfg(test)]
    pub(crate) fn archive_source_bytes_for_test(&self) -> usize {
        self.payload.archive_source_bytes_for_test()
    }
    pub(crate) fn delta(&self) -> &[u8] {
        self.payload.sccp_delta()
    }
}

/// Read state retaining partial I/O, verified prefix and original bytes across local refusal.
/// A carrier is provisional until the complete prefix/tip check succeeds. Only the private
/// restoration reducer consumes it; no public restoration authority is returned mid-stream.
pub(crate) struct SccpHistoryRead {
    capture: HistoryCapture,
    archive: Option<NativeContextArchive>,
    read: Option<NativeContextRead>,
    ready: Option<SccpCarrier>,
    consumed: u64,
    #[cfg(test)]
    peak_retained_carriers: usize,
    prefix: Option<ChargedBuffer<CertifiedPrefix>>,
    current: Option<SharedSignedBlock>,
    bytes: Option<ChargedBuffer<u8>>,
    artifacts: Option<PrefixArtifactsRead>,
    genesis: Option<ChargedBuffer<u8>>,
    pending: [Option<Pending>; 2],
    next: u64,
    complete: bool,
}
impl SccpHistoryRead {
    /// Only the existing original-State capture can start this reader; no caller root/grant.
    pub(in crate::sumeragi) fn new(capture: HistoryCapture) -> Self {
        Self {
            capture,
            archive: None,
            read: None,
            ready: None,
            consumed: 0,
            #[cfg(test)]
            peak_retained_carriers: 0,
            prefix: None,
            current: None,
            bytes: None,
            artifacts: None,
            genesis: None,
            pending: [None, None],
            next: 1,
            complete: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn from_original_state_for_test(state: &State) -> Self {
        let generation = state.state_view_generation();
        let view = state.view();
        Self::new(
            HistoryCapture::for_sccp(state, &view, generation)
                .unwrap()
                .unwrap(),
        )
    }
    #[cfg(test)]
    pub(crate) fn poll_for_test<E: From<Attempt<io::Error>>>(
        &mut self,
        consume: impl FnMut(&SccpCarrier, Hash32) -> Result<(), E>,
    ) -> Result<(), E> {
        self.poll(consume)
    }
    #[cfg(test)]
    pub(crate) fn consumed_for_test(&self) -> u64 {
        self.consumed
    }
    #[cfg(test)]
    pub(crate) fn sealed_for_test(&self) -> bool {
        self.complete
    }
    #[cfg(test)]
    pub(crate) fn retained_carriers_for_test(&self) -> usize {
        usize::from(self.ready.is_some())
            + self.pending.iter().filter(|p| p.is_some()).count()
            + usize::from(self.current.is_some())
    }
    #[cfg(test)]
    pub(crate) fn peak_retained_carriers_for_test(&self) -> usize {
        self.peak_retained_carriers
    }
    /// Consume each carrier once in order. A consumer refusal retains the exact authenticated
    /// carrier and leaves `consumed` unchanged; prefix verification is not repeated on retry.
    /// The consumer must likewise retain its own resumable stage before returning a refusal.
    pub(in crate::sumeragi) fn poll<E: From<Attempt<io::Error>>>(
        &mut self,
        mut consume: impl FnMut(&SccpCarrier, Hash32) -> Result<(), E>,
    ) -> Result<(), E> {
        loop {
            let next = self.read_next();
            #[cfg(test)]
            {
                self.peak_retained_carriers = self
                    .peak_retained_carriers
                    .max(self.retained_carriers_for_test());
            }
            next.map_err(E::from)?;
            if self.complete {
                return Ok(());
            }
            let source = self
                .ready
                .as_ref()
                .expect("one authenticated pending carrier");
            if source.block().header().height().get() != self.consumed + 1 {
                return Err(E::from(invalid("SCCP consume order changed").into()));
            }
            let instance = self.prefix.as_ref().expect("original prefix").as_slice()[0].instance();
            consume(source, instance)?;
            // This commit is infallible and follows consumer success. The exact payload is
            // retained if consume returns any error; no source is read or pushed twice.
            self.ready = None;
            self.consumed += 1;
        }
    }
    fn read_next(&mut self) -> Result<(), Attempt<io::Error>> {
        if self.complete || self.ready.is_some() {
            return Ok(());
        }
        if self.capture.original_tip.root_scope() != SumeragiRootScope::Global {
            return Err(invalid("SCCP restoration requires the original Global root").into());
        }
        if self.archive.is_none() && self.read.is_none() {
            self.archive = Some(
                NativeContextArchive::open_existing(
                    &self.capture.kura,
                    self.capture.budget.clone(),
                    self.capture.kura.native_context_archive_max_bytes(),
                )
                .map_err(archive_error)?,
            );
        }
        loop {
            // Prefix advancement occurs once. A later payload refusal retries this exact
            // original source, without rereading or revalidating a different carrier.
            for slot in &mut self.pending {
                let Some(pending) = slot.take() else {
                    continue;
                };
                match pending.read.authenticate() {
                    Ok(payload) => {
                        self.ready = Some(SccpCarrier {
                            source: pending.source,
                            core: pending.core,
                            result: pending.result,
                            payload,
                        });
                        return Ok(());
                    }
                    Err((read, error)) => {
                        *slot = Some(Pending {
                            read,
                            source: pending.source,
                            core: pending.core,
                            result: pending.result,
                        });
                        return Err(payload_error(error));
                    }
                }
            }
            if self.next > self.capture.original_tip.height() {
                break;
            }
            if self.current.is_none() {
                let index = usize::try_from(self.next)
                    .ok()
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| invalid("SCCP history height overflows"))?;
                let block = self
                    .capture
                    .kura
                    .get_block(index, &self.capture.budget)
                    .map_err(|error| error.map_rejection(io::Error::other))?
                    .ok_or_else(|| invalid("original SCCP carrier is missing"))?;
                let length = norito::canonical_frame_len(block.as_ref())
                    .map_err(invalid)?
                    .checked_add(1)
                    .ok_or_else(|| invalid("SCCP carrier length overflows"))?;
                if length > MAX_FINALITY_BLOCK_BYTES {
                    return Err(invalid("SCCP carrier exceeds canonical reader bound").into());
                }
                self.current = Some(block);
            }
            let block = self.current.as_ref().expect("original carrier");
            if self.bytes.is_none() {
                if self.read.is_none() {
                    self.read = Some(
                        self.archive
                            .take()
                            .expect("original archive")
                            .read_job(self.next, block.hash()),
                    );
                }
                let bytes = loop {
                    match self.read.as_mut().expect("original read").poll() {
                        Ok(Some(bytes)) => break bytes,
                        Ok(None) => {}
                        Err(NativeContextArchiveError::Io(error))
                            if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(archive_error(error)),
                    }
                };
                self.archive = Some(self.read.take().expect("completed read").into_archive());
                self.bytes = Some(bytes);
            }
            if self.next == 1 {
                if self.prefix.is_none() {
                    self.prefix = Some(
                        CertifiedPrefix::new_admitted(
                            &self.capture.chain_id,
                            self.capture.network,
                            block.clone(),
                            &self.capture.budget,
                        )
                        .map_err(|error| error.map_rejection(invalid))?,
                    );
                }
                self.genesis = self.bytes.take();
            } else {
                let read = self.artifacts.take().unwrap_or_else(|| {
                    PrefixArtifactsRead::new(block.clone(), self.capture.budget.clone())
                });
                let artifacts = match read.complete(&self.capture.budget) {
                    Ok(value) => value,
                    Err((read, error)) => {
                        self.artifacts = Some(read);
                        return Err(prefix_error(error));
                    }
                };
                // Keep bytes in their fields until the native prefix accepts this exact input.
                let capture = &self.capture;
                let current_bytes = &mut self.bytes;
                let genesis_bytes = &mut self.genesis;
                let pending = &mut self.pending;
                self.prefix
                    .as_mut()
                    .expect("signed genesis prefix")
                    .as_mut_slice()[0]
                    .push_with_finish(block.clone(), Some(artifacts), |step| {
                        let (current, genesis) = step.into_parts();
                        let current = current.into_committed();
                        if current.height() == capture.original_tip.height()
                            && (current.block_hash() != capture.original_tip.iroha_hash()
                                || current.core_hash() != capture.original_tip.core_hash()
                                || current.result() != capture.original_tip.result()
                                || current.block_time_ms()
                                    != capture.original_tip.creation_time_ms()
                                || current.root_scope() != capture.original_tip.root_scope())
                        {
                            return Err(invalid("SCCP prefix differs from original captured tip"));
                        }
                        let current = Pending::new(
                            current,
                            current_bytes.take().expect("original bytes"),
                            capture,
                        );
                        if let Some(genesis) = genesis {
                            pending[0] = Some(Pending::new(
                                genesis.into_committed(),
                                genesis_bytes.take().expect("original genesis bytes"),
                                capture,
                            ));
                            pending[1] = Some(current);
                        } else {
                            pending[0] = Some(current);
                        }
                        Ok(())
                    })
                    .map_err(|error| error.map_rejection(invalid))??;
            }
            self.current = None;
            self.next = self
                .next
                .checked_add(1)
                .ok_or_else(|| invalid("SCCP history exhausted"))?;
        }
        self.archive
            .as_ref()
            .expect("complete archive")
            .recheck_namespace()
            .map_err(archive_error)?;
        if self.consumed != self.capture.original_tip.height() {
            return Err(invalid("SCCP history is incomplete").into());
        }
        self.complete = true;
        Ok(())
    }
    /// A sealed interval, never a claim inferred from a partial native prefix.
    pub(in crate::sumeragi) fn is_complete(&self) -> bool {
        self.complete
    }
    pub(in crate::sumeragi) fn tip_height(&self) -> u64 {
        self.capture.original_tip.height()
    }
    pub(crate) fn budget(&self) -> &AllocationBudget {
        &self.capture.budget
    }
    pub(crate) fn network(&self) -> iroha_data_model::NetworkId {
        self.capture.network
    }
}
