//! Read-only canonical lane frames for the existing isolated startup replay owner.

use super::*;
use crate::sumeragi::lanes::store::{BatchRead, LaneFrameRead};

struct SelectedRead {
    interest: ReadInterest,
    lane: LaneId,
    incarnation: [u8; 32],
    height: u64,
    reader: LaneFrameRead,
    ready: Option<BatchRead>,
}
impl SelectedRead {
    fn matches(&self, lane: LaneId, incarnation: &[u8; 32], height: u64) -> bool {
        self.lane == lane && self.incarnation == *incarnation && self.height == height
    }
    fn authenticate(&mut self) -> Result<(), Attempt<io::Error>> {
        if self.ready.is_none() {
            let (body, qc) = self.reader.poll()?;
            self.ready = Some(BatchRead { body, qc });
        }
        Ok(())
    }
}

/// The mutex only arbitrates ownership; native I/O and final authority Drop run outside it.
enum ReadSlot {
    Available(Option<SelectedRead>),
    InFlight,
}

/// Retain the same partial read across success, refusal and unwind without another allocation.
struct OriginalRead<'a> {
    slot: &'a Mutex<ReadSlot>,
    selected: Option<SelectedRead>,
}

impl Drop for OriginalRead<'_> {
    fn drop(&mut self) {
        let (previous, cancelled) = {
            let mut slot = self.slot.lock();
            // Cancellation and parking share this bookkeeping mutex. Native I/O and
            // final destruction never hold it, so an InFlight cancellation cannot be lost.
            let cancelled = if !cfg!(all(test, sumeragi_core_mutation = "HC437"))
                && self
                    .selected
                    .as_ref()
                    .is_some_and(|read| read.interest.cancelled())
            {
                self.selected.take()
            } else {
                None
            };
            let previous = std::mem::replace(&mut *slot, ReadSlot::Available(self.selected.take()));
            (previous, cancelled)
        };
        // Any unexpected displaced owner still drops after the actual mutex guard.
        debug_assert!(matches!(previous, ReadSlot::InFlight));
        drop(previous);
        drop(cancelled);
    }
}

/// One retained original read, never a lane store writer, queue or prefix authority.
/// The replay State supplies historical authority; exact committed global merge
/// references select heights. No directory scan, cache or observed tip grants authority.
pub(in crate::sumeragi) struct LaneFrameSource {
    root: PathBuf,
    network: NetworkId,
    chain_id: String,
    crypto: SharedCrypto,
    budget: AllocationBudget,
    authorities: Arc<dyn LaneStoreAuthorities>,
    read: Mutex<ReadSlot>,
}
impl LaneFrameSource {
    pub(in crate::sumeragi) fn new(
        root: PathBuf,
        network: NetworkId,
        chain_id: String,
        crypto: SharedCrypto,
        budget: AllocationBudget,
        authorities: Arc<dyn LaneStoreAuthorities>,
    ) -> Self {
        Self {
            root,
            network,
            chain_id,
            crypto,
            budget,
            authorities,
            read: Mutex::new(ReadSlot::Available(None)),
        }
    }

    fn original_read(&self) -> Result<OriginalRead<'_>, Attempt<io::Error>> {
        let mut slot = self.read.try_lock().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "original lane frame is busy")
        })?;
        let selected = match &mut *slot {
            ReadSlot::Available(original) => original.take(),
            ReadSlot::InFlight => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "original lane frame is busy",
                )
                .into());
            }
        };
        *slot = ReadSlot::InFlight;
        drop(slot);
        Ok(OriginalRead {
            slot: &self.read,
            selected,
        })
    }

    fn selected(
        &self,
        slot: &mut Option<SelectedRead>,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        requested: &ReadInterest,
    ) -> Result<(), Attempt<io::Error>> {
        if height == 0 {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "zero lane frame height").into(),
            );
        }
        if let Some(original) = slot.as_mut() {
            let same_height = original.matches(lane, incarnation, height);
            original.interest.join(requested, same_height)?;
            // A different request cannot discard an unfinished paid source. Finish
            // its exact canonical decoding first; reject corruption before switching.
            original.authenticate()?;
            if original.matches(lane, incarnation, height) {
                return Ok(());
            }
            original
                .ready
                .as_ref()
                .expect("authenticated original body")
                .decode_batch()?;
            *slot = None;
        }
        let instance = incarnation_instance(
            &*self.crypto,
            &self.network,
            &self.chain_id,
            lane,
            incarnation,
        );
        let authority = self
            .authorities
            .authority(lane, incarnation, instance)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "original lane authority is pending",
                )
            })?;
        if authority.schedule.instance() != instance {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "foreign historical lane schedule",
            )
            .into());
        }
        let reader = LaneFrameRead::open(
            &LaneFrameRead::path(&self.root, instance, height),
            height,
            Arc::clone(&self.crypto),
            self.budget.clone(),
            authority.schedule,
        )?;
        *slot = Some(SelectedRead {
            interest: requested.clone(),
            lane,
            incarnation: *incarnation,
            height,
            reader,
            ready: None,
        });
        let result = slot.as_mut().expect("original frame read").authenticate();
        // Initial absence returned from open before this slot was installed. Any
        // failure now belongs to the original open/read/authority owner and must
        // retain its exact partial backing, even when its I/O kind is NotFound.
        if cfg!(all(test, sumeragi_core_mutation = "HC418"))
            && result
                .as_ref()
                .is_err_and(|error| error.io_kind() == io::ErrorKind::NotFound)
        {
            *slot = None;
        }
        result
    }
}
impl LaneFrameSource {
    fn block_with_interest(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        requested: ReadInterest,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        self.budget.with_deferred_refund_notifications(|_| {
            let mut original_read = self.original_read()?;
            #[cfg(all(test, sumeragi_core_mutation = "HC402"))]
            let _held_read_mutex = self.read.lock();
            self.selected(
                &mut original_read.selected,
                lane,
                incarnation,
                height,
                &requested,
            )?;
            let original = original_read
                .selected
                .as_ref()
                .expect("authenticated original source");
            let read = original
                .ready
                .as_ref()
                .expect("authenticated original body");
            let batch = read.decode_batch()?;
            let result = CommittedLaneBlock {
                block_hash: read.qc.block_hash,
                result: read.qc.result,
                batch,
            };
            original_read.selected = None;
            Ok(Some(result))
        })
    }
    fn wait_with_interest(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        requested: ReadInterest,
    ) -> Result<bool, Attempt<io::Error>> {
        // One finite read attempt. The enclosing original replay/producer owns
        // scheduling and the absolute deadline; this reader never sleeps or spins.
        self.budget.with_deferred_refund_notifications(|_| {
            let mut original_read = self.original_read()?;
            #[cfg(all(test, sumeragi_core_mutation = "HC402"))]
            let _held_read_mutex = self.read.lock();
            self.selected(
                &mut original_read.selected,
                lane,
                incarnation,
                height,
                &requested,
            )
            .map(|()| true)
        })
    }
}

impl LaneBlockSource for LaneFrameSource {
    fn tip(&self, _: LaneId, _: &[u8; 32]) -> Result<Option<u64>, Attempt<io::Error>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "read-only replay has no proposal-selection tip authority",
        )
        .into())
    }
    fn block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        self.block_with_interest(lane, incarnation, height, ReadInterest::Historical)
    }
    fn proposal_block(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: u64,
        _: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "read-only replay has no proposal-selection authority",
        )
        .into())
    }
    fn execution_block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        request: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        self.block_with_interest(
            lane,
            incarnation,
            height,
            ReadInterest::proposal(request, &self.budget)?,
        )
    }
    fn execution_wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        _: Duration,
        request: &ProposalReadScope,
    ) -> Result<bool, Attempt<io::Error>> {
        self.wait_with_interest(
            lane,
            incarnation,
            height,
            ReadInterest::proposal(request, &self.budget)?,
        )
    }
    fn release_cancelled_proposal_reads(&self) {
        self.budget.with_deferred_refund_notifications(|_| {
            let cancelled = {
                // This is only the Available/InFlight handoff, never the physical read.
                // Serialize with parking so cancellation cannot miss its final transfer.
                let mut slot = self.read.lock();
                match &mut *slot {
                    ReadSlot::Available(original)
                        if original
                            .as_ref()
                            .is_some_and(|read| read.interest.cancelled()) =>
                    {
                        original.take()
                    }
                    // An active original owner performs this same cleanup before returning.
                    ReadSlot::Available(_) | ReadSlot::InFlight => None,
                }
            };
            drop(cancelled);
        });
    }
    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        _: Duration,
    ) -> Result<bool, Attempt<io::Error>> {
        self.wait_with_interest(lane, incarnation, height, ReadInterest::Historical)
    }
}

#[cfg(test)]
impl LaneFrameSource {
    /// Probe the actual read mutex without blocking a failing destructor control.
    pub(super) fn read_lock_available_for_test(&self) -> bool {
        self.read.try_lock().is_some()
    }
}
