//! Read-only canonical lane frames for the existing isolated startup replay owner.

use super::*;
use crate::sumeragi::lanes::store::{BatchRead, LaneFrameRead};

struct SelectedRead {
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
    read: Mutex<Option<SelectedRead>>,
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
            read: Mutex::new(None),
        }
    }

    fn selected(
        &self,
        slot: &mut Option<SelectedRead>,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<(), Attempt<io::Error>> {
        if height == 0 {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "zero lane frame height").into(),
            );
        }
        if let Some(original) = slot.as_mut() {
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
            lane,
            incarnation: *incarnation,
            height,
            reader,
            ready: None,
        });
        let result = slot.as_mut().expect("original frame read").authenticate();
        // Absent input owns no partial paid decode and must be reopened after a
        // later source publication. Every other refusal retains its exact owner.
        if result
            .as_ref()
            .is_err_and(|error| error.io_kind() == io::ErrorKind::NotFound)
        {
            *slot = None;
        }
        result
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
        self.budget.with_deferred_refund_notifications(|_| {
            let mut slot = self.read.try_lock().ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "original lane frame is busy")
            })?;
            self.selected(&mut slot, lane, incarnation, height)?;
            let original = slot.as_ref().expect("authenticated original source");
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
            *slot = None;
            Ok(Some(result))
        })
    }
    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        _: Duration,
    ) -> Result<bool, Attempt<io::Error>> {
        // One finite read attempt. The enclosing original replay/producer owns
        // scheduling and the absolute deadline; this reader never sleeps or spins.
        self.budget.with_deferred_refund_notifications(|_| {
            let mut slot = self.read.try_lock().ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "original lane frame is busy")
            })?;
            self.selected(&mut slot, lane, incarnation, height)
                .map(|()| true)
        })
    }
}
