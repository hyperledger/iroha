//! Kura's committed store: original signed availability, full certificates and result frames.
//!
//! One canonical SignedBlockWire carries the exact original availability frame and CommitQC.
//! Publication binds opaque body custody to independently authenticated historical authority.
//! Reads retain their original frame and funded decode/restoration work across local refusal;
//! an unreadable committed slot is an error, never an absent entry.
//! Metadata reads authenticate the historical QC, complete executed-result commitment, streamed
//! proposal identity and original signed availability table without allocating a proposal body
//! or regenerating RS16 rows. They return evidence, never available-payload custody. Body reads
//! still verify the complete re-encoded codeword before granting that custody. Both projections
//! retain the original read owner on refusal, including when callers switch projections.

use super::{
    availability_schedule::{AvailabilitySchedule, resolve_source},
    body_read::{BodyReadError, BodyReadJob, BodyReader},
    driver::{SharedCrypto, serve, traits::BlockStore},
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::kura::Kura;
use iroha_allocation::AllocationBudget;
#[cfg(test)]
use iroha_data_model::block::CommitCertificate;
use iroha_data_model::{
    block::{SharedSignedBlock, SignedBlock},
    sumeragi_finality::result_of_preimage,
};
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody},
    crypto::Verifier,
    message::{BlockHeader, PayloadManifest, Qc, SyncEntry},
    types::Hash32,
};
use parking_lot::Mutex;
use std::{io, num::NonZeroUsize, sync::Arc};
#[path = "block_store/body_read.rs"]
mod body_read;
#[path = "block_store/certificate_read.rs"]
pub(super) mod certificate_read;
#[path = "block_store/committed_read.rs"]
mod committed_read;
#[path = "block_store/execution.rs"]
mod execution;
#[path = "block_store/keyed_read.rs"]
mod keyed_read;
#[path = "block_store/publication.rs"]
mod publication;
use committed_read::CommittedRead;

/// A block the executor prepared for commit: what the block store writes for it.
#[derive(Clone, Debug)]
pub struct StagedBlock {
    /// Core block hash of the committed block.
    pub block_hash: Hash32,
    /// The original prepared result-bearing frame, including its exact certificate.
    pub executed: SharedSignedBlock,
}

/// The single-slot hand-off from the executor worker's `prepare` to the driver's
/// block-store `append`. Both retain the same certified frame through retries.
#[derive(Clone, Debug, Default)]
pub struct Staging {
    slot: Arc<Mutex<Option<StagedBlock>>>,
}

impl Staging {
    /// An empty slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage `block`, replacing whatever was staged.
    pub fn stage(&self, block: StagedBlock) {
        *self.slot.lock() = Some(block);
    }

    /// The staged block of `block_hash`, if that is what is staged.
    #[must_use]
    pub fn get(&self, block_hash: &Hash32) -> Option<StagedBlock> {
        self.slot
            .lock()
            .as_ref()
            .filter(|staged| staged.block_hash == *block_hash)
            .cloned()
    }

    /// Drop the staged block.
    pub fn clear(&self) {
        *self.slot.lock() = None;
    }
}

/// An explicitly untrusted certificate for read-only verification fixtures.
/// Production publication uses the executor's original charged buffers.
///
/// # Errors
/// A Norito encoding failure.
#[cfg(test)]
pub(crate) fn commit_certificate(
    header: &BlockHeader,
    commit_qc: &Qc,
    result_preimage: Vec<u8>,
    availability: Vec<u8>,
) -> Result<CommitCertificate, norito::Error> {
    Ok(CommitCertificate::from_untrusted_parts(
        norito::encode_canonical(header)?,
        norito::encode_canonical(commit_qc)?,
        result_preimage,
        availability,
    ))
}

/// Parse untrusted header and QC bytes for certificate-mutation tests. Parsing grants no custody.
///
/// # Errors
/// A part is not one canonical frame.
#[cfg(test)]
pub(crate) fn decode_certificate(
    certificate: &CommitCertificate,
) -> Result<(BlockHeader, Qc), norito::Error> {
    Ok((
        norito::decode_canonical(certificate.consensus_header())?,
        norito::decode_canonical(certificate.commit_qc())?,
    ))
}

/// Kura and the independent authority and allocation owners for one native root instance.
pub struct KuraBlockStore {
    kura: Arc<Kura>,
    hasher: SharedCrypto,
    genesis_height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    staging: Staging,
    execution_budget: AllocationBudget,
    schedule: Arc<dyn AvailabilitySchedule>,

    read: Mutex<Option<CommittedRead>>,
}
impl KuraBlockStore {
    /// Bind Kura to the original State pool and its independently authenticated schedule.
    /// `root_scope` must come from that same root's opaque execution tip or original signed
    /// genesis authority; result bytes never select their own scope.
    #[must_use]
    pub fn new(
        kura: Arc<Kura>,
        hasher: SharedCrypto,
        genesis_height: u64,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        staging: Staging,
        execution_budget: AllocationBudget,
        schedule: Arc<dyn AvailabilitySchedule>,
    ) -> Self {
        Self {
            kura,
            hasher,
            genesis_height,
            root_scope,
            staging,
            execution_budget,
            schedule,
            read: Mutex::new(None),
        }
    }
    /// The executor's original prepared-frame handoff.
    #[must_use]
    pub fn staging(&self) -> &Staging {
        &self.staging
    }

    fn stored(
        &self,
        height: u64,
    ) -> Result<Option<iroha_data_model::block::SharedSignedBlock>, Attempt<io::Error>> {
        if height <= self.genesis_height || height > self.height() {
            return Ok(None);
        }
        let index = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| invalid("committed height exceeds host index range"))?;
        // A known committed slot cannot become absence or erase its original local refusal.
        self.kura
            .get_block(index, &self.execution_budget)
            .map_err(|error| error.map_rejection(io::Error::other))?
            .map(Some)
            .ok_or_else(|| invalid("committed Kura slot cannot be read").into())
    }

    /// Restore original signed body custody and the exact original certificate.
    ///
    /// # Errors
    /// Corruption, invalid authority or I/O. WouldBlock retains the same original read owner.
    pub fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        self.read_committed(height, CommittedRead::poll)
    }

    /// Resume the original read owner, including when callers switch read projections.
    fn read_committed<T>(
        &self,
        height: u64,
        poll: impl Fn(&mut CommittedRead) -> Result<T, Attempt<io::Error>>,
    ) -> Result<Option<T>, Attempt<io::Error>> {
        let mut slot = self
            .read
            .try_lock()
            .ok_or_else(|| busy("committed read is busy"))?;
        if slot.as_ref().is_some_and(|read| read.height() != height) {
            // Finish the existing owner first; no partial backing is discarded by a new height.
            match poll(slot.as_mut().expect("existing original read")) {
                Ok(_) => *slot = None,
                Err(error) => {
                    if error.io_kind() != io::ErrorKind::WouldBlock {
                        *slot = None;
                    }
                    return Err(error);
                }
            }
        }
        if slot.is_none() {
            let Some(block) = self.stored(height)? else {
                return Ok(None);
            };
            *slot = Some(CommittedRead::new(
                block,
                height,
                self.execution_budget.clone(),
                self.hasher.clone(),
                self.schedule.clone(),
                self.root_scope,
            ));
        }
        match poll(slot.as_mut().expect("retained original committed read")) {
            Ok(value) => {
                *slot = None;
                Ok(Some(value))
            }
            Err(error) => {
                if error.io_kind() != io::ErrorKind::WouldBlock {
                    *slot = None;
                }
                Err(error)
            }
        }
    }

    /// Observe the exact retained source/table/witness owners of a refused certificate read.
    /// This test-only observation does not change the read phase or its allocation budget.
    #[cfg(test)]
    pub(crate) fn pending_certificate_read_for_test(
        &self,
    ) -> Option<(*const SignedBlock, Option<*const u8>)> {
        self.read
            .lock()
            .as_ref()?
            .retained_certificate_owners_for_test()
    }

    /// Authenticate stored metadata against the historical authority and executed result.
    /// Does not reconstruct payload custody or regenerate RS16 rows.
    ///
    /// # Errors
    /// Metadata or stored-result corruption, I/O, invalid authority or local resource refusal.
    /// Refusal retains the original read owner; complete codeword checks belong to body reads.
    pub fn certified(&self, height: u64) -> Result<Option<(BlockHeader, Qc)>, Attempt<io::Error>> {
        Ok(self
            .entry(height)?
            .map(|entry| (entry.manifest.header, entry.commit_qc)))
    }
    /// The authenticated header, or genuine absence above tip or at genesis.
    ///
    /// # Errors
    /// Corruption, I/O, authority or resource refusal.
    pub fn header(&self, height: u64) -> Result<Option<BlockHeader>, Attempt<io::Error>> {
        Ok(self.certified(height)?.map(|(header, _)| header))
    }
    /// The committed tip above genesis.
    ///
    /// # Errors
    /// Corruption, I/O, authority or resource refusal.
    pub fn tip(&self) -> Result<Option<SyncEntry>, Attempt<io::Error>> {
        self.entry(self.height())
    }
    /// The last count authenticated headers, oldest first.
    ///
    /// # Errors
    /// Missing committed slots or any read failure.
    pub fn recent_headers(&self, count: u64) -> Result<Vec<BlockHeader>, Attempt<io::Error>> {
        let tip = self.height();
        let first = tip
            .saturating_sub(count)
            .saturating_add(1)
            .max(self.genesis_height.saturating_add(1));
        (first..=tip)
            .map(|height| {
                self.header(height)?
                    .ok_or_else(|| invalid("missing committed header").into())
            })
            .collect()
    }
    /// Bounded consecutive metadata serving, preserving local errors.
    ///
    /// # Errors
    /// Corruption, I/O, authority or resource refusal.
    pub fn entries(
        &self,
        from_height: u64,
        max_count: u16,
        max_bytes: u32,
    ) -> Result<Vec<SyncEntry>, Attempt<io::Error>> {
        serve::entries(self, from_height, max_count, max_bytes)
    }
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn busy(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
impl BodyReader for KuraBlockStore {
    fn begin_read(
        &self,
        source: AvailabilitySource,
    ) -> Result<Box<dyn BodyReadJob>, BodyReadError> {
        let independent = self
            .availability_source(source.height(), source.block_hash())
            .map_err(BodyReadError::from_attempt)?
            .ok_or_else(|| BodyReadError::Io(busy("historical body authority unavailable")))?;
        if source != independent {
            return Err(BodyReadError::Io(invalid(
                "body read uses another historical authority",
            )));
        }
        let block = self
            .stored(source.height())
            .map_err(BodyReadError::from_attempt)?;
        Ok(Box::new(keyed_read::KeyedRead::new(
            source,
            block,
            self.execution_budget.clone(),
            self.hasher.clone(),
            self.schedule.clone(),
            self.root_scope,
        )))
    }
}
impl BlockStore for KuraBlockStore {
    fn retired_publication(
        self: std::sync::Arc<Self>,
    ) -> Option<std::sync::Arc<dyn crate::sumeragi::driver::traits::RetiredPublication>> {
        None
    }
    fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        Self::committed_body(self, height)
    }
    fn height(&self) -> u64 {
        u64::try_from(self.kura.blocks_count())
            .unwrap_or(u64::MAX)
            .max(self.genesis_height)
    }
    fn availability_source(
        &self,
        height: u64,
        hash: Hash32,
    ) -> Result<Option<AvailabilitySource>, Attempt<io::Error>> {
        resolve_source(&*self.schedule, self.schedule.instance(), height, hash)
    }
    fn entry(&self, height: u64) -> Result<Option<SyncEntry>, Attempt<io::Error>> {
        self.read_committed(height, CommittedRead::poll_metadata)
    }
    fn append(&self, body: &AvailableBody, qc: &Qc) -> Result<(), Attempt<io::Error>> {
        self.write(body, qc)
    }
}

#[cfg(test)]
#[path = "block_store/tests.rs"]
mod tests;
