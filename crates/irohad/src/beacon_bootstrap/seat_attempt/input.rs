//! One original FIFO frame, retaining partial input and admission refusal custody.
//!
//! Source caps are bounds, not physical allocations. Once the full header is owned,
//! the exact declared body is admitted before reading one body byte. A refusal keeps
//! the original header, descriptor and operation pool; no consumed FIFO is reread.

use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, PrepaidBufferError};
use std::{
    fs::{File, Metadata},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    time::Instant,
};

#[derive(Debug, thiserror::Error)]
pub enum FrameReadError {
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    #[error(transparent)]
    Backing(#[from] PrepaidBufferError),
    #[error("original DKG frame descriptor operation failed")]
    Io(#[source] std::io::Error),
    #[error("original DKG attempt deadline elapsed")]
    Deadline,
    #[error("DKG frame declares an invalid source length")]
    Length,
    #[error("original DKG frame ended before its declared boundary")]
    EndOfStream,
    #[error("original DKG frame source identity changed")]
    Custody,
    #[error("DKG frame cannot advance before its complete source is consumed")]
    Phase,
}

/// Move-only physical source custody for a single serial stream of phase frames.
/// No decoder or verifier authority is implied by a complete transport frame.
pub(super) struct FrameInput {
    descriptor: File,
    identity: Metadata,
    budget: AllocationBudget,
    maximum: usize,
    deadline: Instant,
    header: [u8; 4],
    header_read: usize,
    body: Option<ChargedBuffer<u8>>,
    body_read: usize,
    complete: bool,
    generation: u64,
}
impl FrameInput {
    /// Take the inherited FIFO once. Rejection returns that same descriptor.
    pub(super) fn new(
        descriptor: File,
        maximum: usize,
        deadline: Instant,
        budget: &AllocationBudget,
    ) -> Result<Self, (File, FrameReadError)> {
        let identity = match descriptor.metadata() {
            Ok(value) => value,
            Err(error) => return Err((descriptor, FrameReadError::Io(error))),
        };
        if !identity.file_type().is_fifo() {
            return Err((descriptor, FrameReadError::Custody));
        }
        if maximum == 0 || u32::try_from(maximum).is_err() {
            return Err((descriptor, FrameReadError::Length));
        }
        // A readiness event is not a guarantee that another inherited reader has
        // left bytes available. Make the owned descriptor nonblocking before the
        // durable claim so such a race cannot extend the original deadline.
        let flags = match rustix::fs::fcntl_getfl(&descriptor) {
            Ok(flags) => flags,
            Err(error) => return Err((descriptor, FrameReadError::Io(error.into()))),
        };
        // Only the inherited read end is an input. Reject a write-only or
        // read/write end before changing flags or consuming an attempt claim.
        if flags & (rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR)
            != rustix::fs::OFlags::RDONLY
        {
            return Err((descriptor, FrameReadError::Custody));
        }
        if let Err(error) =
            rustix::fs::fcntl_setfl(&descriptor, flags | rustix::fs::OFlags::NONBLOCK)
        {
            return Err((descriptor, FrameReadError::Io(error.into())));
        }
        Ok(Self {
            descriptor,
            identity,
            budget: budget.clone(),
            maximum,
            deadline,
            header: [0; 4],
            header_read: 0,
            body: None,
            body_read: 0,
            complete: false,
            generation: 0,
        })
    }

    /// Reject aliased public/finality streams even when their fd numbers differ.
    /// Both descriptor identities are rechecked before their original attempt claims.
    pub(super) fn require_distinct_source(&self, other: &Self) -> Result<(), FrameReadError> {
        self.validate_source()?;
        other.validate_source()?;
        if self.identity.dev() == other.identity.dev()
            && self.identity.ino() == other.identity.ino()
        {
            return Err(FrameReadError::Custody);
        }
        Ok(())
    }

    pub(super) fn source_identity(&self) -> Result<[u64; 2], FrameReadError> {
        self.validate_source()?;
        Ok([self.identity.dev(), self.identity.ino()])
    }
    /// Original count of fully consumed frames; no partial read advances it.
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
    /// Refuse importing an empty cursor over any original partial/full frame.
    pub(super) fn require_empty_cursor(&self) -> Result<(), FrameReadError> {
        self.check_deadline()?;
        self.validate_source()?;
        if self.complete || self.header_read != 0 || self.body.is_some() || self.body_read != 0 {
            return Err(FrameReadError::Phase);
        }
        Ok(())
    }
    /// Called only after the enclosing original durable head is authenticated.
    /// Restore the exact recorded generation on the same inherited empty stream;
    /// this cannot clear consumed bytes, reopen a FIFO or enlarge a partial frame.
    pub(super) fn restore_empty_cursor(
        &mut self,
        generation: u64,
        maximum: usize,
        original_source: [u64; 2],
    ) -> Result<(), FrameReadError> {
        self.require_empty_cursor()?;
        if self.source_identity()? != original_source
            || (self.generation != 0 && self.generation != generation)
        {
            return Err(FrameReadError::Custody);
        }
        self.set_next_maximum(maximum)?;
        self.generation = generation;
        Ok(())
    }
    pub(super) fn tighten_deadline(&mut self, deadline: Instant) {
        self.deadline = self.deadline.min(deadline);
    }

    fn validate_source(&self) -> Result<(), FrameReadError> {
        let now = self.descriptor.metadata().map_err(FrameReadError::Io)?;
        let old = &self.identity;
        if now.dev() != old.dev()
            || now.ino() != old.ino()
            || now.uid() != old.uid()
            || now.gid() != old.gid()
            || now.mode() != old.mode()
            || now.nlink() != old.nlink()
        {
            return Err(FrameReadError::Custody);
        }
        Ok(())
    }
    fn check_deadline(&self) -> Result<(), FrameReadError> {
        if Instant::now() >= self.deadline {
            Err(FrameReadError::Deadline)
        } else {
            Ok(())
        }
    }
    fn offered_length(&self) -> Result<usize, FrameReadError> {
        if self.header_read != self.header.len() {
            return Err(FrameReadError::Phase);
        }
        let length =
            usize::try_from(u32::from_be_bytes(self.header)).map_err(|_| FrameReadError::Length)?;
        if length == 0 || length > self.maximum {
            return Err(FrameReadError::Length);
        }
        Ok(length)
    }
    fn admit_body(&mut self) -> Result<(), FrameReadError> {
        if self.body.is_some() {
            return Ok(());
        }
        let length = self.offered_length()?;
        let mut reservation = self.budget.try_reserve_bytes(length)?;
        let mut body = ChargedBuffer::from_reservation(length, &mut reservation)?;
        // Every read destination byte is initialized. Neither a short read nor a
        // refused syscall changes the exact retained capacity or exposes spare storage.
        for _ in 0..length {
            body.push_reserved(0);
        }
        self.body = Some(body);
        Ok(())
    }

    /// Perform at most one read from the original ready descriptor.
    /// Exact OS/admission causes return without clearing the frame or advancing its generation.
    pub(super) fn read_ready(&mut self) -> Result<bool, FrameReadError> {
        self.check_deadline()?;
        self.validate_source()?;
        if self.complete {
            return Ok(true);
        }
        if self.header_read < self.header.len() {
            let count = rustix::io::read(&self.descriptor, &mut self.header[self.header_read..])
                .map_err(|error| FrameReadError::Io(error.into()))?;
            if count == 0 {
                return Err(FrameReadError::EndOfStream);
            }
            self.header_read += count;
            self.validate_source()?;
            if self.header_read == self.header.len() {
                self.admit_body()?;
            }
            return Ok(false);
        }
        // This also retries an earlier exact allocation refusal without reading a new header.
        self.admit_body()?;
        let body = self.body.as_mut().expect("original admitted frame body");
        if self.body_read < body.as_slice().len() {
            let count =
                rustix::io::read(&self.descriptor, &mut body.as_mut_slice()[self.body_read..])
                    .map_err(|error| FrameReadError::Io(error.into()))?;
            if count == 0 {
                return Err(FrameReadError::EndOfStream);
            }
            self.body_read += count;
        }
        self.validate_source()?;
        self.complete = self.body_read == self.offered_length()?;
        Ok(self.complete)
    }

    /// Wait and resume against the same absolute deadline, never rereading completed bytes.
    pub(super) fn read_until_complete(&mut self) -> Result<(), FrameReadError> {
        loop {
            self.check_deadline()?;
            self.validate_source()?;
            if self.complete {
                return Ok(());
            }
            // Admission occurs before waiting for body readiness, so an occupied
            // original pool is reported even when a peer has not sent more bytes.
            if self.header_read == self.header.len() {
                self.admit_body()?;
                if self.body_read == self.offered_length()? {
                    self.read_ready()?;
                    return Ok(());
                }
            }
            let timeout = rustix::event::Timespec::try_from(
                self.deadline.saturating_duration_since(Instant::now()),
            )
            .map_err(|_| FrameReadError::Deadline)?;
            let mut polls = [rustix::event::PollFd::new(
                &self.descriptor,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut polls, Some(&timeout)) {
                Ok(0) => return Err(FrameReadError::Deadline),
                Ok(_) if polls[0].revents().contains(rustix::event::PollFlags::NVAL) => {
                    return Err(FrameReadError::Custody);
                }
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(FrameReadError::Io(error.into())),
            }
            if self.read_ready()? {
                return Ok(());
            }
        }
    }

    /// Borrow only the complete original frame; decode errors cannot consume it.
    pub(super) fn frame(&self) -> Option<&[u8]> {
        self.charged_frame().map(ChargedBuffer::as_slice)
    }

    /// Borrow the same actual source backing only after the original FIFO frame completes.
    /// Its pool and immutable allocation identity remain available to native proof decoding.
    pub(super) fn charged_frame(&self) -> Option<&ChargedBuffer<u8>> {
        self.complete
            .then(|| self.body.as_ref().expect("complete original frame"))
    }

    /// Select the next already authenticated geometry only between complete frames.
    /// A partially consumed header/body can never acquire a new length allowance.
    pub(super) fn set_next_maximum(&mut self, maximum: usize) -> Result<(), FrameReadError> {
        if self.complete || self.header_read != 0 || self.body.is_some() || self.body_read != 0 {
            return Err(FrameReadError::Phase);
        }
        if maximum == 0 || u32::try_from(maximum).is_err() {
            return Err(FrameReadError::Length);
        }
        self.maximum = maximum;
        Ok(())
    }

    /// Called only after the enclosing authenticated semantic phase has committed.
    pub(super) fn consume_verified_frame(&mut self) -> Result<(), FrameReadError> {
        if !self.complete {
            return Err(FrameReadError::Phase);
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or(FrameReadError::Phase)?;
        self.complete = false;
        self.header = [0; 4];
        self.header_read = 0;
        self.body_read = 0;
        self.generation = next;
        // Publish the empty cursor before dropping old backing/refunding its original pool.
        let old = self.body.take();
        drop(old);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
