//! Retained exact-file archive acquisition across local allocation and I/O refusal.

use super::*;

/// A single immutable carrier selection owning its original namespace, descriptor and buffer.
///
/// Byte acquisition supplies no history authority. The complete returned frame must still
/// authenticate against the original committed execution. No failed poll reopens an acquired
/// file or refunds its partial buffer. Dropping this owner abandons that exact read.
#[must_use = "dropping this owner cancels the original pending archive acquisition"]
pub struct NativeContextRead {
    archive: NativeContextArchive,
    read: RecordRead,
}
impl NativeContextRead {
    pub(super) fn new(
        archive: NativeContextArchive,
        height: u64,
        carrier_hash: HashOf<BlockHeader>,
    ) -> Self {
        Self::new_named(archive, RecordName::new(height, carrier_hash, false))
    }

    pub(super) fn new_named(archive: NativeContextArchive, name: RecordName) -> Self {
        Self {
            archive,
            read: RecordRead::new_named(name),
        }
    }

    /// Acquire at most one 4096-byte chunk from the original file. `None` means bounded progress,
    /// never absence; `Some` transfers the original complete charged byte allocation once.
    /// The archive descriptors remain owned here so callers can recheck before installation.
    ///
    /// # Errors
    /// Namespace/source replacement, missing record, finite byte ceiling, original-pool or
    /// allocator refusal, incomplete I/O, or polling after completion. Every error preserves
    /// the selected descriptor and all acquired bytes; retry cannot select another inode.
    pub fn poll(&mut self) -> Result<Option<ChargedBuffer<u8>>, NativeContextArchiveError> {
        self.read.poll(&self.archive)
    }

    // Observes actual selection only; it authenticates neither bytes nor their carrier.
    // The issuer uses this after a genuine refused poll to move the same retained job.
    // No file is opened, buffer acquired or source identity manufactured by this check.
    pub(crate) fn has_pinned_source(&self) -> bool {
        self.read.file.is_some() && self.read.length.is_some()
    }

    // Borrow the actual pending buffer for custody controls only; no descriptor or source
    // replacement is possible through this observation.
    #[cfg(test)]
    pub(crate) fn acquired_prefix(&self) -> Option<&[u8]> {
        self.read.bytes.as_ref().map(ChargedBuffer::as_slice)
    }

    /// Return the same pinned namespace for the next exact carrier read. Consuming a pending
    /// job explicitly cancels its acquisition: its file closes and partial byte charge drops.
    /// After successful polling, the returned byte owner remains with the caller unchanged.
    pub(crate) fn into_archive(self) -> NativeContextArchive {
        self.archive
    }

    /// Check the same retained archive namespace before using the authenticated result.
    /// This never reopens the selected file and grants no authority to its bytes.
    ///
    /// # Errors
    /// The original directory/root relationship changed or its identity could not be inspected.
    pub fn recheck_namespace(&self) -> Result<(), NativeContextArchiveError> {
        self.archive.recheck_namespace()
    }
}

/// Drive the one-shot convenience without replacing its exact selected read owner.
pub(super) fn to_completion(
    mut poll: impl FnMut() -> Result<Option<ChargedBuffer<u8>>, NativeContextArchiveError>,
) -> Result<ChargedBuffer<u8>, NativeContextArchiveError> {
    loop {
        match poll() {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => {}
            // Preserve Read::read_exact semantics while retrying the same retained owner.
            // Permission, absence, source and pool failures must still reach the caller.
            Err(NativeContextArchiveError::Io(error))
                if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Shared one-shot and retained-read implementation. The selection cannot change between polls.
pub(super) struct RecordRead {
    name: RecordName,
    file: Option<File>,
    length: Option<usize>,
    bytes: Option<ChargedBuffer<u8>>,
    completed: bool,
}
impl RecordRead {
    pub(super) fn new(height: u64, carrier_hash: HashOf<BlockHeader>) -> Self {
        Self::new_named(RecordName::new(height, carrier_hash, false))
    }
    fn new_named(name: RecordName) -> Self {
        Self {
            name,
            file: None,
            length: None,
            bytes: None,
            completed: false,
        }
    }
    pub(super) fn poll(
        &mut self,
        archive: &NativeContextArchive,
    ) -> Result<Option<ChargedBuffer<u8>>, NativeContextArchiveError> {
        if self.completed {
            return Err(NativeContextArchiveError::Source(
                "native context read already completed",
            ));
        }
        archive.recheck_namespace()?;
        if self.file.is_none() {
            self.file = Some(open_named_record(&archive.directory, &self.name)?);
        }
        let file = self.file.as_mut().expect("selected original descriptor");
        let length = match self.length {
            Some(length) => length,
            None => {
                let length = usize::try_from(file.metadata()?.len()).map_err(|_| {
                    NativeContextArchiveError::Source("record length exceeds address space")
                })?;
                // Pin even a refused finite length. Reconfiguration cannot rebind the original
                // descriptor or bless an in-place rewrite with a different allocation geometry.
                self.length = Some(length);
                length
            }
        };
        if length == 0 || length > archive.maximum.get() {
            return Err(NativeContextArchiveError::Limit {
                maximum: archive.maximum.get(),
                actual: length,
            });
        }
        if file.metadata()?.len() != u64::try_from(length).expect("file length fits u64") {
            return Err(NativeContextArchiveError::Source(
                "record length changed during exact read",
            ));
        }
        if self.bytes.is_none() {
            self.bytes = Some(ChargedBuffer::new(length, &archive.budget)?);
        }
        let bytes = self.bytes.as_mut().expect("original exact allocation");
        let used = bytes.as_slice().len();
        // A prior interrupted OS read cannot advance the next poll beyond the retained prefix.
        file.seek(io::SeekFrom::Start(
            u64::try_from(used).expect("prefix fits file length"),
        ))?;
        let mut scratch = [0; 4096];
        if used < length {
            let requested = (length - used).min(scratch.len());
            let count = file.read(&mut scratch[..requested])?;
            if count == 0 {
                return Err(NativeContextArchiveError::Source(
                    "record ended before its original length",
                ));
            }
            bytes.append(&scratch[..count])?;
            if bytes.as_slice().len() < length {
                return Ok(None);
            }
        }
        if file.read(&mut scratch[..1])? != 0
            || file.metadata()?.len() != u64::try_from(length).expect("file length fits u64")
        {
            return Err(NativeContextArchiveError::Source(
                "record changed during exact read",
            ));
        }
        archive.recheck_namespace()?;
        self.completed = true;
        Ok(self.bytes.take())
    }
}

#[cfg(test)]
mod tests;
