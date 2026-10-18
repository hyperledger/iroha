//! Short-lived compressed public DATA for one complete admission transaction.

use std::io::Cursor;

use super::super::SharedOriginalSourceV1;
use super::*;

/// Fixed per-transaction ceiling for the complete compressed original closure.
/// This is not a caller-selected limit or a retained runtime cache.
const MAX_STORED_BYTES: usize = 16 << 20;

fn capture_io(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof => {
            Error::Inventory
        }
        _ => Error::Unavailable,
    }
}

impl StoredSource for Cursor<&[u8]> {
    fn recheck(&self) -> io::Result<()> {
        // The immutable borrow is into the private, bounded transaction snapshot.
        // Physical custody is checked before capture and again before any result
        // can leave the transaction, including a failing body result.
        Ok(())
    }
}

struct SnapshotOriginal {
    identity: EncodedOriginalV1,
    stored: Vec<u8>,
}

struct SnapshotSource {
    originals: BTreeMap<[u8; 32], SnapshotOriginal>,
}

// Reads only the immutable captured map: each open decodes and checks its own copy
// of exact stored bytes, so any number of threads may read at once.
impl SharedOriginalSourceV1 for SnapshotSource {
    fn open_shared(&self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        let original = self.originals.get(&digest).ok_or(Error::Inventory)?;
        let reader = decode_stored(Cursor::new(original.stored.as_slice()), original.identity)
            .map_err(|_| Error::Inventory)?;
        Ok(Box::new(reader))
    }
}

impl OriginalSourceV1 for SnapshotSource {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.open_shared(digest)
    }

    fn shared_view(&self) -> Option<&(dyn SharedOriginalSourceV1 + Sync)> {
        Some(self)
    }
}

impl EncodedDirectoryOriginalsV1 {
    /// Authenticate the complete bounded compressed closure, run one admission
    /// transaction in memory, then close every observed file's retained custody.
    ///
    /// The private snapshot stores only public compressed DATA. Every decoded
    /// read still checks its exact stored and raw identities, single frame and
    /// decoder window. It grants no source, installation or wallet authority.
    /// The snapshot and its borrowed readers cannot escape the callback; it is
    /// dropped before returning, and live proof reads keep using this directory.
    /// Its shared immutable view lets the body's bounded route workers read at
    /// once; every worker joins inside the body, before closing custody runs.
    ///
    /// # Errors
    /// More than 16 MiB of declared stored bytes, an invalid or unavailable
    /// original, corrupt encoding, the callback's error, or changed custody.
    /// Closing custody runs after capture or callback failure and takes
    /// precedence over that result. No streaming fallback is selected on error.
    pub fn with_snapshot<T, E>(
        &self,
        body: impl FnOnce(&mut dyn OriginalSourceV1) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<Error>,
    {
        let result = self
            .capture_snapshot()
            .map_err(E::from)
            .and_then(|mut snapshot| body(&mut snapshot));
        self.revalidate_observed().map_err(E::from)?;
        result
    }

    fn snapshot_extent(&self) -> Result<usize, Error> {
        if self.originals.is_empty() || self.originals.len() > ROWS {
            return Err(Error::Inventory);
        }
        self.originals.values().try_fold(0_usize, |total, row| {
            row.validate().map_err(|_| Error::Inventory)?;
            let size = usize::try_from(row.stored.bytes).map_err(|_| Error::Inventory)?;
            total
                .checked_add(size)
                .filter(|size| *size <= MAX_STORED_BYTES)
                .ok_or(Error::Inventory)
        })
    }

    fn capture_snapshot(&self) -> Result<SnapshotSource, Error> {
        // Check the complete sum and row count before any file open/allocation.
        self.snapshot_extent()?;
        let mut originals = BTreeMap::new();
        for (&digest, &identity) in &self.originals {
            let (file, _) = self
                .retained_file(digest)
                .map_err(capture_io)?
                .ok_or(Error::Unavailable)?;
            let mut reader = StoredReader {
                file,
                expected: identity.stored,
                hash: Sha256::new(),
                bytes: 0,
            };
            let length = usize::try_from(identity.stored.bytes).map_err(|_| Error::Inventory)?;
            let mut stored = vec![0; length];
            reader.read_exact(&mut stored).map_err(capture_io)?;
            let mut excess = [0; 1];
            if reader.read(&mut excess).map_err(capture_io)? != 0 {
                return Err(Error::Inventory);
            }
            reader.finish().map_err(capture_io)?;
            drop(reader);
            // Authenticate even originals that the body might never request.
            // No decoded table is retained in the snapshot.
            let mut decoded = decode_stored(Cursor::new(stored.as_slice()), identity)
                .map_err(|_| Error::Inventory)?;
            let mut buffer = [0; 16 << 10];
            while decoded.read(&mut buffer).map_err(|_| Error::Inventory)? != 0 {}
            drop(decoded);
            originals.insert(digest, SnapshotOriginal { identity, stored });
        }
        Ok(SnapshotSource { originals })
    }

    fn revalidate_observed(&self) -> Result<(), Error> {
        self.directory.revalidate().map_err(|_| Error::Inventory)?;
        let observed = self.observed.lock().map_err(|_| Error::Inventory)?.clone();
        // Reopen one file at a time. The retained snapshot includes identity,
        // name, ancestry and change metadata; closing needs no second hash of
        // unchanged immutable bytes and no collection of open descriptors.
        for (digest, baseline) in observed {
            let (_file, snapshot) = self
                .retained_file(digest)
                .map_err(|_| Error::Inventory)?
                .ok_or(Error::Inventory)?;
            // The helper just checked this snapshot against observed custody.
            // Keep its native file held through this independent closing comparison.
            if snapshot != baseline {
                return Err(Error::Inventory);
            }
        }
        self.directory.revalidate().map_err(|_| Error::Inventory)
    }
}

#[cfg(test)]
#[path = "snapshot/tests.rs"]
mod tests;
