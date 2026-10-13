//! Exact native-byte observations for purpose-owned immutable record associations.

use super::*;

/// One bounded canonical record observed under its original native directory and lock.
///
/// This owns bytes and native identities only. It certifies no decoded value, purpose,
/// authorization, currentness or phase. A purpose owner may privately pair an observation
/// with the decoded immutable value returned at the same read; it must preserve that
/// association itself. No file descriptor or live lock survives in this observation.
/// Record inode identity is not retained: a fresh equal-byte replacement under the same
/// journal directory and lock can match after the original bounded native read succeeds.
pub struct NativeRecordObservation {
    record: NativeRecord,
    directory: FileIdentity,
    lock: FileIdentity,
    bytes: Vec<u8>,
}
impl core::fmt::Debug for NativeRecordObservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeRecordObservation")
            .finish_non_exhaustive()
    }
}

/// Fresh fixed-record read result; equal bytes never supply a cached decoded `T`.
pub enum ObservedNativeRecord<T> {
    /// The original optional record is absent after native custody checks.
    Missing,
    /// Fresh bytes, record selection and native identities match the supplied observation.
    /// This does not validate a caller-owned value or associate these bytes with `T`.
    Unchanged,
    /// Fresh canonical bytes were decoded at this exact record position.
    Decoded {
        /// The decoded value, granting no purpose-owned semantic authority.
        value: T,
        /// Its exact canonical byte and native identity observation.
        observation: NativeRecordObservation,
    },
}

impl NativeJournalReadScope<'_, '_> {
    /// Reopen and read one fixed record before comparing its exact canonical observation.
    ///
    /// The ordinary per-record lock and byte-read checks run even for `Unchanged`.
    /// A miss decodes before any later record is read. This is a byte observation API,
    /// not a generic decoded-value cache: callers own any immutable value association
    /// and must retain their original decoder recipe under an inherited decode owner.
    /// An observation is not bound to `T`: only the purpose owner can pair these bytes with
    /// a known immutable decoded value. In particular, a shared reference to a generic
    /// value does not prove immutability or preserve its original encoding.
    ///
    /// # Errors
    /// Preserves native custody, allocation and canonical decode failures at this record.
    pub fn read_native_observed<T: JsonDeserialize + JsonSerialize>(
        &mut self,
        record: NativeRecord,
        previous: Option<&NativeRecordObservation>,
    ) -> Result<ObservedNativeRecord<T>> {
        let Some(bytes) = self.read_optional(record.name())? else {
            return Ok(ObservedNativeRecord::Missing);
        };
        let directory = self.journal.directory.identity()?;
        let lock = FileIdentity::of(&self.journal.lock)?;
        if previous.is_some_and(|previous| {
            previous.record == record
                && previous.directory == directory
                && previous.lock == lock
                && previous.bytes == bytes
        }) {
            return Ok(ObservedNativeRecord::Unchanged);
        }
        let value = decode_native(&bytes)?;
        Ok(ObservedNativeRecord::Decoded {
            value,
            observation: NativeRecordObservation {
                record,
                directory,
                lock,
                bytes,
            },
        })
    }
}

#[cfg(test)]
#[path = "canonical_read_tests.rs"]
mod tests;
