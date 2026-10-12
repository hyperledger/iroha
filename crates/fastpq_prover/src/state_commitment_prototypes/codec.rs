//! Canonical witness encoding of the prototypes.
//!
//! Integers are little-endian and fixed width, byte strings carry a `u32`
//! length, digests are 32 bytes. A reader consumes the whole witness: a
//! truncated encoding and trailing bytes are both malformed, and no length is
//! trusted before the bytes it announces are present.

use core::marker::PhantomData;

use super::{
    Reject,
    hash::{DIGEST_BYTES, Digest, HashProfile, digest_from_bytes, digest_to_bytes},
};

/// Append-only witness writer.
#[derive(Default)]
pub(super) struct Writer(Vec<u8>);

impl Writer {
    pub(super) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    /// A count that the prototype workloads keep far below `u32::MAX`.
    pub(super) fn count(&mut self, value: usize) {
        self.u32(u32::try_from(value).expect("prototype witness counts fit u32"));
    }

    pub(super) fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.0.extend_from_slice(value);
    }

    pub(super) fn digest(&mut self, value: &Digest) {
        self.0.extend_from_slice(&digest_to_bytes(value));
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Strict witness reader for one hash profile.
pub(super) struct Reader<'a, H> {
    bytes: &'a [u8],
    profile: PhantomData<H>,
}

impl<'a, H: HashProfile> Reader<'a, H> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            profile: PhantomData,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Reject> {
        if self.bytes.len() < length {
            return Err(Reject::Malformed);
        }
        let (head, tail) = self.bytes.split_at(length);
        self.bytes = tail;
        Ok(head)
    }

    pub(super) fn u8(&mut self) -> Result<u8, Reject> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u32(&mut self) -> Result<u32, Reject> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Reject::Malformed)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// A count of items that each occupy at least `minimum_item_bytes`: a count
    /// the remaining bytes cannot hold is malformed before anything is allocated.
    pub(super) fn count(&mut self, minimum_item_bytes: usize) -> Result<usize, Reject> {
        let count = usize::try_from(self.u32()?).map_err(|_| Reject::Malformed)?;
        if count
            .checked_mul(minimum_item_bytes.max(1))
            .is_none_or(|needed| needed > self.bytes.len())
        {
            return Err(Reject::Malformed);
        }
        Ok(count)
    }

    pub(super) fn bytes(&mut self) -> Result<&'a [u8], Reject> {
        let length = usize::try_from(self.u32()?).map_err(|_| Reject::Malformed)?;
        self.take(length)
    }

    /// A digest whose words are canonical for the profile.
    pub(super) fn digest(&mut self) -> Result<Digest, Reject> {
        let bytes: [u8; DIGEST_BYTES] = self
            .take(DIGEST_BYTES)?
            .try_into()
            .map_err(|_| Reject::Malformed)?;
        let digest = digest_from_bytes(&bytes);
        if H::is_canonical(&digest) {
            Ok(digest)
        } else {
            Err(Reject::Malformed)
        }
    }

    /// Require that every byte was consumed.
    pub(super) fn finish(self) -> Result<(), Reject> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Reject::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment_prototypes::hash::{Blake2bProfile, Poseidon2Profile};

    #[test]
    fn writer_and_reader_round_trip_and_reject_noncanonical_input() {
        let mut writer = Writer::default();
        writer.u8(7);
        writer.u32(0x0102_0304);
        writer.count(2);
        writer.bytes(b"key");
        writer.digest(&[1, 2, 3, 4]);
        let bytes = writer.finish();
        let mut reader = Reader::<Blake2bProfile>::new(&bytes);
        assert_eq!(reader.u8(), Ok(7));
        assert_eq!(reader.u32(), Ok(0x0102_0304));
        assert_eq!(reader.count(1), Ok(2));
        assert_eq!(reader.bytes(), Ok(&b"key"[..]));
        assert_eq!(reader.digest(), Ok([1, 2, 3, 4]));
        assert_eq!(reader.finish(), Ok(()));

        // Trailing bytes and truncation.
        let mut reader = Reader::<Blake2bProfile>::new(&bytes);
        assert_eq!(reader.u8(), Ok(7));
        assert_eq!(reader.finish(), Err(Reject::Malformed));
        let mut reader = Reader::<Blake2bProfile>::new(&bytes[..3]);
        assert_eq!(reader.u8(), Ok(7));
        assert_eq!(reader.u32(), Err(Reject::Malformed));

        // A count or a length the remaining bytes cannot hold.
        let mut reader = Reader::<Blake2bProfile>::new(&[9, 0, 0, 0, 1, 2]);
        assert_eq!(reader.count(1), Err(Reject::Malformed));
        let mut reader = Reader::<Blake2bProfile>::new(&[9, 0, 0, 0, 1, 2]);
        assert_eq!(reader.bytes(), Err(Reject::Malformed));
        let mut reader = Reader::<Blake2bProfile>::new(&[2, 0, 0, 0, 1, 2]);
        assert_eq!(reader.count(32), Err(Reject::Malformed));

        // A word at or above the modulus is not an algebraic digest.
        let high = [0xff_u8; 32];
        assert_eq!(
            Reader::<Poseidon2Profile>::new(&high).digest(),
            Err(Reject::Malformed)
        );
        assert!(Reader::<Blake2bProfile>::new(&high).digest().is_ok());
    }
}
