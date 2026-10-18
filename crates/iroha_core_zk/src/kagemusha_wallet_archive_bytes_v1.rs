//! Clearing owners for private wallet archive records and fold checkpoints.
//!
//! Borrowed access grants no source or monetary authority. The owned allocation is cleared
//! when released, including errors and unwinding. Filesystem-internal scratch, OS buffers,
//! register/stack copies, abort and OOM cleanup are outside this allocation contract.

use iroha_plonk_recursion::PrivateWitnessBytes;
use zeroize::Zeroizing;

/// One non-cloneable, redacted archive allocation, cleared on release.
#[derive(Debug)]
pub struct PrivateArchiveBytes(PrivateWitnessBytes);

impl PrivateArchiveBytes {
    /// Take an already guarded allocation without copying or reallocating it.
    pub fn from_guarded(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(PrivateWitnessBytes::from_guarded(bytes))
    }

    /// Copy borrowed bytes directly into an exact clearing allocation.
    ///
    /// # Errors
    /// Returns a writer failure without retaining the partially written allocation.
    pub fn copy_from(bytes: &[u8]) -> std::io::Result<Self> {
        PrivateWitnessBytes::try_write(bytes.len(), |writer| writer.write_all(bytes)).map(Self)
    }

    /// Stream a canonical Norito frame directly into an exact clearing allocation.
    ///
    /// # Errors
    /// Rejects serialization failure, length drift or a partial write.
    pub fn encode<T: norito::NoritoSerialize>(value: &T) -> Result<Self, norito::Error> {
        let size = norito::canonical_frame_len(value)?;
        PrivateWitnessBytes::try_write(size, |mut writer| {
            norito::core::write_canonical_to_writer(value, &mut writer)
        })
        .map(Self)
    }

    /// Borrow the exact retained bytes without transferring or duplicating ownership.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for PrivateArchiveBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for PrivateArchiveBytes {}

impl core::ops::Deref for PrivateArchiveBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl norito::SerializePayload for PrivateArchiveBytes {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::SerializePayload::serialize(&self.as_slice(), writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.len().checked_add(8)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
}

impl norito::NoritoSchema for PrivateArchiveBytes {
    fn nominal_name() -> String {
        "iroha.kagemusha.private_archive_bytes.v1".into()
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for PrivateArchiveBytes {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let (borrowed, used) = <&[u8] as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((Self::copy_from(borrowed)?, used))
    }
}

impl<'de> norito::DeserializePayload<'de> for PrivateArchiveBytes {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("private archive field")
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes).map(|(owned, _)| owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_transfer_preserves_allocation_and_redacts_contents() {
        let bytes = Zeroizing::new(vec![0x5a; 96]);
        let address = bytes.as_ptr();
        let owned = PrivateArchiveBytes::from_guarded(bytes);
        assert_eq!(owned.as_ptr(), address);
        assert_eq!(owned.as_slice(), &[0x5a; 96]);
        assert_eq!(
            format!("{owned:?}"),
            "PrivateArchiveBytes(PrivateWitnessBytes { private: [REDACTED] })"
        );
    }

    #[test]
    fn streamed_private_record_roundtrips_without_relaxing_canonical_decode() {
        let owned = PrivateArchiveBytes::copy_from(&[0x59; 97]).unwrap();
        let frame = PrivateArchiveBytes::encode(&owned).unwrap();
        let decoded: PrivateArchiveBytes = norito::decode_canonical_with_limits(
            &frame,
            norito::canonical_decode_limits(frame.len()),
        )
        .unwrap();
        assert_eq!(decoded.as_slice(), owned.as_slice());
        assert_eq!(frame.as_slice(), norito::encode_canonical(&owned).unwrap());
        let mut bad = Zeroizing::new(frame.as_slice().to_vec());
        bad.push(0);
        assert!(
            norito::decode_canonical_with_limits::<PrivateArchiveBytes>(
                &bad,
                norito::canonical_decode_limits(bad.len()),
            )
            .is_err()
        );
    }
}
