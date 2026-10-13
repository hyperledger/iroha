//! Successful local Original publication for one consuming, unsigned first-attempt admission.
//!
//! This owns exact local bytes, not native state or signing authority. Concrete coordinators
//! must also retain the actual independently authenticated native proof that selected the bytes.

use super::{attempts::FirstReservation, *};

/// Sole successful `CreateNew` publication, borrowed from its original native operation owner.
/// It is neither serializable nor Clone and grants no wallet preparation or dispatch authority.
pub(in crate::managed) struct PublishedInitialIntent<'a> {
    directory: &'a PrivateDirectory,
    original: Vec<u8>,
}
impl<'a> PublishedInitialIntent<'a> {
    /// Publish the original canonical bytes with the existing optional-read/write recipe.
    /// Existing bytes and active decoder admission never produce a reusable receipt.
    pub(in crate::managed) fn publish(
        directory: &'a PrivateDirectory,
        original: Vec<u8>,
        maximum: usize,
        conflict: &'static str,
    ) -> Result<Option<Self>> {
        if let Some(retained) = read_optional(directory, "original.nrt", maximum)? {
            if retained != original {
                return Err(invalid(conflict));
            }
            return Ok(None);
        }
        directory.write_atomic("original.nrt", &original, PublishMode::CreateNew)?;
        if norito::core::decode_limits_active() {
            return Ok(None);
        }
        Ok(Some(Self {
            directory,
            original,
        }))
    }

    /// Close exact original/source custody around pure use of a concrete native proof.
    /// The caller separately closes its live authority/profile on every ordinary result.
    pub(in crate::managed) fn admit<T>(
        self,
        first: &FirstReservation<'_>,
        purpose: attempts::Purpose,
        semantic: [u8; 32],
        use_proof: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.validate(first, purpose, semantic)?;
        let result = use_proof();
        self.validate(first, purpose, semantic)?;
        result
    }

    fn validate(
        &self,
        first: &FirstReservation<'_>,
        purpose: attempts::Purpose,
        semantic: [u8; 32],
    ) -> Result<()> {
        first.validate(self.directory, purpose, semantic)?;
        if self
            .directory
            .read("original.nrt", self.original.len())?
            .as_slice()
            != self.original.as_slice()
        {
            return Err(invalid(
                "new initial intent changed before unsigned admission",
            ));
        }
        Ok(())
    }
}
