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
    /// Durably retain exact pending bytes, publish Original, then mark the sole metadata image pristine.
    /// Existing bytes and active decoder admission never produce a reusable receipt.
    pub(in crate::managed) fn publish(
        directory: &'a PrivateDirectory,
        original: Vec<u8>,
        maximum: usize,
        conflict: &'static str,
    ) -> Result<Option<Self>> {
        if !attempts::metadata::publish_original(directory, &original, maximum, conflict)? {
            return Ok(None);
        }
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
        attempts::metadata::require_published(self.directory, &self.original)?;
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
