//! One original-pool byte owner shared by bounded semantic domains.

use super::{ByteDomain, ByteSequence, ByteStorage};
use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferError, ChargedShared,
    PrepaidSharedError,
};
use std::{fmt, marker::PhantomData, sync::Arc};

/// Static limits of one shared canonical byte domain.
pub trait SharedDomain: ByteDomain {
    /// Smallest permitted byte sequence; semantic verification remains separate.
    const MIN: usize = 1;
    /// Largest permitted byte sequence, enforced before backing construction.
    const MAX: usize;
}

/// Private original backing and semantic identity, without a mutable or naked Vec escape.
pub struct SharedBytes<D> {
    owner: Owner,
    domain: PhantomData<D>,
}

enum Owner {
    Untrusted {
        source: Arc<Vec<u8>>,
        pending: Option<ChargedBuffer<u8>>,
    },
    Admitted(ChargedShared<ChargedBuffer<u8>>),
}

/// Resource refusal shared by all byte domains; it never grants cryptographic authority.
#[derive(Debug)]
pub enum ByteAdmissionError {
    /// Source bytes violate the semantic domain's static bounds.
    Length {
        /// Rejected source length in bytes.
        length: usize,
    },
    /// Original pending/admitted storage belongs to another pool.
    ForeignBudget,
    /// Original-pool byte allocation was refused.
    Buffer(ChargedBufferError),
    /// Original pool refused the shared-control layout.
    ControlAdmission(AllocationRefusal),
    /// Physical allocation of the prepaid shared control failed.
    ControlAllocation(PrepaidSharedError),
}
impl ByteAdmissionError {
    /// Whether retrying the same original owner can recover after local resource relief.
    pub const fn is_local_refusal(&self) -> bool {
        !matches!(self, Self::Length { .. } | Self::ForeignBudget)
    }
}
impl fmt::Display for ByteAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { length } => write!(f, "invalid shared byte sequence length {length}"),
            Self::ForeignBudget => f.write_str("shared bytes belong to another allocation pool"),
            Self::Buffer(error) => error.fmt(f),
            Self::ControlAdmission(error) => error.fmt(f),
            Self::ControlAllocation(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for ByteAdmissionError {}

impl<D: SharedDomain> ByteSequence<SharedBytes<D>> {
    /// Keep explicitly untrusted decoded/fixture bytes; this grants no production admission.
    pub fn from_untrusted(bytes: Vec<u8>) -> Result<Self, ByteAdmissionError> {
        Self::check_len(bytes.len())?;
        Ok(Self {
            storage: SharedBytes {
                owner: Owner::Untrusted {
                    source: Arc::new(bytes),
                    pending: None,
                },
                domain: PhantomData,
            },
        })
    }
    fn check_len(length: usize) -> Result<(), ByteAdmissionError> {
        (D::MIN..=D::MAX)
            .contains(&length)
            .then_some(())
            .ok_or(ByteAdmissionError::Length { length })
    }
    /// Move exact charged bytes into shared custody; every refusal returns the original buffer.
    #[allow(clippy::result_large_err, reason = "a refusal must not allocate")]
    pub fn from_charged(
        bytes: ChargedBuffer<u8>,
        budget: &AllocationBudget,
    ) -> Result<Self, (ChargedBuffer<u8>, ByteAdmissionError)> {
        if let Err(error) = Self::check_len(bytes.as_slice().len()) {
            return Err((bytes, error));
        }
        if !bytes.belongs_to(budget) {
            return Err((bytes, ByteAdmissionError::ForeignBudget));
        }
        let mut reservation =
            match budget.try_reserve(ChargedShared::<ChargedBuffer<u8>>::allocation_layout()) {
                Ok(value) => value,
                Err(error) => return Err((bytes, ByteAdmissionError::ControlAdmission(error))),
            };
        match ChargedShared::from_reservation(bytes, &mut reservation) {
            Ok(bytes) => Ok(Self {
                storage: SharedBytes {
                    owner: Owner::Admitted(bytes),
                    domain: PhantomData,
                },
            }),
            Err((bytes, error)) => Err((bytes, ByteAdmissionError::ControlAllocation(error))),
        }
    }
    /// Admit in place; partial backing/control refusal retains the same original allocation.
    pub fn admit(&mut self, budget: &AllocationBudget) -> Result<(), ByteAdmissionError> {
        if let Owner::Admitted(bytes) = &self.storage.owner {
            return bytes
                .belongs_to(budget)
                .then_some(())
                .ok_or(ByteAdmissionError::ForeignBudget);
        }
        let Owner::Untrusted { source, pending } = &mut self.storage.owner else {
            unreachable!("admitted owner handled above")
        };
        if pending.is_none() {
            let mut bytes =
                ChargedBuffer::new(source.len(), budget).map_err(ByteAdmissionError::Buffer)?;
            bytes
                .append(source.as_slice())
                .expect("exact original-pool byte capacity");
            *pending = Some(bytes);
        }
        let bytes = pending.take().expect("original backing retained above");
        match Self::from_charged(bytes, budget) {
            Ok(admitted) => {
                self.storage = admitted.storage;
                Ok(())
            }
            Err((bytes, error)) => {
                *pending = Some(bytes);
                Err(error)
            }
        }
    }
    /// Borrow the original immutable charged input for a prepared canonical child decoder.
    /// No mutable backing, replacement owner or uncharged byte allocation escapes.
    /// Returns `None` for untrusted storage or another original operation pool.
    pub fn charged_source(&self, budget: &AllocationBudget) -> Option<&ChargedBuffer<u8>> {
        match &self.storage.owner {
            Owner::Admitted(bytes) if bytes.belongs_to(budget) => Some(bytes),
            _ => None,
        }
    }
    /// Whether both original backing and shared control belong to this exact pool.
    pub fn admitted_to(&self, budget: &AllocationBudget) -> bool {
        match &self.storage.owner {
            Owner::Untrusted { .. } => false,
            Owner::Admitted(bytes) => bytes.belongs_to(budget),
        }
    }
}
impl<D> Clone for SharedBytes<D> {
    fn clone(&self) -> Self {
        let owner = match &self.owner {
            Owner::Untrusted { source, .. } => Owner::Untrusted {
                source: Arc::clone(source),
                pending: None,
            },
            Owner::Admitted(bytes) => Owner::Admitted(bytes.clone()),
        };
        Self {
            owner,
            domain: PhantomData,
        }
    }
}
impl<D: SharedDomain> ByteStorage for SharedBytes<D> {
    const MIN: usize = D::MIN;
    const MAX: usize = D::MAX;
    const NAME: &'static str = D::NAME;
    const FRAME: &'static str = D::FRAME;
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            owner: Owner::Untrusted {
                source: Arc::new(bytes.to_vec()),
                pending: None,
            },
            domain: PhantomData,
        }
    }
    fn as_slice(&self) -> &[u8] {
        match &self.owner {
            Owner::Untrusted { source, pending } => pending
                .as_ref()
                .map_or_else(|| source.as_slice(), |bytes| bytes.as_slice()),
            Owner::Admitted(bytes) => bytes.as_slice(),
        }
    }
}

#[cfg(test)]
mod original_source_tests {
    use super::*;
    use crate::availability::RowBytes;
    #[test]
    fn charged_source_accessor_preserves_original_backing_and_rejects_foreign_or_untrusted() {
        let pool = AllocationBudget::new(4096);
        let foreign = AllocationBudget::new(4096);
        let mut value = RowBytes::from_untrusted(vec![7; 64]).unwrap();
        assert!(value.charged_source(&pool).is_none());
        value.admit(&pool).unwrap();
        let source = value.charged_source(&pool).unwrap();
        let pointer = source.as_slice().as_ptr();
        assert!(source.belongs_to(&pool));
        assert!(value.charged_source(&foreign).is_none());
        let retained = value.clone();
        drop(value);
        assert_eq!(
            retained.charged_source(&pool).unwrap().as_slice().as_ptr(),
            pointer
        );
        drop(retained);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[cfg(test)]
mod tests;
