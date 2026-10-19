//! Exact original source, prepaid opaque parent-QC byte leaf and immutable control.
use super::{NposParentServiceCommitQc, Storage};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer,
    ChargedBufferFromChargeError, ChargedShared, ReservedChargedShared, SharedFromChargeError,
};
use iroha_crypto::Hash;
use norito::core::{self as ncore, DecodeFromSlice, SequenceDestinationError, SequenceSpan};
use std::alloc::Layout;

/// Original parent-QC byte-source, canonical or physical custody failure.
#[derive(Debug, thiserror::Error)]
pub enum ParentServiceCustodyError {
    /// A source or retained allocation belongs to another original finite pool.
    #[error("parent-service bytes belong to another original pool")]
    ForeignPool,
    /// Complete source address, length, content or selected field changed.
    #[error("parent-service bytes changed their complete original source")]
    SourceChanged,
    /// The selected field is outside initialized original input.
    #[error("parent-service field is outside its original source")]
    SourceRange,
    /// The enclosing canonical field did not install its advertised layout.
    #[error("parent-service bytes require their original advertised layout")]
    MissingLayout,
    /// The caller retried under another advertised layout.
    #[error("parent-service bytes changed their original advertised layout")]
    LayoutChanged,
    /// Original classified canonical or local logical-limit refusal.
    #[error(transparent)]
    Decode(#[from] ncore::DecodeAttemptError),
    /// The original finite pool refused both concrete allocation layouts.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Physical byte allocation refused its original retained charge.
    #[error(transparent)]
    Buffer(#[from] ChargedBufferFromChargeError),
    /// Physical control allocation refused its original retained charge.
    #[error(transparent)]
    Control(#[from] SharedFromChargeError),
    /// No complete canonical byte fill exists for this source.
    #[error("parent-service preparation is incomplete")]
    Incomplete,
}
use ParentServiceCustodyError as Error;
/// The original byte leaf and control, physically admitted before destination construction.
///
/// A refusal retains both exact prepaid charges and any completed allocation. The
/// immutable result shares them without recopying. This owns opaque wire bytes only.
pub struct PreparedParentServiceCommitQc {
    address: usize,
    length: usize,
    hash: Hash,
    span: SequenceSpan,
    byte_count: usize,
    flags: u8,
    value: Option<ChargedBuffer<u8>>,
    charges: [Option<AllocationCharge>; 2],
    shell: Option<ReservedChargedShared<ChargedBuffer<u8>>>,
    admitted: bool,
    ready: bool,
    pool: AllocationBudget,
}
impl PreparedParentServiceCommitQc {
    /// Inspect the original Vec<u8> field without allocating a destination.
    /// # Errors
    /// Rejects foreign pools, invalid ranges, missing layout or canonical framing.
    pub fn from_source(
        input: &ChargedBuffer<u8>,
        span: SequenceSpan,
        pool: &AllocationBudget,
    ) -> Result<Self, Error> {
        if !input.belongs_to(pool) {
            return Err(Error::ForeignPool);
        }
        let flags = ncore::effective_decode_flags().ok_or(Error::MissingLayout)?;
        let bytes = span.get(input.as_slice()).map_err(|_| Error::SourceRange)?;
        let byte_count = ncore::classify_decode_attempt(|| {
            let (value, used) = <&[u8] as DecodeFromSlice>::decode_from_slice(bytes)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            Ok(value.len())
        })?;
        Ok(Self {
            address: input.as_slice().as_ptr().addr(),
            length: input.as_slice().len(),
            hash: Hash::new(input.as_slice()),
            span,
            byte_count,
            flags,
            value: None,
            charges: [None, None],
            shell: None,
            admitted: false,
            ready: false,
            pool: pool.clone(),
        })
    }
    fn check(&self, input: &ChargedBuffer<u8>) -> Result<(), Error> {
        if !input.belongs_to(&self.pool) {
            return Err(Error::ForeignPool);
        }
        if !cfg!(all(test, sumeragi_model_mutation = "DM51"))
            && (self.address != input.as_slice().as_ptr().addr()
                || self.length != input.as_slice().len()
                || self.hash != Hash::new(input.as_slice()))
        {
            return Err(Error::SourceChanged);
        }
        if ncore::effective_decode_flags().ok_or(Error::MissingLayout)? != self.flags {
            return Err(Error::LayoutChanged);
        }
        Ok(())
    }
    /// Exact byte and immutable-control layouts, before any allocator call.
    /// # Errors
    /// Refuses unrepresentable byte geometry.
    pub fn allocation_layouts(&self) -> Result<[Layout; 2], AllocationRefusal> {
        Ok([
            Layout::array::<u8>(self.byte_count).map_err(|_| AllocationRefusal::DemandOverflow)?,
            NposParentServiceCommitQc::allocation_layout(),
        ])
    }
    /// Whether every retained original allocation and charge belongs to this same pool.
    #[must_use]
    pub fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.pool.same_pool(pool)
            && self.value.as_ref().is_none_or(|v| v.belongs_to(pool))
            && self.charges.iter().flatten().all(|c| c.belongs_to(pool))
            && self.shell.as_ref().is_none_or(|s| s.belongs_to(pool))
    }
    /// Borrow initialized byte storage only for the unchanged original source and layout.
    /// # Errors
    /// Rejects any source, pool or layout change. Initialization alone grants no authority.
    pub fn initialized<'a>(&'a self, input: &ChargedBuffer<u8>) -> Result<Option<&'a [u8]>, Error> {
        self.check(input)?;
        Ok(self.value.as_ref().map(ChargedBuffer::as_slice))
    }
    /// Resume physical preparation with the same charges, then fill using the canonical byte kernel.
    /// # Errors
    /// Retains exact original source, partial allocations and typed refusal on every error.
    pub fn prepare(&mut self, input: &ChargedBuffer<u8>) -> Result<(), Error> {
        self.check(input)?;
        if self.ready {
            return Ok(());
        }
        if !self.admitted {
            let layouts = self.allocation_layouts()?;
            let mut reservation = self.pool.try_reserve_layouts(layouts)?;
            for (charge, layout) in self.charges.iter_mut().zip(layouts) {
                *charge = Some(
                    reservation
                        .try_split(layout)
                        .expect("exact parent-service layouts admitted together"),
                );
            }
            self.admitted = true;
        }
        if self.value.is_none() {
            match ChargedBuffer::try_from_charge(
                self.byte_count,
                self.charges[0].take().expect("original byte charge"),
            ) {
                Ok(value) => self.value = Some(value),
                Err((charge, error)) => {
                    self.charges[0] = Some(charge);
                    return Err(error.into());
                }
            }
        }
        if self.shell.is_none() {
            match ChargedShared::reserve_from_charge(
                self.charges[1].take().expect("original control charge"),
            ) {
                Ok(shell) => self.shell = Some(shell),
                Err((charge, error)) => {
                    self.charges[1] = Some(charge);
                    return Err(error.into());
                }
            }
        }
        let value = self.value.as_mut().expect("original byte backing");
        while value.as_slice().len() < value.capacity() {
            value.push_reserved(0);
        }
        let bytes = self
            .span
            .get(input.as_slice())
            .map_err(|_| Error::SourceRange)?;
        ncore::classify_decode_attempt(|| {
            let (length, used) = ncore::decode_raw_byte_sequence_into(bytes, value.as_mut_slice())
                .map_err(|error| match error {
                    SequenceDestinationError::Codec(original) => original,
                    SequenceDestinationError::Storage { .. } => norito::Error::LengthMismatch,
                })?;
            if length != value.as_slice().len() || used != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            Ok(())
        })?;
        self.ready = true;
        Ok(())
    }
    /// Transfer into the already allocated immutable control without copying bytes.
    /// # Errors
    /// Returns the same owner on changed source/layout or incomplete preparation.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the unchanged original byte owner"
    )]
    pub fn finish(
        mut self,
        input: &ChargedBuffer<u8>,
    ) -> Result<NposParentServiceCommitQc, (Self, Error)> {
        if let Err(error) = self.check(input) {
            return Err((self, error));
        }
        if !self.ready || self.shell.is_none() {
            return Err((self, Error::Incomplete));
        }
        let value = self.value.take().expect("complete original byte leaf");
        let owner = self
            .shell
            .take()
            .expect("complete original control")
            .initialize(value);
        Ok(NposParentServiceCommitQc {
            storage: Storage::Admitted(owner),
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
