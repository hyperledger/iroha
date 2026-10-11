//! Physically prepaid counter controls for one synchronous canonical decode.

use iroha_allocation::{
    AllocationBudget, AllocationReservation, ChargedShared, InsufficientReservation,
    PrepaidSharedError,
};

use super::*;

/// Local construction failure for the prepared decode scope, without protocol meaning.
#[derive(Debug, thiserror::Error)]
pub enum PreparedDecodeScopeError {
    /// The parent reservation belongs to a different original source.
    #[error("prepared decode scope reservation belongs to another pool")]
    ForeignPool,
    /// The unchanged original remainder cannot fund both actual controls.
    #[error(transparent)]
    Reservation(InsufficientReservation),
    /// An actual prepaid control allocation failed.
    #[error(transparent)]
    Allocation(PrepaidSharedError),
    /// This workspace has exhausted its non-repeating local attempt identities.
    #[error("prepared decode scope attempt identity is exhausted")]
    AttemptExhausted,
}

/// Two original charged counter controls reused by the canonical framed entry.
///
/// The controls represent the payload-derived and explicitly supplied protocol
/// limits. Enclosing caller scopes remain in the same borrowed active chain.
/// Reuse allocates no Arc, layer Vec, TLS backing, or replacement identity.
/// Captured errors retain the exact original control through its final reader.
/// This owner does not fund decoded values, input frames or alignment scratch.
/// It cannot be cloned, and each synchronous use requires an exclusive borrow.
pub struct PreparedDecodeWorkspace {
    derived: ChargedShared<DecodeBudgetCounters>,
    explicit: ChargedShared<DecodeBudgetCounters>,
    attempt: u64,
}

impl PreparedDecodeWorkspace {
    /// Exact physical counter/control layouts required before an attempt starts.
    #[must_use]
    pub fn allocation_layouts() -> [Layout; 2] {
        [ChargedShared::<DecodeBudgetCounters>::allocation_layout(); 2]
    }

    /// Construct both actual controls using only the original parent's remainder.
    ///
    /// # Errors
    /// Foreign source or a short aggregate remainder performs no allocation and
    /// leaves the parent unchanged. Physical failure retires completed controls
    /// and refunds only the charges split for these controls; unused parent
    /// credit remains with the original reservation.
    pub fn from_reservation(
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, PreparedDecodeScopeError> {
        if !reservation.belongs_to(budget) {
            return Err(PreparedDecodeScopeError::ForeignPool);
        }
        let required = Self::allocation_layouts()
            .iter()
            .map(Layout::size)
            .sum::<usize>();
        if reservation.remaining_bytes() < required {
            return Err(PreparedDecodeScopeError::Reservation(
                InsufficientReservation {
                    requested_bytes: required,
                    remaining_bytes: reservation.remaining_bytes(),
                },
            ));
        }
        let derived = ChargedShared::from_reservation(DecodeBudgetCounters::default(), reservation)
            .map_err(|(_, error)| PreparedDecodeScopeError::Allocation(error))?;
        let explicit =
            ChargedShared::from_reservation(DecodeBudgetCounters::default(), reservation)
                .map_err(|(_, error)| PreparedDecodeScopeError::Allocation(error))?;
        Ok(Self {
            derived,
            explicit,
            attempt: 0,
        })
    }

    /// Whether both physical controls retain the supplied original finite pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.derived.belongs_to(budget) && self.explicit.belongs_to(budget)
    }

    /// Run under the original derived/explicit protocol ceilings without allocating.
    ///
    /// This is synchronous scope custody, not a decoder or an authentication
    /// claim. The closure must finish its work before returning. The two scopes
    /// use the same enforcement kernel as ordinary and lazy decode contexts.
    /// Call inside the canonical admission classifier so an actual enclosing
    /// refusal is captured before scope retirement. A later use of this same
    /// workspace cannot make a retained old error belong to the new attempt.
    ///
    /// # Errors
    /// Returns a source-less local invariant error before entering a scope when
    /// the attempt counter cannot advance. No wraparound identity is permitted.
    pub fn with_limits<R>(
        &mut self,
        derived: DecodeLimits,
        explicit: DecodeLimits,
        body: impl FnOnce() -> R,
    ) -> Result<R, PreparedDecodeScopeError> {
        let attempt = self
            .attempt
            .checked_add(1)
            .ok_or(PreparedDecodeScopeError::AttemptExhausted)?;
        self.attempt = attempt;
        for counters in [&self.derived, &self.explicit] {
            counters.total_elements.store(0, Ordering::Relaxed);
            counters.total_allocated_bytes.store(0, Ordering::Relaxed);
            counters.attempt.store(attempt, Ordering::Relaxed);
        }
        let depth = DECODE_NESTING_DEPTH.with(Cell::get);
        let layers = [
            ActiveDecodeBudgetLayer {
                budget: DecodeBudgetLayer {
                    limits: derived,
                    counters: CounterOwner::Prepared(self.derived.clone()),
                },
                base_depth: depth,
            },
            ActiveDecodeBudgetLayer {
                budget: DecodeBudgetLayer {
                    limits: explicit,
                    counters: CounterOwner::Prepared(self.explicit.clone()),
                },
                base_depth: depth,
            },
        ];
        decode_attempt::note_fresh_budget(&layers[0].budget.counters);
        Ok(budget_scope::with_layers(&layers, depth, body))
    }
}

#[cfg(test)]
mod tests;

/// Original byte error, original destination refusal, or prepared scope invariant.
#[derive(Debug, thiserror::Error)]
pub enum PreparedDecodeError<E> {
    /// The canonical decoder's exact cause, classified before its scopes retired.
    #[error(transparent)]
    Codec(DecodeAttemptError),
    /// The exact prepared destination refusal; this is never malformed input.
    #[error("prepared record destination refused: {0}")]
    Destination(#[source] E),
    /// Original prepared scope/control failure, without protocol meaning.
    #[error(transparent)]
    Scope(PreparedDecodeScopeError),
}

/// The real ordinary owning entry whose record bounds this prepared caller preserves.
#[derive(Clone, Copy)]
enum PreparedRecordRoot {
    CanonicalField,
    ArchiveView,
}

impl PreparedDecodeWorkspace {
    /// Fill one prepared destination using the sole derived field walk and
    /// authenticate its complete original canonical frame by streaming comparison.
    ///
    /// Header identity, flags, padding, checksum, field/depth ceilings and error
    /// ordering share the ordinary canonical decoder kernels. No alternate wire
    /// representation is accepted. The destination and this scope keep their
    /// original backing through failure, reset and retry; no owned decoder fallback
    /// or lazy alignment buffer is constructed. Individual destination leaves
    /// must use canonical prepared parsers rather than ordinary heap decoders.
    ///
    /// # Errors
    /// Retains exact scope provenance for an enclosing refusal, original leaf
    /// refusal for local custody failure, and intrinsic invalidity for malformed
    /// bytes. On every error the destination's validity is reset while preserving
    /// its allocated storage. The caller retains the original input and all I/O
    /// cursors; this entry consumes neither a secret nor an input descriptor.
    pub fn decode_canonical_into<T, D>(
        &mut self,
        bytes: &[u8],
        limits: DecodeLimits,
        destination: &mut D,
    ) -> Result<(), PreparedDecodeError<D::Error>>
    where
        T: NoritoSerialize + DecodeRecordFields<D>,
        D: PreparedRecordDestination<T>,
    {
        self.decode_canonical_into_with_root::<T, D>(
            bytes,
            limits,
            destination,
            PreparedRecordRoot::CanonicalField,
        )
    }

    /// Fill a canonical frame through its original archive-view record boundary.
    ///
    /// This is the prepared counterpart of [`ArchiveView::decode`] for a derived
    /// positional record with slice decoding. Both use payload-derived protocol
    /// ceilings and the same field walk, without treating the whole record as a
    /// canonical child field or adding a record depth before its first field.
    /// The field prefixes, leaf depth checks and inherited ceilings still apply.
    /// Header/schema/padding/checksum validation precedes the record scope as in
    /// the archive view. Exact canonical frame comparison follows complete filling.
    /// No archived backing, alignment scratch or ordinary owned fallback is made.
    /// The separate canonical-field entry retains its original root checks.
    ///
    /// # Errors
    /// Preserves original byte/resource or destination causes and resets validity
    /// on failure while retaining the original controls and destination storage.
    pub fn decode_canonical_archive_into<T, D>(
        &mut self,
        bytes: &[u8],
        limits: DecodeLimits,
        destination: &mut D,
    ) -> Result<(), PreparedDecodeError<D::Error>>
    where
        T: NoritoSerialize + DecodeRecordFields<D>,
        for<'de> T: NoritoDeserialize<'de> + DecodeFromSlice<'de>,
        D: PreparedRecordDestination<T>,
    {
        self.decode_canonical_into_with_root::<T, D>(
            bytes,
            limits,
            destination,
            PreparedRecordRoot::ArchiveView,
        )
    }

    fn decode_canonical_into_with_root<T, D>(
        &mut self,
        bytes: &[u8],
        limits: DecodeLimits,
        destination: &mut D,
        root: PreparedRecordRoot,
    ) -> Result<(), PreparedDecodeError<D::Error>>
    where
        T: NoritoSerialize + DecodeRecordFields<D>,
        D: PreparedRecordDestination<T>,
    {
        destination.reset();
        let result = decode_attempt::observe(|| {
            let header = crate::checked_canonical_header(bytes)
                .map_err(|error| PreparedDecodeError::Codec(decode_attempt::capture(error)))?;
            // ArchiveView authenticates its complete frame and type before entering
            // the payload-derived scope. Preserve that ordering without constructing
            // an archived payload or running a second decoder.
            let archive = match root {
                PreparedRecordRoot::CanonicalField => None,
                PreparedRecordRoot::ArchiveView => {
                    let view = from_bytes_view(bytes).map_err(|error| {
                        PreparedDecodeError::Codec(decode_attempt::capture(error))
                    })?;
                    if view.schema() != crate::schema::identity::frame_hash::<T>() {
                        return Err(PreparedDecodeError::Codec(decode_attempt::capture(
                            Error::SchemaMismatch,
                        )));
                    }
                    if view.padding_len != payload_alignment_padding_for::<T>() {
                        return Err(PreparedDecodeError::Codec(decode_attempt::capture(
                            Error::LengthMismatch,
                        )));
                    }
                    Some(view)
                }
            };
            let derived_length = archive
                .as_ref()
                .map_or(bytes.len(), |view| view.as_bytes().len());
            let attempt = self.with_limits(
                crate::canonical_decode_limits(derived_length),
                limits,
                || {
                    let _canonical_flags = DecodeFlagsGuard::enter(default_encode_flags());
                    let _outer_context = PayloadCtxGuard::enter(bytes);
                    let payload = match &archive {
                        Some(view) => view.as_bytes(),
                        None => crate::checked_uncompressed_payload::<T>(bytes, &header)?,
                    };
                    let _flags = DecodeFlagsGuard::enter(header.flags);
                    let _depth = match root {
                        PreparedRecordRoot::CanonicalField => {
                            check_decode_field_length(
                                u64::try_from(payload.len()).map_err(|_| Error::LengthMismatch)?,
                            )?;
                            Some(DecodeDepthGuard::enter()?)
                        }
                        PreparedRecordRoot::ArchiveView => None,
                    };
                    let _context = match root {
                        PreparedRecordRoot::CanonicalField => PayloadCtxGuard::enter(payload),
                        PreparedRecordRoot::ArchiveView => {
                            PayloadCtxGuard::enter_with_schema_and_flags(
                                payload,
                                header.schema,
                                header.flags,
                            )
                        }
                    };
                    let _boundary = FieldDecodeBoundaryGuard::enter(match root {
                        PreparedRecordRoot::CanonicalField => FieldDecodeBoundary::Canonical,
                        PreparedRecordRoot::ArchiveView => FieldDecodeBoundary::Prefix,
                    });
                    let (_, used) = T::decode_fields(payload, destination)?;
                    validate_decode_consumption(payload, used)?;
                    let mut exact = ExactSliceWriter::new(bytes);
                    let encoded = encode_frames::write_typed_payload_frame::<T, D, _>(
                        destination,
                        &mut exact,
                        default_encode_flags(),
                    );
                    if exact.mismatched() {
                        return Err(DecodeIntoError::Codec(Error::NonCanonicalEncoding));
                    }
                    encoded?;
                    if !exact.is_complete() {
                        return Err(DecodeIntoError::Codec(Error::NonCanonicalEncoding));
                    }
                    Ok(())
                },
            );
            match attempt {
                Err(error) => Err(PreparedDecodeError::Scope(error)),
                Ok(Err(DecodeIntoError::Destination(error))) => {
                    Err(PreparedDecodeError::Destination(error))
                }
                Ok(Err(DecodeIntoError::Codec(error))) => {
                    let error = match error {
                        Error::DecodeFlagsMismatch { .. } => Error::NonCanonicalEncoding,
                        Error::UnsupportedCompression { found, .. }
                            if found == Compression::Zstd as u8 =>
                        {
                            Error::NonCanonicalEncoding
                        }
                        error => error,
                    };
                    Err(PreparedDecodeError::Codec(decode_attempt::capture(error)))
                }
                Ok(Ok(())) => Ok(()),
            }
        });
        if result.is_err() {
            destination.reset();
        }
        result
    }
}
