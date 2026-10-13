//! Bounded ownership corridor for server-owned singular-query execution.
use super::Error;
use norito::core::{
    DecodeFlagsGuard, Encoder, NoritoDeserialize, NoritoSerialize, SerializePayload,
};
use std::{cell::Cell, ops::Deref};
/// Dynamic source/output ceilings for one singular query executed by a server-owned memory lane.
///
/// The frame ceiling bounds the canonical transient used instead of an unmetered deep clone. The
/// allocation ceiling is installed while decoding that frame into the owned query result. Both are
/// deterministic limits supplied by the embedding server's already-acquired memory reservation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SingularQueryOutputLimits {
    max_frame_bytes: u64,
    max_allocated_bytes: u64,
}
impl SingularQueryOutputLimits {
    /// Construct singular-query ownership limits.
    #[must_use]
    pub const fn new(max_frame_bytes: u64, max_allocated_bytes: u64) -> Self {
        Self {
            max_frame_bytes,
            max_allocated_bytes,
        }
    }
    /// Maximum complete canonical frame used to materialize one output.
    #[must_use]
    pub const fn max_frame_bytes(self) -> u64 {
        self.max_frame_bytes
    }
    /// Maximum resident allocation admitted while owning one output.
    #[must_use]
    pub const fn max_allocated_bytes(self) -> u64 {
        self.max_allocated_bytes
    }
}
thread_local! {
    static ACTIVE_LIMITS: Cell<Option<SingularQueryOutputLimits>> = const { Cell::new(None) };
    static ACTIVE_RETAINED_BUILDER_BYTES: Cell<usize> = const { Cell::new(0) };
}
struct SingularOutputLimitGuard {
    previous: Option<SingularQueryOutputLimits>,
    previous_retained_builder_bytes: usize,
}
impl SingularOutputLimitGuard {
    fn enter(limits: SingularQueryOutputLimits) -> Self {
        let previous = ACTIVE_LIMITS.replace(Some(limits));
        let previous_retained_builder_bytes = ACTIVE_RETAINED_BUILDER_BYTES.get();
        if previous.is_none() {
            ACTIVE_RETAINED_BUILDER_BYTES.set(0);
        }
        Self {
            previous,
            previous_retained_builder_bytes,
        }
    }
}
impl Drop for SingularOutputLimitGuard {
    fn drop(&mut self) {
        ACTIVE_LIMITS.set(self.previous);
        ACTIVE_RETAINED_BUILDER_BYTES.set(self.previous_retained_builder_bytes);
    }
}
pub(super) fn execute_with_limits<T, E: From<Error>>(
    limits: Option<SingularQueryOutputLimits>,
    execute: impl FnOnce() -> Result<T, E>,
) -> Result<T, E>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let Some(limits) = limits else {
        return execute();
    };
    let _guard = SingularOutputLimitGuard::enter(limits);
    let output = execute()?;
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    bounded_roundtrip_owned(output, limits).map_err(Into::into)
}
/// Own one borrowed producer value without invoking an unmetered deep clone.
///
/// Ordinary/IVM queries have no active guard and retain their existing clone
/// behavior. A server-owned singular lane instead canonicalizes into one
/// hard-capped frame and decodes under the admitted allocation ceiling.
pub(crate) fn own_singular_query_value<T>(value: &T) -> Result<T, Error>
where
    T: Clone + NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let Some(limits) = ACTIVE_LIMITS.get() else {
        return Ok(value.clone());
    };
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    bounded_roundtrip::<T, T>(value, limits)
}
/// Own a sequence of borrowed producer values without first accumulating
/// clones in an intermediate `Vec`.
///
/// The borrowed sequence writes each element directly. The output frame owns
/// the exact `Vec<T>` identity. The only source-sized allocation is therefore the
/// admitted canonical frame, followed by the limit-checked decoded result.
pub(crate) fn own_singular_query_values<'a, T, I>(values: I) -> Result<Vec<T>, Error>
where
    T: Clone + NoritoSerialize + 'a,
    for<'de> T: NoritoDeserialize<'de>,
    I: Clone + Iterator<Item = &'a T>,
{
    let Some(limits) = ACTIVE_LIMITS.get() else {
        return Ok(values.cloned().collect());
    };
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let borrowed = BorrowedSequence { values };
    bounded_roundtrip::<_, Vec<T>>(&borrowed, limits)
}
/// Materialize a struct directly from borrowed fields in declaration order.
///
/// This is the bounded counterpart for projections whose world-state storage
/// splits an entity into an identifier and a value. Outside the server-owned
/// lane the existing constructor is used unchanged. Inside it, the fields are
/// encoded under `T`'s schema without first constructing an owned clone.
pub(crate) fn own_singular_query_struct<T, const N: usize>(
    fields: [&dyn SerializePayload; N],
    fallback: impl FnOnce() -> T,
) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let Some(limits) = ACTIVE_LIMITS.get() else {
        return Ok(fallback());
    };
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let borrowed = BorrowedSingularStruct::<N>::new(fields);
    bounded_roundtrip::<_, T>(&borrowed, limits)
}
fn bounded_roundtrip<S, T>(source: &S, limits: SingularQueryOutputLimits) -> Result<T, Error>
where
    S: SerializePayload,
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let max_frame_bytes =
        usize::try_from(limits.max_frame_bytes).map_err(|_| Error::CapacityLimit)?;
    let bytes =
        norito::core::to_bytes_bounded(&SingularQueryFrame::<T>::new(source), max_frame_bytes)
            .map_err(|_| Error::CapacityLimit)?;
    norito::decode_from_bytes_with_limits::<T>(
        &bytes,
        decode_limits(bytes.len(), limits.max_allocated_bytes)?,
    )
    .map_err(|_| Error::CapacityLimit)
}
fn bounded_roundtrip_owned<T>(source: T, limits: SingularQueryOutputLimits) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    bounded_roundtrip_owned_as(source, limits)
}
/// Materialize an output from an owned wire-equivalent source.
///
/// The source is encoded into the admitted frame and dropped before the destination is decoded.
/// This is used by paged singular producers whose source owns a bounded result builder but borrows
/// request or world fields: neither those borrowed fields nor the complete destination are cloned
/// while the source builder remains resident.
pub(crate) fn own_singular_query_serialized_source<S, T>(source: S) -> Result<T, Error>
where
    S: SerializePayload,
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let limits = ACTIVE_LIMITS.get().ok_or_else(|| {
        Error::Conversion(
            "owned singular serialized source requires an active output limit".to_owned(),
        )
    })?;
    let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    bounded_roundtrip_owned_as(source, limits)
}
fn bounded_roundtrip_owned_as<S, T>(
    source: S,
    limits: SingularQueryOutputLimits,
) -> Result<T, Error>
where
    S: SerializePayload,
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let max_frame_bytes =
        usize::try_from(limits.max_frame_bytes).map_err(|_| Error::CapacityLimit)?;
    let bytes =
        norito::core::to_bytes_bounded(&SingularQueryFrame::<T>::new(&source), max_frame_bytes)
            .map_err(|_| Error::CapacityLimit)?;
    // The admitted frame now owns the source's complete representation. Drop
    // the producer value before allocating its decoded replacement so the
    // final corridor owns either source D or decode D, never both.
    drop(source);
    norito::decode_from_bytes_with_limits::<T>(
        &bytes,
        decode_limits(bytes.len(), limits.max_allocated_bytes)?,
    )
    .map_err(|_| Error::CapacityLimit)
}
/// Internal frame for a wire-equivalent query source. Only the owned output selects its header.
#[repr(C)]
pub(super) struct SingularQueryFrame<'a, T> {
    source: &'a dyn SerializePayload,
    // A zero-length array preserves the output alignment without storing or constructing it.
    _alignment: [T; 0],
}
impl<'a, T> SingularQueryFrame<'a, T> {
    pub(super) fn new(source: &'a dyn SerializePayload) -> Self {
        Self {
            source,
            _alignment: [],
        }
    }
}
impl<T: norito::NoritoSchema> norito::NoritoSchema for SingularQueryFrame<'_, T> {
    fn nominal_name() -> String {
        norito::schema::identity::generic_name(
            "iroha_core::smartcontracts::isi::query::singular_memory::SingularQueryFrame",
            &[T::nominal_name()],
        )
    }
    fn frame_name() -> String {
        T::frame_name()
    }
}
impl<T> SerializePayload for SingularQueryFrame<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
        self.source.serialize(writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.source.encoded_len_exact()
    }
}
/// Encode a payload-only test producer through the actual owned-output frame boundary.
#[cfg(test)]
pub(crate) fn encode_singular_query_source_for_test<S: SerializePayload, T: NoritoSerialize>(
    source: &S,
) -> Vec<u8> {
    use norito::NoritoSchema as _;

    assert_ne!(SingularQueryFrame::<T>::nominal_name(), T::nominal_name());
    assert_eq!(SingularQueryFrame::<T>::frame_name(), T::frame_name());
    assert_eq!(
        norito::schema::identity::frame_hash::<SingularQueryFrame<'_, T>>(),
        norito::schema::identity::frame_hash::<T>(),
    );
    let bytes = norito::encode_canonical(&SingularQueryFrame::<T>::new(source))
        .expect("canonical singular-query source frame");
    assert_eq!(bytes[6..22], norito::schema::identity::frame_hash::<T>());
    bytes
}
struct BorrowedSequence<I> {
    values: I,
}
/// Borrowed wire-equivalent of `Option<T>` for a singular projection field.
pub(crate) struct BorrowedSingularOption<'a, T>(Option<&'a T>);
impl<'a, T> BorrowedSingularOption<'a, T> {
    /// Construct a borrowed optional field.
    #[must_use]
    pub(crate) const fn new(value: Option<&'a T>) -> Self {
        Self(value)
    }
}
impl<T: SerializePayload> SerializePayload for BorrowedSingularOption<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
        match self.0 {
            Some(value) => {
                writer.write_all(&[1])?;
                norito::core::write_len_prefixed(writer, value)
            }
            None => {
                writer.write_all(&[0])?;
                Ok(())
            }
        }
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        match self.0 {
            Some(value) => {
                let value_len = value.encoded_len_exact()?;
                1usize
                    .checked_add(norito::core::len_prefix_len(value_len))?
                    .checked_add(value_len)
            }
            None => Some(1),
        }
    }
}
/// Borrowed wire-equivalent of a derived struct in declaration order.
pub(crate) struct BorrowedSingularStruct<'a, const N: usize> {
    fields: [&'a dyn SerializePayload; N],
}
impl<'a, const N: usize> BorrowedSingularStruct<'a, N> {
    /// Construct a borrowed derived-struct representation.
    #[must_use]
    pub(crate) const fn new(fields: [&'a dyn SerializePayload; N]) -> Self {
        Self { fields }
    }
}
impl<const N: usize> SerializePayload for BorrowedSingularStruct<'_, N> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
        for value in self.fields.iter().copied() {
            norito::core::write_len_prefixed(writer, value)?;
        }
        Ok(())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.fields.iter().try_fold(0usize, |total, value| {
            let value_len = value.encoded_len_exact()?;
            total
                .checked_add(norito::core::len_prefix_len(value_len))?
                .checked_add(value_len)
        })
    }
}
impl<'a, I, T> SerializePayload for BorrowedSequence<I>
where
    T: SerializePayload + 'a,
    I: Clone + Iterator<Item = &'a T>,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
        let count = self.values.clone().count();
        norito::core::write_seq_len(
            writer,
            u64::try_from(count).map_err(|_| norito::core::Error::LengthMismatch)?,
        )?;
        for value in self.values.clone() {
            norito::core::write_len_prefixed(writer, value)?;
        }
        Ok(())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.values.clone().try_fold(8usize, |total, value| {
            let value_len = value.encoded_len_exact()?;
            total
                .checked_add(norito::core::len_prefix_len(value_len))?
                .checked_add(value_len)
        })
    }
}

/// Return the currently admitted complete-frame ceiling, capped by a producer protocol maximum.
pub(crate) fn singular_query_frame_limit(protocol_max: usize) -> usize {
    ACTIVE_LIMITS.get().map_or(protocol_max, |limits| {
        usize::try_from(limits.max_frame_bytes)
            .unwrap_or(usize::MAX)
            .min(protocol_max)
    })
}
/// Return whether server-owned singular limits are active on this worker.
pub(crate) fn singular_query_limits_active() -> bool {
    ACTIVE_LIMITS.get().is_some()
}
/// Fallibly build one retained singular-query sequence under the active resident-output allowance.
///
/// Each inserted value is first measured through the canonical codec. The value's complete frame
/// must fit `E`, and the final vector capacity plus the conservative measured allocation charge for
/// all retained elements must fit `D`. The source value and its bounded frame are dropped before
/// insertion, so a producer retains only this builder between loop iterations.
pub(crate) struct SingularQueryVecBuilder<T> {
    values: Vec<T>,
    item_allocation_bytes: Vec<usize>,
    admitted_capacity: usize,
    retained_nested_bytes: usize,
    retained_charge_bytes: usize,
    encoded_frame_bytes: usize,
}
impl<T> SingularQueryVecBuilder<T>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    /// Construct a builder with a fallibly reserved element capacity.
    pub(crate) fn new(capacity: usize) -> Result<Self, Error> {
        let mut values = Vec::new();
        let mut item_allocation_bytes = Vec::new();
        let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let encoded_frame_bytes =
            norito::core::encoded_frame_len(&values).map_err(|_| Error::CapacityLimit)?;
        if let Some(limits) = ACTIVE_LIMITS.get() {
            let max_frame_bytes =
                usize::try_from(limits.max_frame_bytes).map_err(|_| Error::CapacityLimit)?;
            if encoded_frame_bytes > max_frame_bytes {
                return Err(Error::CapacityLimit);
            }
            // Reject the caller-selected capacity before asking the allocator
            // for it. Checking only `values.capacity()` after `try_reserve_exact`
            // lets an over-budget request transiently allocate (or abort the
            // process) before the singular-query ceiling can fail closed.
            ensure_retained_allocation_fits::<T>(capacity, capacity, 0, limits)?;
            let requested_charge = retained_allocation_bytes::<T>(capacity, capacity, 0)?;
            ensure_retained_builder_charge(0, requested_charge, limits)?;
        }
        values
            .try_reserve_exact(capacity)
            .map_err(|_| Error::CapacityLimit)?;
        if ACTIVE_LIMITS.get().is_some() {
            item_allocation_bytes
                .try_reserve_exact(capacity)
                .map_err(|_| Error::CapacityLimit)?;
        }
        let charge_table_capacity = if ACTIVE_LIMITS.get().is_some() {
            capacity
        } else {
            0
        };
        // Allocator rounding is not attacker-controlled logical capacity. Keep
        // the admitted count as the allocation charge and the push boundary,
        // even when `try_reserve_exact` reports spare physical capacity.
        let retained_charge_bytes =
            retained_allocation_bytes::<T>(capacity, charge_table_capacity, 0)?;
        if let Some(limits) = ACTIVE_LIMITS.get() {
            // `try_reserve_exact` may legally return a larger capacity. Keep
            // the retained logical charge conservative even though the
            // deterministic preflight above is the allocation-safety gate.
            replace_retained_builder_charge(0, retained_charge_bytes, limits)?;
        }
        Ok(Self {
            values,
            item_allocation_bytes,
            admitted_capacity: capacity,
            retained_nested_bytes: 0,
            retained_charge_bytes,
            encoded_frame_bytes,
        })
    }
    /// Canonicalize and admit one value before retaining it.
    pub(crate) fn try_push(&mut self, value: T) -> Result<(), Error> {
        let Some(limits) = ACTIVE_LIMITS.get() else {
            if self.values.len() == self.values.capacity() {
                self.values
                    .try_reserve_exact(1)
                    .map_err(|_| Error::CapacityLimit)?;
            }
            self.values.push(value);
            return Ok(());
        };
        if self.values.len() != self.item_allocation_bytes.len() {
            poison_retained_builder_charge();
            return Err(Error::CapacityLimit);
        }
        if self.values.len() >= self.admitted_capacity {
            return Err(Error::CapacityLimit);
        }
        let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let max_frame_bytes =
            usize::try_from(limits.max_frame_bytes).map_err(|_| Error::CapacityLimit)?;
        let item_payload_bytes =
            norito::core::encoded_payload_len(&value).map_err(|_| Error::CapacityLimit)?;
        let item_frame_bytes = if core::any::type_name::<T>() == "u8" {
            item_payload_bytes
        } else {
            norito::core::len_prefix_len(item_payload_bytes)
                .checked_add(item_payload_bytes)
                .ok_or(Error::CapacityLimit)?
        };
        let next_frame_bytes = self
            .encoded_frame_bytes
            .checked_add(item_frame_bytes)
            .filter(|bytes| *bytes <= max_frame_bytes)
            .ok_or(Error::CapacityLimit)?;
        let bytes = norito::core::to_bytes_bounded(&value, max_frame_bytes)
            .map_err(|_| Error::CapacityLimit)?;
        let item_decode_limits = decode_limits(bytes.len(), limits.max_allocated_bytes)?;
        // The canonical frame now owns the value's complete representation.
        // Drop the producer current before decoding its retained replacement,
        // so the corridor owns either the source or the decoded current, never
        // two D-sized values at once.
        drop(value);
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(item_decode_limits, || {
                norito::decode_from_bytes_with_limits::<T>(&bytes, item_decode_limits)
            });
        let decoded = decoded.map_err(|_| Error::CapacityLimit)?;
        drop(bytes);
        let retained_nested_bytes = self
            .retained_nested_bytes
            .checked_add(usage.total_allocated_bytes())
            .ok_or(Error::CapacityLimit)?;
        let requested_charge = retained_allocation_bytes::<T>(
            self.admitted_capacity,
            self.admitted_capacity,
            retained_nested_bytes,
        )?;
        ensure_retained_builder_charge(self.retained_charge_bytes, requested_charge, limits)?;
        let retained_charge_bytes = retained_allocation_bytes::<T>(
            self.admitted_capacity,
            self.admitted_capacity,
            retained_nested_bytes,
        )?;
        replace_retained_builder_charge(self.retained_charge_bytes, retained_charge_bytes, limits)?;
        self.values.push(decoded);
        self.item_allocation_bytes
            .push(usage.total_allocated_bytes());
        self.retained_nested_bytes = retained_nested_bytes;
        self.retained_charge_bytes = retained_charge_bytes;
        self.encoded_frame_bytes = next_frame_bytes;
        Ok(())
    }
    /// Number of values currently retained by the builder.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }
    /// Whether the builder currently retains no values.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    /// Return the most recently retained value.
    #[must_use]
    pub(crate) fn last(&self) -> Option<&T> {
        self.values.last()
    }
    /// Finish the builder without copying its retained values.
    pub(crate) fn into_vec(mut self) -> Result<Vec<T>, Error> {
        let output_charge =
            retained_allocation_bytes::<T>(self.admitted_capacity, 0, self.retained_nested_bytes)?;
        if let Some(limits) = ACTIVE_LIMITS.get() {
            replace_retained_builder_charge(self.retained_charge_bytes, output_charge, limits)?;
        }
        let values = core::mem::take(&mut self.values);
        self.item_allocation_bytes.clear();
        // The output vector remains covered by `output_charge` until the
        // enclosing singular-query allocation scope resets the ledger.
        self.retained_charge_bytes = 0;
        Ok(values)
    }
    /// Finish into a vector that keeps its aggregate builder charge attached.
    ///
    /// This form is for producers that retain several source collections and consume them into one
    /// final builder. Moving one item into the current corridor releases only that item's nested
    /// source charge; the source allocation itself remains charged until its iterator is dropped.
    #[must_use]
    pub(crate) fn into_retained_vec(mut self) -> SingularQueryRetainedVec<T> {
        let values = core::mem::take(&mut self.values);
        let item_allocation_bytes = core::mem::take(&mut self.item_allocation_bytes);
        let retained_charge_bytes = self.retained_charge_bytes;
        self.retained_charge_bytes = 0;
        SingularQueryRetainedVec {
            values,
            item_allocation_bytes,
            retained_charge_bytes,
        }
    }
}
impl<T> Drop for SingularQueryVecBuilder<T> {
    fn drop(&mut self) {
        let _ = release_retained_builder_charge(self.retained_charge_bytes);
    }
}
/// A producer vector whose aggregate resident charge follows its allocation.
pub(crate) struct SingularQueryRetainedVec<T> {
    values: Vec<T>,
    item_allocation_bytes: Vec<usize>,
    retained_charge_bytes: usize,
}
impl<T> Deref for SingularQueryRetainedVec<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<T> SingularQueryRetainedVec<T> {
    /// Sort values and their measured nested-allocation charges together.
    ///
    /// This uses an in-place heapsort so producer validation never allocates a
    /// second permutation or charge table beside the retained source vector.
    pub(crate) fn sort_by(&mut self, mut compare: impl FnMut(&T, &T) -> core::cmp::Ordering) {
        let len = self.values.len();
        if len < 2 {
            return;
        }
        for root in (0..(len / 2)).rev() {
            self.sift_down(root, len, &mut compare);
        }
        for end in (1..len).rev() {
            self.swap_items(0, end);
            self.sift_down(0, end, &mut compare);
        }
    }
    fn sift_down(
        &mut self,
        mut root: usize,
        end: usize,
        compare: &mut impl FnMut(&T, &T) -> core::cmp::Ordering,
    ) {
        loop {
            let Some(left) = root.checked_mul(2).and_then(|index| index.checked_add(1)) else {
                return;
            };
            if left >= end {
                return;
            }
            let right = left + 1;
            let mut larger = left;
            if right < end
                && compare(&self.values[left], &self.values[right]) == core::cmp::Ordering::Less
            {
                larger = right;
            }
            if compare(&self.values[root], &self.values[larger]) != core::cmp::Ordering::Less {
                return;
            }
            self.swap_items(root, larger);
            root = larger;
        }
    }
    fn swap_items(&mut self, left: usize, right: usize) {
        self.values.swap(left, right);
        if self.item_allocation_bytes.len() == self.values.len() {
            self.item_allocation_bytes.swap(left, right);
        }
    }
}
impl<T> Drop for SingularQueryRetainedVec<T> {
    fn drop(&mut self) {
        let _ = release_retained_builder_charge(self.retained_charge_bytes);
    }
}
pub(crate) struct SingularQueryRetainedVecIntoIter<T> {
    values: std::vec::IntoIter<T>,
    item_allocation_bytes: std::vec::IntoIter<usize>,
    retained_charge_bytes: usize,
}
impl<T> Iterator for SingularQueryRetainedVecIntoIter<T> {
    type Item = Result<(T, usize), Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.next_with_allocation_charge() {
            Ok(Some(item)) => Some(Ok(item)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        if ACTIVE_LIMITS.get().is_some()
            && self.values.as_slice().len() != self.item_allocation_bytes.as_slice().len()
        {
            (0, None)
        } else {
            self.values.size_hint()
        }
    }
}
impl<T> SingularQueryRetainedVecIntoIter<T> {
    /// Move the next value into the current corridor with its measured nested allocation charge.
    pub(crate) fn next_with_allocation_charge(&mut self) -> Result<Option<(T, usize)>, Error> {
        let Some(value) = self.values.next() else {
            if ACTIVE_LIMITS.get().is_some() && !self.item_allocation_bytes.as_slice().is_empty() {
                poison_retained_builder_charge();
                return Err(Error::CapacityLimit);
            }
            return Ok(None);
        };
        // Ordinary in-process callers do not install an allocation ledger.
        // Preserve that legacy behavior while enforcing the private parallel-
        // vector invariant for every server-owned execution.
        if ACTIVE_LIMITS.get().is_none() {
            let item_allocation_bytes = self.item_allocation_bytes.next().unwrap_or(0);
            self.retained_charge_bytes = self
                .retained_charge_bytes
                .saturating_sub(item_allocation_bytes);
            return Ok(Some((value, item_allocation_bytes)));
        }
        let Some(item_allocation_bytes) = self.item_allocation_bytes.next() else {
            poison_retained_builder_charge();
            return Err(Error::CapacityLimit);
        };
        let Some(retained_charge_bytes) = self
            .retained_charge_bytes
            .checked_sub(item_allocation_bytes)
        else {
            poison_retained_builder_charge();
            return Err(Error::CapacityLimit);
        };
        if !release_retained_builder_charge(item_allocation_bytes) {
            return Err(Error::CapacityLimit);
        }
        self.retained_charge_bytes = retained_charge_bytes;
        Ok(Some((value, item_allocation_bytes)))
    }
    /// Remaining values, used by sorted merge validation.
    #[must_use]
    pub(crate) fn as_slice(&self) -> &[T] {
        self.values.as_slice()
    }
}
impl<T> Drop for SingularQueryRetainedVecIntoIter<T> {
    fn drop(&mut self) {
        let _ = release_retained_builder_charge(self.retained_charge_bytes);
    }
}
impl<T> IntoIterator for SingularQueryRetainedVec<T> {
    type Item = Result<(T, usize), Error>;
    type IntoIter = SingularQueryRetainedVecIntoIter<T>;
    fn into_iter(mut self) -> Self::IntoIter {
        let values = core::mem::take(&mut self.values).into_iter();
        let item_allocation_bytes = core::mem::take(&mut self.item_allocation_bytes).into_iter();
        let retained_charge_bytes = self.retained_charge_bytes;
        self.retained_charge_bytes = 0;
        SingularQueryRetainedVecIntoIter {
            values,
            item_allocation_bytes,
            retained_charge_bytes,
        }
    }
}
fn ensure_retained_allocation_fits<T>(
    capacity: usize,
    charge_capacity: usize,
    retained_nested_bytes: usize,
    limits: SingularQueryOutputLimits,
) -> Result<(), Error> {
    let retained_bytes =
        retained_allocation_bytes::<T>(capacity, charge_capacity, retained_nested_bytes)?;
    let max_allocated_bytes =
        usize::try_from(limits.max_allocated_bytes).map_err(|_| Error::CapacityLimit)?;
    (retained_bytes <= max_allocated_bytes)
        .then_some(())
        .ok_or(Error::CapacityLimit)
}
fn retained_allocation_bytes<T>(
    capacity: usize,
    charge_capacity: usize,
    retained_nested_bytes: usize,
) -> Result<usize, Error> {
    let inline_bytes = capacity
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(Error::CapacityLimit)?;
    let charge_table_bytes = charge_capacity
        .checked_mul(core::mem::size_of::<usize>())
        .ok_or(Error::CapacityLimit)?;
    inline_bytes
        .checked_add(charge_table_bytes)
        .and_then(|bytes| bytes.checked_add(retained_nested_bytes))
        .ok_or(Error::CapacityLimit)
}
fn ensure_retained_builder_charge(
    previous_charge: usize,
    next_charge: usize,
    limits: SingularQueryOutputLimits,
) -> Result<(), Error> {
    let retained_bytes = ACTIVE_RETAINED_BUILDER_BYTES
        .get()
        .checked_sub(previous_charge)
        .and_then(|bytes| bytes.checked_add(next_charge))
        .ok_or(Error::CapacityLimit)?;
    let max_allocated_bytes =
        usize::try_from(limits.max_allocated_bytes).map_err(|_| Error::CapacityLimit)?;
    (retained_bytes <= max_allocated_bytes)
        .then_some(())
        .ok_or(Error::CapacityLimit)
}
fn replace_retained_builder_charge(
    previous_charge: usize,
    next_charge: usize,
    limits: SingularQueryOutputLimits,
) -> Result<(), Error> {
    ensure_retained_builder_charge(previous_charge, next_charge, limits)?;
    let retained_bytes = ACTIVE_RETAINED_BUILDER_BYTES
        .get()
        .checked_sub(previous_charge)
        .and_then(|bytes| bytes.checked_add(next_charge))
        .ok_or(Error::CapacityLimit)?;
    ACTIVE_RETAINED_BUILDER_BYTES.set(retained_bytes);
    Ok(())
}
fn poison_retained_builder_charge() {
    if ACTIVE_LIMITS.get().is_some() {
        ACTIVE_RETAINED_BUILDER_BYTES.set(usize::MAX);
    }
}
/// Release one retained charge, poisoning the active ledger on underflow.
///
/// `false` means the ledger was already poisoned or this release exposed an
/// internal ownership-accounting mismatch. The poison is sticky for the
/// current scoped guard so every subsequent admission fails closed.
fn release_retained_builder_charge(charge: usize) -> bool {
    if ACTIVE_LIMITS.get().is_none() {
        return true;
    }
    let retained_bytes = ACTIVE_RETAINED_BUILDER_BYTES.get();
    if retained_bytes == usize::MAX {
        return false;
    }
    if charge == 0 {
        return true;
    }
    let Some(retained_bytes) = retained_bytes.checked_sub(charge) else {
        poison_retained_builder_charge();
        return false;
    };
    ACTIVE_RETAINED_BUILDER_BYTES.set(retained_bytes);
    true
}
/// Resident allocation owned by the one current producer value.
///
/// This counter is deliberately local to one loop iteration. It is not a
/// cumulative decode quota: after the current value is dropped, the next
/// source record receives the complete D allowance again.
pub(crate) struct SingularQueryCurrentAllocation {
    retained_bytes: usize,
}
/// A current-value vector with one immutable, logically admitted item count.
///
/// The backing allocator may round its physical capacity up, but callers can only insert through
/// [`Self::push`], which never admits more than the count charged to the current-value allowance.
pub(crate) struct SingularQueryFixedVec<T> {
    values: Vec<T>,
    admitted_capacity: usize,
}
impl<T> SingularQueryFixedVec<T> {
    /// Insert one item without growing beyond the admitted logical count.
    pub(crate) fn push(&mut self, value: T) -> Result<(), Error> {
        if self.values.len() >= self.admitted_capacity {
            return Err(Error::CapacityLimit);
        }
        self.values.push(value);
        Ok(())
    }
    /// Release the fixed-count wrapper without copying its values.
    pub(crate) fn into_vec(self) -> Vec<T> {
        self.values
    }
}
impl<T> Deref for SingularQueryFixedVec<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl SingularQueryCurrentAllocation {
    /// Start accounting with the measured nested allocation of a decoded
    /// source record moved out of a retained builder.
    pub(crate) fn new(retained_bytes: usize) -> Result<Self, Error> {
        let current = Self { retained_bytes };
        current.ensure_fits()?;
        Ok(current)
    }
    /// Add one moved decoded record to the current value.
    pub(crate) fn add_nested(&mut self, bytes: usize) -> Result<(), Error> {
        self.retained_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or(Error::CapacityLimit)?;
        self.ensure_fits()
    }
    /// Return the measured allocation currently resident in this producer
    /// value so a nested validator can start a fresh, non-cumulative decode
    /// phase beside exactly the values that remain live.
    #[must_use]
    pub(crate) const fn resident_bytes(&self) -> usize {
        self.retained_bytes
    }
    /// Cap one additional source decode by the unoccupied part of this
    /// current value's resident allowance.
    ///
    /// Callers measure the successful decode and feed its allocation charge back through
    /// [`Self::add_nested`]. This permits several records that are genuinely live at once while
    /// preventing each nested reader from independently claiming a complete `D` allowance.
    pub(crate) fn decode_limits(
        &self,
        encoded_len: usize,
        protocol: norito::DecodeLimits,
    ) -> Result<norito::DecodeLimits, Error> {
        singular_query_decode_limits_after_resident(encoded_len, protocol, self.retained_bytes)
    }
    /// Fallibly reserve an inline vector owned by the current value.
    pub(crate) fn vec_with_capacity<T>(
        &mut self,
        capacity: usize,
    ) -> Result<SingularQueryFixedVec<T>, Error> {
        let requested = capacity
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(Error::CapacityLimit)?;
        let next = self
            .retained_bytes
            .checked_add(requested)
            .ok_or(Error::CapacityLimit)?;
        Self {
            retained_bytes: next,
        }
        .ensure_fits()?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| Error::CapacityLimit)?;
        self.retained_bytes = next;
        Ok(SingularQueryFixedVec {
            values,
            admitted_capacity: capacity,
        })
    }
    fn ensure_fits(&self) -> Result<(), Error> {
        let Some(limits) = ACTIVE_LIMITS.get() else {
            return Ok(());
        };
        let maximum =
            usize::try_from(limits.max_allocated_bytes).map_err(|_| Error::CapacityLimit)?;
        (self.retained_bytes <= maximum)
            .then_some(())
            .ok_or(Error::CapacityLimit)
    }
}
/// Cap an existing producer decode policy by the active singular-query lane.
///
/// The protocol's tighter dimensions are preserved. Persisted source records
/// are not required to fit the eventual response frame, but no decoded field
/// or collection may allocate beyond the response's admitted decode budget.
pub(crate) fn singular_query_decode_limits(
    encoded_len: usize,
    protocol: norito::DecodeLimits,
) -> Result<norito::DecodeLimits, Error> {
    singular_query_decode_limits_after_resident(encoded_len, protocol, 0)
}
fn singular_query_decode_limits_after_resident(
    encoded_len: usize,
    protocol: norito::DecodeLimits,
    resident_allocated_bytes: usize,
) -> Result<norito::DecodeLimits, Error> {
    let Some(active) = ACTIVE_LIMITS.get() else {
        return Ok(protocol);
    };
    let allocated = usize::try_from(active.max_allocated_bytes)
        .map_err(|_| Error::CapacityLimit)?
        .checked_sub(resident_allocated_bytes)
        .ok_or(Error::CapacityLimit)?;
    Ok(norito::DecodeLimits::new(
        protocol.max_sequence_elements().min(allocated),
        protocol.max_field_bytes().min(encoded_len).min(allocated),
        protocol.max_total_elements().min(allocated),
        protocol.max_total_allocated_bytes().min(allocated),
        protocol.max_nesting_depth(),
    ))
}
fn decode_limits(
    encoded_len: usize,
    max_allocated_bytes: u64,
) -> Result<norito::DecodeLimits, Error> {
    let max_allocated_bytes =
        usize::try_from(max_allocated_bytes).map_err(|_| Error::CapacityLimit)?;
    let elements = encoded_len.checked_mul(8).ok_or(Error::CapacityLimit)?;
    Ok(norito::DecodeLimits::new(
        elements,
        encoded_len,
        elements,
        max_allocated_bytes,
        64,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::NoritoSchema as _;
    use norito::core::DeserializePayload;
    use std::cell::Cell;

    #[test]
    fn borrowed_optional_fields_preserve_owned_frames_and_nominal_arguments() {
        for value in [None, Some(41_u64)] {
            let borrowed = BorrowedSingularOption::new(value.as_ref());
            assert_eq!(
                norito::encode_canonical(&SingularQueryFrame::<Option<u64>>::new(&borrowed))
                    .unwrap(),
                norito::encode_canonical(&value).unwrap(),
            );
        }
        assert_ne!(
            Vec::<SingularQueryFrame<'_, Option<u64>>>::nominal_name(),
            Vec::<Option<u64>>::nominal_name(),
        );
        assert_ne!(
            SingularQueryFrame::<Option<u64>>::nominal_name(),
            SingularQueryFrame::<Option<u32>>::nominal_name(),
        );
    }

    #[test]
    fn borrowed_sequence_frames_are_independent_of_the_iterator_producer() {
        let values = vec![11_u64, 23, 37];
        let direct = BorrowedSequence {
            values: values.iter(),
        };
        let composed = BorrowedSequence {
            values: values[..1].iter().chain(values[1..].iter()),
        };
        let owned_frame = norito::encode_canonical(&values).unwrap();
        assert_eq!(
            norito::encode_canonical(&SingularQueryFrame::<Vec<u64>>::new(&direct)).unwrap(),
            owned_frame
        );
        assert_eq!(
            norito::encode_canonical(&SingularQueryFrame::<Vec<u64>>::new(&composed)).unwrap(),
            owned_frame
        );
    }

    #[test]
    fn borrowed_struct_frames_preserve_the_declared_owned_schema() {
        #[derive(norito::Encode, norito::NoritoSchema)]
        #[norito_schema(name = "iroha_core::query::tests::SingularProjection")]
        struct Projection {
            value: u64,
            label: String,
        }
        let owned = Projection {
            value: 19,
            label: "projection".to_owned(),
        };
        let borrowed = BorrowedSingularStruct::<2>::new([&owned.value, &owned.label]);
        assert_eq!(
            norito::encode_canonical(&SingularQueryFrame::<Projection>::new(&borrowed)).unwrap(),
            norito::encode_canonical(&owned).unwrap(),
        );
        assert_ne!(
            SingularQueryFrame::<'_, Projection>::nominal_name(),
            Projection::nominal_name(),
        );
    }
    thread_local! {
        static OWNED_SOURCE_DROPPED: Cell<bool> = const { Cell::new(false) };
        static ENCODE_ERROR_SOURCE_DROPPED: Cell<bool> = const { Cell::new(false) };
        static DECODE_ERROR_SOURCE_DROPPED: Cell<bool> = const { Cell::new(false) };
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha.core.test.singular-query.drop-before-decode")]
    struct DropBeforeDecodeProbe {
        source: bool,
        marker: u8,
        allocation: Vec<u8>,
    }
    impl Drop for DropBeforeDecodeProbe {
        fn drop(&mut self) {
            if self.source {
                OWNED_SOURCE_DROPPED.set(true);
            }
        }
    }
    impl SerializePayload for DropBeforeDecodeProbe {
        fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
            SerializePayload::serialize(&self.marker, encoder)
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            Some(1)
        }
    }
    impl<'de> DeserializePayload<'de> for DropBeforeDecodeProbe {
        fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
            Self::try_deserialize(archived).expect("drop-before-decode probe")
        }
        fn try_deserialize(
            _archived: &'de norito::core::Archived<Self>,
        ) -> Result<Self, norito::core::Error> {
            if !OWNED_SOURCE_DROPPED.get() {
                return Err(norito::core::Error::LengthMismatch);
            }
            norito::core::reserve_decode_allocation(256)?;
            Ok(Self {
                source: false,
                marker: 7,
                allocation: vec![0; 256],
            })
        }
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha.core.test.singular-query.encode-error")]
    struct EncodeErrorDropProbe;
    impl Drop for EncodeErrorDropProbe {
        fn drop(&mut self) {
            ENCODE_ERROR_SOURCE_DROPPED.set(true);
        }
    }
    impl SerializePayload for EncodeErrorDropProbe {
        fn serialize(&self, _encoder: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
            Err(norito::core::Error::LengthMismatch)
        }
    }
    impl<'de> DeserializePayload<'de> for EncodeErrorDropProbe {
        fn deserialize(_archived: &'de norito::core::Archived<Self>) -> Self {
            Self
        }
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha.core.test.singular-query.decode-error")]
    struct DecodeErrorDropProbe {
        source: bool,
    }
    impl Drop for DecodeErrorDropProbe {
        fn drop(&mut self) {
            if self.source {
                DECODE_ERROR_SOURCE_DROPPED.set(true);
            }
        }
    }
    impl SerializePayload for DecodeErrorDropProbe {
        fn serialize(&self, encoder: &mut Encoder<'_>) -> Result<(), norito::core::Error> {
            SerializePayload::serialize(&1_u8, encoder)
        }
    }
    impl<'de> DeserializePayload<'de> for DecodeErrorDropProbe {
        fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
            Self::try_deserialize(archived).expect("decode-error probe")
        }
        fn try_deserialize(
            _archived: &'de norito::core::Archived<Self>,
        ) -> Result<Self, norito::core::Error> {
            Err(norito::core::Error::LengthMismatch)
        }
    }
    #[test]
    fn final_owned_roundtrip_drops_source_before_decode_allocation() {
        OWNED_SOURCE_DROPPED.set(false);
        let limits = SingularQueryOutputLimits::new(1_024, 1_024);
        let decoded = execute_with_limits(Some(limits), || {
            Ok::<_, Error>(DropBeforeDecodeProbe {
                source: true,
                marker: 7,
                allocation: vec![0; 256],
            })
        })
        .expect("owned source drops before decoder allocation");
        assert!(OWNED_SOURCE_DROPPED.get());
        assert_eq!(decoded.marker, 7);
        assert_eq!(decoded.allocation.len(), 256);
    }
    #[test]
    fn final_owned_roundtrip_drops_source_on_encode_error() {
        ENCODE_ERROR_SOURCE_DROPPED.set(false);
        let limits = SingularQueryOutputLimits::new(1_024, 1_024);
        assert!(matches!(
            execute_with_limits(Some(limits), || Ok(EncodeErrorDropProbe)),
            Err(Error::CapacityLimit)
        ));
        assert!(ENCODE_ERROR_SOURCE_DROPPED.get());
    }
    #[test]
    fn final_owned_roundtrip_drops_source_before_decode_error() {
        DECODE_ERROR_SOURCE_DROPPED.set(false);
        let limits = SingularQueryOutputLimits::new(1_024, 1_024);
        assert!(matches!(
            execute_with_limits(Some(limits), || Ok(DecodeErrorDropProbe { source: true })),
            Err(Error::CapacityLimit)
        ));
        assert!(DECODE_ERROR_SOURCE_DROPPED.get());
    }
    #[test]
    fn scoped_limits_restore_the_previous_value() {
        let outer = SingularQueryOutputLimits::new(1024, 2048);
        let inner = SingularQueryOutputLimits::new(64, 128);
        let _outer = SingularOutputLimitGuard::enter(outer);
        assert_eq!(ACTIVE_LIMITS.get(), Some(outer));
        {
            let _inner = SingularOutputLimitGuard::enter(inner);
            assert_eq!(ACTIVE_LIMITS.get(), Some(inner));
        }
        assert_eq!(ACTIVE_LIMITS.get(), Some(outer));
    }
    #[test]
    fn builder_capacity_is_rejected_by_the_retained_limit() {
        let one_slot_bytes = core::mem::size_of::<u64>() + core::mem::size_of::<usize>();
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(
            1_024,
            u64::try_from(one_slot_bytes).expect("one test slot fits"),
        ));
        assert!(SingularQueryVecBuilder::<u64>::new(1).is_ok());
        assert!(matches!(
            SingularQueryVecBuilder::<u64>::new(2),
            Err(Error::CapacityLimit)
        ));
    }
    #[test]
    fn retained_builders_share_one_resident_allowance() {
        let one_slot_bytes = core::mem::size_of::<u64>() + core::mem::size_of::<usize>();
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(
            1_024,
            u64::try_from(one_slot_bytes).expect("one test slot fits"),
        ));
        let first = SingularQueryVecBuilder::<u64>::new(1).expect("first builder fits");
        assert!(matches!(
            SingularQueryVecBuilder::<u64>::new(1),
            Err(Error::CapacityLimit)
        ));
        drop(first);
        assert!(SingularQueryVecBuilder::<u64>::new(1).is_ok());
    }
    #[test]
    fn current_allocation_is_resident_not_cumulative() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(1_024, 16));
        {
            let mut current = SingularQueryCurrentAllocation::new(8).expect("first current fits");
            current.add_nested(8).expect("complete first current fits");
            assert!(matches!(current.add_nested(1), Err(Error::CapacityLimit)));
        }
        let mut next = SingularQueryCurrentAllocation::new(8).expect("next current resets D");
        next.add_nested(8).expect("complete next current fits");
    }
    #[test]
    fn current_decode_limit_uses_only_the_resident_remainder() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(1_024, 16));
        let current = SingularQueryCurrentAllocation::new(6).expect("initial current fits");
        let protocol = norito::DecodeLimits::new(64, 64, 64, 64, 8);
        let limits = current
            .decode_limits(32, protocol)
            .expect("remaining current decode fits");
        assert_eq!(limits.max_total_allocated_bytes(), 10);
        assert_eq!(limits.max_field_bytes(), 10);
    }
    #[test]
    fn builder_rejects_an_oversized_item_before_retaining_it() {
        let _canonical_flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let empty_frame = norito::core::encoded_frame_len(&Vec::<String>::new())
            .expect("empty string vector has a canonical frame");
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(
            u64::try_from(empty_frame).expect("test frame length fits u64"),
            4_096,
        ));
        let mut builder = SingularQueryVecBuilder::new(1).expect("empty builder fits exactly");
        assert!(matches!(
            builder.try_push("x".to_owned()),
            Err(Error::CapacityLimit)
        ));
        assert!(builder.is_empty());
    }
    #[test]
    fn builder_preserves_values_inside_resident_limits() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(4_096, 4_096));
        let mut builder = SingularQueryVecBuilder::new(2).expect("test builder allocation fits");
        builder
            .try_push("alpha".to_owned())
            .expect("first value fits");
        builder
            .try_push("beta".to_owned())
            .expect("second value fits");
        assert_eq!(
            builder.into_vec().expect("finished builder fits"),
            ["alpha", "beta"]
        );
    }
    #[test]
    fn active_builder_never_grows_beyond_its_preallocated_capacity() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(4_096, 4_096));
        let mut builder = SingularQueryVecBuilder::new(1).expect("one slot fits");
        builder.try_push(7_u64).expect("preallocated slot fits");
        assert!(matches!(builder.try_push(8_u64), Err(Error::CapacityLimit)));
        assert_eq!(builder.into_vec().expect("finished builder fits"), [7]);
    }
    #[test]
    fn spare_allocator_capacity_does_not_expand_builder_admission() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(4_096, 4_096));
        let mut builder = SingularQueryVecBuilder::new(1).expect("one logical slot fits");
        // Simulate an allocator that rounded both reservations up. Admission
        // remains tied to the charged count, not the backing Vec capacities.
        builder.values.reserve(32);
        builder.item_allocation_bytes.reserve(32);
        assert!(builder.values.capacity() > builder.admitted_capacity);
        assert!(builder.item_allocation_bytes.capacity() > builder.admitted_capacity);
        builder.try_push(7_u64).expect("admitted slot fits");
        assert!(matches!(builder.try_push(8_u64), Err(Error::CapacityLimit)));
        assert_eq!(builder.into_vec().expect("finished builder fits"), [7]);
    }
    #[test]
    fn current_fixed_vec_rejects_spare_allocator_capacity() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(4_096, 64));
        let mut current = SingularQueryCurrentAllocation::new(0).expect("empty current fits");
        let mut values = current
            .vec_with_capacity::<u64>(1)
            .expect("one logical slot fits");
        assert_eq!(current.retained_bytes, core::mem::size_of::<u64>());
        values.values.reserve(32);
        assert!(values.values.capacity() > values.admitted_capacity);
        values.push(7).expect("admitted slot fits");
        assert!(matches!(values.push(8), Err(Error::CapacityLimit)));
        assert_eq!(values.into_vec(), [7]);
    }
    #[test]
    fn retained_vector_sort_keeps_nested_charges_aligned() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(8_192, 8_192));
        let mut builder = SingularQueryVecBuilder::new(2).expect("two string slots fit");
        builder.try_push("z".repeat(64)).expect("long string fits");
        builder.try_push("a".to_owned()).expect("short string fits");
        let mut retained = builder.into_retained_vec();
        retained.sort_by(Ord::cmp);
        let mut retained = retained.into_iter();
        let (short, short_charge) = retained
            .next_with_allocation_charge()
            .expect("retained charge table remains valid")
            .expect("short string remains");
        let (long, long_charge) = retained
            .next_with_allocation_charge()
            .expect("retained charge table remains valid")
            .expect("long string remains");
        assert_eq!(short, "a");
        assert_eq!(long, "z".repeat(64));
        assert!(short_charge < long_charge);
    }
    #[test]
    fn retained_builder_double_release_poison_is_sticky_until_scope_exit() {
        {
            let one_slot_bytes = core::mem::size_of::<u64>() + core::mem::size_of::<usize>();
            let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(
                1_024,
                u64::try_from(one_slot_bytes).expect("one test slot fits"),
            ));
            let builder = SingularQueryVecBuilder::<u64>::new(1).expect("one builder fits");
            let charge = builder.retained_charge_bytes;
            assert!(release_retained_builder_charge(charge));
            drop(builder);
            assert_eq!(ACTIVE_RETAINED_BUILDER_BYTES.get(), usize::MAX);
            assert!(matches!(
                SingularQueryVecBuilder::<u64>::new(0),
                Err(Error::CapacityLimit)
            ));
            assert!(!release_retained_builder_charge(1));
            assert_eq!(ACTIVE_RETAINED_BUILDER_BYTES.get(), usize::MAX);
        }
        assert_eq!(ACTIVE_RETAINED_BUILDER_BYTES.get(), 0);
    }
    #[test]
    fn retained_vector_missing_charge_fails_closed() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(1_024, 1_024));
        ACTIVE_RETAINED_BUILDER_BYTES.set(1);
        let mut retained = SingularQueryRetainedVecIntoIter {
            values: vec![7_u64].into_iter(),
            item_allocation_bytes: Vec::new().into_iter(),
            retained_charge_bytes: 1,
        };
        assert!(matches!(
            retained.next_with_allocation_charge(),
            Err(Error::CapacityLimit)
        ));
        assert_eq!(ACTIVE_RETAINED_BUILDER_BYTES.get(), usize::MAX);
        assert!(matches!(
            SingularQueryVecBuilder::<u64>::new(0),
            Err(Error::CapacityLimit)
        ));
    }
    #[test]
    fn retained_vector_charge_subtraction_underflow_fails_closed() {
        let _limits = SingularOutputLimitGuard::enter(SingularQueryOutputLimits::new(1_024, 1_024));
        ACTIVE_RETAINED_BUILDER_BYTES.set(1);
        let mut retained = SingularQueryRetainedVecIntoIter {
            values: vec![7_u64].into_iter(),
            item_allocation_bytes: vec![2].into_iter(),
            retained_charge_bytes: 1,
        };
        assert!(matches!(
            retained.next_with_allocation_charge(),
            Err(Error::CapacityLimit)
        ));
        assert_eq!(ACTIVE_RETAINED_BUILDER_BYTES.get(), usize::MAX);
        assert!(matches!(
            SingularQueryVecBuilder::<u64>::new(0),
            Err(Error::CapacityLimit)
        ));
    }
}

#[cfg(test)]
#[path = "singular_memory_frame_tests.rs"]
mod frame_tests;
