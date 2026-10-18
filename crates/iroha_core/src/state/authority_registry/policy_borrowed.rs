//! Borrowed canonical policy payloads and original-pool ordering scratch.
//!
//! These helpers emit the existing bare V1 field layout. They do not collect
//! payloads, select policy, read State, or acquire publication authority.

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use norito::core::{Encoder, Error, SerializePayload};
use std::io::Write;

/// Borrow an existing canonical payload without copying its variable storage.
#[derive(Clone, Copy)]
pub(crate) struct Ref<'a, T: ?Sized>(pub(crate) &'a T);
impl<T: SerializePayload + ?Sized> SerializePayload for Ref<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
}

/// Preserve a derived struct's special raw fixed-byte-array field layout.
pub(crate) struct Raw<'a>(pub(crate) &'a [u8]);
impl SerializePayload for Raw<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(self.0)?;
        Ok(())
    }
}

/// An immutable stack projection whose fields are measured and streamed twice.
pub(crate) struct Payload<F>(pub(crate) F);
impl<F> SerializePayload for Payload<F>
where
    F: Fn(&mut Encoder<'_>) -> Result<(), Error>,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        (self.0)(writer)
    }
}

/// An immutable linked tuple of already borrowed record fields.
pub(crate) struct FieldsEnd;
pub(crate) struct FieldsCons<H, T>(pub(crate) H, pub(crate) T);
pub(crate) trait Fields {
    fn fields(&self, writer: &mut Encoder<'_>) -> Result<(), Error>;
}
impl Fields for FieldsEnd {
    fn fields(&self, _: &mut Encoder<'_>) -> Result<(), Error> {
        Ok(())
    }
}
impl<H: SerializePayload, T: Fields> Fields for FieldsCons<H, T> {
    fn fields(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        norito::core::write_len_prefixed(writer, &self.0)?;
        self.1.fields(writer)
    }
}
pub(crate) struct Record<T>(pub(crate) T);
impl<T: Fields> SerializePayload for Record<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.0.fields(writer)
    }
}
macro_rules! record_fields {
    () => { $crate::state::authority_registry::policy_borrowed::FieldsEnd };
    ($first:expr $(, $rest:expr)* $(,)?) => {
        $crate::state::authority_registry::policy_borrowed::FieldsCons($first,
            $crate::state::authority_registry::policy_borrowed::record_fields!($($rest),*))
    };
}
pub(crate) use record_fields;
/// Emit exactly the field prefixes of an ordinary derived Norito struct.
macro_rules! record {
    ($($value:expr),* $(,)?) => {
        $crate::state::authority_registry::policy_borrowed::Record(
            $crate::state::authority_registry::policy_borrowed::record_fields!($($value),*))
    };
}
pub(crate) use record;

/// Borrow or project an ordered sequence without collecting a second vector.
pub(crate) struct Seq<I>(pub(crate) I);
impl<I> SerializePayload for Seq<I>
where
    I: Clone + ExactSizeIterator,
    I::Item: SerializePayload,
{
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        norito::core::write_element_sequence::<I::Item, _>(writer, self.0.clone())
    }
}

/// Emit a nested bare payload using the wire layout of its original `Vec<u8>`.
pub(crate) struct BareBytes<T>(pub(crate) T);
impl<T: SerializePayload> SerializePayload for BareBytes<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let length = norito::core::encoded_payload_len(&self.0)?;
        norito::core::write_seq_len(
            writer,
            u64::try_from(length).map_err(|_| Error::LengthMismatch)?,
        )?;
        self.0.serialize(writer)
    }
}

/// Original pool refusal or impossible source/backing count discrepancy.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OrderError {
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    #[error("canonical policy source exceeded its admitted reference count")]
    SourceCount,
    #[error("canonical policy ordering codec failed: {0}")]
    Codec(norito::Error),
}

/// Original-pool references used when policy semantics require a sorted set.
pub(crate) struct SortedRefs<'a, T>(ChargedBuffer<&'a T>);
impl<'a, T> SortedRefs<'a, T> {
    pub(crate) fn new_by(
        source: &'a [T],
        budget: &AllocationBudget,
        mut compare: impl FnMut(&T, &T) -> std::cmp::Ordering,
    ) -> Result<Self, OrderError> {
        let mut values = ChargedBuffer::new(source.len(), budget)?;
        for value in source {
            // Backing was fully admitted before the first reference is retained.
            values
                .try_push(value)
                .map_err(|_| OrderError::SourceCount)?;
        }
        values
            .as_mut_slice()
            .sort_unstable_by(|left, right| compare(left, right));
        Ok(Self(values))
    }
    pub(crate) fn unique(&self) -> Unique<'_, 'a, T>
    where
        T: PartialEq,
    {
        let source = self.0.as_slice();
        let remaining = source
            .iter()
            .enumerate()
            .filter(|(i, value)| *i == 0 || source[*i - 1] != **value)
            .count();
        Unique {
            source,
            offset: 0,
            remaining,
        }
    }
}

/// Exact-cardinality iteration of a sorted reference set, with no new allocation.
pub(crate) struct Unique<'view, 'source, T> {
    source: &'view [&'source T],
    offset: usize,
    remaining: usize,
}
impl<T> Clone for Unique<'_, '_, T> {
    fn clone(&self) -> Self {
        Self {
            source: self.source,
            offset: self.offset,
            remaining: self.remaining,
        }
    }
}
impl<'source, T: PartialEq> Iterator for Unique<'_, 'source, T> {
    type Item = Ref<'source, T>;
    fn next(&mut self) -> Option<Self::Item> {
        let value = *self.source.get(self.offset)?;
        self.offset += 1;
        while self
            .source
            .get(self.offset)
            .is_some_and(|next| *next == value)
        {
            self.offset += 1;
        }
        self.remaining -= 1;
        Some(Ref(value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl<T: PartialEq> ExactSizeIterator for Unique<'_, '_, T> {}

/// Exact encoded originals needed for a set ordered by canonical bytes.
pub(crate) struct EncodedSet(ChargedBuffer<ChargedBuffer<u8>>);
impl EncodedSet {
    pub(crate) fn new<T: SerializePayload>(
        source: &[T],
        budget: &AllocationBudget,
    ) -> Result<Self, OrderError> {
        let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let mut rows = ChargedBuffer::new(source.len(), budget)?;
        for value in source {
            let length = norito::core::encoded_payload_len(value).map_err(OrderError::Codec)?;
            let mut bytes = ChargedBuffer::new(length, budget)?;
            norito::core::serialize_to_writer(value, &mut BufferWriter(&mut bytes))
                .map_err(OrderError::Codec)?;
            if bytes.as_slice().len() != length {
                return Err(OrderError::SourceCount);
            }
            rows.try_push(bytes).map_err(|_| OrderError::SourceCount)?;
        }
        rows.as_mut_slice()
            .sort_unstable_by(|left, right| left.as_slice().cmp(right.as_slice()));
        Ok(Self(rows))
    }
    pub(crate) fn unique(&self) -> UniqueEncoded<'_> {
        let source = self.0.as_slice();
        let remaining = source
            .iter()
            .enumerate()
            .filter(|(i, value)| *i == 0 || source[*i - 1].as_slice() != value.as_slice())
            .count();
        UniqueEncoded {
            source,
            offset: 0,
            remaining,
        }
    }
}

#[derive(Clone)]
pub(crate) struct UniqueEncoded<'a> {
    source: &'a [ChargedBuffer<u8>],
    offset: usize,
    remaining: usize,
}
impl<'a> Iterator for UniqueEncoded<'a> {
    type Item = Raw<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.source.get(self.offset)?.as_slice();
        self.offset += 1;
        while self
            .source
            .get(self.offset)
            .is_some_and(|next| next.as_slice() == value)
        {
            self.offset += 1;
        }
        self.remaining -= 1;
        Some(Raw(value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for UniqueEncoded<'_> {}

struct BufferWriter<'a>(&'a mut ChargedBuffer<u8>);
impl Write for BufferWriter<'_> {
    fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
        self.0.append(value)?;
        Ok(value.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Hash the canonical bare bytes directly, without allocating a preimage vector.
pub(crate) fn hash_payload(
    domain: &[u8],
    value: &impl SerializePayload,
) -> Result<[u8; 32], Error> {
    let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut encoded = Ok(());
    let hash = iroha_crypto::Hash::new_from_writer(|writer| {
        writer.write_all(domain)?;
        encoded = norito::core::serialize_to_writer(value, writer);
        Ok(())
    })?;
    encoded?;
    Ok(hash.into())
}

/// The original display text as a Norito string, without an intermediate String.
pub(crate) struct DisplayString<'a, T: ?Sized>(pub(crate) &'a T);
impl<T: std::fmt::Display + ?Sized> SerializePayload for DisplayString<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let mut count = CountWriter(0);
        display_to(self.0, &mut count)?;
        norito::core::write_len(writer, count.0)?;
        let mut written = CountedWriter {
            writer,
            count: 0,
            limit: count.0,
        };
        display_to(self.0, &mut written)?;
        if written.count != count.0 {
            return Err(Error::LengthMismatch);
        }
        Ok(())
    }
}
fn display_to(
    value: &(impl std::fmt::Display + ?Sized),
    writer: &mut dyn Write,
) -> Result<(), Error> {
    let mut io_error = None;
    let result = norito::json::visit_json_display_text(value, |text| {
        writer.write_all(text.as_bytes()).map_err(|error| {
            io_error = Some(error);
            norito::json::BoundedJsonError::Unsupported
        })
    });
    if let Some(error) = io_error {
        return Err(error.into());
    }
    result.map_err(norito::json::BoundedJsonError::into_core_error)
}
struct CountWriter(u64);
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(u64::try_from(bytes.len()).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("policy byte count overflows"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct CountedWriter<'a> {
    writer: &'a mut dyn Write,
    count: u64,
    limit: u64,
}
impl Write for CountedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .count
            .checked_add(u64::try_from(bytes.len()).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("policy byte count overflows"))?;
        if next > self.limit {
            return Err(std::io::Error::other(
                "policy string changed while streaming",
            ));
        }
        self.writer.write_all(bytes)?;
        self.count = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// Canonical source JSON as the exact original Norito String payload.
pub(crate) struct JsonString<'a, T: ?Sized>(pub(crate) &'a T);
impl<T: norito::json::JsonSerialize + ?Sized> SerializePayload for JsonString<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let mut count = CountWriter(0);
        json_to(self.0, &mut count)?;
        norito::core::write_len(writer, count.0)?;
        let mut written = CountedWriter {
            writer,
            count: 0,
            limit: count.0,
        };
        json_to(self.0, &mut written)?;
        if written.count != count.0 {
            return Err(Error::LengthMismatch);
        }
        Ok(())
    }
}
fn json_to(
    value: &(impl norito::json::JsonSerialize + ?Sized),
    writer: &mut dyn Write,
) -> Result<(), Error> {
    struct Sink<'a> {
        writer: &'a mut dyn Write,
        error: Option<std::io::Error>,
    }
    impl norito::json::JsonWriteSink for Sink<'_> {
        fn push(&mut self, value: char) -> Result<(), norito::json::BoundedJsonError> {
            self.push_str(value.encode_utf8(&mut [0; 4]))
        }
        fn push_str(&mut self, value: &str) -> Result<(), norito::json::BoundedJsonError> {
            if self.error.is_some() {
                return Err(norito::json::BoundedJsonError::Unsupported);
            }
            self.writer.write_all(value.as_bytes()).map_err(|error| {
                self.error = Some(error);
                norito::json::BoundedJsonError::Unsupported
            })
        }
    }
    let mut sink = Sink {
        writer,
        error: None,
    };
    let result = value.json_serialize_to(&mut sink);
    if let Some(error) = sink.error {
        return Err(error.into());
    }
    result.map_err(norito::json::BoundedJsonError::into_core_error)
}
/// Hash the exact retained canonical source body without collecting JSON text.
pub(crate) fn hash_json(
    value: &(impl norito::json::JsonSerialize + ?Sized),
) -> Result<[u8; 32], Error> {
    let mut encoded = Ok(());
    let hash = iroha_crypto::Hash::new_from_writer(|writer| {
        encoded = json_to(value, writer);
        Ok(())
    })?;
    encoded?;
    Ok(hash.into())
}

#[cfg(test)]
pub(crate) fn assert_same_payload(left: &impl SerializePayload, right: &impl SerializePayload) {
    let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut left_bytes = Vec::new();
    let mut right_bytes = Vec::new();
    norito::core::serialize_to_writer(left, &mut left_bytes).unwrap();
    norito::core::serialize_to_writer(right, &mut right_bytes).unwrap();
    assert_eq!(
        left_bytes, right_bytes,
        "borrowed canonical bytes differ from the established owned codec"
    );
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_preserve_fixed_arrays_optional_arrays_and_nested_bare_bytes() {
        #[derive(norito::Encode)]
        struct Owned {
            fixed: [u8; 32],
            optional: Option<[u8; 32]>,
            nested: Vec<u8>,
            names: Vec<String>,
        }
        let fixed = [3; 32];
        let optional = Some([4; 32]);
        let names = vec!["α".to_owned(), "second".to_owned()];
        let original = Owned {
            fixed,
            optional,
            nested: norito::codec::Encode::encode(&17_u64),
            names: names.clone(),
        };
        assert_same_payload(
            &record!(
                Raw(&fixed),
                optional,
                BareBytes(17_u64),
                Seq(names.iter().map(Ref))
            ),
            &original,
        );
        assert_eq!(
            hash_payload(b"domain", &original).unwrap(),
            <[u8; 32]>::from(iroha_crypto::Hash::new_from_chunks(&[
                b"domain",
                &norito::codec::Encode::encode(&original)
            ]))
        );
    }
    #[test]
    fn ordering_scratch_is_funded_and_released_on_the_original_pool() {
        let source = [3_u32, 2, 2, 1];
        let pool = AllocationBudget::new(0);
        assert!(matches!(
            SortedRefs::new_by(&source, &pool, Ord::cmp),
            Err(OrderError::Allocation(_))
        ));
        assert_eq!(pool.reserved_bytes(), 0);
        pool.set_limit_bytes(4096);
        let sorted = SortedRefs::new_by(&source, &pool, Ord::cmp).unwrap();
        assert!(pool.reserved_bytes() >= source.len() * std::mem::size_of::<&u32>());
        assert_same_payload(&Seq(sorted.unique()), &vec![1_u32, 2, 3]);
        drop(sorted);
        assert_eq!(pool.reserved_bytes(), 0);
        let strings = vec!["aa".to_owned(), "b".to_owned(), "aa".to_owned()];
        let encoded = EncodedSet::new(&strings, &pool).unwrap();
        let mut expected = strings
            .iter()
            .map(norito::codec::Encode::encode)
            .collect::<Vec<_>>();
        expected.sort();
        expected.dedup();
        assert_same_payload(&Seq(encoded.unique().map(BareBytes)), &expected);
        drop(encoded);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    #[test]
    fn source_json_and_display_text_stream_the_exact_native_strings() {
        let json = norito::json!({"unicode": "日本語\n\"", "array": [true, null, 7]});
        let expected = norito::json::to_json(&json).unwrap();
        assert_same_payload(&JsonString(&json), &expected);
        assert_eq!(
            hash_json(&json).unwrap(),
            <[u8; 32]>::from(iroha_crypto::Hash::new(expected.as_bytes()))
        );
        let key = iroha_crypto::KeyPair::random().public_key().clone();
        assert_same_payload(&DisplayString(&key), &key.to_string());
    }
}
