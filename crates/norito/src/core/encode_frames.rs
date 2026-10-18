//! Streaming embedded frames without replaying payloads into length-only destinations.

use std::io::Write;

use super::{
    DecodeFlagsGuard, EncodeContextGuard, Encoder, Error, ExactLengthWriter, FramedPayloadWriter,
    Header, NoritoSerialize, compact_len_used, current_decode_flags_effective,
    default_encode_flags, encoded_frame_len, finalized_encode_flags, payload_alignment_padding_for,
    validate_header_flags,
};

/// Write a measured prefix followed by one complete frame using the active layout.
///
/// The callback receives the frame length measured by this codec invocation; it
/// supplies no lengths back to the codec. A length-only destination visits the
/// payload once. A byte destination measures checksum and layout flags, then
/// emits a checked second pass. Neither path retains a frame-sized buffer.
///
/// The prefix runs outside the embedded frame's encoding contexts, so its layout
/// markers belong to the enclosing value. A prefix must propagate writer errors.
///
/// # Errors
///
/// Returns measurement, prefix, or output errors. Actual output rejects length,
/// checksum, or layout drift between passes. Errors after prefix emission leave
/// partial output that the caller must discard.
#[doc(hidden)]
pub fn write_frame_with_prefix<'a, T, F>(
    value: &T,
    writer: &mut Encoder<'a>,
    prefix: F,
) -> Result<(), Error>
where
    T: NoritoSerialize,
    F: FnOnce(&mut Encoder<'a>, usize) -> Result<(), Error>,
{
    let flags = current_decode_flags_effective().unwrap_or_else(default_encode_flags);
    validate_header_flags(flags)?;
    if writer.is_counting() {
        let frame_len = encoded_frame_len(value)?;
        prefix(writer, frame_len)?;
        // This invocation measured this exact value. The private destination
        // operation cannot be reached with a caller-provided length.
        return writer
            .count_measured_bytes(frame_len)?
            .then_some(())
            .ok_or(Error::NonCanonicalEncoding);
    }
    write_frame_to_writer_with_prefix(value, writer, flags, prefix)
}

pub(super) fn write_frame_to_writer_with_flags<T, W>(
    value: &T,
    writer: &mut W,
    base_flags: u8,
) -> Result<(), Error>
where
    T: NoritoSerialize,
    W: Write + ?Sized,
{
    write_frame_to_writer_with_prefix(value, writer, base_flags, |_, _| Ok(()))
}

fn write_frame_to_writer_with_prefix<T, W, F>(
    value: &T,
    writer: &mut W,
    base_flags: u8,
    prefix: F,
) -> Result<(), Error>
where
    T: NoritoSerialize,
    W: Write + ?Sized,
    F: FnOnce(&mut W, usize) -> Result<(), Error>,
{
    write_typed_payload_frame_with_prefix::<T, T, _, _>(value, writer, base_flags, prefix)
}

/// The nominal type supplies only its original frame identity and alignment;
/// the payload still runs through the same checked two-pass frame writer.
pub(super) fn write_typed_payload_frame<T, P, W>(
    value: &P,
    writer: &mut W,
    base_flags: u8,
) -> Result<(), Error>
where
    T: NoritoSerialize,
    P: super::SerializePayload + ?Sized,
    W: Write + ?Sized,
{
    write_typed_payload_frame_with_prefix::<T, P, _, _>(value, writer, base_flags, |_, _| Ok(()))
}

fn write_typed_payload_frame_with_prefix<T, P, W, F>(
    value: &P,
    writer: &mut W,
    base_flags: u8,
    prefix: F,
) -> Result<(), Error>
where
    T: NoritoSerialize,
    P: super::SerializePayload + ?Sized,
    W: Write + ?Sized,
    F: FnOnce(&mut W, usize) -> Result<(), Error>,
{
    validate_header_flags(base_flags)?;
    let first_guard = EncodeContextGuard::enter();
    let mut discard = std::io::sink();
    let mut first_payload = FramedPayloadWriter::new(&mut discard);
    {
        let _flags = DecodeFlagsGuard::enter(base_flags);
        let mut encoder = Encoder::new(&mut first_payload);
        value.serialize(&mut encoder)?;
    }
    let payload_len = first_payload.len;
    let payload_len_u64 = u64::try_from(payload_len).map_err(|_| Error::LengthMismatch)?;
    let first_checksum = first_payload.digest.sum64();
    let first_flags = finalized_encode_flags(base_flags, compact_len_used());
    drop(first_guard);

    let padding = payload_alignment_padding_for::<T>();
    let frame_len = Header::SIZE
        .checked_add(padding)
        .and_then(|size| size.checked_add(payload_len))
        .ok_or(Error::LengthMismatch)?;
    prefix(writer, frame_len)?;

    let mut header = Header::new(
        crate::schema::identity::frame_hash::<T>(),
        payload_len_u64,
        first_checksum,
    );
    header.flags |= first_flags;
    header.write(&mut *writer)?;
    let mut padding = padding;
    const ZEROS: [u8; 64] = [0; 64];
    while padding != 0 {
        let chunk = padding.min(ZEROS.len());
        writer.write_all(&ZEROS[..chunk])?;
        padding -= chunk;
    }

    let second_guard = EncodeContextGuard::enter();
    let mut second_payload = FramedPayloadWriter::new(writer);
    let (serialize_result, written_len, rejected_write) = {
        let mut exact = ExactLengthWriter::new(&mut second_payload, payload_len);
        let result = {
            let _flags = DecodeFlagsGuard::enter(base_flags);
            let mut encoder = Encoder::new(&mut exact);
            value.serialize(&mut encoder)
        };
        (result, exact.written_len(), exact.rejected_write())
    };
    let second_checksum = second_payload.digest.sum64();
    let second_flags = finalized_encode_flags(base_flags, compact_len_used());
    drop(second_guard);
    if rejected_write {
        return Err(Error::LengthMismatch);
    }
    serialize_result?;
    if written_len != payload_len || second_payload.len != payload_len {
        return Err(Error::LengthMismatch);
    }
    if second_checksum != first_checksum {
        return Err(Error::ChecksumMismatch);
    }
    if second_flags != first_flags {
        return Err(Error::NonCanonicalEncoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::SerializePayload;
    use std::cell::Cell;

    use super::*;
    use crate::core::{
        LengthCountingWriter, encoded_payload_len, frame_bare_with_header_flags, header_flags,
        note_compact_len_emitted, serialize_to_buffer, supported_header_flags, to_bytes,
        write_len_header,
    };

    #[derive(crate::NoritoSchema)]
    #[norito_schema(name = "norito.test.core.encode_frames.Leaf")]
    struct Leaf<'a>(&'a Cell<usize>);

    impl SerializePayload for Leaf<'_> {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            self.0.set(self.0.get() + 1);
            writer.write_all(&[0xab])?;
            Ok(())
        }

        fn encoded_len_exact(&self) -> Option<usize> {
            panic!("frame measurement must serialize the child")
        }
    }

    #[derive(crate::NoritoSchema)]
    #[norito_schema(name = "norito.test.core.encode_frames.Framed")]
    struct Framed<T>(T);

    impl<T: NoritoSerialize> SerializePayload for Framed<T> {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            write_frame_with_prefix(&self.0, writer, |writer, length| {
                writer.write_all(
                    &u64::try_from(length)
                        .map_err(|_| Error::LengthMismatch)?
                        .to_le_bytes(),
                )?;
                Ok(())
            })
        }
    }

    fn layouts() -> impl Iterator<Item = u8> {
        (0..=supported_header_flags()).filter(|flags| validate_header_flags(*flags).is_ok())
    }

    #[test]
    fn nested_prefixed_frames_measure_each_leaf_once_and_preserve_wire_bytes() {
        for flags in layouts() {
            let _flags = DecodeFlagsGuard::enter(flags);
            let visits = Cell::new(0);
            let value = Framed(Framed(Leaf(&visits)));
            let inner_frame = to_bytes(&value.0.0).expect("independent buffered leaf frame");
            let mut inner_record = u64::try_from(inner_frame.len())
                .unwrap()
                .to_le_bytes()
                .to_vec();
            inner_record.extend_from_slice(&inner_frame);
            let outer_frame = frame_bare_with_header_flags::<Framed<Leaf<'_>>>(
                &inner_record,
                finalized_encode_flags(flags, false),
            )
            .expect("frame independently assembled nested payload");
            let mut expected = u64::try_from(outer_frame.len())
                .unwrap()
                .to_le_bytes()
                .to_vec();
            expected.extend_from_slice(&outer_frame);

            visits.set(0);
            assert_eq!(encoded_payload_len(&value).unwrap(), expected.len());
            assert_eq!(
                visits.get(),
                1,
                "nested count replayed a leaf, flags {flags:#x}"
            );
            visits.set(0);
            let mut actual = Vec::new();
            serialize_to_buffer(&value, &mut actual).unwrap();
            assert_eq!(
                actual, expected,
                "nested frame bytes changed, flags {flags:#x}"
            );
            assert_eq!(
                visits.get(),
                4,
                "each real frame retains its two checked passes"
            );
        }
    }

    #[test]
    fn frame_prefix_flags_belong_to_the_outer_encoding_context() {
        let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
        let expected_frame = to_bytes(&7_u8).unwrap();
        let outer = EncodeContextGuard::enter();
        let mut bytes = Vec::new();
        write_frame_with_prefix(
            &7_u8,
            &mut Encoder::for_buffer(&mut bytes),
            |writer, length| {
                // The compact length prefix is the only compact marker in this
                // encode: the one-byte frame payload writes no length itself.
                write_len_header(writer, u64::try_from(length).unwrap())?;
                Ok(())
            },
        )
        .unwrap();
        assert!(
            compact_len_used(),
            "frame guards discarded the compact prefix marker"
        );
        drop(outer);
        assert_eq!(&bytes[bytes.len() - expected_frame.len()..], expected_frame);
    }

    #[derive(crate::NoritoSchema)]
    #[norito_schema(name = "norito.test.core.encode_frames.Changes")]
    struct Changes {
        visits: Cell<usize>,
        first: &'static [u8],
        second: &'static [u8],
        flag_drift: bool,
    }

    impl SerializePayload for Changes {
        fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
            let first = self.visits.replace(self.visits.get() + 1) == 0;
            if self.flag_drift && first {
                // Only the first pass claims a compact length prefix, so the
                // advertised COMPACT_LEN bit drifts between the two passes.
                note_compact_len_emitted();
            }
            writer.write_all(if first { self.first } else { self.second })?;
            Ok(())
        }
    }

    #[test]
    fn prefixed_frame_rejects_length_checksum_and_flag_drift_with_bounded_output() {
        for (first, second, flag_drift) in [
            (&[1][..], &[1, 2][..], false),
            (&[1, 2][..], &[1][..], false),
            (&[1][..], &[2][..], false),
            (&[1][..], &[1][..], true),
        ] {
            let value = Changes {
                visits: Cell::new(0),
                first,
                second,
                flag_drift,
            };
            let mut declared = 0;
            let mut bytes = Vec::new();
            let error = write_frame_with_prefix(
                &value,
                &mut Encoder::for_buffer(&mut bytes),
                |writer, length| {
                    declared = length;
                    writer.write_all(&[0xcc])?;
                    Ok(())
                },
            )
            .expect_err("changed frame must fail");
            if first.len() != second.len() {
                assert!(matches!(error, Error::LengthMismatch));
            } else if flag_drift {
                assert!(matches!(error, Error::NonCanonicalEncoding));
            } else {
                assert!(matches!(error, Error::ChecksumMismatch));
            }
            assert_eq!(
                value.visits.get(),
                2,
                "actual frame must not add a separate length pass"
            );
            assert_eq!(bytes[0], 0xcc);
            assert!(
                bytes.len() <= 1 + declared,
                "frame overrun reached the destination"
            );
        }
    }

    #[test]
    fn prefixed_frame_propagates_measurement_and_prefix_errors_without_replay() {
        #[derive(crate::NoritoSchema)]
        #[norito_schema(name = "norito.test.core.encode_frames.Fails")]
        struct Fails;

        impl SerializePayload for Fails {
            fn serialize(&self, _writer: &mut Encoder<'_>) -> Result<(), Error> {
                Err(Error::NonCanonicalEncoding)
            }
        }
        let mut bytes = Vec::new();
        assert!(matches!(
            write_frame_with_prefix(&Fails, &mut Encoder::for_buffer(&mut bytes), |_, _| {
                panic!("failed measurement must not write a prefix")
            }),
            Err(Error::NonCanonicalEncoding)
        ));
        assert!(bytes.is_empty());
        assert!(matches!(
            encoded_payload_len(&Framed(Fails)),
            Err(Error::NonCanonicalEncoding)
        ));

        let visits = Cell::new(0);
        let outer = EncodeContextGuard::enter();
        let error = write_frame_with_prefix(
            &Leaf(&visits),
            &mut Encoder::for_buffer(&mut bytes),
            |writer, _| {
                writer.write_all(&[0xdd])?;
                Err(Error::NonCanonicalEncoding)
            },
        )
        .expect_err("prefix error");
        assert!(matches!(error, Error::NonCanonicalEncoding));
        assert_eq!(bytes, [0xdd]);
        assert_eq!(visits.get(), 1);
        assert!(!compact_len_used());
        drop(outer);
    }

    #[test]
    fn prefixed_frame_propagates_destination_failure_after_the_prefix() {
        struct PrefixOnly {
            bytes: Vec<u8>,
        }
        impl Write for PrefixOnly {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.bytes.is_empty() {
                    self.bytes.extend_from_slice(bytes);
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("frame destination unavailable"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let visits = Cell::new(0);
        let mut destination = PrefixOnly { bytes: Vec::new() };
        let error = write_frame_with_prefix(
            &Leaf(&visits),
            &mut Encoder::new(&mut destination),
            |writer, _| {
                writer.write_all(&[0xee])?;
                Ok(())
            },
        )
        .expect_err("header destination failure");
        assert!(matches!(error, Error::Io(_)));
        assert_eq!(destination.bytes, [0xee]);
        assert_eq!(
            visits.get(),
            1,
            "failed header must not start the payload pass"
        );
    }

    #[test]
    fn counting_frame_rejects_prefix_destination_replacement() {
        let visits = Cell::new(0);
        let mut counter = LengthCountingWriter::default();
        let mut replacement_bytes = Vec::new();
        let error = {
            let replacement = Encoder::for_buffer(&mut replacement_bytes);
            let mut encoder = Encoder::for_counting(&mut counter);
            write_frame_with_prefix(&Leaf(&visits), &mut encoder, move |writer, _| {
                writer.write_all(&[0xcc])?;
                *writer = replacement;
                Ok(())
            })
            .expect_err("a prefix cannot redirect a measured frame into another destination")
        };
        assert!(matches!(error, Error::NonCanonicalEncoding));
        assert_eq!(counter.finish().unwrap(), 1, "only the prefix was counted");
        assert!(
            replacement_bytes.is_empty(),
            "rejected frame bytes escaped to the replacement"
        );
        assert_eq!(
            visits.get(),
            1,
            "replacement rejection must not replay the child"
        );
    }
}
