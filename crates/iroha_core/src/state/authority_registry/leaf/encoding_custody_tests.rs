//! Exact adapter allocation, changing-encoder and concrete Musubi codec controls.

use super::*;
use crate::{
    state::{
        WorldReadOnly,
        authority_registry::{
            schema,
            world::{
                musubi_availability_policy::MusubiAvailabilityAuthorityV1,
                musubi_universal_policy::{MusubiDirectoryAuthorityV1, MusubiResolverAuthorityV1},
            },
        },
        deserialize::seeded_musubi_publication_world_for_testing,
    },
    test_allocations::allocations_during,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use mv::storage::StorageReadOnly;
use std::cell::{Cell, RefCell};

fn without_allocations<T>(operation: impl FnOnce() -> T) -> T {
    let mut result = None;
    let allocations = allocations_during(|| result = Some(operation()));
    assert_eq!(allocations, 0, "the observed adapter must allocate nothing");
    result.unwrap()
}

fn encoding_error(operation: EncodingOperation, reason: EncodingReason) -> LeafError {
    EncodingError::new(operation, reason).into()
}

#[derive(Clone, Copy)]
enum Action {
    Bytes(&'static [u8]),
    OwnedError,
    SwallowOverrun,
    Panic,
}

struct Scripted {
    calls: Cell<usize>,
    first: Action,
    second: Action,
    error: RefCell<Option<norito::Error>>,
}

impl Scripted {
    fn new(first: Action, second: Action, error: Option<norito::Error>) -> Self {
        Self {
            calls: Cell::new(0),
            first,
            second,
            error: RefCell::new(error),
        }
    }
}

impl NoritoSchema for Scripted {
    fn nominal_name() -> String {
        panic!("a literal codec test must not construct an owned schema name")
    }
    fn static_nominal_name() -> Option<&'static str> {
        Some("iroha:test:scripted-canonical-payload")
    }
}

impl norito::SerializePayload for Scripted {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        match if call == 0 { self.first } else { self.second } {
            Action::Bytes(bytes) => encoder.write_all(bytes)?,
            Action::OwnedError => return Err(self.error.borrow_mut().take().unwrap()),
            Action::SwallowOverrun => {
                let _ignored = encoder.write_all(b"oversized");
                let _ignored = encoder.write_all(b"a");
            }
            Action::Panic => panic!("serializer unwind after original frame admission"),
        }
        Ok(())
    }
}

fn scripted_frame(
    value: &Scripted,
    bound: usize,
    pool: &AllocationBudget,
) -> Result<frame::FundedFrame, LeafError> {
    typed_bare_payload("test.codec", schema::<Scripted>(), value, bound, |length| {
        frame::FundedFrame::new(length, pool)
    })
}

#[test]
fn codec_and_io_error_adapters_keep_fixed_categories_without_rendering() {
    let cases = [
        (
            norito::Error::InvalidValue {
                context: "test value",
            },
            EncodingReason::InvalidValue("test value"),
        ),
        (
            norito::Error::AllocationFailed { bytes: 8193 },
            EncodingReason::Allocation { bytes: 8193 },
        ),
        (norito::Error::LengthMismatch, EncodingReason::CodecLength),
        (
            norito::Error::Io(io::ErrorKind::BrokenPipe.into()),
            EncodingReason::Io(io::ErrorKind::BrokenPipe),
        ),
        // The upstream owner exists before observation. Only dropping it is
        // allowed here; arbitrary serializers still owe their own allocations.
        (
            norito::Error::Message("upstream diagnostic".repeat(4096)),
            EncodingReason::Codec,
        ),
    ];
    for (error, reason) in cases {
        let actual =
            without_allocations(|| EncodingError::codec(EncodingOperation::MeasurePayload, error));
        assert_eq!(
            actual,
            EncodingError::new(EncodingOperation::MeasurePayload, reason)
        );
    }
    let actual = without_allocations(|| {
        EncodingError::io(
            EncodingOperation::WriteFrame,
            io::ErrorKind::WriteZero.into(),
        )
    });
    assert_eq!(
        actual,
        EncodingError::new(
            EncodingOperation::WriteFrame,
            EncodingReason::Io(io::ErrorKind::WriteZero)
        )
    );
    assert_eq!(
        actual.to_string(),
        "write admitted canonical frame: canonical I/O failure: WriteZero"
    );
}

#[test]
fn first_pass_codec_refusals_do_not_allocate_or_request_frame_backing() {
    for mode in 0..3 {
        let value = Scripted::new(
            Action::OwnedError,
            Action::Panic,
            Some(norito::Error::InvalidValue {
                context: "scripted input",
            }),
        );
        let pool = AllocationBudget::new(16);
        let error = without_allocations(|| match mode {
            0 => match scripted_frame(&value, 16, &pool) {
                Err(error) => error,
                Ok(_) => panic!("rejected"),
            },
            1 => stream_bare_payload_digests(&value, "test", 16).unwrap_err(),
            _ => typed_payload_hash("test.codec", schema::<Scripted>(), &value, KEY_PAYLOAD, 16)
                .unwrap_err(),
        });
        let operation = if mode == 2 {
            EncodingOperation::HashTypedPayload
        } else {
            EncodingOperation::MeasurePayload
        };
        assert_eq!(
            error,
            encoding_error(operation, EncodingReason::InvalidValue("scripted input"))
        );
        assert_eq!(value.calls.get(), 1);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(pool.peak_reserved_bytes(), 0);
    }
}

#[test]
fn payload_limit_and_original_pool_refusal_are_allocation_free_and_precede_second_pass() {
    for first in [Action::Bytes(b"ab"), Action::SwallowOverrun] {
        for mode in 0..3 {
            let value = Scripted::new(first, Action::Panic, None);
            let pool = AllocationBudget::new(0);
            let error = without_allocations(|| match mode {
                0 => match scripted_frame(&value, 1, &pool) {
                    Err(error) => error,
                    Ok(_) => panic!("rejected"),
                },
                1 => stream_bare_payload_digests(&value, "test", 1).unwrap_err(),
                _ => typed_payload_hash("test.codec", schema::<Scripted>(), &value, KEY_PAYLOAD, 1)
                    .unwrap_err(),
            });
            assert_eq!(error, LeafError::PayloadLimit);
            assert_eq!(value.calls.get(), 1);
            assert_eq!(pool.peak_reserved_bytes(), 0);
        }
    }
    let value = Scripted::new(Action::Bytes(b"ab"), Action::Panic, None);
    let pool = AllocationBudget::new(0);
    let error = without_allocations(|| match scripted_frame(&value, 2, &pool) {
        Err(error) => error,
        Ok(_) => panic!("rejected"),
    });
    assert!(matches!(
        error,
        LeafError::Admission(AllocationRefusal::ExceedsLimit { .. })
    ));
    assert_eq!(value.calls.get(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn every_second_pass_failure_has_only_the_admitted_frame_allocation_and_releases_it() {
    for (second, reason) in [
        (Action::Bytes(b"a"), EncodingReason::ChangedLength),
        (Action::Bytes(b"abc"), EncodingReason::ChangedLength),
        (Action::Bytes(b"cd"), EncodingReason::ChangedPayload),
        (Action::SwallowOverrun, EncodingReason::ChangedLength),
        (
            Action::OwnedError,
            EncodingReason::InvalidValue("second pass"),
        ),
    ] {
        let value = Scripted::new(
            Action::Bytes(b"ab"),
            second,
            Some(norito::Error::InvalidValue {
                context: "second pass",
            }),
        );
        let pool = AllocationBudget::new(2);
        let mut result = None;
        let allocations = allocations_during(|| result = Some(scripted_frame(&value, 2, &pool)));
        assert_eq!(
            allocations, 1,
            "only the original two-byte frame is allocated"
        );
        let Err(error) = result.unwrap() else {
            panic!("changed second pass accepted")
        };
        assert_eq!(error, encoding_error(EncodingOperation::WriteFrame, reason));
        assert_eq!(value.calls.get(), 2);
        assert_eq!(pool.peak_reserved_bytes(), 2);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn every_second_pass_hash_failure_is_allocation_free_and_returns_no_digest() {
    for (second, reason) in [
        (Action::Bytes(b"a"), EncodingReason::ChangedLength),
        (Action::Bytes(b"abc"), EncodingReason::ChangedLength),
        (Action::Bytes(b"cd"), EncodingReason::ChangedPayload),
        (Action::SwallowOverrun, EncodingReason::ChangedLength),
        (
            Action::OwnedError,
            EncodingReason::InvalidValue("second pass"),
        ),
    ] {
        let value = Scripted::new(
            Action::Bytes(b"ab"),
            second,
            Some(norito::Error::InvalidValue {
                context: "second pass",
            }),
        );
        let result = without_allocations(|| stream_bare_payload_digests(&value, "test", 2));
        assert_eq!(
            result.unwrap_err(),
            encoding_error(EncodingOperation::HashPairedValue, reason)
        );
        assert_eq!(value.calls.get(), 2);
    }
}

#[test]
fn raw_digest_frame_rejections_allocate_nothing_and_overrun_is_sticky() {
    for mode in 0..3 {
        let result = without_allocations(|| {
            digest_norito_value_frame_v1(2, |writer| {
                match mode {
                    0 => writer.write_all(b"a")?,
                    1 => writer.write_all(b"abc")?,
                    _ => {
                        let _ = writer.write_all(b"abc");
                        writer.write_all(b"ab")?;
                    }
                }
                Ok(())
            })
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    let mut bytes = [0_u8; 4];
    let mut sink = io::Cursor::new(&mut bytes[..]);
    let mut exceeded = false;
    let mut bounded = BoundedWriter {
        inner: &mut sink,
        remaining: 2,
        exceeded: &mut exceeded,
    };
    assert_eq!(
        without_allocations(|| bounded.write(b"abc"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        without_allocations(|| bounded.write(b"ab"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert!(exceeded);
    assert_eq!(sink.position(), 0);
}

#[test]
fn unwinding_second_pass_releases_original_frame_and_census_tracking() {
    let pool = AllocationBudget::new(2);
    let value = Scripted::new(Action::Bytes(b"ab"), Action::Panic, None);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        allocations_during(|| {
            let _ = scripted_frame(&value, 2, &pool);
        })
    }));
    assert!(result.is_err());
    assert_eq!(value.calls.get(), 2);
    assert_eq!(pool.peak_reserved_bytes(), 2);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(allocations_during(|| {}), 0);
}

fn check_concrete_key<K: Encode + NoritoSchema>(table: &'static str, key: &K) {
    let bytes = norito::codec::encode_adaptive(key);
    let field = declared_table(table).unwrap();
    let Role::Canonical(Canonical::Table {
        key: key_schema, ..
    }) = field.role
    else {
        panic!("table")
    };
    let expected = bare_payload_hash(table, key_schema, &bytes, KEY_PAYLOAD).unwrap();
    let actual = without_allocations(|| {
        typed_payload_hash(table, key_schema, key, KEY_PAYLOAD, bytes.len())
    })
    .unwrap();
    assert_eq!(actual, expected);
    let pool = AllocationBudget::new(bytes.len());
    let mut result = None;
    let allocations = allocations_during(|| {
        result = Some(typed_bare_payload(
            table,
            key_schema,
            key,
            bytes.len(),
            |length| frame::FundedFrame::new(length, &pool),
        ));
    });
    assert_eq!(allocations, 1, "only exact retained key bytes allocate");
    let frame = result.unwrap().unwrap().into_buffer();
    assert_eq!(frame.as_slice(), bytes);
    assert_eq!(frame.capacity(), bytes.len());
    assert_eq!(pool.reserved_bytes(), bytes.len());
    drop(frame);
    assert_eq!(pool.reserved_bytes(), 0);
    let result = without_allocations(|| {
        typed_payload_hash(table, key_schema, key, KEY_PAYLOAD, bytes.len() - 1)
    });
    assert_eq!(result, Err(LeafError::PayloadLimit));
}

fn check_concrete_value<V: Encode>(table: &'static str, identity: &'static str, value: &V) {
    let bytes = norito::codec::encode_adaptive(value);
    let field = declared_table(table).unwrap();
    let Role::Canonical(Canonical::Table {
        value: value_schema,
        ..
    }) = field.role
    else {
        panic!("table")
    };
    let expected_lookup = bare_payload_hash(table, value_schema, &bytes, VALUE_PAYLOAD).unwrap();
    let expected_ordered =
        digest_norito_value_frame_v1(u32::try_from(bytes.len()).unwrap(), |writer| {
            writer.write_all(&bytes)
        })
        .unwrap();
    let actual = without_allocations(|| {
        semantic_bare_payload_digests(table, value_schema, identity, value, bytes.len())
    })
    .unwrap();
    assert_eq!(actual, (expected_ordered, expected_lookup, bytes.len()));
    let result = without_allocations(|| {
        semantic_bare_payload_digests(table, value_schema, identity, value, bytes.len() - 1)
    });
    assert_eq!(result, Err(LeafError::PayloadLimit));
}

#[test]
fn all_three_concrete_musubi_key_codecs_and_value_projections_have_exact_custody() {
    // The populated World and its nested values exist before observation. This
    // tests capture encoding, not snapshot decoding or proof-output funding.
    let world = seeded_musubi_publication_world_for_testing();
    let view = world.view();
    let mut rows = 0;
    for (key, row) in view.musubi_archive_availability().iter() {
        check_concrete_key("world.musubi_archive_availability", key);
        check_concrete_value(
            "world.musubi_archive_availability",
            "iroha:state:musubi-availability-authority:v1",
            &MusubiAvailabilityAuthorityV1::from_record(row),
        );
        rows += 1;
    }
    for (key, row) in view.musubi_resolver_index().iter() {
        check_concrete_key("world.musubi_resolver_index", key);
        check_concrete_value(
            "world.musubi_resolver_index",
            "iroha:state:musubi-resolver-authority:v1",
            &MusubiResolverAuthorityV1::from_record(row),
        );
        let mut nested = key.clone();
        nested.package.scope =
            iroha_data_model::musubi::MusubiPackageScopeV1::Domain("sora".parse().unwrap());
        nested.version = "1.2.3-alpha.7.z".parse().unwrap();
        nested.validate().unwrap();
        check_concrete_key("world.musubi_resolver_index", &nested);
        rows += 1;
    }
    for (key, row) in view.musubi_public_directory().iter() {
        check_concrete_key("world.musubi_public_directory", key);
        check_concrete_value(
            "world.musubi_public_directory",
            "iroha:state:musubi-directory-authority:v1",
            &MusubiDirectoryAuthorityV1::from_record(row),
        );
        rows += 1;
    }
    assert_eq!(
        rows, 3,
        "the three real codec families must all be exercised"
    );
}
