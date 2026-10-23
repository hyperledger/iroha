//! Actual original-pool scratch, strict grammar, replay and scalar validation controls.

use super::*;
use crate::{
    NetworkId,
    amx_prepare_streaming_allocations::{
        PhysicalObservation, measured, with_nth_exact_allocation_denial,
    },
    block::consensus::SumeragiRootScope,
    parameter::system::ConsensusHandshakeValidationError,
};
use iroha_allocation::{ChargedBuffer, ChargedBufferError};
use iroha_crypto::{Hash, HashOf};
use iroha_model_base::topology::DataSpaceId;
use norito::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, classify_decode_attempt,
};
use std::alloc::Layout;

fn fixture(private: bool) -> ConsensusHandshakeMetadata {
    let mut context = SumeragiGenesisContextParameters::recommended();
    if private {
        context.root_scope = SumeragiRootScope::Dataspace {
            parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"handshake parent"),
            )),
            dataspace_id: DataSpaceId::new(u64::MAX),
        };
    }
    ConsensusHandshakeMetadata {
        mode: SumeragiConsensusMode::Npos,
        block_cadence_ms: NonZeroU64::new(1024).unwrap(),
        wire_protocol_version: u32::from(crate::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0xab; 32]),
        sumeragi_context: context,
    }
}
fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<AdmittedConsensusHandshakeMetadata, HandshakeJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let value = AdmittedConsensusHandshakeMetadata::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(value)
}
fn failure(
    result: Result<AdmittedConsensusHandshakeMetadata, HandshakeJsonAdmissionError>,
) -> HandshakeJsonAdmissionError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected refusal"),
    }
}
fn reject(source: &str) {
    let pool = AllocationBudget::new(4096);
    assert!(
        json::from_str::<ConsensusHandshakeMetadata>(source).is_err(),
        "ordinary {source}"
    );
    assert!(decode(source, &pool).is_err(), "admitted {source}");
    assert_eq!(pool.reserved_bytes(), 0);
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn both_root_scopes_share_json_binary_and_original_pool_identity() {
    use norito::codec::{Decode, Encode};
    let pool = AllocationBudget::new(4096);
    let foreign = AllocationBudget::new(4096);
    for private in [false, true] {
        let expected = fixture(private);
        let source = json::to_json(&expected).unwrap();
        let escaped = source.replace("sumeragi_context", "sumeragi_cont\\u0065xt");
        for source in [&source, &escaped] {
            let owner = decode(source, &pool).unwrap();
            assert_eq!(owner.get(), &expected);
            assert_eq!(
                json::from_json_fast::<ConsensusHandshakeMetadata>(source).unwrap(),
                expected
            );
            assert_eq!(
                json::from_str::<ConsensusHandshakeMetadata>(source).unwrap(),
                expected
            );
            assert!(owner.belongs_to(&pool));
            assert!(!owner.belongs_to(&foreign));
            assert_eq!(
                pool.reserved_bytes(),
                0,
                "all fields are scalar; scratch already retired"
            );
            assert_eq!(
                ConsensusHandshakeMetadata::decode(&mut owner.get().encode().as_slice()).unwrap(),
                expected
            );
            assert_eq!(
                json::to_json(owner.get()).unwrap(),
                json::to_json(&expected).unwrap()
            );
        }
    }
}

#[test]
fn required_fields_unknown_duplicates_and_noncanonical_scalars_reject() {
    let original = json::to_value(&fixture(true)).unwrap();
    for field in [
        "mode",
        "block_cadence_ms",
        "wire_protocol_version",
        "consensus_fingerprint",
        "sumeragi_context",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        reject(&json::to_json(&value).unwrap());
    }
    let source = json::to_json(&original).unwrap();
    for (from, to) in [
        ("\"mode\":", "\"mode\":\"Npos\",\"mode\":"),
        ("\"mode\":", "\"m\\u006fde\":\"Npos\",\"mode\":"),
        ("\"mode\":", "\"unexpected\":"),
        ("\"Npos\"", "\"npos\""),
        ("\"block_cadence_ms\":1024", "\"block_cadence_ms\":0"),
        (
            "\"wire_protocol_version\":1",
            "\"wire_protocol_version\":4294967296",
        ),
        ("0xabab", "0xABAB"),
        ("0xabab", "abab"),
        ("\"data_shards\":4", "\"data_shards\":65536"),
        ("\"chunk_size_bytes\":262144", "\"chunk_size_bytes\":-0"),
        ("\"max_chunk_count\":1024", "\"max_chunk_count\":1.0"),
    ] {
        assert!(source.contains(from), "fixture must exercise {from}");
        reject(&source.replacen(from, to, 1));
    }
    reject(&format!("{source} true"));
}

#[test]
fn nested_required_fields_and_duplicates_preserve_one_relation() {
    let original = json::to_value(&fixture(true)).unwrap();
    for (parent, fields) in [
        (
            &["sumeragi_context"][..],
            &[
                "root_scope",
                "da_layout",
                "nexus_amx_context_hash",
                "execution_policy_hash",
            ][..],
        ),
        (
            &["sumeragi_context", "da_layout"][..],
            &[
                "encoding",
                "chunk_size_bytes",
                "data_shards",
                "parity_shards",
                "max_payload_size_bytes",
                "max_chunk_count",
            ][..],
        ),
        (
            &["sumeragi_context", "root_scope", "value"][..],
            &["parent_network_id", "dataspace_id"][..],
        ),
    ] {
        for field in fields {
            let mut value = original.clone();
            let mut current = &mut value;
            for key in parent {
                current = current.as_object_mut().unwrap().get_mut(*key).unwrap();
            }
            current.as_object_mut().unwrap().remove(*field);
            reject(&json::to_json(&value).unwrap());
        }
    }
    let source = json::to_json(&original).unwrap();
    for (needle, duplicate) in [
        ("\"data_shards\":4", "\"data_shards\":4,\"data_shards\":4"),
        (
            "\"dataspace_id\":18446744073709551615",
            "\"dataspace_id\":1,\"dataspace_id\":18446744073709551615",
        ),
        ("\"details\":null", "\"details\":null,\"details\":null"),
    ] {
        assert!(source.contains(needle));
        reject(&source.replacen(needle, duplicate, 1));
    }
}

#[test]
fn zero_pool_refuses_before_native_request_and_no_hidden_retained_graph() {
    let expected = fixture(true);
    let source = json::to_json(&expected).unwrap();
    let pool = AllocationBudget::new(0);
    let (result, requests) = measured(|| decode(&source, &pool));
    assert!(matches!(
        result,
        Err(HandshakeJsonAdmissionError::Allocation(
            ChargedBufferError::Admission(_)
        ))
    ));
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(4096);
    let owner = decode(&source, &pool).unwrap();
    assert_eq!(owner.get(), &expected);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(pool.peak_reserved_bytes() > 0);
}

#[test]
fn every_text_destination_has_fallible_physical_refusal_and_retry() {
    let source = json::to_json(&fixture(true))
        .unwrap()
        .replace("sumeragi_context", "sumeragi_cont\\u0065xt");
    let original = source.clone();
    let pool = AllocationBudget::new(4096);
    // Each is an exact string/key byte layout in this fixture. Distinct keys
    // ensure the injected denial reaches nested kinds, hashes and network text.
    for length in [4, 9, 14, 16, 64, 66, 74] {
        let layout = Layout::array::<u8>(length).unwrap();
        let (result, denied) =
            with_nth_exact_allocation_denial(layout, 0, || decode(&source, &pool));
        assert!(denied, "expected actual destination of {length} bytes");
        assert!(
            matches!(result,Err(HandshakeJsonAdmissionError::Allocation(ChargedBufferError::Allocator {requested_bytes})) if requested_bytes==length)
        );
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(source, original);
        let owner = decode(&source, &pool).unwrap();
        assert_eq!(owner.get(), &fixture(true));
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn scratch_physical_lifetimes_end_before_scalar_return_and_sibling_survives() {
    let source = json::to_json(&fixture(true)).unwrap();
    let pool = AllocationBudget::new(4096);
    let sibling = ChargedBuffer::<u8>::new(100, &pool).unwrap();
    let held = pool.reserved_bytes();
    let observation = PhysicalObservation::start();
    let owner = decode(&source, &pool).unwrap();
    for length in [4, 9, 14, 64, 66, 74] {
        assert_eq!(
            observation
                .snapshot()
                .single_live_pointer(Layout::array::<u8>(length).unwrap()),
            None
        );
    }
    assert_eq!(pool.reserved_bytes(), held);
    pool.set_limit_bytes(held);
    assert!(matches!(
        decode(&source, &pool),
        Err(HandshakeJsonAdmissionError::Allocation(_))
    ));
    assert_eq!(pool.reserved_bytes(), held);
    assert!(owner.belongs_to(&pool));
    assert_eq!(owner.get(), &fixture(true));
    drop(observation);
    drop(sibling);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_decode_observer_survives_saved_replay_is_invalid_and_work_accumulates() {
    let source = json::to_json(&fixture(true)).unwrap();
    let pool = AllocationBudget::new(4096);
    let (result, usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(&source, &pool));
    drop(result.unwrap());
    let demand = usage.total_allocated_bytes();
    assert!(demand > 74);
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let mut seen = None;
    let attempt = context
        .with(|| {
            norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let error = failure(decode(&source, &pool));
                    let HandshakeJsonAdmissionError::Json(json::Error::ScopedDecodeResource(
                        origin,
                    )) = error
                    else {
                        panic!("original observer lost: {error:?}")
                    };
                    seen = Some(origin.clone());
                    Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let norito::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original refusal lost")
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    let replay = context
        .with(|| {
            norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let _ = failure(decode(&source, &pool));
                    Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
                })
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    let before = context.consumed_allocated_bytes();
    drop(context.with(|| decode(&source, &pool)).unwrap());
    assert_eq!(
        context.consumed_allocated_bytes() - before,
        u64::try_from(demand).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn network_literal_canonical_parse_and_validation_are_allocation_free() {
    let expected = fixture(true);
    let SumeragiRootScope::Dataspace {
        parent_network_id, ..
    } = expected.sumeragi_context.root_scope
    else {
        unreachable!()
    };
    let literal = parent_network_id.to_string();
    let (parsed, requests) = measured(|| literal.parse::<NetworkId>());
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(parsed.unwrap(), parent_network_id);
    let mut bad = expected;
    bad.wire_protocol_version = 2;
    let (result, requests) = measured(|| bad.validate());
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(result, Err(ConsensusHandshakeValidationError::WireVersion));
    assert_eq!(
        result.unwrap_err().to_string(),
        "wire_protocol_version must equal the first-release protocol version"
    );
    bad = expected;
    bad.sumeragi_context.da_layout.parity_shards = 0;
    let (result, requests) = measured(|| bad.validate());
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(
        result,
        Err(ConsensusHandshakeValidationError::Context(
            crate::block::consensus::ValidationError::InvalidDataAvailabilityLayout
        ))
    );
    let mut malformed = literal.clone();
    malformed.replace_range(5..6, "g");
    let (result, requests) = measured(|| malformed.parse::<NetworkId>());
    assert!(result.is_err());
    assert_eq!(requests, [0, 0, 0]);
}

#[test]
fn missing_and_duplicate_mode_diagnostics_use_the_wire_field_name() {
    let original = json::to_value(&fixture(true)).unwrap();
    let source = json::to_json(&original).unwrap();
    assert!(source.contains("\"mode\":"));
    let mut missing = original.clone();
    assert!(missing.as_object_mut().unwrap().remove("mode").is_some());
    let pool = AllocationBudget::new(4096);
    for (source, expected_message) in [
        (
            json::to_json(&missing).unwrap(),
            "missing handshake field: mode",
        ),
        (
            source.replacen("\"mode\":", "\"mode\":\"Npos\",\"mode\":", 1),
            "duplicate handshake field: mode",
        ),
        (
            source.replacen("\"mode\":", "\"m\\u006fde\":\"Npos\",\"mode\":", 1),
            "duplicate handshake field: mode",
        ),
    ] {
        let ordinary = json::from_str::<ConsensusHandshakeMetadata>(&source).unwrap_err();
        let admitted = match failure(decode(&source, &pool)) {
            HandshakeJsonAdmissionError::Json(error) => error,
            error => panic!("expected the original JSON diagnostic, got {error:?}"),
        };
        for error in [ordinary, admitted] {
            assert_eq!(
                error.to_string(),
                format!("JSON error: {expected_message} at byte 0 (line 1, col 1)")
            );
            match error {
                json::Error::WithPos {
                    msg,
                    byte,
                    line,
                    col,
                } => {
                    assert_eq!(msg, expected_message);
                    assert_eq!((byte, line, col), (0, 1, 1));
                }
                error => panic!("unexpected diagnostic representation: {error:?}"),
            }
        }
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn cumulative_element_work_refuses_second_handshake_in_original_context() {
    let source = json::to_json(&fixture(true)).unwrap();
    let pool = AllocationBudget::new(4096);
    let (owner, usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(&source, &pool));
    drop(owner.unwrap());
    let work = usage.total_elements();
    assert!(work > 0, "actual parser must charge logical element work");
    let context = DecodeBudgetContext::new(DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        work.checked_mul(2).unwrap() - 1,
        usize::MAX,
        usize::MAX,
    ));
    let first = context.with(|| decode(&source, &pool)).unwrap();
    assert_eq!(first.get(), &fixture(true));
    let mut seen = None;
    let attempt = context
        .with(|| {
            classify_decode_attempt(|| {
                let error = failure(decode(&source, &pool));
                let HandshakeJsonAdmissionError::Json(json::Error::ScopedDecodeResource(origin)) =
                    error
                else {
                    panic!("original finite-work refusal lost: {error:?}");
                };
                seen = Some(origin.clone());
                Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let norito::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original work observer lost after classification");
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(first.belongs_to(&pool));
    assert_eq!(decode(&source, &pool).unwrap().get(), first.get());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn nested_key_and_value_scratch_release_during_unwind_preserves_sibling() {
    use norito::json::scratch::AdmittedText;
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    struct UnwindAtFingerprint<'a> {
        destination: AdmittedScratch<'a>,
        pool: &'a AllocationBudget,
        observation: &'a PhysicalObservation,
        sibling_bytes: usize,
        observed_pointers: &'a Cell<Option<[(usize, usize); 2]>>,
    }
    impl ScratchDestination for UnwindAtFingerprint<'_> {
        type Error = HandshakeJsonAdmissionError;
        type Text = AdmittedText;
        fn key<'a>(
            &self,
            object: &mut json::MapVisitor<'a, '_>,
        ) -> Result<Option<json::KeyRef<'a, Self::Text>>, Self::Error> {
            self.destination.key(object)
        }
        fn string(&self, parser: &mut json::Parser<'_>) -> Result<Self::Text, Self::Error> {
            let text = self.destination.string(parser)?;
            if text.as_ref().len() == 66 {
                assert_eq!(self.pool.reserved_bytes(), self.sibling_bytes + 21 + 66);
                let live = self.observation.snapshot();
                let pointers = [21, 66].map(|length| {
                    let pointer = live
                        .single_live_pointer(Layout::array::<u8>(length).unwrap())
                        .expect("one exact original scratch allocation is live");
                    (pointer, live.retirements(pointer))
                });
                assert_ne!(pointers[0].0, pointers[1].0);
                self.observed_pointers.set(Some(pointers));
                panic!("injected unwind while original key and value are both live");
            }
            Ok(text)
        }
    }

    let source = json::to_json(&fixture(true))
        .unwrap()
        .replace("consensus_fingerprint", "consensus_finger\\u0070rint");
    let original = source.clone();
    let pool = AllocationBudget::new(4096);
    let sibling = ChargedBuffer::<u8>::new(100, &pool).unwrap();
    let held = pool.reserved_bytes();
    let observation = PhysicalObservation::start();
    let observed_pointers = Cell::new(None);
    let destination = UnwindAtFingerprint {
        destination: AdmittedScratch::new(&pool),
        pool: &pool,
        observation: &observation,
        sibling_bytes: held,
        observed_pointers: &observed_pointers,
    };
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let mut parser = json::Parser::new(&source);
        parser.preflight_document().unwrap();
        metadata(&mut parser, &destination).unwrap();
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"injected unwind while original key and value are both live")
    );
    let retired = observation.snapshot();
    for (pointer, previous_retirements) in observed_pointers
        .get()
        .expect("the injected panic recorded both original allocations")
    {
        assert_eq!(retired.retirements(pointer), previous_retirements + 1);
    }
    for length in [21, 66] {
        assert_eq!(
            retired.single_live_pointer(Layout::array::<u8>(length).unwrap()),
            None
        );
    }
    assert_eq!(pool.reserved_bytes(), held);
    assert_eq!(source, original);
    drop(observation);
    assert_eq!(decode(&source, &pool).unwrap().get(), &fixture(true));
    assert_eq!(pool.reserved_bytes(), held);
    drop(sibling);
    assert_eq!(pool.reserved_bytes(), 0);
}
