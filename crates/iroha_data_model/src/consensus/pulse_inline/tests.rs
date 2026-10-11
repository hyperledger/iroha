//! Original transport, canonical field ordering and unchanged pulse validation.
use super::*;
use crate::sumeragi_finality::{
    BeaconPulseShapeError, global_threshold_beacon_pulse_id_v1, validate_beacon_pulse_shape,
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use norito::core::{DecodeFlagsGuard, Encoder, SerializePayload, header_flags};

fn fixture() -> FinalizedGlobalThresholdBeaconPulseV1 {
    // A genuine canonical G1 point exercises shape validation. This is not a
    // threshold signature, authenticated DKG session or native finality fixture.
    let key = KeyPair::from_seed(vec![17; 32], Algorithm::BlsNormal);
    let (_, point) = key.public_key().try_to_bytes().unwrap();
    let mut value = FinalizedGlobalThresholdBeaconPulseV1 {
        version: 1,
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"inline pulse codec genesis",
        ))),
        session_id: [2; 32],
        roster_hash: [3; 32],
        transcript_hash: [4; 32],
        context: GlobalThresholdBeaconPulseContextV1 {
            instance: [5; 32],
            epoch: 7,
            epoch_context_id: [6; 32],
            parent_consensus_hash: [7; 32],
            parent_result: [8; 32],
        },
        height: 9,
        round: 0,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
            height: 8,
            block_hash: HashOf::from_untyped_unchecked(Hash::new(b"inline pulse codec parent")),
        },
        signature: point.try_into().unwrap(),
        seed: [9; 32],
        pulse_id: [0; 32],
    };
    value.pulse_id = global_threshold_beacon_pulse_id_v1(&value, value.seed);
    value
}
fn bare(value: &impl SerializePayload) -> Vec<u8> {
    let mut output = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut output))
        .unwrap();
    output
}

#[test]
fn inline_pulse_keeps_complete_original_wire_schema_json_and_existing_shape_validation() {
    // This independent encoder preserves the prior twelve ordered fields and
    // nominal identity. It is a test oracle, never a production decoder.
    #[derive(norito::codec::Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1")]
    struct OriginalWire {
        version: u16,
        network_id: NetworkId,
        session_id: [u8; 32],
        roster_hash: [u8; 32],
        transcript_hash: [u8; 32],
        context: GlobalThresholdBeaconPulseContextV1,
        height: u64,
        round: u64,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1,
        signature: [u8; 48],
        seed: [u8; 32],
        pulse_id: [u8; 32],
    }
    let valid = fixture();
    validate_beacon_pulse_shape(&valid).unwrap();
    let mut wrong_version = valid;
    wrong_version.version = 7;
    let mut inert_context = valid;
    inert_context.context.parent_result = [0; 32];
    let mut malformed_signature = valid;
    malformed_signature.signature = [0; 48];
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for value in [valid, wrong_version, inert_context, malformed_signature] {
            let original = OriginalWire {
                version: value.version,
                network_id: value.network_id,
                session_id: value.session_id,
                roster_hash: value.roster_hash,
                transcript_hash: value.transcript_hash,
                context: value.context,
                height: value.height,
                round: value.round,
                finalized_chain_anchor: value.finalized_chain_anchor,
                signature: value.signature,
                seed: value.seed,
                pulse_id: value.pulse_id,
            };
            let bytes = bare(&original);
            assert_eq!(bytes, bare(&value));
            let decoded =
                FinalizedGlobalThresholdBeaconPulseV1::decode_inline_payload(&bytes).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(bare(&decoded), bytes);
            assert_eq!(
                norito::encode_canonical(&original).unwrap(),
                norito::encode_canonical(&value).unwrap()
            );
            assert_eq!(HashOf::new(&decoded), HashOf::new(&value));
            assert_eq!(
                norito::json::to_json(&decoded).unwrap(),
                norito::json::to_json(&value).unwrap()
            );
            assert_eq!(
                validate_beacon_pulse_shape(&decoded).map_err(|error| error.to_string()),
                validate_beacon_pulse_shape(&value).map_err(|error| error.to_string())
            );
            assert_eq!(
                <GlobalThresholdBeaconPulseContextV1 as InlineLeaf>::read(&bare(&value.context))
                    .unwrap(),
                value.context
            );
            assert_eq!(
                <GlobalThresholdBeaconChainAnchorV1 as InlineLeaf>::read(&bare(
                    &value.finalized_chain_anchor
                ))
                .unwrap(),
                value.finalized_chain_anchor
            );
        }
    }
    assert!(matches!(
        validate_beacon_pulse_shape(&wrong_version),
        Err(BeaconPulseShapeError::UnsupportedVersion { actual: 7 })
    ));
    assert!(matches!(
        validate_beacon_pulse_shape(&inert_context),
        Err(BeaconPulseShapeError::PulseContextMismatch)
    ));
    assert!(matches!(
        validate_beacon_pulse_shape(&malformed_signature),
        Err(BeaconPulseShapeError::Signature(_))
    ));
}

struct LocateSecondField {
    base: usize,
    span: Option<std::ops::Range<usize>>,
}
impl FieldDestination for LocateSecondField {
    type Error = Infallible;
}
impl<const INDEX: usize, T> DecodeField<INDEX, T> for LocateSecondField {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        if INDEX == 1 {
            let start = field
                .bytes()
                .as_ptr()
                .addr()
                .checked_sub(self.base)
                .unwrap();
            self.span = Some(start..start.checked_add(field.bytes().len()).unwrap());
        }
        Ok(())
    }
}

#[test]
fn inline_pulse_generated_children_keep_marked_hash_and_child_before_trailing_error_order() {
    let value = fixture();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = bare(&value);
        for end in 0..bytes.len() {
            let prepared =
                FinalizedGlobalThresholdBeaconPulseV1::decode_inline_payload(&bytes[..end])
                    .unwrap_err();
            let original = norito::core::decode_field_canonical::<
                FinalizedGlobalThresholdBeaconPulseV1,
            >(&bytes[..end])
            .unwrap_err();
            assert_eq!(prepared.to_string(), original.to_string(), "prefix {end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0xa5);
        assert!(matches!(
            FinalizedGlobalThresholdBeaconPulseV1::decode_inline_payload(&trailing),
            Err(Error::LengthMismatch)
        ));
        let mut location = LocateSecondField {
            base: bytes.as_ptr().addr(),
            span: None,
        };
        let (_, used) =
            FinalizedGlobalThresholdBeaconPulseV1::decode_fields(&bytes, &mut location).unwrap();
        assert_eq!(used, bytes.len());
        let span = location.span.unwrap();
        assert_eq!(&bytes[span.clone()], value.network_id.as_bytes());
        let mut wrong_hash = bytes.clone();
        wrong_hash[span.end - 1] &= !1;
        for bad in [wrong_hash.clone(), {
            wrong_hash.push(0xa5);
            wrong_hash
        }] {
            let prepared =
                FinalizedGlobalThresholdBeaconPulseV1::decode_inline_payload(&bad).unwrap_err();
            let original =
                norito::core::decode_field_canonical::<FinalizedGlobalThresholdBeaconPulseV1>(&bad)
                    .unwrap_err();
            assert!(matches!(
                prepared,
                Error::InvalidValue {
                    context: "hash lsb"
                }
            ));
            assert_eq!(prepared.to_string(), original.to_string());
        }
        for child in [bare(&value.context), bare(&value.finalized_chain_anchor)] {
            assert!(!child.is_empty());
        }
        let mut context = bare(&value.context);
        context.push(0xa5);
        assert!(matches!(
            <GlobalThresholdBeaconPulseContextV1 as InlineLeaf>::read(&context),
            Err(Error::LengthMismatch)
        ));
        let mut anchor = bare(&value.finalized_chain_anchor);
        anchor.push(0xa5);
        assert!(matches!(
            <GlobalThresholdBeaconChainAnchorV1 as InlineLeaf>::read(&anchor),
            Err(Error::LengthMismatch)
        ));
    }
}

// A malformed source producer, not another binary decoder: the real derive
// writes every original field prefix and ordering around these exact leaf bytes.
struct RawHash(Vec<u8>);
impl SerializePayload for RawHash {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(self.0.len())
    }
}
#[derive(norito::codec::Encode)]
struct HashAnchorWire {
    height: u64,
    block_hash: RawHash,
}
#[derive(norito::codec::Encode)]
struct HashPulseWire {
    version: u16,
    network_id: RawHash,
    session_id: [u8; 32],
    roster_hash: [u8; 32],
    transcript_hash: [u8; 32],
    context: GlobalThresholdBeaconPulseContextV1,
    height: u64,
    round: u64,
    finalized_chain_anchor: HashAnchorWire,
    signature: [u8; 48],
    seed: [u8; 32],
    pulse_id: [u8; 32],
}
fn hash_pulse_wire(
    value: &FinalizedGlobalThresholdBeaconPulseV1,
    network: Vec<u8>,
    anchor: Vec<u8>,
) -> HashPulseWire {
    HashPulseWire {
        version: value.version,
        network_id: RawHash(network),
        session_id: value.session_id,
        roster_hash: value.roster_hash,
        transcript_hash: value.transcript_hash,
        context: value.context,
        height: value.height,
        round: value.round,
        finalized_chain_anchor: HashAnchorWire {
            height: value.finalized_chain_anchor.height,
            block_hash: RawHash(anchor),
        },
        signature: value.signature,
        seed: value.seed,
        pulse_id: value.pulse_id,
    }
}

#[test]
fn inline_hash_leaves_keep_original_raw_array_framing_and_logical_error_precedence() {
    use norito::core::{DecodeLimits, classify_decode_attempt, with_decode_limits_scope};
    let value = fixture();
    let network = value.network_id.as_bytes().to_vec();
    let anchor = value.finalized_chain_anchor.block_hash.as_ref().to_vec();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let original_wire = hash_pulse_wire(&value, network.clone(), anchor.clone());
        assert_eq!(bare(&original_wire), bare(&value));
        let mut malformed_leaves = vec![network[..31].to_vec(), {
            let mut bytes = network.clone();
            bytes.push(0xa5);
            bytes
        }];
        // Exact array framing is produced by the sole canonical serializer.
        // Hash ordinarily spells raw bytes; malformed length/framed-array fields
        // must preserve that decoder's existing inner sequence/count behavior.
        let framed = norito::encode_canonical(&[0u8; 32]).unwrap();
        malformed_leaves.push(framed);
        let mut bad_marker = network.clone();
        bad_marker[31] &= !1;
        bad_marker.push(0xa5);
        malformed_leaves.push(bad_marker);
        for leaf in malformed_leaves {
            for mutate_anchor in [false, true] {
                let wire = if mutate_anchor {
                    hash_pulse_wire(&value, network.clone(), leaf.clone())
                } else {
                    hash_pulse_wire(&value, leaf.clone(), anchor.clone())
                };
                let bytes = bare(&wire);
                for trailer in [false, true] {
                    let mut source = bytes.clone();
                    if trailer {
                        source.push(0xa5);
                    }
                    // Compare every original logical envelope, including zero
                    // sequence/metadata allowance. A malformed inner hash must
                    // never be reclassified as a outer trailing-byte error.
                    // Sequence and metadata ceilings stay zero. The original owning
                    // oracle still needs real alignment scratch; use the existing
                    // source-derived canonical allowance, never a guessed cap.
                    // The physical control separately proves its exact zero-budget
                    // refusal and the inline decoder's zero-allocation real cause.
                    for limits in [
                        DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64),
                        DecodeLimits::new(
                            0,
                            1 << 20,
                            0,
                            norito::canonical_decode_limits(source.len())
                                .max_total_allocated_bytes(),
                            64,
                        ),
                    ] {
                        let actual = with_decode_limits_scope(limits, || {
                            classify_decode_attempt(|| {
                                FinalizedGlobalThresholdBeaconPulseV1::decode_inline_payload(
                                    &source,
                                )
                            })
                        })
                        .unwrap_err();
                        let original = with_decode_limits_scope(limits, || {
                            classify_decode_attempt(|| {
                                norito::core::decode_field_canonical::<
                                    FinalizedGlobalThresholdBeaconPulseV1,
                                >(&source)
                                .map(|(value, _)| value)
                            })
                        })
                        .unwrap_err();
                        assert_eq!(actual.kind(), original.kind());
                        let actual = actual.into_error();
                        let original = original.into_error();
                        assert_eq!(
                            actual.decode_resource_error(),
                            original.decode_resource_error()
                        );
                        assert_eq!(
                            actual.to_string(),
                            original.to_string(),
                            "anchor {mutate_anchor}, trailer {trailer}, flags {flags:#x}"
                        );
                    }
                }
            }
        }
    }
}
