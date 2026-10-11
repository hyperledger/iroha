//! Actual header/digest wire, hash and malformed original child error ordering.
use super::*;
use crate::{
    block::execution_context::BlockExecutionContextBundle,
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, NposConsensusEffects},
    da::{
        commitment::{DaCommitmentBundle, DaProofPolicyBundle},
        pin_intent::DaPinIntentBundle,
    },
    transaction::signed::TransactionEntrypoint,
};
use iroha_crypto::{Hash, HashOf, MerkleTree};
use norito::core::{
    CanonicalField, DecodeField, DecodeFlagsGuard, DecodeLimits, Encoder, FieldDestination,
    SerializePayload, classify_decode_attempt, header_flags, with_decode_limits_scope,
};
use std::{convert::Infallible, num::NonZeroU64};

fn typed_hash<T>(label: &[u8]) -> HashOf<T> {
    HashOf::from_untyped_unchecked(Hash::new(label))
}
fn complete() -> BlockHeader {
    BlockHeader {
        height: NonZeroU64::new(2).unwrap(),
        prev_block_hash: Some(typed_hash(b"inline header parent")),
        merkle_root: Some(typed_hash(b"inline header external root")),
        da_proof_policies_hash: Some(typed_hash(b"inline header DA policy")),
        da_commitments_hash: Some(typed_hash(b"inline header DA commitments")),
        da_pin_intents_hash: Some(typed_hash(b"inline header pin intents")),
        npos_effects_hash: Some(typed_hash(b"inline header NPoS effects")),
        creation_time_ms: u64::MAX - 1,
        view_change_index: u64::MAX,
        confidential_features: Some(ConfidentialFeatureDigest::new(
            Some([7; 32]),
            Some(u32::MAX),
            Some(9),
            Some(1),
            Some([11; 32]),
        )),
        execution_context_hash: Some(typed_hash(b"inline header execution context")),
        global_beacon_pulse_hash: Some(typed_hash(b"inline header pulse")),
    }
}
fn bare(value: &impl SerializePayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut bytes))
        .unwrap();
    bytes
}

// Independent unchanged encoder/nominal oracle. It is not a second decoder or
// an alternative header::wire tuple representation.
#[derive(norito::codec::Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::header::model::BlockHeader")]
struct OriginalHeader {
    height: NonZeroU64,
    prev_block_hash: Option<HashOf<BlockHeader>>,
    merkle_root: Option<HashOf<MerkleTree<TransactionEntrypoint>>>,
    da_proof_policies_hash: Option<HashOf<DaProofPolicyBundle>>,
    da_commitments_hash: Option<HashOf<DaCommitmentBundle>>,
    da_pin_intents_hash: Option<HashOf<DaPinIntentBundle>>,
    npos_effects_hash: Option<HashOf<NposConsensusEffects>>,
    creation_time_ms: u64,
    view_change_index: u64,
    confidential_features: Option<ConfidentialFeatureDigest>,
    execution_context_hash: Option<HashOf<BlockExecutionContextBundle>>,
    global_beacon_pulse_hash: Option<HashOf<FinalizedGlobalThresholdBeaconPulseV1>>,
}
impl From<BlockHeader> for OriginalHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            height: value.height,
            prev_block_hash: value.prev_block_hash,
            merkle_root: value.merkle_root,
            da_proof_policies_hash: value.da_proof_policies_hash,
            da_commitments_hash: value.da_commitments_hash,
            da_pin_intents_hash: value.da_pin_intents_hash,
            npos_effects_hash: value.npos_effects_hash,
            creation_time_ms: value.creation_time_ms,
            view_change_index: value.view_change_index,
            confidential_features: value.confidential_features,
            execution_context_hash: value.execution_context_hash,
            global_beacon_pulse_hash: value.global_beacon_pulse_hash,
        }
    }
}

#[test]
fn inline_actual_header_and_digest_keep_complete_original_wire_json_and_consensus_hash_projection()
{
    let all = complete();
    let mut empty = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    empty.confidential_features = None;
    let mut cases = vec![all, empty];
    // Every nullable commitment is absent independently; no hash or digest is
    // inferred from another field, and None never selects another hash layout.
    for index in 0..9 {
        let mut value = all;
        match index {
            0 => value.prev_block_hash = None,
            1 => value.merkle_root = None,
            2 => value.da_proof_policies_hash = None,
            3 => value.da_commitments_hash = None,
            4 => value.da_pin_intents_hash = None,
            5 => value.npos_effects_hash = None,
            6 => value.confidential_features = None,
            7 => value.execution_context_hash = None,
            8 => value.global_beacon_pulse_hash = None,
            _ => unreachable!(),
        }
        cases.push(value);
    }
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for value in &cases {
            let original = OriginalHeader::from(*value);
            let bytes = bare(&original);
            assert_eq!(bytes, bare(value));
            assert_eq!(
                norito::encode_canonical(&original).unwrap(),
                norito::encode_canonical(value).unwrap()
            );
            let decoded = BlockHeader::decode_inline_payload(&bytes).unwrap();
            assert_eq!(decoded, *value);
            assert_eq!(bare(&decoded), bytes);
            assert_eq!(decoded.hash(), value.hash());
            assert_eq!(HashOf::new(&decoded), HashOf::new(value));
            assert_eq!(decoded.is_genesis(), value.is_genesis());
            assert_eq!(decoded.creation_time(), value.creation_time());
            assert_eq!(
                norito::json::to_json(&decoded).unwrap(),
                norito::json::to_json(value).unwrap()
            );
            if let Some(digest) = value.confidential_features {
                let decoded_digest =
                    <ConfidentialFeatureDigest as InlineLeaf>::read(&bare(&digest)).unwrap();
                assert_eq!(decoded_digest, digest);
                assert_eq!(decoded_digest.is_empty(), digest.is_empty());
            }
        }
    }
}

// Only malformed-source producers. The sole derive and Option serializer write
// every actual record/child prefix; no production or test binary parser is added.
struct RawBytes(Vec<u8>);
impl SerializePayload for RawBytes {
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
struct RawDigest {
    vk_set_hash: Option<RawBytes>,
    poseidon_params_id: Option<u32>,
    pedersen_params_id: Option<u32>,
    conf_rules_version: Option<u32>,
    zk_policy_hash: Option<RawBytes>,
}
/// The original child bytes of one present digest hash under the active layout flags.
///
/// The record encoder writes an optional `[u8; 32]` through the sole generic array
/// serializer: thirty-two one-byte elements, each behind its own length prefix. A
/// faithful source producer therefore carries exactly those bytes. Thirty-two packed
/// bytes are a different source that the encoder never emits; the complete-frame
/// decoders refuse a block carrying it. The block test
/// `framed_block_rejects_packed_confidential_digest_hash_arrays` shows that.
fn original_hash_child(bytes: [u8; 32]) -> RawBytes {
    RawBytes(bare(&bytes))
}
#[derive(norito::codec::Encode)]
struct RawHeader {
    height: RawBytes,
    prev_block_hash: Option<RawBytes>,
    merkle_root: Option<HashOf<MerkleTree<TransactionEntrypoint>>>,
    da_proof_policies_hash: Option<HashOf<DaProofPolicyBundle>>,
    da_commitments_hash: Option<HashOf<DaCommitmentBundle>>,
    da_pin_intents_hash: Option<HashOf<DaPinIntentBundle>>,
    npos_effects_hash: Option<HashOf<NposConsensusEffects>>,
    creation_time_ms: u64,
    view_change_index: u64,
    confidential_features: Option<RawDigest>,
    execution_context_hash: Option<HashOf<BlockExecutionContextBundle>>,
    global_beacon_pulse_hash: Option<HashOf<FinalizedGlobalThresholdBeaconPulseV1>>,
}
fn raw(value: BlockHeader) -> RawHeader {
    RawHeader {
        height: RawBytes(value.height.get().to_le_bytes().to_vec()),
        prev_block_hash: value
            .prev_block_hash
            .map(|hash| RawBytes(hash.as_ref().to_vec())),
        merkle_root: value.merkle_root,
        da_proof_policies_hash: value.da_proof_policies_hash,
        da_commitments_hash: value.da_commitments_hash,
        da_pin_intents_hash: value.da_pin_intents_hash,
        npos_effects_hash: value.npos_effects_hash,
        creation_time_ms: value.creation_time_ms,
        view_change_index: value.view_change_index,
        confidential_features: value.confidential_features.map(|d| RawDigest {
            vk_set_hash: d.vk_set_hash.map(original_hash_child),
            poseidon_params_id: d.poseidon_params_id,
            pedersen_params_id: d.pedersen_params_id,
            conf_rules_version: d.conf_rules_version,
            zk_policy_hash: d.zk_policy_hash.map(original_hash_child),
        }),
        execution_context_hash: value.execution_context_hash,
        global_beacon_pulse_hash: value.global_beacon_pulse_hash,
    }
}
fn compare_original_error(bytes: &[u8], limits: DecodeLimits) {
    let actual = with_decode_limits_scope(limits, || {
        classify_decode_attempt(|| BlockHeader::decode_inline_payload(bytes))
    })
    .unwrap_err();
    let ordinary = with_decode_limits_scope(limits, || {
        classify_decode_attempt(|| {
            norito::core::decode_field_canonical::<BlockHeader>(bytes).map(|(value, _)| value)
        })
    })
    .unwrap_err();
    assert_eq!(actual.kind(), ordinary.kind());
    let actual = actual.into_error();
    let ordinary = ordinary.into_error();
    assert_eq!(
        actual.decode_resource_error(),
        ordinary.decode_resource_error()
    );
    assert_eq!(actual.to_string(), ordinary.to_string());
}

struct LocateField<const TARGET: usize> {
    base: usize,
    span: Option<std::ops::Range<usize>>,
}
impl<const TARGET: usize> FieldDestination for LocateField<TARGET> {
    type Error = Infallible;
}
impl<const TARGET: usize, const INDEX: usize, T> DecodeField<INDEX, T> for LocateField<TARGET> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, T>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        if INDEX == TARGET {
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
fn locate_option<const INDEX: usize>(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut destination = LocateField::<INDEX> {
        base: bytes.as_ptr().addr(),
        span: None,
    };
    let (_, used) = BlockHeader::decode_fields(bytes, &mut destination).unwrap();
    assert_eq!(used, bytes.len());
    destination.span.unwrap()
}

#[test]
fn inline_actual_header_preserves_nonzero_child_before_trailer_and_original_prefix_errors() {
    let value = complete();
    let limits = DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = bare(&value);
        assert_eq!(bytes, bare(&raw(value)));
        // The producer's present digest hashes are the emitted array children: one
        // length prefix per byte (eight bytes fixed, one byte compact), never the
        // thirty-two packed bytes.
        let child = original_hash_child([7; 32]).0;
        assert_eq!(
            child.len(),
            if flags == 0 {
                32 * (8 + 1)
            } else {
                32 * (1 + 1)
            }
        );
        assert_ne!(child, [7; 32]);
        for end in 0..bytes.len() {
            compare_original_error(&bytes[..end], limits);
        }
        let mut trailing = bytes.clone();
        trailing.push(0xa5);
        compare_original_error(&trailing, limits);
        for height in [vec![0; 8], vec![0; 7], vec![0; 9]] {
            let mut malformed = raw(value);
            malformed.height = RawBytes(height);
            let bytes = bare(&malformed);
            for trailer in [false, true] {
                let mut source = bytes.clone();
                if trailer {
                    source.push(0xa5);
                }
                compare_original_error(&source, limits);
            }
        }
        let mut zero = raw(value);
        zero.height = RawBytes(vec![0; 8]);
        assert!(matches!(
            BlockHeader::decode_inline_payload(&bare(&zero)),
            Err(Error::InvalidNonZero)
        ));
        let mut digest = bare(&value.confidential_features.unwrap());
        digest.push(0xa5);
        assert!(matches!(
            <ConfidentialFeatureDigest as InlineLeaf>::read(&digest),
            Err(Error::LengthMismatch)
        ));
    }
}

#[test]
fn inline_actual_header_nullable_hash_and_digest_arrays_keep_original_framed_array_and_limit_precedence()
 {
    let value = complete();
    let hash = value.prev_block_hash.unwrap().as_ref().to_vec();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let original_bytes = bare(&value);
        for span in [
            locate_option::<1>(&original_bytes),
            locate_option::<9>(&original_bytes),
        ] {
            assert_eq!(original_bytes[span.start], 1);
            let mut wrong_tag = original_bytes.clone();
            wrong_tag[span.start] = 2;
            for trailer in [false, true] {
                let mut source = wrong_tag.clone();
                if trailer {
                    source.push(0xa5);
                }
                compare_original_error(
                    &source,
                    DecodeLimits::new(1 << 20, 1 << 20, 1 << 20, 1 << 20, 64),
                );
            }
        }
        let leaves = [
            hash[..31].to_vec(),
            {
                let mut bytes = hash.clone();
                bytes.push(0xa5);
                bytes
            },
            norito::encode_canonical(&[0u8; 32]).unwrap(),
            {
                let mut bytes = hash.clone();
                bytes[31] &= !1;
                bytes.push(0xa5);
                bytes
            },
        ];
        for leaf in leaves {
            for child in 0..3 {
                let mut malformed = raw(value);
                match child {
                    0 => malformed.prev_block_hash = Some(RawBytes(leaf.clone())),
                    1 => {
                        malformed
                            .confidential_features
                            .as_mut()
                            .unwrap()
                            .vk_set_hash = Some(RawBytes(leaf.clone()))
                    }
                    2 => {
                        malformed
                            .confidential_features
                            .as_mut()
                            .unwrap()
                            .zk_policy_hash = Some(RawBytes(leaf.clone()))
                    }
                    _ => unreachable!(),
                }
                let bytes = bare(&malformed);
                for trailer in [false, true] {
                    let mut source = bytes.clone();
                    if trailer {
                        source.push(0xa5);
                    }
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
                        compare_original_error(&source, limits);
                    }
                }
            }
        }
    }
}
