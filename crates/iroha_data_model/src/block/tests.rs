//! Canonical block validation and wire-format regressions.

use super::*;
use crate::consensus::NposConsensusEffects;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_version::codec::EncodeVersioned;
use norito::codec::{DecodeAll as _, Encode};
use std::num::NonZeroU64;
// Bring commonly used types referenced in transparent API tests.
#[cfg(feature = "transparent_api")]
use super::output_test_support::{self as fixture, network, simple_time};
#[cfg(feature = "transparent_api")]
use crate::ValidationFail;
#[cfg(feature = "transparent_api")]
use crate::trigger::DataTriggerSequence;
use crate::{
    da::{
        commitment::{DaCommitmentBundle, DaCommitmentRecord, DaProofScheme},
        ingest::{
            DaIngestAuthorizationV1, DaIngestSignatureV1, DaPinScopeAuthorizationV1, DaPinScopeV1,
        },
        pin_intent::{DaPinIntent, DaPinIntentBundle},
        types::{BlobDigest, RetentionPolicy, StorageTicketId},
    },
    query::dsl::{HasProjection, PredicateMarker, SelectorMarker},
    sorafs::pin_registry::ManifestDigest,
    transaction::{TransactionBuilder, signed::TransactionEntrypoint},
};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
fn assert_predicate<T: HasProjection<PredicateMarker>>() {}
fn assert_selector<T: HasProjection<SelectorMarker>>() {}
fn checked_random_keypair() -> KeyPair {
    KeyPair::try_random().expect("test fixture random key generation should succeed")
}
#[cfg(feature = "transparent_api")]
fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
        panic!("{algorithm:?} block fixture key generation should succeed: {err}")
    })
}
#[cfg(feature = "transparent_api")]
fn checked_bls_keypair() -> KeyPair {
    checked_random_keypair_with_algorithm(Algorithm::BlsNormal)
}
fn test_network_id() -> crate::NetworkId {
    crate::NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([0x15; Hash::LENGTH]),
    ))
}
/// Frame an arbitrary block payload under the canonical V1 header.
///
/// `SignedBlock::canonical_wire` is the only production framer and takes a block. Tests use this
/// to assemble a frame independently of it, or around a payload it never produces.
fn frame_block_payload(version: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(1 + norito::core::Header::SIZE + payload.len());
    framed.push(version);
    write_signed_block_header(payload, &mut framed).expect("canonical V1 block header");
    framed.extend_from_slice(payload);
    framed
}
fn split_default_norito_fields(bytes: &[u8], count: usize) -> Vec<Vec<u8>> {
    let flags = norito::core::default_encode_flags();
    let mut offset = 0usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, prefix) = norito::core::read_len_from_slice_with_flags(
            bytes.get(offset..).expect("Norito field prefix"),
            flags,
        )
        .expect("Norito field length");
        let start = offset.checked_add(prefix).expect("Norito field start");
        let end = start.checked_add(len).expect("Norito field end");
        fields.push(
            bytes
                .get(start..end)
                .expect("complete Norito field")
                .to_vec(),
        );
        offset = end;
    }
    assert_eq!(offset, bytes.len(), "unexpected trailing Norito fields");
    fields
}
fn encode_default_norito_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    let flags = norito::core::default_encode_flags();
    let mut encoded = Vec::new();
    for field in fields {
        norito::core::write_len_to_vec_with_flags(
            &mut encoded,
            u64::try_from(field.len()).expect("Norito field length fits u64"),
            flags,
        );
        encoded.extend_from_slice(field);
    }
    encoded
}
fn signed_transaction_with_log_type_name_alias(canonical: &[u8]) -> Vec<u8> {
    assert_eq!(canonical.first(), Some(&1), "signed transaction V1 prefix");
    let mut signed = split_default_norito_fields(&canonical[1..], 3);
    let mut payload = split_default_norito_fields(&signed[1], 9);

    assert_eq!(&payload[3][..4], &0_u32.to_le_bytes());
    let executable_fields = split_default_norito_fields(&payload[3][4..], 1);
    let sequence = &executable_fields[0];
    assert_eq!(&sequence[..8], &1_u64.to_le_bytes());
    let sequence_fields = split_default_norito_fields(&sequence[8..], 1);
    let mut instruction = split_default_norito_fields(&sequence_fields[0], 2);
    let wire_id = split_default_norito_fields(&instruction[0], 1);
    assert_eq!(wire_id[0], b"iroha.log");

    instruction[0] = encode_default_norito_fields(&[std::any::type_name::<crate::prelude::Log>()
        .as_bytes()
        .to_vec()]);
    let mut sequence = 1_u64.to_le_bytes().to_vec();
    sequence.extend_from_slice(&encode_default_norito_fields(&[
        encode_default_norito_fields(&instruction),
    ]));
    let mut executable = 0_u32.to_le_bytes().to_vec();
    executable.extend_from_slice(&encode_default_norito_fields(&[sequence]));
    payload[3] = executable;
    signed[1] = encode_default_norito_fields(&payload);

    let mut alternate = vec![1];
    alternate.extend_from_slice(&encode_default_norito_fields(&signed));
    alternate
}
fn external_entrypoint_wire(signed_transaction_wire: &[u8]) -> Vec<u8> {
    assert_eq!(
        signed_transaction_wire.first(),
        Some(&1),
        "nested signed transaction V1 prefix"
    );
    let mut wire = vec![1];
    wire.extend_from_slice(&0_u32.to_le_bytes());
    wire.extend_from_slice(&encode_default_norito_fields(&[signed_transaction_wire
        [1..]
        .to_vec()]));
    wire
}
fn block_with_nested_transaction_wire_alias(
    canonical_block: &[u8],
    canonical_entrypoint: &[u8],
    alternate_entrypoint: &[u8],
) -> Vec<u8> {
    assert_eq!(canonical_block.first(), Some(&1), "signed block V1 prefix");
    // signatures, payload, result, commit_certificate
    let mut block = split_default_norito_fields(&canonical_block[1..], 4);
    // header, external_entrypoints, da_commitments, da_proof_policies,
    // da_pin_intents, npos_consensus_effects, global_beacon_pulse,
    // execution_context
    let mut payload = split_default_norito_fields(&block[1], 8);
    assert_eq!(&payload[1][..8], &1_u64.to_le_bytes());
    let entrypoints = split_default_norito_fields(&payload[1][8..], 1);
    assert_eq!(entrypoints[0], canonical_entrypoint[1..]);

    let mut alternate_entrypoints = 1_u64.to_le_bytes().to_vec();
    alternate_entrypoints.extend_from_slice(&encode_default_norito_fields(&[alternate_entrypoint
        [1..]
        .to_vec()]));
    payload[1] = alternate_entrypoints;
    block[1] = encode_default_norito_fields(&payload);

    let mut alternate = vec![1];
    alternate.extend_from_slice(&encode_default_norito_fields(&block));
    alternate
}

// Malformed wire fixture only: strip the mandatory header while retaining the version.
// Production APIs expose only the complete canonical block wire.
fn headerless_block_fixture(block: &SignedBlock) -> Vec<u8> {
    let wire = block.canonical_wire().expect("canonical fixture");
    let mut malformed = vec![wire.version()];
    malformed.extend_from_slice(wire.payload());
    malformed
}

#[test]
fn block_rejection_reason_json_has_closed_output_bound() {
    let reason = error::BlockRejectionReason::ConfidentialFeatureDigestMismatch;
    let expected = norito::json::to_json(&reason).expect("serialize block rejection JSON");
    assert_eq!(
        norito::json::to_json_bounded(&reason, expected.len())
            .expect("serialize block rejection at exact JSON bound"),
        expected
    );
    assert_eq!(
        norito::json::to_json_bounded(&reason, expected.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
}
fn test_pin_authorization(lane: LaneId, epoch: u64, sequence: u64) -> DaIngestAuthorizationV1 {
    let key_pair = KeyPair::try_from_seed(vec![0xDE; 32], Algorithm::Ed25519)
        .expect("valid deterministic block pin-intent key");
    let mut authorization = DaIngestAuthorizationV1 {
        network_id: test_network_id(),
        owner: crate::account::AccountId::new(key_pair.public_key().clone()),
        lane_id: lane,
        epoch,
        sequence,
        payload_hash: BlobDigest::new([0xDF; 32]),
        payload_bytes: 1,
        request_content_hash: Hash::prehashed([0xE0; 32]),
        signatures: Vec::new(),
    };
    authorization.signatures.push(DaIngestSignatureV1 {
        signer: key_pair.public_key().clone(),
        signature: Signature::try_new(key_pair.private_key(), &authorization.signing_digest())
            .expect("sign deterministic block pin-intent authorization"),
    });
    authorization
}
pub(super) fn test_pin_intent(
    lane: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: StorageTicketId,
    manifest_hash: ManifestDigest,
) -> DaPinIntent {
    let key_pair = KeyPair::try_from_seed(vec![0xDE; 32], Algorithm::Ed25519)
        .expect("valid deterministic block pin-intent key");
    let authorization = test_pin_authorization(lane, epoch, sequence);
    let scope = DaPinScopeV1::new(&authorization, storage_ticket, manifest_hash, None);
    let scope_authorization = DaPinScopeAuthorizationV1::try_sign(scope, &key_pair)
        .expect("sign deterministic block pin scope");
    DaPinIntent::new(authorization, scope_authorization)
}
pub(super) fn sample_da_bundle() -> DaCommitmentBundle {
    let record = DaCommitmentRecord::new(
        LaneId::new(7),
        1,
        1,
        BlobDigest::new([0x11; 32]),
        ManifestDigest::new([0x22; 32]),
        DaProofScheme::MerkleSha256,
        Hash::prehashed([0x33; 32]),
        Some(Hash::prehashed([0x55; 32])),
        RetentionPolicy::default(),
        StorageTicketId::new([0x66; 32]),
        Signature::try_from_bytes(&[0x77; 64])
            .expect("checked signed-block DA commitment acknowledgement signature fixture"),
    );
    DaCommitmentBundle::new(vec![record])
}
fn checked_block_signature(index: u64, keypair: &KeyPair, header: &BlockHeader) -> BlockSignature {
    BlockSignature::new(
        index,
        SignatureOf::try_from_hash(keypair.private_key(), header.hash())
            .expect("checked signed-block fixture signature"),
    )
}
fn block_with_execution_context(execution_context: BlockExecutionContextBundle) -> SignedBlock {
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 1, 0);
    SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: Some(execution_context),
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    }
}
#[test]
fn merged_lane_entrypoints_are_an_execution_suffix_of_the_proposal() {
    use crate::sumeragi_lanes::{SumeragiLaneMerge, SumeragiLaneMergeSection};
    let transaction = |text: &str| {
        let key_pair = checked_random_keypair();
        let authority = crate::account::AccountId::new(key_pair.public_key().clone());
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            crate::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([crate::prelude::Log::new(crate::Level::INFO, text.into())])
        .sign(key_pair.private_key());
        TransactionEntrypoint::External(signed)
    };
    let context = |entrypoint: &TransactionEntrypoint, lane: u32| {
        ExternalExecutionContext::new(entrypoint.hash(), LaneId::new(lane), DataSpaceId::new(0))
    };
    let own = transaction("lane 0");
    let mut bundle = BlockExecutionContextBundle::new(vec![context(&own, 0)]);
    bundle.lane_merge = Some(SumeragiLaneMergeSection {
        merges: vec![SumeragiLaneMerge {
            lane: LaneId::new(16),
            incarnation: [1; 32],
            from: 1,
            to: 2,
            tip_hash: [2; 32],
            tip_result: [3; 32],
        }],
        time_floor_ms: 0,
        merged_count: 0,
    });
    let mut payload = BlockPayload {
        header: BlockHeader::new(NonZeroU64::new(3).unwrap(), None, None, 0, 0),
        external_entrypoints: vec![own],
        execution_context: Some(bundle),
        da_commitments: None,
        da_proof_policies: None,
        da_pin_intents: None,
        npos_consensus_effects: None,
        global_beacon_pulse: None,
    };
    SignedBlock::refresh_entrypoint_roots(&mut payload);
    let proposal = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload,
        result: None,
        commit_certificate: None,
    };
    let merged = vec![transaction("lane 16 a"), transaction("lane 16 b")];
    let contexts = merged
        .iter()
        .map(|entrypoint| context(entrypoint, 16))
        .collect();
    let original_header = proposal.header();
    let original_merge_pointer = proposal.lane_merge().unwrap().merges.as_ptr();
    let original_proposal = proposal.clone();
    let executed = proposal
        .with_merged_entrypoints(merged, contexts)
        .expect("expand");
    assert_eq!(executed.merged_entrypoint_count(), 2);
    assert_eq!(
        executed.lane_merge().unwrap().merges.as_ptr(),
        original_merge_pointer,
        "successful expansion moves the original proposal graph"
    );
    assert_eq!(executed.payload.external_entrypoints.len(), 3);
    assert_ne!(
        executed.header().merkle_root(),
        original_header.merkle_root(),
        "the executed header binds every executed entrypoint"
    );
    assert_eq!(
        executed
            .canonical_resultless_proposal()
            .expect("valid original proposal"),
        original_proposal
    );
    let own_pointer = executed.payload.external_entrypoints.as_ptr();
    let (executed, merged, contexts, reason) = executed
        .with_merged_entrypoints(Vec::new(), Vec::new())
        .expect_err("merged entrypoints are appended once");
    assert_eq!(reason, "the block already carries merged entrypoints");
    assert_eq!(executed.payload.external_entrypoints.as_ptr(), own_pointer);
    assert!(merged.is_empty());
    assert!(contexts.is_empty());
    let merged = vec![transaction("x")];
    let merged_pointer = merged.as_ptr();
    let original_pointer = original_proposal.payload.external_entrypoints.as_ptr();
    let (proposal, merged, contexts, reason) = original_proposal
        .with_merged_entrypoints(merged, Vec::new())
        .expect_err("contexts must align");
    assert_eq!(reason, "merged entrypoints and contexts differ in length");
    assert_eq!(proposal.header(), original_header);
    assert_eq!(
        proposal.payload.external_entrypoints.as_ptr(),
        original_pointer
    );
    assert_eq!(merged.as_ptr(), merged_pointer);
    assert_eq!(merged.len(), 1);
    assert!(contexts.is_empty());
}
#[test]
fn block_payload_ordering_includes_execution_context() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let payload = BlockPayload {
        header,
        external_entrypoints: Vec::new(),
        execution_context: None,
        da_commitments: None,
        da_proof_policies: None,
        da_pin_intents: None,
        npos_consensus_effects: None,
        global_beacon_pulse: None,
    };
    let mut with_context = payload.clone();
    with_context.execution_context = Some(BlockExecutionContextBundle::new(vec![
        ExternalExecutionContext::new(
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
                [0xC7; Hash::LENGTH],
            )),
            LaneId::new(1),
            DataSpaceId::new(2),
        ),
    ]));
    assert_ne!(payload, with_context);
    assert_ne!(payload.cmp(&with_context), std::cmp::Ordering::Equal);
}
#[test]
fn signed_block_is_empty_without_entrypoints_or_artifacts() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    assert!(block.is_empty());
}
#[test]
fn signed_block_with_empty_execution_context_is_empty() {
    let block = block_with_execution_context(BlockExecutionContextBundle::default());
    assert!(block.is_empty());
}
#[cfg(feature = "transparent_api")]
#[test]
fn signed_block_try_sign_adds_verifiable_signature() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let key_pair = checked_random_keypair();
    let signatory_idx = 3;
    block
        .try_sign(key_pair.private_key(), signatory_idx)
        .expect("checked block signing succeeds");
    let signature = block
        .signatures()
        .find(|signature| signature.index() == signatory_idx as u64)
        .expect("signature for requested signatory is present");
    signature
        .signature()
        .verify_hash(key_pair.public_key(), block.hash())
        .expect("checked block signature verifies");
}
#[test]
fn signed_block_wire_roundtrips_canonical_external_entrypoints() {
    let key_pair = checked_random_keypair();
    let authority = crate::account::AccountId::new(key_pair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(key_pair.private_key());
    let entrypoint = TransactionEntrypoint::from(tx.clone());
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: vec![entrypoint.clone()],
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    assert!(block.is_resultless_proposal());
    let mut explicit_iter = block.external_entrypoints_cloned();
    assert_eq!(explicit_iter.len(), 1);
    assert_eq!(explicit_iter.next_back(), Some(entrypoint.clone()));
    assert_eq!(explicit_iter.len(), 0);
    drop(explicit_iter);
    let (entrypoint_hash, borrowed_tx) = block
        .external_signed_transaction_at(0)
        .expect("explicit signed entrypoint must be directly addressable");
    assert_eq!(entrypoint_hash, entrypoint.hash());
    let TransactionEntrypoint::External(stored_tx) = &block.external_entrypoints_slice()[0] else {
        panic!("expected external signed transaction");
    };
    assert!(std::ptr::eq(borrowed_tx, stored_tx));
    assert!(std::ptr::eq(
        block
            .external_signed_transaction_ref_at(0)
            .expect("explicit transaction reference"),
        stored_tx
    ));
    let wire = block.canonical_wire().expect("canonical block wire");
    let decoded = decode_framed_signed_block(wire.as_framed()).expect("decode framed block");
    assert_eq!(decoded, block);
    assert!(decoded.is_resultless_proposal());
    assert_eq!(
        decoded.external_entrypoints_cloned().collect::<Vec<_>>(),
        vec![entrypoint]
    );
    assert_eq!(decoded.external_transactions().next(), Some(&tx));
}
#[test]
fn block_payload_rejects_pre_release_layout_with_retired_roster_slot() {
    #[derive(norito::codec::Encode)]
    struct PreReleaseBlockPayload {
        header: BlockHeader,
        external_entrypoints: Vec<TransactionEntrypoint>,
        #[norito(required)]
        da_commitments: Option<DaCommitmentBundle>,
        #[norito(required)]
        da_proof_policies: Option<DaProofPolicyBundle>,
        #[norito(required)]
        da_pin_intents: Option<DaPinIntentBundle>,
        #[norito(required)]
        retired_roster_slot: Option<()>,
        #[norito(required)]
        npos_consensus_effects: Option<NposConsensusEffects>,
        #[norito(required)]
        global_beacon_pulse: Option<crate::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
        #[norito(required)]
        execution_context: Option<BlockExecutionContextBundle>,
    }
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 10, 0);
    let pre_release = PreReleaseBlockPayload {
        header,
        external_entrypoints: Vec::new(),
        da_commitments: None,
        da_proof_policies: None,
        da_pin_intents: None,
        // `None` has the exact retired option-slot encoding without reintroducing its type.
        retired_roster_slot: None,
        npos_consensus_effects: None,
        global_beacon_pulse: None,
        execution_context: None,
    };
    let bytes = pre_release.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        BlockPayload::decode_all(&mut cursor).is_err(),
        "the first-release BlockPayload decoder must reject the longer pre-release roster layout"
    );
}
#[test]
fn block_payload_current_layout_roundtrips_empty_required_values() {
    let payload = BlockPayload {
        header: BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 10, 0),
        external_entrypoints: Vec::new(),
        da_commitments: None,
        da_proof_policies: None,
        da_pin_intents: None,
        npos_consensus_effects: None,
        global_beacon_pulse: None,
        execution_context: None,
    };
    let bytes = payload.encode();
    let mut cursor = bytes.as_slice();
    let decoded = BlockPayload::decode_all(&mut cursor).expect("decode current BlockPayload");
    assert_eq!(decoded, payload);
}
#[test]
fn block_result_rejects_wire_omitting_required_axt_policy_snapshot() {
    #[derive(norito::codec::Encode)]
    struct BlockResultWithoutAxtPolicySnapshot {
        outputs: Vec<execution_output::ExecutionOutputV1>,
        output_merkle: MerkleTree<execution_output::ExecutionOutputV1>,
        committed_fragment_count: u64,
        fastpq_transcripts: BTreeMap<Hash, Vec<crate::fastpq::TransferTranscript>>,
        axt_envelopes: Vec<crate::nexus::AxtEnvelopeRecord>,
        axt_transitioned_dataspaces: BTreeSet<iroha_model_base::topology::DataSpaceId>,
    }
    let omitted_snapshot = BlockResultWithoutAxtPolicySnapshot {
        outputs: Vec::new(),
        output_merkle: MerkleTree::default(),
        committed_fragment_count: 0,
        fastpq_transcripts: BTreeMap::new(),
        axt_envelopes: Vec::new(),
        axt_transitioned_dataspaces: BTreeSet::new(),
    };
    let bytes = omitted_snapshot.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        BlockResult::decode_all(&mut cursor).is_err(),
        "the AXT policy snapshot is a required V1 BlockResult wire field"
    );
}
#[test]
fn block_result_native_layout_roundtrips_without_retired_lane_statements() {
    #[derive(norito::codec::Encode)]
    struct NativeBlockResult {
        outputs: Vec<execution_output::ExecutionOutputV1>,
        output_merkle: MerkleTree<execution_output::ExecutionOutputV1>,
        committed_fragment_count: u64,
        fastpq_transcripts: BTreeMap<Hash, Vec<crate::fastpq::TransferTranscript>>,
        axt_envelopes: Vec<crate::nexus::AxtEnvelopeRecord>,
        axt_policy_snapshot: crate::nexus::AxtPolicySnapshot,
        axt_transitioned_dataspaces: BTreeSet<iroha_model_base::topology::DataSpaceId>,
    }
    let native_result = NativeBlockResult {
        outputs: Vec::new(),
        output_merkle: MerkleTree::default(),
        committed_fragment_count: 0,
        fastpq_transcripts: BTreeMap::new(),
        axt_envelopes: Vec::new(),
        axt_policy_snapshot: crate::nexus::AxtPolicySnapshot {
            version: 1,
            entries: Vec::new(),
        },
        axt_transitioned_dataspaces: BTreeSet::new(),
    };
    let bytes = native_result.encode();
    let mut cursor = bytes.as_slice();
    let decoded = BlockResult::decode_all(&mut cursor).expect("current native output layout");
    assert_eq!(decoded.encode(), bytes, "exact native Norito roundtrip");
    assert!(cursor.is_empty());
    let mut json = norito::json::to_value(&decoded).expect("native result JSON");
    json.as_object_mut().unwrap().insert(
        "lane_finality_statements".to_owned(),
        norito::json::Value::Array(Vec::new()),
    );
    assert!(
        norito::json::from_value::<BlockResult>(json).is_err(),
        "removed lane statements are not an optional JSON field"
    );
    let mut retired = bytes.clone();
    retired.extend_from_slice(&Vec::<()>::new().encode());
    assert!(
        BlockResult::decode_all(&mut retired.as_slice()).is_err(),
        "retired trailing lane statements must not be accepted"
    );
}
#[test]
fn block_result_rejects_wire_omitting_required_axt_transition_set() {
    #[derive(norito::codec::Encode)]
    struct BlockResultWithoutAxtTransitionSet {
        outputs: Vec<execution_output::ExecutionOutputV1>,
        output_merkle: MerkleTree<execution_output::ExecutionOutputV1>,
        committed_fragment_count: u64,
        fastpq_transcripts: BTreeMap<Hash, Vec<crate::fastpq::TransferTranscript>>,
        axt_envelopes: Vec<crate::nexus::AxtEnvelopeRecord>,
        axt_policy_snapshot: crate::nexus::AxtPolicySnapshot,
    }
    let omitted_transition_set = BlockResultWithoutAxtTransitionSet {
        outputs: Vec::new(),
        output_merkle: MerkleTree::default(),
        committed_fragment_count: 0,
        fastpq_transcripts: BTreeMap::new(),
        axt_envelopes: Vec::new(),
        axt_policy_snapshot: crate::nexus::AxtPolicySnapshot {
            version: 1,
            entries: Vec::new(),
        },
    };
    let bytes = omitted_transition_set.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        BlockResult::decode_all(&mut cursor).is_err(),
        "the sticky AXT transition set is a required V1 BlockResult wire field"
    );
}
#[test]
#[cfg(feature = "transparent_api")]
fn presigned_with_payload_preserves_payload_and_signature() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let payload = BlockPayload {
        header,
        external_entrypoints: Vec::new(),
        execution_context: None,
        da_commitments: None,
        da_proof_policies: None,
        da_pin_intents: None,
        npos_consensus_effects: None,
        global_beacon_pulse: None,
    };
    let key_pair = checked_bls_keypair();
    let signature = checked_block_signature(0, &key_pair, &payload.header);
    let block = SignedBlock::presigned_with_payload(signature.clone(), payload.clone());
    assert_eq!(block.header(), payload.header);
    assert_eq!(
        block.external_entrypoints_slice(),
        payload.external_entrypoints.as_slice()
    );
    assert!(block.signatures().any(|sig| sig == &signature));
}
#[test]
#[cfg(feature = "transparent_api")]
fn presigned_constructors_normalize_empty_da_bundles() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let key_pair = checked_bls_keypair();
    let signature = checked_block_signature(0, &key_pair, &header);
    let with_da = SignedBlock::presigned_with_da(
        signature.clone(),
        header,
        Vec::new(),
        Some(DaCommitmentBundle::default()),
    );
    assert!(with_da.da_commitments().is_none());
    assert!(with_da.header().da_commitments_hash().is_none());
    let payload = BlockPayload {
        header,
        external_entrypoints: Vec::new(),
        execution_context: None,
        da_commitments: Some(DaCommitmentBundle::default()),
        da_proof_policies: None,
        da_pin_intents: Some(DaPinIntentBundle::default()),
        npos_consensus_effects: None,
        global_beacon_pulse: None,
    };
    let with_payload = SignedBlock::presigned_with_payload(signature, payload);
    assert!(with_payload.da_commitments().is_none());
    assert!(with_payload.header().da_commitments_hash().is_none());
    assert!(with_payload.da_pin_intents().is_none());
    assert!(with_payload.header().da_pin_intents_hash().is_none());
}
#[test]
#[cfg(feature = "transparent_api")]
fn presigned_with_payload_reads_transactions_from_canonical_entrypoints() {
    let key_pair = checked_random_keypair();
    let authority = crate::account::AccountId::new(key_pair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(key_pair.private_key());
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let payload = BlockPayload {
        header,
        external_entrypoints: vec![TransactionEntrypoint::from(tx.clone())],
        execution_context: None,
        da_commitments: None,
        da_proof_policies: None,
        da_pin_intents: None,
        npos_consensus_effects: None,
        global_beacon_pulse: None,
    };
    let signature = checked_block_signature(0, &key_pair, &payload.header);
    let block = SignedBlock::presigned_with_payload(signature, payload);
    assert_eq!(block.external_transactions().next(), Some(&tx));
}
#[cfg(feature = "transparent_api")]
#[test]
fn signed_block_is_not_empty_with_internal_outputs() {
    let mut block = fixture::proposal(0);
    assert!(block.is_empty());
    let time = simple_time(&block, 0);
    fixture::install(&mut block, vec![time], 1).unwrap();
    assert!(!block.is_empty());
    assert_eq!(block.network_entrypoint_count(), 0);
    assert_eq!(block.execution_outputs().len(), 1);
}
#[test]
fn signed_block_is_not_empty_with_da_commitments() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    block.set_da_commitments(Some(sample_da_bundle()));
    assert!(!block.is_empty());
}
#[test]
fn signed_block_is_not_empty_with_da_pin_intents() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let intent = test_pin_intent(
        LaneId::new(7),
        9,
        11,
        StorageTicketId::new([0xAB; 32]),
        ManifestDigest::new([0xCD; 32]),
    );
    let bundle = DaPinIntentBundle::new(vec![intent]);
    block.set_da_pin_intents(Some(bundle));
    assert!(!block.is_empty());
}
#[test]
fn block_header_has_projection_impls() {
    assert_predicate::<BlockHeader>();
    assert_selector::<BlockHeader>();
}
#[cfg(feature = "transparent_api")]
#[test]
fn output_assignment_preserves_complete_proposal_header() {
    let mut block = fixture::proposal(1);
    let proposal = block.clone();
    let header = block.header();
    let proposal_wire_hash = block.canonical_proposal_wire_hash().unwrap();
    assert_eq!(
        proposal_wire_hash,
        Hash::new(proposal.encode_wire().unwrap())
    );
    fixture::install_network(&mut block, vec![Ok(Vec::default())]).unwrap();
    assert_eq!(block.header(), header);
    assert_eq!(block.hash(), proposal.hash());
    assert_eq!(
        block.canonical_proposal_wire_hash().unwrap(),
        proposal_wire_hash
    );
    assert_eq!(
        block
            .canonical_resultless_proposal()
            .expect("valid original proposal"),
        proposal
    );
    assert_ne!(
        block.encode_wire().unwrap(),
        proposal.encode_wire().unwrap()
    );
}
#[test]
fn block_header_new_and_display() {
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    assert_eq!(header.to_string(), format!("{} (№1)", header.hash()));
}
#[test]
fn adversarial_fixture_header_replacement_preserves_body() {
    let keypair = checked_random_keypair();
    let authority = crate::account::AccountId::new(keypair.public_key().clone());
    let transaction = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let mut block = SignedBlock::genesis(vec![transaction], keypair.private_key(), None, None);
    let original = block.header();
    let replacement = BlockHeader::new(
        NonZeroU64::new(2).expect("nonzero height"),
        Some(original.hash()),
        original.merkle_root(),
        1,
        0,
    );
    let transaction_count = block.external_entrypoint_count();
    assert_eq!(block.replace_header_for_testing(replacement), original);
    assert_eq!(block.header(), replacement);
    assert_eq!(block.external_entrypoint_count(), transaction_count);
}
#[test]
fn adversarial_fixture_da_sidecar_replacement_preserves_noncanonical_empty_bundles() {
    let keypair = checked_random_keypair();
    let authority = crate::account::AccountId::new(keypair.public_key().clone());
    let transaction = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let mut block = SignedBlock::genesis(vec![transaction], keypair.private_key(), None, None);
    assert_eq!(
        block.replace_da_sidecars_for_testing(
            Some(DaCommitmentBundle::default()),
            Some(DaPinIntentBundle::default()),
        ),
        (None, None)
    );
    assert!(
        block
            .da_commitments()
            .is_some_and(DaCommitmentBundle::is_empty)
    );
    assert!(
        block
            .da_pin_intents()
            .is_some_and(DaPinIntentBundle::is_empty)
    );
}
#[test]
fn genesis_defaults_confidential_digest() {
    use crate::{account::AccountId, transaction::signed::TransactionBuilder};
    use iroha_model_base::domain::DomainId;
    let keypair = checked_random_keypair();
    let _domain: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let block = SignedBlock::genesis(vec![tx], keypair.private_key(), None, None);
    assert_eq!(
        block.header().confidential_features(),
        Some(crate::confidential::DEFAULT_CONFIDENTIAL_FEATURE_DIGEST)
    );
}
#[test]
fn canonical_wire_prefixes_the_declared_version_and_header() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let versioned = headerless_block_fixture(&block);
    assert!(!versioned.is_empty());
    assert_eq!(versioned[0], SignedBlock::WIRE_VERSION);
    let wire = block.canonical_wire().expect("canonical block wire");
    assert_eq!(wire.payload(), &versioned[1..]);
    assert!(wire.as_framed()[1..].starts_with(MAGIC.as_slice()));
}
#[test]
fn versioned_block_roundtrip_preserves_instruction_order() {
    use crate::{
        account::AccountId,
        parameter::{Parameter, system::SumeragiParameter},
        transaction::{Executable, signed::TransactionBuilder},
    };
    let key_pair = checked_random_keypair();
    let authority = AccountId::new(key_pair.public_key().clone());
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let ordered = vec![
        crate::isi::InstructionBox::from(crate::isi::SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::MaxClockDriftMs(667),
        ))),
        crate::isi::InstructionBox::from(crate::isi::SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::RequireHeightTtl(true),
        ))),
        crate::isi::InstructionBox::from(crate::isi::SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::RequireSequence(true),
        ))),
        crate::isi::InstructionBox::from(crate::isi::SetParameter::new(Parameter::Block(
            crate::parameter::BlockParameter::MaxTransactions(NonZeroU64::new(10_000).unwrap()),
        ))),
    ];
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(ordered.clone())
    .sign(key_pair.private_key());
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: vec![TransactionEntrypoint::from(tx.clone())],
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let wire = block.canonical_wire().expect("canonical block wire");
    let decoded = decode_framed_signed_block(wire.as_framed()).expect("decode framed block");
    let tx = decoded
        .external_transactions()
        .next()
        .expect("block must contain one transaction");
    let Executable::Instructions(actual) = tx.instructions() else {
        panic!("expected instruction executable after block roundtrip");
    };
    let actual = actual.iter().cloned().collect::<Vec<_>>();
    assert_eq!(
        actual, ordered,
        "instruction order must survive signed block roundtrip"
    );
}
#[test]
fn deframe_rejects_payload_exceeding_max_len() {
    use nonzero_ext::nonzero;
    const LENGTH_OFFSET: usize = 1 + 4 + 1 + 1 + 16 + 1;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let mut framed = block
        .canonical_wire()
        .expect("canonical block wire")
        .into_vec();
    let limit = norito::core::max_archive_len();
    let oversized_len = limit
        .checked_add(1)
        .expect("max archive len must be finite for tests");
    // Patch the length field inside the Norito header (after version + magic + major + minor + schema + compression).
    let length_end = LENGTH_OFFSET + core::mem::size_of::<u64>();
    framed[LENGTH_OFFSET..length_end].copy_from_slice(&oversized_len.to_le_bytes());
    let err = borrow_framed_signed_block_payload(&framed)
        .expect_err("payload should exceed enforced Norito length cap");
    match err {
        NoritoFrameError::ArchiveLengthExceeded {
            length,
            limit: enforced,
        } => {
            assert_eq!(length, oversized_len);
            assert_eq!(enforced, limit);
        }
        other => panic!("unexpected error: {other}"),
    }
}
#[test]
fn framed_signed_block_decode_rejects_trailing_bytes() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let mut framed = block
        .canonical_wire()
        .expect("canonical block wire")
        .into_vec();
    framed.push(0_u8);
    let err = decode_framed_signed_block(&framed).expect_err("decode must report trailing bytes");
    assert_eq!(err.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
    assert!(
        matches!(err.into_error(), NoritoFrameError::LengthMismatch),
        "a byte after the declared payload is a length mismatch"
    );
}
#[test]
fn canonical_wire_deframe_roundtrip() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let versioned = headerless_block_fixture(&block);
    let wire = block.canonical_wire().expect("canonical block wire");
    let framed = wire.as_framed();
    assert_eq!(framed.len(), versioned.len() + norito::core::Header::SIZE);
    assert!(framed[1..].starts_with(MAGIC.as_slice()));
    let (_, borrowed) = borrow_framed_signed_block_payload(framed).expect("borrow framed block");
    assert_eq!(borrowed.as_ptr(), framed[1..].as_ptr());
    assert_eq!(wire.payload(), &versioned[1..]);
    let decoded_framed = decode_framed_signed_block(framed).expect("decode framed block");
    assert_eq!(decoded_framed, block);
}
#[test]
fn framed_decode_borrows_payload_from_original_wire() {
    let wire_version = SignedBlock::WIRE_VERSION;
    let mut framed = vec![wire_version];
    write_signed_block_header(&[], &mut framed).expect("write empty canonical frame header");
    let (version, payload) = borrow_framed_signed_block_payload(&framed)
        .expect("canonical frame header must be borrowable");
    assert_eq!(version, wire_version);
    assert_eq!(payload.as_ptr(), framed[1..].as_ptr());
    assert_eq!(payload.len(), framed.len() - 1);
}
#[test]
fn canonical_wire_matches_framed_payload() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let versioned = headerless_block_fixture(&block);
    let canonical = block.canonical_wire().expect("canonical wire");
    let framed = frame_block_payload(versioned[0], &versioned[1..]);
    assert_eq!(canonical.version(), SignedBlock::WIRE_VERSION);
    assert_eq!(canonical.version(), versioned[0]);
    assert_eq!(canonical.as_framed(), framed.as_slice());
    assert_eq!(canonical.payload(), &versioned[1..]);
    let decoded =
        decode_framed_signed_block(canonical.as_framed()).expect("decode canonical framed block");
    assert_eq!(decoded, block);
    let original_frame = canonical.as_framed().as_ptr();
    let owned_frame = canonical.into_vec();
    assert_eq!(owned_frame.as_ptr(), original_frame);
    assert_eq!(owned_frame, framed);
}
#[test]
fn signed_block_decoders_reject_nested_instruction_type_name_alias() {
    let key_pair = checked_random_keypair();
    let authority = crate::account::AccountId::new(key_pair.public_key().clone());
    let transaction = TransactionBuilder::new(
        test_network_id(),
        authority,
        crate::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([crate::prelude::Log::new(
        crate::Level::INFO,
        "canonical block wire".into(),
    )])
    .sign(key_pair.private_key());
    let canonical_transaction = transaction.encode_versioned();
    let alternate_transaction = signed_transaction_with_log_type_name_alias(&canonical_transaction);
    let canonical_entrypoint = TransactionEntrypoint::from(transaction.clone()).encode_versioned();
    let alternate_entrypoint = external_entrypoint_wire(&alternate_transaction);

    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: vec![TransactionEntrypoint::from(transaction)],
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let canonical_block = headerless_block_fixture(&block);
    let alternate_block = block_with_nested_transaction_wire_alias(
        &canonical_block,
        &canonical_entrypoint,
        &alternate_entrypoint,
    );

    let canonical_frame = block.encode_wire().expect("canonical block frame");
    let canonical_decoded = decode_framed_signed_block(&canonical_frame)
        .expect("canonical nested instruction identifiers decode");
    assert_eq!(canonical_decoded, block);
    let structural_error =
        norito::codec::decode_exact_from_slice::<SignedBlock>(&alternate_block[1..])
            .expect_err("the instruction registry rejects removed aliases directly");
    assert!(matches!(structural_error, NoritoFrameError::Message(reason)
        if reason == "unknown instruction wire identifier"));
    let framed = frame_block_payload(alternate_block[0], &alternate_block[1..]);
    let framed_error = decode_framed_signed_block(&framed)
        .expect_err("framed V1 blocks must reject nested instruction aliases");
    assert!(matches!(
        framed_error.into_error(),
        NoritoFrameError::Message(reason)
            if reason == "unknown instruction wire identifier"
    ));
}
/// Rebuild a canonical block payload with the selected confidential-digest hashes
/// written as thirty-two packed bytes instead of the emitted array child.
///
/// `packed` selects by digest field index: 0 is `vk_set_hash`, 4 is `zk_policy_hash`.
fn block_payload_with_packed_digest_hashes(canonical_payload: &[u8], packed: &[usize]) -> Vec<u8> {
    // signatures, payload, result, commit_certificate
    let mut block = split_default_norito_fields(canonical_payload, 4);
    // header, external_entrypoints, da_commitments, da_proof_policies,
    // da_pin_intents, npos_consensus_effects, global_beacon_pulse,
    // execution_context
    let mut payload = split_default_norito_fields(&block[1], 8);
    // height .. confidential_features (9), execution_context_hash,
    // global_beacon_pulse_hash
    let mut header = split_default_norito_fields(&payload[0], 12);
    assert_eq!(header[9][0], 1, "present confidential digest");
    let digest = split_default_norito_fields(&header[9][1..], 1);
    // vk_set_hash, poseidon_params_id, pedersen_params_id, conf_rules_version,
    // zk_policy_hash
    let mut digest = split_default_norito_fields(&digest[0], 5);
    for &index in packed {
        assert_eq!(digest[index][0], 1, "present digest hash");
        let array = split_default_norito_fields(&digest[index][1..], 1);
        // The emitted child: thirty-two one-byte elements, each behind its one-byte
        // compact length prefix.
        assert_eq!(array[0].len(), 32 * (1 + 1));
        let elements = split_default_norito_fields(&array[0], 32);
        let bytes = elements
            .iter()
            .map(|element| {
                assert_eq!(element.len(), 1, "one byte per array element");
                element[0]
            })
            .collect::<Vec<_>>();
        assert_ne!(bytes, array[0], "the emitted array child is not packed");
        let mut option = vec![1];
        option.extend_from_slice(&encode_default_norito_fields(&[bytes]));
        digest[index] = option;
    }
    let mut option = vec![1];
    option.extend_from_slice(&encode_default_norito_fields(&[
        encode_default_norito_fields(&digest),
    ]));
    header[9] = option;
    payload[0] = encode_default_norito_fields(&header);
    block[1] = encode_default_norito_fields(&payload);
    encode_default_norito_fields(&block)
}
#[test]
fn framed_block_rejects_packed_confidential_digest_hash_arrays() {
    use iroha_allocation::{AllocationBudget, ChargedBuffer};
    use norito::core::{DecodeAttemptErrorKind, PreparedDecodeError, SequenceSpan};

    let vk_set_hash = [0x17; 32];
    let zk_policy_hash = [0x25; 32];
    let mut header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    header.set_confidential_features(Some(crate::confidential::ConfidentialFeatureDigest::new(
        Some(vk_set_hash),
        Some(23),
        Some(29),
        Some(31),
        Some(zk_policy_hash),
    )));
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let canonical = block.canonical_wire().expect("canonical wire");
    let canonical_payload = canonical.payload();
    // Rebuilding with nothing packed reproduces the canonical frame, so the surgery
    // below changes the digest hashes and nothing else.
    assert_eq!(
        frame_block_payload(
            canonical.version(),
            &block_payload_with_packed_digest_hashes(canonical_payload, &[])
        ),
        canonical.as_framed()
    );
    assert_eq!(
        decode_framed_signed_block(canonical.as_framed()).expect("canonical frame decodes"),
        block
    );

    let pool = AllocationBudget::new(1 << 20);
    for packed in [&[0][..], &[4][..], &[0, 4][..]] {
        let alternate = block_payload_with_packed_digest_hashes(canonical_payload, packed);
        // Each packed hash drops its thirty-two one-byte element prefixes; an enclosing
        // compact length prefix may shrink with it.
        assert!(canonical_payload.len() - alternate.len() >= 32 * packed.len());
        for hash in [vk_set_hash, zk_policy_hash] {
            assert!(
                alternate.windows(hash.len()).any(|window| window == hash)
                    == packed.contains(&if hash == vk_set_hash { 0 } else { 4 }),
                "only the selected hashes are packed"
            );
        }
        let framed = frame_block_payload(canonical.version(), &alternate);
        assert_ne!(framed, canonical.as_framed());

        // The generic array leaf rejects the packed replacement before the frame
        // decoder's final canonical-encoding comparison.
        let ordinary = decode_framed_signed_block(&framed)
            .expect_err("a packed digest hash is not the canonical block wire");
        assert_eq!(ordinary.kind(), DecodeAttemptErrorKind::Invalid);
        assert!(matches!(
            ordinary.into_error(),
            NoritoFrameError::LengthMismatch
        ));

        // The prepared decoder reaches the same strict leaf decoder.
        let mut source = ChargedBuffer::new(framed.len(), &pool).expect("funded source");
        source.append(&framed).expect("complete source");
        let mut decoder = PreparedSignedBlockSignaturesDecode::new(&pool).expect("controls");
        let prepared = decoder
            .decode(
                &source,
                SequenceSpan {
                    start: 0,
                    end: framed.len(),
                },
                norito::canonical_decode_limits(framed.len()),
            )
            .expect_err("a packed digest hash is not the canonical block wire");
        let PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(prepared)) = prepared
        else {
            panic!("a non-canonical source is a codec refusal, not custody: {prepared}");
        };
        assert_eq!(prepared.kind(), DecodeAttemptErrorKind::Invalid);
        assert!(matches!(
            prepared.into_error(),
            NoritoFrameError::LengthMismatch
        ));
        drop(decoder);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn canonical_wire_roundtrips_genesis_block() {
    use crate::{account::AccountId, transaction::signed::TransactionBuilder};
    use iroha_model_base::domain::DomainId;
    let keypair = checked_random_keypair();
    let _domain: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::empty::<crate::isi::InstructionBox>())
    .sign(keypair.private_key());
    let block = SignedBlock::genesis(vec![tx], keypair.private_key(), None, None);
    let wire = block.canonical_wire().expect("canonical wire");
    assert_eq!(wire.version(), SignedBlock::WIRE_VERSION);
    assert!(wire.as_framed()[1..].starts_with(MAGIC.as_slice()));
    let (_, borrowed) =
        borrow_framed_signed_block_payload(wire.as_framed()).expect("borrow framed genesis");
    assert_eq!(borrowed.as_ptr(), wire.as_framed()[1..].as_ptr());
    assert_eq!(
        wire.payload(),
        norito::codec::encode_adaptive(&block).as_slice()
    );
    let decoded =
        decode_framed_signed_block(wire.as_framed()).expect("decode canonical framed genesis");
    assert_eq!(decoded, block);
}
#[test]
fn framed_decode_counts_canonical_size_before_materialization() {
    let keypair = checked_random_keypair();
    let block = builder::BlockBuilder::new(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0))
        .build_with_signature(0, keypair.private_key());
    let wire = block.encode_wire().unwrap();
    assert_eq!(decode_framed_signed_block(&wire).unwrap(), block);
    // Give the actual layered decoder a complete, valid payload but a
    // smaller claimed original frame. Its canonical output would expand
    // beyond that source: refuse before constructing comparison buffers.
    let error =
        decode_framed_versioned_signed_block_inner(wire[0], &wire[1..], &wire[..wire.len() - 1])
            .unwrap_err();
    assert!(error.to_string().contains("canonical"), "{error}");
    let mut wrong_identity = wire.clone();
    wrong_identity[0] ^= 1;
    assert!(
        decode_framed_versioned_signed_block_inner(wire[0], &wire[1..], &wrong_identity,).is_err(),
        "equal byte count never substitutes for exact canonical equality"
    );
}
#[test]
fn set_da_commitments_updates_header_hash() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    assert!(block.payload.header.da_commitments_hash().is_none());
    block.set_da_commitments(Some(DaCommitmentBundle::default()));
    assert!(block.da_commitments().is_none());
    assert!(block.payload.header.da_commitments_hash().is_none());
    let record = DaCommitmentRecord::new(
        LaneId::new(1),
        2,
        3,
        BlobDigest::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
        DaProofScheme::MerkleSha256,
        Hash::prehashed([0xCC; 32]),
        Some(Hash::prehashed([0xEE; 32])),
        RetentionPolicy::default(),
        StorageTicketId::new([0xFF; 32]),
        Signature::try_from_bytes(&[0x11; 64])
            .expect("checked signed-block DA commitment acknowledgement signature fixture"),
    );
    let bundle = DaCommitmentBundle::new(vec![record]);
    let expected = bundle.merkle_commitment();
    block.set_da_commitments(Some(bundle));
    assert_eq!(block.payload.header.da_commitments_hash(), expected);
    block.set_da_commitments(None);
    assert!(block.payload.header.da_commitments_hash().is_none());
}
#[test]
fn decode_versioned_signed_block_handles_genesis_like_payload() {
    use crate::{account::AccountId, isi::InstructionBox, transaction::signed::TransactionBuilder};
    use iroha_model_base::domain::DomainId;
    let keypair = checked_random_keypair();
    let _domain: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx1 = TransactionBuilder::new_genesis(
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::empty::<InstructionBox>())
    .sign(keypair.private_key());
    let tx2 = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::empty::<InstructionBox>())
    .sign(keypair.private_key());
    let block = SignedBlock::genesis(vec![tx1, tx2], keypair.private_key(), None, None);
    let versioned = headerless_block_fixture(&block);
    let mut manual_payload = Vec::new();
    block.encode_to(&mut manual_payload);
    let mut manual_versioned = Vec::with_capacity(1 + manual_payload.len());
    manual_versioned.push(SignedBlock::WIRE_VERSION);
    manual_versioned.extend_from_slice(&manual_payload);
    assert_eq!(
        manual_versioned, versioned,
        "canonical encode must be stable"
    );
    let wire = block.canonical_wire().expect("canonical genesis wire");
    assert_eq!(wire.payload(), manual_payload.as_slice());
    let decoded = decode_framed_signed_block(wire.as_framed())
        .expect("framed genesis payload must roundtrip");
    assert_eq!(decoded, block);
}
#[test]
fn decode_versioned_signed_block_accepts_framed_payload() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let versioned = headerless_block_fixture(&block);
    let wire = block.canonical_wire().expect("canonical block wire");
    let decoded_from_framed = decode_framed_signed_block(wire.as_framed())
        .expect("decode framed payload via versioned API");
    assert_eq!(decoded_from_framed, block);
    let err =
        decode_framed_signed_block(&versioned).expect_err("headerless payloads must be rejected");
    assert_eq!(err.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
}
fn plain_block_at(height: u64) -> SignedBlock {
    let header = BlockHeader::new(
        NonZeroU64::new(height).expect("non-zero height"),
        None,
        None,
        7,
        1,
    );
    SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    }
}
#[test]
fn borrowed_proposal_wire_comparison_binds_every_original_byte() {
    let block = plain_block_at(2);
    let bytes = block.encode_wire().unwrap();
    assert!(block.matches_resultless_proposal_wire(&bytes).unwrap());
    for index in [0, 1, norito::core::Header::SIZE, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(!block.matches_resultless_proposal_wire(&changed).unwrap());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(!block.matches_resultless_proposal_wire(&trailing).unwrap());
    assert!(
        !block
            .matches_resultless_proposal_wire(&bytes[..bytes.len() - 1])
            .unwrap()
    );
    assert!(
        !plain_block_at(3)
            .matches_resultless_proposal_wire(&bytes)
            .unwrap()
    );
    let certified = block.with_commit_certificate(Some(sample_commit_certificate()));
    assert!(!certified.matches_resultless_proposal_wire(&bytes).unwrap());
}

fn sample_commit_certificate() -> CommitCertificate {
    CommitCertificate::from_untrusted_parts(
        vec![0xA1; 97],
        vec![0xB2; 140],
        vec![0xC3; 480],
        vec![0xD4; 324],
    )
}
#[test]
fn commit_certificate_accessors() {
    let mut block = plain_block_at(2);
    assert!(block.commit_certificate().is_none());
    assert_eq!(
        block.set_commit_certificate(Some(sample_commit_certificate())),
        None
    );
    assert_eq!(
        block.commit_certificate(),
        Some(&sample_commit_certificate())
    );
    assert_eq!(
        block.set_commit_certificate(None),
        Some(sample_commit_certificate())
    );
    assert!(block.commit_certificate().is_none());
    let with = plain_block_at(2).with_commit_certificate(Some(sample_commit_certificate()));
    assert_eq!(
        with.commit_certificate(),
        Some(&sample_commit_certificate())
    );
    assert!(
        with.with_commit_certificate(None)
            .commit_certificate()
            .is_none()
    );
}
#[test]
fn commit_certificate_leaves_block_and_wire_hashes_unchanged() {
    let plain = plain_block_at(2);
    let certified = plain
        .clone()
        .with_commit_certificate(Some(sample_commit_certificate()));
    assert_eq!(certified.hash(), plain.hash());
    assert_eq!(
        certified
            .canonical_proposal_wire_hash()
            .expect("proposal hash"),
        plain.canonical_proposal_wire_hash().expect("proposal hash")
    );
    assert_eq!(
        certified.executed_block_wire_hash().expect("executed hash"),
        plain.executed_block_wire_hash().expect("executed hash")
    );
    // The stored frame does carry the certificate.
    assert_ne!(
        certified.encode_wire().expect("wire"),
        plain.encode_wire().expect("wire")
    );
    assert!(plain.is_resultless_proposal());
    assert!(!certified.is_resultless_proposal());
    let proposal = certified
        .canonical_resultless_proposal()
        .expect("valid original proposal");
    assert!(proposal.commit_certificate().is_none());
    assert!(proposal.is_resultless_proposal());
    assert_eq!(proposal, plain);
    assert_eq!(
        certified
            .clone()
            .into_resultless_proposal()
            .expect("valid original proposal"),
        plain
    );
    let plain_wire = plain.encode_wire().expect("plain canonical wire");
    let identity = (plain_wire.len() as u64, Hash::new(&plain_wire));
    assert_eq!(plain.executed_block_wire_identity().unwrap(), identity);
    assert_eq!(certified.executed_block_wire_identity().unwrap(), identity);
}
#[test]
fn commit_certificate_wire_json_and_versioned_round_trip() {
    for block in [
        plain_block_at(3),
        plain_block_at(3).with_commit_certificate(Some(sample_commit_certificate())),
    ] {
        let wire = block.encode_wire().expect("wire");
        assert_eq!(
            decode_framed_signed_block(&wire).expect("decode wire"),
            block
        );
        assert_eq!(
            decode_framed_signed_block(&wire).expect("decode framed"),
            block
        );
        let canonical = block.canonical_wire().expect("canonical wire");
        assert_eq!(canonical.as_framed(), wire.as_slice());
        let versioned = headerless_block_fixture(&block);
        assert_eq!(versioned[0], canonical.version());
        assert_eq!(&versioned[1..], canonical.payload());
        assert!(
            decode_framed_signed_block(&versioned).is_err(),
            "the headerless payload is not a block wire"
        );
        let json = norito::json::to_json(&block).expect("json");
        let parsed: SignedBlock = norito::json::from_str(&json).expect("json de");
        assert_eq!(parsed, block);
    }
}
#[test]
fn commit_certificate_bytes_are_carried_by_the_stored_frame() {
    let plain = plain_block_at(4);
    let certified = plain
        .clone()
        .with_commit_certificate(Some(sample_commit_certificate()));
    let plain_len = plain.encode_wire().expect("wire").len();
    let certified_len = certified.encode_wire().expect("wire").len();
    assert!(certified_len > plain_len + sample_commit_certificate().payload_len());
    for block in [&plain, &certified] {
        let wire = block.encode_wire().unwrap();
        assert_eq!(
            block.canonical_wire_identity().unwrap(),
            (wire.len() as u64, Hash::new(&wire))
        );
    }
    assert_ne!(
        plain.canonical_wire_identity().unwrap(),
        certified.canonical_wire_identity().unwrap()
    );
    assert_eq!(
        plain.executed_block_wire_identity().unwrap(),
        certified.executed_block_wire_identity().unwrap()
    );
}
#[test]
fn framed_signed_block_uses_v1_layout_flags() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let wire = block.canonical_wire().expect("canonical block wire");
    let framed = wire.as_framed();
    let header_size = norito::core::Header::SIZE;
    let flags = framed[1 + header_size - 1];
    assert_eq!(flags, norito::core::default_encode_flags());
}
#[test]
fn signed_block_da_commitments_roundtrip() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    let bundle = sample_da_bundle();
    assert!(block.da_commitments().is_none());
    block.set_da_commitments(Some(bundle.clone()));
    assert_eq!(block.da_commitments().unwrap(), &bundle);
    assert!(block.header().da_commitments_hash().is_some());
    let wire = block.canonical_wire().expect("canonical block wire");
    let decoded = decode_framed_signed_block(wire.as_framed()).expect("decode framed block");
    assert_eq!(decoded.da_commitments().unwrap(), &bundle);
    block.set_da_commitments(None);
    assert!(block.da_commitments().is_none());
    assert!(block.header().da_commitments_hash().is_none());
}
#[test]
fn set_da_pin_intents_updates_header_hash() {
    use nonzero_ext::nonzero;
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = SignedBlock {
        signatures: crate::block::BlockSignatures::default(),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    };
    assert!(block.payload.header.da_pin_intents_hash().is_none());
    block.set_da_pin_intents(Some(DaPinIntentBundle::default()));
    assert!(block.da_pin_intents().is_none());
    assert!(block.payload.header.da_pin_intents_hash().is_none());
    let intent = test_pin_intent(
        LaneId::new(7),
        9,
        11,
        StorageTicketId::new([0xAB; 32]),
        ManifestDigest::new([0xCD; 32]),
    );
    let bundle = DaPinIntentBundle::new(vec![intent]);
    let expected = bundle
        .merkle_commitment()
        .expect("non-empty bundle must have a tree commitment");
    block.set_da_pin_intents(Some(bundle.clone()));
    assert_eq!(block.da_pin_intents().unwrap(), &bundle);
    assert_eq!(block.header().da_pin_intents_hash(), Some(expected));
    block.set_da_pin_intents(None);
    assert!(block.da_pin_intents().is_none());
    assert!(block.header().da_pin_intents_hash().is_none());
}
#[test]
fn genesis_can_embed_da_commitments() {
    use crate::{account::AccountId, isi::InstructionBox, transaction::signed::TransactionBuilder};
    use iroha_model_base::domain::DomainId;
    let keypair = checked_random_keypair();
    let _domain: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::empty::<InstructionBox>())
    .sign(keypair.private_key());
    let bundle = sample_da_bundle();
    let block = SignedBlock::genesis(
        vec![tx.clone()],
        keypair.private_key(),
        None,
        Some(bundle.clone()),
    );
    assert_eq!(block.da_commitments().unwrap(), &bundle);
    assert!(block.header().da_commitments_hash().is_some());
    let empty = SignedBlock::genesis(
        vec![tx],
        keypair.private_key(),
        None,
        Some(DaCommitmentBundle::default()),
    );
    assert!(empty.da_commitments().is_none());
    assert!(empty.header().da_commitments_hash().is_none());
}
#[test]
fn genesis_can_override_da_proof_policies() {
    use crate::{
        account::AccountId,
        da::commitment::{DaProofPolicy, DaProofPolicyBundle, DaProofScheme},
        isi::InstructionBox,
        transaction::signed::TransactionBuilder,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    let keypair = checked_random_keypair();
    let _domain: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::empty::<InstructionBox>())
    .sign(keypair.private_key());
    let bundle = DaProofPolicyBundle::new(vec![DaProofPolicy {
        lane_id: LaneId::SINGLE,
        dataspace_id: DataSpaceId::UNIVERSAL,
        alias: "custom".to_string(),
        proof_scheme: DaProofScheme::MerkleSha256,
    }]);
    let expected_hash = HashOf::new(&bundle);
    let block = SignedBlock::try_genesis_with_da_proof_policies(
        vec![tx],
        keypair.private_key(),
        None,
        None,
        Some(bundle.clone()),
    )
    .expect("genesis block with explicit DA proof policies should be signed");
    assert_eq!(block.da_proof_policies(), Some(&bundle));
    assert_eq!(block.header().da_proof_policies_hash(), Some(expected_hash));
}
#[test]
fn try_genesis_with_da_proof_policies_signs_and_rejects_empty() {
    use crate::{
        account::AccountId,
        da::commitment::{DaProofPolicy, DaProofPolicyBundle, DaProofScheme},
        isi::InstructionBox,
        transaction::signed::TransactionBuilder,
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    let keypair = KeyPair::try_from_seed(vec![0x53; 32], iroha_crypto::Algorithm::Ed25519)
        .expect("fixture seed derives Ed25519 keypair");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(core::iter::empty::<InstructionBox>())
    .sign(keypair.private_key());
    let bundle = DaProofPolicyBundle::new(vec![DaProofPolicy {
        lane_id: LaneId::SINGLE,
        dataspace_id: DataSpaceId::UNIVERSAL,
        alias: "checked".to_string(),
        proof_scheme: DaProofScheme::MerkleSha256,
    }]);
    let block = SignedBlock::try_genesis_with_da_proof_policies(
        vec![tx],
        keypair.private_key(),
        None,
        None,
        Some(bundle),
    )
    .expect("checked genesis signing should succeed");
    assert!(block.is_resultless_proposal());
    assert_eq!(block.committed_fragment_count(), None);
    assert!(block.execution_outputs().is_empty());
    let signature = block.signatures().next().expect("genesis signature");
    signature
        .signature()
        .verify_hash(keypair.public_key(), block.hash())
        .expect("checked genesis signature verifies");
    let err = SignedBlock::try_genesis(Vec::new(), keypair.private_key(), None, None)
        .expect_err("empty genesis transaction set must fail");
    assert!(
        matches!(err, iroha_crypto::Error::Signing(ref message) if message.contains("Genesis block must have transactions")),
        "unexpected error: {err}"
    );
}
#[cfg(feature = "transparent_api")]
#[test]
fn executed_block_wire_identity_is_the_certificate_free_wire() {
    let mut executed = fixture::proposal(0);
    fixture::install(&mut executed, vec![], 0).unwrap();
    for block in [fixture::proposal(0), executed] {
        let wire = block.encode_wire().expect("wire");
        let expected = (u64::try_from(wire.len()).unwrap(), Hash::new(&wire));
        assert_eq!(block.executed_block_wire_identity().unwrap(), expected);
        let certified =
            block
                .clone()
                .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                    vec![1],
                    vec![2],
                    vec![3],
                    vec![4],
                )));
        assert_eq!(certified.executed_block_wire_identity().unwrap(), expected);
        assert_eq!(certified.executed_block_wire_hash().unwrap(), expected.1);
    }
}
#[cfg(feature = "transparent_api")]
#[test]
fn signed_block_has_results_only_after_assignment() {
    let mut block = fixture::proposal(0);
    let proposal = block.clone();
    let proposal_hash = block.canonical_proposal_wire_hash().unwrap();
    assert_eq!(proposal_hash, Hash::new(proposal.encode_wire().unwrap()));
    assert!(!block.has_results());
    assert!(block.is_resultless_proposal());
    assert_eq!(block.executed_block_wire_hash().unwrap(), proposal_hash);
    fixture::install(&mut block, vec![], 0).unwrap();
    assert!(block.has_results());
    assert!(!block.is_resultless_proposal());
    assert_eq!(
        block
            .canonical_resultless_proposal()
            .expect("valid original proposal"),
        proposal
    );
    assert_eq!(
        block
            .clone()
            .into_resultless_proposal()
            .expect("valid original proposal"),
        proposal
    );
    assert_eq!(block.canonical_proposal_wire_hash().unwrap(), proposal_hash);
    let executed = block.executed_block_wire_hash().unwrap();
    fixture::install(&mut block, vec![], 1).unwrap();
    assert_ne!(block.executed_block_wire_hash().unwrap(), executed);
    assert_eq!(block.canonical_proposal_wire_hash().unwrap(), proposal_hash);
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_records_fastpq_transcripts() {
    use crate::{
        account::AccountId,
        asset::id::AssetDefinitionId,
        fastpq::{TransferDeltaTranscript, TransferTranscript},
    };
    use iroha_crypto::Hash;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Quantity;
    use std::{collections::BTreeMap, num::NonZeroU64};
    fn fixture_account(_domain: &DomainId) -> AccountId {
        let keypair = checked_random_keypair();
        AccountId::new(keypair.public_key().clone())
    }
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let keypair = checked_random_keypair();
    let signature = checked_block_signature(0, &keypair, &header);
    let mut block = SignedBlock::presigned(signature, header, Vec::new());
    let domain: DomainId = DomainId::try_new("test", "universal").expect("domain id");
    let from = fixture_account(&domain);
    let to = fixture_account(&domain);
    let asset: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("test", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let delta = TransferDeltaTranscript {
        from_account: from,
        to_account: to,
        asset_definition: asset,
        amount: Quantity::zero(),
        from_balance_before: Quantity::zero(),
        from_balance_after: Quantity::zero(),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::zero(),
        from_smt_witness: crate::fastpq::TransferSmtWitness::default(),
        to_smt_witness: crate::fastpq::TransferSmtWitness::default(),
    };
    let batch_hash = Hash::prehashed([0xAA; Hash::LENGTH]);
    let transcript = TransferTranscript {
        batch_hash,
        deltas: vec![delta],
        authority_digest: Hash::prehashed([0x11; Hash::LENGTH]),
        poseidon_preimage_digest: None,
    };
    let mut transcripts = BTreeMap::new();
    transcripts.insert(batch_hash, vec![transcript]);
    block
        .set_execution_outputs(
            Vec::new(),
            0,
            transcripts.clone(),
            Vec::new(),
            crate::nexus::AxtPolicySnapshot::default(),
            BTreeSet::new(),
            &fixture::limits(),
        )
        .expect("empty block has no external hash prefix to validate");
    assert_eq!(block.fastpq_transcripts(), &transcripts);
}
#[cfg(feature = "transparent_api")]
#[test]
fn full_output_metadata_is_attached_atomically() {
    let mut block = fixture::proposal(1);
    let header = block.header();
    let proposal = block.canonical_proposal_wire_hash().unwrap();
    block
        .set_execution_outputs(
            vec![network(0, Ok(Vec::default()))],
            3,
            BTreeMap::default(),
            vec![],
            crate::nexus::AxtPolicySnapshot::default(),
            BTreeSet::from([iroha_model_base::topology::DataSpaceId::new(9)]),
            &fixture::limits(),
        )
        .unwrap();
    assert_eq!(block.axt_transitioned_dataspaces().unwrap().len(), 1);
    assert_eq!(block.committed_fragment_count(), Some(3));
    assert_eq!(block.header(), header);
    assert_eq!(block.canonical_proposal_wire_hash().unwrap(), proposal);
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_records_committed_fragment_count() {
    let mut block = fixture::proposal(2);
    let rows = vec![
        network(0, Ok(Vec::default())),
        network(
            1,
            Err(
                crate::transaction::error::TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted("fixture".into()),
                ),
            ),
        ),
    ];
    fixture::install(&mut block, rows.clone(), 3).unwrap();
    assert_eq!(block.committed_fragment_count(), Some(3));
    assert_eq!(block.execution_outputs(), rows);
    fixture::install(&mut block, rows, 7).unwrap();
    assert_eq!(block.committed_fragment_count(), Some(7));
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_rejects_noncanonical_snapshot_without_mutation() {
    use std::num::NonZeroU64;
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let keypair = checked_random_keypair();
    let signature = checked_block_signature(0, &keypair, &header);
    let mut block = SignedBlock::presigned(signature, header, Vec::new());
    let binding = crate::nexus::AxtPolicyBinding {
        dsid: iroha_model_base::topology::DataSpaceId::new(1),
        policy: crate::nexus::AxtPolicyEntry {
            manifest_root: [0x42; 32],
            target_lane: iroha_model_base::topology::LaneId::new(0),
            active_handle_era: 1,
            next_handle_counter: 1,
            current_slot: 1,
        },
    };
    let entries = vec![binding, binding];
    let snapshot = crate::nexus::AxtPolicySnapshot {
        version: crate::nexus::AxtPolicySnapshot::compute_version(&entries),
        entries,
    };
    let original_wire = block.encode_wire().unwrap();
    let error = block
        .set_execution_outputs(
            Vec::new(),
            0,
            BTreeMap::new(),
            Vec::new(),
            snapshot,
            BTreeSet::new(),
            &fixture::limits(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        SetExecutionOutputsError::InvalidAxtPolicySnapshot(
            crate::nexus::AxtPolicySnapshotValidationError::DuplicateDataspaceId(_)
        )
    ));
    assert!(!block.has_results());
    assert_eq!(block.encode_wire().unwrap(), original_wire);
}
#[cfg(feature = "transparent_api")]
#[test]
#[allow(clippy::too_many_lines)]
fn block_proofs_include_fastpq_transcripts() {
    use crate::{
        account::AccountId,
        asset::id::AssetDefinitionId,
        fastpq::{TransferDeltaTranscript, TransferTranscript},
        transaction::signed::TransactionBuilder,
    };
    use iroha_crypto::Hash;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Quantity;
    use std::{collections::BTreeMap, num::NonZeroU64};
    let keypair = checked_random_keypair();
    let _authority_domain: DomainId =
        DomainId::try_new("chain", "universal").expect("chain domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new_genesis(
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let entry_hash = tx.hash_as_entrypoint();
    let header = BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        [entry_hash].into_iter().collect::<MerkleTree<_>>().root(),
        0,
        0,
    );
    let signature = checked_block_signature(0, &keypair, &header);
    let mut block = SignedBlock::presigned(signature, header, vec![tx]);
    let asset: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("chain", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let delta = TransferDeltaTranscript {
        from_account: authority.clone(),
        to_account: authority,
        asset_definition: asset,
        amount: Quantity::zero(),
        from_balance_before: Quantity::zero(),
        from_balance_after: Quantity::zero(),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::zero(),
        from_smt_witness: crate::fastpq::TransferSmtWitness::default(),
        to_smt_witness: crate::fastpq::TransferSmtWitness::default(),
    };
    let batch_hash = Hash::prehashed([0xBB; Hash::LENGTH]);
    let transcript = TransferTranscript {
        batch_hash,
        deltas: vec![delta],
        authority_digest: Hash::prehashed([0x22; Hash::LENGTH]),
        poseidon_preimage_digest: None,
    };
    let mut transcripts = BTreeMap::new();
    transcripts.insert(batch_hash, vec![transcript]);
    let binding = crate::nexus::AxtBinding::new([0x11; 32]);
    let axt_envelope = crate::nexus::AxtEnvelopeRecord {
        binding,
        lane: iroha_model_base::topology::LaneId::new(2),
        descriptor: crate::nexus::AxtDescriptor {
            dsids: vec![iroha_model_base::topology::DataSpaceId::new(9)],
            touches: Vec::new(),
        },
        touches: Vec::new(),
        proofs: Vec::new(),
        spends: Vec::new(),
        commit_height: 1,
    };
    let dsid = iroha_model_base::topology::DataSpaceId::new(9);
    let policy_snapshot = crate::nexus::AxtPolicySnapshot {
        version: 0,
        entries: vec![crate::nexus::AxtPolicyBinding {
            dsid,
            policy: crate::nexus::AxtPolicyEntry {
                manifest_root: [0xAA; 32],
                target_lane: iroha_model_base::topology::LaneId::new(2),
                active_handle_era: 10,
                next_handle_counter: 5,
                current_slot: 7,
            },
        }],
    }
    .with_computed_version()
    .expect("test policy snapshot is canonical");
    let expected_policy_snapshot = policy_snapshot.clone();
    block
        .set_execution_outputs(
            vec![network(0, Ok(Vec::default()))],
            1,
            transcripts.clone(),
            vec![axt_envelope.clone()],
            policy_snapshot,
            BTreeSet::new(),
            &fixture::limits(),
        )
        .expect("entrypoint hash should match payload");
    let proofs = block
        .network_execution_proof(&entry_hash)
        .expect("proofs present");
    assert_eq!(proofs.fastpq_transcripts, transcripts);
    let bytes = norito::to_bytes(&block).expect("encode block");
    let decoded: SignedBlock = norito::decode_from_bytes(&bytes).expect("decode block");
    assert_eq!(
        decoded.axt_envelopes(),
        Some(std::slice::from_ref(&axt_envelope))
    );
    assert_eq!(
        decoded.axt_policy_snapshot(),
        Some(&expected_policy_snapshot)
    );
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_updates_merkle_roots_with_time_triggers() {
    let mut block = fixture::proposal(1);
    let header = block.header();
    let rows = vec![network(0, Ok(Vec::default())), simple_time(&block, 0)];
    let expected: MerkleTree<execution_output::ExecutionOutputV1> =
        rows.iter().map(HashOf::new).collect();
    fixture::install(&mut block, rows.clone(), 2).unwrap();
    assert_eq!(block.header(), header);
    assert_eq!(block.execution_outputs(), rows);
    assert_eq!(block.output_merkle_commitment(), expected.commitment());
    assert_eq!(
        block
            .network_input_merkle_commitment()
            .unwrap()
            .leaf_count()
            .get(),
        1
    );
    assert_eq!(
        block.output_merkle_commitment().unwrap().leaf_count().get(),
        2
    );
    block.validate_output_merkle_cache().unwrap();
}
#[cfg(feature = "transparent_api")]
#[test]
fn network_inputs_are_distinct_from_internal_outputs() {
    let mut block = fixture::proposal(1);
    let entry = block.network_entrypoint_at(0).unwrap().clone();
    let time = simple_time(&block, 0);
    fixture::install(
        &mut block,
        vec![network(0, Ok(Vec::default())), time.clone()],
        2,
    )
    .unwrap();
    assert_eq!(block.network_entrypoint_at(0), Some(&entry));
    assert_eq!(block.network_entrypoint_at(1), None);
    assert_eq!(block.execution_outputs().get(1), Some(&time));
    assert_eq!(block.network_output_at(0).unwrap().1.input_index, 0);
    assert!(block.network_output_at(1).is_none());
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_rejects_too_short_external_hash_prefix() {
    let mut block = fixture::proposal(2);
    let before = block.encode_wire().unwrap();
    assert!(fixture::install(&mut block, vec![network(0, Ok(Vec::default()))], 1).is_err());
    assert_eq!(block.encode_wire().unwrap(), before);
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_rejects_result_count_mismatch() {
    for rows in [
        vec![],
        vec![
            network(0, Ok(Vec::default())),
            network(1, Ok(Vec::default())),
        ],
    ] {
        let mut block = fixture::proposal(1);
        let before = block.encode_wire().unwrap();
        assert!(fixture::install(&mut block, rows, 0).is_err());
        assert_eq!(block.encode_wire().unwrap(), before);
    }
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_rejects_external_hash_mismatch() {
    let mut block = fixture::proposal(1);
    let before = block.encode_wire().unwrap();
    assert!(fixture::install(&mut block, vec![network(1, Ok(Vec::default()))], 1).is_err());
    assert_eq!(block.encode_wire().unwrap(), before);
}
#[cfg(feature = "transparent_api")]
#[test]
fn set_transaction_results_rejects_existing_header_merkle_mismatch() {
    let mut block = fixture::proposal(1);
    block.payload.header.merkle_root = Some(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign input root",
    )));
    let before = block.encode_wire().unwrap();
    assert!(matches!(
        fixture::install_network(&mut block, vec![Ok(Vec::default())]),
        Err(SetExecutionOutputsError::InvalidProposal(_))
    ));
    assert_eq!(block.encode_wire().unwrap(), before);
}
#[cfg(feature = "transparent_api")]
#[test]
fn proofs_for_entry_hash_matches_merkle_roots() {
    let mut block = fixture::proposal(2);
    fixture::install_network(&mut block, vec![Ok(Vec::default()), Ok(Vec::default())]).unwrap();
    for (index, hash) in block.network_input_hashes().enumerate() {
        let expected_index = u32::try_from(index).expect("two-entry fixture index fits u32");
        let proof = block.network_execution_proof(&hash).unwrap();
        assert_eq!(proof.entry_proof.proof().leaf_index(), expected_index);
        assert!(
            proof
                .entry_proof
                .verify(&block.network_input_merkle_commitment().unwrap())
        );
        assert!(
            proof
                .output_proof
                .verify(&block.output_merkle_commitment().unwrap())
        );
        assert!(
            matches!(proof.output_proof.output(), execution_output::ExecutionOutputV1::Network(row) if row.input_index == expected_index)
        );
    }
}
#[cfg(feature = "transparent_api")]
#[test]
fn proofs_for_external_entry_with_time_trigger_use_full_executed_root() {
    let mut block = fixture::proposal(1);
    let rows = vec![network(0, Ok(Vec::default())), simple_time(&block, 0)];
    fixture::install(&mut block, rows, 2).unwrap();
    let hash = block.network_input_hashes().next().unwrap();
    let proof = block.network_execution_proof(&hash).unwrap();
    assert_eq!(proof.entry_commitment.leaf_count().get(), 1);
    assert_eq!(proof.output_commitment.leaf_count().get(), 2);
    assert!(proof.entry_proof.verify(&proof.entry_commitment));
    assert!(proof.output_proof.verify(&proof.output_commitment));
}
#[cfg(feature = "transparent_api")]
#[test]
fn time_invocation_has_only_an_output_proof() {
    let mut block = fixture::proposal(0);
    let time = simple_time(&block, 0);
    fixture::install(&mut block, vec![time.clone()], 1).unwrap();
    assert!(block.network_input_merkle_commitment().is_none());
    assert!(block.network_input_proof(0).is_none());
    assert!(block.output_proof(0).unwrap().verify(
        &HashOf::new(&time),
        &block.output_merkle_commitment().unwrap()
    ));
    assert!(block.output_proof(1).is_none());
}
#[cfg(feature = "transparent_api")]
#[test]
fn proofs_for_entry_hash_missing_returns_none() {
    let mut block = fixture::proposal(1);
    fixture::install_network(&mut block, vec![Ok(Vec::default())]).unwrap();
    assert!(
        block
            .network_execution_proof(&HashOf::from_untyped_unchecked(Hash::new(b"missing")))
            .is_none()
    );
}
#[test]
fn canonical_wire_and_deframe_preserve_layout_flags() {
    use crate::{account::AccountId, transaction::signed::TransactionBuilder};
    use iroha_model_base::domain::DomainId;
    let keypair = checked_random_keypair();
    let _domain_id: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let transaction = TransactionBuilder::new_genesis(
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let block = SignedBlock::genesis(vec![transaction], keypair.private_key(), None, None);
    let wire = block.canonical_wire().expect("canonical wire");
    let header_index = 1 + norito::core::Header::SIZE - 1;
    let header_flags = wire.as_framed()[header_index];
    assert_eq!(header_flags, norito::core::default_encode_flags());
    let versioned = headerless_block_fixture(&block);
    assert_eq!(wire.payload(), &versioned[1..]);
    super::decode_framed_signed_block(wire.as_framed()).expect("decode canonical wire");
    let err = super::decode_framed_signed_block(&versioned)
        .expect_err("headerless payloads must be rejected");
    assert_eq!(err.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
}
#[test]
fn framing_derives_flags_instead_of_reusing_tls_state() {
    use crate::{account::AccountId, transaction::signed::TransactionBuilder};
    use iroha_model_base::domain::DomainId;
    let keypair = checked_random_keypair();
    let _domain_id: DomainId = DomainId::try_new("genesis", "universal").expect("domain id");
    let authority = AccountId::new(keypair.public_key().clone());
    let transaction = TransactionBuilder::new_genesis(
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let block = SignedBlock::genesis(vec![transaction], keypair.private_key(), None, None);
    let versioned = headerless_block_fixture(&block);
    let header_index = 1 + norito::core::Header::SIZE - 1;
    let expected_flags = norito::core::default_encode_flags();
    let wire = block.canonical_wire().expect("canonical block wire");
    let framed = wire.as_framed();
    assert_eq!(
        framed[header_index], expected_flags,
        "Framing must use the canonical fixed layout flags",
    );
    assert_eq!(wire.payload(), &versioned[1..]);
}
#[test]
fn decode_field_respects_length_and_consumes_payload() {
    // Prepare bare Norito payload representing a String value.
    let value = String::from("field-value");
    let mut payload = Vec::new();
    value.encode_to(&mut payload);
    // Prefix the payload with its little-endian length header.
    let mut input = Vec::with_capacity(8 + payload.len());
    input.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    input.extend_from_slice(&payload);
    let (decoded, rest) = super::decode_field::<String>(&input).expect("decode field");
    assert_eq!(decoded, value);
    assert!(rest.is_empty());
}
#[cfg(feature = "transparent_api")]
fn sealed_alias_block_builder() -> crate::block::builder::BlockBuilder {
    crate::block::builder::BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    ))
}
#[cfg(feature = "transparent_api")]
#[test]
fn sealed_reveal_batch_outcome_aliases_are_unique_and_single_assignment() {
    use crate::{
        asset::{AssetDefinitionId, AssetId},
        events::data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferOutcome},
        transaction::{
            FeePaymentIntent,
            signed::{SealedTransactionReveal, TransactionBuilder},
        },
    };
    use iroha_primitives::numeric::Quantity;

    let keypair = checked_random_keypair();
    let authority = crate::account::AccountId::new(keypair.public_key().clone());
    let signed = TransactionBuilder::new_genesis(
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let inner_hash = signed.hash_as_entrypoint();
    let first_reveal = SealedTransactionReveal::new(
        Hash::new(b"sealed batch outcome alias one"),
        signed.clone(),
        [0x41; 32],
    );
    let first_entrypoint = TransactionEntrypoint::SealedReveal(first_reveal.clone());
    let first_outer_hash = first_entrypoint.hash();
    assert_ne!(first_outer_hash, inner_hash);
    assert_eq!(first_entrypoint.execution_call_hash(), inner_hash);
    let outcome = AssetBatchTransferOutcome {
        leg_index: 0,
        leg_id: "sealed-alias-leg".to_owned(),
        asset: AssetId::new(
            AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("sealed", "universal")
                    .expect("domain id"),
                "coin".parse().expect("asset name"),
            ),
            authority.clone(),
        ),
        destination: authority,
        amount: Quantity::from(1_u32),
        status: AssetBatchTransferLegStatus::Applied,
    };
    let mut builder = sealed_alias_block_builder();
    builder.push_sealed_transaction_reveal(first_reveal.clone());
    let mut positive = builder.build(crate::block::BlockSignatures::default());
    let mut result = crate::transaction::TransactionResult::new(Ok(DataTriggerSequence::default()));
    result.set_batch_transfer_outcomes(vec![outcome.clone()]);
    fixture::install(&mut positive, vec![network(0, result)], 1).unwrap();
    assert_eq!(
        positive.batch_transfer_outcomes_for(&first_outer_hash),
        std::slice::from_ref(&outcome)
    );
    assert!(
        positive.batch_transfer_outcomes_for(&inner_hash).is_empty(),
        "outer input lookup is not an implicit signed alias"
    );
    let before = positive.encode_wire().unwrap();
    assert!(
        fixture::install(
            &mut positive,
            vec![
                network(0, Ok(Vec::default())),
                network(0, Ok(Vec::default()))
            ],
            1
        )
        .is_err()
    );
    assert_eq!(positive.encode_wire().unwrap(), before);
    let second_reveal = SealedTransactionReveal::new(Hash::new(b"second"), signed, [0x42; 32]);
    let mut builder = sealed_alias_block_builder();
    builder.push_sealed_transaction_reveal(first_reveal);
    builder.push_sealed_transaction_reveal(second_reveal);
    let mut ambiguous = builder.build(crate::block::BlockSignatures::default());
    assert!(
        fixture::install(
            &mut ambiguous,
            vec![
                network(0, Ok(Vec::default())),
                network(1, Ok(Vec::default()))
            ],
            2
        )
        .is_err()
    );
}
#[cfg(feature = "transparent_api")]
#[test]
fn full_output_replacement_rebuilds_exact_cache() {
    let mut block = fixture::proposal(2);
    let rows = vec![
        network(0, Ok(Vec::default())),
        network(
            1,
            Err(
                crate::transaction::error::TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted("no".into()),
                ),
            ),
        ),
    ];
    fixture::install(&mut block, rows.clone(), 1).unwrap();
    let first = block.output_merkle_commitment();
    let header = block.header();
    let replacement = vec![rows[0].clone(), network(1, Ok(Vec::default()))];
    let expected: MerkleTree<execution_output::ExecutionOutputV1> =
        replacement.iter().map(HashOf::new).collect();
    fixture::install(&mut block, replacement, 2).unwrap();
    assert_ne!(block.output_merkle_commitment(), first);
    assert_eq!(block.output_merkle_commitment(), expected.commitment());
    assert_eq!(block.header(), header);
    block.validate_output_merkle_cache().unwrap();
}

#[test]
fn canonical_block_and_journal_share_strict_header_and_version_rejections() {
    use crate::sumeragi::finality::{
        NativeFinalityArtifact, NativeFinalityDecodeError, NativeFinalityLimits,
    };
    let mut block = plain_block_at(1);
    let key = checked_random_keypair();
    block
        .signatures
        .try_insert(checked_block_signature(0, &key, &block.header()))
        .unwrap();
    let wire = block.encode_wire().unwrap();
    let limits = NativeFinalityLimits {
        block_bytes: 1024 * 1024,
        journal_bytes: 1024 * 1024,
        block_count: 1,
        allocated_bytes: 64 * 1024 * 1024,
    };
    assert_eq!(decode_framed_signed_block(&wire).unwrap(), block);
    assert_eq!(
        NativeFinalityArtifact {
            block_wire: wire.clone()
        }
        .decode_block(limits)
        .unwrap(),
        block
    );
    let mut malformed = Vec::new();
    for offset in [0, 1, 5, 6, 7, 23, 24, 32, norito::core::Header::SIZE] {
        let mut changed = wire.clone();
        changed[offset] ^= 0x80;
        malformed.push(changed);
    }
    let mut oversized = wire.clone();
    oversized[24..32].copy_from_slice(
        &norito::core::max_archive_len()
            .saturating_add(1)
            .to_le_bytes(),
    );
    malformed.push(oversized);
    let mut trailing = wire.clone();
    trailing.push(0);
    malformed.push(trailing);
    malformed.extend([headerless_block_fixture(&block), Vec::new(), vec![1]]);
    for bytes in malformed {
        let direct = norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || decode_framed_signed_block(&bytes),
        )
        .unwrap_err();
        assert_eq!(
            direct.kind(),
            norito::core::DecodeAttemptErrorKind::Invalid,
            "{direct:?}"
        );
        let journal = NativeFinalityArtifact {
            block_wire: bytes.clone(),
        }
        .decode_block(limits)
        .unwrap_err();
        match journal {
            NativeFinalityDecodeError::Malformed(original) => {
                assert_eq!(original.kind(), direct.kind());
                assert_eq!(original.to_string(), direct.to_string());
            }
            NativeFinalityDecodeError::Invalid(_) if bytes.is_empty() => {}
            other => panic!("journal changed canonical invalidity: {other:?}"),
        }
    }
}

#[test]
fn canonical_block_refusal_survives_outer_unwind_and_retries_identical_frame() {
    let mut block = plain_block_at(1);
    let key = checked_random_keypair();
    block
        .signatures
        .try_insert(checked_block_signature(0, &key, &block.header()))
        .unwrap();
    let wire = block.encode_wire().unwrap();
    let saved = std::cell::RefCell::new(None);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            norito::core::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || {
                    *saved.borrow_mut() = Some(decode_framed_signed_block(&wire).unwrap_err());
                    panic!("retire original decoder scope");
                },
            )
        }))
        .is_err()
    );
    let original = saved.into_inner().unwrap();
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(matches!(
        original.into_error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
    ));
    let retried = decode_framed_signed_block(&wire).unwrap();
    assert_eq!(retried, block);
    assert_eq!(retried.encode_wire().unwrap(), wire);
}
