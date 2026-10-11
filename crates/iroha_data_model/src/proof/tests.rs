//! Proof schema, bounds, and canonical codec regressions.

use super::*;
use iroha_crypto::{Hash, HashOf, LaneCommitmentId, MerkleProof};
fn encode_payload_with_flags(value: &impl norito::NoritoSerialize, flags: u8) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(flags);
    let mut payload = Vec::new();
    let mut encoder = ncore::Encoder::for_buffer(&mut payload);
    value
        .serialize(&mut encoder)
        .expect("encode payload with explicit layout flags");
    payload
}
fn write_test_field<T: norito::NoritoSerialize>(encoded: &mut Vec<u8>, value: &T) {
    let mut field = Vec::new();
    ncore::serialize_to_buffer(value, &mut field).expect("serialize test field");
    ncore::write_len_header_to_vec(encoded, field.len() as u64);
    encoded.extend_from_slice(&field);
}
fn proof_bytes_hash(bytes: &[u8]) -> [u8; 32] {
    iroha_crypto::Hash::new(bytes).into()
}

fn hash_json(hash: &[u8; 32]) -> String {
    let body = hash
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{body}]")
}
fn lane_privacy_with_path(
    leaf_index: u32,
    audit_path: Vec<Option<HashOf<[u8; 32]>>>,
) -> crate::nexus::LanePrivacyProof {
    crate::nexus::LanePrivacyProof {
        commitment_id: LaneCommitmentId::new(5),
        witness: crate::nexus::LanePrivacyWitness::Merkle(crate::nexus::LanePrivacyMerkleWitness {
            leaf: [0xAA; 32],
            proof: MerkleProof::from_audit_path(leaf_index, audit_path),
        }),
    }
}
fn canonical_lane_sibling(seed: u8) -> HashOf<[u8; 32]> {
    HashOf::from_untyped_unchecked(Hash::prehashed([seed; Hash::LENGTH]))
}
fn bounded_attachment_list(attachments: Vec<ProofAttachment>) -> ProofAttachmentList {
    ProofAttachmentList::try_from(attachments).expect("valid bounded attachment-list fixture")
}
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[norito(reuse_archived, decode_from_slice)]
struct ReferenceProofAttachmentList(Vec<ProofAttachment>);
#[test]
fn proof_attachment_list_roundtrip_bare() {
    let mut attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    attachment.lane_privacy = Some(crate::nexus::LanePrivacyProof {
        commitment_id: LaneCommitmentId::new(5),
        witness: crate::nexus::LanePrivacyWitness::Merkle(crate::nexus::LanePrivacyMerkleWitness {
            leaf: [0xAA; 32],
            proof: iroha_crypto::MerkleProof::from_audit_path(
                0,
                vec![Some(
                    iroha_crypto::HashOf::<[u8; 32]>::from_untyped_unchecked(
                        iroha_crypto::Hash::prehashed([0xBB; 32]),
                    ),
                )],
            ),
        }),
    });
    let list = bounded_attachment_list(vec![attachment]);
    let bytes = norito::encode_canonical(&list).expect("encode canonical lane attachment list");
    assert_eq!(
        ncore::encoded_frame_len(&list).expect("count canonical lane attachment list"),
        bytes.len(),
        "valid all-Some lane witnesses must expose exact canonical frame sizing"
    );
    let decoded = norito::decode_canonical::<ProofAttachmentList>(&bytes)
        .expect("decode canonical lane attachment list");
    assert_eq!(decoded, list);
}
#[test]
fn proof_attachment_list_custom_wire_matches_independent_derived_tuple_codec() {
    let first = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    let second = ProofAttachment::new_ref(
        "stark/fri".into(),
        ProofBox::new("stark/fri".into(), vec![4, 5, 6, 7]),
        VerifyingKeyId::new("stark/fri", "vk_2"),
    );
    let list = bounded_attachment_list(vec![first.clone(), second.clone()]);
    let reference = ReferenceProofAttachmentList(vec![first, second]);
    let _canonical_flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut custom_bare = Vec::new();
    ncore::serialize_to_buffer(&list, &mut custom_bare)
        .expect("serialize custom bounded list payload");
    let mut reference_bare = Vec::new();
    ncore::serialize_to_buffer(&reference, &mut reference_bare)
        .expect("serialize independently derived tuple payload");
    assert_eq!(
        custom_bare, reference_bare,
        "custom first-release codec must preserve the original one-field tuple wire"
    );
    let (decoded_reference, reference_used) =
        <ReferenceProofAttachmentList as ncore::DecodeFromSlice>::decode_from_slice(&custom_bare)
            .expect("derived reference decoder accepts custom payload");
    assert_eq!(reference_used, custom_bare.len());
    assert_eq!(decoded_reference, reference);
    let (decoded_custom, custom_used) =
        <ProofAttachmentList as ncore::DecodeFromSlice>::decode_from_slice(&reference_bare)
            .expect("custom bounded decoder accepts derived reference payload");
    assert_eq!(custom_used, reference_bare.len());
    assert_eq!(decoded_custom, list);
}
#[test]
fn proof_attachment_list_constructor_enforces_first_release_cardinality() {
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    assert!(matches!(
        ProofAttachmentList::try_from(Vec::new()),
        Err(ProofAttachmentListError::Empty)
    ));
    let maximum = ProofAttachmentList::try_from(vec![
        attachment.clone();
        PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1
    ])
    .expect("exact verifier batch boundary must construct");
    assert_eq!(maximum.len(), PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1);
    assert!(!maximum.is_empty());
    assert_eq!(maximum.as_slice().len(), maximum.len());
    let frame = norito::encode_canonical(&maximum).expect("encode maximum-count list");
    let decoded = norito::decode_canonical::<ProofAttachmentList>(&frame)
        .expect("maximum-count list must round-trip canonically");
    assert_eq!(decoded, maximum);
    assert!(matches!(
        ProofAttachmentList::try_from(vec![
            attachment;
            PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1
        ]),
        Err(ProofAttachmentListError::TooMany {
            actual,
            maximum: PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
        }) if actual == PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1
    ));
}
#[test]
fn proof_attachment_list_try_push_preserves_order_and_rolls_back_cardinality_failure() {
    let attachment = |byte| {
        ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![byte]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        )
    };
    let first = attachment(1);
    let second = attachment(2);
    let mut list = bounded_attachment_list(vec![first.clone()]);
    list.try_push(second.clone())
        .expect("second attachment remains within all list limits");
    assert_eq!(list.as_slice(), [first, second]);
    let mut maximum = bounded_attachment_list(vec![
        attachment(3);
        PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1
    ]);
    let before = norito::encode_canonical(&maximum).expect("encode pre-failure list");
    assert!(matches!(
        maximum.try_push(attachment(4)),
        Err(ProofAttachmentListError::TooMany {
            actual,
            maximum: PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
        }) if actual == PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1
    ));
    assert_eq!(maximum.len(), PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1);
    assert_eq!(
        norito::encode_canonical(&maximum).expect("encode rolled-back list"),
        before,
        "failed cardinality append must leave the list byte-for-byte unchanged"
    );
}
#[test]
fn proof_attachment_list_exact_frame_boundary_and_try_push_rollback() {
    let attachment = |proof_bytes| {
        ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![0_u8; proof_bytes]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        )
    };
    let mut low = 1_usize;
    let mut high = PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1;
    while low < high {
        let midpoint = low + (high - low).div_ceil(2);
        if ProofAttachmentList::try_from(vec![attachment(midpoint)]).is_ok() {
            low = midpoint;
        } else {
            high = midpoint - 1;
        }
    }
    let mut list = ProofAttachmentList::try_from(vec![attachment(low)])
        .expect("binary search returns the largest fitting one-attachment list");
    let before = norito::encode_canonical(&list).expect("encode exact-cap list");
    assert_eq!(
        before.len(),
        PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        "largest accepted proof must fill the complete canonical frame ceiling exactly"
    );
    assert_eq!(
        ncore::encoded_frame_len(&list).expect("authoritative counting serialization"),
        before.len()
    );
    let hinted_payload = norito::SerializePayload::encoded_len_exact(&list)
        .expect("bounded list exposes an exact serialization hint");
    assert_eq!(
        ProofAttachmentList::canonical_frame_len_from_payload_len(hinted_payload)
            .expect("hinted frame length arithmetic"),
        before.len(),
        "the optimization hint must agree with authoritative emitted bytes"
    );
    assert_eq!(
        norito::decode_canonical::<ProofAttachmentList>(&before)
            .expect("exact-cap canonical frame must decode"),
        list
    );

    {
        let json = norito::json::to_json(&list).expect("encode exact-cap list JSON");
        assert_eq!(
            norito::json::from_str::<ProofAttachmentList>(&json)
                .expect("exact-cap canonical base64 list must decode"),
            list
        );
    }
    let next_error = ProofAttachmentList::try_from(vec![attachment(low + 1)])
        .expect_err("the next proof byte must cross the frame ceiling");
    assert!(matches!(
        next_error,
        ProofAttachmentListError::CanonicalFrameTooLarge {
            actual,
            maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        } if actual == PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 + 1
    ));
    ProofAttachmentList::reset_authoritative_length_passes_for_current_test_thread();
    let error = list
        .try_push(attachment(1))
        .expect_err("one more attachment must cross the canonical frame ceiling");
    assert!(matches!(
        error,
        ProofAttachmentListError::CanonicalFrameTooLarge {
            actual,
            maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        } if actual > PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1
    ));
    assert_eq!(
        ProofAttachmentList::authoritative_length_passes_for_current_test_thread(),
        0,
        "a length hint above the ceiling must reject before the allocating serializer"
    );
    assert_eq!(list.len(), 1);
    assert_eq!(
        norito::encode_canonical(&list).expect("encode rolled-back list"),
        before,
        "failed byte-limit append must leave the list byte-for-byte unchanged"
    );
}
#[test]
fn proof_attachment_list_constructor_rejects_frame_above_byte_cap() {
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new(
            "halo2/ipa".into(),
            vec![0_u8; PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1],
        ),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    let error = ProofAttachmentList::try_from(vec![attachment])
        .expect_err("payload alone at the frame ceiling leaves no framing headroom");
    assert!(matches!(
        error,
        ProofAttachmentListError::CanonicalFrameTooLarge {
            actual,
            maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        } if actual > PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1
    ));
}
#[test]
fn proof_attachment_list_gross_oversize_rejects_before_authoritative_serialization() {
    let mut attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new(
            "halo2/ipa".into(),
            vec![0_u8; PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1],
        ),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    attachment.lane_privacy = Some(lane_privacy_with_path(
        1,
        vec![Some(canonical_lane_sibling(0xBB))],
    ));
    assert!(attachment.structural_error().is_none());
    ProofAttachmentList::reset_authoritative_length_passes_for_current_test_thread();
    assert!(matches!(
        ProofAttachmentList::try_from(vec![attachment]),
        Err(ProofAttachmentListError::CanonicalFrameTooLarge {
            actual,
            maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        }) if actual > PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1
    ));
    assert_eq!(
        ProofAttachmentList::authoritative_length_passes_for_current_test_thread(),
        0,
        "an oversized but otherwise valid lane proof must fail without staging serializer buffers"
    );
}
#[test]
fn proof_attachment_list_decode_rejects_forged_count_before_vec_decode() {
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    let list = bounded_attachment_list(vec![attachment]);
    let mut bare = Vec::new();
    ncore::serialize_to_buffer(&list, &mut bare).expect("serialize list payload");
    let (_, field_header_len) = ncore::read_len_dyn_slice(&bare).expect("list field header");
    for forged_count in [0, PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1, usize::MAX] {
        let mut forged = bare.clone();
        let count = u64::try_from(forged_count).unwrap_or(u64::MAX);
        forged[field_header_len..field_header_len + 8].copy_from_slice(&count.to_le_bytes());
        let error = <ProofAttachmentList as ncore::DecodeFromSlice>::decode_from_slice(&forged)
            .expect_err("forged outer sequence count must reject before element decoding");
        let message = error.to_string();
        assert!(
            message.contains("must not be empty")
                || message.contains("attachment count")
                || message.contains("sequence length"),
            "unexpected forged-count error: {error}"
        );
    }
}
#[test]
fn proof_attachment_list_decode_rejects_frame_cap_plus_one_before_field_parsing() {
    let alignment = ncore::archived_payload_align::<ProofAttachmentList>();
    let remainder = ncore::Header::SIZE % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment - remainder
    };
    let maximum_payload = PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1
        .checked_sub(ncore::Header::SIZE + padding)
        .expect("frame ceiling exceeds fixed framing");
    let oversized_payload = vec![0_u8; maximum_payload + 1];
    let error =
        <ProofAttachmentList as ncore::DecodeFromSlice>::decode_from_slice(&oversized_payload)
            .expect_err("standalone canonical frame cap plus one must fail before field parsing");
    assert!(
        error.to_string().contains("canonical frame exceeds"),
        "unexpected cap+1 payload rejection: {error}"
    );
}
#[test]
fn proofbox_norito_roundtrip() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
    let p = ProofBox::new(backend, bytes.clone());
    let enc = norito::to_bytes(&p).expect("encode");
    let arch = norito::from_bytes::<ProofBox>(&enc).expect("archived");
    let dec: ProofBox = norito::core::DeserializePayload::deserialize(arch);
    assert_eq!(dec.backend, "halo2/ipa".to_owned());
    assert_eq!(dec.bytes, bytes);
}
#[test]
fn bounded_byte_boxes_decode_every_v1_layout() {
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3, 5, 8]);
    let verifying_key = VerifyingKeyBox::new("halo2/ipa".into(), vec![13, 21, 34]);
    for flags in [0, ncore::header_flags::COMPACT_LEN] {
        let proof_payload = encode_payload_with_flags(&proof, flags);
        let key_payload = encode_payload_with_flags(&verifying_key, flags);
        let _flags = ncore::DecodeFlagsGuard::enter(flags);
        let (decoded_proof, proof_used) =
            <ProofBox as ncore::DecodeFromSlice>::decode_from_slice(&proof_payload)
                .expect("decode bounded proof byte box");
        let (decoded_key, key_used) =
            <VerifyingKeyBox as ncore::DecodeFromSlice>::decode_from_slice(&key_payload)
                .expect("decode bounded verifier-key byte box");
        assert_eq!(decoded_proof, proof);
        assert_eq!(proof_used, proof_payload.len());
        assert_eq!(decoded_key, verifying_key);
        assert_eq!(key_used, key_payload.len());

        let key_byte_field_start = {
            let (_, byte_field, _) =
                take_byte_box_fields(&key_payload, VERIFYING_KEY_BOX_MAX_FIELD_BYTES_V1)
                    .expect("locate encoded verifier-key byte field");
            (byte_field.as_ptr() as usize).saturating_sub(key_payload.as_ptr() as usize)
        };
        let mut oversized = key_payload;
        oversized[key_byte_field_start..key_byte_field_start + 8].copy_from_slice(
            &u64::try_from(VERIFYING_KEY_BOX_MAX_PAYLOAD_BYTES_V1 + 1)
                .expect("verifier-key cap fits u64")
                .to_le_bytes(),
        );
        assert!(matches!(
            <VerifyingKeyBox as ncore::DecodeFromSlice>::decode_from_slice(&oversized),
            Err(ncore::Error::LengthMismatch)
        ));
    }
}
#[test]
fn proof_box_decode_enforces_complete_canonical_cap_in_every_layout() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let maximum_payload = proof_box_max_proof_bytes_v1(backend.as_str())
        .expect("bounded backend leaves room for proof bytes");
    let proof = ProofBox::new(backend, vec![0xA5; maximum_payload]);
    assert_eq!(
        proof.canonical_encoded_len_v1(),
        Some(PROOF_BOX_MAX_ENCODED_BYTES_V1)
    );

    for flags in [ncore::default_encode_flags(), 0] {
        let mut payload = encode_payload_with_flags(&proof, flags);
        let _flags = ncore::DecodeFlagsGuard::enter(flags);
        let (decoded, used) = <ProofBox as ncore::DecodeFromSlice>::decode_from_slice(&payload)
            .expect("decode exact-cap proof box");
        assert_eq!(decoded, proof);
        assert_eq!(used, payload.len());
        drop(decoded);

        let byte_field_start = {
            let (_, byte_field, _) = take_byte_box_fields(&payload, MAX_LEN_PREFIXED_FIELD_BYTES)
                .expect("locate exact-cap proof byte field");
            (byte_field.as_ptr() as usize).saturating_sub(payload.as_ptr() as usize)
        };
        payload[byte_field_start..byte_field_start + 8].copy_from_slice(
            &u64::try_from(maximum_payload + 1)
                .expect("proof limit fits u64")
                .to_le_bytes(),
        );
        assert!(matches!(
            <ProofBox as ncore::DecodeFromSlice>::decode_from_slice(&payload),
            Err(ncore::Error::LengthMismatch)
        ));
    }
}
#[test]
fn verifying_key_roundtrip() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let vk = VerifyingKeyBox::new(backend, vec![7, 7, 7]);
    let enc = norito::to_bytes(&vk).expect("encode");
    let arch = norito::from_bytes::<VerifyingKeyBox>(&enc).expect("archived");
    let dec: VerifyingKeyBox = norito::core::DeserializePayload::deserialize(arch);
    assert_eq!(dec.backend, "halo2/ipa".to_owned());
    assert_eq!(dec.bytes, vec![7, 7, 7]);
}
#[test]
fn verifying_key_id_decode_from_slice_roundtrip() {
    let id = VerifyingKeyId::new("halo2/ipa", "vk_transfer");
    let encoded = id.encode();
    let (decoded, used) = <VerifyingKeyId as ncore::DecodeFromSlice>::decode_from_slice(&encoded)
        .expect("decode verifying key id from exact slice");
    assert_eq!(used, encoded.len());
    assert_eq!(decoded, id);
}
#[test]
fn verifying_key_id_portable_registry_id_predicate_is_fail_closed() {
    for (backend, name) in [
        ("halo2/ipa", "vk_transfer"),
        ("halo2/ipa", "halo2/ipa::transfer_v1"),
        ("stark/fri/poseidon-x7-goldilocks-6x64-v1", "zk_ace.v1"),
        (
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "generic.binding.v1",
        ),
    ] {
        let id = VerifyingKeyId::new(backend, name);
        assert!(
            id.is_portable_registry_id(),
            "portable verifier-key id `{backend}` / `{name}` must be accepted"
        );
    }
    for (label, backend, name) in [
        ("blank-backend", " ", "vk_transfer"),
        ("blank-name", "halo2/ipa", " "),
        ("uppercase-backend", "Halo2/ipa", "vk_transfer"),
        ("uppercase-name", "halo2/ipa", "VkTransfer"),
        ("control-backend", "halo2/ipa\nforged", "vk_transfer"),
        ("control-name", "halo2/ipa", "vk\nforged"),
        ("zero-width-backend", "halo2/ipa\u{200B}", "vk_transfer"),
        ("zero-width-name", "halo2/ipa", "vk\u{200B}transfer"),
        ("path-traversal-backend", "halo2/ipa/../vk", "vk_transfer"),
        ("path-traversal-name", "halo2/ipa", "vk/../transfer"),
        ("dot-segment-backend", "halo2/ipa/./vk", "vk_transfer"),
        ("dot-segment-name", "halo2/ipa", "vk/./transfer"),
        ("hidden-backend", "halo2/.ipa", "vk_transfer"),
        ("hidden-name", "halo2/ipa", ".vk_transfer"),
        ("slash-colon-backend", "halo2/ipa/:vk", "vk_transfer"),
        ("colon-slash-name", "halo2/ipa", "vk:/transfer"),
        ("backslash-backend", "halo2\\ipa", "vk_transfer"),
        ("backslash-name", "halo2/ipa", "vk\\transfer"),
        ("leading-delimiter-name", "halo2/ipa", "-vk_transfer"),
        ("trailing-delimiter-name", "halo2/ipa", "vk_transfer_"),
    ] {
        let id = VerifyingKeyId::new(backend, name);
        assert!(
            !id.is_portable_registry_id(),
            "case {label} must reject verifier-key id `{backend}` / `{name}`"
        );
    }
    let oversized = "a".repeat(VERIFYING_KEY_ID_MAX_FIELD_BYTES + 1);
    assert!(!VerifyingKeyId::new("halo2/ipa", oversized.as_str()).is_portable_registry_id());
    assert!(!VerifyingKeyId::new(oversized.as_str(), "vk_transfer").is_portable_registry_id());
}
#[test]
fn vk_record_roundtrip() {
    let rec = VerifyingKeyRecord {
        version: 1,
        circuit_id: "transfer_v1".into(),
        owner_manifest_id: Some("core".into()),
        namespace: "core".into(),
        backend: BackendTag::Halo2IpaPasta,
        curve: "pallas".into(),
        public_inputs_schema_hash: [0xAA; 32],
        commitment: [0x11; 32],
        vk_len: 4096,
        max_proof_bytes: 8192,
        gas_schedule_id: Some("halo2_default".into()),
        metadata_uri_cid: Some("ipfs://halo2-transfer".into()),
        vk_bytes_cid: Some("ipfs://vk-transfer".into()),
        activation_height: Some(10),
        withdraw_height: Some(30),
        key: Some(VerifyingKeyBox {
            backend: "halo2/ipa".into(),
            bytes: vec![1, 2, 3],
        }),
        status: ConfidentialStatus::Active,
    };
    let enc = norito::to_bytes(&rec).expect("encode");
    let arch = norito::from_bytes::<VerifyingKeyRecord>(&enc).expect("archived");
    let dec: VerifyingKeyRecord = norito::core::DeserializePayload::deserialize(arch);
    assert_eq!(dec.version, 1);
    assert_eq!(dec.commitment, [0x11; 32]);
    assert!(dec.key.is_some());
}
#[test]
fn vk_record_new_defaults() {
    let rec = VerifyingKeyRecord::new(
        2,
        "shield_v2",
        BackendTag::Halo2IpaPasta,
        "pallas",
        [0xCC; 32],
        [0xDD; 32],
    );
    assert_eq!(rec.version, 2);
    assert_eq!(rec.status, ConfidentialStatus::Proposed);
    assert_eq!(rec.vk_len, 0);
    assert!(rec.max_proof_bytes == 0);
    assert!(rec.key.is_none());
}
#[test]
fn verifying_key_record_active_at_respects_height_window() {
    let mut rec = VerifyingKeyRecord::new(
        1,
        "halo2/ipa:height-window",
        BackendTag::Halo2IpaPasta,
        "pasta",
        [0xAA; 32],
        [0xBB; 32],
    );
    rec.status = ConfidentialStatus::Active;
    assert!(rec.is_active_at(1));
    rec.activation_height = Some(2);
    assert!(!rec.is_active_at(1));
    assert!(rec.is_active_at(2));
    rec.withdraw_height = Some(4);
    assert!(rec.is_active_at(3));
    assert!(!rec.is_active_at(4));
    rec.status = ConfidentialStatus::Proposed;
    assert!(!rec.is_active_at(3));
}
#[test]
fn proof_attachment_roundtrip() {
    let p = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let id = VerifyingKeyId::new("halo2/ipa", "vk_1");
    let a = ProofAttachment::new_ref("halo2/ipa".into(), p.clone(), id);
    let enc = norito::to_bytes(&a).expect("encode");
    let arch = norito::from_bytes::<ProofAttachment>(&enc).expect("archived");
    let dec: ProofAttachment = norito::core::DeserializePayload::deserialize(arch);
    assert_eq!(dec.backend, "halo2/ipa".to_owned());
    assert_eq!(dec.vk_ref.name.as_str(), "vk_1");
}
#[test]
fn proof_attachment_decode_accepts_matching_envelope_hash() {
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let mut attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        proof.clone(),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    attachment.envelope_hash = Some(proof_bytes_hash(&proof.bytes));
    let encoded = norito::to_bytes(&attachment).expect("encode attachment");
    let decoded = norito::decode_from_bytes::<ProofAttachment>(&encoded)
        .expect("matching envelope hash must decode");
    assert_eq!(decoded.envelope_hash, attachment.envelope_hash);
}
#[test]
fn proof_attachment_decode_rejects_missing_vk_ref_field() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let mut encoded = Vec::new();
    write_test_field(&mut encoded, &backend);
    write_test_field(&mut encoded, &proof);
    let result = <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(matches!(result, Err(ncore::Error::LengthMismatch)));
}
#[test]
fn proof_attachment_decode_rejects_legacy_optional_vk_ref_slot() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let legacy_vk_ref: Option<VerifyingKeyId> = None;
    let legacy_vk_inline = Some(VerifyingKeyBox::new("halo2/ipa".into(), vec![4, 5, 6]));
    let mut encoded = Vec::new();
    write_test_field(&mut encoded, &backend);
    write_test_field(&mut encoded, &proof);
    write_test_field(&mut encoded, &legacy_vk_ref);
    write_test_field(&mut encoded, &legacy_vk_inline);
    let result = <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(
        result.is_err(),
        "legacy optional vk_ref/vk_inline payload must not decode as registry-only attachment"
    );
}
#[test]
fn proof_attachment_decode_rejects_legacy_some_vk_ref_inline_slots() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let legacy_vk_ref = Some(VerifyingKeyId::new("halo2/ipa", "legacy_vk"));
    let legacy_vk_inline = Some(VerifyingKeyBox::new("halo2/ipa".into(), vec![4, 5, 6]));
    let mut encoded = Vec::new();
    write_test_field(&mut encoded, &backend);
    write_test_field(&mut encoded, &proof);
    write_test_field(&mut encoded, &legacy_vk_ref);
    write_test_field(&mut encoded, &legacy_vk_inline);
    let result = <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(
        result.is_err(),
        "legacy Some(vk_ref)/Some(vk_inline) payload must not decode as registry-only attachment"
    );
}
#[test]
fn proof_attachment_decode_rejects_inline_vk_tail_after_vk_ref() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let vk_ref = VerifyingKeyId::new("halo2/ipa", "vk_1");
    let legacy_vk_inline = Some(VerifyingKeyBox::new("halo2/ipa".into(), vec![4, 5, 6]));
    let mut encoded = Vec::new();
    write_test_field(&mut encoded, &backend);
    write_test_field(&mut encoded, &proof);
    write_test_field(&mut encoded, &vk_ref);
    write_test_field(&mut encoded, &legacy_vk_inline);
    let result = <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(
        result.is_err(),
        "inline verifying-key tail must not decode as optional vk_commitment"
    );
}
#[test]
fn proof_attachment_decode_rejects_extra_tail_after_allowed_fields() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let vk_ref = VerifyingKeyId::new("halo2/ipa", "vk_1");
    let vk_commitment = Some([0x11; 32]);
    let envelope_hash = Some([0x22; 32]);
    let lane_privacy: Option<crate::nexus::LanePrivacyProof> = None;
    let extra = Some([0x33; 32]);
    let mut encoded = Vec::new();
    write_test_field(&mut encoded, &backend);
    write_test_field(&mut encoded, &proof);
    write_test_field(&mut encoded, &vk_ref);
    write_test_field(&mut encoded, &vk_commitment);
    write_test_field(&mut encoded, &envelope_hash);
    write_test_field(&mut encoded, &lane_privacy);
    write_test_field(&mut encoded, &extra);
    let result = <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(
        matches!(result, Err(ncore::Error::LengthMismatch)),
        "extra tail field after lane_privacy must be rejected, got {result:?}"
    );
}
#[test]
fn proof_attachment_decode_rejects_redundant_none_tail_fields() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let vk_ref = VerifyingKeyId::new("halo2/ipa", "vk_1");
    let required_prefix = || {
        let mut encoded = Vec::new();
        write_test_field(&mut encoded, &backend);
        write_test_field(&mut encoded, &proof);
        write_test_field(&mut encoded, &vk_ref);
        encoded
    };
    let absent_hash: Option<[u8; 32]> = None;
    let present_vk_commitment = Some([0x11; 32]);
    let present_envelope_hash = Some(proof_bytes_hash(&proof.bytes));
    let absent_lane: Option<crate::nexus::LanePrivacyProof> = None;
    let mut malformed = Vec::new();
    let mut trailing_vk_none = required_prefix();
    write_test_field(&mut trailing_vk_none, &absent_hash);
    malformed.push(trailing_vk_none);
    let mut trailing_envelope_none = required_prefix();
    write_test_field(&mut trailing_envelope_none, &present_vk_commitment);
    write_test_field(&mut trailing_envelope_none, &absent_hash);
    malformed.push(trailing_envelope_none);
    let mut trailing_lane_none = required_prefix();
    write_test_field(&mut trailing_lane_none, &absent_hash);
    write_test_field(&mut trailing_lane_none, &present_envelope_hash);
    write_test_field(&mut trailing_lane_none, &absent_lane);
    malformed.push(trailing_lane_none);
    let mut three_redundant_nones = required_prefix();
    write_test_field(&mut three_redundant_nones, &absent_hash);
    write_test_field(&mut three_redundant_nones, &absent_hash);
    write_test_field(&mut three_redundant_nones, &absent_lane);
    malformed.push(three_redundant_nones);
    for encoded in malformed {
        let error = <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&encoded)
            .expect_err("redundant trailing None fields must not have a second wire spelling");
        assert!(
            matches!(&error, ncore::Error::LengthMismatch)
                || error.to_string().contains("non-canonical redundant"),
            "unexpected error: {error}"
        );
    }
}
#[test]
fn proof_attachment_decode_accepts_none_placeholders_before_later_some_fields() {
    let proof = ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]);
    let mut envelope_only = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        proof.clone(),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    envelope_only.envelope_hash = Some(proof_bytes_hash(&proof.bytes));
    let mut lane_only = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        proof,
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    lane_only.lane_privacy = Some(lane_privacy_with_path(
        0,
        vec![Some(canonical_lane_sibling(0x23))],
    ));
    for attachment in [envelope_only, lane_only] {
        let encoded = norito::to_bytes(&attachment).expect("encode canonical sparse tail");
        let decoded = norito::decode_from_bytes::<ProofAttachment>(&encoded)
            .expect("None placeholders before a later Some field must decode");
        assert_eq!(decoded, attachment);
    }
}
#[test]
fn proof_attachment_decode_rejects_malformed_lane_privacy_paths() {
    let sibling = canonical_lane_sibling(0x22);
    let malformed = [
        lane_privacy_with_path(0, Vec::new()),
        lane_privacy_with_path(0, vec![None]),
        lane_privacy_with_path(2, vec![Some(sibling)]),
        lane_privacy_with_path(
            0,
            vec![Some(sibling); crate::nexus::LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 + 1],
        ),
    ];
    for lane_privacy in malformed {
        let mut attachment = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        );
        attachment.lane_privacy = Some(lane_privacy);
        let encoded = norito::to_bytes(&attachment).expect("encode malformed lane witness");
        let error = norito::decode_from_bytes::<ProofAttachment>(&encoded)
            .expect_err("malformed lane witness must not decode inside an attachment");
        assert!(error.to_string().contains("lane_privacy"));
    }
}
#[test]
fn proof_attachment_decode_rejects_blank_verifying_key_name() {
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "   "),
    );
    let encoded = norito::to_bytes(&attachment).expect("encode blank vk name attachment");
    let err = norito::decode_from_bytes::<ProofAttachment>(&encoded)
        .expect_err("blank verifying key names must not decode");
    assert!(err.to_string().contains("vk_ref.name"));
}
#[test]
fn proof_attachment_decode_rejects_blank_backend_fields() {
    let cases = [
        (
            ProofAttachment::new_ref(
                "   ".into(),
                ProofBox::new("   ".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("   ", "vk_1"),
            ),
            "backend",
        ),
        (
            ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("   ".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("halo2/ipa", "vk_1"),
            ),
            "proof.backend",
        ),
        (
            ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("   ", "vk_1"),
            ),
            "vk_ref.backend",
        ),
    ];
    for (attachment, expected_field) in cases {
        let encoded = norito::to_bytes(&attachment).expect("encode blank backend attachment");
        let err = norito::decode_from_bytes::<ProofAttachment>(&encoded)
            .expect_err("blank backend fields must not decode");
        assert!(
            err.to_string().contains(expected_field),
            "expected error to mention {expected_field}, got {err}"
        );
    }
}
#[test]
fn proof_attachment_decode_rejects_nonportable_refs_empty_proofs_and_zero_hashes() {
    let mut zero_vk_commitment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    zero_vk_commitment.vk_commitment = Some([0u8; 32]);
    let mut zero_envelope_hash = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    zero_envelope_hash.envelope_hash = Some([0u8; 32]);
    let mut forged_envelope_hash = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    let mut forged_hash = proof_bytes_hash(&forged_envelope_hash.proof.bytes);
    forged_hash[0] ^= 0x80;
    forged_envelope_hash.envelope_hash = Some(forged_hash);
    let cases = [
        (
            ProofAttachment::new_ref(
                "Halo2/ipa".into(),
                ProofBox::new("Halo2/ipa".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("Halo2/ipa", "vk_1"),
            ),
            "vk_ref",
        ),
        (
            ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("halo2/ipa", "Vk_1"),
            ),
            "vk_ref",
        ),
        (
            ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("halo2/ipa", "vk_1\u{200B}"),
            ),
            "vk_ref",
        ),
        (
            ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), Vec::new()),
                VerifyingKeyId::new("halo2/ipa", "vk_1"),
            ),
            "proof.bytes",
        ),
        (zero_vk_commitment, "vk_commitment"),
        (zero_envelope_hash, "envelope_hash"),
        (forged_envelope_hash, "envelope_hash"),
    ];
    for (attachment, expected_field) in cases {
        let encoded = norito::to_bytes(&attachment).expect("encode malformed attachment");
        let err = norito::decode_from_bytes::<ProofAttachment>(&encoded)
            .expect_err("malformed proof attachment must not decode");
        assert!(
            err.to_string().contains(expected_field),
            "expected error to mention {expected_field}, got {err}"
        );
    }
}
#[test]
fn proof_box_canonical_size_limit_accounts_for_backend_and_framing() {
    let backend = "halo2/ipa::transfer_v1";
    let proof = ProofBox::new(backend.into(), vec![1, 2, 3, 4, 5]);
    let canonical_payload =
        ncore::encoded_payload_len(&proof).expect("canonical nested ProofBox payload");
    assert_eq!(proof.canonical_encoded_len_v1(), Some(canonical_payload));
    assert!(
        norito::encode_canonical(&proof)
            .expect("standalone canonical ProofBox frame")
            .len()
            > canonical_payload,
        "a standalone frame adds a header and alignment; the attachment cap covers the complete nested ProofBox payload"
    );
    assert_eq!(
        proof_box_max_proof_bytes_v1(backend),
        Some(PROOF_BOX_MAX_ENCODED_BYTES_V1 - 36)
    );
    let maximum = proof_box_max_proof_bytes_v1(backend).expect("bounded backend");
    let mut maximum_sized_proof = Vec::with_capacity(maximum + 1);
    maximum_sized_proof.resize(maximum, 0xA5);
    let mut attachment = ProofAttachment::new_ref(
        backend.into(),
        ProofBox::new(backend.into(), maximum_sized_proof),
        VerifyingKeyId::new(backend, "transfer_v1"),
    );
    assert_eq!(
        attachment.proof.canonical_encoded_len_v1(),
        Some(PROOF_BOX_MAX_ENCODED_BYTES_V1)
    );
    assert_eq!(
        ncore::encoded_payload_len(&attachment.proof)
            .expect("count maximum nested ProofBox payload"),
        PROOF_BOX_MAX_ENCODED_BYTES_V1
    );
    assert_eq!(attachment.structural_error(), None);
    attachment.proof.bytes.push(0x5A);
    assert_eq!(
        ncore::encoded_payload_len(&attachment.proof)
            .expect("count oversized nested ProofBox payload"),
        PROOF_BOX_MAX_ENCODED_BYTES_V1 + 1
    );
    assert_eq!(
        attachment.structural_error(),
        Some(("proof", "canonical encoding exceeds the 64 MiB limit"))
    );
}
#[test]
fn proof_box_size_accounting_matches_norito_at_compact_prefix_transitions() {
    let _canonical_flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    for backend_len in [1, 126, 127, 128, 255, 256, 4_094] {
        let backend = "a".repeat(backend_len);
        for proof_len in [0, 1, 118, 119, 120, 121, 16_374, 16_375, 16_376, 16_377] {
            let proof = ProofBox::new(backend.clone(), vec![0xC3; proof_len]);
            assert_eq!(
                proof.canonical_encoded_len_v1(),
                Some(
                    ncore::encoded_payload_len(&proof)
                        .expect("count canonical nested ProofBox payload")
                ),
                "backend length {backend_len}, proof length {proof_len}"
            );
        }
    }
    for backend_len in [1, 127, 128, 256, 4_094] {
        let backend = "b".repeat(backend_len);
        let maximum = proof_box_max_proof_bytes_v1(&backend).expect("bounded backend");
        assert_eq!(
            proof_box_canonical_encoded_len_for_lengths_v1(backend_len, maximum),
            Some(PROOF_BOX_MAX_ENCODED_BYTES_V1)
        );
        assert!(
            proof_box_canonical_encoded_len_for_lengths_v1(backend_len, maximum + 1)
                .is_some_and(|length| length > PROOF_BOX_MAX_ENCODED_BYTES_V1)
        );
    }
    let largest_backend = "c".repeat(4_094);
    let proof = ProofBox::new(largest_backend.clone(), vec![0x5A]);
    assert!(proof.canonical_encoded_len_v1().is_some());
    assert!(proof_box_max_proof_bytes_v1(&largest_backend).is_some());
    let encoded = norito::to_bytes(&proof).expect("encode maximum backend field");
    let decoded = norito::decode_from_bytes::<ProofBox>(&encoded)
        .expect("maximum backend field must round-trip");
    assert_eq!(decoded, proof);
    for backend_len in [4_095, 4_096] {
        let backend = "d".repeat(backend_len);
        let proof = ProofBox::new(backend.clone(), vec![0x5A]);
        assert_eq!(proof.canonical_encoded_len_v1(), None);
        assert_eq!(proof_box_max_proof_bytes_v1(&backend), None);
        let encoded = norito::to_bytes(&proof).expect("encoding remains infallible");
        assert!(
            norito::decode_from_bytes::<ProofBox>(&encoded).is_err(),
            "raw backend length {backend_len} exceeds the canonical field boundary"
        );
    }
}
#[test]
fn proof_attachment_decode_rejects_backend_mismatches() {
    for (proof_backend, vk_backend, expected_field) in [
        ("stark/fri", "halo2/ipa", "proof.backend"),
        ("halo2/ipa", "stark/fri", "vk_ref.backend"),
    ] {
        let attachment = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new(proof_backend.into(), vec![1, 2, 3]),
            VerifyingKeyId::new(vk_backend, "vk_1"),
        );
        let encoded = norito::to_bytes(&attachment).expect("encode mismatched attachment");
        let result = norito::decode_from_bytes::<ProofAttachment>(&encoded)
            .expect_err("backend-inconsistent attachment must not decode");
        assert!(
            result.to_string().contains(expected_field),
            "unexpected error: {result}"
        );
    }
}

#[test]
fn proof_attachment_list_json_rejects_backend_mismatch_inside_wire_payload() {
    use base64::Engine as _;
    let list = bounded_attachment_list(vec![ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("stark/fri", "vk_1"),
    )]);
    let encoded = norito::to_bytes(&list).expect("encode mismatched attachment list");
    let json = format!("\"{}\"", STANDARD.encode(encoded));
    let err = norito::json::from_str::<ProofAttachmentList>(&json)
        .expect_err("base64 Norito list with backend mismatch must be rejected");
    assert!(err.to_string().contains("vk_ref.backend"));
}

#[test]
fn proof_attachment_list_json_rejects_single_attachment_wire_payload() {
    use base64::Engine as _;
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    let encoded = norito::to_bytes(&attachment).expect("encode single attachment");
    let json = format!("\"{}\"", STANDARD.encode(encoded));
    norito::json::from_str::<ProofAttachmentList>(&json)
        .expect_err("single ProofAttachment wire payload must not decode as a list");
}

#[test]
fn proof_attachment_list_json_is_canonical_and_ambient_independent() {
    use base64::Engine as _;
    let list = bounded_attachment_list(vec![ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    )]);
    let canonical_json =
        norito::json::to_json(&list).expect("encode canonical proof-attachment list JSON");
    let canonical_frame =
        norito::encode_canonical(&list).expect("encode canonical proof-attachment list frame");
    assert_eq!(
        canonical_json,
        format!("\"{}\"", STANDARD.encode(canonical_frame)),
        "streamed base64 must preserve the legacy JSON bytes"
    );
    assert_eq!(
        norito::json::to_json_bounded(&list, canonical_json.len())
            .expect("serialize attachment list at its exact JSON limit"),
        canonical_json
    );
    assert_eq!(
        norito::json::to_json_bounded(&list, canonical_json.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_eq!(
            norito::json::to_json(&list).expect("encode list JSON under alternate ambient layout"),
            canonical_json
        );
    }
    let alternate_frame = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&list).expect("encode alternate-layout proof-attachment list")
    };
    let alternate_json = format!("\"{}\"", STANDARD.encode(alternate_frame));
    norito::json::from_str::<ProofAttachmentList>(&alternate_json)
        .expect_err("alternate-layout proof-attachment list JSON must be rejected");
    let value = norito::json::parse_value(&canonical_json)
        .expect("parse canonical list as a borrowed generic value");
    let frame = STANDARD
        .decode(value.as_str().expect("list JSON must be a base64 string"))
        .expect("decode canonical list frame for count preflight test");
    assert_eq!(
        proof_attachment_list_frame_attachment_count(&frame)
            .expect("inspect canonical list count without decoding elements"),
        1
    );
    let from_value =
        <ProofAttachmentList as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect("canonical list Value must pass bounded preflight");
    assert_eq!(from_value, list);
}

#[test]
fn proof_manual_json_writers_preserve_bytes_and_closed_limits() {
    fn assert_bounded<T: norito::json::JsonSerialize>(value: &T) {
        let expected = norito::json::to_json(value).expect("serialize ordinary JSON");
        assert_eq!(
            norito::json::to_json_bounded(value, expected.len())
                .expect("serialize at exact JSON limit"),
            expected
        );
        assert_eq!(
            norito::json::to_json_bounded(value, expected.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
    }
    let mut attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    attachment.vk_commitment = Some([0xBC; 32]);
    assert_bounded(&attachment);
    let id = ProofId {
        backend: "halo2/ipa:profile".into(),
        proof_hash: [0xAB; 32],
    };
    assert_bounded(&id);
    let record = ProofRecord {
        id,
        vk_ref: None,
        vk_commitment: Some([0xCD; 32]),
        status: ProofStatus::Verified,
        verified_at_height: Some(7),
        bridge: None,
    };
    assert_bounded(&record);
    assert_bounded(&crate::query::QueryResponse::Singular(
        crate::query::SingularQueryOutputBox::ProofRecord(record),
    ));
    for status in [
        ProofStatus::Submitted,
        ProofStatus::Verified,
        ProofStatus::Rejected,
    ] {
        assert_bounded(&status);
    }
}

#[test]
fn proof_attachment_list_json_limit_helpers_use_closed_boundaries() {
    use base64::Engine as _;
    proof_attachment_list_validate_limits(8, 2, 8, 2)
        .expect("frame and count exactly at their limits must pass");
    assert!(proof_attachment_list_validate_limits(9, 2, 8, 2).is_err());
    assert!(proof_attachment_list_validate_limits(8, 0, 8, 2).is_err());
    assert!(proof_attachment_list_validate_limits(8, 3, 8, 2).is_err());
    let at_limit = STANDARD.encode([0_u8; 6]);
    assert_eq!(
        proof_attachment_list_base64_decoded_len(&at_limit, 6)
            .expect("decoded bytes exactly at the test limit"),
        6
    );
    let over_limit = STANDARD.encode([0_u8; 7]);
    proof_attachment_list_base64_decoded_len(&over_limit, 6)
        .expect_err("encoded token above the decoded-byte limit must reject");
    let json = format!("\"{at_limit}\"");
    let mut parser = norito::json::Parser::new(&json);
    let (borrowed, decoded_len) = proof_attachment_list_borrowed_base64_token(&mut parser, 6)
        .expect("canonical token exactly at the bounded parser limit");
    assert_eq!(borrowed, at_limit);
    assert_eq!(decoded_len, 6);
    assert_eq!(parser.position(), json.len());
    let full_limit_plus_one = PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 + 1;
    let encoded_len = proof_attachment_list_base64_encoded_len(full_limit_plus_one)
        .expect("full-size base64 arithmetic");
    let full_over_limit = "A".repeat(encoded_len);
    assert_eq!(
        proof_attachment_list_base64_decoded_len(
            &full_over_limit,
            PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        )
        .expect_err("canonical full-size token decoding to cap+1 must fail")
        .to_string(),
        proof_attachment_list_json_error("decoded frame exceeds the first-release byte limit")
            .to_string()
    );
    let full_over_limit_json = format!("\"{full_over_limit}\"");
    norito::json::from_str::<ProofAttachmentList>(&full_over_limit_json)
        .expect_err("full-size cap+1 JSON token must fail before base64 allocation");
}

#[test]
fn proof_attachment_list_json_rejects_noncanonical_base64_before_decode() {
    for encoded in [
        "",      // no complete Norito frame
        "AQ",    // missing required padding
        "AQ=",   // impossible encoded length
        "A===",  // excess padding
        "A=AA",  // interior padding
        "AQ-_",  // URL-safe alphabet
        "/x==",  // non-zero low four tail bits
        "AAB=",  // non-zero low two tail bits
        "AQI= ", // embedded whitespace
    ] {
        let json = format!("\"{encoded}\"");
        norito::json::from_str::<ProofAttachmentList>(&json)
            .expect_err("noncanonical base64 must fail bounded preflight");
        let value = norito::json::parse_value(&json).expect("valid generic JSON string");
        <ProofAttachmentList as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("Value preflight must reject the same noncanonical base64");
    }
    norito::json::from_str::<ProofAttachmentList>(r#""\/w==""#)
        .expect_err("escaped base64 spelling must not alias its canonical wire spelling");
}

#[test]
fn proof_attachment_list_json_rejects_over_limit_attachment_count() {
    use base64::Engine as _;
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    let list = ProofAttachmentList(vec![
        attachment;
        PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1
    ]);
    let frame = norito::encode_canonical(&list).expect("encode over-count test frame");
    assert!(frame.len() < PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1);
    assert_eq!(
        proof_attachment_list_frame_attachment_count(&frame)
            .expect("inspect over-limit count before element allocation"),
        PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1
    );
    let json = format!("\"{}\"", STANDARD.encode(frame));
    let error = norito::json::from_str::<ProofAttachmentList>(&json)
        .expect_err("canonical frame above the attachment-count limit must reject");
    assert!(error.to_string().contains("attachment count"));
}

#[test]
fn proof_attachment_list_json_rejects_forged_empty_frame() {
    use base64::Engine as _;
    // The private field prevents this value outside the defining module;
    // forge it here solely to exercise hostile wire input.
    let frame = norito::encode_canonical(&ProofAttachmentList(Vec::new()))
        .expect("encode forged empty attachment-list frame");
    let json = format!("\"{}\"", STANDARD.encode(frame));
    let error = norito::json::from_str::<ProofAttachmentList>(&json)
        .expect_err("empty attachment-list frame must reject");
    assert!(error.to_string().contains("must not be empty"));
}

#[test]
fn proof_primitives_json_reject_unknown_first_release_fields() {
    let proof = r#"{
            "backend": "halo2/ipa",
            "bytes": [1, 2, 3],
            "future_proof_metadata": true
        }"#;
    let error = norito::json::from_str::<ProofBox>(proof)
        .expect_err("ProofBox must reject unknown first-release fields");
    assert!(error.to_string().contains("unknown"));

    let verifying_key = r#"{
            "backend": "halo2/ipa",
            "name": "vk_1",
            "future_registry_metadata": true
        }"#;
    let error = norito::json::from_str::<VerifyingKeyId>(verifying_key)
        .expect_err("VerifyingKeyId must reject unknown first-release fields");
    assert!(error.to_string().contains("unknown"));
}

#[test]
fn proof_attachment_json_accepts_reference_only_payload() {
    let json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
            "vk_commitment": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
            "envelope_hash": null,
            "lane_privacy": null
        }"#;
    let attachment: ProofAttachment = norito::json::from_str(json).expect("reference JSON");
    assert_eq!(attachment.backend.as_str(), "halo2/ipa");
    assert_eq!(attachment.proof.bytes, vec![1, 2, 3]);
    assert_eq!(attachment.vk_ref.name.as_str(), "vk_1");
    assert_eq!(
        attachment.vk_commitment,
        Some({
            let mut commitment = [0u8; 32];
            commitment[31] = 7;
            commitment
        })
    );
    assert!(attachment.envelope_hash.is_none());
}

#[test]
fn proof_attachment_json_uses_canonical_proof_byte_array() {
    let json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
            "vk_commitment": null,
            "envelope_hash": null,
            "lane_privacy": null
        }"#;
    let attachment: ProofAttachment = norito::json::from_str(json).expect("canonical JSON");
    assert_eq!(attachment.proof.bytes, vec![1, 2, 3]);
    let canonical = norito::json::to_json(&attachment).expect("serialize canonical JSON");
    assert!(canonical.contains("\"bytes\":[1,2,3]"));
    assert!(!canonical.contains("bytes_b64"));
    assert!(canonical.contains("\"vk_commitment\":null"));
    assert!(canonical.contains("\"envelope_hash\":null"));
    assert!(canonical.contains("\"lane_privacy\":null"));
    let roundtrip: ProofAttachment =
        norito::json::from_str(&canonical).expect("canonical roundtrip JSON");
    assert_eq!(roundtrip, attachment);
    let value = norito::json::parse_value(&canonical).expect("canonical generic JSON value");
    let from_value = <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
        .expect("canonical Value must use the streaming acceptance language");
    assert_eq!(from_value, attachment);
}

#[test]
fn proof_attachment_json_streaming_decoder_is_field_order_independent() {
    let json = r#"{
            "lane_privacy": null,
            "vk_ref": { "name": "vk_1", "backend": "halo2/ipa" },
            "envelope_hash": null,
            "proof": { "bytes": [1, 2, 3], "backend": "halo2/ipa" },
            "backend": "halo2/ipa",
            "vk_commitment": null
        }"#;
    let attachment: ProofAttachment =
        norito::json::from_str(json).expect("reordered canonical attachment JSON");
    assert_eq!(attachment.backend, "halo2/ipa");
    assert_eq!(attachment.proof.bytes, [1, 2, 3]);
    assert_eq!(attachment.vk_ref.name, "vk_1");
}

#[test]
fn proof_attachment_json_proof_bytes_are_bounded_while_streaming() {
    // The production decoder uses the multi-million-byte V1 ceiling. A
    // small const-generic limit exercises the identical boundary without
    // constructing an adversarial 64 MiB fixture in a unit test.
    assert!(proof_box_max_proof_bytes_v1("halo2/ipa").is_some_and(|maximum| maximum > 1_000_000));
    let at_limit = norito::json::from_str::<ProofAttachmentJsonProofBoxV1<4>>(
        r#"{ "backend": "halo2/ipa", "bytes": [0, 1, 2, 3] }"#,
    )
    .expect("stream exactly at the test limit through the production proof decoder");
    assert_eq!(at_limit.backend, "halo2/ipa");
    assert_eq!(at_limit.bytes, [0, 1, 2, 3]);
    let error = norito::json::from_str::<ProofAttachmentJsonProofBoxV1<4>>(
        r#"{ "backend": "halo2/ipa", "bytes": [0, 1, 2, 3, 4] }"#,
    )
    .err()
    .expect("the fifth byte must be rejected before output growth");
    assert!(error.to_string().contains("4-byte streaming limit"));
    let error = norito::json::from_str::<ProofAttachmentJsonProofBoxV1<4>>(
        r#"{ "bytes": [0, 1, 2, 3, 4], "backend": "halo2/ipa" }"#,
    )
    .err()
    .expect("backend discovered after bytes must still bound the byte stream");
    assert!(error.to_string().contains("4-byte streaming limit"));
    let value = norito::json::parse_value(
        r#"{
                "backend": "halo2/ipa",
                "proof": { "bytes": [0, 1, 2, 3, 4], "backend": "halo2/ipa" },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
    )
    .expect("generic over-limit proof fixture");
    let error = proof_attachment_json_value_preflight::<4>(&value)
        .expect_err("borrowed Value preflight must reject the fifth byte");
    assert!(error.to_string().contains("proof.bytes"));
}

#[test]
fn proof_attachment_json_lane_path_is_bounded_while_streaming() {
    let sibling = norito::json::to_json(&canonical_lane_sibling(0x23))
        .expect("serialize canonical Merkle sibling");
    let at_limit = format!("[{sibling},{sibling}]");
    let decoded = norito::json::from_str::<ProofAttachmentJsonAuditPathV1<2>>(&at_limit)
        .expect("path exactly at the test limit");
    assert_eq!(decoded.0.len(), 2);
    let over_limit = format!("[{sibling},{sibling},{sibling}]");
    let error = norito::json::from_str::<ProofAttachmentJsonAuditPathV1<2>>(&over_limit)
        .err()
        .expect("third sibling must be rejected before output growth");
    assert!(error.to_string().contains("2-sibling limit"));
}

#[test]
fn proof_attachment_json_requires_explicit_nullable_fields() {
    let canonical = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1] },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
            "vk_commitment": null,
            "envelope_hash": null,
            "lane_privacy": null
        }"#;
    let attachment = norito::json::from_str::<ProofAttachment>(canonical)
        .expect("explicit null is the canonical spelling for an empty nullable field");
    assert!(attachment.vk_commitment.is_none());
    assert!(attachment.envelope_hash.is_none());
    assert!(attachment.lane_privacy.is_none());
    let value = norito::json::parse_value(canonical).expect("canonical generic JSON fixture");
    let from_value = <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
        .expect("json_from_value accepts the same explicit-null shape");
    assert_eq!(from_value, attachment);

    for json in [
        r#"{
                "backend": null,
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                "vk_commitment": null,
                "envelope_hash": null,
                "lane_privacy": null
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": null,
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                "vk_commitment": null,
                "envelope_hash": null,
                "lane_privacy": null
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": null,
                "vk_commitment": null,
                "envelope_hash": null,
                "lane_privacy": null
            }"#,
    ] {
        assert!(
            norito::json::from_str::<ProofAttachment>(json).is_err(),
            "non-nullable field must reject null: {json}"
        );
        let value = norito::json::parse_value(json).expect("valid generic JSON fixture");
        assert!(
            <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value).is_err(),
            "json_from_value must enforce the same non-nullable rule: {json}"
        );
    }

    for missing_field in ["vk_commitment", "envelope_hash", "lane_privacy"] {
        let mut value = norito::json::parse_value(canonical).expect("canonical JSON fixture");
        value
            .as_object_mut()
            .expect("attachment object")
            .remove(missing_field);
        let json = norito::json::to_json(&value).expect("serialize missing-field fixture");
        let error = norito::json::from_str::<ProofAttachment>(&json)
            .expect_err("omitted nullable field must reject in first-release JSON");
        assert!(error.to_string().contains(missing_field));
        let error = <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("Value path must reject the same omitted nullable field");
        assert!(error.to_string().contains(missing_field));
    }
}

#[test]
fn proof_attachment_json_value_preflight_rejects_wrong_shapes() {
    for json in [
        "[]",
        r#"{
                "backend": 7,
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": [],
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": "AQ==" },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": []
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                "vk_commitment": "not-a-byte-array"
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                "lane_privacy": []
            }"#,
    ] {
        let value = norito::json::parse_value(json).expect("valid generic JSON fixture");
        <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("borrowed preflight must reject wrong first-release shapes");
    }
}

#[test]
fn proof_attachment_json_rejects_oversized_identifier_fields() {
    let oversized = "a".repeat(VERIFYING_KEY_ID_MAX_FIELD_BYTES + 1);
    for json in [
        format!(
            r#"{{
                    "backend": "{oversized}",
                    "proof": {{ "backend": "{oversized}", "bytes": [1] }},
                    "vk_ref": {{ "backend": "{oversized}", "name": "vk_1" }}
                }}"#
        ),
        format!(
            r#"{{
                    "backend": "halo2/ipa",
                    "proof": {{ "backend": "halo2/ipa", "bytes": [1] }},
                    "vk_ref": {{ "backend": "halo2/ipa", "name": "{oversized}" }}
                }}"#
        ),
    ] {
        let error = norito::json::from_str::<ProofAttachment>(&json)
            .expect_err("oversized attachment identifiers must reject");
        assert!(error.to_string().contains("256-byte limit"));
        let value = norito::json::parse_value(&json).expect("valid generic JSON fixture");
        <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("borrowed Value preflight must reject oversized identifiers");
    }
}

#[test]
fn proof_attachment_json_rejects_trailing_commas() {
    for json in [
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1], },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1,] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1", }
            }"#,
    ] {
        assert!(
            norito::json::from_str::<ProofAttachment>(json).is_err(),
            "trailing comma must be rejected: {json}"
        );
    }
}

#[test]
fn proof_attachment_json_rejects_noncanonical_proof_byte_encodings() {
    for proof_json in [
        r#"{"backend":"halo2/ipa"}"#,
        r#"{"backend":"halo2/ipa","bytes_b64":"AQID"}"#,
        r#"{"backend":"halo2/ipa","bytes":[1,2,3],"bytes_b64":"AQID"}"#,
        r#"{"backend":"halo2/ipa","bytes":"AQID"}"#,
        r#"{"backend":"halo2/ipa","bytes":[1,256,3]}"#,
    ] {
        let json = format!(
            r#"{{"backend":"halo2/ipa","proof":{proof_json},"vk_ref":{{"backend":"halo2/ipa","name":"vk_1"}}}}"#
        );
        norito::json::from_str::<ProofAttachment>(&json)
            .expect_err("noncanonical proof bytes must fail");
        let value = norito::json::parse_value(&json).expect("valid generic JSON fixture");
        <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("Value preflight or strict re-entry must reject proof shape");
    }
}

#[test]
fn proof_attachment_json_accepts_matching_envelope_hash() {
    let proof_bytes = [1u8, 2, 3];
    let envelope_hash = proof_bytes_hash(&proof_bytes);
    let envelope_hash_json = hash_json(&envelope_hash);
    let json = format!(
        r#"{{
                "backend": "halo2/ipa",
                "proof": {{ "backend": "halo2/ipa", "bytes": [1, 2, 3] }},
                "vk_ref": {{ "backend": "halo2/ipa", "name": "vk_1" }},
                "vk_commitment": null,
                "envelope_hash": {envelope_hash_json},
                "lane_privacy": null
            }}"#
    );
    let attachment: ProofAttachment =
        norito::json::from_str(&json).expect("matching envelope hash JSON");
    assert_eq!(attachment.envelope_hash, Some(envelope_hash));
}

#[test]
fn proof_attachment_json_rejects_retired_inline_vk_fields() {
    for field in [
        "vk_inline",
        "vkInline",
        "verifyingKeyInline",
        "verifying_key_inline",
    ] {
        let json = format!(
            r#"{{
                    "backend": "halo2/ipa",
                    "proof": {{ "backend": "halo2/ipa", "bytes": [1, 2, 3] }},
                    "vk_ref": {{ "backend": "halo2/ipa", "name": "vk_1" }},
                    "{field}": {{ "backend": "halo2/ipa", "bytes": [9, 9, 9] }}
                }}"#
        );
        let err = norito::json::from_str::<ProofAttachment>(&json)
            .expect_err("retired inline verifying key must be rejected");
        assert!(
            err.to_string()
                .contains("retired inline verifying-key field")
        );
    }
}

#[test]
fn proof_attachment_json_rejects_unknown_members_at_every_declared_layer() {
    for json in [
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                "future_attachment_metadata": true
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3], "future_proof_metadata": 7 },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1", "future_registry_metadata": 7 }
            }"#,
    ] {
        let error = norito::json::from_str::<ProofAttachment>(json)
            .expect_err("unknown first-release member must be rejected");
        assert!(error.to_string().contains("unknown fields"));
        let value = norito::json::parse_value(json).expect("valid generic JSON fixture");
        let error = <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("borrowed Value preflight must reject every unknown member");
        assert!(error.to_string().contains("unknown"));
    }
}

#[test]
fn proof_attachment_json_requires_exact_structural_lane_privacy() {
    let sibling = canonical_lane_sibling(0x22);
    let mut attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        VerifyingKeyId::new("halo2/ipa", "vk_1"),
    );
    attachment.lane_privacy = Some(lane_privacy_with_path(1, vec![Some(sibling)]));
    let canonical = norito::json::to_json(&attachment).expect("canonical lane attachment JSON");
    let decoded = norito::json::from_str::<ProofAttachment>(&canonical)
        .expect("canonical lane attachment JSON must decode");
    assert_eq!(decoded, attachment);
    let value = norito::json::parse_value(&canonical).expect("canonical lane Value");
    let decoded = <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
        .expect("canonical lane Value must pass preflight and strict re-entry");
    assert_eq!(decoded, attachment);
    let unknown = canonical.replacen("\"leaf_index\":1", "\"shadow\":0,\"leaf_index\":1", 1);
    let error = norito::json::from_str::<ProofAttachment>(&unknown)
        .expect_err("unknown nested lane field must reject");
    assert!(error.to_string().contains("unknown fields"));
    let value = norito::json::parse_value(&unknown).expect("unknown nested lane Value");
    <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
        .expect_err("borrowed preflight must reject unknown nested lane fields");
    let duplicate = canonical.replacen(
        "\"commitment_id\":[5]",
        "\"commitment_id\":[5],\"commitment_id\":[5]",
        1,
    );
    let error = norito::json::from_str::<ProofAttachment>(&duplicate)
        .expect_err("duplicate nested lane field must reject");
    assert!(error.to_string().contains("duplicate field"));
    for malformed in [
        lane_privacy_with_path(0, Vec::new()),
        lane_privacy_with_path(0, vec![None]),
        lane_privacy_with_path(2, vec![Some(sibling)]),
        lane_privacy_with_path(
            0,
            vec![Some(sibling); crate::nexus::LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 + 1],
        ),
    ] {
        attachment.lane_privacy = Some(malformed);
        let json = norito::json::to_json(&attachment).expect("malformed lane JSON fixture");
        let error = norito::json::from_str::<ProofAttachment>(&json)
            .expect_err("malformed lane JSON must reject");
        assert!(error.to_string().contains("lane_privacy"));
        let value = norito::json::parse_value(&json).expect("malformed lane generic Value");
        <ProofAttachment as norito::json::JsonDeserialize>::json_from_value(&value)
            .expect_err("Value preflight or strict re-entry must reject malformed lane data");
    }
}

#[test]
fn proof_attachment_json_rejects_duplicate_declared_members() {
    for json in [
        r#"{
                "backend": "halo2/ipa",
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1], "bytes": [2] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
            }"#,
        r#"{
                "backend": "halo2/ipa",
                "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                "vk_ref": { "backend": "halo2/ipa", "name": "vk_1", "name": "vk_2" }
            }"#,
    ] {
        let err = norito::json::from_str::<ProofAttachment>(json)
            .expect_err("duplicate declared member must fail");
        assert!(err.to_string().contains("duplicate field"));
    }
}

#[test]
fn proof_attachment_json_rejects_malformed_fixed_hashes() {
    for (json, expected) in [
        (
            r#"{
                    "backend": "halo2/ipa",
                    "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                    "vk_commitment": [0, 1, 2]
                }"#,
            "expected 32 bytes",
        ),
        (
            r#"{
                    "backend": "halo2/ipa",
                    "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                    "vk_commitment": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                }"#,
            "exactly 32 bytes",
        ),
    ] {
        let err = norito::json::from_str::<ProofAttachment>(json)
            .expect_err("malformed vk_commitment must be rejected");
        assert!(
            err.to_string().contains(expected),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn proof_attachment_json_rejects_invalid_fixed_hash_byte() {
    let json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
            "envelope_hash": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300]
        }"#;
    let err = norito::json::from_str::<ProofAttachment>(json)
        .expect_err("out-of-range envelope_hash byte must be rejected");
    assert!(err.to_string().contains("not a valid u8"));
}

#[test]
fn proof_attachment_json_rejects_backend_mismatches() {
    let proof_backend_json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "stark/fri", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
            "vk_commitment": null,
            "envelope_hash": null,
            "lane_privacy": null
        }"#;
    let err = norito::json::from_str::<ProofAttachment>(proof_backend_json)
        .expect_err("proof backend mismatch must be rejected");
    assert!(err.to_string().contains("proof.backend"));
    let vk_backend_json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "stark/fri", "name": "vk_1" },
            "vk_commitment": null,
            "envelope_hash": null,
            "lane_privacy": null
        }"#;
    let err = norito::json::from_str::<ProofAttachment>(vk_backend_json)
        .expect_err("vk_ref backend mismatch must be rejected");
    assert!(err.to_string().contains("vk_ref.backend"));
}

#[test]
fn proof_attachment_json_rejects_nested_retired_inline_vk_fields() {
    let proof_shadow_json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3], "vk_inline": { "backend": "halo2/ipa", "bytes": [9] } },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" }
        }"#;
    let err = norito::json::from_str::<ProofAttachment>(proof_shadow_json)
        .expect_err("retired proof inline key must be rejected");
    assert!(err.to_string().contains("proof.vk_inline"));
    let vk_ref_shadow_json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "halo2/ipa", "name": "vk_1", "verifying_key_inline": "shadow" }
        }"#;
    let err = norito::json::from_str::<ProofAttachment>(vk_ref_shadow_json)
        .expect_err("retired vk_ref inline key must be rejected");
    assert!(err.to_string().contains("vk_ref.verifying_key_inline"));
}

#[test]
fn proof_attachment_json_rejects_blank_verifying_key_name() {
    let json = r#"{
            "backend": "halo2/ipa",
            "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
            "vk_ref": { "backend": "halo2/ipa", "name": "   " },
            "vk_commitment": null,
            "envelope_hash": null,
            "lane_privacy": null
        }"#;
    let err = norito::json::from_str::<ProofAttachment>(json)
        .expect_err("blank verifying key names must be rejected");
    assert!(err.to_string().contains("vk_ref.name"));
}

#[test]
fn proof_attachment_json_rejects_blank_backend_fields() {
    let cases = [
        (
            r#"{
                    "backend": "   ",
                    "proof": { "backend": "   ", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "   ", "name": "vk_1" },
                    "vk_commitment": null,
                    "envelope_hash": null,
                    "lane_privacy": null
                }"#,
            "backend",
        ),
        (
            r#"{
                    "backend": "halo2/ipa",
                    "proof": { "backend": "   ", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                    "vk_commitment": null,
                    "envelope_hash": null,
                    "lane_privacy": null
                }"#,
            "proof.backend",
        ),
        (
            r#"{
                    "backend": "halo2/ipa",
                    "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "   ", "name": "vk_1" },
                    "vk_commitment": null,
                    "envelope_hash": null,
                    "lane_privacy": null
                }"#,
            "vk_ref.backend",
        ),
    ];
    for (json, expected_field) in cases {
        let err = norito::json::from_str::<ProofAttachment>(json)
            .expect_err("blank backend fields must be rejected");
        assert!(
            err.to_string().contains(expected_field),
            "expected error to mention {expected_field}, got {err}"
        );
    }
}

#[test]
fn proof_attachment_json_rejects_nonportable_refs_empty_proofs_and_zero_hashes() {
    let zero_hash = "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]";
    let mut forged_hash = proof_bytes_hash(&[1, 2, 3]);
    forged_hash[0] ^= 0x80;
    let forged_hash = hash_json(&forged_hash);
    let cases = [
        (
            r#"{
                    "backend": "Halo2/ipa",
                    "proof": { "backend": "Halo2/ipa", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "Halo2/ipa", "name": "vk_1" },
                    "vk_commitment": null,
                    "envelope_hash": null,
                    "lane_privacy": null
                }"#
            .to_owned(),
            "vk_ref",
        ),
        (
            r#"{
                    "backend": "halo2/ipa",
                    "proof": { "backend": "halo2/ipa", "bytes": [1, 2, 3] },
                    "vk_ref": { "backend": "halo2/ipa", "name": "Vk_1" },
                    "vk_commitment": null,
                    "envelope_hash": null,
                    "lane_privacy": null
                }"#
            .to_owned(),
            "vk_ref",
        ),
        (
            r#"{
                    "backend": "halo2/ipa",
                    "proof": { "backend": "halo2/ipa", "bytes": [] },
                    "vk_ref": { "backend": "halo2/ipa", "name": "vk_1" },
                    "vk_commitment": null,
                    "envelope_hash": null,
                    "lane_privacy": null
                }"#
            .to_owned(),
            "proof.bytes",
        ),
        (
            format!(
                r#"{{
                        "backend": "halo2/ipa",
                        "proof": {{ "backend": "halo2/ipa", "bytes": [1, 2, 3] }},
                        "vk_ref": {{ "backend": "halo2/ipa", "name": "vk_1" }},
                        "vk_commitment": {zero_hash},
                        "envelope_hash": null,
                        "lane_privacy": null
                    }}"#
            ),
            "vk_commitment",
        ),
        (
            format!(
                r#"{{
                        "backend": "halo2/ipa",
                        "proof": {{ "backend": "halo2/ipa", "bytes": [1, 2, 3] }},
                        "vk_ref": {{ "backend": "halo2/ipa", "name": "vk_1" }},
                        "vk_commitment": null,
                        "envelope_hash": {zero_hash},
                        "lane_privacy": null
                    }}"#
            ),
            "envelope_hash",
        ),
        (
            format!(
                r#"{{
                        "backend": "halo2/ipa",
                        "proof": {{ "backend": "halo2/ipa", "bytes": [1, 2, 3] }},
                        "vk_ref": {{ "backend": "halo2/ipa", "name": "vk_1" }},
                        "vk_commitment": null,
                        "envelope_hash": {forged_hash},
                        "lane_privacy": null
                    }}"#
            ),
            "envelope_hash",
        ),
    ];
    for (json, expected_field) in cases {
        let err = norito::json::from_str::<ProofAttachment>(&json)
            .expect_err("malformed proof attachment JSON must be rejected");
        assert!(
            err.to_string().contains(expected_field),
            "expected JSON error to mention {expected_field}, got {err}"
        );
    }
}
#[test]
fn proofed_committed_tx_roundtrip() {
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![0x39; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let entrypoint = crate::transaction::TransactionEntrypoint::External(
        crate::transaction::TransactionBuilder::new_genesis(
            crate::account::AccountId::new(key.public_key().clone()),
            crate::transaction::FeePaymentIntent::authority(vec![], None),
        )
        .sign(key.private_key()),
    );
    let output = crate::block::output_test_support::network(
        0,
        Err(
            crate::transaction::error::TransactionRejectionReason::Validation(
                crate::ValidationFail::NotPermitted("not permitted".into()),
            ),
        ),
    );
    let base = crate::query::CommittedTransaction {
        block_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"carrier",
        )),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: iroha_crypto::MerkleProof::from_audit_path(0, vec![]),
        entrypoint,
        output_hash: iroha_crypto::HashOf::new(&output),
        output_proof: iroha_crypto::MerkleProof::from_audit_path(0, vec![]),
        output,
    };
    let pct = ProofedCommittedTransaction::new(
        base,
        Some(ProofBox::new("halo2/ipa".into(), vec![1, 2, 3, 4])),
    );
    let enc = norito::to_bytes(&pct).unwrap();
    let dec: ProofedCommittedTransaction = norito::decode_from_bytes(&enc).unwrap();
    assert_eq!(dec, pct);
    assert!(dec.proof.is_some());
}
#[test]
fn proof_record_roundtrip() {
    let id = ProofId {
        backend: "halo2/ipa".into(),
        proof_hash: [0xAA; 32],
    };
    let rec = ProofRecord {
        id,
        vk_ref: Some(VerifyingKeyId::new("halo2/ipa", "vk")),
        vk_commitment: Some([0x55; 32]),
        status: ProofStatus::Verified,
        verified_at_height: Some(42),
        bridge: None,
    };
    let enc = norito::to_bytes(&rec).expect("encode");
    let arch = norito::from_bytes::<ProofRecord>(&enc).expect("archived");
    let dec: ProofRecord = norito::core::DeserializePayload::deserialize(arch);
    assert!(matches!(dec.status, ProofStatus::Verified));
    assert_eq!(dec.verified_at_height, Some(42));
}
#[test]
fn take_len_prefixed_slice_rejects_fields_beyond_cap() {
    let mut encoded = Vec::new();
    ncore::write_len_header_to_vec(&mut encoded, (MAX_BACKEND_FIELD_BYTES as u64) + 1);
    let mut offset = 0usize;
    let result = take_len_prefixed_slice(&encoded, &mut offset, MAX_BACKEND_FIELD_BYTES);
    assert!(matches!(result, Err(ncore::Error::LengthMismatch)));
}
/// Longest name whose compact length prefix and bytes fill exactly `field_len` bytes.
fn name_len_filling_field(field_len: usize) -> usize {
    let mut name_len = field_len;
    while ncore::varint_len_prefix_len(name_len) + name_len > field_len {
        name_len -= 1;
    }
    assert_eq!(ncore::varint_len_prefix_len(name_len) + name_len, field_len);
    name_len
}
#[test]
fn verifying_key_reference_fields_accept_the_limit_and_reject_one_over() {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    // The name of a verifying-key id is one bounded field.
    let name_at_limit = name_len_filling_field(MAX_REF_FIELD_BYTES);
    let encode_id = |name_len: usize| {
        norito::codec::Encode::encode(&VerifyingKeyId::new("halo2/ipa", "n".repeat(name_len)))
    };
    let at_limit = encode_id(name_at_limit);
    let (decoded, used) = <VerifyingKeyId as ncore::DecodeFromSlice>::decode_from_slice(&at_limit)
        .expect("name field of exactly the limit");
    assert_eq!((decoded.name.len(), used), (name_at_limit, at_limit.len()));
    assert!(matches!(
        <VerifyingKeyId as ncore::DecodeFromSlice>::decode_from_slice(&encode_id(
            name_at_limit + 1
        )),
        Err(ncore::Error::LengthMismatch)
    ));

    // The whole reference is one bounded field of a proof attachment. A
    // reference of exactly the limit passes the length gate and is then refused
    // for its content; one byte over is refused by the gate itself.
    let encode_attachment = |name_len: usize| {
        let reference = VerifyingKeyId::new("halo2/ipa", "n".repeat(name_len));
        let reference_len = norito::codec::Encode::encode(&reference).len();
        let attachment = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            reference,
        );
        (reference_len, norito::codec::Encode::encode(&attachment))
    };
    let mut name_len = MAX_REF_FIELD_BYTES;
    while encode_attachment(name_len).0 > MAX_REF_FIELD_BYTES {
        name_len -= 1;
    }
    let (reference_len, at_limit) = encode_attachment(name_len);
    assert_eq!(reference_len, MAX_REF_FIELD_BYTES);
    match <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&at_limit) {
        Err(ncore::Error::Message(message)) => {
            assert!(message.contains("vk_ref"), "{message}");
        }
        other => panic!("expected the content refusal behind the length gate, got {other:?}"),
    }
    let (reference_len, over) = encode_attachment(name_len + 1);
    assert_eq!(reference_len, MAX_REF_FIELD_BYTES + 1);
    assert!(matches!(
        <ProofAttachment as ncore::DecodeFromSlice>::decode_from_slice(&over),
        Err(ncore::Error::LengthMismatch)
    ));
}
#[test]
fn proofbox_decode_rejects_oversized_len_prefixed_payloads() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let backend_bytes = norito::to_bytes(&backend).expect("encode backend");
    let mut encoded = Vec::new();
    ncore::write_len_header_to_vec(&mut encoded, backend_bytes.len() as u64);
    encoded.extend_from_slice(&backend_bytes);
    ncore::write_len_header_to_vec(&mut encoded, (MAX_LEN_PREFIXED_FIELD_BYTES as u64) + 1);
    let result = <ProofBox as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(matches!(result, Err(ncore::Error::LengthMismatch)));
}
#[test]
fn verifying_key_box_decode_rejects_oversized_outer_field_before_decode() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let backend_bytes = norito::to_bytes(&backend).expect("encode backend");
    let mut encoded = Vec::new();
    ncore::write_len_header_to_vec(&mut encoded, backend_bytes.len() as u64);
    encoded.extend_from_slice(&backend_bytes);
    ncore::write_len_header_to_vec(
        &mut encoded,
        (VERIFYING_KEY_BOX_MAX_FIELD_BYTES_V1 as u64) + 1,
    );
    let result = <VerifyingKeyBox as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(matches!(result, Err(ncore::Error::LengthMismatch)));
}
#[test]
fn verifying_key_box_decode_rejects_oversized_declared_vector_before_allocation() {
    let backend: iroha_schema::Ident = "halo2/ipa".into();
    let backend_bytes = norito::to_bytes(&backend).expect("encode backend");
    let mut vk_field = Vec::new();
    ncore::write_seq_len(
        &mut vk_field,
        (VERIFYING_KEY_BOX_MAX_PAYLOAD_BYTES_V1 as u64) + 1,
    )
    .expect("encode declared verifier-key length");
    let mut encoded = Vec::new();
    ncore::write_len_header_to_vec(&mut encoded, backend_bytes.len() as u64);
    encoded.extend_from_slice(&backend_bytes);
    ncore::write_len_header_to_vec(&mut encoded, vk_field.len() as u64);
    encoded.extend_from_slice(&vk_field);
    let result = <VerifyingKeyBox as ncore::DecodeFromSlice>::decode_from_slice(&encoded);
    assert!(matches!(result, Err(ncore::Error::LengthMismatch)));
}
