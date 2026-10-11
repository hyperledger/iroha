//! Merkle marker identities and pre-cutover binary frame fixtures.

use iroha_crypto::{
    CompactMerkleProof, Hash, HashOf, MerkleProof, MerkleTree, MerkleTreeCommitment,
};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize, json};

#[derive(NoritoSchema)]
#[norito_schema(name = "iroha_crypto_group_01::merkle_schema_identity::OriginalMarker")]
struct OriginalMarker;

#[derive(NoritoSchema)]
#[norito_schema(name = "iroha_crypto_group_01::merkle_schema_identity::OriginalMarker")]
struct RelocatedMarker;

fn tree<T>() -> MerkleTree<T> {
    [1, 2, 3, 4, 5]
        .map(|byte| HashOf::from_untyped_unchecked(Hash::prehashed([byte; 32])))
        .into_iter()
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn record<T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>>(
    value: &T,
) -> json::Value {
    assert_eq!(T::nominal_name(), std::any::type_name::<T>());
    assert_eq!(T::frame_name(), T::nominal_name());
    let frame = norito::to_bytes(value).unwrap();
    let header = norito::core::Header::read(frame.as_slice()).unwrap();
    assert_eq!(header.schema, norito::schema::identity::frame_hash::<T>());
    let decoded: T = norito::decode_from_bytes(&frame).unwrap();
    assert_eq!(norito::to_bytes(&decoded).unwrap(), frame);
    norito::json!({
        "nominal": (std::any::type_name::<T>()),
        "frame_name": (std::any::type_name::<T>()),
        "serialize_hash": (hex(&norito::schema::identity::frame_hash::<T>())),
        "deserialize_hash": (hex(&norito::schema::identity::frame_hash::<T>())),
        "frame_hex": (hex(&frame)),
    })
}

fn current_frames() -> Vec<json::Value> {
    let tree = tree::<OriginalMarker>();
    vec![
        record(&tree.get_proof(2).unwrap()),
        record(&tree.commitment().unwrap()),
        record(&tree),
        record(
            &HashOf::<MerkleTree<OriginalMarker>>::from_untyped_unchecked(Hash::prehashed([7; 32])),
        ),
    ]
}

#[test]
fn merkle_schema_identity_frames_match_pre_declaration_goldens() {
    let expected: Vec<json::Value> =
        json::from_str(include_str!("fixtures/merkle_schema_identity_frames.json")).unwrap();
    assert_eq!(current_frames(), expected);
}

#[test]
fn merkle_schema_identity_composes_markers_without_codec_bounds() {
    use norito::schema::identity::frame_hash;
    assert_eq!(
        frame_hash::<MerkleTree<OriginalMarker>>(),
        frame_hash::<MerkleTree<RelocatedMarker>>()
    );
    assert_eq!(
        frame_hash::<MerkleProof<OriginalMarker>>(),
        frame_hash::<MerkleProof<RelocatedMarker>>()
    );
    assert_eq!(
        frame_hash::<MerkleTreeCommitment<OriginalMarker>>(),
        frame_hash::<MerkleTreeCommitment<RelocatedMarker>>()
    );
    assert_eq!(
        frame_hash::<CompactMerkleProof<OriginalMarker>>(),
        frame_hash::<CompactMerkleProof<RelocatedMarker>>()
    );
    assert_eq!(
        CompactMerkleProof::<OriginalMarker>::nominal_name(),
        std::any::type_name::<CompactMerkleProof<OriginalMarker>>()
    );
    assert_ne!(
        frame_hash::<MerkleTree<u32>>(),
        frame_hash::<MerkleTree<u64>>()
    );
    assert_ne!(
        frame_hash::<MerkleProof<u32>>(),
        frame_hash::<MerkleProof<u64>>()
    );
    assert_ne!(
        frame_hash::<MerkleTreeCommitment<u32>>(),
        frame_hash::<MerkleTreeCommitment<u64>>()
    );
    assert_ne!(
        frame_hash::<CompactMerkleProof<u32>>(),
        frame_hash::<CompactMerkleProof<u64>>()
    );
    let original = tree::<OriginalMarker>();
    let relocated = tree::<RelocatedMarker>();
    let original_frames = [
        norito::to_bytes(&original).unwrap(),
        norito::to_bytes(&original.get_proof(2).unwrap()).unwrap(),
        norito::to_bytes(&original.commitment().unwrap()).unwrap(),
    ];
    let relocated_frames = [
        norito::to_bytes(&relocated).unwrap(),
        norito::to_bytes(&relocated.get_proof(2).unwrap()).unwrap(),
        norito::to_bytes(&relocated.commitment().unwrap()).unwrap(),
    ];
    assert_eq!(original_frames, relocated_frames);
    let decoded: MerkleTree<RelocatedMarker> =
        norito::decode_from_bytes(&original_frames[0]).unwrap();
    assert_eq!(norito::to_bytes(&decoded).unwrap(), original_frames[0]);
    let decoded: MerkleProof<RelocatedMarker> =
        norito::decode_from_bytes(&original_frames[1]).unwrap();
    assert_eq!(norito::to_bytes(&decoded).unwrap(), original_frames[1]);
    let decoded: MerkleTreeCommitment<RelocatedMarker> =
        norito::decode_from_bytes(&original_frames[2]).unwrap();
    assert_eq!(norito::to_bytes(&decoded).unwrap(), original_frames[2]);
    assert!(norito::decode_from_bytes::<MerkleProof<OriginalMarker>>(&original_frames[0]).is_err());
    let proof = CompactMerkleProof::try_from_full(original.get_proof(2).unwrap()).unwrap();
    assert_eq!(proof.depth(), 3);
    assert_eq!(proof.dirs(), 2);
    // The compact proof has no Norito binary codec. Its existing canonical full
    // projection verifies the same marker-only commitment without a new wire type.
    let full = proof.try_into_full().unwrap();
    assert_eq!(norito::to_bytes(&full).unwrap(), original_frames[1]);
}

#[cfg(feature = "json")]
#[test]
fn compact_merkle_schema_identity_does_not_require_marker_json_codecs() {
    let original =
        CompactMerkleProof::try_from_full(tree::<OriginalMarker>().get_proof(2).unwrap()).unwrap();
    let relocated =
        CompactMerkleProof::try_from_full(tree::<RelocatedMarker>().get_proof(2).unwrap()).unwrap();
    let text = json::to_json(&original).unwrap();
    assert_eq!(text, json::to_json(&relocated).unwrap());
    assert!(text.starts_with("{\"depth\":3,\"dirs\":2,\"siblings\":["));
    let decoded: CompactMerkleProof<RelocatedMarker> = json::from_str(&text).unwrap();
    assert_eq!(json::to_json(&decoded).unwrap(), text);
    assert_eq!(
        norito::to_bytes(&decoded.try_into_full().unwrap()).unwrap(),
        norito::to_bytes(&tree::<RelocatedMarker>().get_proof(2).unwrap()).unwrap()
    );
}
