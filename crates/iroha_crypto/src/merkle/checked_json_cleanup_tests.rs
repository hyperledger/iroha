//! Manual crypto JSON cleanup preserves original output and retained leaf graph.

use crate::{Algorithm, CompactMerkleProof, Hash, HashOf, KeyPair, MerkleProof, MerkleTree};
use norito::json::{self, BoundedJsonError, JsonSerialize, JsonWriteSink};
use std::collections::BTreeSet;

const INHERITED_DEPTH: usize = 7;
const ASSERTION: &str = "owning manual JSON writers must restore the original inherited sink depth";
struct TrackingSink {
    output: String,
    limit: usize,
    depth: usize,
    depth_limit: Option<usize>,
}
impl TrackingSink {
    fn new(limit: usize) -> Self {
        Self {
            output: String::new(),
            limit,
            depth: INHERITED_DEPTH,
            depth_limit: None,
        }
    }
}
impl JsonWriteSink for TrackingSink {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.push_str(value.encode_utf8(&mut [0; 4]))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        if self
            .output
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.output.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if self.depth_limit.is_some_and(|n| next >= n) {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        assert!(
            self.depth > INHERITED_DEPTH,
            "writer must not release inherited levels"
        );
        self.depth -= 1;
    }
}
fn audit(value: &impl JsonSerialize, label: &str, defects: &mut Vec<String>) {
    let ordinary = json::to_json(value).expect("ordinary original serializer");
    let mut changed = BTreeSet::new();
    for limit in 0..ordinary.len() {
        let mut sink = TrackingSink::new(limit);
        assert_eq!(
            value.json_serialize_to(&mut sink),
            Err(BoundedJsonError::BodyTooLarge)
        );
        if sink.depth != INHERITED_DEPTH {
            changed.insert(sink.depth);
        }
    }
    let mut sink = TrackingSink::new(ordinary.len());
    assert_eq!(value.json_serialize_to(&mut sink), Ok(()));
    assert_eq!(sink.output, ordinary);
    assert_eq!(sink.depth, INHERITED_DEPTH);
    let mut sink = TrackingSink::new(usize::MAX);
    sink.depth_limit = Some(INHERITED_DEPTH + 1);
    assert_eq!(
        value.json_serialize_to(&mut sink),
        Err(BoundedJsonError::Unsupported)
    );
    assert!(sink.output.is_empty());
    assert_eq!(sink.depth, INHERITED_DEPTH);
    println!(
        "shape={label}; exact byte refusals={}; changed depths={changed:?}",
        ordinary.len()
    );
    if !changed.is_empty() {
        defects.push(format!("{label}: {changed:?}"));
    }
}
fn complete(defects: &[String]) {
    assert!(defects.is_empty(), "{ASSERTION}: {defects:?}");
}
fn tree() -> MerkleTree<u64> {
    [
        HashOf::<u64>::from_untyped_unchecked(Hash::new(b"manual cleanup leaf one")),
        HashOf::<u64>::from_untyped_unchecked(Hash::new(b"manual cleanup leaf two")),
    ]
    .into_iter()
    .collect()
}
#[test]
fn original_key_pair_refusal_preserves_inherited_depth() {
    let value = KeyPair::from_seed(vec![17; 32], Algorithm::Ed25519);
    let mut defects = Vec::new();
    audit(&value, "KeyPair Ed25519", &mut defects);
    complete(&defects);
}
#[test]
fn original_merkle_commitment_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(
        &tree().commitment().unwrap(),
        "MerkleTreeCommitment",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_merkle_tree_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(&tree(), "MerkleTree populated", &mut defects);
    audit(
        &MerkleTree::<u64>::default(),
        "MerkleTree empty",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_merkle_proof_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(
        &tree().get_proof(0).unwrap(),
        "MerkleProof populated",
        &mut defects,
    );
    audit(
        &MerkleProof::<u64>::from_audit_path(0, vec![]),
        "MerkleProof empty",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_compact_merkle_proof_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(
        &CompactMerkleProof::try_from_full(tree().get_proof(0).unwrap()).unwrap(),
        "CompactMerkleProof populated",
        &mut defects,
    );
    audit(
        &CompactMerkleProof::<u64>::from_parts(0, 0, vec![]),
        "CompactMerkleProof empty",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_merkle_nested_begin_refusal_preserves_inherited_depth() {
    let mut sink = TrackingSink::new(usize::MAX);
    sink.depth_limit = Some(INHERITED_DEPTH + 2);
    assert_eq!(
        tree().json_serialize_to(&mut sink),
        Err(BoundedJsonError::Unsupported)
    );
    assert_eq!(
        sink.depth, INHERITED_DEPTH,
        "{ASSERTION}: original nested begin refusal"
    );
}

#[test]
fn invalid_merkle_cache_retains_the_exact_rejected_shape_and_balanced_depth() {
    let mut value = tree();
    value.nodes[0] = Some(HashOf::from_untyped_unchecked(Hash::new(
        b"changed cached root",
    )));
    assert!(value.serialized_view().is_err());
    assert_eq!(
        json::to_json(&value).unwrap(),
        r#"{"hash_scheme":0,"leaves":[]}"#
    );
    let pointer = value.nodes.as_ptr();
    let bytes = value.allocated_bytes();
    let mut defects = Vec::new();
    audit(&value, "invalid cached Merkle tree", &mut defects);
    complete(&defects);
    let mut sink = TrackingSink::new(usize::MAX);
    sink.depth_limit = Some(INHERITED_DEPTH + 2);
    assert_eq!(
        value.json_serialize_to(&mut sink),
        Err(BoundedJsonError::Unsupported)
    );
    assert_eq!(sink.depth, INHERITED_DEPTH);
    assert_eq!(value.nodes.as_ptr(), pointer);
    assert_eq!(value.allocated_bytes(), bytes);
    assert!(value.serialized_view().is_err());
}
#[test]
fn checked_merkle_refusals_do_not_replace_the_original_node_allocation() {
    let value = tree();
    let pointer = value.nodes.as_ptr();
    let bytes = value.allocated_bytes();
    let mut defects = Vec::new();
    audit(&value, "original node allocation", &mut defects);
    complete(&defects);
    assert_eq!(value.nodes.as_ptr(), pointer);
    assert_eq!(value.allocated_bytes(), bytes);
}
