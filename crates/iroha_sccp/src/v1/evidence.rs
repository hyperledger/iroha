//! Consensus anchors and the forgery-evidence identity (`specs/sccp.md` §3.9, §4.2.1, §4.9).
//!
//! The anchor of height `a` is `(core_hash_a, R_a)`: the Sumeragi core block hash and the
//! certified result, which is what a `CommitQC` signs as `block_hash` and `R`. Taira keeps
//! the anchors of the open chunk and one Merkle root per completed chunk of
//! [`SCCP_ANCHOR_CHUNK`] heights:
//!
//! ```text
//! chunk(a)    = ⌊(a − 1) / 4096⌋            position(a) = (a − 1) mod 4096
//! anchor_leaf = H_iroha("sccp/anchor-leaf/v1" ‖ be64(a) ‖ core_hash ‖ R)
//! anchor_node = H_iroha("sccp/anchor-node/v1" ‖ left ‖ right)
//! chunk root  = complete binary tree over the 4 096 leaves; a path is 12 hashes, bottom-up
//! ```
//!
//! `H_iroha` is [`iroha_crypto::Hash`] (Blake2b-256 with the marker bit). Forgery evidence
//! is identified by `H_iroha("sccp/forgery-evidence/v1" ‖ be64(g) ‖ m ‖ be32(signers))`.
//!
//! This module holds the hash functions only.
//!
//! Core owns the evidence rules E0–E4 over original committed state and verified
//! certificates, including witness acquisition and source-bound refusal. Pure hash
//! helpers do not establish evidence or finality authority.

use iroha_crypto::Hash;

/// Heights per anchor chunk.
pub const SCCP_ANCHOR_CHUNK: u64 = 4096;
/// Hashes in an anchor witness path: the depth of the complete tree over one chunk.
pub const ANCHOR_PATH_LEN: usize = 12;
/// Domain tag of [`anchor_leaf`].
pub const ANCHOR_LEAF_TAG: &[u8] = b"sccp/anchor-leaf/v1";
/// Domain tag of [`anchor_node`].
pub const ANCHOR_NODE_TAG: &[u8] = b"sccp/anchor-node/v1";
/// Domain tag of [`forgery_evidence_id`].
pub const FORGERY_EVIDENCE_TAG: &[u8] = b"sccp/forgery-evidence/v1";

/// Leaves of one chunk tree.
const CHUNK_LEAVES: usize = 1 << ANCHOR_PATH_LEN;

const _: () = assert!(SCCP_ANCHOR_CHUNK == 1 << ANCHOR_PATH_LEN);

/// `anchor_leaf(a) = H_iroha("sccp/anchor-leaf/v1" ‖ be64(a) ‖ core_hash ‖ R)`.
#[must_use]
pub fn anchor_leaf(height: u64, core_hash: &[u8; 32], result: &[u8; 32]) -> [u8; 32] {
    Hash::new_from_chunks(&[ANCHOR_LEAF_TAG, &height.to_be_bytes(), core_hash, result]).into()
}

/// `anchor_node(l, r) = H_iroha("sccp/anchor-node/v1" ‖ l ‖ r)`.
#[must_use]
pub fn anchor_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Hash::new_from_chunks(&[ANCHOR_NODE_TAG, left, right]).into()
}

/// `(chunk, position)` of height `a`: `(⌊(a − 1) / 4096⌋, (a − 1) mod 4096)`.
///
/// Returns `None` for height 0, which has no anchor.
#[must_use]
pub fn anchor_chunk_position(height: u64) -> Option<(u64, usize)> {
    let index = height.checked_sub(1)?;
    // The remainder is below 4 096, so it fits every `usize`.
    let position = usize::try_from(index % SCCP_ANCHOR_CHUNK).ok()?;
    Some((index / SCCP_ANCHOR_CHUNK, position))
}

/// The first height of `chunk`, which holds heights `4096·chunk + 1 ..= 4096·(chunk + 1)`.
///
/// Returns `None` when the chunk starts above `u64::MAX`.
#[must_use]
pub const fn anchor_chunk_first_height(chunk: u64) -> Option<u64> {
    match chunk.checked_mul(SCCP_ANCHOR_CHUNK) {
        Some(below) => below.checked_add(1),
        None => None,
    }
}

/// Root of the complete binary tree over the [`anchor_leaf`] values of one completed chunk.
///
/// `leaves` are the chunk's leaves by position. Returns `None` unless there are exactly
/// [`SCCP_ANCHOR_CHUNK`] of them: an open chunk has no root.
#[must_use]
pub fn anchor_chunk_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    chunk_levels(leaves)?.pop()?.first().copied()
}

/// The witness path of `position` in a completed chunk: its 12 sibling hashes, bottom-up.
///
/// Returns `None` unless `leaves` holds exactly [`SCCP_ANCHOR_CHUNK`] leaves and `position`
/// is one of them.
#[must_use]
pub fn anchor_chunk_path(
    leaves: &[[u8; 32]],
    position: usize,
) -> Option<[[u8; 32]; ANCHOR_PATH_LEN]> {
    if position >= CHUNK_LEAVES {
        return None;
    }
    let levels = chunk_levels(leaves)?;
    let mut path = [[0_u8; 32]; ANCHOR_PATH_LEN];
    let mut index = position;
    for (sibling, level) in path.iter_mut().zip(&levels) {
        *sibling = *level.get(index ^ 1)?;
        index >>= 1;
    }
    Some(path)
}

/// The chunk root that `leaf` at `position` reaches through `path`.
///
/// Returns `None` when `position` is not a position of a chunk.
#[must_use]
pub fn anchor_path_root(
    leaf: &[u8; 32],
    position: usize,
    path: &[[u8; 32]; ANCHOR_PATH_LEN],
) -> Option<[u8; 32]> {
    if position >= CHUNK_LEAVES {
        return None;
    }
    let mut hash = *leaf;
    let mut index = position;
    for sibling in path {
        hash = if index & 1 == 0 {
            anchor_node(&hash, sibling)
        } else {
            anchor_node(sibling, &hash)
        };
        index >>= 1;
    }
    Some(hash)
}

/// Whether `leaf` at `position` hashes to the chunk root `root` through `path`
/// (the anchor lookup of §4.2.1 for a completed chunk).
#[must_use]
pub fn verify_anchor_path(
    leaf: &[u8; 32],
    position: usize,
    path: &[[u8; 32]; ANCHOR_PATH_LEN],
    root: &[u8; 32],
) -> bool {
    anchor_path_root(leaf, position, path) == Some(*root)
}

/// `H_iroha("sccp/forgery-evidence/v1" ‖ be64(g) ‖ m ‖ be32(signers))`: the identity of one
/// forged certificate, from its generation, its Commit message `m` and its `signers` field.
#[must_use]
pub fn forgery_evidence_id(generation: u64, message: &[u8; 32], signers: u32) -> [u8; 32] {
    Hash::new_from_chunks(&[
        FORGERY_EVIDENCE_TAG,
        &generation.to_be_bytes(),
        message,
        &signers.to_be_bytes(),
    ])
    .into()
}

// Every level of a chunk tree, leaves first and the root last.
fn chunk_levels(leaves: &[[u8; 32]]) -> Option<Vec<Vec<[u8; 32]>>> {
    if leaves.len() != CHUNK_LEAVES {
        return None;
    }
    let mut levels = Vec::with_capacity(ANCHOR_PATH_LEN + 1);
    levels.push(leaves.to_vec());
    while let Some(level) = levels.last()
        && level.len() > 1
    {
        let (pairs, _) = level.as_chunks::<2>();
        let next = pairs
            .iter()
            .map(|[left, right]| anchor_node(left, right))
            .collect();
        levels.push(next);
    }
    Some(levels)
}

#[cfg(test)]
mod tests {
    use norito::json::Value;
    use sha2::{Digest as _, Sha256};

    use super::{
        super::finality::{
            QcFixedV1, RESULT_TAG, X_LEN, commit_message, commit_preimage,
            vectors::{bytes, field, hex, number, reference, rows, text, word},
        },
        *,
    };

    const CORE_HASH: [u8; 32] = [0x99; 32];
    /// `R` of the §11.2 non-rotation example (height 7199).
    const R_NON_ROTATION: &str = "93d642e5cd5e489a395a937a88c63834fceaa8db9ef267e600f70ba58027c9ac";
    /// `R` of the §11.2 rotation example (height 7200).
    const R_ROTATION: &str = "3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7";
    /// `m` of the §11.2 Commit example.
    const M: &str = "85c684fac5aab78b197a5e2d40329ec518bc038abd99974a37064ea26e4943e0";

    fn word_of(hex_digits: &str) -> [u8; 32] {
        bytes(&format!("0x{hex_digits}")).try_into().unwrap()
    }

    /// Chunk 0 with the anchor `(0x99^32, 0x66^32)` at every height.
    fn uniform_chunk() -> Vec<[u8; 32]> {
        (1..=SCCP_ANCHOR_CHUNK)
            .map(|height| anchor_leaf(height, &CORE_HASH, &[0x66; 32]))
            .collect()
    }

    #[test]
    fn anchor_constants_are_pinned() {
        assert_eq!(SCCP_ANCHOR_CHUNK, 4096);
        assert_eq!(ANCHOR_PATH_LEN, 12);
        assert_eq!(ANCHOR_LEAF_TAG, b"sccp/anchor-leaf/v1");
        assert_eq!(ANCHOR_NODE_TAG, b"sccp/anchor-node/v1");
        assert_eq!(FORGERY_EVIDENCE_TAG, b"sccp/forgery-evidence/v1");
    }

    #[test]
    fn anchor_chunk_position_follows_the_height() {
        assert_eq!(anchor_chunk_position(0), None);
        assert_eq!(anchor_chunk_position(1), Some((0, 0)));
        assert_eq!(anchor_chunk_position(4096), Some((0, 4095)));
        assert_eq!(anchor_chunk_position(4097), Some((1, 0)));
        // The spec's sibling pair.
        assert_eq!(anchor_chunk_position(7199), Some((1, 3102)));
        assert_eq!(anchor_chunk_position(7200), Some((1, 3103)));
        assert_eq!(
            anchor_chunk_position(u64::MAX),
            Some(((u64::MAX - 1) / 4096, 4094))
        );

        assert_eq!(anchor_chunk_first_height(0), Some(1));
        assert_eq!(anchor_chunk_first_height(1), Some(4097));
        // The last chunk starts 4 095 heights below 2^64 and can never complete; the next
        // chunk index has no height at all.
        let last = (u64::MAX - 1) / 4096;
        assert_eq!(anchor_chunk_first_height(last), Some(u64::MAX - 4094));
        assert_eq!(anchor_chunk_first_height(last + 1), None);
        assert_eq!(anchor_chunk_first_height(u64::MAX), None);
        for chunk in [0, 1, 7, last] {
            let first = anchor_chunk_first_height(chunk).unwrap();
            assert_eq!(anchor_chunk_position(first), Some((chunk, 0)));
        }
    }

    #[test]
    fn anchor_leaf_node_and_chunk_root_match_spec() {
        let leaf_7199 = anchor_leaf(7199, &CORE_HASH, &word_of(R_NON_ROTATION));
        let leaf_7200 = anchor_leaf(7200, &CORE_HASH, &word_of(R_ROTATION));
        assert_eq!(
            hex(&leaf_7199),
            "a22346dda5d3ec12cd1308908cbbcb509f68f3b860377153ca4bae4a5f13df65"
        );
        assert_eq!(
            hex(&leaf_7200),
            "0422761979d4e89d78edd5dcfbd719b1f6e10f339603a53da14e4b1587202ed7"
        );
        // Positions 3102 and 3103 are siblings: the even one is the left child.
        assert_eq!(
            hex(&anchor_node(&leaf_7199, &leaf_7200)),
            "1d1e5d3ee82efa64b0c2703e18202b34c29bed398a688bb1626f873c2d36d1a3"
        );
        assert_ne!(
            anchor_node(&leaf_7199, &leaf_7200),
            anchor_node(&leaf_7200, &leaf_7199)
        );
        assert_eq!(
            hex(&anchor_chunk_root(&uniform_chunk()).unwrap()),
            "2367ae00d979ce576c55f1be87c6971c22921aae16c939eb9ff85b820d2e235f"
        );
        // Every output is an Iroha hash: the marker bit is set.
        for hash in [leaf_7199, leaf_7200, anchor_node(&leaf_7199, &leaf_7200)] {
            assert_eq!(hash[31] & 1, 1);
        }
        // A leaf binds its height, core hash and result.
        assert_ne!(
            leaf_7199,
            anchor_leaf(7200, &CORE_HASH, &word_of(R_NON_ROTATION))
        );
        assert_ne!(
            leaf_7199,
            anchor_leaf(7199, &[0x98; 32], &word_of(R_NON_ROTATION))
        );
        assert_ne!(
            leaf_7199,
            anchor_leaf(7199, &CORE_HASH, &word_of(R_ROTATION))
        );
    }

    #[test]
    fn anchor_chunk_root_needs_a_complete_chunk() {
        let leaves = uniform_chunk();
        assert_eq!(anchor_chunk_root(&[]), None);
        assert_eq!(anchor_chunk_root(&leaves[..4095]), None);
        assert_eq!(anchor_chunk_root(&leaves[..2048]), None);
        let mut longer = leaves.clone();
        longer.push([0; 32]);
        assert_eq!(anchor_chunk_root(&longer), None);
        assert_eq!(anchor_chunk_path(&leaves[..4095], 0), None);
        assert_eq!(anchor_chunk_path(&leaves, 4096), None);
        assert!(anchor_chunk_path(&leaves, 4095).is_some());
    }

    #[test]
    fn anchor_chunk_path_verifies_at_both_ends() {
        let leaves = uniform_chunk();
        let root = anchor_chunk_root(&leaves).unwrap();
        for position in [0, 1, 2047, 2048, 3102, 3103, 4094, 4095] {
            let path = anchor_chunk_path(&leaves, position).unwrap();
            assert_eq!(
                anchor_path_root(&leaves[position], position, &path),
                Some(root)
            );
            assert!(verify_anchor_path(
                &leaves[position],
                position,
                &path,
                &root
            ));
            // The path is positional: it fails for the neighbour and for another leaf.
            assert!(!verify_anchor_path(
                &leaves[position],
                position ^ 1,
                &path,
                &root
            ));
            assert!(!verify_anchor_path(&[0x01; 32], position, &path, &root));
            let mut tampered = path;
            tampered[ANCHOR_PATH_LEN - 1][0] ^= 1;
            assert!(!verify_anchor_path(
                &leaves[position],
                position,
                &tampered,
                &root
            ));
        }
        // The first sibling of a leaf is its neighbour's leaf.
        assert_eq!(anchor_chunk_path(&leaves, 0).unwrap()[0], leaves[1]);
        assert_eq!(anchor_chunk_path(&leaves, 4095).unwrap()[0], leaves[4094]);
        // A position outside the chunk has no root, whatever the path.
        let path = anchor_chunk_path(&leaves, 0).unwrap();
        assert_eq!(anchor_path_root(&leaves[0], 4096, &path), None);
        assert!(!verify_anchor_path(&leaves[0], 4096, &path, &root));
    }

    #[test]
    fn forgery_evidence_id_matches_spec() {
        let id = forgery_evidence_id(3, &word_of(M), 0x4000_0201);
        assert_eq!(
            hex(&id),
            "5fe24c413eba8a5e1d7727f630f9bf0c005286c75662061a8216b0292a454f35"
        );
        assert_eq!(id[31] & 1, 1);
        // The id binds the generation, the message and the signer set.
        assert_ne!(id, forgery_evidence_id(4, &word_of(M), 0x4000_0201));
        assert_ne!(id, forgery_evidence_id(3, &[0x85; 32], 0x4000_0201));
        assert_ne!(id, forgery_evidence_id(3, &word_of(M), 0x0102_0040));
    }

    /// The anchor and evidence rows of `fixtures/sccp/finality_v1.json`.
    #[test]
    fn anchors_and_evidence_ids_match_the_reference_vectors() {
        let reference = reference("finality_v1.json", "iroha.sccp.finality.v1");
        let examples = field(&reference, "worked_examples");
        let anchors = field(examples, "anchors");
        let core_hash = word(anchors, "core_hash");

        let mut leaves = Vec::new();
        for (key, height) in [("leaf_7199", 7199), ("leaf_7200", 7200)] {
            let row = field(anchors, key);
            let (chunk, position) = anchor_chunk_position(height).unwrap();
            assert_eq!(chunk, number(row, "chunk"));
            assert_eq!(u64::try_from(position), Ok(number(row, "position")));
            let leaf = anchor_leaf(height, &core_hash, &word(row, "r"));
            assert_eq!(leaf, word(row, "leaf"));
            leaves.push(leaf);
        }
        assert_eq!(
            anchor_node(&leaves[0], &leaves[1]),
            word(anchors, "node_7199_7200")
        );

        let chunk = field(anchors, "chunk0_all_99_66");
        let uniform = uniform_chunk();
        let root = word(chunk, "root");
        assert_eq!(anchor_chunk_root(&uniform), Some(root));
        for (height, leaf_key, path_key) in [
            (1_u64, "leaf_height_1", "path_height_1"),
            (4096, "leaf_height_4096", "path_height_4096"),
        ] {
            let (_, position) = anchor_chunk_position(height).unwrap();
            assert_eq!(uniform[position], word(chunk, leaf_key));
            let path = anchor_chunk_path(&uniform, position).unwrap();
            let expected: Vec<[u8; 32]> = rows(chunk, path_key)
                .iter()
                .map(|hash| bytes(hash.as_str().unwrap()).try_into().unwrap())
                .collect();
            assert_eq!(path[..], expected[..]);
            assert!(verify_anchor_path(
                &uniform[position],
                position,
                &path,
                &root
            ));
        }

        let evidence = field(examples, "forgery_evidence_id");
        assert_eq!(
            forgery_evidence_id(
                number(evidence, "generation"),
                &word(evidence, "m"),
                u32::try_from(number(evidence, "signers")).unwrap(),
            ),
            word(evidence, "id")
        );

        // The id is over the `m` a verifier derives from the wire (§4.9): `SHA-256(P)` with
        // the pinned instance, the `QC_FIXED` fields, and `X.height` and `R` of the header
        // bytes as they are. A row carries the id exactly when its `m`, the message that was
        // signed, is that value; the id is then over the generation at offset 141 of `X`,
        // that `m` and the last four bytes of `QC_FIXED`.
        let instance = word(
            field(&reference, "verification_context"),
            "consensus_instance",
        );
        let (mut checked, mut signed_another_message) = (0, Vec::new());
        for key in [
            "certificates",
            "negative_certificates",
            "flavor_specific_certificates",
        ] {
            for row in rows(&reference, key) {
                let label = text(row, "label");
                let wire = field(row, "evm");
                let header = bytes(text(wire, "header"));
                let Ok(qc) = QcFixedV1::parse(&bytes(text(wire, "qc"))) else {
                    assert!(row.get("forgery_evidence_id").is_none(), "{label}");
                    continue;
                };
                if header.len() != X_LEN {
                    assert!(row.get("forgery_evidence_id").is_none(), "{label}");
                    continue;
                }
                let result: [u8; 32] = Sha256::new()
                    .chain_update(RESULT_TAG)
                    .chain_update(&header)
                    .chain_update(qc.result_body)
                    .finalize()
                    .into();
                let height = u64::from_be_bytes(header[48..56].try_into().unwrap());
                let message = commit_message(&commit_preimage(&instance, &qc, height, &result));
                if message != word(row, "m") {
                    assert!(row.get("forgery_evidence_id").is_none(), "{label}");
                    signed_another_message.push(label);
                    continue;
                }
                let id = row.get("forgery_evidence_id").and_then(Value::as_str);
                assert_eq!(
                    forgery_evidence_id(
                        u64::from_be_bytes(header[141..149].try_into().unwrap()),
                        &message,
                        qc.signers,
                    )[..],
                    bytes(id.unwrap_or_else(|| panic!("{label} carries no evidence id")))[..],
                    "{label}"
                );
                checked += 1;
            }
        }
        // The rows whose signature covers another message than the one their wire names.
        assert_eq!(
            signed_another_message,
            [
                "prepare_kind",
                "wrong_instance",
                "signed_height_mismatch",
                "tampered_x"
            ]
        );
        assert!(checked >= 13, "only {checked} rows carry an evidence id");
    }
}
