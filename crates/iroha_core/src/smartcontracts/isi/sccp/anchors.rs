//! Exact anchor lookup for native forgery verification over retained original history.
use iroha_data_model::sccp::generation::SccpAnchorV1;
use iroha_sccp::v1::evidence::{
    ANCHOR_PATH_LEN, SCCP_ANCHOR_CHUNK, anchor_chunk_position, anchor_leaf, verify_anchor_path,
};

/// Why an anchor cannot be recovered from the exact parent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpAnchorLookupError {
    /// The height is zero, after the parent, or inconsistent with the parent-state layout.
    InvalidHeight,
    /// A completed chunk needs the caller's original anchor and 12 sibling hashes.
    WitnessRequired,
    /// The witness does not reach the retained chunk root.
    BadWitness,
    /// The completed chunk root has been pruned.
    EvidenceExpired,
}

/// Recover an anchor from the parent tip, the open chunk, or a retained completed root.
///
/// `parent_height` and `parent_anchor` come from the authenticated native execution tip.
/// `completed_root` is the stored root for the queried height's chunk, if retained; it is
/// consulted only for completed chunks. Supplying a witness never overrides a tip or open
/// anchor. There is no fallback from an unavailable root to unauthenticated witness bytes.
///
/// # Errors
///
/// Returns the precise height, retention or witness refusal above.
pub fn lookup_anchor(
    parent_height: u64,
    parent_anchor: SccpAnchorV1,
    open: &[SccpAnchorV1],
    height: u64,
    completed_root: Option<&[u8; 32]>,
    witness: Option<(&SccpAnchorV1, &[[u8; 32]; ANCHOR_PATH_LEN])>,
) -> Result<SccpAnchorV1, SccpAnchorLookupError> {
    let (chunk, position) = anchor_chunk_position(height)
        .filter(|_| height <= parent_height)
        .ok_or(SccpAnchorLookupError::InvalidHeight)?;
    // At the parent tip, A1 has appended only heights through parent_height - 1.
    let (open_chunk, expected_open_len) =
        anchor_chunk_position(parent_height).ok_or(SccpAnchorLookupError::InvalidHeight)?;
    if open.len() != expected_open_len || open.len() >= SCCP_ANCHOR_CHUNK as usize {
        return Err(SccpAnchorLookupError::InvalidHeight);
    }
    if height == parent_height {
        return Ok(parent_anchor);
    }
    if chunk == open_chunk {
        return open
            .get(position)
            .copied()
            .ok_or(SccpAnchorLookupError::InvalidHeight);
    }
    let root = completed_root.ok_or(SccpAnchorLookupError::EvidenceExpired)?;
    let (anchor, path) = witness.ok_or(SccpAnchorLookupError::WitnessRequired)?;
    let leaf = anchor_leaf(height, &anchor.core_hash, &anchor.result);
    if !verify_anchor_path(&leaf, position, path, root) {
        return Err(SccpAnchorLookupError::BadWitness);
    }
    Ok(*anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_sccp::v1::evidence::{anchor_chunk_path, anchor_chunk_root};
    fn anchor(seed: u8) -> SccpAnchorV1 {
        SccpAnchorV1 {
            core_hash: [seed; 32],
            result: [seed.wrapping_add(1); 32],
        }
    }

    #[test]
    fn anchor_roundtrip_preserves_both_original_native_identities() {
        let original = anchor(7);
        let frame = norito::to_bytes(&original).unwrap();
        let decoded = norito::decode_from_bytes::<SccpAnchorV1>(&frame).unwrap();
        assert_eq!(decoded.core_hash, [7; 32]);
        assert_eq!(decoded.result, [8; 32]);
        let json = norito::json::to_json(&original).unwrap();
        assert_eq!(
            norito::json::from_json::<SccpAnchorV1>(&json).unwrap(),
            original
        );
    }

    #[test]
    fn tip_and_open_chunk_use_only_the_original_parent_state() {
        let open = [anchor(1), anchor(2)];
        let fake = anchor(9);
        let witness = Some((&fake, &[[0; 32]; ANCHOR_PATH_LEN]));
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 3, None, witness),
            Ok(anchor(3))
        );
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 1, None, witness),
            Ok(anchor(1))
        );
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 0, None, None),
            Err(SccpAnchorLookupError::InvalidHeight)
        );
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 4, None, None),
            Err(SccpAnchorLookupError::InvalidHeight)
        );
    }

    #[test]
    fn incomplete_open_state_never_relabels_missing_anchors_as_absent() {
        assert_eq!(
            lookup_anchor(3, anchor(3), &[anchor(1)], 1, None, None),
            Err(SccpAnchorLookupError::InvalidHeight)
        );
    }

    #[test]
    fn completed_chunk_requires_a_retained_root_and_exact_path() {
        let original = anchor(7);
        let leaves = (1..=SCCP_ANCHOR_CHUNK)
            .map(|height| anchor_leaf(height, &original.core_hash, &original.result))
            .collect::<Vec<_>>();
        let root = anchor_chunk_root(&leaves).unwrap();
        let path = anchor_chunk_path(&leaves, 0).unwrap();
        let parent_height = SCCP_ANCHOR_CHUNK + 1;
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                Some(&root),
                Some((&original, &path))
            ),
            Ok(original)
        );
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                None,
                Some((&original, &path))
            ),
            Err(SccpAnchorLookupError::EvidenceExpired)
        );
        assert_eq!(
            lookup_anchor(parent_height, anchor(8), &[], 1, Some(&root), None),
            Err(SccpAnchorLookupError::WitnessRequired)
        );
        let mut changed = original;
        changed.result[0] ^= 1;
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                Some(&root),
                Some((&changed, &path))
            ),
            Err(SccpAnchorLookupError::BadWitness)
        );
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                2,
                Some(&root),
                Some((&original, &path))
            ),
            Err(SccpAnchorLookupError::BadWitness)
        );
        let mut changed_path = path;
        changed_path[11][0] ^= 1;
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                Some(&root),
                Some((&original, &changed_path))
            ),
            Err(SccpAnchorLookupError::BadWitness)
        );
    }

    #[test]
    fn last_height_of_open_chunk_stays_the_tip_until_the_next_append() {
        let open = vec![anchor(1); SCCP_ANCHOR_CHUNK as usize - 1];
        assert_eq!(
            lookup_anchor(
                SCCP_ANCHOR_CHUNK,
                anchor(2),
                &open,
                SCCP_ANCHOR_CHUNK,
                None,
                None
            ),
            Ok(anchor(2))
        );
        assert_eq!(
            lookup_anchor(
                SCCP_ANCHOR_CHUNK,
                anchor(2),
                &open,
                SCCP_ANCHOR_CHUNK - 1,
                None,
                None
            ),
            Ok(anchor(1))
        );
    }
}
