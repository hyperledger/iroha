//! Cross-field structural consistency of one complete native-generation snapshot cut.
//!
//! Current and original undo cuts are checked separately. Passing these checks never grants
//! finality authority: original signed-genesis and certified-history replay remains required.

use iroha_data_model::sccp::committee::SccpCommitteeGenerationV1;

/// Check already structurally validated rows without cloning a map or generation graph.
pub(crate) fn validate_cut<'a>(
    exists: bool,
    current: u64,
    lc: u64,
    degraded_run: u32,
    rows: impl IntoIterator<Item = (&'a u64, &'a SccpCommitteeGenerationV1)>,
) -> Result<(), &'static str> {
    if !exists && (current != 0 || lc != 0 || degraded_run != 0) {
        return Err("absent SCCP has native generation state");
    }
    if exists && current == 0 {
        return Err("initialized SCCP has no current generation");
    }
    let mut found_current = false;
    for (key, record) in rows {
        if !exists || *key != record.generation || *key == 0 || *key > current {
            return Err("generation coordinate disagrees with the current cut");
        }
        if record.start_lc > lc {
            return Err("generation begins after this cut's liability clock");
        }
        if *key == current {
            if found_current || record.end.is_some() || record.dest_cleared_lc.is_some() {
                return Err("current generation is duplicate, ended or destination-cleared");
            }
            found_current = true;
        } else if record.end.is_none() {
            return Err("retained predecessor generation has no immutable end");
        }
        if record.dest_cleared_lc.is_some_and(|cleared| cleared > lc) {
            return Err("destination clearance is after this cut's liability clock");
        }
    }
    if exists && !found_current {
        return Err("current generation is absent from its original map");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sccp::committee::{SccpGenerationCauseV1, SccpGenerationEndV1};

    // Key validity belongs to the caller's per-record structural decoder, tested separately.
    fn row(generation: u64) -> SccpCommitteeGenerationV1 {
        SccpCommitteeGenerationV1 {
            generation,
            committee_root: [1; 32],
            keys: vec![],
            members: vec![],
            cause: SccpGenerationCauseV1::Heartbeat,
            start_height: 2,
            start_timestamp_ms: 10,
            start_lc: 10,
            validity_ms: 100,
            deadline_ms: 110,
            grace_ms: 100,
            progress_cap_ms: 100,
            liable_until_lc: 210,
            dest_cleared_lc: None,
            end: None,
        }
    }
    #[test]
    fn both_empty_pre_genesis_and_open_current_cut_are_structurally_valid() {
        assert_eq!(validate_cut(false, 0, 0, 0, []), Ok(()));
        assert_eq!(validate_cut(true, 2, 10, 0, [(&2, &row(2))]), Ok(()));
        assert!(validate_cut(true, 2, 10, 0, []).is_err());
        assert!(validate_cut(false, 0, 0, 0, [(&2, &row(2))]).is_err());
        assert!(validate_cut(false, 0, 1, 0, []).is_err());
        assert!(validate_cut(true, 0, 0, 0, []).is_err());
    }
    #[test]
    fn predecessor_lifecycle_and_cut_coordinates_cannot_be_mixed() {
        let mut old = row(1);
        let current = row(2);
        assert!(validate_cut(true, 2, 10, 0, [(&1, &old), (&2, &current)]).is_err());
        old.end = Some(SccpGenerationEndV1 {
            end_height: 2,
            end_timestamp_ms: 10,
            next_committee_root: [1; 32],
            successor_validity_ms: 100,
        });
        assert_eq!(
            validate_cut(true, 2, 10, 0, [(&1, &old), (&2, &current)]),
            Ok(())
        );
        assert!(validate_cut(true, 1, 10, 0, [(&1, &old)]).is_err());
        assert!(validate_cut(true, 2, 9, 0, [(&1, &old), (&2, &current)]).is_err());
        assert!(validate_cut(true, 2, 10, 0, [(&1, &current), (&2, &current)]).is_err());
        old.dest_cleared_lc = Some(11);
        assert!(validate_cut(true, 2, 10, 0, [(&1, &old), (&2, &current)]).is_err());
    }
}
