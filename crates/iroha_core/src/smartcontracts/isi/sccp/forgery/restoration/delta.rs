//! Borrowed canonical SCCP delta selection; parsing alone grants no authority.
use norito::{codec::DecodeAll, core::SerializePayload};

// Exact writer order in WorldBlock::write_sccp_execution_delta. Retired/unknown
// names have no decoder. Other fields are structurally skipped, never defaulted.
const NAMES: &[(&[u8], bool)] = &[
    (b"sccp_parameters", false),
    (b"sccp_reset_nonce", false),
    (b"sccp_forgery_max_generation", false),
    (b"sccp_history", false),
    (b"sccp_committee_current", false),
    (b"sccp_liability_clock", false),
    (b"sccp_degraded_run", false),
    (b"sccp_anchor_open", false),
    (b"sccp_pause_panel", false),
    (b"sccp_forgery_offences", true),
    (b"sccp_block_leaves", true),
    (b"sccp_block_commitments", true),
    (b"sccp_history_leaves", true),
    (b"sccp_committee_generations", true),
    (b"sccp_anchor_chunks", true),
    (b"sccp_outbound_messages", true),
    (b"sccp_outbound_by_nonce", true),
    (b"sccp_control_messages", true),
    (b"sccp_fast_pauses", true),
    (b"sccp_fast_pause_suspended_until_ms", true),
    (b"sccp_fast_pause_rounds", true),
    (b"sccp_routes", true),
    (b"sccp_destination_words", true),
    (b"sccp_governance_revisions", true),
    (b"sccp_inbound_messages", true),
    (b"sccp_pending_counts", true),
    (b"sccp_light_clients", true),
    (b"sccp_light_client_sets", true),
    (b"sccp_light_client_checkpoints", true),
    (b"sccp_light_client_stride_index", true),
    (b"sccp_light_client_profiles", true),
];
#[derive(Clone, Copy)]
pub(super) struct Entry<'a> {
    pub(super) name: &'a [u8],
    pub(super) key: Option<&'a [u8]>,
    pub(super) value: Option<&'a [u8]>,
}
fn count(input: &mut &[u8]) -> Result<usize, norito::Error> {
    let value = input.get(..8).ok_or(norito::Error::LengthMismatch)?;
    let n = usize::try_from(u64::from_le_bytes(value.try_into().expect("eight bytes")))
        .map_err(|_| norito::Error::LengthMismatch)?;
    *input = &input[8..];
    Ok(n)
}
fn component<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], norito::Error> {
    let n = count(input)?;
    let value = input.get(..n).ok_or(norito::Error::LengthMismatch)?;
    *input = &input[n..];
    Ok(value)
}
pub(super) fn visit<'a, E: From<norito::Error> + From<norito::core::DecodeAttemptError>>(
    mut bytes: &'a [u8],
    mut f: impl FnMut(Entry<'a>) -> Result<(), E>,
) -> Result<(), E> {
    let mut next = 0;
    while !bytes.is_empty() {
        let name = component(&mut bytes)?;
        let offset = NAMES[next..]
            .iter()
            .position(|(known, _)| *known == name)
            .ok_or(norito::Error::NonCanonicalEncoding)?;
        let index = next + offset;
        next = index + 1;
        if !NAMES[index].1 {
            f(Entry {
                name,
                key: None,
                value: Some(component(&mut bytes)?),
            })?;
            continue;
        }
        let n = count(&mut bytes)?;
        if n > bytes.len() / 9 {
            return Err(norito::Error::NonCanonicalEncoding.into());
        }
        let mut previous_u64 = None;
        for _ in 0..n {
            let key = component(&mut bytes)?;
            let tag = *bytes.first().ok_or(norito::Error::LengthMismatch)?;
            bytes = &bytes[1..];
            let value = match tag {
                0 => None,
                1 => Some(component(&mut bytes)?),
                _ => return Err(norito::Error::NonCanonicalEncoding.into()),
            };
            // The two consumed scalar-key maps have exact semantic order checked here.
            // Offence tuples are checked against original owned keys by the reducer. Other
            // fields are structurally skipped: this parser claims no unchecked typed order.
            if name == b"sccp_committee_generations" || name == b"sccp_anchor_chunks" {
                let current: u64 = fixed(key)?;
                if previous_u64.is_some_and(|previous| previous >= current) {
                    return Err(norito::Error::NonCanonicalEncoding.into());
                }
                previous_u64 = Some(current);
            }
            f(Entry {
                name,
                key: Some(key),
                value,
            })?;
        }
    }
    Ok(())
}
/// Locate one complete canonical field once per pending carrier. Offence queries then
/// scan only that field, independent of unrelated message/route/archive delta volume.
pub(super) fn field_range(
    mut bytes: &[u8],
    selected: &[u8],
) -> Result<Option<(usize, usize)>, norito::Error> {
    let length = bytes.len();
    let mut next = 0usize;
    let mut found = None;
    while !bytes.is_empty() {
        let start = length - bytes.len();
        let name = component(&mut bytes)?;
        let offset = NAMES[next..]
            .iter()
            .position(|(known, _)| *known == name)
            .ok_or(norito::Error::NonCanonicalEncoding)?;
        let index = next + offset;
        next = index + 1;
        if NAMES[index].1 {
            let n = count(&mut bytes)?;
            if n > bytes.len() / 9 {
                return Err(norito::Error::NonCanonicalEncoding);
            }
            for _ in 0..n {
                component(&mut bytes)?;
                let tag = *bytes.first().ok_or(norito::Error::LengthMismatch)?;
                bytes = &bytes[1..];
                match tag {
                    0 => {}
                    1 => {
                        component(&mut bytes)?;
                    }
                    _ => return Err(norito::Error::NonCanonicalEncoding),
                }
            }
        } else {
            component(&mut bytes)?;
        }
        if name == selected {
            found = Some((start, length - bytes.len()));
        }
    }
    Ok(found)
}
/// Exact current bare Norito payload; used only with fixed-size scalar/parameter types.
pub(super) fn fixed<T: DecodeAll + SerializePayload>(
    bytes: &[u8],
) -> Result<T, norito::core::DecodeAttemptError> {
    norito::core::classify_decode_attempt(|| {
        let value = T::decode_all(&mut &*bytes)?;
        norito::codec::verify_exact_payload(&value, bytes)?;
        Ok(value)
    })
}
/// Streaming equality with the exact writer codec; no key/account clone or encoding Vec.
pub(super) fn matches<T: SerializePayload>(value: &T, bytes: &[u8]) -> bool {
    struct Exact<'a>(&'a [u8]);
    impl std::io::Write for Exact<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.0.starts_with(bytes) {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            self.0 = &self.0[bytes.len()..];
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut exact = Exact(bytes);
    norito::codec::encode_adaptive_into(value, &mut exact).is_ok() && exact.0.is_empty()
}
/// A selected deletion differs from no update. Repeated matching rows are refused.
pub(super) fn select<'a>(
    bytes: &'a [u8],
    name: &[u8],
    key: Option<&dyn Fn(&[u8]) -> bool>,
) -> Result<Option<Option<&'a [u8]>>, super::Error> {
    let mut found = None;
    visit::<super::Error>(bytes, |entry| {
        if entry.name == name
            && match (entry.key, key) {
                (None, None) => true,
                (Some(bytes), Some(test)) => test(bytes),
                _ => false,
            }
        {
            if found.is_some() {
                return Err(norito::Error::NonCanonicalEncoding.into());
            }
            found = Some(entry.value);
        }
        Ok(())
    })?;
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::Encode as _;
    fn component(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
        out.extend_from_slice(bytes);
    }
    fn cell(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        component(&mut out, name);
        component(&mut out, value);
        out
    }
    #[test]
    fn exact_cells_require_current_order_complete_bytes_and_payload() {
        let first = cell(b"sccp_committee_current", &7_u64.encode());
        let second = cell(b"sccp_liability_clock", &9_u64.encode());
        let mut joined = first.clone();
        joined.extend_from_slice(&second);
        assert_eq!(
            fixed::<u64>(
                select(&joined, b"sccp_committee_current", None)
                    .unwrap()
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            7
        );
        assert_eq!(select(&joined, b"sccp_anchor_open", None).unwrap(), None);
        let mut reversed = second;
        reversed.extend_from_slice(&first);
        assert!(select(&reversed, b"sccp_committee_current", None).is_err());
        let mut duplicate = first.clone();
        duplicate.extend_from_slice(&first);
        assert!(select(&duplicate, b"sccp_committee_current", None).is_err());
        assert!(
            select(
                &cell(b"sccp_rosters", &7_u64.encode()),
                b"sccp_committee_current",
                None
            )
            .is_err()
        );
        for end in 1..first.len() {
            assert!(select(&first[..end], b"sccp_committee_current", None).is_err());
        }
        assert!(!matches(&8_u64, &7_u64.encode()));
        assert!(fixed::<u64>(&[0]).is_err());
    }
    #[test]
    fn map_deletion_unknown_tags_and_duplicate_keys_are_not_absence() {
        let mut data = Vec::new();
        component(&mut data, b"sccp_anchor_chunks");
        data.extend_from_slice(&1_u64.to_le_bytes());
        component(&mut data, &3_u64.encode());
        data.push(0);
        assert_eq!(
            select(
                &data,
                b"sccp_anchor_chunks",
                Some(&|bytes| matches(&3_u64, bytes))
            )
            .unwrap(),
            Some(None)
        );
        assert_eq!(
            select(
                &data,
                b"sccp_anchor_chunks",
                Some(&|bytes| matches(&4_u64, bytes))
            )
            .unwrap(),
            None
        );
        let last = data.len() - 1;
        data[last] = 2;
        assert!(select(&data, b"sccp_anchor_chunks", None).is_err());
        data[last] = 0;
        let mut duplicate = Vec::new();
        component(&mut duplicate, b"sccp_anchor_chunks");
        duplicate.extend_from_slice(&2_u64.to_le_bytes());
        for _ in 0..2 {
            component(&mut duplicate, &3_u64.encode());
            duplicate.push(0);
        }
        assert!(select(&duplicate, b"sccp_anchor_chunks", None).is_err());
        let mut huge = Vec::new();
        component(&mut huge, b"sccp_anchor_chunks");
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(select(&huge, b"sccp_anchor_chunks", None).is_err());
    }
    fn map(name: &[u8], keys: impl IntoIterator<Item = u64>) -> Vec<u8> {
        let keys: Vec<_> = keys.into_iter().collect();
        let mut out = Vec::new();
        component(&mut out, name);
        out.extend_from_slice(&u64::try_from(keys.len()).unwrap().to_le_bytes());
        for key in keys {
            component(&mut out, &key.encode());
            out.push(1);
            component(&mut out, &[0xA5_u8; 32].encode());
        }
        out
    }

    #[test]
    fn large_consumed_map_visits_each_row_once_and_rejects_typed_order_changes() {
        const ROWS: u64 = 4096;
        let bytes = map(b"sccp_anchor_chunks", 0..ROWS);
        let mut seen = 0u64;
        visit::<super::super::Error>(&bytes, |entry| {
            assert_eq!(entry.name, b"sccp_anchor_chunks");
            assert_eq!(fixed::<u64>(entry.key.unwrap())?, seen);
            assert_eq!(fixed::<[u8; 32]>(entry.value.unwrap())?, [0xA5; 32]);
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ROWS);
        // Strict semantic u64 order (not lexicographic encoded bytes) crosses 255/256.
        assert!(
            select(
                &map(b"sccp_anchor_chunks", [255, 256]),
                b"sccp_anchor_chunks",
                None
            )
            .is_ok()
        );
        for keys in [vec![255, 256, 255], vec![0, 1, 1], vec![2, 1, 3]] {
            assert!(
                visit::<super::super::Error>(&map(b"sccp_anchor_chunks", keys), |_| Ok(()))
                    .is_err()
            );
        }
        let mut visits = 0u64;
        let duplicate_tail = map(b"sccp_committee_generations", (0..ROWS).chain([ROWS - 1]));
        assert!(
            visit::<super::super::Error>(&duplicate_tail, |_| {
                visits += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(
            visits, ROWS,
            "invalid duplicate is rejected before its callback"
        );
    }

    #[test]
    fn offence_field_range_excludes_large_unrelated_maps_and_refuses_bad_framing() {
        let prefix = cell(b"sccp_liability_clock", &7_u64.encode());
        // Raw keys here exercise structural field selection only, never offence authority.
        let selected = map(b"sccp_forgery_offences", 0..3);
        let mut suffix = map(b"sccp_committee_generations", 0..4096);
        suffix.extend_from_slice(&map(b"sccp_routes", 0..4096));
        let mut joined = prefix.clone();
        joined.extend_from_slice(&selected);
        joined.extend_from_slice(&suffix);
        let (start, end) = field_range(&joined, b"sccp_forgery_offences")
            .unwrap()
            .unwrap();
        assert_eq!((start, end), (prefix.len(), prefix.len() + selected.len()));
        assert_eq!(&joined[start..end], selected);
        let mut visits = 0usize;
        visit::<super::super::Error>(&joined[start..end], |_| {
            visits += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(visits, 3, "offence lookup excludes unrelated delta rows");
        assert_eq!(field_range(&joined, b"sccp_anchor_open").unwrap(), None);
        let mut repeated = selected.clone();
        repeated.extend_from_slice(&selected);
        assert!(field_range(&repeated, b"sccp_forgery_offences").is_err());
        let mut truncated = joined;
        truncated.pop();
        assert!(
            field_range(&truncated, b"sccp_forgery_offences").is_err(),
            "finding the target does not skip trailing validation"
        );
    }
}
