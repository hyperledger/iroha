//! Bounded parsing for the app-facing `ZK1` TLV envelope.
/// Maximum number of TLV records accepted in one first-release `ZK1` envelope.
pub const MAX_TLV_COUNT: usize = 64;
const MAGIC: &[u8; 4] = b"ZK1\0";
const MAX_TLV_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
/// Parse and deduplicate the four-byte tags in a structurally valid `ZK1` envelope.
///
/// Unknown and non-UTF-8 tags remain structurally valid. Non-UTF-8 tags use a
/// deterministic hexadecimal representation in app metadata. No tag metadata
/// is returned for a malformed or over-cardinality envelope.
pub fn parse_tags(bytes: &[u8]) -> Result<Vec<String>, String> {
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err("missing ZK1 magic".to_owned());
    }
    if bytes.len() == MAGIC.len() {
        return Ok(Vec::new());
    }
    let mut tags = Vec::new();
    let mut pos = MAGIC.len();
    let mut tlv_count = 0usize;
    while pos < bytes.len() {
        tlv_count = tlv_count.saturating_add(1);
        if tlv_count > MAX_TLV_COUNT {
            return Err(format!("too many ZK1 TLVs (maximum {MAX_TLV_COUNT})"));
        }
        let header_end = pos
            .checked_add(8)
            .ok_or_else(|| "ZK1 TLV header length overflow".to_owned())?;
        if header_end > bytes.len() {
            return Err("truncated TLV header".to_owned());
        }
        let tag_bytes: &[u8; 4] = bytes[pos..pos + 4]
            .try_into()
            .expect("bounded four-byte ZK1 tag slice");
        let tag = core::str::from_utf8(tag_bytes)
            .ok()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{tag_bytes:02X?}"));
        if !tags.contains(&tag) {
            tags.push(tag);
        }
        let len = u32::from_le_bytes(
            bytes[pos + 4..header_end]
                .try_into()
                .expect("bounded four-byte ZK1 length slice"),
        ) as usize;
        if len > MAX_TLV_PAYLOAD_BYTES {
            return Err("TLV payload too large".to_owned());
        }
        pos = header_end;
        let payload_end = pos
            .checked_add(len)
            .ok_or_else(|| "TLV payload length overflow".to_owned())?;
        if payload_end > bytes.len() {
            return Err("truncated TLV payload".to_owned());
        }
        pos = payload_end;
    }
    Ok(tags)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tags_are_deduplicated_and_cardinality_is_bounded() {
        let mut envelope = MAGIC.to_vec();
        for _ in 0..MAX_TLV_COUNT {
            envelope.extend_from_slice(b"PROF");
            envelope.extend_from_slice(&0u32.to_le_bytes());
        }
        assert_eq!(parse_tags(&envelope), Ok(vec!["PROF".to_owned()]));
        envelope.extend_from_slice(b"IPAK");
        envelope.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_tags(&envelope).is_err());
    }
    #[test]
    fn malformed_envelopes_never_return_partial_tags() {
        let mut envelope = MAGIC.to_vec();
        envelope.extend_from_slice(b"PROF");
        envelope.extend_from_slice(&0u32.to_le_bytes());
        envelope.extend_from_slice(b"IPAK");
        envelope.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_tags(&envelope),
            Err("truncated TLV payload".to_owned())
        );
    }
}
