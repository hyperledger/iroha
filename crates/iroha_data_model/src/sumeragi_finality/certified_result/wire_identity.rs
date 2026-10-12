//! Explicit release-identity description of the native `X || body` wire format.
//!
//! This is a codec description, not an `IntoSchema` alias for a Norito structure:
//! `X` is fixed raw bytes and the body is one complete canonical Norito frame.
//! The body payload's real schema is an independent release-identity root.

use super::*;

/// Name of this native format in the release identity's ordered descriptor list.
pub const FORMAT_NAME: &str = "iroha.sumeragi.certified_result.v1";

/// Canonical description of the compiled header layout, body framing and result hash.
///
/// Each ordered entry is `le64(name.len) || name || le64(value.len) || value`,
/// following a little-endian `u64` entry count. Numeric descriptor values use
/// little-endian `u64`; this does not change the big-endian integers inside `X`.
/// Offsets, magic, flag masks, bounds, tags and Norito frame properties come from
/// the actual codec constants. This description and the real body schema must
/// both be included in the release identity; neither substitutes for the other.
#[must_use]
pub fn descriptor() -> Vec<u8> {
    render(&entries())
}

type Entries = Vec<(&'static str, Vec<u8>)>;

fn entries() -> Entries {
    use norito::NoritoSchema;

    let number = |value: usize| (value as u64).to_le_bytes().to_vec();
    let mut out = vec![
        ("format", b"raw-X || canonical-Norito-body; no outer prefix or padding".to_vec()),
        ("x.magic", X_MAGIC.to_vec()),
        ("x.length", number(X_LEN)),
        ("x.integer_endianness", b"big-endian".to_vec()),
        ("x.active_mask", vec![FLAG_ACTIVE]),
        ("x.rotation_mask", vec![FLAG_ROTATION]),
        ("x.allowed_flags", vec![FLAG_ACTIVE | FLAG_ROTATION]),
        ("x.max_messages", u64::from(SCCP_MESSAGES_MAX_PER_BLOCK_V1).to_le_bytes().to_vec()),
        ("x.max_history_size", MAX_HISTORY_SIZE.to_le_bytes().to_vec()),
        ("x.max_validity_ms", MAX_VALIDITY_MS.to_le_bytes().to_vec()),
        ("x.rules", b"X1 magic+reserved-flags; X2 inactive: rotation=0, suffix-after-flags=0; X3 active: generation>0, committee-root!=0; X4 count=0 iff sccp-root=0; X5 history-size=0 iff history-root=0; X6 rotation: successor-root!=0, validity>=1, height+1 and generation+1 fit u64; nonrotation: successor-root=0, validity=0; X7 height>=1".to_vec()),
    ];
    // The codec's own offsets are used, rather than a second set of numeric offsets.
    for (name, start, end, encoding) in [
        ("x.field.magic", 0, OFFSET_NETWORK_ID, "fixed-bytes"),
        (
            "x.field.network_id",
            OFFSET_NETWORK_ID,
            OFFSET_HEIGHT,
            "fixed-bytes",
        ),
        (
            "x.field.height",
            OFFSET_HEIGHT,
            OFFSET_TIMESTAMP_MS,
            "u64-be",
        ),
        (
            "x.field.timestamp_ms",
            OFFSET_TIMESTAMP_MS,
            OFFSET_FLAGS,
            "u64-be",
        ),
        ("x.field.flags", OFFSET_FLAGS, OFFSET_MESSAGE_COUNT, "u8"),
        (
            "x.field.message_count",
            OFFSET_MESSAGE_COUNT,
            OFFSET_SCCP_ROOT,
            "u32-be",
        ),
        (
            "x.field.sccp_root",
            OFFSET_SCCP_ROOT,
            OFFSET_HISTORY_SIZE,
            "fixed-bytes",
        ),
        (
            "x.field.history_size",
            OFFSET_HISTORY_SIZE,
            OFFSET_HISTORY_ROOT,
            "u64-be",
        ),
        (
            "x.field.history_root",
            OFFSET_HISTORY_ROOT,
            OFFSET_GENERATION,
            "fixed-bytes",
        ),
        (
            "x.field.generation",
            OFFSET_GENERATION,
            OFFSET_COMMITTEE_ROOT,
            "u64-be",
        ),
        (
            "x.field.committee_root",
            OFFSET_COMMITTEE_ROOT,
            OFFSET_VALIDITY_MS,
            "fixed-bytes",
        ),
        (
            "x.field.validity_ms",
            OFFSET_VALIDITY_MS,
            OFFSET_NEXT_COMMITTEE_ROOT,
            "u64-be",
        ),
        (
            "x.field.next_committee_root",
            OFFSET_NEXT_COMMITTEE_ROOT,
            X_LEN,
            "fixed-bytes",
        ),
    ] {
        let mut value = number(start);
        value.extend_from_slice(&number(end - start));
        value.extend_from_slice(encoding.as_bytes());
        out.push((name, value));
    }
    out.extend([
        ("preimage.min_bytes", number(X_LEN + 1)),
        ("preimage.max_bytes", number(MAX_RESULT_PREIMAGE_BYTES)),
        ("body.max_bytes", number(MAX_RESULT_BODY_BYTES)),
        ("body.frame", b"one exact canonical Norito frame; no trailing bytes; zero alignment padding; uncompressed".to_vec()),
        ("body.frame_name", ExecutionResultCommitment::frame_name().into_bytes()),
        ("body.frame_hash", norito::schema::identity::frame_hash::<ExecutionResultCommitment>().to_vec()),
        ("body.norito_magic", norito::core::MAGIC.to_vec()),
        ("body.norito_version", vec![norito::core::VERSION_MAJOR, norito::core::VERSION_MINOR]),
        ("body.norito_header_bytes", number(norito::core::Header::SIZE)),
        ("body.norito_header_layout", b"magic[4],major:u8,minor:u8,schema[16],compression:u8,length:u64-le,crc64-xz:u64-le,flags:u8".to_vec()),
        ("body.norito_flags", vec![norito::core::default_encode_flags()]),
        ("body.norito_compression", vec![norito::Compression::None as u8]),
        ("body.payload_alignment", number(norito::core::archived_payload_align::<ExecutionResultCommitment>())),
        ("body.hash_algorithm", b"BLAKE2b-256, Iroha marker bit set".to_vec()),
        ("body.hash_tag", RESULT_BODY_TAG.to_vec()),
        ("body.hash_preimage", b"body.hash_tag || complete canonical body frame".to_vec()),
        ("result.hash_algorithm", b"SHA-256, raw 32-byte output, no marker bit".to_vec()),
        ("result.hash_tag", RESULT_TAG.to_vec()),
        ("result.hash_preimage", b"result.hash_tag || X || body_digest[32]".to_vec()),
    ]);
    out
}

fn render(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = (entries.len() as u64).to_le_bytes().to_vec();
    for (name, value) in entries {
        out.extend_from_slice(&(name.len() as u64).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_descriptor_binds_layout_endianness_domains_and_bounds() {
        let hash = |bytes: &[u8]| {
            crate::wire_schema::wire_schema_hash_of(&[], &[(FORMAT_NAME, bytes)], [0; 32])
        };
        let original = descriptor();
        assert_eq!(original, render(&entries()));
        let expected = hash(&original);
        // Exercise changes hidden by the body's unchanged Norito schema.
        for name in [
            "format",
            "x.magic",
            "x.length",
            "x.integer_endianness",
            "x.field.height",
            "x.allowed_flags",
            "body.max_bytes",
            "preimage.max_bytes",
            "body.norito_flags",
            "body.payload_alignment",
            "body.hash_tag",
            "result.hash_tag",
            "result.hash_algorithm",
        ] {
            let mut changed = entries();
            let value = &mut changed.iter_mut().find(|(key, _)| *key == name).unwrap().1;
            value[0] ^= 1;
            assert_ne!(hash(&render(&changed)), expected, "{name}");
        }
    }

    #[test]
    fn descriptor_fields_match_the_fixed_header_encoder() {
        let fields = SccpFinalityHeaderFieldsV1 {
            network_id: [0x17; 32],
            height: 0x0102_0304_0506_0708,
            timestamp_ms: 0x1112_1314_1516_1718,
            flags: FLAG_ACTIVE | FLAG_ROTATION,
            message_count: 0x2122_2324,
            sccp_root: [0x37; 32],
            history_size: 0x4142_4344_4546_4748,
            history_root: [0x57; 32],
            generation: 0x6162_6364_6566_6768,
            committee_root: [0x77; 32],
            validity_ms: 0x8182_8384_8586_8788,
            next_committee_root: [0x97; 32],
        };
        let encoded = fields.to_bytes();
        let expected: [&[u8]; 13] = [
            X_MAGIC,
            &fields.network_id,
            &fields.height.to_be_bytes(),
            &fields.timestamp_ms.to_be_bytes(),
            &[fields.flags],
            &fields.message_count.to_be_bytes(),
            &fields.sccp_root,
            &fields.history_size.to_be_bytes(),
            &fields.history_root,
            &fields.generation.to_be_bytes(),
            &fields.committee_root,
            &fields.validity_ms.to_be_bytes(),
            &fields.next_committee_root,
        ];
        let entries = entries();
        let fields: Vec<_> = entries
            .iter()
            .filter(|(name, _)| name.starts_with("x.field."))
            .collect();
        assert_eq!(fields.len(), expected.len());
        let mut cursor = 0;
        for ((name, value), expected) in fields.into_iter().zip(expected) {
            let start = u64::from_le_bytes(value[..8].try_into().unwrap()) as usize;
            let width = u64::from_le_bytes(value[8..16].try_into().unwrap()) as usize;
            assert_eq!(start, cursor, "{name}");
            assert_eq!(&encoded[start..start + width], expected, "{name}");
            cursor += width;
        }
        assert_eq!(cursor, X_LEN);
    }

    #[test]
    fn descriptor_body_framing_matches_the_original_certificate() {
        use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
        let fixture = NativeFinalityFixture::new();
        let block = fixture
            .verifier()
            .verify_retained_decision(fixture.latest())
            .unwrap();
        let original = block
            .block()
            .commit_certificate()
            .unwrap()
            .result_preimage();
        let body = norito::encode_canonical(block.commitment()).unwrap();
        assert_eq!(&original[X_LEN..], body);
        assert_eq!(result_of_preimage(original), Some(block.result()));
        assert_eq!(&body[..4], &norito::core::MAGIC);
        assert_eq!(body[4], norito::core::VERSION_MAJOR);
        assert_eq!(body[5], norito::core::VERSION_MINOR);
        assert_eq!(
            &body[6..22],
            norito::schema::identity::frame_hash::<ExecutionResultCommitment>()
        );
        assert_eq!(body[22], norito::Compression::None as u8);
        assert_eq!(body[39], norito::core::default_encode_flags());
        let alignment = norito::core::archived_payload_align::<ExecutionResultCommitment>();
        let start = norito::core::Header::SIZE.next_multiple_of(alignment);
        assert!(
            body[norito::core::Header::SIZE..start]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(
            u64::from_le_bytes(body[23..31].try_into().unwrap()) as usize,
            body.len() - start
        );
        assert_eq!(MAX_RESULT_BODY_BYTES + X_LEN, MAX_RESULT_PREIMAGE_BYTES);
    }
}
