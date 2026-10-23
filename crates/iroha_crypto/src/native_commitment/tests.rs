//! Production frame checks against independent layout and SHA3/BLAKE3 answers.

use super::*;

fn domain() -> NativeCommitmentDomainV1<'static> {
    NativeCommitmentDomainV1 {
        catalog: b"iroha-privacy-exact12-v1",
        protocol: b"privacy-exact12-catalog-v1",
        role: b"catalog",
        phase: b"commitment",
        level: 0,
        index: 0,
        counter: 0,
    }
}

fn bytes(text: &str) -> Vec<u8> {
    if text == "-" {
        Vec::new()
    } else {
        hex::decode(text).expect("fixture hex")
    }
}

#[test]
fn production_frames_match_every_applicable_independent_vector() {
    let mut checked = Vec::new();
    let mut layout_only = Vec::new();
    for line in include_str!("../hash_native_candidate_vectors.txt")
        .lines()
        .filter(|line| line.starts_with("example "))
    {
        let row = line.split(' ').collect::<Vec<_>>();
        let algorithm = bytes(row[2]);
        let labels: [Vec<u8>; 5] = core::array::from_fn(|i| bytes(row[3 + i]));
        if algorithm != NATIVE_COMMITMENT_ALGORITHM_V1.as_bytes()
            || labels[2] != NATIVE_COMMITMENT_PROFILE_V1.as_bytes()
        {
            // H.1 also records a comparator and an all-empty-domain layout sample.
            // They are not inputs to the selected fixed-algorithm/profile owner.
            layout_only.push(row[1]);
            continue;
        }
        let count: usize = row[11].parse().expect("field count");
        let tail = 12 + count;
        assert_eq!(row.len(), tail + 4);
        let owned: Vec<_> = row[12..tail].iter().map(|value| bytes(value)).collect();
        let fields: Vec<_> = owned.iter().map(Vec::as_slice).collect();
        let frame = NativeCommitmentFrameV1::new(
            NativeCommitmentDomainV1 {
                catalog: &labels[0],
                protocol: &labels[1],
                role: &labels[3],
                phase: &labels[4],
                level: row[8].parse().unwrap(),
                index: row[9].parse().unwrap(),
                counter: row[10].parse().unwrap(),
            },
            &fields,
        )
        .expect("bounded vector");
        let mut encoded = vec![0; usize::try_from(frame.encoded_len()).unwrap()];
        frame.write_frame(&mut encoded).unwrap();
        assert_eq!(encoded, bytes(row[tail]), "complete frame {}", row[1]);
        let digest = frame.digest();
        assert_eq!(
            digest.as_bytes().as_slice(),
            bytes(row[tail + 1]),
            "full raw BLAKE3 {}",
            row[1]
        );
        assert_eq!(frame.verify_digest(digest.as_bytes()).unwrap(), digest);
        assert_eq!(blake3::hash(&encoded).as_bytes(), digest.as_bytes());
        checked.push(row[1]);
    }
    assert_eq!(
        checked,
        [
            "catalog-commitment",
            "kaigi-call-id",
            "kaigi-account-id",
            "spentness-leaf",
            "spentness-node",
            "outer-statement-identity",
            "no-fields",
            "one-empty-field",
            "split-abc-def",
            "joined-abcdef"
        ]
    );
    assert_eq!(
        layout_only,
        ["empty-domain-strings", "comparator-shake256-384"]
    );
    // The spentness rows exercise framing only: their consumer remains deferred.
}

#[test]
fn typed_profile_matches_independent_frame_and_frozen_identity() {
    let profile = native_commitment_profile_v1().unwrap();
    assert_eq!(profile.kind(), SemanticProfileKindV1::NativeCommitment);
    assert_eq!(profile.name(), NATIVE_COMMITMENT_PROFILE_NAME_V1);
    assert_eq!(
        profile.as_bytes(),
        bytes(include_str!("profile_v1.hex").trim())
    );
    assert_eq!(
        profile.id().to_string(),
        "d758de9793685820992fc67569d0b2b54c5a9c8d58e4c88c2310b56f57f561e8"
    );
    // Semantic descriptor parsing rejects truncation and trailing data.
    for end in 0..profile.as_bytes().len() {
        assert!(SemanticProfileV1::decode(&profile.as_bytes()[..end]).is_err());
    }
    let mut extra = profile.as_bytes().to_vec();
    extra.push(0);
    assert!(SemanticProfileV1::decode(&extra).is_err());
}

#[test]
fn every_role_context_coordinate_boundary_and_order_is_bound() {
    let base = domain();
    let fields: [&[u8]; 2] = [b"abc", b"def"];
    let expected = NativeCommitmentFrameV1::new(base, &fields)
        .unwrap()
        .digest();
    let mutations = [
        NativeCommitmentDomainV1 {
            catalog: b"other-catalog",
            ..base
        },
        NativeCommitmentDomainV1 {
            protocol: b"other-protocol",
            ..base
        },
        NativeCommitmentDomainV1 {
            role: b"other-role",
            ..base
        },
        NativeCommitmentDomainV1 {
            phase: b"other-phase",
            ..base
        },
        NativeCommitmentDomainV1 { level: 1, ..base },
        NativeCommitmentDomainV1 { index: 1, ..base },
        NativeCommitmentDomainV1 { counter: 1, ..base },
    ];
    let mut seen = std::collections::BTreeSet::from([expected]);
    for changed in mutations {
        let frame = NativeCommitmentFrameV1::new(changed, &fields).unwrap();
        assert_eq!(
            frame.verify_digest(expected.as_bytes()),
            Err(NativeCommitmentErrorV1::DigestMismatch)
        );
        assert!(seen.insert(frame.digest()));
    }
    for changed in [
        &[b"abcdef".as_slice()][..],
        &[b"def".as_slice(), b"abc"][..],
        &[b"abc".as_slice(), b"def", b""][..],
        &[b"ab".as_slice(), b"cdef"][..],
        &[b"abc".as_slice(), b"deg"][..],
    ] {
        let frame = NativeCommitmentFrameV1::new(base, changed).unwrap();
        assert_eq!(
            frame.verify_digest(expected.as_bytes()),
            Err(NativeCommitmentErrorV1::DigestMismatch)
        );
        assert!(seen.insert(frame.digest()));
    }
    let empty = NativeCommitmentFrameV1::new(base, &[]).unwrap();
    let one_empty = NativeCommitmentFrameV1::new(base, &[b""]).unwrap();
    assert_ne!(empty.digest(), one_empty.digest());
}

#[test]
fn exact_frame_and_digest_lengths_refuse_truncation_without_output_mutation() {
    let fields: [&[u8]; 1] = [b"framed payload"];
    let frame = NativeCommitmentFrameV1::new(domain(), &fields).unwrap();
    let len = usize::try_from(frame.encoded_len()).unwrap();
    for size in [0, len - 1, len + 1] {
        let mut output = vec![0xa7; size];
        assert_eq!(
            frame.write_frame(&mut output),
            Err(NativeCommitmentErrorV1::FrameLength)
        );
        assert!(output.iter().all(|value| *value == 0xa7));
    }
    let digest = frame.digest();
    for len in 0..NativeCommitmentDigestV1::BYTES {
        assert_eq!(
            frame.verify_digest(&digest.as_bytes()[..len]),
            Err(NativeCommitmentErrorV1::DigestLength)
        );
    }
    let mut extended = digest.as_bytes().to_vec();
    extended.push(0);
    assert_eq!(
        frame.verify_digest(&extended),
        Err(NativeCommitmentErrorV1::DigestLength)
    );
    let mut changed = *digest.as_bytes();
    changed[31] ^= 1;
    assert_eq!(
        frame.verify_digest(&changed),
        Err(NativeCommitmentErrorV1::DigestMismatch)
    );
}

#[test]
fn frozen_bounds_are_checked_before_encoding_or_allocating_payloads() {
    let wide = vec![0; NATIVE_COMMITMENT_MAX_DOMAIN_BYTES_V1 + 1];
    let base = domain();
    for value in [
        NativeCommitmentDomainV1 {
            catalog: &wide,
            ..base
        },
        NativeCommitmentDomainV1 {
            protocol: &wide,
            ..base
        },
        NativeCommitmentDomainV1 {
            role: &wide,
            ..base
        },
        NativeCommitmentDomainV1 {
            phase: &wide,
            ..base
        },
    ] {
        assert_eq!(
            NativeCommitmentFrameV1::new(value, &[]).unwrap_err(),
            NativeCommitmentErrorV1::DomainTooLong
        );
        assert_eq!(
            NativeCommitmentFrameV1::encoded_len_for_field_lengths(value, &[]),
            Err(NativeCommitmentErrorV1::DomainTooLong)
        );
    }
    let fields = vec![b"".as_slice(); NATIVE_COMMITMENT_MAX_FIELDS_V1 + 1];
    assert_eq!(
        NativeCommitmentFrameV1::new(base, &fields).unwrap_err(),
        NativeCommitmentErrorV1::TooManyFields
    );
    let accepted =
        NativeCommitmentFrameV1::new(base, &fields[..NATIVE_COMMITMENT_MAX_FIELDS_V1]).unwrap();
    assert_eq!(
        accepted.encoded_len(),
        NativeCommitmentFrameV1::encoded_len_for_field_lengths(
            base,
            &vec![0; NATIVE_COMMITMENT_MAX_FIELDS_V1]
        )
        .unwrap()
    );
    assert_eq!(
        NativeCommitmentFrameV1::encoded_len_for_field_lengths(
            base,
            &vec![0; NATIVE_COMMITMENT_MAX_FIELDS_V1 + 1]
        ),
        Err(NativeCommitmentErrorV1::TooManyFields)
    );
    let max_domain = &wide[..NATIVE_COMMITMENT_MAX_DOMAIN_BYTES_V1];
    assert!(
        NativeCommitmentFrameV1::new(
            NativeCommitmentDomainV1 {
                catalog: max_domain,
                ..base
            },
            &[]
        )
        .is_ok()
    );
    if let Ok(over) = usize::try_from(NATIVE_COMMITMENT_MAX_FIELD_BYTES_V1 + 1) {
        assert_eq!(
            NativeCommitmentFrameV1::encoded_len_for_field_lengths(base, &[over]),
            Err(NativeCommitmentErrorV1::FieldTooLong)
        );
    }
    assert!(
        NativeCommitmentFrameV1::encoded_len_for_field_lengths(base, &[u32::MAX as usize]).is_ok()
    );
}

#[test]
fn streamed_hash_preserves_all_bytes_and_uses_no_ledger_marker() {
    let payload: Vec<_> = (0..131_073)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let fields: [&[u8]; 3] = [&payload, b"", &payload[..1025]];
    let frame = NativeCommitmentFrameV1::new(domain(), &fields).unwrap();
    let mut encoded = vec![0; usize::try_from(frame.encoded_len()).unwrap()];
    frame.write_frame(&mut encoded).unwrap();
    assert_eq!(frame.digest().as_bytes(), blake3::hash(&encoded).as_bytes());
    let mut saw_zero_low_bit = false;
    for counter in 0..32 {
        let value = NativeCommitmentFrameV1::new(
            NativeCommitmentDomainV1 {
                counter,
                ..domain()
            },
            &fields,
        )
        .unwrap()
        .digest();
        saw_zero_low_bit |= value.as_bytes()[31] & 1 == 0;
    }
    assert!(
        saw_zero_low_bit,
        "the full raw output is not marked as a ledger Hash"
    );
}

#[test]
fn empty_domain_values_remain_present_with_fixed_algorithm_and_profile() {
    let empty = NativeCommitmentDomainV1 {
        catalog: b"",
        protocol: b"",
        role: b"",
        phase: b"",
        level: 0,
        index: 0,
        counter: 0,
    };
    let frame = NativeCommitmentFrameV1::new(empty, &[]).unwrap();
    let mut output = vec![0; usize::try_from(frame.encoded_len()).unwrap()];
    frame.write_frame(&mut output).unwrap();
    let mut expected = NATIVE_COMMITMENT_MAGIC_V1.to_vec();
    for (tag, value) in [
        (1, b"blake3-256".as_slice()),
        (2, b""),
        (3, b""),
        (4, b"native-commitment-blake3-256-v1"),
        (5, b""),
        (6, b""),
    ] {
        expected.push(tag);
        expected.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
        expected.extend_from_slice(value);
    }
    for tag in 7..=9 {
        expected.push(tag);
        expected.extend_from_slice(&0_u64.to_le_bytes());
    }
    expected.push(10);
    expected.extend_from_slice(&0_u32.to_le_bytes());
    assert_eq!(output, expected);
}

#[test]
fn errors_have_distinct_diagnostics_and_debug_omits_payloads() {
    let errors = [
        NativeCommitmentErrorV1::DomainTooLong,
        NativeCommitmentErrorV1::TooManyFields,
        NativeCommitmentErrorV1::FieldTooLong,
        NativeCommitmentErrorV1::FrameLength,
        NativeCommitmentErrorV1::DigestLength,
        NativeCommitmentErrorV1::DigestMismatch,
    ];
    assert_eq!(
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        errors.len()
    );
    let fields: [&[u8]; 1] = [b"private-fixture-payload"];
    let frame = NativeCommitmentFrameV1::new(domain(), &fields).unwrap();
    assert!(!format!("{frame:?}").contains("private-fixture-payload"));
}
