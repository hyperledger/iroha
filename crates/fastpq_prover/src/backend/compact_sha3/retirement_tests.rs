//! Canonical framing and owner invariants migrated from the retired q375 hash owner.
use super::*;
// Test-only copy of the owned field shape; never a production encoder or decoder.
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_sha3::retirement_tests::OwnedBodyReference",
    frame = "fastpq_prover::compact_sha3::BodyV1"
)]
struct OwnedBodyReference {
    kind: u8,
    oracle: u8,
    round: u8,
    level: u32,
    position: u32,
    output_bytes: u32,
    fields: Vec<Vec<u8>>,
}

fn owned_body_reference(frame: &Frame<'_>) -> OwnedBodyReference {
    let fields = match frame.fields {
        BodyFields::One(field) => vec![field.to_vec()],
        BodyFields::Two(first, second) => vec![first.to_vec(), second.to_vec()],
    };
    OwnedBodyReference {
        kind: frame.kind,
        oracle: frame.oracle,
        round: frame.round,
        level: frame.level,
        position: frame.position,
        output_bytes: frame.output_bytes,
        fields,
    }
}

fn one_shot_owned_h(context: &Context, reference: &OwnedBodyReference) -> Digest {
    let mut hash = Sha3_256V1::new();
    hash.update(&context.prefix.encoded);
    hash.update(&norito::encode_canonical(reference).unwrap());
    hash.finalize()
}

fn valid_layouts() -> impl Iterator<Item = u8> {
    (0..=norito::core::supported_header_flags())
        .filter(|flags| norito::core::validate_header_flags(*flags).is_ok())
}

fn assert_owned_body_bytes(frame: &Frame<'_>) {
    let owned = owned_body_reference(frame);
    let expected = norito::encode_canonical(&owned).unwrap();
    // Comparing the entire frame includes schema, flags, lengths and CRC64.
    for flags in valid_layouts() {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(norito::encode_canonical(frame).unwrap(), expected);
        assert_eq!(norito::canonical_frame_len(frame).unwrap(), expected.len());
    }
}

#[test]
fn borrowed_byte_fields_match_vector_payloads_for_all_layouts_and_boundaries() {
    use norito::core::SerializePayload;
    for flags in valid_layouts() {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        for len in [0, 1, 7, 8, 48, 119, 120, 127, 128, 2736, 29_584] {
            // The byte pattern is the index modulo 256.
            let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(len).collect();
            let byte_field = ByteField(&bytes);
            let mut actual = Vec::new();
            let mut expected = Vec::new();
            norito::core::serialize_to_buffer(&byte_field, &mut actual).unwrap();
            norito::core::serialize_to_buffer(&bytes, &mut expected).unwrap();
            assert_eq!(actual, expected, "byte count {len}, flags {flags:#x}");
            assert_eq!(byte_field.encoded_len_hint(), Some(expected.len()));
            assert_eq!(byte_field.encoded_len_exact(), Some(expected.len()));
            assert_eq!(
                norito::core::encoded_payload_len(&byte_field).unwrap(),
                expected.len()
            );
            for fields in [BodyFields::One(&bytes), BodyFields::Two(&bytes, b"second")] {
                let owned = match fields {
                    BodyFields::One(first) => vec![first.to_vec()],
                    BodyFields::Two(first, second) => vec![first.to_vec(), second.to_vec()],
                };
                actual.clear();
                expected.clear();
                norito::core::serialize_to_buffer(&fields, &mut actual).unwrap();
                norito::core::serialize_to_buffer(&owned, &mut expected).unwrap();
                assert_eq!(
                    actual, expected,
                    "field count, bytes {len}, flags {flags:#x}"
                );
                assert_eq!(
                    norito::core::encoded_payload_len(&fields).unwrap(),
                    expected.len()
                );
            }
        }
    }
}

#[test]
fn owned_and_borrowed_complete_bodies_preserve_schema_flags_lengths_and_checksums() {
    assert_eq!(
        <Frame<'_> as norito::NoritoSchema>::nominal_name(),
        "fastpq_prover::backend::compact_sha3::Frame"
    );
    assert_eq!(
        <Frame<'_> as norito::NoritoSchema>::frame_name(),
        "fastpq_prover::compact_sha3::BodyV1"
    );
    let context = Context::new(b"complete borrowed SHA3 frame coverage").unwrap();
    for (kind, oracle, round, level, index, length) in [
        (1, 1, 0, 0, 0, 2408),
        (1, 1, 0, 0, 8_388_607, 2408),
        (1, 2, 0, 0, 7, 96),
        (1, 3, 0, 0, 524_287, 512),
        (1, 3, 4, 0, 127, 128),
        (1, 4, 5, 0, 0, 4096),
        (1, 5, 0, 0, 0, 19328),
    ] {
        let payload = (0..=u8::MAX).cycle().take(length).collect::<Vec<_>>();
        let frame = context.frame(
            kind,
            oracle,
            round,
            level,
            index,
            32,
            BodyFields::One(&payload),
        );
        assert_owned_body_bytes(&frame);
        assert_eq!(
            context.hash_frame(&frame).unwrap(),
            one_shot_owned_h(&context, &owned_body_reference(&frame))
        );
        let BodyFields::One(borrowed) = frame.fields else {
            unreachable!()
        };
        assert!(std::ptr::eq(borrowed, payload.as_slice()));
    }
    let left = [0xff; 32];
    let right = [0x80; 32];
    for round in 0..=5 {
        for level in [1, 23] {
            for index in [0, u32::MAX] {
                let frame = context.frame(
                    2,
                    3,
                    round,
                    level,
                    index,
                    32,
                    BodyFields::Two(&left, &right),
                );
                assert_owned_body_bytes(&frame);
                assert_eq!(
                    context.hash_frame(&frame).unwrap(),
                    one_shot_owned_h(&context, &owned_body_reference(&frame))
                );
            }
        }
    }
    for ordinal in 1..=10 {
        let round = RawTapeRoundV1::new(ordinal).unwrap();
        let g = context.frame(
            4,
            0,
            ordinal,
            0,
            0,
            round.tape_bytes(),
            BodyFields::One(&left),
        );
        assert_owned_body_bytes(&g);
        if ordinal < 10 {
            let raw = vec![0xA7; round.tape_bytes()];
            let h = context.frame(3, 0, ordinal, 0, 0, 32, BodyFields::Two(&raw, &right));
            assert_owned_body_bytes(&h);
            assert_eq!(
                context.hash_frame(&h).unwrap(),
                one_shot_owned_h(&context, &owned_body_reference(&h))
            );
        }
    }
}
#[test]
fn immutable_prefix_binds_catalog_protocol_identity_and_full_context_under_concurrency() {
    let bytes = vec![0x9d; MAX_CONTEXT_BYTES];
    let context = Context::new(&bytes).unwrap();
    let expected = norito::encode_canonical(&PrefixFrame {
        version: 1,
        catalog: FASTPQ_CATALOG_V1.as_bytes().to_vec(),
        construction: super::super::transcript_profile::CONSTRUCTION
            .as_bytes()
            .to_vec(),
        profile: super::super::transcript_profile::profile()
            .as_bytes()
            .to_vec(),
        context: bytes,
    })
    .unwrap();
    assert_eq!(context.prefix.encoded.as_ref(), expected);
    for flags in valid_layouts() {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            Context::new(&vec![0x9d; MAX_CONTEXT_BYTES])
                .unwrap()
                .prefix
                .encoded
                .as_ref(),
            expected
        );
    }
    assert_eq!(
        Context::new(&[b'a'; 101])
            .unwrap()
            .maximum_retained_payload_bytes()
            .unwrap()
            - Context::new(b"a")
                .unwrap()
                .maximum_retained_payload_bytes()
                .unwrap(),
        100
    );
    assert_eq!(Arc::strong_count(&context.prefix), 1);
    let charge = context.maximum_retained_payload_bytes().unwrap();
    let frame = context.frame(
        2,
        3,
        4,
        23,
        u32::MAX,
        32,
        BodyFields::Two(&[0xff; 32], &[0x80; 32]),
    );
    let expected_hash = one_shot_owned_h(&context, &owned_body_reference(&frame));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let worker = context.clone();
            let frame = frame.clone();
            scope.spawn(move || {
                for _ in 0..4 {
                    assert_eq!(worker.hash_frame(&frame).unwrap(), expected_hash);
                }
            });
        }
    });
    for ordinal in 1..=10 {
        let round = RawTapeRoundV1::new(ordinal).unwrap();
        let frame = context.frame(
            4,
            0,
            ordinal,
            0,
            0,
            round.tape_bytes(),
            BodyFields::One(&[0; 32]),
        );
        context
            .tape(round, &norito::encode_canonical(&frame).unwrap())
            .unwrap();
    }
    assert_eq!(context.maximum_retained_payload_bytes().unwrap(), charge);
    assert_eq!(Arc::strong_count(&context.prefix), 1);
}
#[test]
fn prepared_body_borrows_exact_owner_and_never_exposes_a_consumable_prefix() {
    let context = Context::new(b"prepared owner migration").unwrap();
    for length in [0, 1, 7, 8, 96, 2408, 4096] {
        let payload = vec![37; length];
        let frame = context.frame(1, 1, 0, 0, 17, 32, BodyFields::One(&payload));
        let prepared = context.prepare_hash_frame(&frame).unwrap();
        let expected = norito::encode_canonical(&frame).unwrap();
        assert_eq!(&*prepared.encoded, expected);
        assert_eq!(prepared.job().body().len(), expected.len());
        assert!(std::ptr::eq(
            prepared.job().body(),
            std::ptr::from_ref(&*prepared.encoded)
        ));
        for _ in 0..3 {
            assert_eq!(prepared.job().scalar(), context.hash_frame(&frame).unwrap());
        }
        let mut tail = prepared.job().prefix().clone();
        tail.update(prepared.job().body());
        assert_eq!(tail.finalize(), context.hash_frame(&frame).unwrap());
    }
    assert!(
        context
            .prepare_hash_frame(&context.frame(
                1,
                1,
                0,
                0,
                0,
                32,
                BodyFields::One(&vec![0; MAX_PREPARED_HASH_FRAME_BYTES])
            ))
            .is_err()
    );
}

#[test]
fn private_frame_storage_is_exact_guarded_and_preserves_canonical_bytes() {
    let context = Context::new(b"private framing erasure regression").unwrap();
    for bytes in [0, 1, 96, 301 * 8, 342 * 8, 4096] {
        let payload = (0..bytes)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>();
        for fields in [
            BodyFields::One(&payload),
            BodyFields::Two(&payload, b"other"),
        ] {
            let frame = context.frame(1, 1, 0, 0, u32::MAX, 32, fields);
            let expected = norito::encode_canonical(&frame).unwrap();
            let encoded = encode_private_frame(&frame).unwrap();
            assert_eq!(&*encoded, expected);
            assert_eq!(encoded.len(), norito::canonical_frame_len(&frame).unwrap());
            let mut short = SecretPolynomial::<u8>::zeroed(encoded.len() - 1).unwrap();
            assert!(norito::core::write_canonical_to_writer(&frame, &mut &mut short[..]).is_err());
        }
    }
}
#[test]
fn every_typed_coordinate_binds_hash_while_prefix_custody_stays_constant() {
    let context = Context::new(b"one immutable shared prefix").unwrap();
    let before = context.maximum_retained_payload_bytes().unwrap();
    let mut hashes = std::collections::BTreeSet::new();
    for kind in 1..=4 {
        for oracle in 0..=5 {
            for round in 0..=10 {
                for level in 0..=23 {
                    let frame = context.frame(
                        kind,
                        oracle,
                        round,
                        level,
                        0,
                        32,
                        BodyFields::One(b"fixed payload"),
                    );
                    assert!(hashes.insert(context.hash_frame(&frame).unwrap().into_bytes()));
                }
            }
        }
    }
    assert_eq!(hashes.len(), 4 * 6 * 11 * 24);
    assert_eq!(context.maximum_retained_payload_bytes().unwrap(), before);
    assert_eq!(Arc::strong_count(&context.prefix), 1);
}

#[test]
fn independent_complete_prefix_dummy_tape_and_chain_known_answers() {
    // Independently encoded canonical Norito in Python, SHA-256 schema IDs,
    // CRC64-XZ payload checksums and hashlib SHA3/SHAKE
    // (`scripts/zk_semantic_profile_reference.py`). The prefix is the header and
    // the version, catalog and construction fields, then the complete typed
    // profile descriptor, then the context field; its whole digest is pinned.
    let context = Context::new(b"complete public context without a private witness").unwrap();
    let profile = super::super::transcript_profile::profile();
    assert_eq!(profile.as_bytes().len(), 3_871);
    assert_eq!(context.prefix.encoded.len(), 4_063);
    assert_eq!(
        hex::encode(&context.prefix.encoded),
        [
            "4e5254300000568fedfb2a9232dfd5dd6e73bda1284000b70f00000000000057294c5f1254ee100202010020180000000000000069726f68612d707269766163792d657861637431322d76312f2700000000000000666970733230322d61746f6d69632d77686f6c652d746170652d7472616e7363726970742d7631a71e1f0f000000000000",
            hex::encode(profile.as_bytes()).as_str(),
            "393100000000000000636f6d706c657465207075626c696320636f6e7465787420776974686f757420612070726976617465207769746e657373",
        ]
        .concat()
    );
    let mut whole = Sha3_256V1::new();
    whole.update(&context.prefix.encoded);
    assert_eq!(
        hex::encode(whole.finalize().into_bytes()),
        "0639025aa47dbe15e2792551bad60665e9701324feac90893e126c7b81d040d7"
    );
    let round = RawTapeRoundV1::new(1).unwrap();
    let g = context.frame(4, 0, 1, 0, 0, 32, BodyFields::One(&[0; 32]));
    let encoded = norito::encode_canonical(&g).unwrap();
    assert_eq!(encoded.len(), 111);
    assert_eq!(
        hex::encode(&encoded),
        "4e525430000006b0bfd67e8a9cdc61d3474fc82491dd0047000000000000006d19aee8c6f4f2e5020104010001010400000000040000000004200000003101000000000000002820000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    let tape = context.tape(round, &encoded).unwrap();
    assert_eq!(
        hex::encode(tape.as_bytes()),
        "26d8592fc8042efc7dee3349db03b6700b82ecb4512e5e97732d8f0007637a9e"
    );
    let root = [0; 32];
    let chain = context.frame(3, 0, 1, 0, 0, 32, BodyFields::Two(tape.as_bytes(), &root));
    let BodyFields::Two(borrowed, borrowed_root) = chain.fields else {
        unreachable!()
    };
    assert!(std::ptr::eq(borrowed, tape.as_bytes()));
    assert!(std::ptr::eq(borrowed_root, root.as_slice()));
    assert_eq!(
        hex::encode(norito::encode_canonical(&chain).unwrap()),
        "4e525430000006b0bfd67e8a9cdc61d3474fc82491dd007000000000000000b723010a45b01dd2020103010001010400000000040000000004200000005a020000000000000028200000000000000026d8592fc8042efc7dee3349db03b6700b82ecb4512e5e97732d8f0007637a9e2820000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode(context.hash_frame(&chain).unwrap().into_bytes()),
        "fb779ea41553b05852feb64ea57dd9fbef344bbd7733264426e0a69bd018773a"
    );
}
