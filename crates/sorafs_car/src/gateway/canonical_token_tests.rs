// Gateway stream-token frames have one canonical encoding, independently of caller layout.
fn canonical_token_layouts() -> [u8; 2] {
    [0, norito::core::header_flags::COMPACT_LEN]
}

fn canonical_token_fixture() -> StreamTokenV1 {
    sample_stream_token(
        &sample_manifest_cid_hex(),
        &provider_id_hex(),
        &chunker_handle(),
        2,
    )
}

#[test]
fn canonical_token_context_and_signed_bytes_ignore_all_caller_layouts() {
    let token = canonical_token_fixture();
    let canonical = norito::encode_canonical(&token).unwrap();
    assert!(canonical.len() <= STREAM_TOKEN_MAX_WIRE_BYTES_V1);
    let encoded = STANDARD.encode(&canonical);
    let mut alternatives = 0;
    for flags in canonical_token_layouts() {
        let _layout = norito::core::DecodeFlagsGuard::enter(flags);
        let signed = StreamTokenV1::sign(token.body.clone(), &gateway_signing_key()).unwrap();
        assert_eq!(signed, token);
        assert_eq!(norito::encode_canonical(&signed).unwrap(), canonical);
        assert_eq!(encode_token_b64(&signed), encoded);
        assert_eq!(decode_stream_token(&encoded).unwrap(), token);
        signed
            .verify(&gateway_signing_key().verifying_key())
            .unwrap();
        let context = build_test_context(
            gateway_config(&"11".repeat(32), &chunker_handle()),
            [gateway_provider_input(&signed)],
        )
        .expect("actual gateway admission preserves the exact signed canonical token");
        let runtime = context.fetcher.inner.providers.get("alpha").unwrap();
        assert_eq!(runtime.stream_token.to_str().unwrap(), encoded);
        assert_eq!(runtime.token_id, token.body.token_id);

        let alternate = norito::core::to_bytes(&token).unwrap();
        if alternate != canonical {
            alternatives += 1;
            assert_eq!(
                norito::decode_from_bytes::<StreamTokenV1>(&alternate).unwrap(),
                token
            );
            let alternate_b64 = STANDARD.encode(&alternate);
            assert!(matches!(
                decode_stream_token(&alternate_b64),
                Err(StreamTokenDecodeError::NonCanonicalPayload)
            ));
            let mut input = gateway_provider_input(&token);
            input.stream_token_b64 = alternate_b64;
            assert!(matches!(
                build_test_context(gateway_config(&"11".repeat(32), &chunker_handle()), [input]),
                Err(GatewayBuildError::InvalidStreamToken {
                    source: StreamTokenDecodeError::NonCanonicalPayload,
                    ..
                })
            ));
        }
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
    assert!(
        alternatives > 0,
        "ordinary decoding must accept distinct same-value frames"
    );
}

#[test]
fn canonical_token_compression_is_rejected_before_norito_collection_allocation() {
    let token = canonical_token_fixture();
    let canonical = norito::encode_canonical(&token).unwrap();
    let header = norito::core::Header::read(canonical.as_slice()).unwrap();
    assert_eq!(header.compression, norito::Compression::None);
    let compression_offset = header.magic.len() + 2 + header.schema.len();
    let mut tagged = canonical.clone();
    tagged[compression_offset] = norito::Compression::Zstd as u8;
    assert_eq!(
        norito::core::Header::read(tagged.as_slice())
            .unwrap()
            .compression,
        norito::Compression::Zstd
    );
    let mut advertised = tagged[..norito::core::Header::SIZE].to_vec();
    advertised[compression_offset + 1..compression_offset + 9]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        norito::core::Header::read(advertised.as_slice())
            .unwrap()
            .length,
        u64::MAX
    );
    // The default feature set may omit compression. The existing norito/compression lane
    // additionally exercises a genuine Zstd frame; forbidden tag/header tests are unconditional.
    let compressed =
        match norito::to_compressed_bytes(&token, Some(norito::CompressionConfig::default())) {
            Ok(bytes) => {
                assert!(bytes.len() <= STREAM_TOKEN_MAX_WIRE_BYTES_V1);
                assert_eq!(
                    norito::decode_from_bytes::<StreamTokenV1>(&bytes).unwrap(),
                    token
                );
                Some(bytes)
            }
            Err(norito::Error::Io(error))
                if error.kind() == std::io::ErrorKind::Other
                    && error.to_string() == "compression support disabled" =>
            {
                None
            }
            Err(error) => panic!("genuine compression fixture failed: {error}"),
        };
    let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let measured = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128);
    let encoded = STANDARD.encode(&canonical);
    for flags in canonical_token_layouts() {
        let _layout = norito::core::DecodeFlagsGuard::enter(flags);
        let (positive, usage) =
            norito::core::with_decode_limits_measured(measured, || decode_stream_token(&encoded));
        assert_eq!(positive.unwrap(), token);
        assert!(usage.total_allocated_bytes() > 0);
        assert!(usage.total_elements() > 0);
        assert!(matches!(
            norito::with_decode_limits_scope(no_allocation, || decode_stream_token(&encoded)),
            Err(StreamTokenDecodeError::InvalidPayload(
                norito::Error::TotalAllocationExceeded { limit: 0, .. }
            ))
        ));
        for frame in [&tagged, &advertised].into_iter().chain(compressed.iter()) {
            let input = STANDARD.encode(frame);
            let (result, usage) = norito::core::with_decode_limits_measured(no_allocation, || {
                decode_stream_token(&input)
            });
            assert!(matches!(
                result,
                Err(StreamTokenDecodeError::NonCanonicalPayload)
            ));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
        }
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
}

#[test]
fn canonical_token_wire_change_preserves_signature_provider_time_and_size_denials() {
    let sample = canonical_token_fixture();
    let canonical = norito::encode_canonical(&sample).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = sample.body.clone();
    expired.issued_at = now - 60;
    expired.ttl_epoch = now;
    let expired = StreamTokenV1::sign(expired, &gateway_signing_key()).unwrap();
    let mut future = sample.body.clone();
    future.issued_at = now + STREAM_TOKEN_CLOCK_SKEW_SECS + 120;
    future.ttl_epoch = future.issued_at + 60;
    let future = StreamTokenV1::sign(future, &gateway_signing_key()).unwrap();
    let mut inverted = sample.body.clone();
    inverted.ttl_epoch = inverted.issued_at;
    let inverted = StreamTokenV1::sign(inverted, &gateway_signing_key()).unwrap();
    let mut tampered = sample.clone();
    tampered.signature[0] ^= 1;
    let mut trailing = canonical.clone();
    trailing.push(0);
    for flags in canonical_token_layouts() {
        let _layout = norito::core::DecodeFlagsGuard::enter(flags);
        for frame in [&trailing[..], &canonical[..canonical.len() - 1]] {
            assert!(matches!(
                decode_stream_token(&STANDARD.encode(frame)),
                Err(StreamTokenDecodeError::InvalidPayload(_))
            ));
        }
        assert!(matches!(
            decode_stream_token("!"),
            Err(StreamTokenDecodeError::InvalidBase64(_))
        ));
        assert!(matches!(
            decode_stream_token(&format!(" {}", STANDARD.encode(&canonical))),
            Err(StreamTokenDecodeError::NonCanonicalBase64)
        ));
        assert!(matches!(
            decode_stream_token(&"A".repeat(STREAM_TOKEN_MAX_BASE64_BYTES_V1 + 1)),
            Err(StreamTokenDecodeError::Oversized)
        ));
        assert!(matches!(
            decode_stream_token(&STANDARD.encode(vec![0; STREAM_TOKEN_MAX_WIRE_BYTES_V1 + 1])),
            Err(StreamTokenDecodeError::Oversized)
        ));
        let admit = |token: &StreamTokenV1| {
            build_test_context(
                gateway_config(&"11".repeat(32), &chunker_handle()),
                [gateway_provider_input(token)],
            )
        };
        admit(&sample).expect("signed positive remains admissible in every caller context");
        assert!(matches!(
            admit(&tampered),
            Err(GatewayBuildError::InvalidStreamTokenSignature { .. })
        ));
        assert!(matches!(
            admit(&expired),
            Err(GatewayBuildError::ExpiredStreamToken { .. })
        ));
        assert!(matches!(
            admit(&future),
            Err(GatewayBuildError::FutureStreamToken { .. })
        ));
        assert!(matches!(
            admit(&inverted),
            Err(GatewayBuildError::InvalidStreamTokenLifetime { .. })
        ));
        let mut wrong_provider = gateway_provider_input(&sample);
        wrong_provider.provider_id_hex = "bc".repeat(32);
        assert!(matches!(
            build_test_context(
                gateway_config(&"11".repeat(32), &chunker_handle()),
                [wrong_provider]
            ),
            Err(GatewayBuildError::ProviderIdMismatch { .. })
        ));
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
}

#[test]
fn invalid_stream_token_keeps_provider_identity_and_original_decode_cause() {
    let token = canonical_token_fixture();
    let provider = provider_id_hex();
    for (encoded, malformed_payload) in [
        (String::from("!"), false),
        (STANDARD.encode(b"invalid"), true),
    ] {
        let mut input = gateway_provider_input(&token);
        input.stream_token_b64 = encoded;
        let error =
            build_test_context(gateway_config(&"11".repeat(32), &chunker_handle()), [input])
                .expect_err("malformed token must fail gateway admission");
        assert!(error.to_string().contains(&provider));
        let GatewayBuildError::InvalidStreamToken {
            provider_id,
            source,
        } = error
        else {
            panic!("expected original stream-token decode error");
        };
        assert_eq!(provider_id.as_ref(), provider);
        if malformed_payload {
            assert!(matches!(source, StreamTokenDecodeError::InvalidPayload(_)));
        } else {
            assert!(matches!(source, StreamTokenDecodeError::InvalidBase64(_)));
        }
    }
}
