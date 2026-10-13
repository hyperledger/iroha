// Actual CAR/chunk body ownership through the external durable admission and cleanup owners.

async fn assert_body_retains_route_lease(kind: CapabilityRangeKind, consume: bool) {
    let advert = make_signed_advert();
    let payload = b"accepted application bodies retain the stream lease".to_vec();
    let mut context = capability_token_context(&advert, payload.clone());
    let mut app = Arc::try_unwrap(context.app).unwrap_or_else(|_| panic!("exclusive route app"));
    let admission = ServingAdmissionFixture::new();
    app.stream_token_admission_capture = Some(admission.capture.clone());
    let cleanup = RangeCleanupTestOwner::install(&mut app, 64);
    context.app = Arc::new(app);
    let manifest = context.manifest();
    let digest = hex::encode(manifest.chunk(0).expect("stored fixture chunk").digest);
    let encoded = issue_token_base64(
        &context,
        TokenOverrides {
            max_streams: Some(1),
            ..TokenOverrides::default()
        },
    )
    .await;
    let headers = |nonce| {
        kind.headers(
            manifest.chunk_profile_handle(),
            manifest.content_length(),
            Some(&digest),
            &encoded,
            nonce,
        )
    };
    let expected_status = match kind {
        CapabilityRangeKind::Car => StatusCode::PARTIAL_CONTENT,
        CapabilityRangeKind::Chunk => StatusCode::OK,
    };
    let first = kind
        .request(
            &context,
            Some(digest.clone()),
            headers("body-retained-first"),
            8201,
        )
        .await;
    assert_eq!(first.status(), expected_status);
    assert_eq!(admission.active_leases(), 1);
    assert_eq!(admission.outcomes()[0].status, CustodyStatus::Accepted);
    let second = kind
        .request(
            &context,
            Some(digest.clone()),
            headers("body-retained-second"),
            8202,
        )
        .await;
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the first response body has not been consumed or cancelled"
    );
    assert_eq!(admission.active_leases(), 1);
    if consume {
        let actual = body::to_bytes(first.into_body(), 1024 * 1024)
            .await
            .expect("complete canonical response");
        match kind {
            CapabilityRangeKind::Car => assert!(!actual.is_empty()),
            CapabilityRangeKind::Chunk => assert_eq!(actual.as_ref(), payload.as_slice()),
        }
    } else {
        drop(first);
    }
    wait_for_range_cleanup(|| admission.active_leases() == 0).await;
    let retry = kind
        .request(
            &context,
            Some(digest.clone()),
            headers("body-retained-retry"),
            8203,
        )
        .await;
    assert_eq!(
        retry.status(),
        expected_status,
        "EOF or cancellation must release the exact prior lease"
    );
    assert_eq!(admission.active_leases(), 1);
    let actual = body::to_bytes(retry.into_body(), 1024 * 1024)
        .await
        .expect("retry response");
    assert!(!actual.is_empty());
    wait_for_range_cleanup(|| admission.active_leases() == 0).await;
    cleanup.finish().await;
}

#[tokio::test]
async fn car_route_body_retains_concurrency_until_eof_or_cancellation() {
    for consume in [false, true] {
        Box::pin(assert_body_retains_route_lease(
            CapabilityRangeKind::Car,
            consume,
        ))
        .await;
    }
}

#[tokio::test]
async fn chunk_route_body_retains_concurrency_until_eof_or_cancellation() {
    for consume in [false, true] {
        Box::pin(assert_body_retains_route_lease(
            CapabilityRangeKind::Chunk,
            consume,
        ))
        .await;
    }
}
#[derive(Clone, Copy)]
enum CapabilityRangeKind {
    Car,
    Chunk,
}

impl CapabilityRangeKind {
    fn headers(
        self,
        chunker_handle: &str,
        content_length: u64,
        chunk_digest_hex: Option<&str>,
        token_base64: &str,
        nonce: &str,
    ) -> HeaderMap {
        match self {
            Self::Car => car_range_headers(chunker_handle, content_length, token_base64, nonce),
            Self::Chunk => chunk_range_headers(
                chunker_handle,
                chunk_digest_hex.expect("chunk metadata present"),
                token_base64,
                nonce,
            ),
        }
    }

    async fn request(
        self,
        context: &TokenTestContext,
        chunk_digest_hex: Option<String>,
        headers: HeaderMap,
        port: u16,
    ) -> Response {
        match self {
            Self::Car => {
                api_test_route!(get_storage_car_range; State(context.app.clone()); Path(context.manifest_id_hex.clone()); headers; ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))))
            }
            Self::Chunk => {
                api_test_route!(get_storage_chunk; State(context.app.clone()); Path(( context.manifest_id_hex.clone(), chunk_digest_hex.expect("chunk metadata present"), )); headers; ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))))
            }
        }
    }
}
