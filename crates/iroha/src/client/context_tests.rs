//! Construction failures and cache isolation for immutable client contexts.

use super::{
    evidence_http_tests::{base_url, client_with_base_url},
    *,
};

#[test]
fn shared_capability_probe_preserves_typed_timeout_classification() {
    let coordinator = CompatibilityProbeCoordinator::new();
    let observed = coordinator.generation();
    let cause: eyre::Report =
        std::io::Error::new(std::io::ErrorKind::TimedOut, "bounded request").into();
    let immediate = coordinator.finish_failure(&cause.wrap_err("capability request"));
    assert!(immediate.is_timeout());
    let shared = coordinator.completion_after(observed).unwrap().unwrap_err();
    assert!(shared.is_timeout());
    assert!(CapabilityProbeError::from_report(&eyre::Report::new(shared)).is_timeout());
    let unrelated = coordinator.finish_failure(&eyre!("a non-timeout error mentioning timeout"));
    assert!(
        !unrelated.is_timeout(),
        "error text cannot authorize timeout recovery"
    );
}

#[test]
fn request_deadline_clones_context_and_survives_rebuilding() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let original = client_with_base_url(base_url()).with_test_http_transport(
        DefaultHttpTransport::mock(Arc::new(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(http::Response::new(Vec::new()))
        })),
    );
    let bounded = original.with_request_deadline(std::time::Instant::now());
    assert!(Arc::ptr_eq(
        &original.data_model_compatibility,
        &bounded.data_model_compatibility
    ));
    assert!(Arc::ptr_eq(
        &original.compatibility_probe,
        &bounded.compatibility_probe
    ));
    assert!(
        original
            .http_transport
            .shares_pools_with(&bounded.http_transport)
    );
    let rebuilt = bounded
        .to_builder()
        .build()
        .expect("bounded rebuilt context")
        .with_request_deadline(std::time::Instant::now() + Duration::from_secs(60));
    for client in [&bounded, &rebuilt] {
        let error = client
            .default_request(HttpMethod::POST, base_url())
            .build()
            .unwrap()
            .send_blocking()
            .expect_err("no dispatch after original deadline");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    original
        .default_request(HttpMethod::GET, base_url())
        .build()
        .unwrap()
        .send_blocking()
        .expect("original client remains usable");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn request_deadline_bounds_waiting_for_blocking_compatibility_probe() {
    let client = client_with_base_url(base_url());
    let _occupied = client.compatibility_probe.gate.blocking_lock();
    let bounded =
        client.with_request_deadline(std::time::Instant::now() + Duration::from_millis(30));
    let started = std::time::Instant::now();
    let error = bounded
        .ensure_data_model_compatibility()
        .expect_err("sibling probe must not extend deadline");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn request_deadline_bounds_waiting_for_async_compatibility_probe() {
    let client = client_with_base_url(base_url());
    let _occupied = client.compatibility_probe.gate.lock().await;
    let bounded =
        client.with_request_deadline(std::time::Instant::now() + Duration::from_millis(30));
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        bounded.ensure_compatibility(CompatibilityRequirement::Submission, false),
    )
    .await
    .expect("sibling probe must not extend deadline");
    let error = result.expect_err("deadline ends compatibility wait");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
}

#[test]
fn rebuilding_never_inherits_compatibility_or_in_flight_probes() {
    let original = client_with_base_url(base_url());
    original.store_compatibility_outcome(DataModelCompatibility::SubmitCompatible);
    let clone = original.clone();
    assert!(Arc::ptr_eq(
        &original.data_model_compatibility,
        &clone.data_model_compatibility
    ));
    assert!(Arc::ptr_eq(
        &original.compatibility_probe,
        &clone.compatibility_probe
    ));

    let mut builder = original.to_builder();
    builder.chain = "independent context chain".parse().expect("chain identity");
    builder.torii_url = "https://other.example/api/".parse().expect("endpoint");
    builder.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"independent context network",
    )));
    builder.key_pair = checked_random_keypair();
    builder.account = AccountId::new(builder.key_pair.public_key().clone());
    builder.account_chain_discriminant = 4242;
    let rebuilt = builder.build().expect("new independent context");
    assert!(!Arc::ptr_eq(
        &original.data_model_compatibility,
        &rebuilt.data_model_compatibility
    ));
    assert!(!Arc::ptr_eq(
        &original.compatibility_probe,
        &rebuilt.compatibility_probe
    ));
    assert_ne!(original.endpoint(), rebuilt.endpoint());
    assert_ne!(original.network_id(), rebuilt.network_id());
    assert_ne!(original.account(), rebuilt.account());
    assert_eq!(rebuilt.account_chain_discriminant(), 4242);
    assert_eq!(original.endpoint(), &base_url());

    // A late completion owned by an old context cannot populate the new cache.
    clone.store_compatibility_outcome(DataModelCompatibility::Incompatible(
        DataModelCompatibilityError::Missing {
            expected: DATA_MODEL_VERSION,
        },
    ));
    assert!(matches!(
        *rebuilt.data_model_compatibility.lock().expect("cache"),
        DataModelCompatibility::Unchecked
    ));
    let account = rebuilt.account_client().expect("account context");
    assert_eq!(account.chain_id(), rebuilt.chain());
    assert_ne!(account.chain_id(), original.chain());
    assert_eq!(account.endpoint(), rebuilt.endpoint());
    assert_eq!(account.network_id(), rebuilt.network_id());
    assert_eq!(account.authority(), rebuilt.account());
}

#[test]
fn context_builder_rejects_ambiguous_and_invalid_headers_without_values_in_errors() {
    for headers in [
        HashMap::from([
            (String::from("Authorization"), String::from("secret-one")),
            (String::from("authorization"), String::from("secret-two")),
        ]),
        HashMap::from([(String::from("Invalid\nHeader"), String::from("secret-one"))]),
        HashMap::from([(
            String::from("Authorization"),
            String::from("secret-one\nsecret-two"),
        )]),
    ] {
        let mut builder = client_with_base_url(base_url()).to_builder();
        builder.headers = headers;
        let error = builder
            .build()
            .expect_err("invalid headers must fail before dispatch");
        assert!(matches!(
            error,
            SdkError::Context(
                AuthorityContextError::DuplicateHeader { .. }
                    | AuthorityContextError::InvalidHeaderName
                    | AuthorityContextError::InvalidHeaderValue { .. }
            )
        ));
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains("secret-one"));
            assert!(!diagnostic.contains("secret-two"));
        }
    }
}

#[test]
fn configured_authentication_has_one_case_insensitive_header() {
    let mut builder = client_with_base_url(base_url()).to_builder();
    builder.headers = HashMap::from([(
        String::from("Authorization"),
        String::from("Basic configured"),
    )]);
    let configured = builder
        .headers(HashMap::from([
            (
                String::from("authorization"),
                String::from("Bearer supplied"),
            ),
            (String::from("X-Application"), String::from("fixture")),
        ]))
        .build()
        .expect("unambiguous configuration");
    assert_eq!(configured.headers().len(), 2);
    assert_eq!(configured.headers()["authorization"], "Basic configured");
    assert_eq!(configured.headers()["x-application"], "fixture");
}

#[test]
fn address_formatting_is_validated_and_preserved_when_rebuilding() {
    let original = client_with_base_url(base_url());
    let builder = original.to_builder();
    assert_eq!(
        builder.account_chain_discriminant,
        original.account_chain_discriminant()
    );
    let mut invalid = builder;
    invalid.account_chain_discriminant = 0;
    {
        let actual_error = invalid.build().expect_err("zero address discriminant");
        let SdkError::Context(actual_source) = &actual_error else {
            panic!("unexpected SDK error: {actual_error:?}");
        };
        assert_eq!(
            actual_source,
            &(AuthorityContextError::InvalidAddressDiscriminant)
        );
    };
}

#[test]
fn context_configuration_survives_binding_and_rebuilding() {
    let mut builder = client_with_base_url(base_url()).to_builder();
    builder.chain = ChainId::from("configuration-fixture");
    builder.transaction_ttl = None;
    builder.transaction_status_timeout = Duration::from_secs(37);
    builder.torii_request_timeout = Duration::from_secs(19);
    builder.add_transaction_nonce = true;
    builder.wire_format_preference = WireFormatPreference::NoritoOnly;
    builder
        .headers
        .insert("X-Application".to_owned(), "fixture".to_owned());
    let expected = builder.clone();
    let client = builder.build().expect("configured context");
    for context in [
        client.clone(),
        client.to_builder().build().expect("rebuilt context"),
    ] {
        assert_eq!(context.chain(), &expected.chain);
        assert_eq!(context.network_id(), &expected.network_id);
        assert_eq!(context.endpoint(), &expected.torii_url);
        assert_eq!(context.account(), &expected.account);
        assert_eq!(
            context.key_pair().public_key(),
            expected.key_pair.public_key()
        );
        assert_eq!(
            context.account_chain_discriminant(),
            expected.account_chain_discriminant
        );
        assert_eq!(context.transaction_ttl(), None);
        assert_eq!(
            context.transaction_status_timeout(),
            Duration::from_secs(37)
        );
        assert_eq!(context.torii_request_timeout(), Duration::from_secs(19));
        assert!(context.add_transaction_nonce());
        assert_eq!(
            context.wire_format_preference(),
            WireFormatPreference::NoritoOnly
        );
        assert_eq!(context.headers()["x-application"], "fixture");
        assert_eq!(
            context.operator_key_pair().map(KeyPair::public_key),
            expected.operator_key_pair.as_ref().map(KeyPair::public_key)
        );
        assert_eq!(
            context.default_anonymity_policy(),
            expected.default_anonymity_policy
        );
        assert_eq!(context.rollout_phase(), expected.rollout_phase);
        assert_eq!(
            context.alias_cache_policy().positive_ttl(),
            expected.alias_cache_policy.positive_ttl()
        );
        assert_eq!(
            context.alias_cache_policy().refresh_window(),
            expected.alias_cache_policy.refresh_window()
        );
        assert_eq!(
            context.alias_cache_policy().hard_expiry(),
            expected.alias_cache_policy.hard_expiry()
        );
        assert_eq!(
            context.alias_cache_policy().negative_ttl(),
            expected.alias_cache_policy.negative_ttl()
        );
        assert_eq!(
            context.alias_cache_policy().revocation_ttl(),
            expected.alias_cache_policy.revocation_ttl()
        );
        assert_eq!(
            context.alias_cache_policy().rotation_max_age(),
            expected.alias_cache_policy.rotation_max_age()
        );
        assert_eq!(
            context.alias_cache_policy().successor_grace(),
            expected.alias_cache_policy.successor_grace()
        );
        assert_eq!(
            context.alias_cache_policy().governance_grace(),
            expected.alias_cache_policy.governance_grace()
        );
    }
}
