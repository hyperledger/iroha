#[test]
fn iterable_query_payload_decode_is_canonical_and_variant_safe() {
    use iroha_data_model::query::{
        account::prelude::FindAccountsWithAsset,
        domain::prelude::{FindDomains, FindDomainsByAccountId},
    };
    let unit_payload = norito::codec::Encode::encode(&FindDomains);
    assert!(decode_exact_in_scope::<FindDomains>(&unit_payload).is_ok());
    let mut trailing_unit_payload = unit_payload;
    trailing_unit_payload.push(0xA5);
    assert!(
        decode_exact_in_scope::<FindDomains>(&trailing_unit_payload).is_err(),
        "a unit query must not accept nonempty or trailing payload bytes"
    );
    let parameterized = FindDomainsByAccountId {
        id: ALICE_ID.clone(),
    };
    let parameterized_payload = norito::codec::Encode::encode(&parameterized);
    assert!(decode_exact_in_scope::<FindDomainsByAccountId>(&parameterized_payload).is_ok());
    assert!(
        decode_exact_in_scope::<FindDomains>(&parameterized_payload).is_err(),
        "a parameterized payload must not collide with the global unit query"
    );
    let mut trailing_parameterized_payload = parameterized_payload;
    trailing_parameterized_payload.push(0x5A);
    assert!(
        decode_exact_in_scope::<FindDomainsByAccountId>(&trailing_parameterized_payload).is_err(),
        "a parameterized query must reject trailing payload bytes"
    );
    let other_parameterized_payload = norito::codec::Encode::encode(&FindAccountsWithAsset {
        asset_definition: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        ),
    });
    assert!(
        decode_exact_in_scope::<FindDomains>(&other_parameterized_payload).is_err(),
        "another query variant's payload must not become a global domain query"
    );
}
#[test]
fn stored_query_revalidation_archive_ignores_ambient_norito_layout() {
    let request = block_request_with_payload(Vec::new()).request;
    let canonical = encode_stored_query_revalidation_request(&request, None)
        .expect("encode canonical stored-query request");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    assert_ne!(
        norito::to_bytes(&request).expect("encode alternate-layout stored-query request"),
        canonical,
        "fixture must exercise a distinct ambient Norito layout"
    );
    assert_eq!(
        encode_stored_query_revalidation_request(&request, None)
            .expect("encode stored-query request under alternate ambient layout"),
        canonical
    );
}
#[tokio::test]
async fn iterable_query_engines_reject_noncanonical_payloads_before_global_execution() -> Result<()>
{
    use iroha_data_model::query::{
        account::prelude::FindAccountsWithAsset,
        domain::prelude::{FindDomains, FindDomainsByAccountId},
    };
    let state = state_with_test_blocks_and_transactions(1, 1, 0)?;
    let state_view = state.view();
    let query_handle = state_view.query_handle().clone();
    let mut trailing_unit = norito::codec::Encode::encode(&FindDomains);
    trailing_unit.push(0xA5);
    let mut trailing_parameterized = norito::codec::Encode::encode(&FindDomainsByAccountId {
        id: ALICE_ID.clone(),
    });
    trailing_parameterized.push(0x5A);
    let cross_variant = norito::codec::Encode::encode(&FindAccountsWithAsset {
        asset_definition: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        ),
    });
    for (case, payload) in [
        ("trailing unit bytes", trailing_unit),
        ("trailing parameterized bytes", trailing_parameterized),
        ("cross-variant parameterized bytes", cross_variant),
        ("malformed bytes", vec![0xFF, 0x00, 0xA5]),
    ] {
        assert!(
            domain_request_with_payload(payload.clone())
                .execute(&query_handle, &state_view, &ALICE_ID)
                .is_err(),
            "stored execution accepted {case} as a global domain query"
        );
        assert!(
            domain_request_with_payload(payload.clone())
                .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
                .is_err(),
            "ephemeral execution accepted {case} as a global domain query"
        );
    }
    let cross_variant = norito::codec::Encode::encode(&FindAccountsWithAsset {
        asset_definition: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        ),
    });
    assert!(
        transaction_request_with_payload(cross_variant.clone())
            .execute(&query_handle, &state_view, &ALICE_ID)
            .is_err(),
        "stored execution treated FindAccountsWithAsset bytes as global transaction history"
    );
    assert!(
        transaction_request_with_payload(cross_variant.clone())
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .is_err(),
        "ephemeral execution treated FindAccountsWithAsset bytes as global transaction history"
    );
    assert!(
        block_request_with_payload(cross_variant.clone())
            .execute(&query_handle, &state_view, &ALICE_ID)
            .is_err(),
        "stored execution treated FindAccountsWithAsset bytes as global signed blocks"
    );
    assert!(
        block_request_with_payload(cross_variant.clone())
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .is_err(),
        "ephemeral execution treated FindAccountsWithAsset bytes as global signed blocks"
    );
    assert!(
        role_request_with_payload(cross_variant.clone())
            .execute(&query_handle, &state_view, &ALICE_ID)
            .is_err(),
        "stored execution treated FindAccountsWithAsset bytes as global roles"
    );
    assert!(
        role_request_with_payload(cross_variant)
            .execute_ephemeral(&query_handle, &state_view, &ALICE_ID)
            .is_err(),
        "ephemeral execution treated FindAccountsWithAsset bytes as global roles"
    );
    Ok(())
}
#[test]
fn checked_keypair_helpers_preserve_requested_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::Ed25519).algorithm(),
        Algorithm::Ed25519
    );
    #[cfg(feature = "bls")]
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::BlsNormal).algorithm(),
        Algorithm::BlsNormal
    );
}
fn dummy_accepted_transaction(network_id: NetworkId) -> AcceptedTransaction<'static> {
    let keypair = checked_keypair_with_algorithm(Algorithm::Ed25519);
    let authority = AccountId::new(keypair.public_key().clone());
    let mut builder = TransactionBuilder::new(
        network_id,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions([Log::new(Level::INFO, "dummy".to_owned())])
        .sign(keypair.private_key());
    AcceptedTransaction::new_unchecked(Cow::Owned(tx))
}
#[tokio::test]
async fn validate_for_client_world_parts_matches_state_view_path() {
    let state = State::new_for_testing(
        World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let limits = QueryLimits::default();
    ValidQueryRequest::validate_for_client_parts(
        QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters)),
        &ALICE_ID,
        &state.view(),
        limits,
    )
    .expect("state-view validation should pass");
    let world = state.world_view();
    let latest_block = state.latest_block_header_fast();
    ValidQueryRequest::validate_for_client_world_parts(
        QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters)),
        &ALICE_ID,
        &world,
        latest_block.as_ref(),
        limits,
        &state.ivm_execution_budget(),
    )
    .expect("world validation should pass");
}
