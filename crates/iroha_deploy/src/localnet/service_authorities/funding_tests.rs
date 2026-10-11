//! Genuine signed-genesis allocations and exact funding-gate refusal controls.
//!
//! Altered instruction projections exercise the private funding gate only. They are not
//! re-signed genesis, finality proofs, current native reserves or runtime authority claims.

use super::*;
use norito::core::DecodeBudgetContext;
use std::collections::BTreeMap;

fn fixture() -> (
    tempfile::TempDir,
    PreparedLocalnet,
    StreamTokenAuthorityManifest,
    Vec<InstructionBox>,
) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "original-service-funding",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let root = prepared.context.client_config.parent().unwrap();
    let config_bytes = iroha_fs::read_private(&prepared.peers[0].config_path, 1024 * 1024).unwrap();
    let config = parse_localnet_peer_config(
        std::str::from_utf8(&config_bytes).unwrap(),
        Some(&prepared.peers[0].config_path),
    )
    .unwrap();
    let genesis = RawGenesisTransaction::from_path(&root.join("genesis.json")).unwrap();
    let signed =
        iroha_fs::read_private(root.join("genesis.signed.nrt"), SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap();
    // Independently establish the source signature/manifest/hash before projecting any ISI.
    let verified = iroha_genesis::validate_prepared_genesis_bundle(
        &signed,
        &genesis,
        &config.genesis.public_key,
        config.genesis.expected_hash,
    )
    .unwrap();
    assert_eq!(verified.canonical_wire(), signed.as_slice());
    assert_eq!(
        NetworkId::from_genesis_hash(verified.block().hash()),
        manifest.network_id
    );
    let instructions = verified
        .block()
        .external_transactions()
        .flat_map(|transaction| transaction.instructions().explicit_instructions())
        .cloned()
        .collect();
    (temporary, prepared, manifest, instructions)
}

fn expected_funding(manifest: &StreamTokenAuthorityManifest) -> BTreeMap<AccountId, Quantity> {
    let mut expected = BTreeMap::new();
    for role in NETWORK_ROLES {
        expected.insert(
            manifest.network.authority(role).unwrap().account.clone(),
            Quantity::from(10_u64),
        );
    }
    for provider in &manifest.providers {
        for role in ROLES {
            if role.transacts() {
                expected.insert(
                    provider.authority(role).unwrap().account.clone(),
                    if role == StreamTokenAuthorityRole::IssuerOperator {
                        // Independent fixed stock plan: 12 XOR monthly rent × 2 underwriting,
                        // exceeding launch/admitted collateral 0.75, plus original 10 XOR fee headroom.
                        Quantity::from(34_u64)
                    } else {
                        Quantity::from(10_u64)
                    },
                );
            }
        }
    }
    expected
}

fn funding_refused(result: crate::managed::Result<()>) {
    assert!(matches!(
        result,
        Err(Error::Invalid(message)) if message == "invalid original service genesis funding"
    ));
}

#[test]
fn original_role_funding_rejects_missing_duplicate_incorrect_and_oversized_issuer_mints() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, _prepared, manifest, instructions) = fixture();
    let expected = expected_funding(&manifest);
    assert_eq!(expected.len(), 27);
    assert!(!expected.contains_key(&manifest.manager));
    validate_genesis_funding(&expected, &manifest.network.reserve_accounts, &instructions).unwrap();
    for provider in &manifest.providers {
        let asset = AssetId::new(
            localnet_xor_asset_definition_id(),
            provider
                .authority(StreamTokenAuthorityRole::IssuerOperator)
                .unwrap()
                .account
                .clone(),
        );
        let index = instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction.as_any().downcast_ref::<MintBox>(),
                    Some(MintBox::Asset(mint)) if mint.destination() == &asset
                )
            })
            .unwrap();
        for mutation in 0..4 {
            let mut changed = instructions.clone();
            match mutation {
                0 => {
                    changed.remove(index);
                }
                1 => changed[index] = Mint::asset_quantity(10_u64, asset.clone()).into(),
                2 => changed[index] = Mint::asset_quantity(35_u64, asset.clone()).into(),
                3 => changed.push(changed[index].clone()),
                _ => unreachable!(),
            }
            funding_refused(validate_genesis_funding(
                &expected,
                &manifest.network.reserve_accounts,
                &changed,
            ));
        }
    }
    for account in [
        &manifest.network.reserve_accounts.custody,
        &manifest.network.reserve_accounts.treasury,
    ] {
        let mut changed = instructions.clone();
        changed.push(
            Mint::asset_quantity(
                1_u64,
                AssetId::new(localnet_xor_asset_definition_id(), account.clone()),
            )
            .into(),
        );
        funding_refused(validate_genesis_funding(
            &expected,
            &manifest.network.reserve_accounts,
            &changed,
        ));
    }
    // Every mutation is a component projection; the unchanged authenticated original still passes.
    validate_genesis_funding(&expected, &manifest.network.reserve_accounts, &instructions).unwrap();
}

#[test]
fn original_issuer_funding_reproduces_principal_and_fee_headroom_across_generation() {
    let _resources = crate::managed::native_test_guard();
    for _ in 0..2 {
        let (_temporary, prepared, manifest, instructions) = fixture();
        let expected = expected_funding(&manifest);
        validate_genesis_funding(&expected, &manifest.network.reserve_accounts, &instructions)
            .unwrap();
        let plans = prepared.provider_service_plans().unwrap().unwrap();
        assert_eq!(plans.len(), 3);
        for plan in plans {
            let terms = plan.reserve_terms();
            let quote = iroha_data_model::sorafs::reserve::ReservePolicyV1::default()
                .quote(
                    terms.storage_class,
                    terms.capacity_gib,
                    terms.duration,
                    terms.tier,
                    sorafs_manifest::deal::XorQuantity::zero(),
                )
                .unwrap();
            assert_eq!(
                quote.reserve_requirement.as_quantity(),
                &Quantity::from(24_u64)
            );
            assert_eq!(
                plan.declaration().stake.stake_amount.as_quantity(),
                &"0.75".parse::<Quantity>().unwrap(),
            );
            assert_eq!(
                expected[&terms.provider_account],
                quote
                    .reserve_requirement
                    .into_quantity()
                    .checked_add(&Quantity::from(10_u64))
                    .unwrap(),
            );
            let inventory = manifest.provider(plan.provider_id()).unwrap();
            for role in ROLES.into_iter().filter(|role| role.transacts()) {
                assert_eq!(
                    expected[&inventory.authority(role).unwrap().account],
                    Quantity::from(if role == StreamTokenAuthorityRole::IssuerOperator {
                        34_u64
                    } else {
                        10_u64
                    }),
                );
            }
        }
    }
}

fn caller_limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

#[test]
fn original_role_funding_preserves_enclosing_budget_refusal_and_same_source_retry() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, manifest, _instructions) = fixture();
    let baseline = DecodeBudgetContext::new(caller_limits(64 * 1024 * 1024));
    let restored = baseline
        .with(|| prepared.stream_token_authorities())
        .unwrap()
        .unwrap();
    assert_eq!(restored.network_id, manifest.network_id);
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 0);
    let exact = DecodeBudgetContext::new(caller_limits(usize::try_from(charge).unwrap()));
    let restored = exact
        .with(|| prepared.stream_token_authorities())
        .unwrap()
        .unwrap();
    assert_eq!(restored.network_id, manifest.network_id);
    assert_eq!(exact.consumed_allocated_bytes(), charge);
    let short = DecodeBudgetContext::new(caller_limits(usize::try_from(charge - 1).unwrap()));
    assert!(matches!(
        short.with(|| prepared.stream_token_authorities()),
        Err(Error::Invalid(message))
            if message == "retained stream-token authority prerequisites are invalid"
    ));
    let zero = DecodeBudgetContext::new(caller_limits(0));
    assert!(matches!(
        zero.with(|| prepared.stream_token_authorities()),
        Err(Error::Invalid(message))
            if message == "retained stream-token authority prerequisites are invalid"
    ));
    let retry = DecodeBudgetContext::new(caller_limits(usize::try_from(charge).unwrap()));
    let restored = retry
        .with(|| prepared.stream_token_authorities())
        .unwrap()
        .unwrap();
    assert_eq!(expected_funding(&restored), expected_funding(&manifest));
    assert_eq!(retry.consumed_allocated_bytes(), charge);
}
