//! Exact generated admission and pricing through original native genesis and a genuine paid H2.
//! This is component execution/finality evidence, not service or four-process qualification.

use super::native_fixture::{NativeFixture, balance, policy, quote_instructions};
use crate::{
    localnet::{LocalnetServiceProfile, prepare_localnet_at},
    managed::{
        LocalnetPorts,
        service_authority::{NetworkPurpose, ServiceAuthority},
    },
};
use iroha_core::{
    query::provider_admission::read_finalized_provider_admission_v1,
    state::{State, StorageReadOnly as _, WorldReadOnly},
};
use iroha_data_model::{
    asset::AssetId,
    isi::{InstructionBox, Log},
    permission::Permission,
};
use iroha_executor_data_model::permission::sorafs::CanSetSorafsPricing;

#[test]
fn generated_provider_admission_and_price_require_original_genesis_and_real_h2() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "native-provider-profile",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let plan = prepared
        .provider_service_plan(super::provider_id(&prepared, 0))
        .unwrap()
        .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let provider = plan.provider_id();
    let original = plan.admission_material();
    let genesis_time =
        u64::try_from(native.chain.genesis().header().creation_time().as_millis()).unwrap() / 1_000;
    assert!(
        read_finalized_provider_admission_v1(&native.chain.state().view(), provider, genesis_time)
            .is_err(),
        "genesis alone cannot export independently authenticated execution"
    );
    let asset = AssetId::new(
        policy(&authority).asset_definition,
        authority.config.account.clone(),
    );
    let before = balance(native.chain.state(), &asset);
    let signed = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "authenticate generated provider prerequisites".into(),
        ))],
    );
    let exact_wire = signed.encode_wire_v1().unwrap();
    assert_eq!(native.chain.commit(vec![signed]), vec![true]);
    assert!(
        balance(native.chain.state(), &asset) < before,
        "ordinary H2 pays the native fee"
    );
    let observed = native.observe(&authority);
    let tip = observed.verified_tip().unwrap();
    assert_eq!(tip.height(), 2);
    tip.verify_global_scope(plan.network_id(), authority.config.chain.as_ref())
        .unwrap();
    assert_eq!(tip.block().network_entrypoint_count(), 1);
    assert_eq!(
        tip.block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        exact_wire
    );
    let view = native.chain.state().view();
    let now = u64::try_from(tip.header().creation_time().as_millis()).unwrap() / 1_000;
    let admission = read_finalized_provider_admission_v1(&view, provider, now)
        .unwrap()
        .unwrap();
    assert!(admission.is_genesis_material());
    assert_eq!(
        admission.envelope().network_id,
        *plan.network_id().as_bytes()
    );
    assert_eq!(&admission.envelope().proposal, &original.proposal);
    assert_eq!(&admission.envelope().advert_body, &original.advert_body);
    assert_eq!(
        (
            admission.envelope().issued_at,
            admission.envelope().retention_epoch
        ),
        (original.issued_at, original.retention_epoch)
    );
    assert!(
        admission.envelope().council_signatures.is_empty(),
        "genesis provenance is not forged council approval"
    );
    assert!(
        read_finalized_provider_admission_v1(&view, provider, original.retention_epoch).is_err()
    );
    assert_eq!(
        view.world().provider_owners().get(&provider),
        Some(&plan.reserve_terms().provider_account)
    );
    assert_eq!(view.world().sorafs_pricing(), plan.pricing());
    assert!(
        view.world()
            .provider_credit_ledger()
            .get(&provider)
            .is_none()
    );
    assert!(
        view.world()
            .capacity_declarations()
            .get(&provider)
            .is_none()
    );
    let pricing_permission = Permission::from(CanSetSorafsPricing);
    for account in [
        &authority.config.account,
        authority
            .genesis
            .genesis
            .external_transactions()
            .next()
            .unwrap()
            .authority(),
    ] {
        assert!(
            view.world()
                .account_permissions()
                .get(account)
                .is_none_or(|permissions| !permissions.contains(&pricing_permission)),
            "temporary genesis pricing grant does not install runtime management permission"
        );
    }
    // Reuse the existing complete native World producer, then independently authenticate the
    // original pricing/owner and exact credit/capacity absence against challenged Global finality.
    let proof = native.policy_proof(&authority.config.account);
    assert_eq!(
        proof.world.schema_hash,
        State::native_world_schema_hash_v1().unwrap()
    );
    assert!(
        proof.current.is_none(),
        "provider admission creates no reserve policy"
    );
    let world = proof.world.authenticate(&tip).unwrap();
    world
        .verify_cell_value("world.sorafs_pricing", plan.pricing())
        .unwrap();
    world
        .verify_table_value(
            "world.provider_owners",
            &provider,
            &plan.reserve_terms().provider_account,
        )
        .unwrap();
    world.verify_provider_credit_absent(&provider).unwrap();
    world.verify_capacity_declaration_absent(&provider).unwrap();
    let recovered = prepared
        .provider_service_plan(super::provider_id(&prepared, 0))
        .unwrap()
        .unwrap();
    assert_eq!(recovered.admission_material(), original);
    assert_eq!(recovered.declaration(), plan.declaration());
    assert_eq!(recovered.https_origin(), plan.https_origin());
    let all = prepared.provider_service_plans().unwrap().unwrap();
    for (slot, selected) in all.iter().enumerate() {
        assert_eq!(usize::from(selected.slot()), slot);
        assert_eq!(selected.peer_index(), slot);
        assert_eq!(
            selected.original_profile_commitment(),
            plan.original_profile_commitment()
        );
        assert_eq!(selected.pricing(), plan.pricing());
        let provider = selected.provider_id();
        let admission = read_finalized_provider_admission_v1(&view, provider, now)
            .unwrap()
            .unwrap();
        assert!(admission.is_genesis_material());
        assert_eq!(
            admission.envelope().proposal,
            selected.admission_material().proposal
        );
        assert_eq!(
            admission.envelope().advert_body,
            selected.admission_material().advert_body
        );
        world
            .verify_table_value(
                "world.provider_owners",
                &provider,
                &selected.reserve_terms().provider_account,
            )
            .unwrap();
        world.verify_provider_credit_absent(&provider).unwrap();
        world.verify_capacity_declaration_absent(&provider).unwrap();
    }
}
