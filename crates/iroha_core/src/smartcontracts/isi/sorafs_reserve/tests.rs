//! Reserve custody and durable state regression tests.
include!("schema_identity_tests.rs");
include!("finalized_fixture_tests.rs");
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
    block::BlockHeader,
    domain::Domain,
    isi::{Burn, Transfer, Unregister},
    permission::{Permission, Permissions},
    sorafs::{
        pin_registry::StorageClass,
        reserve::{
            ClassRentRate, RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveDuration, ReservePolicyV1,
            ReserveProviderTermsV1, ReserveTier,
        },
    },
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::{json::Json, numeric::Quantity};
use nonzero_ext::nonzero;
const NOW: u64 = 20_000;
const PROVIDER_ID: ProviderId = ProviderId::new([0x61; 32]);
fn keypair(seed: u8) -> KeyPair {
    let private = PrivateKey::from_bytes(Algorithm::Ed25519, &[seed; 32])
        .expect("valid deterministic Ed25519 seed");
    KeyPair::from_private_key(private).expect("derive deterministic keypair")
}
fn account(keypair: &KeyPair) -> AccountId {
    AccountId::new(keypair.public_key().clone())
}
fn asset_definition() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("reserve", "universal").expect("reserve domain"),
        "xor".parse().expect("reserve asset"),
    )
}
fn quantity_micro(micro: u128) -> Quantity {
    XorQuantity::try_from_micro(micro)
        .expect("micro-XOR fixture")
        .into_quantity()
}
fn xor_micro(micro: u128) -> XorQuantity {
    XorQuantity::try_from_micro(micro).expect("micro-XOR reserve fixture")
}
fn policy(
    revision: u64,
    predecessor_policy_digest: Option<[u8; 32]>,
    custody_account: AccountId,
    treasury_account: AccountId,
    service_authority: &AccountId,
) -> ReserveAuthorityPolicyV1 {
    ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision,
        predecessor_policy_digest,
        economics: ReservePolicyV1::default(),
        asset_definition: asset_definition(),
        custody_account,
        treasury_account,
        operations_authority: service_authority.clone(),
        decision_authority: service_authority.clone(),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: xor_micro(1_000_000_000),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    }
}
fn state_fixture(
    governance: &AccountId,
    provider: &AccountId,
    custody: &AccountId,
    treasury: &AccountId,
) -> State {
    state_fixture_with_provider_balance(
        governance,
        provider,
        custody,
        treasury,
        quantity_micro(100_000_000),
    )
}
fn state_fixture_with_provider_balance(
    governance: &AccountId,
    provider: &AccountId,
    custody: &AccountId,
    treasury: &AccountId,
    provider_balance: Quantity,
) -> State {
    let definition_id = asset_definition();
    let domain = Domain::new(DomainId::try_new("reserve", "universal").expect("reserve domain"))
        .build(governance);
    let definition = AssetDefinition::numeric(
        definition_id.clone(),
        "XOR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(governance);
    let provider_asset = Asset::new(
        AssetId::of(definition_id.clone(), provider.clone()),
        provider_balance,
    );
    let treasury_asset = Asset::new(
        AssetId::of(definition_id, treasury.clone()),
        quantity_micro(100_000_000),
    );
    let mut world = World::with_assets(
        [domain],
        [
            Account::new(governance.clone()).build(governance),
            Account::new(provider.clone()).build(provider),
            Account::new(custody.clone()).build(custody),
            Account::new(treasury.clone()).build(treasury),
        ],
        [definition],
        [provider_asset, treasury_asset],
        [],
    );
    let mut permissions = Permissions::new();
    permissions.insert(Permission::new(
        "CanSetSorafsReservePolicy".to_owned(),
        Json::new(()),
    ));
    world
        .account_permissions
        .insert(governance.clone(), permissions);
    world.provider_owners.insert(PROVIDER_ID, provider.clone());
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn terms(provider_account: AccountId) -> ReserveProviderTermsV1 {
    terms_for(PROVIDER_ID, provider_account)
}
fn terms_for(provider_id: ProviderId, provider_account: AccountId) -> ReserveProviderTermsV1 {
    ReserveProviderTermsV1 {
        provider_id,
        provider_account,
        tier: ReserveTier::TierA,
        storage_class: StorageClass::Hot,
        duration: ReserveDuration::Monthly,
        capacity_gib: 10,
    }
}
fn block_header_at(height: u64, now_unix: u64) -> BlockHeader {
    BlockHeader::new(
        height.try_into().expect("nonzero fixture block height"),
        None,
        None,
        now_unix * 1_000,
        0,
    )
}
fn transact(
    state: &mut State,
    height: u64,
    now_unix: u64,
    operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
) -> Result<(), InstructionExecutionError> {
    let invocation = Hash::new([height.to_le_bytes(), now_unix.to_le_bytes()].concat());
    transact_at_original_invocation(state, height, now_unix, invocation, operation)
}
// The original local component invocation must enter the finite pool before
// State is borrowed. This World-only fixture does not publish a Network carrier.
fn transact_at_original_invocation(
    state: &mut State,
    height: u64,
    now_unix: u64,
    invocation: Hash,
    operation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<(), InstructionExecutionError>,
) -> Result<(), InstructionExecutionError> {
    let header = block_header_at(height, now_unix);
    let mut block = state.block(header.clone());
    let mut transaction = block.transaction_for_fastpq_testing(invocation);
    operation(&mut transaction)?;
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit reserve test block");
    state.push_block_hash_for_testing(header.hash());
    Ok(())
}
fn reserve_asset_balance(state: &State, owner: &AccountId) -> XorQuantity {
    let view = state.view();
    let asset_id = AssetId::of(asset_definition(), owner.clone());
    view.world()
        .assets()
        .get(&asset_id)
        .map_or_else(XorQuantity::zero, |value| {
            XorQuantity::try_from_quantity(value.as_ref().clone())
                .expect("stored reserve asset is canonical")
        })
}
#[test]
fn reserve_component_funding_refuses_an_unretained_original_invocation() {
    let governance = account(&keypair(0xE1));
    let provider = account(&keypair(0xE2));
    let custody = account(&keypair(0xE3));
    let treasury = account(&keypair(0xE4));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let configured = policy(1, None, custody.clone(), treasury, &governance);
    let policy_digest = configured.digest().expect("original reserve policy");
    let invocation = Hash::prehashed([0xE5; Hash::LENGTH]);
    let request_id = [0xE6; 32];
    let prepare = |transaction: &mut StateTransaction<'_, '_>| {
        SetSorafsReservePolicy::new(configured.clone()).execute(&governance, transaction)?;
        RegisterSorafsReserveAccount::new(terms(provider.clone()), policy_digest)
            .execute(&governance, transaction)?;
        RequestSorafsReserveMovement::new(
            request_id,
            PROVIDER_ID,
            ReserveMovementKindV1::TopUp,
            xor_micro(1),
            1,
            policy_digest,
        )
        .execute(&provider, transaction)
    };
    let decision = DecideSorafsReserveMovement::new(
        request_id,
        2,
        policy_digest,
        true,
        "fund the original component invocation".to_owned(),
    );
    {
        let mut block = state.block(block_header_at(1, NOW));
        let mut transaction = block.transaction();
        transaction.tx_call_hash = Some(invocation);
        prepare(&mut transaction).expect("prepare the unchanged movement");
        let provider_before =
            read_provider(transaction.world(), PROVIDER_ID).expect("read original provider");
        let movement_before =
            read_movement(transaction.world(), request_id).expect("read original movement");
        let error = decision
            .clone()
            .execute(&governance, &mut transaction)
            .expect_err("assigning a hash cannot invent its finite source owner");
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            reason,
        )) = &error
        else {
            panic!("unexpected source refusal: {error:?}");
        };
        assert!(
            reason.contains("FASTPQ source has no retained producer invocation"),
            "source refusal: {error:?}"
        );
        assert_eq!(
            read_provider(transaction.world(), PROVIDER_ID).expect("read refused provider"),
            provider_before
        );
        assert_eq!(
            read_movement(transaction.world(), request_id).expect("read refused movement"),
            movement_before
        );
    }
    assert_eq!(
        reserve_asset_balance(&state, &provider),
        xor_micro(100_000_000)
    );
    assert!(reserve_asset_balance(&state, &custody).is_zero());
    transact_at_original_invocation(&mut state, 1, NOW, invocation, |transaction| {
        prepare(transaction)?;
        decision.execute(&governance, transaction)
    })
    .expect("the same original invocation funds native reserve custody");
    assert_eq!(
        reserve_asset_balance(&state, &provider),
        xor_micro(99_999_999)
    );
    assert_eq!(reserve_asset_balance(&state, &custody), xor_micro(1));
}
#[test]
fn domain_retirement_rejects_active_sorafs_reserve_backing_atomically() {
    let governance = account(&keypair(0x71));
    let provider = account(&keypair(0x72));
    let custody = account(&keypair(0x73));
    let treasury = account(&keypair(0x74));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    transact(&mut state, 1, NOW, |transaction| {
        let domain_id = DomainId::try_new("reserve", "universal").expect("reserve asset domain");
        // The hashed definition identity does not establish domain ownership.
        // This teardown fixture explicitly owns the backing definition in the
        // domain and uses the canonical World mutator to retain both indexes.
        let definition_id = asset_definition();
        transaction.world.insert_asset_definition_entry(
            definition_id.clone(),
            AssetDefinition::numeric(
                definition_id.clone(),
                "XOR".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(domain_id.clone()),
            )
            .build(&governance),
        );
        assert_eq!(
            transaction
                .world
                .asset_definition_domains
                .get(&definition_id),
            Some(&domain_id)
        );
        assert!(
            transaction
                .world
                .domain_asset_definitions
                .get(&(domain_id.clone(), definition_id.clone()))
                .is_some()
        );
        let configured = policy(1, None, custody.clone(), treasury.clone(), &governance);
        SetSorafsReservePolicy::new(configured).execute(&governance, transaction)?;
        let error = Unregister::domain(domain_id.clone())
            .execute(&governance, transaction)
            .expect_err("active SoraFS reserve backing must survive domain retirement");
        assert!(error.to_string().contains("active SoraFS reserve custody"));
        assert!(transaction.world.domains.get(&domain_id).is_some());
        assert!(
            transaction
                .world
                .asset_definitions
                .get(&asset_definition())
                .is_some()
        );
        assert!(read_reserve_state(transaction.world())?.is_some());
        Ok(())
    })
    .expect("reserve policy remains active after rejected domain retirement");
}

#[test]
fn reserve_custody_rejects_user_debits_but_allows_exact_approved_withdrawal() {
    let governance = account(&keypair(0x51));
    let provider = account(&keypair(0x52));
    let custody = account(&keypair(0x53));
    let treasury = account(&keypair(0x54));
    let mut state = state_fixture_with_provider_balance(
        &governance,
        &provider,
        &custody,
        &treasury,
        quantity_micro(500_000_000),
    );
    let top_up = xor_micro(300_000_000);
    let slash_lien = xor_micro(10_000_000);
    let withdrawal = xor_micro(1);
    transact_at_original_invocation(
        &mut state,
        1,
        NOW,
        Hash::prehashed([0x52; Hash::LENGTH]),
        |transaction| {
            let configured = policy(1, None, custody.clone(), treasury.clone(), &governance);
            let policy_digest = configured.digest().expect("reserve policy digest");
            SetSorafsReservePolicy::new(configured).execute(&governance, transaction)?;
            let persisted =
                read_reserve_state(transaction.world())?.expect("installed reserve state");
            crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
                &persisted,
                "iroha_data_model::sorafs::reserve::history::ReserveStateV1",
            );
            let frame = encode_state(&persisted, "reserve state")?;
            assert_eq!(decode_reserve_state(&frame)?, persisted);

            RegisterSorafsReserveAccount::new(terms(provider.clone()), policy_digest)
                .execute(&governance, transaction)?;
            RequestSorafsReserveMovement::new(
                [0x53; 32],
                PROVIDER_ID,
                ReserveMovementKindV1::TopUp,
                top_up.clone(),
                1,
                policy_digest,
            )
            .execute(&provider, transaction)?;
            DecideSorafsReserveMovement::new(
                [0x53; 32],
                2,
                policy_digest,
                true,
                "fund native reserve custody".to_owned(),
            )
            .execute(&governance, transaction)?;
            let custody_asset = AssetId::of(asset_definition(), custody.clone());
            let transfer_error = Transfer::asset_quantity(
                custody_asset.clone(),
                quantity_micro(1),
                provider.clone(),
            )
            .execute(&custody, transaction)
            .expect_err("ordinary transfer must not debit reserve custody");
            assert!(
                transfer_error
                    .to_string()
                    .contains("SoraFS reserve custody")
            );
            let burn_error = Burn::asset_quantity(quantity_micro(1), custody_asset)
                .execute(&custody, transaction)
                .expect_err("ordinary burn must not debit reserve custody");
            assert!(burn_error.to_string().contains("SoraFS reserve custody"));
            let account_error = Unregister::account(custody.clone())
                .execute(&governance, transaction)
                .expect_err("active reserve custody account must remain registered");
            assert!(account_error.to_string().contains("SoraFS reserve custody"));
            let definition_error = Unregister::asset_definition(asset_definition())
                .execute(&governance, transaction)
                .expect_err("active reserve asset definition must remain registered");
            assert!(
                definition_error
                    .to_string()
                    .contains("SoraFS reserve custody")
            );
            let mut credit = ProviderCreditRecord::new(
                PROVIDER_ID,
                Quantity::zero(),
                top_up.clone().into_quantity(),
                Quantity::zero(),
                Quantity::zero(),
                0,
                0,
                iroha_model_base::metadata::Metadata::default(),
            );
            credit
                .apply_penalty(&slash_lien.clone().into_quantity(), 1)
                .expect("apply custody-backed slash lien");
            transaction
                .world
                .provider_credit_ledger
                .insert(PROVIDER_ID, credit);
            RequestSorafsReserveMovement::new(
                [0x54; 32],
                PROVIDER_ID,
                ReserveMovementKindV1::Withdrawal,
                withdrawal.clone(),
                3,
                policy_digest,
            )
            .execute(&provider, transaction)?;
            DecideSorafsReserveMovement::new(
                [0x54; 32],
                4,
                policy_digest,
                true,
                "release exact approved withdrawal".to_owned(),
            )
            .execute(&governance, transaction)?;
            Ok(())
        },
    )
    .expect("reserve custody flow");
    assert_eq!(
        reserve_asset_balance(&state, &custody),
        top_up.checked_sub(&withdrawal).expect("bounded withdrawal")
    );
    assert_eq!(
        verified_provider_bond(state.view().world(), PROVIDER_ID, &provider, 10)
            .expect("remaining native reserve stays verified"),
        top_up.checked_sub(&withdrawal).expect("bounded withdrawal")
    );
    let view = state.view();
    let credit = view
        .world()
        .provider_credit_ledger()
        .get(&PROVIDER_ID)
        .expect("credit projection remains");
    assert_eq!(credit.slashed, slash_lien.clone().into_quantity());
    assert_eq!(
        credit.bonded,
        top_up
            .checked_sub(&slash_lien)
            .and_then(|bonded| bonded.checked_sub(&withdrawal))
            .expect("unslashed withdrawal projection")
            .into_quantity()
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn pending_operations_survive_concurrency_and_policy_rotation() {
    let governance = account(&keypair(0x71));
    let provider = account(&keypair(0x72));
    let custody = account(&keypair(0x73));
    let treasury = account(&keypair(0x74));
    let state = state_fixture(&governance, &provider, &custody, &treasury);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, NOW * 1_000, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    let first = policy(1, None, custody.clone(), treasury.clone(), &governance);
    let first_digest = first.digest().expect("first policy digest");
    assert!(
        SetSorafsReservePolicy::new(first.clone())
            .execute(&provider, &mut stx)
            .is_err(),
        "provider cannot activate reserve governance policy"
    );
    SetSorafsReservePolicy::new(first)
        .execute(&governance, &mut stx)
        .expect("activate first policy");
    RegisterSorafsReserveAccount::new(terms(provider.clone()), first_digest)
        .execute(&governance, &mut stx)
        .expect("register reserve account");
    stx.world.provider_owners.remove(PROVIDER_ID);
    assert!(
        read_provider(stx.world(), PROVIDER_ID)
            .expect("read provider after registry withdrawal")
            .is_some(),
        "registered reserve state remains authoritative after provider registry withdrawal"
    );
    for (id, revision) in [(0x81, 1), (0x82, 2)] {
        RequestSorafsReserveMovement::new(
            [id; 32],
            PROVIDER_ID,
            ReserveMovementKindV1::TopUp,
            xor_micro(10_000_000),
            revision,
            first_digest,
        )
        .execute(&provider, &mut stx)
        .expect("request concurrent top-up");
    }
    let pending = read_provider(stx.world(), PROVIDER_ID)
        .expect("read provider")
        .expect("provider");
    assert_eq!((pending.revision, pending.pending_movements), (3, 2));
    assert!(
        RequestSorafsReserveMovement::new(
            [0x83; 32],
            PROVIDER_ID,
            ReserveMovementKindV1::TopUp,
            xor_micro(1_000_000),
            1,
            first_digest,
        )
        .execute(&provider, &mut stx)
        .is_err(),
        "stale provider revision must fail closed"
    );
    assert_eq!(
        read_provider(stx.world(), PROVIDER_ID)
            .expect("read provider")
            .expect("provider"),
        pending
    );
    for (id, revision) in [(0x81, 3), (0x82, 4)] {
        DecideSorafsReserveMovement::new(
            [id; 32],
            revision,
            first_digest,
            true,
            "approved".to_owned(),
        )
        .execute(&governance, &mut stx)
        .expect("decide concurrent top-up");
    }
    RequestSorafsReserveMovement::new(
        [0x84; 32],
        PROVIDER_ID,
        ReserveMovementKindV1::TopUp,
        xor_micro(10_000_000),
        5,
        first_digest,
    )
    .execute(&provider, &mut stx)
    .expect("request before policy rotation");
    let second = policy(
        2,
        Some(first_digest),
        custody.clone(),
        treasury.clone(),
        &governance,
    );
    let second_digest = second.digest().expect("second policy digest");
    SetSorafsReservePolicy::new(second)
        .execute(&governance, &mut stx)
        .expect("rotate reserve policy");
    DecideSorafsReserveMovement::new(
        [0x84; 32],
        6,
        second_digest,
        true,
        "approved after rotation".to_owned(),
    )
    .execute(&governance, &mut stx)
    .expect("pending movement remains decidable after rotation");
    for (id, revision) in [(0x91_u8, 7), (0x92, 8)] {
        SubmitSorafsReserveAppeal::new(
            [id; 32],
            PROVIDER_ID,
            revision,
            ReserveLifecycleStage::Warning,
            "review lifecycle evidence".to_owned(),
            Some([id.wrapping_add(1); 32]),
            second_digest,
        )
        .execute(&provider, &mut stx)
        .expect("submit concurrent appeal");
    }
    for (id, revision) in [(0x91, 9), (0x92, 10)] {
        DecideSorafsReserveAppeal::new(
            [id; 32],
            revision,
            second_digest,
            false,
            "not substantiated".to_owned(),
        )
        .execute(&governance, &mut stx)
        .expect("decide concurrent appeal");
    }
    let before_cap_reduction = FindSorafsReserveProviderById::new(PROVIDER_ID)
        .execute(&stx)
        .expect("query provider");
    assert_eq!(before_cap_reduction.revision, 11);
    assert_eq!(before_cap_reduction.policy_digest, second_digest);
    assert_eq!(before_cap_reduction.reserve_balance, xor_micro(30_000_000));
    assert_eq!(
        verified_provider_bond(stx.world(), PROVIDER_ID, &provider, 10)
            .expect("approved native custody top-ups are verified collateral"),
        xor_micro(30_000_000)
    );
    assert_eq!(before_cap_reduction.open_appeals, 0);
    assert_eq!(
        FindSorafsReserveAppealById::new([0x91; 32])
            .execute(&stx)
            .expect("query appeal")
            .status,
        ReserveAppealStatusV1::Rejected
    );
    DrawSorafsReserveCredit::new(PROVIDER_ID, 11, xor_micro(10_000_000), second_digest)
        .execute(&governance, &mut stx)
        .expect("draw credit before cap reduction");
    assert_eq!(
        verified_provider_bond(stx.world(), PROVIDER_ID, &provider, 10)
            .expect("treasury-funded credit is held in custody but is not provider stake"),
        xor_micro(30_000_000)
    );
    let mut unsafe_apr_change = policy(
        3,
        Some(second_digest),
        custody.clone(),
        treasury.clone(),
        &governance,
    );
    unsafe_apr_change
        .economics
        .tiers
        .iter_mut()
        .find(|tier| tier.tier == ReserveTier::TierA)
        .expect("tier A fixture")
        .interest_apr_bps += 1;
    assert!(
        SetSorafsReservePolicy::new(unsafe_apr_change)
            .execute(&governance, &mut stx)
            .is_err(),
        "APR rotation with outstanding debt must fail rather than reprice it retroactively"
    );
    assert_eq!(
        read_policy(stx.world())
            .expect("read policy")
            .expect("active policy")
            .policy_digest,
        second_digest
    );
    let mut third = policy(
        3,
        Some(second_digest),
        custody.clone(),
        treasury.clone(),
        &governance,
    );
    third.max_provider_debt = xor_micro(1_000_000);
    let third_digest = third.digest().expect("third policy digest");
    SetSorafsReservePolicy::new(third)
        .execute(&governance, &mut stx)
        .expect("reduce credit cap below grandfathered principal");
    RepaySorafsReserveCredit::new(PROVIDER_ID, 12, xor_micro(10_000_000), third_digest)
        .execute(&provider, &mut stx)
        .expect("cap reduction must not brick repayment");
    let final_account = FindSorafsReserveProviderById::new(PROVIDER_ID)
        .execute(&stx)
        .expect("query final provider");
    assert_eq!(final_account.revision, 13);
    assert_eq!(final_account.policy_digest, third_digest);
    assert_eq!(final_account.reserve_balance, xor_micro(40_000_000));
    assert_eq!(final_account.debt_principal, XorQuantity::zero());
    assert_eq!(final_account.credit_cap, xor_micro(1_000_000));
    assert_eq!(
        verified_provider_bond(stx.world(), PROVIDER_ID, &provider, 10)
            .expect("repaid principal becomes owner-funded reserve"),
        xor_micro(40_000_000)
    );
    let provider_balance = stx
        .world
        .assets
        .get(&AssetId::of(asset_definition(), provider.clone()))
        .expect("provider asset")
        .as_ref()
        .clone();
    let custody_asset_id = AssetId::of(asset_definition(), custody);
    let custody_balance = stx
        .world
        .assets
        .get(&custody_asset_id)
        .expect("custody asset")
        .as_ref()
        .clone();
    assert_eq!(provider_balance, quantity_micro(60_000_000));
    assert_eq!(custody_balance, quantity_micro(40_000_000));
    stx.world.assets.remove(custody_asset_id);
    let error = verified_provider_bond(stx.world(), PROVIDER_ID, &provider, 10)
        .expect_err("an unfunded reserve partition must not qualify as bonded stake");
    assert!(matches!(
        error,
        InstructionExecutionError::InvariantViolation(message)
            if message.contains("aggregate provider reserve partitions exceed")
    ));
}
#[test]
fn committed_record_queries_are_finalized_exclusive_and_deterministic() {
    let governance = account(&keypair(0x81));
    let provider = account(&keypair(0x82));
    let custody = account(&keypair(0x83));
    let treasury = account(&keypair(0x84));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let mut first = policy(1, None, custody, treasury, &governance);
    first.max_open_appeals_per_provider = 4;
    let first_digest = first.digest().expect("reserve policy digest");
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(first).execute(&governance, transaction)
    })
    .expect("commit reserve policy");
    let provider_ids = [
        ProviderId::new([0x61; 32]),
        ProviderId::new([0x62; 32]),
        ProviderId::new([0x63; 32]),
    ];
    transact(&mut state, 2, NOW + 1, |transaction| {
        for provider_id in provider_ids {
            transaction
                .world
                .provider_owners
                .insert(provider_id, provider.clone());
        }
        for provider_id in [provider_ids[2], provider_ids[0], provider_ids[1]] {
            RegisterSorafsReserveAccount::new(
                terms_for(provider_id, provider.clone()),
                first_digest,
            )
            .execute(&governance, transaction)?;
        }
        for (movement_id, revision) in [([0xB3; 32], 1_u64), ([0xB1; 32], 2), ([0xB2; 32], 3)] {
            RequestSorafsReserveMovement::new(
                movement_id,
                provider_ids[0],
                ReserveMovementKindV1::TopUp,
                xor_micro(1_000_000),
                revision,
                first_digest,
            )
            .execute(&provider, transaction)?;
        }
        for (appeal_id, revision) in [([0xC3; 32], 4_u64), ([0xC1; 32], 5), ([0xC2; 32], 6)] {
            SubmitSorafsReserveAppeal::new(
                appeal_id,
                provider_ids[0],
                revision,
                ReserveLifecycleStage::Active,
                "review deterministic reserve evidence".to_owned(),
                Some([appeal_id[0].wrapping_add(1); 32]),
                first_digest,
            )
            .execute(&provider, transaction)?;
        }
        Ok(())
    })
    .expect("commit authoritative reserve records");
    let view = state.view();
    let provider_first = FindSorafsReserveProviders::new(None, None, 2)
        .execute(&view)
        .expect("query first provider page");
    assert_eq!(provider_first.finalized_cursor.height, 2);
    assert_eq!(
        provider_first
            .accounts
            .iter()
            .map(|account| account.terms.provider_id)
            .collect::<Vec<_>>(),
        provider_ids[..2]
    );
    assert!(provider_first.has_more);
    assert_eq!(provider_first.next_after, Some(provider_ids[1]));
    let provider_second = FindSorafsReserveProviders::new(
        Some(provider_first.finalized_cursor),
        provider_first.next_after,
        2,
    )
    .execute(&view)
    .expect("query second provider page");
    assert_eq!(
        provider_second
            .accounts
            .iter()
            .map(|account| account.terms.provider_id)
            .collect::<Vec<_>>(),
        vec![provider_ids[2]]
    );
    assert!(!provider_second.has_more);
    assert!(provider_second.next_after.is_none());
    let movement_first = FindSorafsReserveMovements::new(None, None, 2)
        .execute(&view)
        .expect("query first movement page");
    assert_eq!(
        movement_first
            .movements
            .iter()
            .map(|movement| movement.movement_id)
            .collect::<Vec<_>>(),
        vec![[0xB1; 32], [0xB2; 32]]
    );
    assert!(movement_first.has_more);
    assert_eq!(movement_first.next_after, Some([0xB2; 32]));
    let movement_second = FindSorafsReserveMovements::new(
        Some(movement_first.finalized_cursor),
        movement_first.next_after,
        2,
    )
    .execute(&view)
    .expect("query second movement page");
    assert_eq!(
        movement_second
            .movements
            .iter()
            .map(|movement| movement.movement_id)
            .collect::<Vec<_>>(),
        vec![[0xB3; 32]]
    );
    assert!(!movement_second.has_more);
    assert!(movement_second.next_after.is_none());
    let appeal_first = FindSorafsReserveAppeals::new(None, None, 2)
        .execute(&view)
        .expect("query first appeal page");
    assert_eq!(
        appeal_first
            .appeals
            .iter()
            .map(|appeal| appeal.appeal_id)
            .collect::<Vec<_>>(),
        vec![[0xC1; 32], [0xC2; 32]]
    );
    assert!(appeal_first.has_more);
    assert_eq!(appeal_first.next_after, Some([0xC2; 32]));
    let appeal_second = FindSorafsReserveAppeals::new(
        Some(appeal_first.finalized_cursor),
        appeal_first.next_after,
        2,
    )
    .execute(&view)
    .expect("query second appeal page");
    assert_eq!(
        appeal_second
            .appeals
            .iter()
            .map(|appeal| appeal.appeal_id)
            .collect::<Vec<_>>(),
        vec![[0xC3; 32]]
    );
    assert!(!appeal_second.has_more);
    assert!(appeal_second.next_after.is_none());
    let mut stale_anchor = provider_first.finalized_cursor;
    stale_anchor.block_hash[0] ^= 0xFF;
    assert_eq!(
        FindSorafsReserveProviders::new(Some(stale_anchor), None, 1).execute(&view),
        Err(QueryExecutionFail::Expired)
    );
    assert_eq!(
        FindSorafsReserveMovements::new(Some(stale_anchor), None, 1).execute(&view),
        Err(QueryExecutionFail::Expired)
    );
    assert_eq!(
        FindSorafsReserveAppeals::new(Some(stale_anchor), None, 1).execute(&view),
        Err(QueryExecutionFail::Expired)
    );
}
#[test]
fn committed_record_queries_enforce_limits_budgets_and_corruption_checks() {
    let governance = account(&keypair(0x85));
    let provider = account(&keypair(0x86));
    let custody = account(&keypair(0x87));
    let treasury = account(&keypair(0x88));
    let build_policy_state = || {
        let mut state = state_fixture(&governance, &provider, &custody, &treasury);
        let first = policy(1, None, custody.clone(), treasury.clone(), &governance);
        transact(&mut state, 1, NOW, |transaction| {
            SetSorafsReservePolicy::new(first).execute(&governance, transaction)
        })
        .expect("commit reserve policy fixture");
        state
    };
    let state = build_policy_state();
    let view = state.view();
    for invalid_limit in [0, RESERVE_QUERY_MAX_ITEMS_V1 + 1] {
        assert!(matches!(
            FindSorafsReserveProviders::new(None, None, invalid_limit).execute(&view),
            Err(QueryExecutionFail::Conversion(_))
        ));
        assert!(matches!(
            FindSorafsReserveMovements::new(None, None, invalid_limit).execute(&view),
            Err(QueryExecutionFail::Conversion(_))
        ));
        assert!(matches!(
            FindSorafsReserveAppeals::new(None, None, invalid_limit).execute(&view),
            Err(QueryExecutionFail::Conversion(_))
        ));
    }
    let mut maximum_page = build_policy_state();
    {
        let header = block_header_at(2, NOW + 1);
        let mut block = maximum_page.block(header.clone());
        let mut transaction = block.transaction();
        for marker in 1_u8..=129 {
            let provider_id = ProviderId::new([marker; 32]);
            let account = ReserveProviderAccountV1 {
                terms: terms_for(provider_id, provider.clone()),
                policy_digest: read_policy(transaction.world())
                    .expect("read active policy")
                    .expect("active policy")
                    .policy_digest,
                revision: 1,
                reserve_balance: XorQuantity::zero(),
                debt_principal: XorQuantity::zero(),
                accrued_interest: XorQuantity::zero(),
                credit_cap: xor_micro(1_000_000_000),
                lifecycle_stage: ReserveLifecycleStage::Warning,
                days_past_due: 0,
                pending_movements: 0,
                open_appeals: 0,
                rent_charged_through_unix: NOW + 1,
                interest_accrued_at_unix: NOW + 1,
                updated_at_unix: NOW + 1,
            };
            transaction.world.smart_contract_state.insert(
                reserve_provider_key(provider_id),
                encode_state(&account, "maximum reserve provider page")
                    .expect("encode provider account"),
            );
        }
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit maximum provider page");
        maximum_page.push_block_hash_for_testing(header.hash());
    }
    let maximum = FindSorafsReserveProviders::new(None, None, RESERVE_QUERY_MAX_ITEMS_V1)
        .execute(&maximum_page.view())
        .expect("maximum provider page remains within query budgets");
    assert_eq!(
        maximum.accounts.len(),
        usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1).expect("query maximum fits usize")
    );
    assert_eq!(
        maximum.accounts[0].terms.provider_id,
        ProviderId::new([1; 32])
    );
    assert_eq!(
        maximum
            .accounts
            .last()
            .expect("terminal provider")
            .terms
            .provider_id,
        ProviderId::new([128; 32])
    );
    assert!(maximum.has_more);
    assert_eq!(maximum.next_after, Some(ProviderId::new([128; 32])));
    let mut mismatched_key = build_policy_state();
    {
        let header = block_header_at(2, NOW + 1);
        let mut block = mismatched_key.block(header.clone());
        let mut transaction = block.transaction();
        let mut account = ReserveProviderAccountV1 {
            terms: terms_for(ProviderId::new([0x21; 32]), provider.clone()),
            policy_digest: read_policy(transaction.world())
                .expect("read active policy")
                .expect("active policy")
                .policy_digest,
            revision: 1,
            reserve_balance: XorQuantity::zero(),
            debt_principal: XorQuantity::zero(),
            accrued_interest: XorQuantity::zero(),
            credit_cap: xor_micro(1_000_000),
            lifecycle_stage: ReserveLifecycleStage::Warning,
            days_past_due: 0,
            pending_movements: 0,
            open_appeals: 0,
            rent_charged_through_unix: NOW + 1,
            interest_accrued_at_unix: NOW + 1,
            updated_at_unix: NOW + 1,
        };
        account.terms.provider_id = ProviderId::new([0x22; 32]);
        transaction.world.smart_contract_state.insert(
            reserve_provider_key(ProviderId::new([0x21; 32])),
            encode_state(&account, "mismatched reserve provider")
                .expect("encode mismatched provider"),
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit mismatched provider key");
        mismatched_key.push_block_hash_for_testing(header.hash());
    }
    assert!(matches!(
        FindSorafsReserveProviders::new(None, None, 1).execute(&mismatched_key.view()),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("key does not match")
    ));
    let mut oversized_record = build_policy_state();
    {
        let header = block_header_at(2, NOW + 1);
        let mut block = oversized_record.block(header.clone());
        let mut transaction = block.transaction();
        transaction.world.smart_contract_state.insert(
            reserve_provider_key(ProviderId::new([0x31; 32])),
            vec![0xFF; RESERVE_QUERY_MAX_RECORD_BYTES_V1 + 1],
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit oversized provider record");
        oversized_record.push_block_hash_for_testing(header.hash());
    }
    assert!(matches!(
        FindSorafsReserveProviders::new(None, None, 1).execute(&oversized_record.view()),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("record exceeds")
    ));
    validate_encoded_record_page(&vec![0_u8; RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1 - 64])
        .expect("record page below the response-byte ceiling is accepted");
    assert!(matches!(
        validate_encoded_record_page(&vec![
            0_u8;
            RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1
        ]),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("record page encodes")
    ));
    let mut read_budget = ReserveEventQueryBudgetV1::default();
    read_budget
        .inspect_storage_probe(1, None, RESERVE_QUERY_MAX_EVENT_READ_BYTES_V1)
        .expect("exact reserve query read-byte ceiling is accepted");
    assert!(matches!(
        read_budget.inspect_storage_probe(1, None, 1),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("read bytes")
    ));
    let mut probe_budget = ReserveEventQueryBudgetV1::default();
    for _ in 0..RESERVE_QUERY_MAX_EVENT_STORAGE_PROBES_V1 {
        probe_budget
            .inspect_storage_probe(1, None, 0)
            .expect("exact reserve query storage-probe ceiling is accepted");
    }
    assert!(matches!(
        probe_budget.inspect_storage_probe(1, None, 0),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("storage probes")
    ));
    let mut key_budget = ReserveEventQueryBudgetV1::default();
    for _ in 0..128 {
        key_budget
            .inspect_storage_probe(RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1, None, 0)
            .expect("exact reserve query key-byte ceiling is accepted");
    }
    assert!(matches!(
        key_budget.inspect_storage_probe(1, None, 0),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("probed key bytes")
    ));
}
#[test]
fn persisted_reserve_event_requires_exact_lifecycle_projection_shape() {
    let authority = account(&keypair(0x89));
    let event_record =
        |kind, provider_id, operation_id, provider_revision, resulting_lifecycle_stage| {
            ReservePersistedEventV1 {
                sequence: 1,
                target_block_height: 1,
                event_index: 0,
                event: SorafsReserveLedgerEvent {
                    kind,
                    provider_id,
                    operation_id,
                    policy_digest: [0x8A; 32],
                    provider_revision,
                    resulting_lifecycle_stage,
                    authority: authority.clone(),
                    occurred_at_unix_ms: 1,
                },
            }
        };
    let policy_activation = event_record(
        SorafsReserveLedgerEventKind::PolicyActivated,
        None,
        None,
        0,
        None,
    );
    validate_persisted_event(&policy_activation, 1)
        .expect("policy activation without provider lifecycle is valid");
    crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
        &policy_activation,
        "iroha_core::smartcontracts::isi::sorafs_reserve::ReservePersistedEventV1",
    );
    let bytes = encode_state(&policy_activation, "reserve event").expect("production event writer");
    let decoded: ReservePersistedEventV1 =
        decode_state(&bytes, "reserve event").expect("bounded event reader");
    validate_persisted_event(&decoded, 1).expect("decoded event projection validates");
    assert_eq!(decoded, policy_activation);

    let mut policy_with_provider_stage = policy_activation;
    policy_with_provider_stage.event.resulting_lifecycle_stage =
        Some(ReserveLifecycleStage::Active);
    assert!(matches!(
        validate_persisted_event(&policy_with_provider_stage, 1),
        Err(InstructionExecutionError::InvariantViolation(_))
    ));
    for (kind, operation_id, provider_revision) in [
        (SorafsReserveLedgerEventKind::ProviderRegistered, None, 1),
        (
            SorafsReserveLedgerEventKind::MovementRequested,
            Some([0x81; 32]),
            2,
        ),
        (
            SorafsReserveLedgerEventKind::MovementApproved,
            Some([0x82; 32]),
            2,
        ),
        (
            SorafsReserveLedgerEventKind::MovementRejected,
            Some([0x83; 32]),
            2,
        ),
        (SorafsReserveLedgerEventKind::RentCharged, None, 2),
        (SorafsReserveLedgerEventKind::LifecycleAdvanced, None, 2),
        (SorafsReserveLedgerEventKind::CreditDrawn, None, 2),
        (SorafsReserveLedgerEventKind::CreditRepaid, None, 2),
        (
            SorafsReserveLedgerEventKind::AppealSubmitted,
            Some([0x84; 32]),
            2,
        ),
        (
            SorafsReserveLedgerEventKind::AppealAccepted,
            Some([0x85; 32]),
            2,
        ),
        (
            SorafsReserveLedgerEventKind::AppealRejected,
            Some([0x86; 32]),
            2,
        ),
    ] {
        let projected = event_record(
            kind,
            Some(PROVIDER_ID),
            operation_id,
            provider_revision,
            Some(ReserveLifecycleStage::Warning),
        );
        validate_persisted_event(&projected, 1)
            .expect("provider event with resulting lifecycle is valid");
        let mut missing_projection = projected;
        missing_projection.event.resulting_lifecycle_stage = None;
        assert!(matches!(
            validate_persisted_event(&missing_projection, 1),
            Err(InstructionExecutionError::InvariantViolation(_))
        ));
    }
}
#[test]
#[allow(clippy::too_many_lines)]
fn provider_event_projection_uses_exact_authoritative_after_state() {
    let governance = account(&keypair(0x8B));
    let provider = account(&keypair(0x8C));
    let custody = account(&keypair(0x8D));
    let treasury = account(&keypair(0x8E));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let first = policy(1, None, custody, treasury, &governance);
    let first_digest = first.digest().expect("reserve policy digest");
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(first).execute(&governance, transaction)?;
        RegisterSorafsReserveAccount::new(terms(provider.clone()), first_digest)
            .execute(&governance, transaction)
    })
    .expect("activate policy and register reserve provider");
    let lifecycle_at = NOW + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1 + 31 * 86_400;
    let header = block_header_at(2, lifecycle_at);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 1, 31, first_digest)
        .execute(&governance, &mut transaction)
        .expect("advance provider to default");
    SubmitSorafsReserveAppeal::new(
        [0x8F; 32],
        PROVIDER_ID,
        2,
        ReserveLifecycleStage::Active,
        "restore active lifecycle".to_owned(),
        Some([0x90; 32]),
        first_digest,
    )
    .execute(&provider, &mut transaction)
    .expect("submit lifecycle appeal");
    DecideSorafsReserveAppeal::new(
        [0x8F; 32],
        3,
        first_digest,
        true,
        "appeal accepted".to_owned(),
    )
    .execute(&governance, &mut transaction)
    .expect("accept lifecycle appeal");
    assert_eq!(
        (1..=5)
            .map(|sequence| {
                read_persisted_event(transaction.world(), sequence)
                    .expect("read reserve event")
                    .expect("reserve event exists")
                    .event
                    .resulting_lifecycle_stage
            })
            .collect::<Vec<_>>(),
        vec![
            None,
            Some(ReserveLifecycleStage::Warning),
            Some(ReserveLifecycleStage::Default),
            Some(ReserveLifecycleStage::Default),
            Some(ReserveLifecycleStage::Active),
        ]
    );
    let account = read_provider(transaction.world(), PROVIDER_ID)
        .expect("read provider after appeal")
        .expect("provider exists");
    assert_eq!(account.lifecycle_stage, ReserveLifecycleStage::Active);
    let journal_head = read_reserve_state(transaction.world())
        .expect("read reserve state")
        .expect("reserve state exists")
        .journal_head;
    let next_sequence = journal_head
        .last_sequence
        .checked_add(1)
        .expect("fixture journal sequence has room");
    let mismatched_revision = account
        .revision
        .checked_add(1)
        .expect("fixture provider revision has room");
    let mismatched_updated_at = NOW.checked_add(1).expect("fixture timestamp has room");
    for rejected in [
        emit_reserve_event(
            &mut transaction,
            SorafsReserveLedgerEventKind::RentCharged,
            PROVIDER_ID,
            None,
            [0x91; 32],
            account.revision,
            &governance,
            NOW,
        ),
        emit_reserve_event(
            &mut transaction,
            SorafsReserveLedgerEventKind::RentCharged,
            PROVIDER_ID,
            None,
            account.policy_digest,
            mismatched_revision,
            &governance,
            NOW,
        ),
        emit_reserve_event(
            &mut transaction,
            SorafsReserveLedgerEventKind::RentCharged,
            PROVIDER_ID,
            None,
            account.policy_digest,
            account.revision,
            &governance,
            mismatched_updated_at,
        ),
        emit_reserve_event(
            &mut transaction,
            SorafsReserveLedgerEventKind::PolicyActivated,
            PROVIDER_ID,
            None,
            account.policy_digest,
            account.revision,
            &governance,
            NOW,
        ),
    ] {
        assert!(matches!(
            rejected,
            Err(InstructionExecutionError::InvariantViolation(_))
        ));
    }
    assert_eq!(
        read_reserve_state(transaction.world())
            .expect("read reserve state after rejected events")
            .expect("reserve state exists")
            .journal_head,
        journal_head
    );
    assert!(
        transaction
            .world
            .smart_contract_state
            .get(&event_key(next_sequence))
            .is_none()
    );
    transaction
        .world
        .smart_contract_state
        .remove(reserve_provider_key(PROVIDER_ID));
    assert!(matches!(
        emit_reserve_event(
            &mut transaction,
            SorafsReserveLedgerEventKind::RentCharged,
            PROVIDER_ID,
            None,
            account.policy_digest,
            account.revision,
            &governance,
            NOW,
        ),
        Err(InstructionExecutionError::InvariantViolation(_))
    ));
    assert_eq!(
        read_reserve_state(transaction.world())
            .expect("read reserve state after missing provider")
            .expect("reserve state exists")
            .journal_head,
        journal_head
    );
    assert!(
        transaction
            .world
            .smart_contract_state
            .get(&event_key(next_sequence))
            .is_none()
    );
}
#[test]
fn committed_event_query_accepts_maximum_page_with_full_metering() {
    let governance = account(&keypair(0x7D));
    let provider = account(&keypair(0x7E));
    let custody = account(&keypair(0x7F));
    let treasury = account(&keypair(0x80));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let first = policy(1, None, custody, treasury, &governance);
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(first).execute(&governance, transaction)
    })
    .expect("commit reserve policy");
    let header = block_header_at(2, NOW + 1);
    let mut block = state.block(header.clone());
    let mut transaction = block.transaction();
    let template = read_persisted_event(transaction.world(), 1)
        .expect("read initial reserve event")
        .expect("initial reserve event exists");
    let terminal_sequence = u64::from(RESERVE_QUERY_MAX_ITEMS_V1) + 2;
    for sequence in 2..=terminal_sequence {
        let mut record = template.clone();
        record.sequence = sequence;
        record.event_index = u32::try_from(sequence - 1).expect("event index fits into u32");
        transaction.world.smart_contract_state.insert(
            event_key(sequence),
            encode_state(&record, "maximum-page reserve event")
                .expect("encode maximum-page reserve event"),
        );
    }
    let head = ReserveEventJournalHeadV1 {
        last_sequence: terminal_sequence,
        last_target_block_height: 1,
        last_event_index: u32::try_from(terminal_sequence - 1)
            .expect("terminal event index fits into u32"),
    };
    let mut reserve_state = read_reserve_state(transaction.world())
        .expect("read maximum-page reserve state")
        .expect("reserve state exists");
    reserve_state.journal_head = head;
    transaction.world.smart_contract_state.insert(
        reserve_state_key().clone(),
        encode_state(&reserve_state, "maximum-page reserve state")
            .expect("encode maximum-page reserve state"),
    );
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit maximum-page fixture");
    state.push_block_hash_for_testing(header.hash());
    let view = state.view();
    let prefix = FindSorafsReserveEvents::new(None, None, 2)
        .execute(&view)
        .expect("query reserve event prefix");
    let after = prefix.events[1].cursor();
    let page = FindSorafsReserveEvents::new(
        Some(prefix.finalized_cursor),
        Some(after),
        RESERVE_QUERY_MAX_ITEMS_V1,
    )
    .execute(&view)
    .expect("maximum reserve event page remains within every budget");
    assert_eq!(
        page.events.len(),
        usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1).expect("query maximum fits into usize")
    );
    assert_eq!(page.events[0].sequence, 3);
    assert_eq!(page.events.last().expect("terminal event").sequence, 130);
    assert!(!page.has_more);
    assert!(page.next_after.is_none());
}
#[test]
fn committed_event_queries_fail_closed_on_corruption_and_resource_exhaustion() {
    let governance = account(&keypair(0x79));
    let provider = account(&keypair(0x7A));
    let custody = account(&keypair(0x7B));
    let treasury = account(&keypair(0x7C));
    let build_policy_state = || {
        let mut state = state_fixture(&governance, &provider, &custody, &treasury);
        let first = policy(1, None, custody.clone(), treasury.clone(), &governance);
        transact(&mut state, 1, NOW, |transaction| {
            SetSorafsReservePolicy::new(first).execute(&governance, transaction)
        })
        .expect("commit reserve policy fixture");
        state
    };
    let mut missing_head = build_policy_state();
    {
        let header = block_header_at(2, NOW + 1);
        let mut block = missing_head.block(header.clone());
        let mut transaction = block.transaction();
        let mut reserve_state = read_reserve_state(transaction.world())
            .expect("read reserve state")
            .expect("reserve state exists");
        reserve_state.journal_head.last_sequence = 0;
        transaction.world.smart_contract_state.insert(
            reserve_state_key().clone(),
            encode_state(&reserve_state, "corrupt reserve state")
                .expect("encode corrupt reserve state"),
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit missing-head corruption");
        missing_head.push_block_hash_for_testing(header.hash());
    }
    assert!(matches!(
        FindSorafsReserveEvents::new(None, None, 10).execute(&missing_head.view()),
        Err(QueryExecutionFail::Conversion(_))
    ));
    let mut oversized = build_policy_state();
    {
        let header = block_header_at(2, NOW + 1);
        let mut block = oversized.block(header.clone());
        let mut transaction = block.transaction();
        transaction.world.smart_contract_state.insert(
            event_key(1),
            vec![0xFF; RESERVE_COMMITTED_EVENT_MAX_BYTES_V1 + 1],
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit oversized-event corruption");
        oversized.push_block_hash_for_testing(header.hash());
    }
    assert!(matches!(
        FindSorafsReserveEvents::new(None, None, 10).execute(&oversized.view()),
        Err(QueryExecutionFail::Conversion(_))
    ));
    let mut orphan = build_policy_state();
    {
        let header = block_header_at(2, NOW + 1);
        let mut block = orphan.block(header.clone());
        let mut transaction = block.transaction();
        let mut record = read_persisted_event(transaction.world(), 1)
            .expect("read policy event")
            .expect("policy event exists");
        record.sequence = 2;
        record.target_block_height = 2;
        record.event_index = 0;
        transaction.world.smart_contract_state.insert(
            event_key(2),
            encode_state(&record, "orphan event").expect("encode orphan reserve event"),
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit orphan-event corruption");
        orphan.push_block_hash_for_testing(header.hash());
    }
    assert!(matches!(
        FindSorafsReserveEvents::new(None, None, 10).execute(&orphan.view()),
        Err(QueryExecutionFail::Conversion(_))
    ));
    let mut read_budget = ReserveEventQueryBudgetV1::default();
    read_budget
        .inspect_storage_probe(1, None, RESERVE_QUERY_MAX_EVENT_READ_BYTES_V1)
        .expect("exact reserve query read-byte ceiling is accepted");
    assert!(matches!(
        read_budget.inspect_storage_probe(1, None, 1),
        Err(QueryExecutionFail::Conversion(_))
    ));
    let mut probe_budget = ReserveEventQueryBudgetV1::default();
    for _ in 0..RESERVE_QUERY_MAX_EVENT_STORAGE_PROBES_V1 {
        probe_budget
            .inspect_storage_probe(1, None, 0)
            .expect("exact reserve query storage-probe ceiling is accepted");
    }
    assert!(matches!(
        probe_budget.inspect_storage_probe(1, None, 0),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("storage probes")
    ));
    let mut key_budget = ReserveEventQueryBudgetV1::default();
    for _ in 0..128 {
        key_budget
            .inspect_storage_probe(RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1, None, 0)
            .expect("exact reserve query total key-byte ceiling is accepted");
    }
    assert!(matches!(
        key_budget.inspect_storage_probe(1, None, 0),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("probed key bytes")
    ));
    assert!(matches!(
        ReserveEventQueryBudgetV1::default().inspect_storage_probe(
            RESERVE_QUERY_MAX_EVENT_PROBE_KEY_BYTES_V1 + 1,
            None,
            0,
        ),
        Err(QueryExecutionFail::Conversion(message)) if message.contains("probe key")
    ));
}
#[test]
fn initial_policy_activation_preserves_adjacent_user_state() {
    let governance = account(&keypair(0x91));
    let provider = account(&keypair(0x92));
    let custody = account(&keypair(0x93));
    let treasury = account(&keypair(0x94));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let ordinary: StatePath = "sorafs_reservex_state_v1".parse().unwrap();
    state
        .world
        .smart_contract_state
        .insert(ordinary.clone(), vec![7]);
    let selected = policy(1, None, custody, treasury, &governance);
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(selected.clone()).execute(&governance, transaction)
    })
    .expect("native authorized policy activation retains its own write authority");
    let view = state.view();
    assert_eq!(
        view.world().smart_contract_state().get(&ordinary),
        Some(&vec![7])
    );
    assert_eq!(read_policy(view.world()).unwrap().unwrap().policy, selected);
    assert!(
        view.world()
            .smart_contract_state()
            .get(&event_key(1))
            .is_some()
    );
}

#[test]
fn initial_policy_activation_rejects_a_nonempty_reserve_namespace_atomically() {
    let governance = account(&keypair(0x91));
    let provider = account(&keypair(0x92));
    let custody = account(&keypair(0x93));
    let treasury = account(&keypair(0x94));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let legacy_key =
        StatePath::from_str("sorafs_reserve_policy_v1").expect("legacy fixture key is valid");
    state
        .world
        .smart_contract_state
        .insert(legacy_key.clone(), vec![0xA5]);
    let result = transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(policy(1, None, custody, treasury, &governance))
            .execute(&governance, transaction)
    });
    assert!(matches!(
        result,
        Err(InstructionExecutionError::InvariantViolation(_))
    ));
    let view = state.view();
    assert_eq!(
        view.world().smart_contract_state().get(&legacy_key),
        Some(&vec![0xA5])
    );
    assert!(
        view.world()
            .smart_contract_state()
            .get(reserve_state_key())
            .is_none()
    );
    assert!(
        view.world()
            .smart_contract_state()
            .get(&event_key(1))
            .is_none()
    );
}
#[test]
fn rent_charge_advances_only_due_periods_in_bounded_catchup_batches() {
    let governance = account(&keypair(0xC1));
    let provider = account(&keypair(0xC2));
    let custody = account(&keypair(0xC3));
    let treasury = account(&keypair(0xC4));
    let mut state = state_fixture_with_provider_balance(
        &governance,
        &provider,
        &custody,
        &treasury,
        quantity_micro(2_000_000_000),
    );
    let configured = policy(1, None, custody.clone(), treasury.clone(), &governance);
    let policy_digest = configured.digest().expect("reserve policy digest");
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(configured).execute(&governance, transaction)?;
        RegisterSorafsReserveAccount::new(terms(provider), policy_digest)
            .execute(&governance, transaction)
    })
    .expect("activate policy and register provider");
    let catchup_at = NOW + 13 * RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
    transact(&mut state, 2, catchup_at, |transaction| {
        ChargeSorafsReserveRent::new(
            PROVIDER_ID,
            1,
            RESERVE_RENT_MAX_BILLING_PERIODS_V1,
            policy_digest,
        )
        .execute(&governance, transaction)
    })
    .expect("settle the native maximum catchup batch");
    let after_first = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read provider after first catchup batch")
        .expect("provider remains");
    assert_eq!(after_first.revision, 2);
    assert_eq!(
        after_first.rent_charged_through_unix,
        NOW + 12 * RESERVE_RENT_BILLING_PERIOD_SECONDS_V1
    );
    assert_eq!(
        after_first
            .rent_periods_due_at(catchup_at)
            .expect("one period remains due"),
        1
    );
    assert!(
        transact(&mut state, 3, catchup_at, |transaction| {
            ChargeSorafsReserveRent::new(PROVIDER_ID, 2, 2, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "a charge cannot move the rent anchor beyond the finalized block time"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after rejected overcharge")
            .expect("provider remains"),
        after_first
    );
    transact(&mut state, 3, catchup_at, |transaction| {
        ChargeSorafsReserveRent::new(PROVIDER_ID, 2, 1, policy_digest)
            .execute(&governance, transaction)
    })
    .expect("settle the final due period");
    let caught_up = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read fully caught-up provider")
        .expect("provider remains");
    assert_eq!(caught_up.revision, 3);
    assert_eq!(caught_up.rent_charged_through_unix, catchup_at);
    assert_eq!(
        caught_up
            .rent_periods_due_at(catchup_at)
            .expect("provider is current"),
        0
    );
}
#[test]
fn exact_balance_charge_succeeds_and_stale_revision_cannot_double_settle() {
    let governance = account(&keypair(0xC5));
    let provider = account(&keypair(0xC6));
    let custody = account(&keypair(0xC7));
    let treasury = account(&keypair(0xC8));
    let configured = policy(1, None, custody, treasury, &governance);
    let rent = configured
        .economics
        .quote(
            StorageClass::Hot,
            10,
            ReserveDuration::Monthly,
            ReserveTier::TierA,
            XorQuantity::zero(),
        )
        .expect("rent quote")
        .effective_rent;
    let mut state = state_fixture_with_provider_balance(
        &governance,
        &provider,
        &configured.custody_account,
        &configured.treasury_account,
        rent.clone().into_quantity(),
    );
    let policy_digest = configured.digest().expect("reserve policy digest");
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(configured).execute(&governance, transaction)?;
        RegisterSorafsReserveAccount::new(terms(provider.clone()), policy_digest)
            .execute(&governance, transaction)
    })
    .expect("activate policy and register exact-balance provider");
    let due_at = NOW + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
    transact(&mut state, 2, due_at, |transaction| {
        ChargeSorafsReserveRent::new(PROVIDER_ID, 1, 1, policy_digest)
            .execute(&governance, transaction)
    })
    .expect("an exact spendable balance settles rent");
    let settled = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read settled provider")
        .expect("provider remains");
    assert_eq!(settled.revision, 2);
    assert_eq!(settled.rent_charged_through_unix, due_at);
    assert!(reserve_asset_balance(&state, &provider).is_zero());
    assert!(
        transact(&mut state, 3, due_at, |transaction| {
            ChargeSorafsReserveRent::new(PROVIDER_ID, 1, 1, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "the stale compare-and-set revision cannot settle rent twice"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after stale replay")
            .expect("provider remains"),
        settled
    );
}
#[test]
fn lifecycle_uses_exact_anchor_age_and_rejects_noop_or_timestamp_regression() {
    let governance = account(&keypair(0xD1));
    let provider = account(&keypair(0xD2));
    let custody = account(&keypair(0xD3));
    let treasury = account(&keypair(0xD4));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let configured = policy(1, None, custody, treasury, &governance);
    let policy_digest = configured.digest().expect("reserve policy digest");
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(configured).execute(&governance, transaction)?;
        RegisterSorafsReserveAccount::new(terms(provider), policy_digest)
            .execute(&governance, transaction)
    })
    .expect("activate policy and register provider");
    let baseline = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read provider baseline")
        .expect("provider exists");
    let exact_boundary = NOW + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
    assert!(
        transact(&mut state, 2, exact_boundary, |transaction| {
            AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 1, 1, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "the exact due boundary is day zero, never day one"
    );
    assert!(
        transact(&mut state, 2, exact_boundary, |transaction| {
            AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 1, 0, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "an exact-day lifecycle no-op cannot churn the provider revision"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after rejected boundary transitions")
            .expect("provider remains"),
        baseline
    );
    let one_day_overdue = exact_boundary + 86_400;
    transact(&mut state, 2, one_day_overdue, |transaction| {
        AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 1, 1, policy_digest)
            .execute(&governance, transaction)
    })
    .expect("the exact derived lifecycle transition succeeds");
    let overdue = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read overdue provider")
        .expect("provider remains");
    assert_eq!(overdue.days_past_due, 1);
    assert_eq!(overdue.lifecycle_stage, ReserveLifecycleStage::Grace);
    assert!(
        transact(&mut state, 3, exact_boundary, |transaction| {
            AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 2, 0, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "a later height cannot regress the provider timestamp or overdue age"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after timestamp regression")
            .expect("provider remains"),
        overdue
    );
}
#[test]
fn lifecycle_requires_anchor_advancement_for_zero_or_funded_rent_periods() {
    let governance = account(&keypair(0xD5));
    let provider = account(&keypair(0xD6));
    let custody = account(&keypair(0xD7));
    let treasury = account(&keypair(0xD8));
    let mut state = state_fixture_with_provider_balance(
        &governance,
        &provider,
        &custody,
        &treasury,
        quantity_micro(1_000_000_000),
    );
    let first = policy(1, None, custody.clone(), treasury.clone(), &governance);
    let first_digest = first.digest().expect("first reserve policy digest");
    let reserve_requirement = first
        .economics
        .quote(
            StorageClass::Hot,
            10,
            ReserveDuration::Monthly,
            ReserveTier::TierA,
            XorQuantity::zero(),
        )
        .expect("first reserve quote")
        .reserve_requirement;
    transact(&mut state, 1, NOW, |transaction| {
        SetSorafsReservePolicy::new(first).execute(&governance, transaction)?;
        RegisterSorafsReserveAccount::new(terms(provider.clone()), first_digest)
            .execute(&governance, transaction)?;
        RequestSorafsReserveMovement::new(
            [0xD9; 32],
            PROVIDER_ID,
            ReserveMovementKindV1::TopUp,
            reserve_requirement,
            1,
            first_digest,
        )
        .execute(&provider, transaction)?;
        DecideSorafsReserveMovement::new(
            [0xD9; 32],
            2,
            first_digest,
            true,
            "fund exact underwriting requirement".to_owned(),
        )
        .execute(&governance, transaction)?;
        AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 3, 0, first_digest)
            .execute(&governance, transaction)
    })
    .expect("establish an active zero-rent provider");
    let active = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read active provider")
        .expect("provider remains");
    assert_eq!(active.revision, 4);
    assert_eq!(active.lifecycle_stage, ReserveLifecycleStage::Active);
    let first_due = NOW + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
    assert!(
        transact(&mut state, 2, first_due, |transaction| {
            AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 4, 0, first_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "a zero-rent period must advance through ChargeRent, not lifecycle aging"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after rejected zero-rent aging")
            .expect("provider remains"),
        active
    );
    let mut second = policy(2, Some(first_digest), custody, treasury, &governance);
    second
        .economics
        .rent_rates
        .retain(|rate| rate.storage_class != StorageClass::Hot);
    second.economics.rent_rates.push(ClassRentRate::new(
        StorageClass::Hot,
        "24".parse().expect("rotated hot rent"),
    ));
    let second_digest = second.digest().expect("second reserve policy digest");
    transact(&mut state, 2, first_due, |transaction| {
        ChargeSorafsReserveRent::new(PROVIDER_ID, 4, 1, first_digest)
            .execute(&governance, transaction)?;
        SetSorafsReservePolicy::new(second).execute(&governance, transaction)
    })
    .expect("advance the zero-rent anchor and rotate pricing");
    let after_zero_rent = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read provider after zero-rent charge")
        .expect("provider remains");
    assert_eq!(after_zero_rent.revision, 5);
    assert_eq!(after_zero_rent.rent_charged_through_unix, first_due);
    let second_due = first_due + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
    assert!(
        transact(&mut state, 3, second_due, |transaction| {
            AdvanceSorafsReserveLifecycle::new(PROVIDER_ID, 5, 0, second_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "one exactly affordable positive-rent period must be charged, never aged"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after rejected funded aging")
            .expect("provider remains"),
        after_zero_rent
    );
    transact(&mut state, 3, second_due, |transaction| {
        ChargeSorafsReserveRent::new(PROVIDER_ID, 5, 1, second_digest)
            .execute(&governance, transaction)
    })
    .expect("the funded period advances through ChargeRent");
    let settled = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read settled rotated provider")
        .expect("provider remains");
    assert_eq!(settled.revision, 6);
    assert_eq!(settled.rent_charged_through_unix, second_due);
    assert_eq!(settled.policy_digest, second_digest);
}
#[test]
fn failed_transfer_and_finalized_timestamp_rollback_preserve_rent_anchor() {
    let governance = account(&keypair(0xC9));
    let provider = account(&keypair(0xCA));
    let custody = account(&keypair(0xCB));
    let treasury = account(&keypair(0xCC));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let configured = policy(1, None, custody.clone(), treasury.clone(), &governance);
    let policy_digest = configured.digest().expect("reserve policy digest");
    transact(&mut state, 1, NOW - 100, |transaction| {
        SetSorafsReservePolicy::new(configured).execute(&governance, transaction)
    })
    .expect("activate reserve policy");
    transact(&mut state, 2, NOW, |transaction| {
        RegisterSorafsReserveAccount::new(terms(provider.clone()), policy_digest)
            .execute(&governance, transaction)
    })
    .expect("register provider at its rent anchor");
    let baseline = read_provider(state.view().world(), PROVIDER_ID)
        .expect("read provider baseline")
        .expect("provider exists");
    let provider_balance = reserve_asset_balance(&state, &provider);
    let treasury_balance = reserve_asset_balance(&state, &treasury);
    let due_at = NOW + RESERVE_RENT_BILLING_PERIOD_SECONDS_V1;
    assert!(
        transact(&mut state, 3, due_at, |transaction| {
            ChargeSorafsReserveRent::new(PROVIDER_ID, 1, 1, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "the fixture provider cannot cover one whole rent period"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after failed transfer")
            .expect("provider remains"),
        baseline,
        "a failed custody transfer cannot advance revision, lifecycle, or rent anchor"
    );
    assert_eq!(reserve_asset_balance(&state, &provider), provider_balance);
    assert_eq!(reserve_asset_balance(&state, &treasury), treasury_balance);
    assert!(
        transact(&mut state, 3, NOW - 1, |transaction| {
            ChargeSorafsReserveRent::new(PROVIDER_ID, 1, 1, policy_digest)
                .execute(&governance, transaction)
        })
        .is_err(),
        "a later height cannot supply a timestamp before the ledger rent anchor"
    );
    assert_eq!(
        read_provider(state.view().world(), PROVIDER_ID)
            .expect("read provider after timestamp rollback")
            .expect("provider remains"),
        baseline
    );
}
#[test]
fn policy_rotation_rejects_regressed_activation_time() {
    let governance = account(&keypair(0xED));
    let provider = account(&keypair(0xEE));
    let custody = account(&keypair(0xEF));
    let treasury = account(&keypair(0xF0));
    let mut state = state_fixture(&governance, &provider, &custody, &treasury);
    let activated_at = NOW + 100;
    let first = policy(1, None, custody.clone(), treasury.clone(), &governance);
    let first_digest = first.digest().expect("first reserve policy digest");
    transact(&mut state, 1, activated_at, |transaction| {
        SetSorafsReservePolicy::new(first).execute(&governance, transaction)
    })
    .expect("activate first reserve policy");
    let baseline = read_reserve_state(state.view().world())
        .expect("read baseline reserve state")
        .expect("reserve state exists");
    let second = policy(2, Some(first_digest), custody, treasury, &governance);
    let header = block_header_at(2, activated_at - 1);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let error = SetSorafsReservePolicy::new(second)
        .execute(&governance, &mut transaction)
        .expect_err("regressed reserve policy activation must fail");
    assert!(
        matches!(&error, InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(message)
        ) if message.contains("predates active policy activation")),
        "policy rotation failed for the wrong reason: {error}"
    );
    assert_eq!(
        read_reserve_state(transaction.world())
            .expect("read reserve state after rejected policy")
            .expect("reserve state remains"),
        baseline
    );
    assert!(
        read_persisted_event(transaction.world(), 2)
            .expect("read absent policy event")
            .is_none(),
        "rejected policy rotation cannot append an event"
    );
}
#[test]
fn exact_service_authorities_and_decision_cas_fail_without_mutation() {
    let governance = account(&keypair(0xA1));
    let provider = account(&keypair(0xA2));
    let decision = account(&keypair(0xA3));
    let operations = account(&keypair(0xA4));
    let state = state_fixture(&governance, &provider, &decision, &operations);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, NOW * 1_000, 0);
    let mut block = state.block(header);
    let mut transaction =
        block.transaction_for_fastpq_testing(Hash::prehashed([0xA5; Hash::LENGTH]));
    let mut first = policy(1, None, decision.clone(), operations.clone(), &governance);
    first.operations_authority = operations.clone();
    first.decision_authority = decision.clone();
    let first_digest = first.digest().expect("first policy digest");
    SetSorafsReservePolicy::new(first)
        .execute(&governance, &mut transaction)
        .expect("activate first policy");
    let registration = RegisterSorafsReserveAccount::new(terms(provider.clone()), first_digest);
    assert!(
        registration
            .clone()
            .execute(&governance, &mut transaction)
            .is_err(),
        "broad reserve-governance permission must not substitute for the operations account"
    );
    assert!(
        read_provider(transaction.world(), PROVIDER_ID)
            .expect("read provider after rejected registration")
            .is_none()
    );
    registration
        .execute(&operations, &mut transaction)
        .expect("exact operations account registers provider");
    RequestSorafsReserveMovement::new(
        [0xA6; 32],
        PROVIDER_ID,
        ReserveMovementKindV1::TopUp,
        xor_micro(10_000_000),
        1,
        first_digest,
    )
    .execute(&provider, &mut transaction)
    .expect("provider requests top-up");
    let provider_before = read_provider(transaction.world(), PROVIDER_ID)
        .expect("read provider before rotation")
        .expect("registered provider");
    let movement_before = read_movement(transaction.world(), [0xA6; 32])
        .expect("read movement before rotation")
        .expect("pending movement");
    let mut second = policy(
        2,
        Some(first_digest),
        decision.clone(),
        operations.clone(),
        &governance,
    );
    second.operations_authority = operations.clone();
    second.decision_authority = decision.clone();
    let second_digest = second.digest().expect("second policy digest");
    SetSorafsReservePolicy::new(second)
        .execute(&governance, &mut transaction)
        .expect("rotate reserve policy");
    for (authority, revision, digest) in [
        (&governance, 2, second_digest),
        (&decision, 1, second_digest),
        (&decision, 2, first_digest),
    ] {
        assert!(
            DecideSorafsReserveMovement::new(
                [0xA6; 32],
                revision,
                digest,
                true,
                "approve top-up".to_owned(),
            )
            .execute(authority, &mut transaction)
            .is_err()
        );
        assert_eq!(
            read_provider(transaction.world(), PROVIDER_ID)
                .expect("read provider after rejected decision")
                .expect("provider remains"),
            provider_before
        );
        assert_eq!(
            read_movement(transaction.world(), [0xA6; 32])
                .expect("read movement after rejected decision")
                .expect("movement remains"),
            movement_before
        );
    }
    DecideSorafsReserveMovement::new(
        [0xA6; 32],
        2,
        second_digest,
        true,
        "approve top-up".to_owned(),
    )
    .execute(&decision, &mut transaction)
    .expect("exact decision account and CAS apply top-up");
    let after_decision = read_provider(transaction.world(), PROVIDER_ID)
        .expect("read provider after decision")
        .expect("provider remains");
    assert_eq!(after_decision.revision, 3);
    assert!(
        ChargeSorafsReserveRent::new(PROVIDER_ID, 3, 1, second_digest)
            .execute(&governance, &mut transaction)
            .is_err(),
        "broad governance permission must not substitute for operations"
    );
    assert_eq!(
        read_provider(transaction.world(), PROVIDER_ID)
            .expect("read provider after rejected charge")
            .expect("provider remains"),
        after_decision
    );
}
