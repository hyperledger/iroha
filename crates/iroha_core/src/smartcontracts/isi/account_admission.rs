//! Helpers for global account admission and implicit account creation.
//!
//! This module provides a deterministic implementation of "implicit accounts":
//! when global policy allows receipt-like operations (asset mint/transfer, NFT transfer), the
//! destination `Account` object may be created automatically if it does not exist yet.
use crate::{
    role::RoleIdWithOwner,
    state::{StateTransaction, WorldReadOnly},
};
use iroha_data_model::query::error::FindError;
use iroha_data_model::{
    IntoKeyValue,
    account::{
        AccountAdmissionMode, AccountAdmissionPolicy,
        admission::{ImplicitAccountCreationFee, ImplicitAccountFeeDestination},
    },
    asset::{AssetDefinitionId, AssetId},
    isi::error::{
        AccountAdmissionDefaultRoleError, AccountAdmissionError, AccountAdmissionFeeUnsatisfied,
        AccountAdmissionInvalidPolicy, AccountAdmissionMinInitialAmountUnsatisfied,
        AccountAdmissionQuotaExceeded, AccountAdmissionQuotaScope, InstructionExecutionError,
    },
    prelude::*,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use std::sync::LazyLock;
static IMPLICIT_CREATED_VIA_KEY: LazyLock<Name> = LazyLock::new(|| {
    "iroha:created_via"
        .parse()
        .expect("implicit created_via metadata key must be a valid Name")
});
fn first_disallowed_algorithm(
    controller: &AccountController,
    allowed: &[iroha_crypto::Algorithm],
) -> Result<Option<iroha_crypto::Algorithm>, AccountAdmissionError> {
    match controller {
        AccountController::Single(signatory) => Ok(algorithm_if_disallowed(
            controller_algorithm(signatory)?,
            allowed,
        )),
        AccountController::Multisig(policy) => {
            for member in policy.members() {
                if let Some(disallowed) =
                    algorithm_if_disallowed(controller_algorithm(member.public_key())?, allowed)
                {
                    return Ok(Some(disallowed));
                }
            }
            Ok(None)
        }
    }
}
fn controller_algorithm(
    public_key: &iroha_crypto::PublicKey,
) -> Result<iroha_crypto::Algorithm, AccountAdmissionError> {
    public_key.try_algorithm().map_err(|err| {
        AccountAdmissionError::InvalidPolicy(AccountAdmissionInvalidPolicy {
            reason: format!("account controller public key is malformed: {err}"),
        })
    })
}
fn algorithm_if_disallowed(
    algorithm: iroha_crypto::Algorithm,
    allowed: &[iroha_crypto::Algorithm],
) -> Option<iroha_crypto::Algorithm> {
    if allowed.contains(&algorithm) {
        None
    } else {
        Some(algorithm)
    }
}
fn ensure_controller_allowed_for_implicit_admission(
    controller: &AccountController,
    policy: &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1,
) -> Result<(), AccountAdmissionError> {
    if let Some(disallowed) = first_disallowed_algorithm(controller, policy.allowed_algorithms())? {
        return Err(AccountAdmissionError::AlgorithmNotAllowed(disallowed));
    }
    Ok(())
}

fn load_account_admission_policy(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<AccountAdmissionPolicy, InstructionExecutionError> {
    let from_chain = state_transaction
        .world
        .parameters()
        .custom()
        .get(&AccountAdmissionPolicy::parameter_id());
    if let Some(custom) = from_chain {
        return custom
            .payload()
            .try_into_any_norito::<AccountAdmissionPolicy>()
            .map_err(|err| {
                AccountAdmissionError::InvalidPolicy(AccountAdmissionInvalidPolicy {
                    reason: format!(
                        "chain parameter `{}` decode error: {err}",
                        AccountAdmissionPolicy::PARAMETER_ID_STR
                    ),
                })
                .into()
            });
    }
    Ok(AccountAdmissionPolicy::default())
}
fn apply_implicit_creation_fee(
    authority: &AccountId,
    created_account: &AccountId,
    fee: &ImplicitAccountCreationFee,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    let payer = resolve_existing_account_for_subject(state_transaction, authority)?;
    let payer_asset_id =
        state_transaction
            .world
            .resolve_asset_id_for_current_scope(&AssetId::new(
                fee.asset_definition_id.clone(),
                payer,
            ))?;
    let available = state_transaction
        .world
        .asset(&payer_asset_id)
        .map_or_else(|_| Quantity::zero(), |asset| asset.value().as_ref().clone());
    if available < fee.amount {
        return Err(
            AccountAdmissionError::FeeUnsatisfied(AccountAdmissionFeeUnsatisfied {
                asset_definition: fee.asset_definition_id.clone(),
                required: fee.amount.clone(),
                available,
            })
            .into(),
        );
    }
    match &fee.destination {
        ImplicitAccountFeeDestination::Burn => {
            crate::smartcontracts::isi::asset::isi::execute_account_admission_fee_burn(
                state_transaction,
                authority,
                created_account,
                payer_asset_id,
                fee.amount.clone(),
            )?;
        }
        ImplicitAccountFeeDestination::Account(sink) => {
            let sink = resolve_existing_account_for_subject(state_transaction, sink)?;
            let sink_asset_id =
                state_transaction
                    .world
                    .resolve_asset_id_for_current_scope(&AssetId::new(
                        fee.asset_definition_id.clone(),
                        sink,
                    ))?;
            crate::smartcontracts::isi::asset::isi::execute_account_admission_fee_transfer(
                state_transaction,
                authority,
                created_account,
                payer_asset_id,
                sink_asset_id,
                fee.amount.clone(),
            )?;
        }
    }
    Ok(())
}
fn resolve_existing_account_for_subject(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<AccountId, InstructionExecutionError> {
    match state_transaction.world.account(account) {
        Ok(_) => return Ok(account.clone()),
        Err(FindError::Account(_)) => {}
        Err(err) => return Err(err.into()),
    }
    state_transaction
        .world
        .accounts_for_subject_iter(&account.subject_id())
        .next()
        .map(|entry| entry.id().clone())
        .ok_or_else(|| FindError::Account(account.clone()).into())
}
fn create_implicit_account(
    _authority: &AccountId,
    destination: &AccountId,
    default_role_on_create: Option<&RoleId>,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    let mut metadata = Metadata::default();
    metadata.insert(IMPLICIT_CREATED_VIA_KEY.clone(), Json::new("implicit"));
    let account = Account {
        id: destination.clone(),
        metadata,
        label: None,
        uaid: None,
        opaque_ids: Vec::new(),
    };
    let (account_id, account_value) = account.clone().into_key_value();
    state_transaction
        .world
        .accounts
        .insert(account_id, account_value);
    let mut default_role_granted = None;
    if let Some(role) = default_role_on_create {
        let role_key = RoleIdWithOwner::new(destination.clone(), role.clone());
        if state_transaction
            .world
            .account_roles
            .insert(role_key.clone(), ())
            .is_some()
        {
            state_transaction.world.account_roles.remove(role_key);
            state_transaction.world.accounts.remove(destination.clone());
            return Err(AccountAdmissionError::DefaultRoleError(
                AccountAdmissionDefaultRoleError {
                    role: role.clone(),
                    reason: "duplicate role assignment".to_owned(),
                },
            )
            .into());
        }
        default_role_granted = Some(role.clone());
        state_transaction.invalidate_permission_cache_for_account(destination);
    }
    state_transaction
        .world
        .emit_events(Some(AccountEvent::Created(AccountCreated::new(account))));
    if let Some(role) = default_role_granted {
        state_transaction
            .world
            .emit_events(Some(AccountEvent::RoleGranted(AccountRoleChanged {
                account: destination.clone(),
                role,
            })));
    }
    Ok(())
}
/// Ensure `destination` account exists, creating it implicitly when allowed by policy.
///
/// Returns `Ok(true)` when the account was created, `Ok(false)` when it already existed.
pub(super) fn ensure_receiving_account(
    authority: &AccountId,
    destination: &AccountId,
    value_hint: Option<(&AssetDefinitionId, &Quantity)>,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<bool, InstructionExecutionError> {
    if state_transaction.world.account(destination).is_ok() {
        return Ok(false);
    }
    let policy = load_account_admission_policy(state_transaction)?;
    if policy.mode != AccountAdmissionMode::ImplicitReceive {
        return Err(AccountAdmissionError::ImplicitAccountCreationDisabled.into());
    }
    if let Some((asset_def_id, amount)) = value_hint {
        if let Some(required) = policy.min_initial_amount_for(asset_def_id) {
            if amount < required {
                return Err(AccountAdmissionError::MinInitialAmountUnsatisfied(
                    AccountAdmissionMinInitialAmountUnsatisfied {
                        asset_definition: asset_def_id.clone(),
                        required: required.clone(),
                        provided: amount.clone(),
                    },
                )
                .into());
            }
        }
    }
    let max_creations = policy.max_implicit_creations_per_tx();
    if state_transaction.implicit_account_creations_in_tx >= max_creations {
        return Err(
            AccountAdmissionError::QuotaExceeded(AccountAdmissionQuotaExceeded {
                scope: AccountAdmissionQuotaScope::Transaction,
                created: state_transaction.implicit_account_creations_in_tx,
                cap: max_creations,
            })
            .into(),
        );
    }
    if let Some(max_creations) = policy.max_implicit_creations_per_block() {
        let created_so_far = state_transaction
            .implicit_account_creations_in_block_so_far
            .saturating_add(state_transaction.implicit_account_creations_in_tx);
        if created_so_far >= max_creations {
            return Err(
                AccountAdmissionError::QuotaExceeded(AccountAdmissionQuotaExceeded {
                    scope: AccountAdmissionQuotaScope::Block,
                    created: created_so_far,
                    cap: max_creations,
                })
                .into(),
            );
        }
    }
    let default_role_on_create = policy.default_role_on_create().cloned();
    if let Some(default_role) = &default_role_on_create {
        state_transaction.world.role(default_role).map_err(|err| {
            AccountAdmissionError::DefaultRoleError(AccountAdmissionDefaultRoleError {
                role: default_role.clone(),
                reason: err.to_string(),
            })
        })?;
    }
    ensure_controller_allowed_for_implicit_admission(
        destination.controller(),
        state_transaction
            .crypto_admission_policy()
            .map_err(|message| {
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                    message.into(),
                )
            })?,
    )?;
    if let Some(fee) = policy.implicit_creation_fee() {
        apply_implicit_creation_fee(authority, destination, fee, state_transaction)?;
    }
    create_implicit_account(
        authority,
        destination,
        default_role_on_create.as_ref(),
        state_transaction,
    )?;
    state_transaction.implicit_account_creations_in_tx += 1;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::Execute,
        state::{State, StateTransaction, World},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::admission::ImplicitAccountCreationFee, parameter::Parameters,
        permission::Permissions,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_test_samples::ALICE_ID;
    use nonzero_ext::nonzero;
    use std::collections::BTreeMap;
    fn checked_ed25519_keypair() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("account admission fixture key generation should succeed")
    }
    fn random_account_id() -> AccountId {
        let key_pair = checked_ed25519_keypair();
        AccountId::new(key_pair.public_key().clone())
    }
    #[test]
    fn checked_ed25519_keypair_preserves_algorithm() {
        assert_eq!(checked_ed25519_keypair().algorithm(), Algorithm::Ed25519);
    }
    fn fixture_keypair(seed: u8, algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], algorithm)
            .expect("fixture seed must derive a valid keypair")
    }
    fn open_domain(domain_id: DomainId) -> Domain {
        Domain::new(domain_id).build(&ALICE_ID)
    }
    fn build_account_in_domain(
        account_id: AccountId,
        _domain_id: DomainId,
        authority: &AccountId,
    ) -> iroha_data_model::account::Account {
        iroha_data_model::account::NewAccount::new(account_id.clone()).build(authority)
    }
    fn test_state(mut world: World, policy: AccountAdmissionPolicy) -> State {
        let custom = policy.into_custom_parameter();
        let mut params = Parameters::default();
        params.custom.insert(custom);
        params.set_parameter(
            iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(
                Algorithm::ALL.to_vec(),
            )
            .unwrap()
            .into_parameter()
            .unwrap(),
        );
        world.parameters = mv::cell::Cell::new(
            crate::state::StateParameters::try_from(params).expect("valid fixture parameters"),
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        State::new_for_testing(world, kura, query)
    }
    fn seed_test_call_hash(state_transaction: &mut StateTransaction<'_, '_>, byte: u8) {
        state_transaction.tx_call_hash = Some(Hash::prehashed([byte; Hash::LENGTH]));
    }
    #[test]
    fn implicit_admission_controller_checks_use_checked_algorithm_access() {
        let ed25519 = fixture_keypair(0x41, Algorithm::Ed25519);
        let secp256k1 = fixture_keypair(0x42, Algorithm::Secp256k1);
        let allowed =
            iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                Algorithm::Ed25519,
            ])
            .unwrap();
        ensure_controller_allowed_for_implicit_admission(
            &AccountController::Single(ed25519.public_key().clone()),
            &allowed,
        )
        .expect("Ed25519 controller should be allowed");
        let err = ensure_controller_allowed_for_implicit_admission(
            &AccountController::Single(secp256k1.public_key().clone()),
            &allowed,
        )
        .expect_err("Secp256k1 controller should be rejected by committed policy");
        assert!(matches!(
            err,
            AccountAdmissionError::AlgorithmNotAllowed(Algorithm::Secp256k1)
        ));
    }
    #[test]
    fn fixture_keypair_uses_checked_seed_derivation() {
        assert_eq!(
            fixture_keypair(0x43, Algorithm::Ed25519).algorithm(),
            Algorithm::Ed25519
        );
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn transfer_asset_creates_destination_account_in_open_domain() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(100_u32));
        let world = World::with_assets([domain], [alice_account], [asset_def], [alice_asset], []);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.admit_fastpq_source_for_testing(Hash::prehashed([0xA1; Hash::LENGTH]));
        let mut stx = block.transaction();
        seed_test_call_hash(&mut stx, 0xA1);
        let dest = random_account_id();
        Transfer::asset_quantity(alice_asset_id.clone(), 10_u32, dest.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("transfer succeeds");
        stx.world
            .account(&dest)
            .expect("destination account should be created");
        let dest_asset_id = AssetId::new(asset_def_id.clone(), dest.clone());
        let alice_balance = stx
            .world
            .asset_mut(&alice_asset_id)
            .expect("alice asset exists")
            .clone()
            .into_inner();
        let dest_balance = stx
            .world
            .asset_mut(&dest_asset_id)
            .expect("destination asset exists")
            .clone()
            .into_inner();
        assert_eq!(alice_balance, Quantity::from(90_u32));
        assert_eq!(dest_balance, Quantity::from(10_u32));
        // AccountCreated must come before any receipt events.
        let events = &stx.world.internal_event_buf;
        assert!(!events.is_empty(), "events must be emitted");
        assert!(
            matches!(
                events[0].as_ref(),
                DataEvent::Account(AccountEvent::Created(_))
            ),
            "first event should be destination AccountCreated, got {:?}",
            events[0]
        );
        // The created account must advertise its origin in metadata.
        let account = stx.world.account(&dest).expect("account");
        let account_details = account.value();
        let created_via_key: Name = "iroha:created_via".parse().expect("created_via key");
        assert_eq!(
            account_details.metadata().get(&created_via_key),
            Some(&Json::new("implicit"))
        );
    }
    #[test]
    fn transfer_asset_batch_creates_destination_account_in_open_domain() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(100_u32));
        let world = World::with_assets([domain], [alice_account], [asset_def], [alice_asset], []);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.admit_fastpq_source_for_testing(Hash::prehashed([0xA2; Hash::LENGTH]));
        let mut stx = block.transaction();
        seed_test_call_hash(&mut stx, 0xA2);
        let dest = random_account_id();
        let entry = TransferAssetBatchEntry::new(
            ALICE_ID.clone(),
            dest.clone(),
            asset_def_id.clone(),
            5_u32,
        );
        TransferAssetBatch::new(vec![entry])
            .execute(&ALICE_ID, &mut stx)
            .expect("batch transfer succeeds");
        stx.world
            .account(&dest)
            .expect("destination account should be created");
        let dest_asset_id = AssetId::new(asset_def_id, dest);
        let alice_balance = stx
            .world
            .asset_mut(&alice_asset_id)
            .expect("alice asset exists")
            .clone()
            .into_inner();
        let dest_balance = stx
            .world
            .asset_mut(&dest_asset_id)
            .expect("destination asset exists")
            .clone()
            .into_inner();
        assert_eq!(alice_balance, Quantity::from(95_u32));
        assert_eq!(dest_balance, Quantity::from(5_u32));
    }
    #[test]
    fn mint_asset_creates_destination_account_in_open_domain() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let world = World::with([domain], [alice_account], [asset_def]);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let dest_asset_id = AssetId::new(asset_def_id.clone(), dest.clone());
        Mint::asset_quantity(7_u32, dest_asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("mint succeeds");
        stx.world
            .account(&dest)
            .expect("destination account should be created");
        let dest_balance = stx
            .world
            .asset_mut(&dest_asset_id)
            .expect("destination asset exists")
            .clone()
            .into_inner();
        assert_eq!(dest_balance, Quantity::from(7_u32));
        let events = &stx.world.internal_event_buf;
        assert!(
            matches!(
                events[0].as_ref(),
                DataEvent::Account(AccountEvent::Created(_))
            ),
            "first event should be destination AccountCreated"
        );
    }
    #[test]
    fn transfer_nft_creates_destination_account_in_open_domain() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let nft_id: NftId = "n0$wonderland.universal".parse().expect("nft id");
        let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&ALICE_ID);
        let world = World::with_assets([domain], [alice_account], [], [], [nft]);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        Transfer::nft(ALICE_ID.clone(), nft_id.clone(), dest.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("nft transfer succeeds");
        stx.world
            .account(&dest)
            .expect("destination account should be created");
        let nft_entry = stx.world.nft(&nft_id).expect("nft exists");
        assert_eq!(nft_entry.value().owned_by, dest);
        let events = &stx.world.internal_event_buf;
        assert_eq!(events.len(), 2, "expected account + nft events");
        assert!(
            matches!(
                events[0].as_ref(),
                DataEvent::Account(AccountEvent::Created(_))
            ),
            "first event should be destination AccountCreated"
        );
        assert!(
            matches!(
                events[1].as_ref(),
                DataEvent::Domain(DomainEvent::Nft(NftEvent::OwnerChanged(_)))
            ),
            "second event should be NFT owner change"
        );
    }
    #[test]
    fn transfer_asset_rejects_missing_destination_in_explicit_domain() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ExplicitOnly,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(100_u32));
        let world = World::with_assets([domain], [alice_account], [asset_def], [alice_asset], []);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let err = Transfer::asset_quantity(alice_asset_id.clone(), 10_u32, dest.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("transfer should fail in ExplicitOnly domain");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(
                    AccountAdmissionError::ImplicitAccountCreationDisabled
                )
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            stx.world.account(&dest).is_err(),
            "destination must not exist"
        );
    }
    #[test]
    fn global_policy_disables_implicit_receive() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(100_u32));
        let world = World::with_assets([domain], [alice_account], [asset_def], [alice_asset], []);
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ExplicitOnly,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let err = Transfer::asset_quantity(alice_asset_id.clone(), 10_u32, dest.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("transfer should be rejected via chain default explicit policy");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(
                    AccountAdmissionError::ImplicitAccountCreationDisabled
                )
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            stx.world.account(&dest).is_err(),
            "destination must not exist"
        );
    }
    #[test]
    fn implicit_creation_cap_is_enforced_per_transaction() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: Some(1),
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let world = World::with([domain], [alice_account], [asset_def]);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest1 = random_account_id();
        let dest1_asset_id = AssetId::new(asset_def_id.clone(), dest1.clone());
        Mint::asset_quantity(1_u32, dest1_asset_id)
            .execute(&ALICE_ID, &mut stx)
            .expect("first mint creates account");
        let dest2 = random_account_id();
        let dest2_asset_id = AssetId::new(asset_def_id.clone(), dest2.clone());
        let err = Mint::asset_quantity(1_u32, dest2_asset_id)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("second mint exceeds cap");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(AccountAdmissionError::QuotaExceeded(
                    AccountAdmissionQuotaExceeded {
                        scope: AccountAdmissionQuotaScope::Transaction,
                        ..
                    }
                ))
            ),
            "unexpected error: {err:?}"
        );
        assert!(stx.world.account(&dest2).is_err(), "dest2 must not exist");
    }
    #[test]
    fn implicit_creation_cap_is_enforced_per_block_across_transactions() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: Some(1),
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let world = World::with([domain], [alice_account], [asset_def]);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let dest1 = random_account_id();
        let dest1_asset_id = AssetId::new(asset_def_id.clone(), dest1.clone());
        {
            let mut stx = block.transaction();
            Mint::asset_quantity(1_u32, dest1_asset_id)
                .execute(&ALICE_ID, &mut stx)
                .expect("first mint creates account");
            stx.apply();
        }
        let dest2 = random_account_id();
        let dest2_asset_id = AssetId::new(asset_def_id.clone(), dest2.clone());
        let mut stx = block.transaction();
        let err = Mint::asset_quantity(1_u32, dest2_asset_id)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("second mint exceeds block cap");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(AccountAdmissionError::QuotaExceeded(
                    AccountAdmissionQuotaExceeded {
                        scope: AccountAdmissionQuotaScope::Block,
                        ..
                    }
                ))
            ),
            "unexpected error: {err:?}"
        );
        assert!(stx.world.account(&dest2).is_err(), "dest2 must not exist");
    }
    #[test]
    fn implicit_creation_fee_is_enforced_and_charged() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let fee_sink = random_account_id();
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: Some(ImplicitAccountCreationFee {
                asset_definition_id: asset_def_id.clone(),
                amount: Quantity::from(5_u32),
                destination: ImplicitAccountFeeDestination::Account(fee_sink.clone()),
            }),
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let fee_sink_account =
            build_account_in_domain(fee_sink.clone(), domain_id.clone(), &fee_sink);
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(20_u32));
        let world = World::with_assets(
            [domain],
            [alice_account, fee_sink_account],
            [asset_def],
            [alice_asset],
            [],
        );
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block
            .transaction_for_fastpq_testing(Hash::new(b"implicit-account-creation-fee-fixture"));
        let dest = random_account_id();
        let dest_asset_id = AssetId::new(asset_def_id.clone(), dest.clone());
        Mint::asset_quantity(10_u32, dest_asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("mint should succeed with fee payment");
        stx.world.account(&dest).expect("destination exists");
        let alice_balance = stx
            .world
            .asset_mut(&alice_asset_id)
            .expect("alice asset exists")
            .clone()
            .into_inner();
        assert_eq!(alice_balance, Quantity::from(15_u32));
        let sink_asset_id = AssetId::new(asset_def_id.clone(), fee_sink.clone());
        let sink_balance = stx
            .world
            .asset_mut(&sink_asset_id)
            .expect("fee sink asset exists")
            .clone()
            .into_inner();
        assert_eq!(sink_balance, Quantity::from(5_u32));
        let dest_balance = stx
            .world
            .asset_mut(&dest_asset_id)
            .expect("destination asset exists")
            .clone()
            .into_inner();
        assert_eq!(dest_balance, Quantity::from(10_u32));
    }
    #[test]
    fn implicit_creation_fee_rejects_when_insufficient_balance() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: Some(ImplicitAccountCreationFee {
                asset_definition_id: asset_def_id.clone(),
                amount: Quantity::from(5_u32),
                destination: ImplicitAccountFeeDestination::Burn,
            }),
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(3_u32));
        let world = World::with_assets([domain], [alice_account], [asset_def], [alice_asset], []);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let dest_asset_id = AssetId::new(asset_def_id.clone(), dest.clone());
        let err = Mint::asset_quantity(1_u32, dest_asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("fee should prevent implicit creation");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(AccountAdmissionError::FeeUnsatisfied(
                    AccountAdmissionFeeUnsatisfied { .. }
                ))
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            stx.world.account(&dest).is_err(),
            "destination must not exist"
        );
        let alice_balance = stx
            .world
            .asset_mut(&alice_asset_id)
            .expect("alice asset exists")
            .clone()
            .into_inner();
        assert_eq!(alice_balance, Quantity::from(3_u32));
    }
    #[test]
    fn min_initial_amount_is_enforced() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let mut min_initial_amounts = BTreeMap::new();
        min_initial_amounts.insert(asset_def_id.clone(), Quantity::from(10_u32));
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts,
            default_role_on_create: None,
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let world = World::with([domain], [alice_account], [asset_def]);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let dest_asset_id = AssetId::new(asset_def_id.clone(), dest.clone());
        let err = Mint::asset_quantity(5_u32, dest_asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("mint should fail when below min initial amount");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(
                    AccountAdmissionError::MinInitialAmountUnsatisfied(
                        AccountAdmissionMinInitialAmountUnsatisfied { .. }
                    )
                )
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            stx.world.account(&dest).is_err(),
            "destination must not exist"
        );
        assert!(
            stx.world.asset_mut(&dest_asset_id).is_err(),
            "destination asset must not exist"
        );
    }
    #[test]
    fn default_role_is_assigned_on_implicit_creation() {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let role_id: RoleId = "baseline_user".parse().expect("role id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: Some(role_id.clone()),
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let asset_def_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_def = {
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let mut world = World::with([domain], [alice_account], [asset_def]);
        let role = iroha_data_model::role::Role {
            id: role_id.clone(),
            permissions: Permissions::new(),
            permission_epochs: BTreeMap::new(),
        };
        world.roles.insert(role_id.clone(), role);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let dest_asset_id = AssetId::new(asset_def_id.clone(), dest.clone());
        Mint::asset_quantity(1_u32, dest_asset_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("mint should create account and assign role");
        let mut roles = stx.world.account_roles_iter(&dest);
        assert_eq!(
            roles.next(),
            Some(&role_id),
            "implicit account should receive default role"
        );
        let events = &stx.world.internal_event_buf;
        let created_pos = events.iter().position(|event| {
            matches!(event.as_ref(), DataEvent::Account(AccountEvent::Created(_)))
        });
        let role_granted_pos = events.iter().position(|event| {
            matches!(
                event.as_ref(),
                DataEvent::Account(AccountEvent::RoleGranted(_))
            )
        });
        assert!(
            created_pos.is_some(),
            "account creation event should be emitted"
        );
        assert!(
            role_granted_pos.is_some(),
            "default role grant event should be emitted"
        );
        assert!(
            created_pos < role_granted_pos,
            "account creation should happen before default role grant"
        );
    }
    #[test]
    fn default_role_missing_rejects_implicit_creation() {
        let domain_id: DomainId = DomainId::try_new("missing-role", "world").expect("domain id");
        let role_id: RoleId = "starter".parse().expect("role id");
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: None,
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: Some(role_id.clone()),
        };
        let domain = open_domain(domain_id.clone());
        let alice_account = build_account_in_domain(ALICE_ID.clone(), domain_id.clone(), &ALICE_ID);
        let world = World::with([domain], [alice_account], []);
        let state = test_state(world, policy);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let dest = random_account_id();
        let err = ensure_receiving_account(&ALICE_ID, &dest, None, &mut stx)
            .expect_err("implicit creation should fail when role is absent");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AccountAdmission(
                    AccountAdmissionError::DefaultRoleError(AccountAdmissionDefaultRoleError {
                        ref role,
                        ..
                    })
                ) if role == &role_id
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            stx.world.account(&dest).is_err(),
            "account must not exist on failure"
        );
        assert!(
            stx.world.internal_event_buf.is_empty(),
            "no events should be emitted when role is missing"
        );
    }
}
