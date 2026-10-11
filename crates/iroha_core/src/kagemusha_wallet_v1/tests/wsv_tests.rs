//! Real WSV/canonical asset-owner tests; native fixture verification remains explicitly local.
use super::*;
use crate::{
    smartcontracts::Execute as _,
    state::{State, StateTransaction, World, WorldReadOnly},
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetId},
    block::BlockHeader,
    isi::{Burn, Transfer, Unregister},
    nexus::AxtAssetIncarnationV1,
    permission::Permissions,
};
use iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet;
use iroha_primitives::numeric::{Numeric, NumericSpec, Quantity};
use mv::storage::StorageReadOnly as _;

#[path = "load_event_evidence_tests.rs"]
mod load_event_evidence_tests;

#[path = "universal_asset_registration_tests.rs"]
mod universal_asset_registration_tests;

fn load_event_digests(events: &[iroha_data_model::events::EventBox]) -> Vec<[u8; 32]> {
    use iroha_data_model::events::{EventBox, data::DataEvent};
    events
        .iter()
        .filter_map(|event| match event {
            EventBox::Data(event) => match event.as_ref() {
                DataEvent::KagemushaLoadCommitted(load) => Some(load.receipt_digest),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn world_state(memory: &Memory, permission: bool) -> State {
    let r = &memory.registration;
    let owner = &memory.authority;
    let definition = AssetDefinition::new(
        r.asset.asset.clone(),
        "offline test",
        NumericSpec::fractional(r.asset.scale),
        AssetBalancePolicy::Global,
        None,
    )
    .build(owner);
    let assets = memory
        .balances
        .iter()
        .map(|(owner, value)| {
            Asset::new(
                AssetId::of(r.asset.asset.clone(), owner.clone()),
                Quantity::from_canonical_numeric(Numeric::new(*value, r.asset.scale)).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let mut world = World::with_assets(
        [],
        memory
            .balances
            .keys()
            .map(|account| Account::new(account.clone()).build(account)),
        [definition],
        assets,
        [],
    );
    world.axt_asset_incarnations.insert(
        r.asset.asset.clone(),
        AxtAssetIncarnationV1::try_from_bytes(r.asset.asset_incarnation).unwrap(),
    );
    if permission {
        world.account_permissions.insert(
            r.reserve.clone(),
            Permissions::from_iter([CanManageKagemushaWallet {
                asset_definition: r.asset.asset.clone(),
            }
            .into()]),
        );
    }
    let mut state = State::new_for_testing(
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    state.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::from_untyped_unchecked(Hash::prehashed(r.scheme.network_id)),
    );
    state
}
fn transact<T>(
    state: &mut State,
    height: u64,
    action: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<T>,
) -> Result<T> {
    let header = BlockHeader::new(height.try_into().unwrap(), None, None, height * 1_000, 0);
    let mut block = state.block(header.clone());
    let invocation = Hash::new(height.to_le_bytes());
    let mut tx = block.transaction_for_fastpq_testing(invocation);
    // Explicit local fixture binding: this is not network/finality qualification.
    tx.current_network_entrypoint_hash = Some(HashOf::from_untyped_unchecked(invocation));
    let result = action(&mut tx)?;
    tx.apply();
    event_evidence::retain(
        &mut block.world,
        height,
        &iroha_allocation::AllocationBudget::new(2_000_000),
    )
    .map_err(|_| Error::Unavailable)?;
    block.commit_world_overlay_for_testing().unwrap();
    state.push_block_hash_for_testing(header.hash());
    Ok(result)
}
fn register(state: &mut State, memory: &Memory, height: u64) -> Result<()> {
    transact(state, height, |tx| {
        wsv::WsvLedger::new(tx, &memory.registration.reserve)?.register(memory.registration.clone())
    })
}
fn balance(state: &State, memory: &Memory, owner: &AccountId) -> Quantity {
    state
        .view()
        .world
        .assets()
        .get(&AssetId::of(
            memory.registration.asset.asset.clone(),
            owner.clone(),
        ))
        .map(|v| v.as_ref().clone())
        .unwrap_or_else(Quantity::zero)
}
#[test]
fn registration_requires_dedicated_asset_permission_and_reserve_consent() {
    let memory = Memory::new();
    let mut state = world_state(&memory, false);
    assert!(register(&mut state, &memory, 1).is_err());
    assert!(
        state
            .view()
            .world
            .kagemusha_wallet_ledger()
            .iter()
            .next()
            .is_none()
    );
    // Owning the asset alone cannot capture another account's reserve bucket.
    assert!(
        transact(&mut state, 1, |tx| wsv::WsvLedger::new(
            tx,
            &memory.authority
        )?
        .register(memory.registration.clone()))
        .is_err()
    );
    transact(&mut state, 1, |tx| {
        tx.world.account_permissions.insert(
            memory.registration.reserve.clone(),
            Permissions::from_iter([CanManageKagemushaWallet {
                asset_definition:
                    iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                        iroha_model_base::domain::DomainId::try_new("wrong", "universal").unwrap(),
                        "coin".parse().unwrap(),
                    ),
            }
            .into()]),
        );
        Ok(())
    })
    .unwrap();
    assert!(register(&mut state, &memory, 2).is_err());
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    register(&mut state, &memory, 2).unwrap();
    let view = state.view();
    assert!(custody::is_reserve_account(&view.world, &memory.registration.reserve).unwrap());
    assert!(custody::is_reserve_definition(&view.world, &memory.registration.asset.asset).unwrap());
    let refs: u64 = storage::decode(
        view.world
            .kagemusha_wallet_ledger()
            .get(&storage::reserve_account_key(&memory.registration.reserve).unwrap())
            .unwrap(),
        128,
    )
    .unwrap();
    assert_eq!(
        refs, 1,
        "exact retry must not increment permanent references"
    );
}
#[test]
fn registration_rejects_a_foreign_network_before_creating_reserve_rows() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    state.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::from_untyped_unchecked(Hash::new(b"foreign KAGEMUSHA network")),
    );
    assert!(matches!(
        register(&mut state, &memory, 1),
        Err(Error::Binding)
    ));
    assert!(
        state
            .view()
            .world
            .kagemusha_wallet_ledger()
            .iter()
            .next()
            .is_none()
    );
}

#[test]
fn registered_reserve_rejects_ordinary_transfer_burn_and_teardown() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let reserve = custody::reserve_id(&memory.registration);
    let before = balance(&state, &memory, &memory.registration.reserve);
    let amount =
        Quantity::from_canonical_numeric(Numeric::new(1_u32, memory.registration.asset.scale))
            .unwrap();
    assert!(
        transact(&mut state, 2, |tx| Transfer::asset_quantity(
            reserve.clone(),
            amount.clone(),
            memory.authority.clone()
        )
        .execute(&memory.registration.reserve, tx)
        .map_err(Error::from))
        .is_err()
    );
    assert!(
        transact(&mut state, 2, |tx| Burn::asset_quantity(
            amount,
            reserve.clone()
        )
        .execute(&memory.registration.reserve, tx)
        .map_err(Error::from))
        .is_err()
    );
    assert!(
        transact(&mut state, 2, |tx| Unregister::account(
            memory.registration.reserve.clone()
        )
        .execute(&memory.registration.reserve, tx)
        .map_err(Error::from))
        .is_err()
    );
    assert!(
        transact(&mut state, 2, |tx| Unregister::asset_definition(
            memory.registration.asset.asset.clone()
        )
        .execute(&memory.authority, tx)
        .map_err(Error::from))
        .is_err()
    );
    assert_eq!(
        balance(&state, &memory, &memory.registration.reserve),
        before
    );
}
#[test]
fn native_rejection_and_missing_source_anchor_cannot_activate() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
    let before = state.view().world.kagemusha_wallet_ledger().iter().count();
    assert!(matches!(
        transact(&mut state, 2, |tx| activate(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &Verifier::new(false),
            &activation
        )),
        Err(Error::Proof)
    ));
    assert_eq!(
        state.view().world.kagemusha_wallet_ledger().iter().count(),
        before
    );
    assert!(matches!(
        transact(&mut state, 2, |tx| {
            tx.current_network_entrypoint_hash = None;
            wsv::WsvLedger::new(tx, &memory.authority).map(|_| ())
        }),
        Err(Error::Binding)
    ));
}
#[test]
fn real_asset_batch_loads_once_and_failed_debit_rolls_back_ordinal() {
    let mut memory = Memory::new();
    let command = memory.active();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let activation = fixture("KagemushaWalletActivationV1");
    transact(&mut state, 2, |tx| {
        activate(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &Verifier::new(true),
            &activation,
        )
    })
    .unwrap();
    let prior = balance(&state, &memory, &memory.registration.reserve);
    let first = transact(&mut state, 3, |tx| {
        let original = {
            let mut ledger = wsv::WsvLedger::new(tx, &memory.authority)?;
            let original = issue_load(&mut ledger, &command)?;
            assert_eq!(issue_load(&mut ledger, &command)?, original);
            original
        };
        assert_eq!(
            load_event_digests(&tx.world.external_event_buf),
            [original.body.receipt_digest()?],
            "the same execution retry must not emit a second funding event",
        );
        Ok(original)
    })
    .unwrap();
    let funded = balance(&state, &memory, &memory.registration.reserve);
    assert_eq!(
        funded,
        prior
            .checked_add(
                &Quantity::from_canonical_numeric(Numeric::new(
                    command.amount,
                    memory.registration.asset.scale
                ))
                .unwrap()
            )
            .unwrap()
    );
    assert!(matches!(
        transact(&mut state, 4, |tx| issue_load(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &command
        )),
        Err(Error::Conflict)
    ));
    assert_eq!(
        balance(&state, &memory, &memory.registration.reserve),
        funded
    );
    let mut overdrawn = command.clone();
    overdrawn.request_id = [0x79; 32];
    overdrawn.amount = 10_000;
    overdrawn.ordinal = 1;
    assert!(
        transact(&mut state, 5, |tx| issue_load(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &overdrawn
        ))
        .is_err()
    );
    assert_eq!(
        balance(&state, &memory, &memory.registration.reserve),
        funded
    );
    transact(&mut state, 5, |tx| {
        let ledger = wsv::WsvLedger::new(tx, &memory.authority)?;
        assert_eq!(
            ledger.issuance(&command.scheme, &command.wallet, &command.request_id)?,
            Some(first.clone())
        );
        assert_eq!(
            ledger
                .wallet(&command.scheme, &command.wallet)?
                .unwrap()
                .next_load,
            1
        );
        assert!(
            ledger
                .issuance(&command.scheme, &command.wallet, &overdrawn.request_id)?
                .is_none()
        );
        Ok(())
    })
    .unwrap();
    let rows: BTreeMap<_, _> = state
        .view()
        .world
        .kagemusha_wallet_ledger()
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let check = |rows: &BTreeMap<KagemushaWalletLedgerKeyV1, Vec<u8>>| {
        storage::validate_snapshot(rows.iter(), |key| rows.get(key).map(Vec::as_slice))
    };
    check(&rows).unwrap();
    for missing_key in [
        storage::key(storage::REGISTRATION, command.scheme, command.asset),
        storage::key(storage::WALLET, command.scheme, command.wallet),
    ] {
        let mut missing = rows.clone();
        missing.remove(&missing_key);
        assert!(
            check(&missing).is_err(),
            "issuance requires its permanent registration and wallet"
        );
    }
    for mutation in 0..6 {
        let mut altered = first.clone();
        match mutation {
            0 => altered.body.asset_digest = [0x88; 32],
            1 => altered.body.ordinal += 1,
            2 => altered.body.request_id = [0x89; 32],
            3 => {
                altered.body.payer_account_digest =
                    kagemusha_wallet_account_digest_v1(&memory.registration.reserve).unwrap()
            }
            4 => altered.body.amount += 1,
            _ => altered.command.wallet = [0x90; 32],
        }
        let mut changed = rows.clone();
        changed.insert(
            storage::issuance_key(command.scheme, command.wallet, command.request_id),
            storage::encode(&altered).unwrap(),
        );
        assert!(
            check(&changed).is_err(),
            "altered issuance field {mutation}"
        );
    }
}
#[test]
fn committed_reader_requires_an_original_cut_and_finite_limits() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let limits = norito::DecodeLimits::new(2_000_000, 2_000_000, 8_000_000, 16_000_000, 128);
    assert!(matches!(
        CommittedLoadReceipts::new(&chain.state().view(), 2_000_000, limits),
        Err(Error::NotCommitted)
    ));
    chain.commit_at(2_000, Vec::new());
    {
        let view = chain.state().view();
        let reader = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        assert!(matches!(
            reader.receipt_for(&Memory::new().authority, &[1; 32], &[2; 32], &[3; 32]),
            Err(Error::Unavailable)
        ));
        for maximum in [0, usize::MAX] {
            assert!(CommittedLoadReceipts::new(&view, maximum, limits).is_err());
        }
        assert!(
            CommittedLoadReceipts::new(&view, 2_000_000, norito::DecodeLimits::new(1, 1, 1, 0, 1))
                .is_err()
        );
    }
    // Recovery data comes from the original committed cut, without reopening local QCs.
    // This constructor produces no independent finality verification capability.
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    assert!(CommittedLoadReceipts::new(&chain.state().view(), 2_000_000, limits).is_ok());
}

#[test]
fn routing_uses_permanent_scope_and_refuses_missing_wallet_records() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1,
    };
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
    let instruction = KagemushaWalletLedgerV1::new(
        memory.registration.scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Activate(activation.to_canonical_bytes().unwrap()),
    );
    assert_eq!(
        routing::dataspace(&state.view().world, &instruction).unwrap(),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL
    );
    let missing = KagemushaWalletLedgerV1::new(
        instruction.scheme,
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: [3; 32],
            asset: memory.registration.asset.asset_digest(),
            ordinal: 0,
            request_id: [4; 32],
            amount: 1,
            charge: None,
        },
    );
    assert!(matches!(
        routing::dataspace(&state.view().world, &missing),
        Err(Error::Unavailable)
    ));
}

#[test]
fn verifier_pack_routing_requires_the_exact_registered_asset_and_permanent_scope() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1,
    };
    use iroha_model_base::topology::DataSpaceId;

    let memory = Memory::new();
    let scheme = memory.registration.scheme.scheme_id();
    let asset = memory.registration.asset.asset_digest();
    let instruction = KagemushaWalletLedgerV1::new(
        scheme,
        KagemushaWalletLedgerActionV1::InstallVerifierPack {
            asset,
            manifest_digest: [0x51; 32],
            // Routing selects the registered scope; execution authenticates the pack.
            pack: Vec::new(),
        },
    );
    let key = storage::key(storage::REGISTRATION, scheme, asset);
    let mut world = World::new();
    assert!(matches!(
        routing::dataspace(&world.view(), &instruction),
        Err(Error::Unavailable)
    ));
    for (scope, expected) in [
        (AssetBalanceScope::Global, Some(DataSpaceId::UNIVERSAL)),
        (
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            Some(DataSpaceId::new(7)),
        ),
        (AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL), None),
    ] {
        let mut registration = memory.registration.clone();
        registration.balance_scope = scope;
        world
            .kagemusha_wallet_ledger
            .insert(key, storage::encode(&registration).unwrap());
        match expected {
            Some(expected) => {
                assert_eq!(
                    routing::dataspace(&world.view(), &instruction).unwrap(),
                    expected
                );
            }
            None => assert!(matches!(
                routing::dataspace(&world.view(), &instruction),
                Err(Error::Binding)
            )),
        }
    }
    let mut substituted = memory.registration.clone();
    substituted.asset.asset_incarnation[0] ^= 1;
    world
        .kagemusha_wallet_ledger
        .insert(key, storage::encode(&substituted).unwrap());
    assert!(matches!(
        routing::dataspace(&world.view(), &instruction),
        Err(Error::Binding)
    ));
}

#[test]
fn verifier_install_routing_requires_the_registered_authorizing_asset_and_scheme() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1,
    };
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let scheme = memory.registration.scheme.scheme_id();
    let asset = memory.registration.asset.asset_digest();
    let instruction = |scheme, asset| {
        KagemushaWalletLedgerV1::new(
            scheme,
            KagemushaWalletLedgerActionV1::InstallVerifierPack {
                asset,
                manifest_digest: [0x47; 32],
                // Routing uses permanent scope, not untrusted artifact contents. The
                // execution owner separately rejects this unadmitted empty pack.
                pack: Vec::new(),
            },
        )
    };
    assert_eq!(
        routing::dataspace(&state.view().world, &instruction(scheme, asset)).unwrap(),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL
    );
    for (selected_scheme, selected_asset) in [(scheme, [0x91; 32]), ([0x92; 32], asset)] {
        assert!(matches!(
            routing::dataspace(
                &state.view().world,
                &instruction(selected_scheme, selected_asset),
            ),
            Err(Error::Unavailable)
        ));
    }
}

#[test]
fn package_quota_charges_exact_native_calls_and_one_operation_at_the_boundary() {
    let memory = Memory::new();
    let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
    let unload: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    for (package, calls) in [(&activation.bootstrap, 1), (&unload.package, 2)] {
        assert_eq!(package.lineage.lineage().is_some(), calls == 2);
        let bytes = package.step_proof.bytes.len()
            + package
                .lineage
                .lineage()
                .map_or(0, |value| value.proof.len());
        assert!(bytes > 0);
        let mut state = world_state(&memory, true);
        transact(&mut state, 1, |tx| {
            tx.zk.max_proof_size_bytes = u32::try_from(bytes).unwrap();
            tx.zk.max_verify_calls_per_tx = calls;
            tx.zk.max_verify_calls_per_block = calls;
            tx.zk.max_confidential_ops_per_block = 1;
            tx.zk.max_proof_bytes_block = u64::try_from(bytes).unwrap();
            let rows = tx.world.kagemusha_wallet_ledger.iter().count();
            // Existing model fixtures are used only to count retained transport
            // work. No fixture proof enters the native verifier or gets a verdict.
            wsv::WsvLedger::new(tx, &memory.authority)?.reserve_package_proof(package)?;
            assert_eq!(tx.zk_confidential_ops_in_tx, 1);
            assert_eq!(tx.zk_verify_calls_in_tx, calls);
            assert_eq!(tx.zk_proof_bytes_in_tx, u64::try_from(bytes).unwrap());
            assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn package_quota_refusal_is_atomic_for_sigma_and_lineage_limits_and_overflow() {
    let memory = Memory::new();
    let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
    let unload: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    for (package, calls) in [(&activation.bootstrap, 1), (&unload.package, 2)] {
        let bytes = package.step_proof.bytes.len()
            + package
                .lineage
                .lineage()
                .map_or(0, |value| value.proof.len());
        assert!(bytes > 1);
        for refusal in 0..10 {
            let mut state = world_state(&memory, true);
            transact(&mut state, 1, |tx| {
                tx.zk_confidential_ops_in_tx = 1;
                tx.zk_verify_calls_in_tx = 1;
                tx.zk_proof_bytes_in_tx = 13;
                tx.zk.max_proof_size_bytes = u32::try_from(bytes).unwrap();
                tx.zk.max_verify_calls_per_tx = calls + 1;
                tx.zk.max_verify_calls_per_block = calls + 1;
                tx.zk.max_confidential_ops_per_block = 2;
                tx.zk.max_proof_bytes_block = 13 + u64::try_from(bytes).unwrap();
                match refusal {
                    0 => tx.zk.max_verify_calls_per_tx = calls,
                    1 => tx.zk.max_verify_calls_per_block = calls,
                    2 => tx.zk.max_proof_bytes_block -= 1,
                    3 => tx.zk.max_proof_size_bytes -= 1,
                    4 => tx.zk.max_confidential_ops_per_block = 1,
                    5 => tx.zk_verify_calls_in_tx = u32::MAX,
                    6 => tx.zk_proof_bytes_in_tx = u64::MAX,
                    7 => tx.zk_confidential_ops_in_tx = u32::MAX,
                    8 => tx.zk_verify_calls_in_block_so_far = u32::MAX,
                    _ => tx.zk_proof_bytes_in_block_so_far = u64::MAX,
                }
                let before = (
                    tx.zk_confidential_ops_in_tx,
                    tx.zk_verify_calls_in_tx,
                    tx.zk_proof_bytes_in_tx,
                    tx.zk_confidential_ops_in_block_so_far,
                    tx.zk_verify_calls_in_block_so_far,
                    tx.zk_proof_bytes_in_block_so_far,
                );
                let rows = tx.world.kagemusha_wallet_ledger.iter().count();
                assert!(
                    wsv::WsvLedger::new(tx, &memory.authority)?
                        .reserve_package_proof(package)
                        .is_err(),
                    "native call count {calls}, refusal {refusal}"
                );
                assert_eq!(
                    (
                        tx.zk_confidential_ops_in_tx,
                        tx.zk_verify_calls_in_tx,
                        tx.zk_proof_bytes_in_tx,
                        tx.zk_confidential_ops_in_block_so_far,
                        tx.zk_verify_calls_in_block_so_far,
                        tx.zk_proof_bytes_in_block_so_far,
                    ),
                    before,
                    "refused whole-package reservation must leave no partial charge"
                );
                assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
                Ok(())
            })
            .unwrap();
        }
    }
}

#[test]
fn lineage_call_quota_refuses_before_native_verifier_or_payout() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1,
    };
    let memory = Memory::new();
    let claim: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    assert!(claim.package.lineage.lineage().is_some());
    claim.verify(&memory.registration.scheme).unwrap();
    for transaction_limit in [true, false] {
        let mut state = world_state(&memory, true);
        register(&mut state, &memory, 1).unwrap();
        let verifier = Verifier::new(true);
        let instruction = KagemushaWalletLedgerV1::new(
            memory.registration.scheme.scheme_id(),
            KagemushaWalletLedgerActionV1::Unload(claim.to_canonical_bytes().unwrap()),
        );
        let result: Result<()> = transact(&mut state, 2, |tx| {
            tx.zk.max_verify_calls_per_tx = if transaction_limit { 1 } else { 2 };
            tx.zk.max_verify_calls_per_block = if transaction_limit { 2 } else { 1 };
            let rows = tx.world.kagemusha_wallet_ledger.iter().count();
            let result = crate::smartcontracts::isi::kagemusha_wallet::execute_with_verifier(
                instruction,
                &memory.authority,
                tx,
                &verifier,
            );
            assert!(matches!(result, Err(Error::Execution(_))));
            assert_eq!(verifier.calls.get(), 0);
            assert_eq!(tx.zk_confidential_ops_in_tx, 0);
            assert_eq!(tx.zk_verify_calls_in_tx, 0);
            assert_eq!(tx.zk_proof_bytes_in_tx, 0);
            assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
            result
        });
        assert!(matches!(result, Err(Error::Execution(_))));
        assert_eq!(verifier.calls.get(), 0);
    }
}

#[test]
fn unavailable_production_artifacts_retain_local_deferral_and_no_activation() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1,
    };
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
    let instruction = KagemushaWalletLedgerV1::new(
        memory.registration.scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Activate(activation.to_canonical_bytes().unwrap()),
    );
    let result: Result<()> = transact(&mut state, 2, |tx| {
        let rows = tx.world.kagemusha_wallet_ledger.iter().count();
        assert!(instruction.execute(&memory.authority, tx).is_err());
        assert_eq!(
            tx.execution_deferral().unwrap().reason(),
            ivm::error::ExecutionDeferral::VerifierArtifactsUnavailable
        );
        assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
        Err(Error::ArtifactsUnavailable)
    });
    assert!(matches!(result, Err(Error::ArtifactsUnavailable)));
}

#[test]
fn verifier_install_requires_actual_reserve_owner_before_artifact_parsing() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let result: Result<()> = transact(&mut state, 2, |tx| {
        let rows = tx.world.kagemusha_wallet_ledger.iter().count();
        let result = wsv::WsvLedger::new(tx, &memory.authority)?.install_verifier_pack(
            memory.registration.scheme.scheme_id(),
            memory.registration.asset.asset_digest(),
            [3; 32],
            vec![1],
        );
        assert!(matches!(result, Err(Error::Execution(_))));
        assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
        result
    });
    assert!(matches!(result, Err(Error::Execution(_))));
}

#[test]
#[ignore = "genuine complete signed native inventory; run optimized"]
fn genuine_verifier_install_is_immutable_exact_retry_and_same_overlay_native_owner() {
    use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
        InstalledVerifierPackV1, engineering_fixture,
    };
    let (pack, installation) = engineering_fixture::signed_inventory();
    let mut memory = Memory::new();
    memory.registration.scheme =
        KagemushaWalletSchemeV1::decode_canonical(&pack.scheme, &installation.scheme_id).unwrap();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let original = pack.to_canonical_bytes().unwrap();
    InstalledVerifierPackV1::load(&original, installation).unwrap();
    let row_key = super::super::artifacts::key(installation.scheme_id);
    let install = |tx: &mut StateTransaction<'_, '_>, pin, original| {
        wsv::WsvLedger::new(tx, &memory.registration.reserve)?.install_verifier_pack(
            installation.scheme_id,
            memory.registration.asset.asset_digest(),
            pin,
            original,
        )
    };
    let before_rows = state.view().world.kagemusha_wallet_ledger().iter().count();
    transact(&mut state, 2, |tx| {
        install(tx, installation.manifest_digest, original.clone())
    })
    .unwrap();
    let retained = state
        .view()
        .world
        .kagemusha_wallet_ledger()
        .get(&row_key)
        .unwrap()
        .clone();
    assert_eq!(
        state.view().world.kagemusha_wallet_ledger().iter().count(),
        before_rows + 1
    );
    let (alternate, alternate_installation) =
        engineering_fixture::alternate_authority(&pack, installation);
    let alternate_original = alternate.to_canonical_bytes().unwrap();
    InstalledVerifierPackV1::load(&alternate_original, alternate_installation).unwrap();
    assert_ne!(alternate_original, original);
    assert!(matches!(
        transact(&mut state, 4, |tx| install(
            tx,
            alternate_installation.manifest_digest,
            alternate_original
        )),
        Err(Error::Conflict)
    ));
    assert_eq!(
        state.view().world.kagemusha_wallet_ledger().get(&row_key),
        Some(&retained)
    );
    transact(&mut state, 3, |tx| {
        install(tx, installation.manifest_digest, original.clone())
    })
    .unwrap();
    assert_eq!(
        state.view().world.kagemusha_wallet_ledger().get(&row_key),
        Some(&retained)
    );
    assert_eq!(
        state.view().world.kagemusha_wallet_ledger().iter().count(),
        before_rows + 1
    );
    for changed_member in 0..5 {
        let mut changed = pack.clone();
        let member = match changed_member {
            0 => &mut changed.signer_certificate,
            1 => &mut changed.manifest,
            2 => &mut changed.steps[0].artifact.descriptor,
            3 => &mut changed.steps[0].artifact.verifying_key,
            _ => &mut changed.lineage.verifying_key,
        };
        *member.last_mut().unwrap() ^= 1;
        assert!(
            transact(&mut state, 4, |tx| {
                install(
                    tx,
                    installation.manifest_digest,
                    changed.to_canonical_bytes().unwrap(),
                )
            })
            .is_err()
        );
        assert_eq!(
            state.view().world.kagemusha_wallet_ledger().get(&row_key),
            Some(&retained)
        );
    }
    assert!(
        transact(&mut state, 4, |tx| install(
            tx,
            [0x52; 32],
            original.clone()
        ))
        .is_err()
    );
    assert!(
        transact(&mut state, 4, |tx| {
            wsv::WsvLedger::new(tx, &memory.registration.reserve)?.install_verifier_pack(
                installation.scheme_id,
                [0x53; 32],
                installation.manifest_digest,
                original.clone(),
            )
        })
        .is_err()
    );
    assert_eq!(
        state.view().world.kagemusha_wallet_ledger().get(&row_key),
        Some(&retained)
    );
    // The real same-overlay verifier exists, but unrelated fixture credentials/packages
    // cannot obtain a verdict from this engineering-only installation.
    transact(&mut state, 4, |tx| {
        let verifier =
            super::super::artifacts::LedgerVerifier::from_state(tx, installation.scheme_id);
        let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
        assert!(
            verifier
                .verify(
                    &memory.registration.scheme,
                    &activation.credential,
                    &activation.bootstrap
                )
                .is_err()
        );
        let value: super::super::artifacts::VerifierInstallation = storage::decode(
            tx.world.kagemusha_wallet_ledger.get(&row_key).unwrap(),
            super::super::artifacts::CAP,
        )?;
        value.require_registration(&memory.registration)?;
        let mut changed_registration = memory.registration.clone();
        changed_registration.asset.asset_incarnation[0] ^= 1;
        assert!(value.require_registration(&changed_registration).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn verifier_install_rechecks_live_asset_permission_and_registered_scope() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    transact(&mut state, 2, |tx| {
        tx.world
            .account_permissions
            .remove(memory.registration.reserve.clone());
        Ok(())
    })
    .unwrap();
    let result: Result<()> = transact(&mut state, 3, |tx| {
        let rows = tx.world.kagemusha_wallet_ledger.iter().count();
        let result = wsv::WsvLedger::new(tx, &memory.registration.reserve)?.install_verifier_pack(
            memory.registration.scheme.scheme_id(),
            memory.registration.asset.asset_digest(),
            [3; 32],
            vec![1],
        );
        assert!(matches!(result, Err(Error::Execution(_))));
        assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
        result
    });
    assert!(matches!(result, Err(Error::Execution(_))));
    assert!(
        transact(&mut state, 3, |tx| {
            wsv::WsvLedger::new(tx, &memory.registration.reserve)?.install_verifier_pack(
                memory.registration.scheme.scheme_id(),
                [7; 32],
                [3; 32],
                vec![1],
            )
        })
        .is_err()
    );
}

#[test]
fn authorized_install_cannot_turn_missing_originals_into_a_verifier() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    for (manifest, original) in [
        ([0; 32], vec![1]),
        ([3; 32], Vec::new()),
        ([3; 32], vec![1]),
    ] {
        assert!(
            transact(&mut state, 2, |tx| {
                let rows = tx.world.kagemusha_wallet_ledger.iter().count();
                let result = wsv::WsvLedger::new(tx, &memory.registration.reserve)?
                    .install_verifier_pack(
                        memory.registration.scheme.scheme_id(),
                        memory.registration.asset.asset_digest(),
                        manifest,
                        original,
                    );
                assert!(result.is_err());
                assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
                assert!(
                    tx.world
                        .kagemusha_wallet_ledger
                        .get(&super::super::artifacts::key(
                            memory.registration.scheme.scheme_id()
                        ),)
                        .is_none()
                );
                result
            })
            .is_err()
        );
    }
}

#[test]
fn package_quota_refuses_before_native_verifier_and_ledger_activation() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1,
    };
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let activation: KagemushaWalletActivationV1 = fixture("KagemushaWalletActivationV1");
    let verifier = Verifier::new(true);
    let instruction = KagemushaWalletLedgerV1::new(
        memory.registration.scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Activate(activation.to_canonical_bytes().unwrap()),
    );
    assert!(
        transact(&mut state, 2, |tx| {
            tx.zk.max_proof_size_bytes = 1;
            let rows = tx.world.kagemusha_wallet_ledger.iter().count();
            let result = crate::smartcontracts::isi::kagemusha_wallet::execute_with_verifier(
                instruction,
                &memory.authority,
                tx,
                &verifier,
            );
            assert!(matches!(result, Err(Error::Execution(_))));
            assert_eq!(verifier.calls.get(), 0);
            assert_eq!(tx.world.kagemusha_wallet_ledger.iter().count(), rows);
            result
        })
        .is_err()
    );
}

#[test]
fn real_reserve_pays_unload_once_and_online_controls_defer_without_consuming_it() {
    use iroha_data_model::{asset::AssetTransferAvailability, isi::SetAssetTransferAvailability};
    let mut memory = Memory::new();
    let claim: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    if let KagemushaWalletUnloadChargeV1::Quoted { beneficiary, .. } = &claim.charge {
        memory.balances.insert(beneficiary.clone(), 0);
    }
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let key = KagemushaWalletPayoutKeyV1::Unload(
        claim.verify(&memory.registration.scheme).unwrap().nullifier,
    );
    let before = balance(&state, &memory, &memory.registration.reserve);
    transact(&mut state, 2, |tx| {
        SetAssetTransferAvailability::new(
            memory.registration.reserve.clone(),
            memory.registration.asset.asset.clone(),
            0,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Disabled,
            None,
        )
        .execute(&memory.authority, tx)
        .map_err(Error::from)
    })
    .unwrap();
    assert!(
        transact(&mut state, 3, |tx| pay_unload(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &Verifier::new(true),
            &claim,
        ))
        .is_err()
    );
    assert_eq!(
        balance(&state, &memory, &memory.registration.reserve),
        before
    );
    transact(&mut state, 3, |tx| {
        assert!(
            wsv::WsvLedger::new(tx, &memory.authority)?
                .payout(&memory.registration.scheme.scheme_id(), key)?
                .is_none()
        );
        SetAssetTransferAvailability::new(
            memory.registration.reserve.clone(),
            memory.registration.asset.asset.clone(),
            1,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Enabled,
            None,
        )
        .execute(&memory.authority, tx)
        .map_err(Error::from)
    })
    .unwrap();
    let verifier = Verifier::new(true);
    let paid = transact(&mut state, 4, |tx| {
        pay_unload(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &verifier,
            &claim,
        )
    })
    .unwrap();
    let expected = before
        .checked_sub(
            &Quantity::from_canonical_numeric(Numeric::new(
                paid.amount,
                memory.registration.asset.scale,
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        balance(&state, &memory, &memory.registration.reserve),
        expected
    );
    assert_eq!(
        transact(&mut state, 5, |tx| pay_unload(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &verifier,
            &claim,
        ))
        .unwrap(),
        paid
    );
    assert_eq!(
        balance(&state, &memory, &memory.registration.reserve),
        expected
    );
    assert_eq!(
        verifier.calls.get(),
        2,
        "retry re-verifies the retained claim"
    );
}

#[test]
fn real_fee_payout_requires_retained_history_and_never_requires_receive() {
    let mut memory = Memory::new();
    memory.history = true;
    let claim: KagemushaWalletFeeClaimV1 = fixture("KagemushaWalletFeeClaimV1");
    memory.balances.insert(claim.beneficiary.clone(), 0);
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    assert!(matches!(
        transact(&mut state, 2, |tx| pay_fee(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &Verifier::new(true),
            &claim,
        )),
        Err(Error::Unavailable)
    ));
    let history = memory.fee_inputs(&claim).unwrap();
    transact(&mut state, 2, |tx| {
        let mut ledger = wsv::WsvLedger::new(tx, &memory.authority)?;
        ledger.retain_credential(CredentialRecord {
            credential: history.payer,
            certificates: history.certificates.clone(),
        })?;
        ledger.retain_request(history.request.clone())
    })
    .unwrap();
    let paid = transact(&mut state, 3, |tx| {
        pay_fee(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &Verifier::new(true),
            &claim,
        )
    })
    .unwrap();
    assert_eq!(
        balance(&state, &memory, &claim.beneficiary),
        Quantity::from_canonical_numeric(Numeric::new(
            paid.amount,
            memory.registration.asset.scale
        ))
        .unwrap()
    );
    assert_eq!(
        transact(&mut state, 4, |tx| pay_fee(
            &mut wsv::WsvLedger::new(tx, &memory.authority)?,
            &Verifier::new(true),
            &claim,
        ))
        .unwrap(),
        paid
    );
    assert_eq!(
        balance(&state, &memory, &claim.beneficiary),
        Quantity::from_canonical_numeric(Numeric::new(
            paid.amount,
            memory.registration.asset.scale
        ))
        .unwrap()
    );
}

#[test]
fn corrupted_reserve_owner_and_mutated_registration_are_rejected() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let mut changed = memory.registration.clone();
    changed.balance_scope =
        AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::new(3));
    assert!(
        transact(&mut state, 2, |tx| wsv::WsvLedger::new(
            tx,
            &memory.registration.reserve
        )?
        .register(changed))
        .is_err()
    );
    transact(&mut state, 2, |tx| {
        let reserve = custody::reserve_id(&memory.registration);
        let key = storage::reserve_key(&reserve)?;
        tx.world.kagemusha_wallet_ledger.insert(key, vec![0; 32]);
        assert!(custody::reserve_registration(tx.world(), &reserve).is_err());
        Ok(())
    })
    .unwrap();
    assert!(register(&mut state, &memory, 3).is_err());
}

#[test]
fn snapshot_requires_exact_reserve_indexes_and_reference_counts() {
    let memory = Memory::new();
    let mut state = world_state(&memory, true);
    register(&mut state, &memory, 1).unwrap();
    let rows: BTreeMap<_, _> = state
        .view()
        .world
        .kagemusha_wallet_ledger()
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let check = |rows: &BTreeMap<KagemushaWalletLedgerKeyV1, Vec<u8>>| {
        storage::validate_snapshot(rows.iter(), |key| rows.get(key).map(Vec::as_slice))
    };
    check(&rows).unwrap();
    for key in [
        storage::reserve_key(&custody::reserve_id(&memory.registration)).unwrap(),
        storage::reserve_account_key(&memory.registration.reserve).unwrap(),
        storage::reserve_definition_key(&memory.registration.asset.asset).unwrap(),
        storage::key(
            storage::REGISTRATION,
            memory.registration.scheme.scheme_id(),
            memory.registration.asset.asset_digest(),
        ),
    ] {
        let mut missing = rows.clone();
        missing.remove(&key);
        assert!(
            check(&missing).is_err(),
            "every original binding is required"
        );
    }
    let mut inflated = rows.clone();
    inflated.insert(
        storage::reserve_account_key(&memory.registration.reserve).unwrap(),
        storage::encode(&2_u64).unwrap(),
    );
    assert!(check(&inflated).is_err());
    let mut orphan = rows;
    orphan.insert(
        storage::reserve_account_key(&memory.authority).unwrap(),
        storage::encode(&1_u64).unwrap(),
    );
    assert!(check(&orphan).is_err());
}

#[test]
fn private_root_load_rejects_before_debit_or_receipt_creation() {
    use crate::{
        state::StateReadOnly as _,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        block::consensus::{PrivateRootFeePolicy, SumeragiRootScope},
        domain::Domain,
        isi::{
            Mint, Register,
            kagemusha_wallet::{KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1},
        },
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

    let mut memory = Memory::new();
    let payer_key =
        iroha_crypto::KeyPair::from_seed(vec![0x66; 32], iroha_crypto::Algorithm::Ed25519);
    memory.balances.remove(&memory.authority);
    memory.authority = AccountId::new(payer_key.public_key().clone());
    memory.balances.insert(memory.authority.clone(), 1000);
    let dataspace = DataSpaceId::new(117);
    let balance_scope = AssetBalanceScope::Dataspace(dataspace);
    memory.registration.balance_scope = balance_scope;
    // The owning domain must resolve to the actual configured private dataspace.
    let dataspace_alias = "private-load";
    let domain = DomainId::try_new("load", dataspace_alias).unwrap();
    let mut world = World::with_assets(
        [Domain::new(domain.clone()).build(&memory.authority)],
        memory
            .balances
            .keys()
            .map(|account| Account::new(account.clone()).build(account)),
        [AssetDefinition::new(
            memory.registration.asset.asset.clone(),
            "private Load principal",
            NumericSpec::fractional(memory.registration.asset.scale),
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain.clone()),
        )
        .build(&memory.authority)],
        memory.balances.iter().map(|(account, amount)| {
            Asset::new(
                AssetId::with_scope(
                    memory.registration.asset.asset.clone(),
                    account.clone(),
                    balance_scope,
                ),
                Quantity::from_canonical_numeric(Numeric::new(
                    *amount,
                    memory.registration.asset.scale,
                ))
                .unwrap(),
            )
        }),
        [],
    );
    world.axt_asset_incarnations.insert(
        memory.registration.asset.asset.clone(),
        AxtAssetIncarnationV1::try_from_bytes(memory.registration.asset.asset_incarnation).unwrap(),
    );
    world.account_permissions.insert(
        memory.registration.reserve.clone(),
        Permissions::from_iter([CanManageKagemushaWallet {
            asset_definition: memory.registration.asset.asset.clone(),
        }
        .into()]),
    );
    let fee_asset = iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    let mut config = TestChainConfig::new(world, 1_000);
    // Genesis registers the separate execution-fee asset in this domain. Keep
    // its actual owner distinct from the ordinary Load payer being tested.
    let genesis_authority = AccountId::new(config.genesis_key.public_key().clone());
    config.world.insert_domain_for_testing(
        domain.clone(),
        Domain::new(domain.clone()).build(&genesis_authority),
    );
    config.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"parent of private Load root")),
        ),
        dataspace_id: dataspace,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.lane_catalog = LaneCatalog::new(
        1_u32.try_into().unwrap(),
        vec![LaneConfig {
            dataspace_id: dataspace,
            alias: dataspace_alias.into(),
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: dataspace,
        alias: dataspace_alias.into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = dataspace;
    nexus.fees.fee_asset_id = fee_asset.canonical_address();
    nexus.fees.fee_sink_account_id =
        AccountId::new(config.genesis_key.public_key().clone()).to_string();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            PrivateRootFeePolicy {
                asset_definition_id: fee_asset.clone(),
                base_fee: 1_u32.into(),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: 1_u32.into(),
                per_gas_unit_fee: 1_u32.into(),
            }
            .into_custom_parameter()
            .unwrap(),
        ));
    config.pipeline.gas.tech_account_id =
        AccountId::new(config.genesis_key.public_key().clone()).to_string();
    config.pipeline.gas.accepted_assets = vec![fee_asset.canonical_address()];
    config.pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: fee_asset.canonical_address(),
        units_per_gas: 1,
        twap_local_per_xor: Numeric::one(),
        liquidity: iroha_config::parameters::actual::GasLiquidity::Tier2,
        volatility: iroha_config::parameters::actual::GasVolatility::Stable,
    }];
    config
        .genesis_instructions
        .extend([Register::asset_definition(AssetDefinition::numeric(
            fee_asset.clone(),
            "private Load execution fee",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        ))
        .into()]);
    // Execution fees have a separate asset; principal balances must remain exact.
    for key in [
        payer_key.clone(),
        config.genesis_key.clone(),
        iroha_crypto::KeyPair::from_seed(vec![0xCC; 32], iroha_crypto::Algorithm::Ed25519),
    ] {
        config.genesis_instructions.push(
            Mint::asset_quantity(
                1_000_000_u32,
                AssetId::with_scope(
                    fee_asset.clone(),
                    AccountId::new(key.public_key().clone()),
                    balance_scope,
                ),
            )
            .into(),
        );
    }
    let mut chain = CertifiedTestChain::start(config).unwrap();
    memory.registration.scheme.network_id = *chain.network_id().as_bytes();
    let scheme = memory.registration.scheme.scheme_id();
    let wallet = [0x95; 32];
    let request = [0x96; 32];
    // Enrollment is fixture data, as in the global happy-path test. The root scope,
    // payer source, routing, paid execution and rejection are actual chain inputs.
    chain.setup_world_at(2_000, |tx| {
        tx.current_network_entrypoint_hash = Some(HashOf::from_untyped_unchecked(Hash::new(
            b"private registration fixture",
        )));
        wsv::WsvLedger::new(tx, &memory.registration.reserve)
            .unwrap()
            .register(memory.registration.clone())
            .unwrap();
        tx.world.kagemusha_wallet_ledger.insert(
            storage::key(storage::WALLET, scheme, wallet),
            storage::encode(&WalletRecord {
                asset: memory.registration.asset.asset_digest(),
                phase: Phase::Active,
                activation: [0x97; 32],
                next_load: 0,
            })
            .unwrap(),
        );
    });
    let instruction = KagemushaWalletLedgerV1::new(
        scheme,
        Action::IssueLoad {
            wallet,
            asset: memory.registration.asset.asset_digest(),
            ordinal: 0,
            request_id: request,
            amount: 100,
            charge: None,
        },
    );
    let original_rows = {
        let view = chain.state().view();
        let target = crate::queue::native_instruction_execution_target(
            &instruction,
            &view.nexus().dataspace_catalog,
            view.world(),
            2_000,
        )
        .unwrap();
        assert_eq!(target.dataspace, Some(dataspace));
        assert!(
            !target.global,
            "ordinary private routing alone permits this Load"
        );
        view.world()
            .kagemusha_wallet_ledger()
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>()
    };
    let load = chain.sign(&payer_key, [instruction.into()], 1_999);
    assert_eq!(chain.commit_at(2_000, vec![load]), vec![false]);
    let committed = chain.committed(2);
    let (_, output) = committed.block().network_output_at(0).unwrap();
    assert!(
        format!("{:?}", output.result).contains("KAGEMUSHA Load requires the original Global root"),
        "unexpected rejection: {:?}",
        output.result,
    );
    let view = chain.state().view();
    for (account, amount) in &memory.balances {
        assert_eq!(
            view.world()
                .assets()
                .get(&AssetId::with_scope(
                    memory.registration.asset.asset.clone(),
                    account.clone(),
                    balance_scope,
                ))
                .unwrap()
                .as_ref(),
            &Quantity::from_canonical_numeric(Numeric::new(
                *amount,
                memory.registration.asset.scale
            ))
            .unwrap(),
        );
    }
    assert_eq!(
        view.world()
            .kagemusha_wallet_ledger()
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>(),
        original_rows,
        "rejected Load must preserve the wallet ordinal and every retained row",
    );
    assert!(
        view.world()
            .kagemusha_wallet_ledger()
            .get(&storage::issuance_key(scheme, wallet, request))
            .is_none()
    );
}

#[test]
fn ordinary_load_receipt_is_recovered_after_growth_and_local_qc_loss() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1,
    };
    let mut memory = Memory::new();
    let payer_key =
        iroha_crypto::KeyPair::from_seed(vec![0x66; 32], iroha_crypto::Algorithm::Ed25519);
    memory.balances.remove(&memory.authority);
    memory.authority = AccountId::new(payer_key.public_key().clone());
    memory.balances.insert(memory.authority.clone(), 1000);
    let world = world_state(&memory, true).world;
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
    memory.registration.scheme.network_id = *chain.network_id().as_bytes();
    let scheme = memory.registration.scheme.scheme_id();
    let wallet = [0x91; 32];
    let request = [0x92; 32];
    // Only Bootstrap enrollment is a fixture. Issuance, transaction/output membership,
    // ordinary permissions and exact-quorum finality use the actual chain owners.
    chain.setup_world_at(2_000, |tx| {
        tx.current_network_entrypoint_hash = Some(HashOf::from_untyped_unchecked(Hash::new(
            b"registration fixture",
        )));
        wsv::WsvLedger::new(tx, &memory.registration.reserve)
            .unwrap()
            .register(memory.registration.clone())
            .unwrap();
        tx.world.kagemusha_wallet_ledger.insert(
            storage::key(storage::WALLET, scheme, wallet),
            storage::encode(&WalletRecord {
                asset: memory.registration.asset.asset_digest(),
                phase: Phase::Active,
                activation: [0x93; 32],
                next_load: 0,
            })
            .unwrap(),
        );
    });
    let issue = |ordinal, request_id| {
        KagemushaWalletLedgerV1::new(
            scheme,
            Action::IssueLoad {
                wallet,
                asset: memory.registration.asset.asset_digest(),
                ordinal,
                request_id,
                amount: 100,
                charge: None,
            },
        )
    };
    chain.take_events().unwrap();
    let first = chain.sign(&payer_key, [issue(0, request).into()], 1_999);
    assert_eq!(chain.commit_at(2_000, vec![first]), vec![true]);
    let limits = norito::DecodeLimits::new(2_000_000, 2_000_000, 16_000_000, 32_000_000, 128);
    let original = {
        let view = chain.state().view();
        let source = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        let original = source
            .receipt_for(&memory.authority, &scheme, &wallet, &request)
            .unwrap();
        assert_eq!(original.block_height, 2);
        assert_eq!(original.ordinal, 0);
        assert_eq!(original.request_id, request);
        assert_eq!(
            original.payer_account_digest,
            kagemusha_wallet_account_digest_v1(&memory.authority).unwrap()
        );
        assert!(
            source
                .receipt_for(&memory.registration.reserve, &scheme, &wallet, &request)
                .is_err()
        );
        let tiny = CommittedLoadReceipts::new(&view, 1, limits).unwrap();
        assert!(matches!(
            tiny.receipt_for(&memory.authority, &scheme, &wallet, &request),
            Err(Error::Unavailable)
        ));
        let bounded = CommittedLoadReceipts::new(
            &view,
            2_000_000,
            norito::DecodeLimits::new(2_000_000, 2_000_000, 16_000_000, 64_000, 128),
        )
        .unwrap();
        assert_eq!(
            bounded
                .receipt_for(&memory.authority, &scheme, &wallet, &request)
                .unwrap(),
            original
        );
        assert!((0..128).any(|_| {
            bounded
                .receipt_for(&memory.authority, &scheme, &wallet, &request)
                .is_err()
        }));
        assert!(
            bounded
                .receipt_for(&memory.authority, &scheme, &wallet, &request)
                .is_err()
        );
        let fresh = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        assert!(
            norito::core::with_decode_limits_scope(
                norito::DecodeLimits::new(2_000_000, 2_000_000, 16_000_000, 1, 128),
                || fresh.receipt_for(&memory.authority, &scheme, &wallet, &request),
            )
            .is_err()
        );
        original
    };
    // The native certificate authenticates the exact ordinary event bytes and count.
    // Publishing the event does not add any separate signature or authority.
    let emitted = chain
        .take_events()
        .unwrap()
        .into_iter()
        .filter(|event| {
            !matches!(
                event,
                iroha_data_model::events::EventBox::Pipeline(_)
                    | iroha_data_model::events::EventBox::PipelineBatch(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        load_event_digests(&emitted),
        [original.receipt_digest().unwrap()]
    );
    let certified = chain.committed(2);
    assert_eq!(
        certified.commitment().execution.event_commitment,
        crate::sumeragi::commitment::event_commitment(&emitted).unwrap(),
    );
    let tree = emitted
        .iter()
        .map(HashOf::new)
        .collect::<iroha_crypto::MerkleTree<_>>();
    let event_index = emitted
        .iter()
        .position(|event| !load_event_digests(core::slice::from_ref(event)).is_empty())
        .unwrap();
    assert!(
        tree.get_proof(event_index.try_into().unwrap())
            .unwrap()
            .verify(
                &HashOf::new(&emitted[event_index]),
                &certified.commitment().execution.event_commitment.unwrap(),
            )
    );
    let stale = chain.sign(&payer_key, [issue(0, [0x94; 32]).into()], 2_999);
    assert_eq!(chain.commit_at(3_000, vec![stale]), vec![false]);
    assert!(load_event_digests(&chain.take_events().unwrap()).is_empty());
    let retry = chain.sign(&payer_key, [issue(0, request).into()], 3_999);
    assert_eq!(chain.commit_at(4_000, vec![retry]), vec![false]);
    assert!(load_event_digests(&chain.take_events().unwrap()).is_empty());
    // Load succeeds in its disposable overlay, then a later instruction fails.
    // Neither the event nor its reserve transfer/ordinal/receipt may escape rollback.
    let failed_request = [0x98; 32];
    let rollback = chain.sign(
        &payer_key,
        [
            issue(1, failed_request).into(),
            Burn::asset_quantity(
                10_000_u32,
                AssetId::of(
                    memory.registration.asset.asset.clone(),
                    memory.authority.clone(),
                ),
            )
            .into(),
        ],
        4_999,
    );
    let before_reserve = balance(chain.state(), &memory, &memory.registration.reserve);
    assert_eq!(chain.commit_at(5_000, vec![rollback]), vec![false]);
    let rejected = chain.committed(5);
    let (_, output) = rejected.block().network_output_at(0).unwrap();
    assert!(
        format!("{:?}", output.result).contains("insufficient fee custody balance"),
        "unexpected rejection: {:?}",
        output.result
    );
    assert!(load_event_digests(&chain.take_events().unwrap()).is_empty());
    assert_eq!(
        balance(chain.state(), &memory, &memory.registration.reserve),
        before_reserve
    );
    {
        let view = chain.state().view();
        let rows = view.world().kagemusha_wallet_ledger();
        assert!(
            rows.get(&storage::issuance_key(scheme, wallet, failed_request))
                .is_none()
        );
        let record: WalletRecord = storage::decode(
            rows.get(&storage::key(storage::WALLET, scheme, wallet))
                .unwrap(),
            2_000_000,
        )
        .unwrap();
        assert_eq!(record.next_load, 1);
    }
    for height in 6..=20 {
        chain.commit_at(height * 1_000, Vec::new());
    }
    {
        let view = chain.state().view();
        let source = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        assert_eq!(
            source
                .receipt_for(&memory.authority, &scheme, &wallet, &request)
                .unwrap(),
            original
        );
        assert!(matches!(
            source.receipt_for(&memory.authority, &scheme, &wallet, &[0x94; 32]),
            Err(Error::Unavailable)
        ));
        let rows = view.world.kagemusha_wallet_ledger();
        storage::validate_snapshot(rows.iter(), |key| rows.get(key).map(Vec::as_slice)).unwrap();
    }
    load_event_evidence_tests::check_retained_load_event(&chain, &memory, &original);
    // Local certificate availability cannot prevent receipt recovery. The returned DTO
    // remains data; the independent native finality verifier still owns proof admission.
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    {
        let view = chain.state().view();
        let source = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        assert_eq!(
            source
                .receipt_for(&memory.authority, &scheme, &wallet, &request)
                .unwrap(),
            original
        );
    }
    let key = storage::issuance_key(scheme, wallet, request);
    let retained: Issuance = {
        let view = chain.state().view();
        storage::decode(
            view.world.kagemusha_wallet_ledger().get(&key).unwrap(),
            2_000_000,
        )
        .unwrap()
    };
    // Malformed local recovery data cannot claim a missing or different committed input.
    for changed in 0..2 {
        let mut altered = retained.clone();
        if changed == 0 {
            altered.body.transaction_hash = *Hash::new(b"absent load transaction").as_ref();
        } else {
            altered.body.block_height += 1;
        }
        chain.setup_world_at(21_000, |tx| {
            tx.world
                .kagemusha_wallet_ledger
                .insert(key, storage::encode(&altered).unwrap());
        });
        let view = chain.state().view();
        let source = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        assert!(
            source
                .receipt_for(&memory.authority, &scheme, &wallet, &request)
                .is_err()
        );
    }
    let mut foreign = memory.registration.clone();
    foreign.scheme.network_id = *Hash::new(b"foreign receipt recovery network").as_ref();
    let foreign_scheme = foreign.scheme.scheme_id();
    let mut foreign_issue = retained.clone();
    foreign_issue.command.scheme = foreign_scheme;
    foreign_issue.body.scheme_id = foreign_scheme;
    chain.setup_world_at(21_000, |tx| {
        tx.world.kagemusha_wallet_ledger.insert(
            storage::key(
                storage::REGISTRATION,
                foreign_scheme,
                foreign.asset.asset_digest(),
            ),
            storage::encode(&foreign).unwrap(),
        );
        tx.world.kagemusha_wallet_ledger.insert(
            storage::issuance_key(foreign_scheme, wallet, request),
            storage::encode(&foreign_issue).unwrap(),
        );
    });
    let view = chain.state().view();
    let source = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
    assert!(matches!(
        source.receipt_for(&memory.authority, &foreign_scheme, &wallet, &request),
        Err(Error::Binding)
    ));
}
