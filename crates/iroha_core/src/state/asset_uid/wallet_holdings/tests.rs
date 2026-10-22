//! Staged native snapshot controls. UNCOMPILED/UNRUN until the composed candidate is admitted.
use super::*;
use crate::state::World;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    asset::{Asset, AssetDefinition, uid::AssetUidDailyWindowV1},
    escrow::{
        AssetEscrowRecord, ConditionalEscrowCondition, ConditionalEscrowConditionState,
        ConditionalEscrowOracleCondition, ConditionalEscrowPredicate, ConditionalEscrowValue,
        ConditionalEscrowWithinCondition, EscrowId,
    },
    prelude::Account,
};
use std::{
    collections::BTreeSet,
    num::{NonZeroU32, NonZeroU64},
};

struct Fixture {
    world: World,
    network: NetworkId,
    policy: AssetUidPolicyV1,
    wallet: AccountId,
    other: AccountId,
    records: Vec<AssetEscrowRecord>,
}
fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
impl Fixture {
    fn new() -> Self {
        let wallet = account(81);
        let other = account(82);
        let definition = iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes([
            0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0x48, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8,
            0xa8, 0xa8,
        ])
        .unwrap();
        let network =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed([6; 32])));
        let policy = AssetUidPolicyV1 {
            asset_definition_id: definition.clone(),
            uid: [7; 32],
            revision: 1,
            accounts: BTreeSet::from([wallet.clone(), other.clone()]),
            holding_limit: Some(100_u32.into()),
            daily_window: AssetUidDailyWindowV1::UtcDay,
            daily_spend_limit: Some(100_u32.into()),
            daily_outgoing_limit: Some(100_u32.into()),
        };
        let records: Vec<_> = (0..4)
            .map(|n| {
                let id = EscrowId::new(Hash::new([n]));
                let custody = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
                    &network,
                    &id,
                    &definition,
                );
                AssetEscrowRecord {
                    id,
                    seller: if n == 0 || n == 2 {
                        wallet.clone()
                    } else {
                        other.clone()
                    },
                    buyer: Some(if n == 0 || n == 2 {
                        other.clone()
                    } else {
                        wallet.clone()
                    }),
                    asset_definition: definition.clone(),
                    amount: 90_u32.into(),
                    custody,
                    status: AssetEscrowStatus::Locked,
                    kind: if n < 2 {
                        AssetEscrowKind::Conditional
                    } else {
                        AssetEscrowKind::Lock
                    },
                    remaining_amount: 80_u32.into(),
                    release_authority: None,
                    expires_at_ms: Some(2_000),
                    evidence_hashes: vec![],
                    conditions: if n < 2 {
                        vec![
                            ConditionalEscrowConditionState {
                                condition: ConditionalEscrowCondition::Within(
                                    ConditionalEscrowWithinCondition {
                                        id: "deadline".parse().unwrap(),
                                        duration_ms: NonZeroU64::new(1_000).unwrap(),
                                    },
                                ),
                                attestation: None,
                                satisfied_at_ms: None,
                            },
                            ConditionalEscrowConditionState {
                                condition: ConditionalEscrowCondition::Oracle(
                                    ConditionalEscrowOracleCondition {
                                        id: "approval".parse().unwrap(),
                                        attestor: other.clone(),
                                        predicate: ConditionalEscrowPredicate::Equals(
                                            ConditionalEscrowValue::Bool(true),
                                        ),
                                        sequence: NonZeroU32::new(1).unwrap(),
                                    },
                                ),
                                attestation: None,
                                satisfied_at_ms: None,
                            },
                        ]
                    } else {
                        vec![]
                    },
                    created_at_ms: 1_000,
                    accepted_at_ms: None,
                    payment_sent_at_ms: None,
                    disputed_at_ms: None,
                    closed_at_ms: None,
                    resolution: None,
                }
            })
            .collect();
        let members = std::iter::once(&wallet)
            .chain(std::iter::once(&other))
            .chain(records.iter().map(|r| &r.custody));
        let assets = [(&wallet, 11), (&other, 67)]
            .into_iter()
            .chain(
                records
                    .iter()
                    .enumerate()
                    .map(|(n, r)| (&r.custody, (n as u32 + 1) * 3)),
            )
            .map(|(a, n)| Asset::new(AssetId::new(definition.clone(), a.clone()), n));
        let world =
            World::with_assets(
                [],
                members.map(|a| Account::new(a.clone()).build(&wallet)),
                [AssetDefinition::numeric(
                    definition.clone(),
                    "DS",
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&wallet)],
                assets,
                [],
            );
        {
            let mut state = world.smart_contract_state.block();
            for a in &policy.accounts {
                state.insert(
                    binding_key(&policy.asset_definition_id, a),
                    norito::encode_canonical(&AssetUidBindingV1 {
                        asset_definition_id: policy.asset_definition_id.clone(),
                        account_id: a.clone(),
                        uid: policy.uid,
                    })
                    .unwrap(),
                );
            }
            state.commit();
        }
        let f = Self {
            world,
            network,
            policy,
            wallet,
            other,
            records,
        };
        for r in &f.records {
            f.insert(r.clone());
        }
        f
    }
    fn insert(&self, record: AssetEscrowRecord) {
        let mut escrows = self.world.asset_escrows.block();
        escrows.insert(record.id, record.clone());
        escrows.commit();
        let mut sellers = self.world.asset_escrows_by_seller.block();
        sellers.insert((record.seller.clone(), record.id), ());
        sellers.commit();
        let mut buyers = self.world.asset_escrows_by_buyer.block();
        if let Some(buyer) = record.buyer {
            buyers.insert((buyer, record.id), ());
        }
        buyers.commit();
    }
    fn read(&self, now: u64, maximum_work: usize) -> Result<AssetUidWalletHoldingsV1, Error> {
        let mut used = 0;
        collect(
            &self.world.view(),
            &self.network,
            &self.policy,
            &self.wallet,
            now,
            65_536,
            norito::DecodeLimits::new(524_288, 65_536, 524_288, 1_048_576, 64),
            || {
                used += 1;
                if used > maximum_work {
                    Err(Error::CapacityLimit)
                } else {
                    Ok(())
                }
            },
        )
    }
    fn balance(&self, account: &AccountId, scope: AssetBalanceScope, amount: Quantity) {
        let mut values = self.world.assets.block();
        let (key, value) = Asset::new(
            AssetId::with_scope(
                self.policy.asset_definition_id.clone(),
                account.clone(),
                scope,
            ),
            amount,
        )
        .into_key_value();
        values.insert(key, value);
        values.commit();
    }
}

#[test]
fn actual_custody_only_requested_wallet_not_uid_or_nominal_remaining() {
    let f = Fixture::new();
    let row = f.read(1_500, 100).unwrap();
    assert_eq!(row.account_id, f.wallet);
    assert_eq!(
        row.asset_id,
        AssetId::with_scope(
            f.policy.asset_definition_id.clone(),
            f.wallet.clone(),
            AssetBalanceScope::Global
        )
    );
    assert_eq!(row.spendable, 11_u32.into());
    assert_eq!(row.locked, 12_u32.into()); // actual 3 + 9, not nominal 80 + 80
    assert_eq!(row.total, 23_u32.into());
    assert_eq!(row.pending_incoming, 6_u32.into()); // conditional 6, not generic lock 12
    assert!(row.total < f.policy.holding_limit.clone().unwrap());
    assert_ne!(row.spendable, 78_u32.into()); // the other same-UID wallet is not exposed
}
#[test]
fn expiry_is_strict_for_pending_but_outgoing_custody_remains_until_refund() {
    let f = Fixture::new();
    assert_eq!(f.read(1_999, 100).unwrap().pending_incoming, 6_u32.into());
    for now in [2_000, 2_001, u64::MAX] {
        let row = f.read(now, 100).unwrap();
        assert_eq!(row.pending_incoming, Quantity::zero());
        assert_eq!(row.locked, 12_u32.into());
    }
}
#[test]
fn stored_effective_expiry_controls_pending_not_a_later_external_deadline() {
    let f = Fixture::new();
    let mut row = f.records[1].clone();
    // Native opening stores min(explicit, created + Within). An external 9000
    // deadline does not override this already-resolved 1500 native deadline.
    row.expires_at_ms = Some(1_500);
    if let ConditionalEscrowCondition::Within(window) = &mut row.conditions[0].condition {
        window.duration_ms = NonZeroU64::new(500).unwrap();
    } else {
        panic!("fixture window");
    }
    f.insert(row);
    assert_eq!(f.read(1_499, 100).unwrap().pending_incoming, 6_u32.into());
    assert_eq!(
        f.read(1_500, 100).unwrap().pending_incoming,
        Quantity::zero()
    );
}
#[test]
fn global_view_never_adds_dataspace_bucket_even_ds_zero() {
    let f = Fixture::new();
    for ds in [0, 7] {
        f.balance(
            &f.wallet,
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::new(ds)),
            999_u32.into(),
        );
        f.balance(
            &f.records[0].custody,
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::new(ds)),
            999_u32.into(),
        );
    }
    assert_eq!(f.read(1_500, 100).unwrap().total, 23_u32.into());
}
#[test]
fn restricted_definition_refuses_instead_of_guessing_wallet_scope() {
    let f = Fixture::new();
    let mut values = f.world.asset_definitions.block();
    values.insert(
        f.policy.asset_definition_id.clone(),
        AssetDefinition::numeric(
            f.policy.asset_definition_id.clone(),
            "DS",
            AssetBalancePolicy::DataspaceRestricted,
            None,
        )
        .build(&f.wallet),
    );
    values.commit();
    assert!(f.read(1_500, 100).is_err());
}
#[test]
fn missing_foreign_corrupt_and_nonreciprocal_membership_refuse() {
    for variant in 0..5 {
        let mut f = Fixture::new();
        let key = binding_key(&f.policy.asset_definition_id, &f.wallet);
        let mut values = f.world.smart_contract_state.block();
        match variant {
            0 => {
                values.remove(key);
            }
            1 => {
                values.insert(key, vec![0xff]);
            }
            2 => {
                values.insert(
                    key,
                    norito::encode_canonical(&AssetUidBindingV1 {
                        asset_definition_id: f.policy.asset_definition_id.clone(),
                        account_id: f.wallet.clone(),
                        uid: [9; 32],
                    })
                    .unwrap(),
                );
            }
            3 => {
                values.insert(
                    key,
                    norito::encode_canonical(&AssetUidBindingV1 {
                        asset_definition_id: f.policy.asset_definition_id.clone(),
                        account_id: f.other.clone(),
                        uid: f.policy.uid,
                    })
                    .unwrap(),
                );
            }
            _ => {
                f.policy.accounts.remove(&f.wallet);
            }
        }
        values.commit();
        assert!(f.read(1_500, 100).is_err(), "variant {variant}");
    }
}
#[test]
fn complete_scan_refuses_missing_seller_and_buyer_indexes() {
    for seller in [true, false] {
        let f = Fixture::new();
        if seller {
            let mut values = f.world.asset_escrows_by_seller.block();
            values.remove((f.wallet.clone(), f.records[0].id));
            values.commit();
        } else {
            let mut values = f.world.asset_escrows_by_buyer.block();
            values.remove((f.wallet.clone(), f.records[1].id));
            values.commit();
        }
        assert!(f.read(1_500, 100).is_err());
    }
}
#[test]
fn dangling_and_foreign_index_entries_refuse() {
    for dangling in [true, false] {
        let f = Fixture::new();
        let id = if dangling {
            EscrowId::new(Hash::new(b"absent"))
        } else {
            f.records[1].id
        };
        let mut values = f.world.asset_escrows_by_seller.block();
        values.insert((f.wallet.clone(), id), ());
        values.commit();
        assert!(f.read(1_500, 100).is_err());
    }
}
#[test]
fn budget_refusal_at_any_incomplete_scan_never_returns_partial_amounts() {
    let f = Fixture::new();
    let mut refused = 0;
    for budget in 0..100 {
        match f.read(1_500, budget) {
            Err(Error::CapacityLimit) => refused += 1,
            Ok(row) => {
                assert_eq!(row.total, 23_u32.into());
                assert!(refused >= 16);
                return;
            }
            Err(other) => panic!("unexpected refusal {other:?}"),
        }
    }
    panic!("bounded fixture must finish at a sufficient finite budget");
}
#[test]
fn terminal_records_do_not_count_and_missing_balance_is_real_zero() {
    let f = Fixture::new();
    let mut row = f.records[0].clone();
    row.status = AssetEscrowStatus::Expired;
    row.closed_at_ms = Some(2_000);
    f.insert(row);
    f.balance(&f.wallet, AssetBalanceScope::Global, Quantity::zero());
    let mut values = f.world.assets.block();
    values.remove(AssetId::new(
        f.policy.asset_definition_id.clone(),
        f.records[2].custody.clone(),
    ));
    values.commit();
    let row = f.read(2_000, 100).unwrap();
    assert_eq!(row.spendable, Quantity::zero());
    assert_eq!(row.locked, Quantity::zero());
    assert_eq!(row.total, Quantity::zero());
}
#[test]
fn noncanonical_custody_missing_account_and_invalid_active_state_refuse() {
    for variant in 0..4 {
        let f = Fixture::new();
        let mut row = f.records[0].clone();
        match variant {
            0 => {
                row.custody = f.other.clone();
            }
            1 => {
                let mut values = f.world.accounts.block();
                values.remove(row.custody.clone());
                values.commit();
            }
            2 => {
                row.closed_at_ms = Some(1_400);
            }
            _ => {
                row.status = AssetEscrowStatus::Accepted;
            }
        }
        f.insert(row);
        assert!(f.read(1_500, 100).is_err());
    }
}
#[test]
fn checked_total_overflow_is_refusal_not_saturation() {
    let f = Fixture::new();
    // Exact maximum positive signed 512-bit mantissa, constructed offline.
    let maximum: Quantity = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047".parse().unwrap();
    f.balance(&f.wallet, AssetBalanceScope::Global, maximum);
    assert!(matches!(f.read(1_500, 100), Err(Error::CapacityLimit)));
}
#[test]
fn current_amounts_ignore_holding_cap_without_clipping_or_hiding_overcap() {
    let mut f = Fixture::new();
    f.policy.holding_limit = Some(1_u32.into());
    assert_eq!(f.read(1_500, 100).unwrap().total, 23_u32.into());
}
#[test]
fn self_conditional_does_not_double_count_pending_in_total() {
    let f = Fixture::new();
    let mut row = f.records[1].clone();
    // Retain exact indexes after changing seller, as real native publication does.
    let mut values = f.world.asset_escrows_by_seller.block();
    values.remove((row.seller.clone(), row.id));
    values.commit();
    row.seller = f.wallet.clone();
    f.insert(row);
    let result = f.read(1_500, 100).unwrap();
    assert_eq!(result.locked, 18_u32.into());
    assert_eq!(result.pending_incoming, 6_u32.into());
    assert_eq!(result.total, 29_u32.into());
}
