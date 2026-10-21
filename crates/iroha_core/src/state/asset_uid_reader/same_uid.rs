//! Private equality of two exact native retail memberships; no UID or roster projection.
use super::*;
use crate::smartcontracts::isi::query::{QueryExecutionBudget, QueryExecutionStats};

fn row<T>(
    world: &impl WorldReadOnly,
    key: &StatePath,
    budget: QueryExecutionBudget,
    stats: &mut QueryExecutionStats,
) -> Result<T, AssetUidHoldingQuoteError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    stats.record_item(key, Some(budget))?;
    let bytes = world
        .smart_contract_state()
        .get(key)
        .ok_or_else(|| reject("same-UID read requires exact retained native state"))?;
    metered_decode(bytes, budget, stats)
}

fn retail_uid(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
    budget: QueryExecutionBudget,
    stats: &mut QueryExecutionStats,
) -> Result<[u8; 32], AssetUidHoldingQuoteError> {
    stats.record_item(account, Some(budget))?;
    world
        .account(account)
        .map_err(InstructionExecutionError::from)?;
    // Even revoked institutional rows retain their category. This reader never
    // interprets an absent UID as a shared zero/default UID or an exemption.
    for key in [
        crate::state::asset_fi::fi_key(definition, account),
        crate::state::asset_uid_enrollment::system_key(definition, account),
    ] {
        stats.record_item(&key, Some(budget))?;
        if world.smart_contract_state().get(&key).is_some() {
            return Err(reject("same-UID read requires exclusively retail membership").into());
        }
    }
    let binding: AssetUidBindingV1 = row(
        world,
        &crate::state::asset_uid::binding_key(definition, account),
        budget,
        stats,
    )?;
    if binding.asset_definition_id != *definition
        || binding.account_id != *account
        || binding.uid == [0; 32]
    {
        return Err(reject("same-UID binding differs from its exact native key").into());
    }
    let policy: AssetUidPolicyV1 = row(
        world,
        &crate::state::asset_uid::policy_key(definition, &binding.uid),
        budget,
        stats,
    )?;
    policy.validate_shape().map_err(reject)?;
    if policy.asset_definition_id != *definition
        || policy.uid != binding.uid
        || !policy.accounts.contains(account)
    {
        return Err(reject("same-UID policy differs from native membership").into());
    }
    Ok(binding.uid)
}

/// Compare two current retail memberships only after exact runtime and owner-grant checks.
///
/// False means two valid retail identities differ. Unknown, institutional, corrupt or
/// ungranted operands are errors. Identity is retained after wallet closure; transfer
/// availability remains independently enforced by the native settlement kernel.
#[allow(clippy::too_many_arguments)]
pub(crate) fn same_uid_for_contract(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    context: &ContractRuntimeExecutionContext,
    definition: &AssetDefinitionId,
    source: &AccountId,
    destination: &AccountId,
    budget: QueryExecutionBudget,
) -> Result<(bool, QueryExecutionStats), AssetUidHoldingQuoteError> {
    let mut stats = QueryExecutionStats::default();
    stats.record_item(&context.contract_address, Some(budget))?;
    if !crate::executor::valid_contract_runtime_subject(world, authority, Some(context)) {
        return Err(reject("same-UID read requires its exact active contract runtime").into());
    }
    stats.record_item(definition, Some(budget))?;
    if world
        .asset_definition(definition)
        .map_err(InstructionExecutionError::from)?
        .balance_scope_policy()
        != iroha_data_model::asset::AssetBalancePolicy::Global
    {
        return Err(reject("same-UID read requires a Global asset").into());
    }
    let grant: AssetUidPolicyReaderV1 = row(
        world,
        &reader_key(definition, &context.contract_address),
        budget,
        &mut stats,
    )?;
    if grant.asset_definition_id != *definition
        || grant.controller != context.contract_address
        || grant.revision == 0
        || !grant.enabled
    {
        return Err(
            reject("same-UID read requires the current enabled asset-owner reader grant").into(),
        );
    }
    // Always validate both operands, including equal addresses. There is no
    // revision/cap comparison, equality shortcut, issuer alias or mirror fallback.
    let left = retail_uid(world, definition, source, budget, &mut stats)?;
    let right = retail_uid(world, definition, destination, budget, &mut stats)?;
    let equal = left == right;
    stats.record_response(&equal, Some(budget))?;
    Ok((equal, stats))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, StateTransaction, World},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        Registrable,
        asset::{AssetBalancePolicy, AssetDefinition, uid::AssetUidDailyWindowV1},
        prelude::{Account, BlockHeader, Domain},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use std::{collections::BTreeSet, num::NonZeroU64};
    pub(crate) struct Fixture {
        pub(crate) owner: AccountId,
        pub(crate) source: AccountId,
        pub(crate) destination: AccountId,
        pub(crate) foreign: AccountId,
        pub(crate) definition: AssetDefinitionId,
        pub(crate) context: ContractRuntimeExecutionContext,
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(
            KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }
    pub(crate) fn header() -> BlockHeader {
        BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 1_000, 0)
    }
    pub(crate) fn budget() -> QueryExecutionBudget {
        QueryExecutionBudget::from_weighted_limit(10_000_000, 7, 3)
    }
    impl Fixture {
        pub(crate) fn new() -> (Self, State) {
            let owner = account(41);
            let source = account(42);
            let destination = account(43);
            let foreign = account(44);
            let domain = DomainId::try_new("sameuid", "universal").unwrap();
            let definition =
                AssetDefinitionId::derive_from_components(domain.clone(), "ds".parse().unwrap());
            let world = World::with(
                [Domain::new(domain).build(&owner)],
                [&owner, &source, &destination, &foreign]
                    .into_iter()
                    .map(|a| Account::new(a.clone()).build(&owner)),
                [AssetDefinition::numeric(
                    definition.clone(),
                    "DS",
                    AssetBalancePolicy::Global,
                    None,
                )
                .build(&owner)],
            );
            {
                let mut parameters = world.parameters.block();
                parameters
                    .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                        iroha_data_model::block::consensus::SumeragiRootScope::Global,
                    ))
                    .unwrap();
                parameters.commit();
            }
            let state = State::new_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            let address =
                ContractAddress::derive(state.network_id_ref(), &owner, 29, DataSpaceId::UNIVERSAL)
                    .unwrap();
            let context = ContractRuntimeExecutionContext {
                contract_subject: address.subject_id(),
                contract_address: address,
                contract_alias: None,
                entrypoint: "same".into(),
            };
            (
                Self {
                    owner,
                    source,
                    destination,
                    foreign,
                    definition,
                    context,
                },
                state,
            )
        }
        pub(crate) fn grant(&self) -> AssetUidPolicyReaderV1 {
            AssetUidPolicyReaderV1 {
                asset_definition_id: self.definition.clone(),
                controller: self.context.contract_address.clone(),
                revision: 1,
                enabled: true,
            }
        }
        pub(crate) fn policy(
            &self,
            uid: [u8; 32],
            accounts: impl IntoIterator<Item = AccountId>,
        ) -> AssetUidPolicyV1 {
            AssetUidPolicyV1 {
                asset_definition_id: self.definition.clone(),
                uid,
                revision: 3,
                accounts: accounts.into_iter().collect::<BTreeSet<_>>(),
                holding_limit: Some(100_u32.into()),
                daily_spend_limit: Some(40_u32.into()),
                daily_outgoing_limit: None,
                daily_window: AssetUidDailyWindowV1::UtcDay,
            }
        }
        pub(crate) fn binding(&self, account: &AccountId, uid: [u8; 32]) -> AssetUidBindingV1 {
            AssetUidBindingV1 {
                asset_definition_id: self.definition.clone(),
                account_id: account.clone(),
                uid,
            }
        }
        pub(crate) fn put<T: norito::NoritoSerialize>(
            tx: &mut StateTransaction<'_, '_>,
            key: StatePath,
            value: &T,
        ) {
            tx.world
                .smart_contract_state
                .insert(key, norito::encode_canonical(value).unwrap());
        }
        // Direct native retained-row fixture; not signature or owner-admission qualification.
        pub(crate) fn install(&self, tx: &mut StateTransaction<'_, '_>) {
            tx.world.bind_active_contract_subject_for_testing(
                self.context.contract_address.clone(),
                Hash::new(b"sameuid-fixture"),
            );
            Self::put(
                tx,
                reader_key(&self.definition, &self.context.contract_address),
                &self.grant(),
            );
            Self::put(
                tx,
                crate::state::asset_uid::policy_key(&self.definition, &[7; 32]),
                &self.policy([7; 32], [self.source.clone(), self.destination.clone()]),
            );
            Self::put(
                tx,
                crate::state::asset_uid::policy_key(&self.definition, &[8; 32]),
                &self.policy([8; 32], [self.foreign.clone()]),
            );
            for (a, uid) in [
                (&self.source, [7; 32]),
                (&self.destination, [7; 32]),
                (&self.foreign, [8; 32]),
            ] {
                Self::put(
                    tx,
                    crate::state::asset_uid::binding_key(&self.definition, a),
                    &self.binding(a, uid),
                );
            }
        }
        pub(crate) fn read(
            &self,
            world: &impl WorldReadOnly,
            a: &AccountId,
            b: &AccountId,
        ) -> Result<(bool, QueryExecutionStats), AssetUidHoldingQuoteError> {
            same_uid_for_contract(
                world,
                &self.context.contract_subject,
                &self.context,
                &self.definition,
                a,
                b,
                budget(),
            )
        }
    }
    #[test]
    fn same_uid_compares_only_exact_native_identity_not_equal_revisions_caps_or_addresses() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        let before = tx
            .world
            .smart_contract_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        assert!(f.read(tx.world(), &f.source, &f.destination).unwrap().0);
        assert!(
            !f.read(tx.world(), &f.source, &f.foreign).unwrap().0,
            "same policy revision/caps do not imply same identity"
        );
        assert!(f.read(tx.world(), &f.source, &f.source).unwrap().0);
        assert!(
            f.read(tx.world(), &f.owner, &f.owner).is_err(),
            "same unbound address is not identity evidence"
        );
        assert_eq!(
            before,
            tx.world
                .smart_contract_state
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn same_uid_refuses_missing_corrupt_zero_foreign_or_removed_membership_and_policy() {
        for operand in 0..2 {
            for defect in 0..10 {
                let (f, state) = Fixture::new();
                let mut block = state.block(header());
                let mut tx = block.transaction();
                f.install(&mut tx);
                let a = if operand == 0 {
                    &f.source
                } else {
                    &f.destination
                };
                let bk = crate::state::asset_uid::binding_key(&f.definition, a);
                let pk = crate::state::asset_uid::policy_key(&f.definition, &[7; 32]);
                let other = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("sameuid", "universal").unwrap(),
                    "other".parse().unwrap(),
                );
                let mut binding = f.binding(a, [7; 32]);
                let mut policy = f.policy([7; 32], [f.source.clone(), f.destination.clone()]);
                match defect {
                    0 => {
                        tx.world.smart_contract_state.remove(bk.clone());
                    }
                    1 => {
                        tx.world
                            .smart_contract_state
                            .insert(bk.clone(), vec![0xff; 128]);
                    }
                    2 => {
                        binding.uid = [0; 32];
                        Fixture::put(&mut tx, bk.clone(), &binding);
                    }
                    3 => {
                        binding.account_id = f.foreign.clone();
                        Fixture::put(&mut tx, bk.clone(), &binding);
                    }
                    4 => {
                        binding.asset_definition_id = other.clone();
                        Fixture::put(&mut tx, bk.clone(), &binding);
                    }
                    5 => {
                        tx.world.smart_contract_state.remove(pk.clone());
                    }
                    6 => {
                        policy.accounts.remove(a);
                        Fixture::put(&mut tx, pk.clone(), &policy);
                    }
                    7 => {
                        policy.uid = [8; 32];
                        Fixture::put(&mut tx, pk.clone(), &policy);
                    }
                    8 => {
                        policy.asset_definition_id = other;
                        Fixture::put(&mut tx, pk.clone(), &policy);
                    }
                    9 => {
                        policy.revision = 0;
                        Fixture::put(&mut tx, pk.clone(), &policy);
                    }
                    _ => unreachable!(),
                }
                assert!(
                    f.read(tx.world(), &f.source, &f.destination).is_err(),
                    "operand {operand} defect {defect}"
                );
            }
        }
    }
    #[test]
    fn same_uid_refuses_revoked_foreign_missing_or_corrupt_reader_grant() {
        for defect in 0..6 {
            let (f, state) = Fixture::new();
            let mut block = state.block(header());
            let mut tx = block.transaction();
            f.install(&mut tx);
            let key = reader_key(&f.definition, &f.context.contract_address);
            let mut grant = f.grant();
            match defect {
                0 => {
                    tx.world.smart_contract_state.remove(key.clone());
                }
                1 => {
                    grant.enabled = false;
                    Fixture::put(&mut tx, key.clone(), &grant);
                }
                2 => {
                    grant.revision = 0;
                    Fixture::put(&mut tx, key.clone(), &grant);
                }
                3 => {
                    grant.controller = ContractAddress::derive(
                        state.network_id_ref(),
                        &f.owner,
                        30,
                        DataSpaceId::UNIVERSAL,
                    )
                    .unwrap();
                    Fixture::put(&mut tx, key.clone(), &grant);
                }
                4 => {
                    grant.asset_definition_id = AssetDefinitionId::derive_from_components(
                        DomainId::try_new("sameuid", "universal").unwrap(),
                        "other".parse().unwrap(),
                    );
                    Fixture::put(&mut tx, key.clone(), &grant);
                }
                5 => {
                    tx.world.smart_contract_state.insert(key, vec![0xff; 128]);
                }
                _ => unreachable!(),
            }
            assert!(
                f.read(tx.world(), &f.source, &f.destination).is_err(),
                "grant defect {defect}"
            );
        }
    }
    #[test]
    fn same_uid_requires_installed_frame_and_refuses_institutional_overlap_even_revoked() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        assert!(
            same_uid_for_contract(
                tx.world(),
                &f.owner,
                &f.context,
                &f.definition,
                &f.source,
                &f.destination,
                budget()
            )
            .is_err()
        );
        let mut forged = f.context.clone();
        forged.contract_subject = f.owner.clone();
        assert!(
            same_uid_for_contract(
                tx.world(),
                &f.owner,
                &forged,
                &f.definition,
                &f.source,
                &f.destination,
                budget()
            )
            .is_err()
        );
        for account in [&f.source, &f.destination] {
            for key in [
                crate::state::asset_fi::fi_key(&f.definition, account),
                crate::state::asset_uid_enrollment::system_key(&f.definition, account),
            ] {
                // Existence already precludes exclusive retail status; corrupt and revoked
                // institutional rows cannot be interpreted as absence or a zero UID.
                tx.world
                    .smart_contract_state
                    .insert(key.clone(), vec![0xff]);
                assert!(f.read(tx.world(), &f.source, &f.destination).is_err());
                tx.world.smart_contract_state.remove(key);
            }
        }
        tx.world
            .contract_instances
            .remove(f.context.contract_address.clone());
        assert!(f.read(tx.world(), &f.source, &f.destination).is_err());
    }
    #[test]
    fn same_uid_bounds_source_before_decode_and_rejects_noncanonical_trailing_bytes() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        let key = crate::state::asset_uid::binding_key(&f.definition, &f.source);
        tx.world
            .smart_contract_state
            .insert(key.clone(), vec![0xff; 32768]);
        let mut stats = QueryExecutionStats::default();
        let error = row::<AssetUidBindingV1>(
            tx.world(),
            &key,
            QueryExecutionBudget::from_weighted_limit(512, 7, 3),
            &mut stats,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AssetUidHoldingQuoteError::Query(QueryExecutionFail::GasBudgetExceeded)
        ));
        assert!(stats.processed_bytes() < 32768);
        let mut bytes = norito::encode_canonical(&f.binding(&f.source, [7; 32])).unwrap();
        bytes.push(0);
        tx.world.smart_contract_state.insert(key, bytes);
        assert!(f.read(tx.world(), &f.source, &f.destination).is_err());
        assert!(
            same_uid_for_contract(
                tx.world(),
                &f.context.contract_subject,
                &f.context,
                &f.definition,
                &f.source,
                &f.destination,
                QueryExecutionBudget::from_weighted_limit(0, 7, 3)
            )
            .is_err()
        );
    }
    #[test]
    fn same_uid_refuses_actual_enabled_and_revoked_fi_system_classifications() {
        use iroha_data_model::asset::{
            fi_link::AssetFiV1, uid_enrollment::AssetUidSystemAccountV1,
        };
        for enabled in [true, false] {
            for operand in 0..2 {
                for system in [true, false] {
                    let (f, state) = Fixture::new();
                    let mut block = state.block(header());
                    let mut tx = block.transaction();
                    f.install(&mut tx);
                    let a = if operand == 0 {
                        &f.source
                    } else {
                        &f.destination
                    };
                    if system {
                        Fixture::put(
                            &mut tx,
                            crate::state::asset_uid_enrollment::system_key(&f.definition, a),
                            &AssetUidSystemAccountV1 {
                                asset_definition_id: f.definition.clone(),
                                account_id: a.clone(),
                                revision: 1,
                                enabled,
                            },
                        );
                    } else {
                        Fixture::put(
                            &mut tx,
                            crate::state::asset_fi::fi_key(&f.definition, a),
                            &AssetFiV1 {
                                asset_definition_id: f.definition.clone(),
                                fi_account_id: a.clone(),
                                revision: 1,
                                enabled,
                            },
                        );
                    }
                    assert!(f.read(tx.world(), &f.source, &f.destination).is_err());
                    // Removing retail state never makes a system-only input a false result.
                    tx.world
                        .smart_contract_state
                        .remove(crate::state::asset_uid::binding_key(&f.definition, a));
                    assert!(f.read(tx.world(), &f.source, &f.destination).is_err());
                }
            }
        }
    }
}
