//! This module contains [`Nft`] instructions and queries implementations.
use super::prelude::*;
use iroha_telemetry::metrics;
/// ISI module contains all instructions related to NFTs:
/// - register/unregister NFT
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use super::*;
    use crate::smartcontracts::isi::account_admission::ensure_receiving_account;
    use iroha_data_model::{
        IntoKeyValue, isi::error::RepetitionError, permission::Permission, query::error::FindError,
    };
    use iroha_telemetry::metrics;
    fn is_permission_nft_associated(permission: &Permission, nft_id: &NftId) -> bool {
        if let Ok(permission) =
            iroha_executor_data_model::permission::nft::CanUnregisterNft::try_from(permission)
        {
            return &permission.nft == nft_id;
        }
        if let Ok(permission) =
            iroha_executor_data_model::permission::nft::CanTransferNft::try_from(permission)
        {
            return &permission.nft == nft_id;
        }
        if let Ok(permission) =
            iroha_executor_data_model::permission::nft::CanModifyNftMetadata::try_from(permission)
        {
            return &permission.nft == nft_id;
        }
        false
    }
    pub(crate) fn remove_nft_associated_permissions(
        state_transaction: &mut StateTransaction<'_, '_>,
        nft_id: &NftId,
    ) {
        let account_ids: Vec<AccountId> = state_transaction
            .world
            .account_permissions
            .iter()
            .map(|(holder, _)| holder.clone())
            .collect();
        for holder in account_ids {
            let should_remove = state_transaction
                .world
                .account_permissions
                .get(&holder)
                .is_some_and(|permissions| {
                    permissions
                        .iter()
                        .any(|permission| is_permission_nft_associated(permission, nft_id))
                });
            if !should_remove {
                continue;
            }
            let remove_entry = if let Some(permissions) =
                state_transaction.world.account_permissions.get_mut(&holder)
            {
                permissions.retain(|permission| !is_permission_nft_associated(permission, nft_id));
                permissions.is_empty()
            } else {
                false
            };
            if remove_entry {
                state_transaction
                    .world
                    .account_permissions
                    .remove(holder.clone());
            }
            state_transaction.invalidate_permission_cache_for_account(&holder);
        }
        let role_ids: Vec<RoleId> = state_transaction
            .world
            .roles
            .iter()
            .map(|(role_id, _)| role_id.clone())
            .collect();
        for role_id in role_ids {
            let should_remove = state_transaction
                .world
                .roles
                .get(&role_id)
                .is_some_and(|role| {
                    role.permissions()
                        .any(|permission| is_permission_nft_associated(permission, nft_id))
                });
            if !should_remove {
                continue;
            }
            let impacted_accounts = state_transaction.accounts_with_role(&role_id);
            if let Some(role) = state_transaction.world.roles.get_mut(&role_id) {
                role.permissions
                    .retain(|permission| !is_permission_nft_associated(permission, nft_id));
                role.permission_epochs
                    .retain(|permission, _| role.permissions.contains(permission));
            }
            if !impacted_accounts.is_empty() {
                state_transaction.invalidate_permission_cache_for(impacted_accounts.iter());
            }
        }
    }
    impl Execute for Register<Nft> {
        #[metrics(+"register_nft")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let nft = self.object().clone().build(authority);
            crate::smartcontracts::limits::enforce_metadata_value_sizes(
                state_transaction,
                nft.content(),
            )?;
            let (nft_id, nft_value) = nft.clone().into_key_value();
            super::super::nft_custody::ensure_nft_unreserved(&state_transaction.world, &nft_id)?;
            super::super::nft_custody::ensure_nft_destination_unreserved(
                &state_transaction.world,
                authority,
            )?;
            if state_transaction.world.nft(&nft_id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::NftId(nft_id),
                }
                .into());
            }
            let _ = state_transaction.world.domain(nft_id.domain())?;
            state_transaction.world.insert_nft_entry(nft_id, nft_value);
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Nft(NftEvent::Created(nft))));
            Ok(())
        }
    }
    impl Execute for Unregister<Nft> {
        #[metrics(+"unregister_nft")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let nft_id = self.object().clone();
            super::super::nft_custody::ensure_nft_unreserved(&state_transaction.world, &nft_id)?;
            remove_nft_associated_permissions(state_transaction, &nft_id);
            state_transaction
                .world
                .remove_nft_entry(&nft_id)
                .ok_or_else(|| FindError::Nft(nft_id.clone()))?;
            let _ = state_transaction.world.domain(nft_id.domain())?;
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Nft(NftEvent::Deleted(nft_id))));
            Ok(())
        }
    }
    impl Execute for SetKeyValue<Nft> {
        #[metrics(+"set_nft_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let SetKeyValue {
                object: nft_id,
                key,
                value,
            } = self;
            super::super::nft_custody::ensure_nft_unreserved(&state_transaction.world, &nft_id)?;
            crate::smartcontracts::limits::enforce_json_size(
                state_transaction,
                &value,
                "max_metadata_value_bytes",
                crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
            )?;
            state_transaction
                .world
                .nft_mut(&nft_id)
                .map_err(Error::from)
                .map(|nft| nft.content.insert(key.clone(), value.clone()))?;
            state_transaction
                .world
                .emit_events(Some(NftEvent::MetadataInserted(MetadataChanged {
                    target: nft_id,
                    key,
                    value,
                })));
            Ok(())
        }
    }
    impl Execute for RemoveKeyValue<Nft> {
        #[metrics(+"remove_nft_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let nft_id = self.object().clone();
            super::super::nft_custody::ensure_nft_unreserved(&state_transaction.world, &nft_id)?;
            let value = state_transaction.world.nft_mut(&nft_id).and_then(|nft| {
                nft.content
                    .remove(self.key().as_ref())
                    .ok_or_else(|| FindError::MetadataKey(self.key().clone()))
            })?;
            state_transaction
                .world
                .emit_events(Some(NftEvent::MetadataRemoved(MetadataChanged {
                    target: nft_id,
                    key: self.key().clone(),
                    value,
                })));
            Ok(())
        }
    }
    // centralized in smartcontracts::limits
    impl Execute for Transfer<Account, NftId, Account> {
        #[metrics(+"transfer_nft")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let Transfer {
                source,
                object,
                destination,
            } = self;
            super::super::nft_custody::ensure_nft_unreserved(&state_transaction.world, &object)?;
            super::super::nft_custody::ensure_nft_destination_unreserved(
                &state_transaction.world,
                &destination,
            )?;
            state_transaction.world.account(&source)?;
            let _created =
                ensure_receiving_account(authority, &destination, None, state_transaction)?;
            let authority_is_source_owner = authority == &source;
            let authority_is_nft_domain_owner =
                state_transaction.world.domain(object.domain())?.owned_by() == authority;
            let required_permission: Permission =
                iroha_executor_data_model::permission::nft::CanTransferNft {
                    nft: object.clone(),
                }
                .into();
            let authority_has_transfer_permission = state_transaction
                .world
                .account_permissions_iter(authority)?
                .into_iter()
                .any(|permission| permission == &required_permission)
                || state_transaction
                    .world
                    .account_roles_iter(authority)
                    .any(|role_id| {
                        state_transaction
                            .world
                            .roles
                            .get(role_id)
                            .is_some_and(|role| {
                                role.permissions()
                                    .any(|permission| permission == &required_permission)
                            })
                    });
            if !(authority_is_source_owner
                || authority_is_nft_domain_owner
                || authority_has_transfer_permission)
            {
                return Err(Error::InvariantViolation(
                    "Can't transfer NFT of another account".to_owned().into(),
                ));
            }
            {
                let nft = state_transaction.world.nft_mut(&object)?;
                if nft.owned_by != source {
                    return Err(Error::InvariantViolation(
                        format!("Can't transfer NFT {object} since {source} doesn't own it",)
                            .into(),
                    ));
                }
                nft.owned_by = destination.clone();
            }
            state_transaction
                .world
                .replace_nft_owner_index(&object, &source, &destination);
            state_transaction
                .world
                .emit_events(Some(NftEvent::OwnerChanged(NftOwnerChanged {
                    nft: object,
                    new_owner: destination,
                })));
            Ok(())
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            block::ValidBlock,
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use core::num::NonZeroU64;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::{
            permission::Permission,
            query::error::FindError,
            role::{Role, RoleId},
        };
        use iroha_model_base::domain::DomainId;
        use iroha_model_base::metadata::Metadata;
        use iroha_test_samples::ALICE_ID;
        fn checked_keypair() -> KeyPair {
            KeyPair::try_random().expect("NFT ISI fixture key generation should succeed")
        }
        fn checked_account_id() -> AccountId {
            AccountId::new(checked_keypair().public_key().clone())
        }
        #[test]
        fn checked_keypair_preserves_default_algorithm() {
            assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        }
        fn new_dummy_block() -> crate::block::CommittedBlock {
            let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
            let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
            let topology = crate::sumeragi::network_topology::Topology::new(vec![peer_id]);
            ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
                h.set_height(NonZeroU64::new(1).unwrap());
            })
            .commit(&topology, crate::block::reserve_block_for_tests())
            .unpack(|_| {})
            .unwrap()
        }
        #[test]
        fn register_nft_rejects_missing_domain() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let nft_id: NftId = "nft1$wonderland.universal".parse().unwrap();
            let err = Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
                .execute(&ALICE_ID, &mut stx)
                .expect_err("missing domain should be rejected");
            assert!(
                matches!(err, Error::Find(FindError::Domain(ref id)) if id == nft_id.domain()),
                "expected missing-domain error, got {err:?}"
            );
        }
        #[test]
        fn unregister_nft_rejects_missing_domain() {
            let mut world = World::default();
            let nft_id: NftId = "nft1$wonderland.universal".parse().unwrap();
            let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&ALICE_ID);
            let (id, value) = nft.into_key_value();
            world.nfts.insert(id, value);
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(world, kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let err = Unregister::nft(nft_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("missing domain should be rejected");
            assert!(
                matches!(err, Error::Find(FindError::Domain(ref id)) if id == nft_id.domain()),
                "expected missing-domain error, got {err:?}"
            );
        }
        #[test]
        fn unregister_nft_removes_associated_permissions_from_accounts_and_roles() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId =
                DomainId::try_new("nft-cleanup", "universal").expect("domain id");
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register domain");
            let holder_id = checked_account_id();
            Register::account(Account::new(holder_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register holder account");
            let nft_id: NftId = "cleanup$nft-cleanup.universal".parse().expect("nft id");
            Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register nft");
            let permission: Permission =
                iroha_executor_data_model::permission::nft::CanModifyNftMetadata {
                    nft: nft_id.clone(),
                }
                .into();
            Grant::account_permission(permission.clone(), holder_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("grant permission to holder");
            let role_id: RoleId = "NFT_CLEANUP".parse().expect("role id");
            Register::role(Role::new(role_id.clone(), holder_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register role");
            Grant::role_permission(permission.clone(), role_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("grant permission to role");
            assert!(
                stx.world
                    .account_permissions
                    .get(&holder_id)
                    .is_some_and(|perms| perms.contains(&permission)),
                "holder should have permission before unregister"
            );
            let role = stx.world.roles.get(&role_id).expect("role should exist");
            assert!(
                role.permissions().any(|perm| perm == &permission),
                "role should include permission before unregister"
            );
            Unregister::nft(nft_id.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("unregister nft");
            assert!(
                !stx.world
                    .account_permissions
                    .get(&holder_id)
                    .is_some_and(|perms| perms.contains(&permission)),
                "holder permission should be removed"
            );
            let role = stx.world.roles.get(&role_id).expect("role should exist");
            assert!(
                !role.permissions().any(|perm| perm == &permission),
                "role permission should be removed"
            );
            assert!(
                !role.permission_epochs().contains_key(&permission),
                "permission epoch should be pruned"
            );
        }
        #[test]
        fn transfer_nft_rejects_authority_without_ownership() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let users_domain: DomainId =
                DomainId::try_new("users", "universal").expect("domain id");
            let user1 = checked_account_id();
            let user2 = checked_account_id();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let alice_domain: DomainId =
                DomainId::try_new("wonderland", "universal").expect("domain id");
            Register::domain(Domain::new(alice_domain.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register alice domain");
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register alice account");
            Register::domain(Domain::new(users_domain.clone()))
                .execute(&user1, &mut stx)
                .expect("register users domain");
            Register::account(Account::new(user1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register user1 account");
            Register::account(Account::new(user2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register user2 account");
            let nft_id: NftId = "ticket$users.universal".parse().expect("nft id");
            Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
                .execute(&user1, &mut stx)
                .expect("register nft");
            let err = Transfer::nft(user1, nft_id.clone(), user2)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("authority without ownership must not transfer nft");
            let err_string = err.to_string();
            assert!(
                err_string.contains("Can't transfer NFT of another account"),
                "unexpected error: {err_string}"
            );
        }
        #[test]
        fn transfer_nft_allows_nft_domain_owner() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let users_domain: DomainId =
                DomainId::try_new("users", "universal").expect("domain id");
            let user1 = checked_account_id();
            let user2 = checked_account_id();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let alice_domain: DomainId =
                DomainId::try_new("wonderland", "universal").expect("domain id");
            Register::domain(Domain::new(alice_domain.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register alice domain");
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register alice account");
            Register::domain(Domain::new(users_domain.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register users domain");
            Register::account(Account::new(user1.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register user1 account");
            Register::account(Account::new(user2.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect("register user2 account");
            let nft_id: NftId = "ticket$users.universal".parse().expect("nft id");
            Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
                .execute(&user1, &mut stx)
                .expect("register nft");
            Transfer::nft(user1, nft_id.clone(), user2.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect("nft-domain owner should be allowed to transfer");
            let nft = stx.world.nft(&nft_id).expect("nft remains after transfer");
            assert_eq!(
                nft.owned_by, user2,
                "destination should own transferred nft"
            );
        }
    }
}
/// NFT-related query implementations.
pub mod query {
    use super::*;
    use crate::smartcontracts::isi::query::json_predicate::predicate_matches_with_aliases;
    use crate::{
        smartcontracts::{ValidQuery, ValidSingularQuery},
        state::{StateReadOnly, WorldReadOnly},
    };
    use eyre::Result;
    use iroha_data_model::{
        nft::NftEntry,
        query::{
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::QueryExecutionFail as Error,
            json::PredicateJson,
        },
    };
    use iroha_model_base::domain::DomainId;
    use norito::json::Value;
    use std::collections::BTreeSet;
    #[derive(Debug, Default)]
    struct NftPredicateView {
        ids: BTreeSet<NftId>,
        owners: BTreeSet<AccountId>,
        domains: BTreeSet<DomainId>,
    }
    impl NftPredicateView {
        fn from_predicate(predicate: &CompoundPredicate<Nft>) -> Self {
            let mut view = Self::default();
            let Some(raw) = predicate.json_payload() else {
                return view;
            };
            let Some(predicate) =
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution(raw)
            else {
                return view;
            };
            for condition in predicate.equals {
                view.push_field_value(&condition.field, &condition.value);
            }
            for membership in predicate.r#in {
                for value in membership.values {
                    view.push_field_value(&membership.field, &value);
                }
            }
            view
        }
        fn push_field_value(&mut self, field: &str, value: &Value) {
            let Value::String(raw) = value else {
                return;
            };
            match field {
                "id" | "nft" | "nft_id" => {
                    if let Ok(id) = raw.parse::<NftId>() {
                        self.ids.insert(id);
                    }
                }
                "owner" | "owned_by" | "account" | "account_id" => {
                    if let Ok(account_id) = AccountId::parse_encoded(raw) {
                        self.owners.insert(account_id.subject_id());
                    }
                }
                "domain" | "id.domain" | "nft.domain" => {
                    if let Some(domain_id) = DomainId::parse_fully_qualified(raw)
                        .ok()
                        .or_else(|| DomainId::try_new(raw, "universal").ok())
                    {
                        self.domains.insert(domain_id);
                    }
                }
                _ => {}
            }
        }
        fn plan(&self) -> NftQueryPlan {
            let mut ids = self.ids.iter().cloned().collect::<Vec<_>>();
            ids.sort();
            let mut owners = self.owners.iter().cloned().collect::<Vec<_>>();
            owners.sort();
            let mut domains = self.domains.iter().cloned().collect::<Vec<_>>();
            domains.sort();
            if !ids.is_empty() {
                return NftQueryPlan::Ids(ids);
            }
            if !owners.is_empty() {
                return NftQueryPlan::Owners(owners);
            }
            if !domains.is_empty() {
                return NftQueryPlan::Domains(domains);
            }
            NftQueryPlan::Full
        }
    }
    #[derive(Debug)]
    enum NftQueryPlan {
        Ids(Vec<NftId>),
        Owners(Vec<AccountId>),
        Domains(Vec<DomainId>),
        Full,
    }
    fn nft_from_entry(entry: NftEntry<'_>) -> Nft {
        let details = entry.value().clone().into_inner();
        Nft {
            id: entry.id().clone(),
            content: details.content,
            owned_by: details.owned_by,
        }
    }
    impl ValidSingularQuery for FindNftById {
        #[metrics(+"find_nft_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Nft, Error> {
            let entry = state_ro.world().nft(self.nft_id())?;
            let details = entry.value().as_ref();
            crate::smartcontracts::isi::query::own_singular_query_struct::<Nft, 3>(
                [entry.id(), &details.content, &details.owned_by],
                || Nft {
                    id: entry.id().clone(),
                    content: details.content.clone(),
                    owned_by: details.owned_by.clone(),
                },
            )
        }
    }
    fn nft_alias_values(nft: &Nft, field: &str) -> Vec<String> {
        match field {
            "id" | "nft" | "nft_id" => vec![nft.id().to_string()],
            "domain" | "id.domain" | "nft.domain" => vec![nft.id().domain().to_string()],
            "owner" | "owned_by" | "account" | "account_id" => vec![nft.owned_by().to_string()],
            _ => Vec::new(),
        }
    }
    fn predicate_matches_nft(predicate: &PredicateJson, nft: &Nft) -> bool {
        predicate_matches_with_aliases(predicate, nft, nft_alias_values)
    }
    impl ValidQuery for FindNfts {
        #[metrics(+"find_nfts")]
        fn execute(
            self,
            filter: CompoundPredicate<Nft>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Nft>, Error> {
            let world = state_ro.world();
            let predicate_view = NftPredicateView::from_predicate(&filter);
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let iter: Box<dyn Iterator<Item = Nft> + '_> = match predicate_view.plan() {
                NftQueryPlan::Ids(ids) => {
                    Box::new(world.nft_entries_by_ids_iter(ids).map(nft_from_entry))
                }
                NftQueryPlan::Owners(owners) => {
                    Box::new(owners.into_iter().flat_map(move |owner| {
                        let nft_ids = crate::state::range_bounds::index_members(
                            world.nfts_by_owner(),
                            &owner,
                        )
                        .cloned();
                        world.nft_entries_by_ids_iter(nft_ids).map(nft_from_entry)
                    }))
                }
                NftQueryPlan::Domains(domains) => {
                    Box::new(domains.into_iter().flat_map(move |domain| {
                        let nft_ids = world
                            .nfts_in_domain_iter(&domain)
                            .map(|entry| entry.id().clone())
                            .collect::<Vec<_>>();
                        world.nft_entries_by_ids_iter(nft_ids).map(nft_from_entry)
                    }))
                }
                NftQueryPlan::Full => Box::new(world.nfts_iter().map(nft_from_entry)),
            };
            Ok(iter.filter(move |nft| {
                if let Some(predicate) = predicate_json.as_ref() {
                    predicate_matches_nft(predicate, nft)
                } else {
                    filter.applies(nft)
                }
            }))
        }
    }
    impl ValidQuery for FindNftsByAccountId {
        #[metrics(+"find_nfts_by_account_id")]
        fn execute(
            self,
            filter: CompoundPredicate<Nft>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Nft>, Error> {
            use iroha_data_model::query::dsl::EvaluatePredicate;
            let account_id = self.account_id().clone();
            state_ro.world().account(&account_id)?;
            let world = state_ro.world();
            let nft_ids =
                crate::state::range_bounds::index_members(world.nfts_by_owner(), &account_id)
                    .cloned();
            let nfts = world
                .nft_entries_by_ids_iter(nft_ids)
                .filter_map(move |entry| {
                    let details = entry.value().clone().into_inner();
                    let nft = Nft {
                        id: entry.id().clone(),
                        content: details.content,
                        owned_by: details.owned_by,
                    };
                    filter.applies(&nft).then_some(nft)
                })
                .collect::<Vec<_>>();
            Ok(nfts.into_iter())
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            block::ValidBlock,
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World, WorldReadOnly},
        };
        use core::num::NonZeroU64;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::IntoKeyValue;
        use iroha_model_base::metadata::Metadata;
        use iroha_model_base::name::Name;
        use iroha_primitives::json::Json;
        use iroha_test_samples::ALICE_ID;
        fn checked_keypair() -> KeyPair {
            KeyPair::try_random().expect("NFT query fixture key generation should succeed")
        }
        #[test]
        fn checked_keypair_preserves_default_algorithm() {
            assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        }
        #[test]
        fn find_nft_by_id_returns_present_and_reports_missing() {
            use iroha_data_model::query::error::FindError;
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut state = State::new_for_testing(World::default(), kura, query_handle);
            let nft_id: NftId = "ticket$wonderland.universal".parse().expect("NFT id");
            let nft = Nft {
                id: nft_id.clone(),
                content: Metadata::default(),
                owned_by: ALICE_ID.clone(),
            };
            let (id, value) = nft.clone().into_key_value();
            state.world.nfts.insert(id, value);
            let view = state.view();
            assert_eq!(
                FindNftById::new(nft_id).execute(&view),
                Ok(nft),
                "the singular query must materialize the exact stored NFT",
            );
            let missing: NftId = "missing$wonderland.universal".parse().expect("NFT id");
            let error = FindNftById::new(missing.clone())
                .execute(&view)
                .expect_err("missing NFT must remain a query find error");
            assert!(
                matches!(&error, Error::Find(FindError::Nft(id)) if id == &missing),
                "unexpected missing-NFT error: {error:?}",
            );
        }
        fn new_dummy_block() -> crate::block::CommittedBlock {
            let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
            let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
            let topology = crate::sumeragi::network_topology::Topology::new(vec![peer_id]);
            ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
                h.set_height(NonZeroU64::new(1).unwrap());
            })
            .commit(&topology, crate::block::reserve_block_for_tests())
            .unpack(|_| {})
            .unwrap()
        }
        #[test]
        fn find_nfts_applies_predicate() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let nft1_id: NftId = "nft1$wonderland.universal".parse().unwrap();
            let nft2_id: NftId = "nft2$wonderland.universal".parse().unwrap();
            Register::nft(Nft::new(nft1_id.clone(), Metadata::default()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::nft(Nft::new(nft2_id.clone(), Metadata::default()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let rarity_key: Name = "rarity".parse().unwrap();
            SetKeyValue::nft(nft1_id.clone(), rarity_key.clone(), Json::from("rare"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            SetKeyValue::nft(nft2_id.clone(), rarity_key, Json::from("common"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Nft>::build(|p| p.equals("content.rarity", "rare"));
            let results: Vec<_> = FindNfts
                .execute(predicate, &view)
                .unwrap()
                .map(|nft| nft.id)
                .collect();
            assert_eq!(results, vec![nft1_id]);
        }
        #[test]
        fn find_nfts_filters_owner_with_owner_index() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut state = State::new_for_testing(World::default(), kura, query_handle);
            let users_domain = DomainId::try_new("users", "universal").unwrap();
            let (user1, _) = iroha_test_samples::gen_account_in("users");
            let (user2, _) = iroha_test_samples::gen_account_in("users");
            state.world.domains.insert(
                users_domain.clone(),
                Domain {
                    id: users_domain,
                    logo: None,
                    metadata: Metadata::default(),
                    owned_by: ALICE_ID.clone(),
                },
            );
            for account in [
                Account::new(user1.clone()).build(&user1),
                Account::new(user2.clone()).build(&user2),
            ] {
                let (account_id, account_value) = account.into_key_value();
                state.world.accounts.insert(account_id, account_value);
            }
            let nft1_id: NftId = "ticket1$users.universal".parse().expect("nft id");
            let nft2_id: NftId = "ticket2$users.universal".parse().expect("nft id");
            for nft in [
                Nft {
                    id: nft1_id.clone(),
                    content: Metadata::default(),
                    owned_by: user1.clone(),
                },
                Nft {
                    id: nft2_id.clone(),
                    content: Metadata::default(),
                    owned_by: user2.clone(),
                },
            ] {
                let (id, value) = nft.into_key_value();
                state.world.nfts.insert(id, value);
            }
            state
                .world
                .nfts_by_owner
                .insert((user1.clone(), nft1_id.clone()), ());
            state.world.nfts_by_owner.insert((user2, nft2_id), ());
            let view = state.view();
            assert_eq!(
                view.world()
                    .nfts_in_account_iter(&user1)
                    .map(|entry| entry.id().clone())
                    .collect::<Vec<_>>(),
                vec![nft1_id.clone()],
                "fixture should populate the owner index used by the query planner",
            );
            let predicate =
                CompoundPredicate::<Nft>::build(|p| p.equals("owner", user1.to_string()));
            let results: Vec<_> = FindNfts
                .execute(predicate, &view)
                .expect("query execution succeeds")
                .map(|nft| nft.id)
                .collect();
            assert_eq!(results, vec![nft1_id]);
        }
        #[test]
        fn find_nfts_filters_domain_with_domain_range() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut state = State::new_for_testing(World::default(), kura, query_handle);
            let tickets_domain = DomainId::try_new("tickets", "universal").expect("domain id");
            let badges_domain = DomainId::try_new("badges", "universal").expect("domain id");
            for domain_id in [tickets_domain.clone(), badges_domain.clone()] {
                state.world.domains.insert(
                    domain_id.clone(),
                    Domain {
                        id: domain_id,
                        logo: None,
                        metadata: Metadata::default(),
                        owned_by: ALICE_ID.clone(),
                    },
                );
            }
            let ticket_id: NftId = "concert$tickets.universal".parse().expect("nft id");
            let badge_id: NftId = "vip$badges.universal".parse().expect("nft id");
            for nft in [
                Nft {
                    id: ticket_id.clone(),
                    content: Metadata::default(),
                    owned_by: ALICE_ID.clone(),
                },
                Nft {
                    id: badge_id,
                    content: Metadata::default(),
                    owned_by: ALICE_ID.clone(),
                },
            ] {
                let (id, value) = nft.into_key_value();
                state.world.nfts.insert(id, value);
            }
            let view = state.view();
            assert_eq!(
                view.world()
                    .nfts_in_domain_iter(&tickets_domain)
                    .map(|entry| entry.id().clone())
                    .collect::<Vec<_>>(),
                vec![ticket_id.clone()],
                "fixture should populate the NFT id ordering used by the domain range",
            );
            let predicate =
                CompoundPredicate::<Nft>::build(|p| p.equals("domain", "tickets.universal"));
            let results: Vec<_> = FindNfts
                .execute(predicate, &view)
                .expect("query execution succeeds")
                .map(|nft| nft.id)
                .collect();
            assert_eq!(results, vec![ticket_id]);
        }
        #[test]
        fn find_nfts_by_account_id_limits_results_to_requested_owner() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut state = State::new_for_testing(World::default(), kura, query_handle);
            let alice_domain = DomainId::try_new("wonderland", "universal").expect("domain id");
            let users_domain = DomainId::try_new("users", "universal").unwrap();
            let (user1, _) = iroha_test_samples::gen_account_in("users");
            let (user2, _) = iroha_test_samples::gen_account_in("users");
            for (domain_id, owner) in [
                (alice_domain.clone(), ALICE_ID.clone()),
                (users_domain.clone(), ALICE_ID.clone()),
            ] {
                state.world.domains.insert(
                    domain_id.clone(),
                    Domain {
                        id: domain_id,
                        logo: None,
                        metadata: Metadata::default(),
                        owned_by: owner,
                    },
                );
            }
            for account in [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(user1.clone()).build(&user1),
                Account::new(user2.clone()).build(&user2),
            ] {
                let (account_id, account_value) = account.into_key_value();
                state.world.accounts.insert(account_id, account_value);
            }
            let nft1_id: NftId = "ticket1$users.universal".parse().expect("nft id");
            let nft2_id: NftId = "ticket2$users.universal".parse().expect("nft id");
            for nft in [
                Nft {
                    id: nft1_id.clone(),
                    content: Metadata::default(),
                    owned_by: user1.clone(),
                },
                Nft {
                    id: nft2_id.clone(),
                    content: Metadata::default(),
                    owned_by: user2.clone(),
                },
            ] {
                let (id, value) = nft.into_key_value();
                state.world.nfts.insert(id, value);
            }
            state
                .world
                .nfts_by_owner
                .insert((user1.clone(), nft1_id.clone()), ());
            state.world.nfts_by_owner.insert((user2, nft2_id), ());
            let view = state.view();
            let results: Vec<_> = FindNftsByAccountId::new(user1.clone())
                .execute(CompoundPredicate::PASS, &view)
                .expect("query execution succeeds")
                .map(|nft| nft.id)
                .collect();
            assert_eq!(results, vec![nft1_id]);
        }
        #[test]
        fn nft_owner_index_tracks_register_transfer_and_unregister() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("tickets", "universal").unwrap();
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let (user1, _) = iroha_test_samples::gen_account_in("users");
            let (user2, _) = iroha_test_samples::gen_account_in("users");
            for account_id in [&user1, &user2] {
                Register::account(Account::new(account_id.clone()))
                    .execute(&ALICE_ID, &mut stx)
                    .unwrap();
            }
            let nft_id: NftId = "ticket$tickets.universal".parse().unwrap();
            Register::nft(Nft::new(nft_id.clone(), Metadata::default()))
                .execute(&user1, &mut stx)
                .unwrap();
            let owned_by_user1 = stx
                .world
                .nfts_in_account_iter(&user1)
                .map(|nft| nft.id().clone())
                .collect::<Vec<_>>();
            assert_eq!(owned_by_user1, vec![nft_id.clone()]);
            assert!(
                stx.world.nfts_in_account_iter(&user2).next().is_none(),
                "register should not add the NFT to another owner bucket",
            );
            Transfer::nft(user1.clone(), nft_id.clone(), user2.clone())
                .execute(&user1, &mut stx)
                .unwrap();
            assert!(
                stx.world.nfts_in_account_iter(&user1).next().is_none(),
                "transfer should remove the NFT from the source owner bucket",
            );
            let owned_by_user2 = stx
                .world
                .nfts_in_account_iter(&user2)
                .map(|nft| nft.id().clone())
                .collect::<Vec<_>>();
            assert_eq!(owned_by_user2, vec![nft_id.clone()]);
            Unregister::nft(nft_id.clone())
                .execute(&user2, &mut stx)
                .unwrap();
            assert!(
                stx.world.nfts_in_account_iter(&user2).next().is_none(),
                "unregister should remove the NFT from the owner index",
            );
        }
    }
}
