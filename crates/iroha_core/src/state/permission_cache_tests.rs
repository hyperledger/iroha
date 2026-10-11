use super::*;
use crate::{prelude::StateReadOnly, smartcontracts::Execute};
use iroha_data_model::{
    account::AccountId,
    isi::{Grant, Revoke},
    permission::Permission,
    prelude::{Account, Domain},
    role::{Role, RoleId},
    trigger::TriggerId,
};
use iroha_executor_data_model::permission::{
    account::{AccountAliasPermissionScope, CanManageAccountAlias},
    role::CanManageRoles,
    trigger::{CanExecuteTrigger, CanRegisterTrigger},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;
use std::collections::BTreeSet;
fn wonderland_domain_id() -> DomainId {
    DomainId::try_new("wonderland", "universal").expect("domain id")
}
fn new_wonderland_account(account_id: &AccountId) -> iroha_data_model::account::NewAccount {
    Account::new(account_id.clone())
}
#[test]
fn revoke_permission_invalidates_trigger_cache() {
    let (registrar, _) = gen_account_in("wonderland");
    let (owner, _) = gen_account_in("wonderland");
    let domain: Domain = Domain::new(wonderland_domain_id()).build(&registrar);
    let registrar_account = new_wonderland_account(&registrar).build(&registrar);
    let owner_account = new_wonderland_account(&owner).build(&registrar);
    let world = World::with([domain], [registrar_account, owner_account], []);
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(world, kura, query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let permission = CanRegisterTrigger {
        authority: owner.clone(),
    };
    Grant::account_permission(permission.clone(), registrar.clone())
        .execute(&registrar, &mut stx)
        .expect("grant trigger permission");
    assert!(
        stx.can_register_trigger_for(&registrar, &owner),
        "permission should allow trigger registration"
    );
    Revoke::account_permission(permission, registrar.clone())
        .execute(&registrar, &mut stx)
        .expect("revoke trigger permission");
    assert!(
        !stx.can_register_trigger_for(&registrar, &owner),
        "cache must be invalidated after revoke"
    );
}
#[test]
fn trigger_permission_payload_with_whitespace_is_rejected() {
    let raw_payload = "{  \"trigger\"  :   \"trigger_alpha\" }";
    Json::from_raw_json(raw_payload.to_owned())
        .expect_err("permission payload aliases must fail at the Json boundary");
}
#[test]
fn alias_valued_trigger_registration_permission_is_not_cached() {
    let mut summary = AccountPermissionSummary::default();
    let alias_valued = Permission::new(
        "CanRegisterTrigger".to_owned(),
        Json::from_raw_json(r#"{"authority":"customer@aliasbank.universal"}"#.to_owned())
            .expect("valid raw permission payload"),
    );

    summary.apply_grant(&alias_valued);

    assert!(
        summary.reg_trigger_authorities.is_empty(),
        "permission-cache hydration must not resolve an alias-valued authority"
    );
}
#[test]
fn permission_deserialization_rejects_alias_and_matches_canonical_payload() {
    let alias = r#"{
            "name": "CanManageAccountAlias",
            "payload": { "scope": { "scope": "dataspace", "value": 0 } }
        }"#;
    norito::json::from_str::<Permission>(alias)
        .expect_err("noncanonical nested Json payload must fail closed");
    let stored: Permission = norito::json::from_str(
        r#"{"name":"CanManageAccountAlias","payload":{"scope":{"scope":"dataspace","value":0}}}"#,
    )
    .expect("deserialize permission with canonical payload");
    let target = Permission::from(CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
    });
    let permissions = BTreeSet::from([stored]);
    assert!(
        permissions.contains(&target),
        "deserialized canonical permission should match the typed permission: stored={}, target={}",
        permissions
            .first()
            .expect("stored permission")
            .payload()
            .get(),
        target.payload().get(),
    );
}
#[test]
fn role_granted_trigger_permissions_cache_and_invalidate() {
    let (registrar, _) = gen_account_in("wonderland");
    let (owner, _) = gen_account_in("wonderland");
    let domain: Domain = Domain::new(wonderland_domain_id()).build(&registrar);
    let registrar_account = new_wonderland_account(&registrar).build(&registrar);
    let owner_account = new_wonderland_account(&owner).build(&registrar);
    let role_id: RoleId = "trigger_role".parse().unwrap();
    let trigger_id: TriggerId = "trigger_alpha".parse().unwrap();
    let role = Role::new(role_id.clone(), registrar.clone())
        .add_permission(CanRegisterTrigger {
            authority: owner.clone(),
        })
        .add_permission(CanExecuteTrigger {
            trigger: trigger_id.clone(),
        })
        .build(&registrar);
    let mut world = World::with([domain], [registrar_account, owner_account], []);
    assert!(world.roles.insert(role_id.clone(), role).is_none());
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(world, kura, query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    assert!(
        !stx.can_register_trigger_for(&registrar, &owner),
        "role permissions should not apply before membership"
    );
    assert!(
        !stx.can_execute_trigger_for(&registrar, &trigger_id),
        "role permissions should not apply before membership"
    );
    Grant::account_role(role_id.clone(), registrar.clone())
        .execute(&registrar, &mut stx)
        .expect("grant account role");
    assert!(
        stx.can_register_trigger_for(&registrar, &owner),
        "granting role should allow trigger registration"
    );
    assert!(
        stx.can_execute_trigger_for(&registrar, &trigger_id),
        "granting role should allow trigger execution"
    );
    // Cached value should remain true while role membership stays in place.
    assert!(stx.can_register_trigger_for(&registrar, &owner));
    assert!(stx.can_execute_trigger_for(&registrar, &trigger_id));
    Revoke::account_role(role_id, registrar.clone())
        .execute(&registrar, &mut stx)
        .expect("revoke account role");
    assert!(
        !stx.can_register_trigger_for(&registrar, &owner),
        "revoking role should invalidate cache and revoke registration permission"
    );
    assert!(
        !stx.can_execute_trigger_for(&registrar, &trigger_id),
        "revoking role should invalidate cache and revoke execution permission"
    );
}
fn assert_replayed_permission_cache(
    state: &State,
    registrar: &AccountId,
    owner: &AccountId,
    trigger_id: &TriggerId,
    expected: bool,
) {
    let parent = state
        .view()
        .latest_block()
        .expect("completed original State read")
        .expect("committed permission-cache parent");
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(parent.header().height().get() + 1).expect("next height"),
        Some(parent.hash()),
        None,
        u64::try_from(
            (parent.header().creation_time() + std::time::Duration::from_secs(1)).as_millis(),
        )
        .expect("logical time fits u64"),
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    assert!(
        stx.perm_cache.needs_hydration(registrar),
        "a fresh execution/restart must hydrate permissions from committed state"
    );
    assert_eq!(
        stx.can_register_trigger_for(registrar, owner),
        expected,
        "registration permission must reflect the authenticated block prefix"
    );
    assert_eq!(
        stx.can_execute_trigger_for(registrar, trigger_id),
        expected,
        "execution permission must reflect the authenticated block prefix"
    );
    let expected_count = usize::from(expected);
    let summary = stx.ensure_permission_summary(registrar);
    assert_eq!(summary.reg_trigger_authorities.len(), expected_count);
    assert_eq!(summary.exec_trigger_ids.len(), expected_count);
    assert!(
        !stx.perm_cache.needs_hydration(registrar),
        "the actual WSV summary must be cached"
    );
    assert_eq!(
        stx.can_register_trigger_for(registrar, owner),
        expected,
        "repeat registration cache hit"
    );
    assert_eq!(
        stx.can_execute_trigger_for(registrar, trigger_id),
        expected,
        "repeat execution cache hit"
    );
    assert_eq!(
        stx.ensure_permission_summary(registrar)
            .reg_trigger_authorities
            .len(),
        expected_count
    );
}
#[test]
fn permission_cache_rebuilds_after_restart() {
    // The full replay pipeline has deep debug-mode stack use; do not depend on libtest's
    // platform-default worker stack for this integration-heavy scenario.
    let handle = crate::sumeragi::threads::sumeragi_thread_builder(
        "permission_cache_rebuilds_after_restart",
    )
    .spawn(permission_cache_rebuilds_after_restart_impl)
    .expect("spawn permission cache replay test");
    if let Err(payload) = handle.join() {
        std::panic::resume_unwind(payload);
    }
}
#[allow(clippy::too_many_lines)]
fn permission_cache_rebuilds_after_restart_impl() {
    use iroha_data_model::isi::{InstructionBox, Log, Register};
    use iroha_data_model::{
        events::execute_trigger::ExecuteTriggerEventFilter,
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let (registrar, registrar_keypair) = gen_account_in("wonderland");
    let (owner, owner_keypair) = gen_account_in("wonderland");
    let trigger_id: TriggerId = "trigger_alpha".parse().expect("trigger id");
    let genesis_instructions = vec![
        InstructionBox::from(Register::domain(Domain::new(wonderland_domain_id()))),
        InstructionBox::from(Register::account(Account::new(AccountId::new(
            registrar_keypair.public_key().clone(),
        )))),
        InstructionBox::from(Register::account(Account::new(AccountId::new(
            owner_keypair.public_key().clone(),
        )))),
        InstructionBox::from(Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                vec![InstructionBox::from(Log::new(
                    iroha_logger::Level::INFO,
                    "permission cache trigger".to_owned(),
                ))],
                Repeats::Indefinitely,
                owner.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(owner.clone()),
            )
            .expect("canonical trigger action"),
        ))),
        InstructionBox::from(Grant::account_permission(CanManageRoles, owner.clone())),
    ];
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let config = || {
        let mut config = TestChainConfig::new(World::new(), 1000);
        config.genesis_instructions = genesis_instructions.clone();
        config
    };
    let mut fixture = CertifiedTestChain::start(config()).unwrap();
    let permission_register = CanRegisterTrigger {
        authority: owner.clone(),
    };
    let permission_execute = CanExecuteTrigger {
        trigger: trigger_id.clone(),
    };
    let role_id: RoleId = "trigger_role_restart".parse().expect("role id");
    let role = Role::new(role_id.clone(), owner.clone())
        .add_permission(permission_register.clone())
        .add_permission(permission_execute.clone());
    let rounds = [
        (
            "direct grant",
            true,
            vec![
                InstructionBox::from(Grant::account_permission(
                    permission_register.clone(),
                    registrar.clone(),
                )),
                InstructionBox::from(Grant::account_permission(
                    permission_execute.clone(),
                    registrar.clone(),
                )),
            ],
        ),
        (
            "direct revoke",
            false,
            vec![
                InstructionBox::from(Revoke::account_permission(
                    permission_register,
                    registrar.clone(),
                )),
                InstructionBox::from(Revoke::account_permission(
                    permission_execute,
                    registrar.clone(),
                )),
            ],
        ),
        (
            "role grant",
            true,
            vec![
                InstructionBox::from(Register::role(role)),
                InstructionBox::from(Grant::account_role(role_id.clone(), registrar.clone())),
            ],
        ),
        (
            "role revoke",
            false,
            vec![InstructionBox::from(Revoke::account_role(
                role_id,
                registrar.clone(),
            ))],
        ),
    ];
    assert_replayed_permission_cache(
        fixture.state().as_ref(),
        &registrar,
        &owner,
        &trigger_id,
        false,
    );
    for (label, expected, instructions) in rounds {
        let transaction = fixture.sign(&owner_keypair, instructions, (fixture.height() + 1) * 1000);
        assert_eq!(
            fixture.commit(vec![transaction]),
            vec![true],
            "{label} really executes"
        );
        assert_replayed_permission_cache(
            fixture.state().as_ref(),
            &registrar,
            &owner,
            &trigger_id,
            expected,
        );
        // A projection cannot install authenticated native history. Restart from
        // the original signed genesis and replay the exact certified carriers
        // into a fresh State whose permission summaries were never warmed.
        let live = fixture.state();
        let captured = crate::snapshot::CapturedStateSnapshot::capture(live).unwrap();
        let projected = super::deserialize::KuraSeed {
            execution_budget: live.ivm_execution_budget(),
            kura: Arc::clone(fixture.kura()),
            lane_manifests: live.lane_manifests.read().clone(),
            query_handle: crate::query::store::LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            telemetry: Default::default(),
        }
        .into_state_from_json_str_with_configured_nexus(captured.as_json(), live.nexus_snapshot());
        assert!(matches!(
            projected,
            Err(super::deserialize::StateRestoreError::NativeExecutionReplayRequired)
        ));
        let mut replayed =
            CertifiedTestChain::start(config()).expect("restart original permission genesis");
        replayed
            .replay_from(&fixture)
            .expect("replay every original certified permission carrier");
        let restarted = replayed.state().as_ref();
        assert_eq!(restarted.committed_height(), fixture.height() as usize);
        assert_eq!(
            restarted.latest_block_hash_fast(),
            live.latest_block_hash_fast()
        );
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&restarted).unwrap(),
            crate::snapshot::canonical_state_snapshot_hash(live).unwrap()
        );
        assert!(
            restarted.world_view().accounts().get(&registrar).is_some(),
            "registrar survives restart"
        );
        assert!(
            restarted.world_view().accounts().get(&owner).is_some(),
            "owner survives restart"
        );
        assert_replayed_permission_cache(&restarted, &registrar, &owner, &trigger_id, expected);
    }
}
