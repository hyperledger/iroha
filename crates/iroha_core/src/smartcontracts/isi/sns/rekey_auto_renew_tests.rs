//! Signed multisig rekey and exact-owner auto-renew lifecycle regressions.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU64},
};

use crate::{
    state::{World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountAddress, AccountId, MultisigMember, MultisigPolicy},
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasAutoRenewConfigV1, AliasAutoRenewStateV1, AliasIntentV1, AliasLeaseAcquisitionV1,
        AliasLifecyclePlanDispositionV1, AliasQuoteGuardV1, AliasTargetV1, ResolvedAccountAliasV1,
        ResolvedDataSpaceV1,
    },
    asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    domain::Domain,
    isi::{
        AddSignatory, InstructionBox, Transfer,
        alias_setup::{ConfigureAliasAutoRenew, EnsureAlias},
    },
    nexus::DataSpaceCatalog,
    permission::Permission,
    sns::{NameControllerV1, NameRecordV1},
};
use iroha_executor_data_model::{
    isi::multisig::{MultisigApprove, MultisigPropose, MultisigRegister, MultisigSpec},
    permission::account::{AccountAliasPermissionScope, CanManageAccountAlias},
};
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::codec::{Decode, Encode};

struct RekeyFixture {
    chain: CertifiedTestChain,
    signer: KeyPair,
    admin_key: KeyPair,
    collector: AccountId,
    payment: AssetDefinitionId,
    old_owner: AccountId,
    current_owner: AccountId,
    target: AliasTargetV1,
    configured: AliasAutoRenewStateV1,
}

impl RekeyFixture {
    fn multisig_apply(&mut self, account: AccountId, instruction: InstructionBox) -> bool {
        let instructions = vec![instruction];
        let hash = HashOf::new(&instructions);
        let time = 1_000 + self.chain.height() * 10;
        let proposal = self.chain.sign(
            &self.signer,
            [MultisigPropose::new(account.clone(), instructions, None).into()],
            time,
        );
        assert_eq!(
            self.chain.commit(vec![proposal]),
            vec![true],
            "original signed proposal"
        );
        let approval = self.chain.sign(
            &self.signer,
            [MultisigApprove::new(account, hash).into()],
            time + 1,
        );
        let result = self.chain.commit(vec![approval]);
        assert_eq!(result.len(), 1);
        result[0]
    }

    fn stored(&self) -> AliasAutoRenewStateV1 {
        crate::sns::alias_auto_renew_state(self.chain.state().view().world(), &self.target)
            .unwrap()
            .unwrap()
    }

    fn retained(&self) -> Vec<(AccountId, AccountId, AssetDefinitionId)> {
        let view = self.chain.state().view();
        let mut obligations = Vec::new();
        // Inspect the actual canonical persisted corpus; the retired production visitor
        // is not an independent authority for this fixture's retained obligations.
        for (key, bytes) in view.world().smart_contract_state().iter() {
            if !key.as_ref().starts_with("sns/auto_renew/") {
                continue;
            }
            let mut cursor = bytes.as_slice();
            let state = AliasAutoRenewStateV1::decode(&mut cursor).unwrap();
            assert!(cursor.is_empty());
            assert_eq!(state.version, AliasAutoRenewStateV1::VERSION);
            assert_eq!(
                crate::sns::alias_auto_renew_storage_key(&state.target).unwrap(),
                *key
            );
            let Some(config) = state.config else { continue };
            let selector =
                crate::alias_setup::selector_for_resolved_alias_target(&state.target).unwrap();
            let policy = crate::sns::policy_by_id(view.world(), selector.suffix_id)
                .unwrap()
                .unwrap();
            obligations.push((
                state.owner,
                policy.fund_splitter_account,
                config.payment_asset,
            ));
        }
        obligations
    }

    fn balance(&self, owner: &AccountId) -> Quantity {
        self.chain
            .state()
            .view()
            .world()
            .asset(&AssetId::of(self.payment.clone(), owner.clone()))
            .map(|value| value.value().clone().into_inner())
            .unwrap_or_else(|_| Quantity::zero())
    }

    fn assert_original_rekey(&self) {
        let view = self.chain.state().view();
        assert!(view.world().accounts().get(&self.old_owner).is_none());
        assert!(view.world().accounts().get(&self.current_owner).is_some());
        let AliasTargetV1::AccountAlias(alias) = &self.target else {
            unreachable!()
        };
        assert_eq!(
            view.world().account_aliases().get(&alias.account_alias()),
            Some(&self.current_owner)
        );
        let continuity = view
            .world()
            .account_rekey_records()
            .get(&alias.account_alias())
            .unwrap();
        assert_eq!(continuity.active_account_id, self.current_owner);
        assert_eq!(
            continuity.previous_account_ids,
            vec![self.old_owner.clone()]
        );
        let selector =
            crate::alias_setup::selector_for_resolved_alias_target(&self.target).unwrap();
        let lease = crate::sns::record_by_selector(view.world(), &selector)
            .unwrap()
            .unwrap();
        assert_eq!(lease.owner, self.current_owner);
        assert_eq!(
            lease.controllers,
            vec![NameControllerV1::account(
                &AccountAddress::from_account_id(&self.current_owner).unwrap()
            )]
        );
        let configured = crate::sns::alias_auto_renew_state(view.world(), &self.target)
            .unwrap()
            .unwrap();
        assert_eq!(configured.owner, self.old_owner);
        assert_eq!(configured.config, self.configured.config);
    }
}

fn original_rekey_fixture() -> RekeyFixture {
    original_rekey_fixture_with_enabled(true)
}

fn original_rekey_fixture_with_enabled(enabled: bool) -> RekeyFixture {
    // The governance pool remains finite and separate from optional SNS Time work.
    let mut profile = iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap();
    profile.mandatory.max_retained_obligations = 1;
    original_rekey_fixture_with_source_policy(enabled, profile)
}

fn original_rekey_fixture_with_source_policy(
    enabled: bool,
    profile: iroha_data_model::parameter::FastpqSourcePolicyV1,
) -> RekeyFixture {
    let admin_key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
    let admin = AccountId::new(admin_key.public_key().clone());
    let collector = AccountId::new(
        KeyPair::from_seed(vec![0xD8; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let signer = KeyPair::from_seed(vec![0xD9; 32], Algorithm::Ed25519);
    let added = KeyPair::from_seed(vec![0xDA; 32], Algorithm::Ed25519);
    let signer_id = AccountId::new(signer.public_key().clone());
    let old_owner = AccountId::new_multisig(
        MultisigPolicy::new(
            1,
            vec![MultisigMember::new(signer.public_key().clone(), 1).unwrap()],
        )
        .unwrap(),
    );
    let current_owner = AccountId::new_multisig(
        MultisigPolicy::new(
            1,
            vec![
                MultisigMember::new(signer.public_key().clone(), 1).unwrap(),
                MultisigMember::new(added.public_key().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    let payment: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .unwrap();
    let mut world = World::with_assets(
        [Domain::new(DomainId::try_new("genesis", "universal").unwrap()).build(&collector)],
        [
            Account::new(admin.clone()).build(&admin),
            Account::new(collector.clone()).build(&collector),
            Account::new(signer_id.clone()).build(&signer_id),
        ],
        [AssetDefinition::numeric(
            payment.clone(),
            "Fixture fee",
            AssetBalancePolicy::Global,
            None,
        )
        .build(&admin)],
        [Asset::new(
            AssetId::of(payment.clone(), admin.clone()),
            Quantity::from(100_u32),
        )],
        [],
    );
    crate::sns::seed_default_namespace_policies(&mut world);
    let parent = AliasTargetV1::Dataspace(ResolvedDataSpaceV1::new(
        "universal".parse().unwrap(),
        DataSpaceId::UNIVERSAL,
    ));
    let selector = crate::alias_setup::selector_for_resolved_alias_target(&parent).unwrap();
    let record = NameRecordV1::new(
        selector.clone(),
        admin.clone(),
        vec![NameControllerV1::account(
            &AccountAddress::from_account_id(&admin).unwrap(),
        )],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        crate::alias_setup::alias_registration_metadata(&parent).unwrap(),
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), record.encode());
    world.account_permissions.insert(
        admin.clone(),
        BTreeSet::from([
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
            }),
            Permission::from(iroha_executor_data_model::permission::parameter::CanSetParameters),
        ]),
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_key = admin_key.clone();
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Block(
            iroha_data_model::parameter::BlockParameter::FastpqSource(profile),
        ));
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let spec = MultisigSpec::new(
        BTreeMap::from([(signer_id, 1)]),
        NonZeroU16::new(1).unwrap(),
        NonZeroU64::new(60_000).unwrap(),
    );
    let register = chain.sign(
        &signer,
        [MultisigRegister::new(old_owner.clone(), None, spec).into()],
        1_010,
    );
    assert_eq!(
        chain.commit(vec![register]),
        vec![true],
        "native multisig registration"
    );
    let alias = ResolvedAccountAliasV1::new(
        "renewal@universal".parse::<AccountAliasName>().unwrap(),
        DataSpaceId::UNIVERSAL,
    );
    let target = AliasTargetV1::AccountAlias(alias.clone());
    let selector = crate::alias_setup::selector_for_resolved_alias_target(&target).unwrap();
    let (quote, policy) = {
        let view = chain.state().view();
        (
            crate::sns::quote_resolved_name_registration(
                view.world(),
                selector,
                &old_owner,
                1,
                None,
                1_020,
            )
            .unwrap(),
            crate::sns::policy_by_id(view.world(), crate::sns::ACCOUNT_ALIAS_SUFFIX_ID)
                .unwrap()
                .unwrap(),
        )
    };
    let ensure = EnsureAlias::new(
        AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias,
            target_account: old_owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Primary,
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: policy.policy_version,
            expected_payment_asset: payment.clone(),
            max_amount: quote.charge_amount,
            valid_until_ms: 120_000,
        },
    );
    let signed = chain.sign(&admin_key, [ensure.into()], 1_020);
    let accepted = chain.commit(vec![signed]);
    assert_eq!(
        accepted,
        vec![true],
        "signed alias acquisition: {:?}",
        chain.committed(chain.height()).block().network_output_at(0)
    );
    let renewal = AliasAutoRenewConfigV1 {
        term_years: 1,
        policy_version: policy.policy_version,
        payment_asset: payment.clone(),
        max_amount: Quantity::one(),
        renew_before_expiry_ms: 1_000,
        retry_backoff_ms: 1,
        max_failures: 3,
    };
    let mut fixture = RekeyFixture {
        chain,
        signer,
        admin_key,
        collector,
        payment,
        old_owner,
        current_owner,
        target,
        configured: AliasAutoRenewStateV1::new(parent, admin, 0, None),
    };
    assert!(
        fixture.multisig_apply(
            fixture.old_owner.clone(),
            ConfigureAliasAutoRenew::new(fixture.target.clone(), 0, enabled.then_some(renewal))
                .into()
        ),
        "original signed configuration"
    );
    fixture.configured = fixture.stored();
    assert_eq!(fixture.configured.revision, 1);
    // No balance is moved by this legitimate assetless controller change. The
    // new owner can be funded afterward; no owner or lease record is edited here.
    assert!(
        fixture.multisig_apply(
            fixture.old_owner.clone(),
            AddSignatory::new(fixture.old_owner.clone(), added.public_key().clone()).into()
        ),
        "original signed rekey"
    );
    fixture.assert_original_rekey();
    fixture
}

#[test]
fn signed_rekey_current_owner_can_replace_stale_auto_renew_configuration() {
    let mut fixture = original_rekey_fixture();
    let original = fixture.stored();
    let applied = fixture.multisig_apply(
        fixture.current_owner.clone(),
        ConfigureAliasAutoRenew::new(
            fixture.target.clone(),
            original.revision,
            original.config.clone(),
        )
        .into(),
    );
    assert!(
        applied,
        "current lease owner must be able to replace the stale owner at exact revision; output: {:?}",
        fixture
            .chain
            .committed(fixture.chain.height())
            .block()
            .network_output_at(0)
    );
    let after = fixture.stored();
    assert_eq!(after.owner, fixture.current_owner);
    assert_eq!(after.revision, original.revision + 1);
    assert_eq!(after.config, original.config);
    assert_eq!(
        fixture.retained(),
        vec![(
            fixture.current_owner.clone(),
            fixture.collector.clone(),
            fixture.payment.clone()
        )]
    );
    let profile = fixture
        .chain
        .state()
        .view()
        .world()
        .parameters()
        .block()
        .fastpq_source();
    let mut expected_profile = iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap();
    expected_profile.mandatory.max_retained_obligations = 1;
    assert_eq!(profile, expected_profile);
    let admin = AccountId::new(fixture.admin_key.public_key().clone());
    assert!(fixture.balance(&fixture.current_owner).is_zero());
    let transfer = Transfer::asset_quantity(
        AssetId::of(fixture.payment.clone(), admin),
        Quantity::from(2_u32),
        fixture.current_owner.clone(),
    );
    let funding = fixture
        .chain
        .sign(&fixture.admin_key, [transfer.into()], 2_000);
    assert_eq!(
        fixture.chain.commit(vec![funding]),
        vec![true],
        "fund exact current account after rekey"
    );
    let (expiry, quote) = {
        let view = fixture.chain.state().view();
        let selector =
            crate::alias_setup::selector_for_resolved_alias_target(&fixture.target).unwrap();
        let lease = crate::sns::record_by_selector(view.world(), &selector)
            .unwrap()
            .unwrap();
        let expiry = lease.expires_at_ms;
        let quote = crate::sns::quote_resolved_name_renewal(
            view.world(),
            selector,
            expiry,
            expiry + iroha_data_model::alias_setup::ALIAS_LEASE_YEAR_MS,
            expiry - 1_000,
        )
        .unwrap();
        (expiry, quote)
    };
    let collector_before = fixture.balance(&fixture.collector);
    fixture.chain.commit_at(expiry - 1_000, Vec::new());
    assert_eq!(
        fixture.balance(&fixture.current_owner),
        Quantity::from(2_u32).try_sub(&quote.charge_amount).unwrap()
    );
    assert_eq!(
        fixture.balance(&fixture.collector),
        collector_before.checked_add(&quote.charge_amount).unwrap()
    );
    assert!(fixture.balance(&fixture.old_owner).is_zero());
    let renewed = fixture.stored();
    assert_eq!(renewed.owner, fixture.current_owner);
    assert_eq!(renewed.revision, after.revision + 1);
    assert_eq!(renewed.failure_count, 0);
    assert_eq!(renewed.suspended_reason, None);
    assert_eq!(renewed.next_retry_at_ms, None);
    {
        let view = fixture.chain.state().view();
        let selector =
            crate::alias_setup::selector_for_resolved_alias_target(&fixture.target).unwrap();
        assert_eq!(
            crate::sns::record_by_selector(view.world(), &selector)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            expiry + iroha_data_model::alias_setup::ALIAS_LEASE_YEAR_MS
        );
        assert_eq!(view.world().parameters().block().fastpq_source(), profile);
    }
    let charged = fixture.balance(&fixture.current_owner);
    fixture.chain.commit_at(expiry - 999, Vec::new());
    assert_eq!(
        fixture.balance(&fixture.current_owner),
        charged,
        "same renewal is not charged twice"
    );
    assert_eq!(fixture.stored(), renewed);
}

#[test]
fn signed_rekey_same_configuration_requires_owner_replacement_cas() {
    let fixture = original_rekey_fixture();
    let original = fixture.stored();
    let operation = ConfigureAliasAutoRenew::new(
        fixture.target.clone(),
        original.revision,
        original.config.clone(),
    );
    let view = fixture.chain.state().view();
    assert_eq!(
        crate::alias_setup::classify_alias_auto_renew(
            view.world(),
            &DataSpaceCatalog::default(),
            &fixture.current_owner,
            &operation,
            2_000
        )
        .expect("authenticated current owner may replace old ownership"),
        AliasLifecyclePlanDispositionV1::Apply
    );
    assert_eq!(
        fixture.stored(),
        original,
        "read-only planning cannot replace custody"
    );
}

#[test]
fn signed_rekey_disabled_clean_record_requires_exact_owner_revision() {
    let mut fixture = original_rekey_fixture_with_enabled(false);
    let original = fixture.stored();
    assert_eq!(original.config, None);
    assert_eq!(original.failure_count, 0);
    assert_eq!(original.suspended_reason, None);
    assert_eq!(original.next_retry_at_ms, None);
    assert!(fixture.retained().is_empty());
    let operation = ConfigureAliasAutoRenew::new(fixture.target.clone(), original.revision, None);
    {
        let view = fixture.chain.state().view();
        let catalog = DataSpaceCatalog::default();
        assert_eq!(
            crate::alias_setup::classify_alias_auto_renew(
                view.world(),
                &catalog,
                &fixture.current_owner,
                &operation,
                2_000
            )
            .unwrap(),
            AliasLifecyclePlanDispositionV1::Apply
        );
        let stale =
            ConfigureAliasAutoRenew::new(fixture.target.clone(), original.revision - 1, None);
        assert_eq!(
            crate::alias_setup::classify_alias_auto_renew(
                view.world(),
                &catalog,
                &fixture.current_owner,
                &stale,
                2_000
            )
            .unwrap_err()
            .code(),
            "alias.auto_renew.revision_conflict"
        );
        for authority in [
            &fixture.old_owner,
            &AccountId::new(fixture.signer.public_key().clone()),
        ] {
            assert_eq!(
                crate::alias_setup::classify_alias_auto_renew(
                    view.world(),
                    &catalog,
                    authority,
                    &operation,
                    2_000
                )
                .unwrap_err()
                .code(),
                "alias.auto_renew.owner_forbidden"
            );
        }
    }
    assert!(fixture.multisig_apply(fixture.current_owner.clone(), operation.clone().into()));
    let after = fixture.stored();
    assert_eq!(after.owner, fixture.current_owner);
    assert_eq!(after.revision, original.revision + 1);
    assert_eq!(after.config, None);
    assert!(fixture.retained().is_empty());
    let view = fixture.chain.state().view();
    assert_eq!(
        crate::alias_setup::classify_alias_auto_renew(
            view.world(),
            &DataSpaceCatalog::default(),
            &fixture.current_owner,
            &operation,
            2_000
        )
        .unwrap(),
        AliasLifecyclePlanDispositionV1::NoOp,
        "exact current-owner clean state keeps the existing idempotent planning contract"
    );
}

#[test]
fn signed_rekey_owner_can_disable_but_foreign_and_stale_requests_preserve_original() {
    let mut fixture = original_rekey_fixture();
    let original = fixture.stored();
    let retained = fixture.retained();
    assert_eq!(
        retained,
        vec![(
            fixture.old_owner.clone(),
            fixture.collector.clone(),
            fixture.payment.clone()
        )]
    );
    let policy = fixture
        .chain
        .state()
        .view()
        .world()
        .parameters()
        .block()
        .fastpq_source();
    // A real signature from the signatory's independent single-key account is
    // not a signature from the lease-owning multisig account.
    let foreign = fixture.chain.sign(
        &fixture.signer,
        [ConfigureAliasAutoRenew::new(fixture.target.clone(), original.revision, None).into()],
        2_000,
    );
    assert_eq!(fixture.chain.commit(vec![foreign]), vec![false]);
    assert_eq!(fixture.stored(), original);
    assert_eq!(fixture.retained(), retained);
    assert!(!fixture.multisig_apply(
        fixture.current_owner.clone(),
        ConfigureAliasAutoRenew::new(fixture.target.clone(), original.revision - 1, None).into()
    ));
    assert_eq!(fixture.stored(), original);
    assert_eq!(fixture.retained(), retained);
    assert!(fixture.multisig_apply(
        fixture.current_owner.clone(),
        ConfigureAliasAutoRenew::new(fixture.target.clone(), original.revision, None).into()
    ));
    let disabled = fixture.stored();
    assert_eq!(disabled.owner, fixture.current_owner);
    assert_eq!(disabled.revision, original.revision + 1);
    assert_eq!(disabled.config, None);
    assert_eq!(disabled.failure_count, 0);
    assert_eq!(disabled.suspended_reason, None);
    assert!(fixture.retained().is_empty());
    assert_eq!(
        fixture
            .chain
            .state()
            .view()
            .world()
            .parameters()
            .block()
            .fastpq_source(),
        policy
    );
}

#[test]
fn signed_rekey_larger_owner_cannot_exceed_committed_native_renewal_allowance() {
    use iroha_data_model::{
        block::{BlockHeader, builder::BlockBuilder},
        isi::Mint,
    };
    let prepare_current_owner = |fixture: &mut RekeyFixture| {
        let original = fixture.stored();
        assert!(
            fixture.multisig_apply(
                fixture.current_owner.clone(),
                ConfigureAliasAutoRenew::new(
                    fixture.target.clone(),
                    original.revision,
                    original.config.clone(),
                )
                .into(),
            )
        );
        let configured = fixture.stored();
        assert_eq!(configured.owner, fixture.current_owner);
        assert_eq!(configured.revision, original.revision + 1);
        assert_eq!(configured.config, original.config);
        assert!(
            norito::canonical_frame_len(&configured).unwrap()
                > norito::canonical_frame_len(&original).unwrap()
        );
        let funding = fixture.chain.sign(
            &fixture.admin_key,
            [Mint::asset_quantity(
                Quantity::from(2_u32),
                AssetId::of(fixture.payment.clone(), fixture.current_owner.clone()),
            )
            .into()],
            2_000,
        );
        assert_eq!(
            fixture.chain.commit(vec![funding]),
            vec![true],
            "signed original fee-asset issuer funding: {:?}",
            fixture
                .chain
                .committed(fixture.chain.height())
                .block()
                .network_output_at(0)
        );
        assert_eq!(
            fixture.balance(&fixture.current_owner),
            Quantity::from(2_u32)
        );
        configured
    };
    let due_source = |fixture: &RekeyFixture, configured: &AliasAutoRenewStateV1| {
        let view = fixture.chain.state().view();
        let selector =
            crate::alias_setup::selector_for_resolved_alias_target(&fixture.target).unwrap();
        let expiry = crate::sns::record_by_selector(view.world(), &selector)
            .unwrap()
            .unwrap()
            .expires_at_ms;
        BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(fixture.chain.height() + 1).unwrap(),
            view.latest_block_hash(),
            None,
            expiry - configured.config.as_ref().unwrap().renew_before_expiry_ms,
            0,
        ))
        .build_with_signature(0, fixture.admin_key.private_key())
    };
    // Measure one actual native renewal under the original finite policy. This
    // unpublished component contributes its byte count, never execution authority.
    let mut sizing = original_rekey_fixture();
    let configured = prepare_current_owner(&mut sizing);
    let source = due_source(&sizing, &configured);
    let (block, recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(sizing.chain.state(), &source);
    assert!(outputs.is_empty());
    let native_usage = block.native_maintenance_usage_for_testing();
    assert_eq!(native_usage.executed_entries, 1);
    assert_eq!(native_usage.transcripts, 1);
    assert_eq!(native_usage.deltas, 1);
    drop(block);
    drop(recording);
    assert_eq!(sizing.stored(), configured);
    assert_eq!(sizing.balance(&sizing.current_owner), Quantity::from(2_u32));
    let mut source_policy = sizing
        .chain
        .state()
        .view()
        .world()
        .parameters()
        .block()
        .fastpq_source();
    let input_limit = native_usage.input_transcript_bytes.checked_sub(1).unwrap();
    assert!(
        input_limit >= u64::try_from(norito::canonical_frame_len(&configured).unwrap()).unwrap()
    );
    source_policy.intrinsic.max_input_transcript_bytes = input_limit;
    source_policy
        .mandatory
        .per_obligation
        .max_input_transcript_bytes = input_limit;
    source_policy
        .validate(
            sizing
                .chain
                .state()
                .view()
                .world()
                .parameters()
                .block()
                .execution_output(),
        )
        .unwrap();
    drop(sizing);
    // Capacity is immutable after genesis. Start a real signed chain under the
    // measured finite quota, retaining paid acquisition, signed rekey and issuer funding.
    let mut fixture = original_rekey_fixture_with_source_policy(true, source_policy);
    let configured = prepare_current_owner(&mut fixture);
    let owner_before = fixture.balance(&fixture.current_owner);
    let collector_before = fixture.balance(&fixture.collector);
    assert_eq!(fixture.stored(), configured);
    assert_eq!(
        fixture
            .chain
            .state()
            .view()
            .world()
            .parameters()
            .block()
            .fastpq_source(),
        source_policy
    );
    assert_eq!(
        source_policy
            .native_maintenance_reservation()
            .unwrap()
            .max_executed_entries,
        source_policy.max_native_maintenance_invocations
    );

    let selector = crate::alias_setup::selector_for_resolved_alias_target(&fixture.target).unwrap();
    let expiry = crate::sns::record_by_selector(fixture.chain.state().view().world(), &selector)
        .unwrap()
        .unwrap()
        .expires_at_ms;
    let now = expiry - configured.config.as_ref().unwrap().renew_before_expiry_ms;
    let source = {
        let view = fixture.chain.state().view();
        BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(fixture.chain.height() + 1).unwrap(),
            view.latest_block_hash(),
            None,
            now,
            0,
        ))
        .build_with_signature(0, fixture.admin_key.private_key())
    };
    // This invokes the actual original Time producer. The source-only component
    // helper grants neither empty-block production nor publication authority.
    let (mut block, refused_recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(fixture.chain.state(), &source);
    assert!(outputs.is_empty());
    assert_eq!(
        block.native_maintenance_usage_for_testing(),
        crate::fastpq::source_reservation::SourceUsage::ZERO
    );
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    let balance = |owner: &AccountId| {
        block
            .world
            .asset(&AssetId::of(fixture.payment.clone(), owner.clone()))
            .map(|asset| asset.value().clone().into_inner())
            .unwrap_or_else(|_| Quantity::zero())
    };
    assert_eq!(balance(&fixture.current_owner), owner_before);
    assert_eq!(balance(&fixture.collector), collector_before);
    assert_eq!(balance(&fixture.old_owner), Quantity::zero());
    assert_eq!(
        crate::sns::record_by_selector(&block.world, &selector)
            .unwrap()
            .unwrap()
            .expires_at_ms,
        expiry
    );
    let retry = crate::sns::alias_auto_renew_state(&block.world, &fixture.target)
        .unwrap()
        .unwrap();
    assert_eq!(retry.owner, fixture.current_owner);
    assert_eq!(retry.config, configured.config);
    assert_eq!(retry.revision, configured.revision + 1);
    assert_eq!(retry.failure_count, 1);
    assert_eq!(
        retry.next_retry_at_ms,
        Some(now + configured.config.as_ref().unwrap().retry_backoff_ms)
    );
    assert_eq!(retry.suspended_reason, None);
    block
        .finalize_sns_owned_sources_for_testing(&source)
        .unwrap();
    assert!(
        block
            .fastpq_source_inventory()
            .unwrap()
            .unwrap()
            .entries()
            .is_empty()
    );
    drop(block);
    drop(refused_recording);
    // The component attempted no publication; authenticated committed bytes remain.
    assert_eq!(fixture.stored(), configured);
    assert_eq!(fixture.balance(&fixture.current_owner), owner_before);
    assert_eq!(fixture.balance(&fixture.collector), collector_before);
    assert!(fixture.multisig_apply(
        fixture.current_owner.clone(),
        ConfigureAliasAutoRenew::new(fixture.target.clone(), configured.revision, None).into()
    ));
    assert!(fixture.retained().is_empty());
    assert_eq!(fixture.balance(&fixture.current_owner), owner_before);
    assert_eq!(fixture.balance(&fixture.collector), collector_before);
    assert_eq!(
        fixture
            .chain
            .state()
            .view()
            .world()
            .parameters()
            .block()
            .fastpq_source(),
        source_policy
    );
}
