//! Genuine native Set/Register cuts; no synthesized result, current proof or service authority.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{Asset, AssetBalancePolicy, AssetDefinition},
    domain::Domain,
    isi::{
        Log,
        sorafs::{RegisterSorafsReserveAccount, SetSorafsReservePolicy, UpsertProviderCredit},
    },
    sorafs::capacity::ProviderId,
    sorafs::reserve::{
        RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReserveDuration,
        ReservePolicyV1, ReserveProviderTermsV1, ReserveTier,
        account_proof::{
            ReserveAccountProofExpectedV1, ReserveAccountProofRefV1, ReserveAccountProofV1,
        },
        history::reserve_policy_permission,
    },
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_model_base::domain::DomainId;
use sorafs_manifest::deal::XorQuantity;
use std::{cell::Cell, collections::BTreeSet};

struct Fixture {
    chain: CertifiedTestChain,
    key: KeyPair,
    manager: AccountId,
    policy: ReserveAuthorityPolicyV1,
    owner: AccountId,
    provider: ProviderId,
}

#[test]
fn reserve_account_projection_authenticates_native_absence_and_registration() {
    let mut f = Fixture::new();
    f.publish_policy();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let absent = f.proof(&budget);
    assert!(
        absent
            .verify(&f.expected(), &f.verified_tip())
            .unwrap()
            .current()
            .is_none()
    );
    f.register();
    let proof = f.proof(&budget);
    let tip = f.verified_tip();
    let verified = proof.verify(&f.expected(), &tip).unwrap();
    let row = verified.current().unwrap();
    assert_eq!(row.terms.provider_id, f.provider);
    assert_eq!(row.terms.provider_account, f.owner);
    assert_eq!(row.revision, 1);
    assert!(row.reserve_balance.is_zero());
    assert!(row.debt_principal.is_zero());
    assert!(absent.verify(&f.expected(), &tip).is_err());
    let mut hidden = proof;
    hidden.current = None;
    assert!(hidden.verify(&f.expected(), &tip).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_account_projection_preserves_old_partition_policy_after_native_rotation() {
    let mut f = Fixture::new();
    f.publish_policy();
    f.register();
    let old_digest = f.policy.digest().unwrap();
    f.policy.revision = 2;
    f.policy.predecessor_policy_digest = Some(old_digest);
    f.policy.grace_period_days += 1;
    let signed = f.chain.sign(
        &f.key,
        [SetSorafsReservePolicy::new(f.policy.clone()).into()],
        5_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let proof = f.proof(&budget);
    let verified = proof.verify(&f.expected(), &f.verified_tip()).unwrap();
    assert_eq!(verified.policy().policy, f.policy);
    assert_eq!(verified.current().unwrap().policy_digest, old_digest);
    assert_ne!(verified.policy().policy_digest, old_digest);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_account_projection_refuses_missing_policy_wrong_operator_and_unfunded_reads() {
    let mut f = Fixture::new();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let called = Cell::new(false);
    let result = f.chain.state().with_native_reserve_account_snapshot_v1(
        &f.chain.committed(f.chain.height()),
        &f.manager,
        f.provider,
        &budget,
        |_, _, _, _, _, _, _| {
            called.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!called.get());
    f.publish_policy();
    let tip = f.chain.committed(f.chain.height());
    for (operator, provider, bytes) in [
        (&f.owner, f.provider, 64 * 1024 * 1024),
        (&f.manager, ProviderId::new([0; 32]), 64 * 1024 * 1024),
        (&f.manager, ProviderId::new([0xe5; 32]), 64 * 1024 * 1024),
        (&f.manager, f.provider, 0),
    ] {
        let budget = AllocationBudget::new(bytes);
        assert!(
            f.chain
                .state()
                .with_native_reserve_account_snapshot_v1(
                    &tip,
                    operator,
                    provider,
                    &budget,
                    |_, _, _, _, _, _, _| {
                        called.set(true);
                        Ok(())
                    },
                )
                .is_err()
        );
        assert!(!called.get());
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    assert!(
        norito::with_decode_limits_scope(zero, || {
            f.chain.state().with_native_reserve_account_snapshot_v1(
                &tip,
                &f.manager,
                f.provider,
                &budget,
                |_, _, _, _, _, _, _| {
                    called.set(true);
                    Ok(())
                },
            )
        })
        .is_err()
    );
    assert!(!called.get());
    // Retrying with the same native cut and original pool succeeds once the tighter caller
    // refusal scope has ended. No replacement State or manufactured proof is introduced.
    assert!(
        f.proof(&budget)
            .verify(&f.expected(), &f.verified_tip())
            .is_ok()
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_account_projection_rejects_hidden_and_tail_modified_originals() {
    let mut f = Fixture::new();
    f.publish_policy();
    f.register();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let proof = f.proof(&budget);
    let tip = f.chain.committed(f.chain.height());
    let mut world = f.chain.state().world.block();
    let check = |world: &WorldBlock<'_>| {
        reserve_account_originals(
            &proof.world,
            world,
            &f.manager,
            f.provider,
            tip.block_time_ms(),
            tip.height(),
            &budget,
        )
        .map(|_| ())
    };
    check(&world).unwrap();
    let key = reserve_provider_key(f.provider);
    world.smart_contract_state.remove(key.clone());
    assert!(check(&world).unwrap_err().contains("absence differs"));
    world
        .smart_contract_state
        .insert(key.clone(), proof.current.clone().unwrap());
    let mut changed =
        decode_reserve_provider_frame(proof.current.as_ref().unwrap(), f.provider).unwrap();
    changed.revision += 1;
    world
        .smart_contract_state
        .insert(key.clone(), norito::encode_canonical(&changed).unwrap());
    assert!(check(&world).unwrap_err().contains("typed target"));
    world
        .smart_contract_state
        .insert(key, proof.current.clone().unwrap());
    world.provider_owners.insert(f.provider, f.manager.clone());
    assert!(check(&world).unwrap_err().contains("typed target"));
    world.provider_owners.insert(f.provider, f.owner.clone());
    world
        .smart_contract_state
        .remove(reserve_state_key().clone());
    assert!(check(&world).unwrap_err().contains("active policy"));
    let mut changed = ReserveStateV1::decode_frame(&proof.policy).unwrap();
    changed.policy.activated_at_unix += 1;
    world.smart_contract_state.insert(
        reserve_state_key().clone(),
        norito::encode_canonical(&changed).unwrap(),
    );
    assert!(check(&world).unwrap_err().contains("typed target"));
    // Every mutation is an uncommitted negative specimen, never certified state authority.
    drop(world);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_account_projection_requires_current_original_capture_and_stable_generation() {
    let mut f = Fixture::new();
    f.publish_policy();
    let old = f.chain.committed(f.chain.height());
    f.register();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let called = Cell::new(false);
    assert!(
        f.chain
            .state()
            .with_native_reserve_account_snapshot_v1(
                &old,
                &f.manager,
                f.provider,
                &budget,
                |_, _, _, _, _, _, _| {
                    called.set(true);
                    Ok(())
                },
            )
            .is_err()
    );
    assert!(!called.get());
    let tip = f.chain.committed(f.chain.height());
    let state = f.chain.state();
    let result = state.with_native_reserve_account_snapshot_v1(
        &tip,
        &f.manager,
        f.provider,
        &budget,
        |_, _, _, _, _, _, _| {
            called.set(true);
            let mut publication = state.state_view_publication();
            let _writer = publication.begin();
            Ok(())
        },
    );
    assert!(called.get());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("generation changed")
    );
    let mut fresh = Fixture::new();
    fresh.publish_policy();
    *fresh.chain.state().native_world_cut.lock() = None;
    called.set(false);
    assert!(
        fresh
            .chain
            .state()
            .with_native_reserve_account_snapshot_v1(
                &fresh.chain.committed(fresh.chain.height()),
                &fresh.manager,
                fresh.provider,
                &budget,
                |_, _, _, _, _, _, _| {
                    called.set(true);
                    Ok(())
                },
            )
            .unwrap_err()
            .to_string()
            .contains("requires native replay")
    );
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), 0);
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_owner_funds(false)
    }

    fn new_with_owner_funds(funded: bool) -> Self {
        let key = KeyPair::from_seed(vec![0xb1; 32], Algorithm::Ed25519);
        let manager = AccountId::new(key.public_key().clone());
        let account = |seed| {
            AccountId::new(
                KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        };
        let owner = account(0xb4);
        let provider = ProviderId::new([0xd4; 32]);
        let custody = account(0xb2);
        let treasury = account(0xb3);
        let domain = DomainId::parse_fully_qualified("app.reserve-proof-test").unwrap();
        let asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "xor".parse().unwrap());
        let mut definition = AssetDefinition::numeric(
            asset.clone(),
            "Reserve proof asset",
            AssetBalancePolicy::Global,
            Some(domain.clone()),
        )
        .build(&manager);
        let assets = if funded {
            definition.total_quantity = 100_u32.into();
            vec![Asset::new(
                iroha_data_model::asset::AssetId::new(asset.clone(), owner.clone()),
                100_u32,
            )]
        } else {
            Vec::new()
        };
        let mut world = World::with_assets(
            [Domain::new(domain).build(&manager)],
            [&manager, &owner, &custody, &treasury]
                .map(|id| Account::new(id.clone()).build(&manager)),
            [definition],
            assets,
            [],
        );
        let mut permissions = BTreeSet::from([
            reserve_policy_permission(),
            iroha_data_model::permission::Permission::from(
                iroha_executor_data_model::permission::sorafs::CanUpsertSorafsProviderCredit,
            ),
        ]);
        if funded {
            permissions.insert(iroha_data_model::permission::Permission::from(
                iroha_executor_data_model::permission::sorafs::CanSetSorafsPricing,
            ));
        }
        world
            .account_permissions
            .insert(manager.clone(), permissions);
        let policy = ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: ReservePolicyV1::default(),
            asset_definition: asset,
            custody_account: custody,
            treasury_account: treasury,
            operations_authority: manager.clone(),
            decision_authority: manager.clone(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).unwrap(),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        };
        policy.validate().unwrap();
        let mut configuration = TestChainConfig::new(world, 1_000);
        let mut governance = iroha_config::parameters::actual::Governance::default();
        governance
            .sorafs_provider_owners
            .insert(provider, owner.clone());
        configuration.governance = Some(governance);
        let mut chain = CertifiedTestChain::start(configuration).unwrap();
        let signed = chain.sign(
            &key,
            [Log::new(iroha_logger::Level::INFO, "reserve proof source".into()).into()],
            2_000,
        );
        assert!(chain.commit(vec![signed])[0]);
        Self {
            chain,
            key,
            manager,
            policy,
            owner,
            provider,
        }
    }

    fn publish_policy(&mut self) {
        let signed = self.chain.sign(
            &self.key,
            [SetSorafsReservePolicy::new(self.policy.clone()).into()],
            3_000,
        );
        assert!(self.chain.commit(vec![signed])[0]);
    }

    fn register(&mut self) {
        let signed = self.chain.sign(
            &self.key,
            [RegisterSorafsReserveAccount::new(
                ReserveProviderTermsV1 {
                    provider_id: self.provider,
                    provider_account: self.owner.clone(),
                    tier: ReserveTier::TierA,
                    storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
                    duration: ReserveDuration::Monthly,
                    capacity_gib: 10,
                },
                self.policy.digest().unwrap(),
            )
            .into()],
            4_000,
        );
        assert_eq!(self.chain.commit(vec![signed]), vec![true]);
    }

    fn expected(&self) -> ReserveAccountProofExpectedV1<'_> {
        ReserveAccountProofExpectedV1 {
            chain: self.chain.state().chain_id_ref().as_str(),
            network_id: self.chain.network_id(),
            operator: &self.manager,
            provider_id: self.provider,
            owner: &self.owner,
            policy: &self.policy,
            schema: State::native_world_schema_hash_v1().unwrap(),
        }
    }

    fn verified_tip(&self) -> VerifiedSumeragiBlock {
        let validators = self
            .chain
            .validators()
            .iter()
            .map(|(peer, pop)| FinalityValidator {
                public_key: peer.public_key().clone(),
                proof_of_possession: pop.clone(),
            })
            .collect();
        let mut verifier = SumeragiFinalityVerifier::new(
            self.chain.genesis(),
            self.chain.state().chain_id_ref().as_str(),
            validators,
        )
        .unwrap();
        let view = self.chain.state().view();
        let mut tip = None;
        for height in 1..=self.chain.height() {
            tip = Some(
                verifier
                    .verify(&crate::sumeragi::finality::build_proof(&view, height).unwrap())
                    .unwrap(),
            );
        }
        tip.unwrap()
    }

    fn proof(&self, budget: &AllocationBudget) -> ReserveAccountProofV1 {
        let tip = self.chain.committed(self.chain.height());
        let (bytes, charge) = self
            .chain
            .state()
            .with_native_reserve_account_snapshot_v1(
                &tip,
                &self.manager,
                self.provider,
                budget,
                |world, owner, policy, current, credit, capacity, pricing| {
                    assert_eq!(owner, &self.owner);
                    assert_eq!(
                        world.root().unwrap(),
                        tip.commitment().execution.world_state_root
                    );
                    let borrowed = ReserveAccountProofRefV1::new(
                        world, owner, policy, current, credit, capacity, pricing,
                    );
                    let size = norito::canonical_frame_len(&borrowed).map_err(|e| e.to_string())?;
                    let charge = budget.try_reserve_bytes(size).map_err(|e| e.to_string())?;
                    Ok((
                        norito::encode_canonical(&borrowed).map_err(|e| e.to_string())?,
                        charge,
                    ))
                },
            )
            .unwrap();
        let proof = ReserveAccountProofV1::decode_frame(&bytes).unwrap();
        drop(bytes);
        drop(charge);
        proof
    }
}

fn private_reserve_fixture() -> (CertifiedTestChain, KeyPair) {
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{
            Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId,
            AssetId,
        },
        block::consensus::RootFeePolicy,
        domain::Domain,
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        parameter::Parameter,
    };
    use iroha_model_base::topology::DataSpaceId;

    let ds = DataSpaceId::new(u64::MAX - 15);
    let key = KeyPair::from_seed(vec![0xcc; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let domain =
        iroha_model_base::domain::DomainId::parse_fully_qualified("app.private-pin-test").unwrap();
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "gas".parse().unwrap());
    let mut definition = AssetDefinition::numeric(
        asset.clone(),
        "Private gas",
        AssetBalancePolicy::DataspaceRestricted,
        Some(domain.clone()),
    )
    .build(&owner);
    definition.total_quantity = 1_000_000_u32.into();
    let world = World::with_assets(
        [Domain::new(domain).build(&owner)],
        [Account::new(owner.clone()).build(&owner)],
        [definition],
        [Asset::new(
            AssetId::with_scope(asset.clone(), owner, AssetBalanceScope::Dataspace(ds)),
            1_000_000_u32,
        )],
        [],
    );
    let mut configuration = TestChainConfig::new(world, 1_000);
    configuration.genesis_parameters.push(Parameter::Custom(
        RootFeePolicy {
            fee_asset_id: asset.clone(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
            ..iroha_config::parameters::defaults::nexus::fees::genesis_policy()
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    configuration.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"independent public parent")),
        ),
        dataspace_id: ds,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = asset.clone();
    nexus.lane_catalog = LaneCatalog::new(
        std::num::NonZeroU32::new(1).unwrap(),
        vec![LaneConfig {
            dataspace_id: ds,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: ds,
        alias: "private-pin-test".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = ds;
    configuration.nexus = Some(nexus);
    (CertifiedTestChain::start(configuration).unwrap(), key)
}

#[test]
fn reserve_account_projection_refuses_genuine_private_root_before_consumer() {
    let (mut chain, key) = private_reserve_fixture();
    let signed = chain.sign(
        &key,
        [Log::new(iroha_logger::Level::INFO, "private reserve read".into()).into()],
        2_000,
    );
    assert_eq!(chain.commit(vec![signed]), vec![true]);
    let operator = AccountId::new(key.public_key().clone());
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let called = Cell::new(false);
    let result = chain.state().with_native_reserve_account_snapshot_v1(
        &chain.committed(chain.height()),
        &operator,
        ProviderId::new([0xd4; 32]),
        &budget,
        |_, _, _, _, _, _, _| {
            called.set(true);
            Ok(())
        },
    );
    assert!(result.unwrap_err().to_string().contains("Global root"));
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), 0);
}

fn native_credit(provider: ProviderId) -> ProviderCreditRecord {
    let mut record = ProviderCreditRecord::new(
        provider,
        17_u32.into(),
        0_u32.into(),
        19_u32.into(),
        23_u32.into(),
        1_000_000,
        999_999,
        iroha_model_base::metadata::Metadata::default(),
    );
    record.metadata.insert(
        "projection".parse().unwrap(),
        iroha_primitives::json::Json::new("native-original"),
    );
    record
}

#[test]
fn reserve_account_credit_tracks_actual_native_upsert_and_rejected_absent_cas() {
    let mut f = Fixture::new();
    f.publish_policy();
    f.register();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let absent = f.proof(&budget);
    assert!(
        absent
            .verify(&f.expected(), &f.verified_tip())
            .unwrap()
            .credit()
            .is_none()
    );
    let original = native_credit(f.provider);
    let signed = f.chain.sign(
        &f.key,
        [UpsertProviderCredit::new(None, original.clone()).into()],
        5_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let proof = f.proof(&budget);
    let tip = f.verified_tip();
    assert_eq!(
        proof.verify(&f.expected(), &tip).unwrap().credit(),
        Some(&original)
    );
    assert!(absent.verify(&f.expected(), &tip).is_err());
    let mut hidden = proof.clone();
    hidden.credit = None;
    assert!(hidden.verify(&f.expected(), &tip).is_err());
    let mut replacement = original.clone();
    replacement.available_credit = 29_u32.into();
    let signed = f.chain.sign(
        &f.key,
        [UpsertProviderCredit::new(None, replacement.clone()).into()],
        6_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![false]);
    assert_eq!(
        f.proof(&budget)
            .verify(&f.expected(), &f.verified_tip())
            .unwrap()
            .credit(),
        Some(&original)
    );
    // A successful guarded update uses the native typed hash, never the World value digest.
    let expected = iroha_crypto::HashOf::try_new(&original).unwrap();
    let signed = f.chain.sign(
        &f.key,
        [UpsertProviderCredit::new(Some(expected), replacement.clone()).into()],
        7_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    assert_eq!(
        f.proof(&budget)
            .verify(&f.expected(), &f.verified_tip())
            .unwrap()
            .credit(),
        Some(&replacement)
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_account_credit_tail_changes_and_hidden_rows_refuse_before_publication() {
    let mut f = Fixture::new();
    f.publish_policy();
    f.register();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let absent = f.proof(&budget);
    let original = native_credit(f.provider);
    let signed = f.chain.sign(
        &f.key,
        [UpsertProviderCredit::new(None, original.clone()).into()],
        5_000,
    );
    assert_eq!(f.chain.commit(vec![signed]), vec![true]);
    let proof = f.proof(&budget);
    let tip = f.chain.committed(f.chain.height());
    let mut world = f.chain.state().world.block();
    let check = |snapshot: &WorldStateSnapshotV1, world: &WorldBlock<'_>| {
        reserve_account_originals(
            snapshot,
            world,
            &f.manager,
            f.provider,
            tip.block_time_ms(),
            tip.height(),
            &budget,
        )
        .map(|_| ())
    };
    check(&proof.world, &world).unwrap();
    world.provider_credit_ledger.remove(f.provider);
    assert!(
        check(&proof.world, &world)
            .unwrap_err()
            .contains("credit absence differs")
    );
    let mut changed = original.clone();
    changed.expected_settlement = 101_u32.into();
    world.provider_credit_ledger.insert(f.provider, changed);
    assert!(
        check(&proof.world, &world)
            .unwrap_err()
            .contains("typed target")
    );
    world.provider_credit_ledger.insert(f.provider, original);
    // Even a genuine row at a later cut cannot be backfilled into an earlier absent cut.
    assert!(
        check(&absent.world, &world)
            .unwrap_err()
            .contains("typed target")
    );
    drop(world);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_account_credit_frame_reservation_is_exact_cumulative_and_refundable() {
    let original = native_credit(ProviderId::new([0xd4; 32]));
    let length = norito::canonical_frame_len(&original).unwrap();
    let too_small = AllocationBudget::new(length - 1);
    assert!(encode_original(&original, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1, &too_small).is_err());
    assert_eq!(too_small.reserved_bytes(), 0);
    let budget = AllocationBudget::new(length);
    let exact = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length, 128);
    let ((bytes, charge), usage) = norito::core::with_decode_limits_measured(exact, || {
        encode_original(&original, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1, &budget).unwrap()
    });
    assert_eq!(bytes, norito::encode_canonical(&original).unwrap());
    assert_eq!(budget.reserved_bytes(), length);
    assert_eq!(usage.total_allocated_bytes(), length);
    drop(bytes);
    drop(charge);
    assert_eq!(budget.reserved_bytes(), 0);
    norito::core::with_decode_limits_scope(exact, || {
        let first =
            encode_original(&original, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1, &budget).unwrap();
        drop(first);
        // Pool credits refund but the same inherited cumulative codec allowance does not.
        assert!(encode_original(&original, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1, &budget).is_err());
    });
    assert_eq!(budget.reserved_bytes(), 0);
    let mut oversized = original;
    // Each metadata value obeys the JSON bound; their genuine parent frame exceeds
    // the independent reserve-account response bound that this control exercises.
    use iroha_primitives::json::{Json, MAX_JSON_BYTES};
    assert!(Json::try_new("x".repeat(MAX_JSON_BYTES - 1)).is_err());
    for name in ["large_a", "large_b", "large_c"] {
        let value = Json::try_new("x".repeat(MAX_JSON_BYTES - 2)).unwrap();
        assert_eq!(value.get().len(), MAX_JSON_BYTES);
        oversized.metadata.insert(name.parse().unwrap(), value);
    }
    assert!(norito::canonical_frame_len(&oversized).unwrap() > MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1);
    assert!(
        encode_original(&oversized, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1, &budget)
            .err()
            .unwrap()
            .contains("response bound")
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[path = "capacity_pricing_tests.rs"]
mod capacity_pricing_tests;
