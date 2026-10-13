//! Genuine native reserve projection, exact original permission and certified-cut refusals.

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
    isi::{Log, sorafs::SetSorafsReservePolicy},
    permission::Permission,
    sorafs::reserve::{
        RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReservePolicyV1,
        proof::{ReservePolicyProofRefV1, ReservePolicyProofV1},
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
}

impl Fixture {
    fn new(permission: Permission) -> Self {
        let key = KeyPair::from_seed(vec![0xb1; 32], Algorithm::Ed25519);
        let manager = AccountId::new(key.public_key().clone());
        let account = |seed| {
            AccountId::new(
                KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        };
        let custody = account(0xb2);
        let treasury = account(0xb3);
        let domain = DomainId::parse_fully_qualified("app.reserve-proof-test").unwrap();
        let asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "xor".parse().unwrap());
        let definition = AssetDefinition::numeric(
            asset.clone(),
            "Reserve proof asset",
            AssetBalancePolicy::Global,
            Some(domain.clone()),
        )
        .build(&manager);
        let mut world = World::with_assets(
            [Domain::new(domain).build(&manager)],
            [&manager, &custody, &treasury].map(|id| Account::new(id.clone()).build(&manager)),
            [definition],
            std::iter::empty::<Asset>(),
            [],
        );
        world
            .account_permissions
            .insert(manager.clone(), BTreeSet::from([permission]));
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
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        let signed = chain.sign(
            &key,
            [Log::new(iroha_logger::Level::INFO, "reserve proof source".into()).into()],
            2_000,
        );
        assert!(chain.commit_at(2_000, vec![signed])[0]);
        Self {
            chain,
            key,
            manager,
            policy,
        }
    }

    fn publish_policy(&mut self) {
        let signed = self.chain.sign(
            &self.key,
            [SetSorafsReservePolicy::new(self.policy.clone()).into()],
            3_000,
        );
        assert!(self.chain.commit_at(3_000, vec![signed])[0]);
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

    fn proof(&self, budget: &AllocationBudget) -> ReservePolicyProofV1 {
        let tip = self.chain.committed(self.chain.height());
        let (bytes, charge) = self
            .chain
            .state()
            .with_native_reserve_policy_snapshot_v1(
                &tip,
                &self.manager,
                budget,
                |world, permissions, current| {
                    assert_eq!(permissions, &BTreeSet::from([reserve_policy_permission()]));
                    assert_eq!(
                        world.root().unwrap(),
                        tip.commitment().execution.world_state_root
                    );
                    let borrowed = ReservePolicyProofRefV1::new(world, permissions, current);
                    let size = norito::canonical_frame_len(&borrowed).map_err(|e| e.to_string())?;
                    let charge = budget.try_reserve_bytes(size).map_err(|e| e.to_string())?;
                    Ok((
                        norito::encode_canonical(&borrowed).map_err(|e| e.to_string())?,
                        charge,
                    ))
                },
            )
            .unwrap();
        let proof = ReservePolicyProofV1::decode_frame(&bytes).unwrap();
        drop(bytes);
        drop(charge);
        proof
    }
}

#[test]
fn reserve_projection_canonical_permission_matches_native_executor_token() {
    let native: Permission =
        iroha_executor_data_model::permission::sorafs::CanSetSorafsReservePolicy.into();
    assert_eq!(reserve_policy_permission(), native);
}

#[test]
fn reserve_projection_authenticates_absence_and_exact_signed_policy_without_broad_read_grant() {
    let mut f = Fixture::new(reserve_policy_permission());
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    for present in [false, true] {
        if present {
            f.publish_policy();
        }
        let proof = f.proof(&budget);
        assert_eq!(budget.reserved_bytes(), 0);
        let native = f.verified_tip();
        let verified = proof
            .verify(
                f.chain.state().chain_id_ref().as_str(),
                f.chain.network_id(),
                &f.manager,
                &f.policy,
                State::native_world_schema_hash_v1().unwrap(),
                &native,
            )
            .unwrap();
        assert_eq!(verified.current().is_some(), present);
        assert_eq!(verified.manager(), &f.manager);
        assert_eq!(verified.height(), f.chain.height());
        if let Some(current) = verified.current() {
            assert_eq!(current.policy, f.policy);
            assert_eq!(current.activated_by, f.manager);
            assert_eq!(current.activated_at_unix, 3);
            let mut hidden = proof.clone();
            hidden.current = None;
            assert!(
                hidden
                    .verify(
                        f.chain.state().chain_id_ref().as_str(),
                        f.chain.network_id(),
                        &f.manager,
                        &f.policy,
                        State::native_world_schema_hash_v1().unwrap(),
                        &native
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn reserve_projection_refuses_missing_or_noncanonical_direct_grants_and_original_budget_exhaustion()
{
    let broad: Permission =
        iroha_executor_data_model::permission::query::CanReadAllLedgerData.into();
    let malformed = Permission::new(
        "CanSetSorafsReservePolicy".into(),
        iroha_primitives::json::Json::new("wrong payload"),
    );
    for permission in [broad, malformed] {
        let f = Fixture::new(permission);
        let tip = f.chain.committed(f.chain.height());
        let called = Cell::new(false);
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let result = f.chain.state().with_native_reserve_policy_snapshot_v1(
            &tip,
            &f.manager,
            &budget,
            |_, _, _| {
                called.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!called.get());
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let mut f = Fixture::new(reserve_policy_permission());
    f.publish_policy();
    let tip = f.chain.committed(f.chain.height());
    let called = Cell::new(false);
    for (manager, bytes) in [
        (&f.manager, 0),
        (f.chain.genesis_account(), 32 * 1024 * 1024),
    ] {
        let budget = AllocationBudget::new(bytes);
        assert!(
            f.chain
                .state()
                .with_native_reserve_policy_snapshot_v1(&tip, manager, &budget, |_, _, _| {
                    called.set(true);
                    Ok(())
                })
                .is_err()
        );
        assert!(!called.get());
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let unknown = AccountId::new(
        KeyPair::from_seed(vec![0xdd; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    assert!(
        f.chain
            .state()
            .with_native_reserve_policy_snapshot_v1(&tip, &unknown, &budget, |_, _, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    assert!(
        norito::with_decode_limits_scope(zero, || f
            .chain
            .state()
            .with_native_reserve_policy_snapshot_v1(&tip, &f.manager, &budget, |_, _, _| {
                called.set(true);
                Ok(())
            }))
        .is_err()
    );
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_projection_cannot_hide_or_replace_original_policy_or_direct_permission_rows() {
    let mut f = Fixture::new(reserve_policy_permission());
    f.publish_policy();
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let proof = f.proof(&budget);
    let original = proof.current.as_ref().unwrap();
    let mut world = f.chain.state().world.block();
    reserve_policy_originals(&proof.world, &world, &f.manager, &budget).unwrap();
    world
        .smart_contract_state
        .remove(reserve_state_key().clone());
    assert!(
        reserve_policy_originals(&proof.world, &world, &f.manager, &budget)
            .unwrap_err()
            .clone()
            .contains("absence differs")
    );
    let mut changed = ReserveStateV1::decode_frame(original).unwrap();
    changed.policy.activated_at_unix += 1;
    world.smart_contract_state.insert(
        reserve_state_key().clone(),
        norito::encode_canonical(&changed).unwrap(),
    );
    assert!(
        reserve_policy_originals(&proof.world, &world, &f.manager, &budget)
            .unwrap_err()
            .clone()
            .contains("typed target")
    );
    world
        .smart_contract_state
        .insert(reserve_state_key().clone(), original.clone());
    world.account_permissions.insert(
        f.manager.clone(),
        BTreeSet::from([
            reserve_policy_permission(),
            iroha_executor_data_model::permission::query::CanReadAllLedgerData.into(),
        ]),
    );
    assert!(
        reserve_policy_originals(&proof.world, &world, &f.manager, &budget)
            .unwrap_err()
            .clone()
            .contains("typed target")
    );
    // The uncommitted overlay is a mutation specimen, never native authority.
    drop(world);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reserve_projection_refuses_obsolete_or_missing_original_publication_and_generation_changes() {
    let mut f = Fixture::new(reserve_policy_permission());
    let old_tip = f.chain.committed(f.chain.height());
    f.publish_policy();
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let called = Cell::new(false);
    assert!(
        f.chain
            .state()
            .with_native_reserve_policy_snapshot_v1(&old_tip, &f.manager, &budget, |_, _, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.get());
    let tip = f.chain.committed(f.chain.height());
    let state = f.chain.state();
    let result =
        state.with_native_reserve_policy_snapshot_v1(&tip, &f.manager, &budget, |_, _, _| {
            called.set(true);
            let mut publication = state.state_view_publication();
            let _writer = publication.begin();
            Ok(())
        });
    assert!(called.get());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("generation changed")
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let fresh = Fixture::new(reserve_policy_permission());
    let tip = fresh.chain.committed(fresh.chain.height());
    *fresh.chain.state().native_world_cut.lock() = None;
    called.set(false);
    let result = fresh.chain.state().with_native_reserve_policy_snapshot_v1(
        &tip,
        &fresh.manager,
        &budget,
        |_, _, _| {
            called.set(true);
            Ok(())
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires native replay")
    );
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), 0);
}
