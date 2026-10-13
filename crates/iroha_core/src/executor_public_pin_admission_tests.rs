//! Genuine signed public pin admission through the Initial executor and native fee policy.

use crate::{
    executor::Executor,
    state::{World, WorldReadOnly as _},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_config::parameters::actual::{Governance, SorafsPinApprovalSigner};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    domain::Domain,
    executor::ValidationFail,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError, MathError},
        sorafs::RegisterPinManifest,
    },
    sorafs::pin_registry::{ManifestDigest, PinStatus, StorageClass},
    transaction::error::TransactionRejectionReason,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::{NumericSpec, Quantity};
use mv::storage::StorageReadOnly as _;
use sorafs_manifest::{DagCodecId, ManifestBuilder, ManifestV1};

const PIN_TIME_MS: u64 = 2_000;
const CONTENT_BYTES: u64 = 1 << 30;
const RETENTION_EPOCH: u64 = 2_592_002;

struct Fixture {
    chain: CertifiedTestChain,
    key: KeyPair,
    authority: AccountId,
    treasury: AccountId,
    fee_asset: AssetDefinitionId,
}

impl Fixture {
    fn new(balance: Quantity) -> Self {
        let key = KeyPair::from_seed(vec![0xd1; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let treasury = AccountId::new(
            KeyPair::from_seed(vec![0xd2; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let domain = DomainId::parse_fully_qualified("app.public-pin-test").unwrap();
        let fee_asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "pin_fee".parse().unwrap());
        let mut definition = AssetDefinition::new(
            fee_asset.clone(),
            "Public pin fee",
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            Some(domain.clone()),
        )
        .build(&authority);
        definition.total_quantity = balance.clone();
        let world = World::with_assets(
            [Domain::new(domain).build(&authority)],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(treasury.clone()).build(&authority),
            ],
            [definition],
            [Asset::new(
                AssetId::new(fee_asset.clone(), authority.clone()),
                balance,
            )],
            [],
        );
        let mut governance = Governance {
            sorafs_pin_fee_asset_id: fee_asset.clone(),
            sorafs_pin_fee_treasury_account: treasury.clone(),
            ..Default::default()
        };
        governance.sorafs_pin_policy.min_replicas_floor = 3;
        // Paid registration is valid while approval is pending. This exercises the genuine
        // council gate without injecting provider assignments or bypassing replication policy.
        governance.sorafs_pin_policy.require_council_signatures = true;
        governance.sorafs_pin_policy.approval_quorum = 1;
        governance.sorafs_pin_policy.approval_signers = vec![SorafsPinApprovalSigner {
            signer_id: "native-pin-council".to_owned(),
            public_key: KeyPair::from_seed(vec![0xd3; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
            valid_from_block_height: 0,
            revoked_at_block_height: None,
        }];
        let mut config = TestChainConfig::new(world, 1_000);
        config.governance = Some(governance);
        let chain = CertifiedTestChain::start(config).unwrap();
        {
            let view = chain.state().view();
            assert!(matches!(view.world().executor(), Executor::Initial));
            assert!(
                view.world()
                    .account_permissions()
                    .get(&authority)
                    .is_none_or(|permissions| permissions.is_empty())
            );
        }
        Self {
            chain,
            key,
            authority,
            treasury,
            fee_asset,
        }
    }

    fn balance(&self, account: &AccountId) -> Quantity {
        self.chain
            .state()
            .view()
            .world()
            .assets()
            .get(&AssetId::new(self.fee_asset.clone(), account.clone()))
            .map_or_else(Quantity::zero, |value| value.as_ref().clone())
    }

    fn submit(&mut self, manifest: &ManifestV1) -> bool {
        let signed = self.chain.sign(
            &self.key,
            [RegisterPinManifest::new(manifest.encode().unwrap(), None, None).into()],
            PIN_TIME_MS,
        );
        self.chain.commit_at(PIN_TIME_MS, vec![signed])[0]
    }
}

fn manifest(min_replicas: u16) -> ManifestV1 {
    ManifestBuilder::new()
        .root_cid(sorafs_manifest::canonical_manifest_root_cid([0xe1; 32]))
        .dag_codec(DagCodecId(sorafs_manifest::MANIFEST_DAG_CODEC))
        .chunking_from_registry(sorafs_manifest::chunker_registry::default_descriptor().id)
        .chunk_digest_sha3_256([0xe2; 32])
        .por_root([0xe3; 32])
        .content_length(CONTENT_BYTES)
        .car_digest([0xe4; 32])
        .car_size(CONTENT_BYTES + 4_096)
        .pin_policy(sorafs_manifest::PinPolicy {
            min_replicas,
            storage_class: sorafs_manifest::StorageClass::Hot,
            retention_epoch: RETENTION_EPOCH,
        })
        .build()
        .unwrap()
}

#[test]
fn signed_public_pin_without_permission_pays_exact_fee_and_retains_council_gate() {
    let mut f = Fixture::new(1_000_000_u32.into());
    let manifest = manifest(3);
    let digest = ManifestDigest::from_manifest(&manifest).unwrap();
    let before = f.balance(&f.authority);
    let treasury_before = f.balance(&f.treasury);
    assert!(f.submit(&manifest));
    let view = f.chain.state().view();
    let record = view.world().pin_manifests().get(&digest).unwrap();
    assert_eq!(record.submitted_by, f.authority);
    assert_eq!(record.submitted_epoch, PIN_TIME_MS / 1_000);
    assert_eq!(record.status, PinStatus::Pending);
    assert!(record.alias.is_none());
    let expected = view
        .world()
        .sorafs_pricing()
        .public_pin_fee(
            StorageClass::Hot,
            CONTENT_BYTES,
            3,
            record.submitted_epoch,
            RETENTION_EPOCH,
        )
        .unwrap();
    assert!(expected > Quantity::zero());
    let payment = record.pin_fee_payment.as_ref().unwrap();
    assert_eq!(payment.paid_by, f.authority);
    assert_eq!(payment.fee_asset_id, f.fee_asset);
    assert_eq!(payment.treasury_account_id, f.treasury);
    assert_eq!(payment.amount, expected);
    assert_eq!(
        f.balance(&f.authority),
        before.checked_sub(&expected).unwrap()
    );
    assert_eq!(
        f.balance(&f.treasury),
        treasury_before.checked_add(&expected).unwrap()
    );
    assert_eq!(view.world().replication_orders().iter().count(), 0);
    assert_eq!(view.world().manifest_aliases().iter().count(), 0);
}

#[test]
fn signed_public_pin_fee_and_replica_policy_fail_without_pin_or_replication_effects() {
    for (balance, replicas, expected_error) in [
        (
            "0.000000001",
            3,
            InstructionExecutionError::Math(MathError::NotEnoughQuantity),
        ),
        (
            "1000000",
            2,
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "manifest payload failed validation: pin policy requires at least 3 replicas but manifest specifies 2"
                    .to_owned(),
            )),
        ),
    ] {
        let mut f = Fixture::new(balance.parse().unwrap());
        let manifest = manifest(replicas);
        let before = f.balance(&f.authority);
        let treasury_before = f.balance(&f.treasury);
        assert!(!f.submit(&manifest));
        let committed = f.chain.committed(f.chain.height());
        let result = &committed.block().network_output_at(0).unwrap().1.result;
        assert_eq!(
            result.as_ref().unwrap_err(),
            &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                expected_error,
            )),
        );
        let view = f.chain.state().view();
        assert_eq!(view.world().pin_manifests().iter().count(), 0);
        assert_eq!(view.world().replication_orders().iter().count(), 0);
        assert_eq!(view.world().manifest_aliases().iter().count(), 0);
        assert_eq!(f.balance(&f.authority), before);
        assert_eq!(f.balance(&f.treasury), treasury_before);
    }
}
