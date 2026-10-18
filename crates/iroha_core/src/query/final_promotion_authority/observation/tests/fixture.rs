//! Actual native instructions in blocks of a certified test chain (real BLS `CommitQC`s of a
//! fixed four-validator committee; height 1 is the signed genesis).
//!
//! The chain is not a consensus application-state-root proof. Custody attestations are
//! software-signed fixtures and do not qualify a physical device.

use super::*;
use crate::{
    query::signer_check::fixture as chain_fixture, state::World,
    sumeragi::test_chain::CertifiedTestChain,
};
use iroha_crypto::{KeyPair, Signature};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::Account,
    isi::sorafs::MutateSorafsFinalPromotionAccountCustody,
    permission::{Permission, Permissions},
    sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyActionV1,
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsFinalPromotion, CanManageSorafsFinalPromotionAccountCustody,
    CanManageSorafsFinalPromotionCustody, CanOperateSorafsFinalPromotion,
};
use sorafs_manifest::{
    self as manifest,
    signer::{
        custody::{
            SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyAuthorityV1,
            SignerCustodyRecordV1, SignerCustodyStatementV1, SignerCustodyUseContextV1,
            verify_signer_custody_use_v1,
        },
        custody_control::SignerCustodyPolicyV1,
        final_promotion::{
            SignerFinalPromotionExpectedV1, signer_final_promotion_digest_v1,
            statement::prepare_final_promotion_statement_v1,
        },
    },
};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sorafs_manifest/src/signer/final_promotion/tests/statement_fixture_support.rs"
));

pub(super) const NOW: u64 = 3_000;
pub(super) const DEPLOYMENT: &str = "promotion-primary";

pub(super) fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}

pub(super) struct Fixture {
    pub(super) state: Arc<State>,
    pub(super) policy: SignerCustodyPolicyV1,
    pub(super) account_policy: SignerCustodyPolicyV1,
    pub(super) chain: CertifiedTestChain,
    pub(super) reserve_signed: Option<SignedTransaction>,
    pub(super) reserve_floor: Option<FinalPromotionCheckFloorV1>,
    fee_asset: Option<iroha_data_model::asset::AssetDefinitionId>,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::with_observer_permissions([])
    }

    pub(super) fn with_observer_permissions(
        extra_permissions: impl IntoIterator<Item = Permission>,
    ) -> Self {
        Self::with_options(extra_permissions, false)
    }

    pub(super) fn with_fees() -> Self {
        Self::with_options([], true)
    }

    fn with_options(
        extra_permissions: impl IntoIterator<Item = Permission>,
        charged: bool,
    ) -> Self {
        let manager = AccountId::new(key(1).public_key().clone());
        let operator = AccountId::new(key(2).public_key().clone());
        let observer = AccountId::new(key(3).public_key().clone());
        let mut extra_permissions = Some(extra_permissions);
        let mut world = World::new();
        for authority in [&manager, &operator, &observer] {
            let (id, account) = Account::new(authority.clone())
                .build(&manager)
                .into_key_value();
            world.accounts.insert(id, account);
        }
        for (authority, permission) in [
            (
                observer.clone(),
                Permission::from(CanCheckSorafsFinalPromotion {
                    deployment_id: DEPLOYMENT.into(),
                }),
            ),
            (
                manager.clone(),
                Permission::from(CanManageSorafsFinalPromotionCustody {
                    deployment_id: DEPLOYMENT.into(),
                }),
            ),
            (
                operator.clone(),
                Permission::from(CanOperateSorafsFinalPromotion {
                    deployment_id: DEPLOYMENT.into(),
                }),
            ),
        ] {
            let mut permissions = Permissions::new();
            permissions.insert(permission);
            if authority == manager {
                permissions.insert(Permission::from(
                    CanManageSorafsFinalPromotionAccountCustody {
                        deployment_id: DEPLOYMENT.into(),
                    },
                ));
            }
            if authority == observer {
                permissions.extend(extra_permissions.take().unwrap());
            }
            world.account_permissions.insert(authority, permissions);
        }
        let fee_asset = charged.then(|| {
            iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
                &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
            )
            .unwrap()
        });
        let chain = if let Some(asset) = &fee_asset {
            use crate::sumeragi::test_chain::TestChainConfig;
            use iroha_data_model::{
                asset::{AssetBalancePolicy, AssetDefinition, AssetId},
                isi::{Mint, Register},
            };
            use iroha_primitives::numeric::Quantity;
            let mut config = TestChainConfig::new(world, chain_fixture::GENESIS_TIME_MS);
            let mut nexus = iroha_config::parameters::actual::Nexus::default();
            nexus.fees.base_fee = Quantity::from(1_u32);
            nexus.fees.per_instruction_fee = Quantity::from(1_u32);
            nexus.fees.per_byte_fee = Quantity::zero();
            nexus.fees.per_gas_unit_fee = Quantity::zero();
            nexus.fees.fee_asset_id = asset.clone();
            nexus.fees.fee_sink_account_id = observer.clone();
            config.nexus = Some(nexus);
            config.genesis_instructions.push(
                Register::asset_definition(AssetDefinition::numeric(
                    asset.clone(),
                    "Native final-promotion fee",
                    AssetBalancePolicy::Global,
                    None,
                ))
                .into(),
            );
            for authority in [&manager, &operator, &observer] {
                config.genesis_instructions.push(
                    Mint::asset_quantity(
                        Quantity::from(100_u32),
                        AssetId::of(asset.clone(), authority.clone()),
                    )
                    .into(),
                );
            }
            CertifiedTestChain::start(config).unwrap()
        } else {
            chain_fixture::chain(world)
        };
        let state = Arc::clone(chain.state());
        let policy = SignerCustodyPolicyV1 {
            binding: SignerCustodyBindingV1 {
                chain_id: state.chain_id_ref().to_string(),
                network_id: *state.network_id_ref().as_bytes(),
                runtime_handle: "software://sorafs/final-promotion-provenance/primary".into(),
                key_handle: "software://sorafs/final-promotion-provenance/key-1".into(),
                service_id: "promotion-service".into(),
                administrator_id: "promotion-admin".into(),
                role: SignerRoleV1::FinalPromotionProvenance,
                purpose: SignerPurposeBindingV1::FinalPromotionProvenance {
                    deployment_id: DEPLOYMENT.into(),
                },
                algorithm: SignerKeyAlgorithmV1::Ed25519,
                public_key: key(4).public_key().clone(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: [5; 32],
            },
            attester_authority: SignerCustodyAuthorityV1 {
                service_id: "custody-service".into(),
                administrator_id: "custody-admin".into(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: [6; 32],
            },
            attester_public_key: key(7).public_key().clone(),
            active_from_unix_ms: 100,
            active_until_unix_ms: 500_000,
            max_validity_ms: 120_000,
            max_anchor_age_ms: 60_000,
        };
        let mut account_policy = policy.clone();
        account_policy.binding.runtime_handle =
            "software://sorafs/final-promotion-account-transaction/primary".into();
        account_policy.binding.key_handle =
            "software://sorafs/final-promotion-account-transaction/key-1".into();
        account_policy.binding.role = SignerRoleV1::FinalPromotionAccountTransaction;
        account_policy.binding.purpose = SignerPurposeBindingV1::FinalPromotionAccountTransaction {
            deployment_id: DEPLOYMENT.into(),
        };
        account_policy.binding.public_key = key(2).public_key().clone();
        account_policy.binding.policy_digest = [8; 32];
        account_policy.attester_public_key = key(8).public_key().clone();
        account_policy.attester_authority.policy_digest = [8; 32];
        let mut f = Self {
            state,
            policy,
            account_policy,
            chain,
            reserve_signed: None,
            reserve_floor: None,
            fee_asset,
        };
        let configure = MutateSorafsFinalPromotionAuthority {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: 0,
            expected_control_digest: [0; 32],
            action: FinalPromotionAuthorityActionV1::Configure(
                norito::encode_canonical(&f.policy).unwrap(),
            ),
        };
        let configure_account = MutateSorafsFinalPromotionAccountCustody {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: 0,
            expected_control_digest: [0; 32],
            action: FinalPromotionAccountCustodyActionV1::Configure(
                norito::encode_canonical(&f.account_policy).unwrap(),
            ),
        };
        assert_eq!(
            f.commit(
                1_000,
                vec![
                    f.sign(configure.into(), 1, 1_000),
                    f.sign(configure_account.into(), 1, 1_000)
                ],
                true,
                true
            ),
            [true, true]
        );
        let current = f.snapshot();
        let statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: f.policy.binding.clone(),
            authority: f.policy.attester_authority.clone(),
            anchor: current.custody_anchor,
            sequence: current.control.next_sequence,
            predecessor_digest: current.control.predecessor_digest,
            issued_at_unix_ms: 1_500,
            expires_at_unix_ms: 100_000,
            evidence_digest: [12; 32],
            revoked: false,
        };
        let signature =
            Signature::try_new(key(7).private_key(), &statement.signing_payload().unwrap())
                .unwrap();
        let record = SignerCustodyRecordV1 {
            statement,
            attestation: signature.payload().try_into().unwrap(),
        };
        let enroll = f.instruction(FinalPromotionAuthorityActionV1::Enroll(
            norito::encode_canonical(&record).unwrap(),
        ));
        let account = crate::query::final_promotion_account_custody::read_final_promotion_account_custody_at_v1(
            &f.state.view(),
            &f.account_policy.binding,
            2,
        )
        .unwrap()
        .unwrap();
        let account_statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: f.account_policy.binding.clone(),
            authority: f.account_policy.attester_authority.clone(),
            anchor: account.custody_anchor,
            sequence: account.control.next_sequence,
            predecessor_digest: account.control.predecessor_digest,
            issued_at_unix_ms: 1_500,
            expires_at_unix_ms: 100_000,
            evidence_digest: [13; 32],
            revoked: false,
        };
        let account_signature = Signature::try_new(
            key(8).private_key(),
            &account_statement.signing_payload().unwrap(),
        )
        .unwrap();
        let account_record = SignerCustodyRecordV1 {
            statement: account_statement,
            attestation: account_signature.payload().try_into().unwrap(),
        };
        let enroll_account = MutateSorafsFinalPromotionAccountCustody {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: account.control_record.revision,
            expected_control_digest: account.custody_anchor.state_digest,
            action: FinalPromotionAccountCustodyActionV1::Enroll(
                norito::encode_canonical(&account_record).unwrap(),
            ),
        };
        assert_eq!(
            f.commit(
                1_500,
                vec![
                    f.sign(enroll.into(), 1, 1_500),
                    f.sign(enroll_account.into(), 1, 1_500)
                ],
                true,
                true
            ),
            [true, true]
        );
        f
    }

    pub(super) fn snapshot(&self) -> FinalPromotionAuthoritySnapshotV1 {
        super::super::super::read_final_promotion_authority_at_v1(
            &self.state.view(),
            &self.policy.binding,
            self.state.view().height() as u64,
            None,
        )
        .unwrap()
        .unwrap()
    }

    pub(super) fn instruction(
        &self,
        action: FinalPromotionAuthorityActionV1,
    ) -> MutateSorafsFinalPromotionAuthority {
        let current = self.snapshot();
        MutateSorafsFinalPromotionAuthority {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: current.control_record.revision,
            expected_control_digest: current.custody_anchor.state_digest,
            action,
        }
    }

    pub(super) fn expected(&self) -> FinalPromotionCheckExpectedV1 {
        let current = self.snapshot();
        let binding = self.policy.binding.clone();
        let custody = verify_signer_custody_use_v1(
            current.control_record.enrollment.as_deref().unwrap(),
            &binding,
            &self.policy.custody_trust(),
            &SignerCustodyUseContextV1 {
                now_unix_ms: NOW,
                anchor_observed_at_unix_ms: NOW,
                current_anchor: current.custody_anchor,
                active_head: current.control.active_head.unwrap(),
                signer_revoked: false,
                attester_revoked: false,
            },
        )
        .unwrap();
        let message = statement_message(&binding);
        let prepared = prepare_final_promotion_statement_v1(&message, &binding).unwrap();
        let request = SignerFinalPromotionRequestV1::new(
            &custody,
            &SignerFinalPromotionExpectedV1 {
                operation_id: [31; 32],
                statement_digest: signer_final_promotion_digest_v1(&message),
                statement_size: message.len() as u64,
            },
            &prepared,
        )
        .unwrap();
        let tip = self.chain.committed(self.chain.height());
        FinalPromotionCheckExpectedV1 {
            binding,
            observer: AccountId::new(key(3).public_key().clone()),
            expected_operator: AccountId::new(key(2).public_key().clone()),
            request,
            subject: FinalPromotionCheckSubjectV1::Current(current.operations.audit),
            control_revision: current.control_record.revision,
            control_digest: current.custody_anchor.state_digest,
            floor: FinalPromotionCheckFloorV1 {
                height: tip.height(),
                block_hash: *tip.block_hash().as_ref(),
                context_id: tip.id(),
            },
        }
    }

    pub(super) fn prepared(&self) -> PreparedFinalPromotionCheckV1 {
        begin_final_promotion_check_v1(
            Arc::clone(&self.state),
            self.expected(),
            Duration::from_secs(60),
        )
        .unwrap()
    }

    pub(super) fn sign(
        &self,
        instruction: InstructionBox,
        seed: u8,
        now: u64,
    ) -> SignedTransaction {
        use iroha_data_model::transaction::{
            FeeChargeKind, FeeChargeLimit, FeePaymentIntent, TransactionBuilder,
        };

        let Some(asset) = &self.fee_asset else {
            return chain_fixture::sign(&self.state, instruction, seed, now);
        };
        let signer = key(seed);
        let mut builder = TransactionBuilder::new(
            *self.state.network_id_ref(),
            AccountId::new(signer.public_key().clone()),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset.clone(),
                    2_u32.into(),
                )],
                None,
            ),
        );
        builder.set_creation_time(Duration::from_millis(now.saturating_sub(1)));
        builder
            .with_instructions([instruction])
            .try_sign(signer.private_key())
            .unwrap()
    }

    pub(super) fn pending(&self) -> PendingFinalPromotionCheckV1 {
        let prepared = self.prepared();
        let signed = self.sign(prepared.instruction().clone().into(), 3, NOW);
        prepared.bind_signed_transaction(signed).unwrap()
    }

    /// Commit `transactions` in one block at `now`. Without `membership` the State indexes them
    /// at genesis instead of their block; without `finality` the block's local `CommitQC` does
    /// not verify.
    pub(super) fn commit(
        &mut self,
        now: u64,
        transactions: Vec<SignedTransaction>,
        membership: bool,
        finality: bool,
    ) -> Vec<bool> {
        let outcomes = if finality {
            chain_fixture::commit(&mut self.chain, now, transactions.clone())
        } else {
            chain_fixture::commit_uncertified(&mut self.chain, now, transactions.clone())
        };
        if !membership {
            chain_fixture::misplace_membership(&self.chain, &transactions);
        }
        outcomes
    }
}
