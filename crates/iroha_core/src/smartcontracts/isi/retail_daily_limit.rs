//! Native first-release retail DAY activation and identity enrollment.
use super::*;
use crate::state::retail_daily_limit_state as retail_state;
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetId, RetailMonetaryPurposeV1},
    isi::{
        error::InstructionExecutionError,
        retail_daily_limit::{
            ActivateRetailDailyLimitV1, BindRetailIdentityV1, RetailMonetaryMovementV1,
        },
    },
};
use iroha_model_base::topology::DataSpaceId;
use std::collections::BTreeSet;

fn retail_reject(message: impl Into<String>) -> Error {
    InstructionExecutionError::InvariantViolation(message.into().into())
}

impl Execute for ActivateRetailDailyLimitV1 {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let definition = self.definition.clone().build(authority);
        let definition_id = definition.id();
        let policy = self.policy;
        if &policy.asset_definition_id != definition_id {
            return Err(retail_reject(
                "retail DAY activation policy differs from the fresh asset definition",
            ));
        }
        policy.validate_shape().map_err(retail_reject)?;
        if policy.revision != 1 {
            return Err(retail_reject(
                "first-release retail DAY activation requires revision one",
            ));
        }
        if !policy.institutional_exceptions.is_empty() {
            return Err(retail_reject(
                "retail DAY institutional exception admission is not implemented",
            ));
        }
        if definition.balance_scope_policy() != AssetBalancePolicy::DataspaceRestricted {
            return Err(retail_reject(
                "retail DAY activation requires a dataspace-restricted definition",
            ));
        }
        if definition.spec().scale() != Some(2) {
            return Err(retail_reject(
                "first-release PGK definition requires exact two-decimal precision",
            ));
        }
        let Some(owning_domain) = definition.owning_domain().as_ref() else {
            return Err(retail_reject(
                "retail DAY activation requires an exact owning domain",
            ));
        };
        let dataspace = policy.physical_dataspace;
        if dataspace == DataSpaceId::UNIVERSAL
            || stx.current_dataspace_id != Some(dataspace)
            || stx.world.current_dataspace_id != Some(dataspace)
            || stx
                .nexus
                .dataspace_catalog
                .by_id(dataspace)
                .is_none_or(|entry| entry.alias != owning_domain.dataspace().as_ref())
        {
            return Err(retail_reject(
                "retail DAY activation requires the exact physical dataspace lane and owning domain",
            ));
        }
        stx.world.account(&policy.identity_issuer)?;
        stx.world.account(&policy.monetary_issuer_account)?;
        stx.world.account(&policy.reserve_account)?;
        if stx.world.asset_definition(definition_id).is_ok() {
            return Err(retail_reject(
                "retail DAY activation requires an absent definition registered atomically",
            ));
        }
        if retail_state::retained_definition(stx.world(), &BTreeSet::from([definition_id.clone()]))
            .map_err(retail_reject)?
            .is_some()
        {
            return Err(retail_reject(
                "retail DAY activation cannot replace retained policy, identity or usage state",
            ));
        }
        // Validate and encode before registration; the registered definition and
        // active policy become visible in this single consensus state transaction.
        let policy_bytes =
            norito::encode_canonical(&policy).map_err(|error| retail_reject(error.to_string()))?;
        let activation =
            retail_state::activation_for_policy(&policy, stx.block_unix_timestamp_ms())
                .map_err(retail_reject)?;
        let activation_bytes = norito::encode_canonical(&activation)
            .map_err(|error| retail_reject(error.to_string()))?;
        iroha_data_model::isi::Register::asset_definition(self.definition)
            .execute(authority, stx)?;
        stx.world.smart_contract_state.insert(
            retail_state::policy_key(definition_id, dataspace),
            policy_bytes,
        );
        stx.world.smart_contract_state.insert(
            retail_state::activation_key(definition_id),
            activation_bytes,
        );
        Ok(())
    }
}

impl Execute for BindRetailIdentityV1 {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let body = &self.attestation.body;
        let dataspace = body.physical_dataspace;
        if stx.current_dataspace_id != Some(dataspace)
            || stx.world.current_dataspace_id != Some(dataspace)
        {
            return Err(retail_reject(
                "retail identity binding requires the exact physical dataspace lane",
            ));
        }
        let policy =
            retail_state::policy_for_exact(stx.world(), &body.asset_definition_id, dataspace)
                .map_err(retail_reject)?
                .ok_or_else(|| {
                    retail_reject("retail identity binding has no exact active policy")
                })?;
        retail_state::activation_for_exact(stx.world(), &policy).map_err(retail_reject)?;
        if &policy.identity_issuer != authority {
            return Err(retail_reject(
                "retail identity binding requires the policy's exact issuer account authority",
            ));
        }
        if body.account_id == policy.reserve_account {
            return Err(retail_reject(
                "retail identity binding cannot turn the monetary reserve into a retail account",
            ));
        }
        stx.world.account(&body.account_id)?;
        self.attestation
            .verify_for(&policy, &body.account_id)
            .map_err(retail_reject)?;
        let path =
            retail_state::identity_key(&body.asset_definition_id, dataspace, &body.account_id);
        if stx.world.smart_contract_state.get(&path).is_some() {
            return Err(retail_reject(
                "retail identity binding already exists and cannot be replaced in this release",
            ));
        }
        let bytes = norito::encode_canonical(&self.attestation)
            .map_err(|error| retail_reject(error.to_string()))?;
        stx.world.smart_contract_state.insert(path, bytes);
        Ok(())
    }
}

impl Execute for RetailMonetaryMovementV1 {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let dataspace = stx
            .current_dataspace_id
            .ok_or_else(|| retail_reject("retail monetary movement requires a physical lane"))?;
        if dataspace == DataSpaceId::UNIVERSAL
            || stx.world.current_dataspace_id != Some(dataspace)
            || self.operation_digest == [0; 32]
            || self.amount.is_zero()
        {
            return Err(retail_reject(
                "retail monetary movement requires its exact lane, positive amount and nonzero operation digest",
            ));
        }
        let policy =
            retail_state::policy_for_exact(stx.world(), &self.asset_definition_id, dataspace)
                .map_err(retail_reject)?
                .ok_or_else(|| retail_reject("retail monetary movement has no exact policy"))?;
        retail_state::activation_for_exact(stx.world(), &policy).map_err(retail_reject)?;
        if retail_state::monetary_operation_exists(
            stx.world(),
            &self.asset_definition_id,
            &self.operation_digest,
        ) {
            return Err(retail_reject(
                "retail monetary operation digest was already consumed",
            ));
        }
        let record =
            norito::encode_canonical(&self).map_err(|error| retail_reject(error.to_string()))?;
        let reserve = AssetId::with_scope(
            self.asset_definition_id.clone(),
            policy.reserve_account.clone(),
            AssetBalanceScope::Dataspace(dataspace),
        );
        match (self.purpose, self.retail_account.as_ref()) {
            (RetailMonetaryPurposeV1::MintToReserve, None) => {
                crate::smartcontracts::isi::asset::isi::execute_retail_reserve_mint(
                    stx,
                    authority,
                    reserve,
                    self.amount.clone(),
                )?;
            }
            (RetailMonetaryPurposeV1::BurnReserve, None) => {
                crate::smartcontracts::isi::asset::isi::execute_retail_reserve_burn(
                    stx,
                    authority,
                    reserve,
                    self.amount.clone(),
                )?;
            }
            (RetailMonetaryPurposeV1::CreditRetail, Some(retail))
                if authority == &policy.reserve_account && retail != &policy.reserve_account =>
            {
                let destination = AssetId::with_scope(
                    self.asset_definition_id.clone(),
                    retail.clone(),
                    AssetBalanceScope::Dataspace(dataspace),
                );
                crate::smartcontracts::isi::asset::isi::execute_retail_monetary_transfer(
                    stx,
                    authority,
                    reserve,
                    destination,
                    self.amount.clone(),
                    self.purpose,
                )?;
            }
            (RetailMonetaryPurposeV1::DefundRetail, Some(retail))
                if authority == retail && retail != &policy.reserve_account =>
            {
                let source = AssetId::with_scope(
                    self.asset_definition_id.clone(),
                    retail.clone(),
                    AssetBalanceScope::Dataspace(dataspace),
                );
                crate::smartcontracts::isi::asset::isi::execute_retail_monetary_transfer(
                    stx,
                    authority,
                    source,
                    reserve,
                    self.amount.clone(),
                    self.purpose,
                )?;
            }
            _ => {
                return Err(retail_reject(
                    "retail monetary purpose, authority and reserve/retail endpoints do not match",
                ));
            }
        }
        stx.world.smart_contract_state.insert(
            retail_state::monetary_operation_key(&self.asset_definition_id, &self.operation_digest),
            record,
        );
        Ok(())
    }
}

#[cfg(test)]
mod finality_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
    use iroha_data_model::{
        account::Account,
        asset::{
            AssetDefinition, AssetDefinitionId, RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1,
            RetailDailyLimitPolicyV1, RetailDailyUsageKeyV1, RetailIdentityAttestationBodyV1,
            RetailIdentityCommitmentV1,
        },
        block::BlockHeader,
        domain::Domain,
        nexus::{DataSpaceCatalog, DataSpaceMetadata},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::{NumericSpec, Quantity};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use nonzero_ext::nonzero;

    fn test_reserve_account() -> AccountId {
        let key = KeyPair::try_from_seed(vec![0x75; 32], Algorithm::Ed25519)
            .expect("test-only monetary reserve key");
        AccountId::new(key.public_key().clone())
    }

    fn fixture() -> (
        State,
        iroha_data_model::asset::NewAssetDefinition,
        RetailDailyLimitPolicyV1,
        KeyPair,
    ) {
        let domain_id = DomainId::try_new("retail", "bpng").expect("test domain");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "kina".parse().expect("asset name"),
        );
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let world = World::with(
            [domain],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
                Account::new(test_reserve_account()).build(&ALICE_ID),
            ],
            [],
        );
        let issuer = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
            .expect("test-only issuer key");
        let policy = RetailDailyLimitPolicyV1 {
            asset_definition_id: definition_id.clone(),
            physical_dataspace: DataSpaceId::new(7),
            revision: 1,
            daily_cap: Quantity::from(5_u32),
            identity_issuer: ALICE_ID.clone(),
            identity_issuer_public_key: issuer.public_key().clone(),
            monetary_issuer_account: ALICE_ID.clone(),
            reserve_account: test_reserve_account(),
            institutional_exceptions: BTreeSet::new(),
        };
        (
            State::new(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            ),
            AssetDefinition::new(
                definition_id,
                "Kina".to_owned(),
                NumericSpec::fractional(2),
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id),
            ),
            policy,
            issuer,
        )
    }

    fn set_physical_lane(stx: &mut StateTransaction<'_, '_>) {
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(7),
                alias: "bpng".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("test catalog");
        stx.nexus.dataspace_catalog = catalog.clone();
        stx.world.dataspace_catalog = catalog;
        stx.current_dataspace_id = Some(DataSpaceId::new(7));
        stx.world.current_dataspace_id = Some(DataSpaceId::new(7));
    }

    #[test]
    fn activation_is_one_shot_owner_authorized_and_registers_exact_fresh_definition() {
        let (state, definition, policy, _) = fixture();
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut stx = block.transaction();
        set_physical_lane(&mut stx);
        let instruction = ActivateRetailDailyLimitV1 {
            definition,
            policy: policy.clone(),
        };
        assert!(instruction.clone().execute(&BOB_ID, &mut stx).is_err());
        let mut wrong_precision = instruction.clone();
        wrong_precision.definition = AssetDefinition::numeric(
            policy.asset_definition_id.clone(),
            "Kina".to_owned(),
            AssetBalancePolicy::DataspaceRestricted,
            Some(DomainId::try_new("retail", "bpng").expect("test domain")),
        );
        assert!(wrong_precision.execute(&ALICE_ID, &mut stx).is_err());
        assert!(
            stx.world
                .asset_definition(&policy.asset_definition_id)
                .is_err()
        );
        assert!(
            retail_state::policy_for_exact(
                stx.world(),
                &policy.asset_definition_id,
                DataSpaceId::new(7)
            )
            .expect("canonical policy state")
            .is_none()
        );
        instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect("owner activation");
        assert!(
            stx.world
                .asset_definition(&policy.asset_definition_id)
                .is_ok()
        );
        assert_eq!(
            retail_state::policy_for_exact(
                stx.world(),
                &policy.asset_definition_id,
                DataSpaceId::new(7)
            )
            .expect("canonical policy state"),
            Some(policy.clone()),
        );
        assert_eq!(
            retail_state::activation_for_exact(stx.world(), &policy)
                .expect("exact immutable activation")
                .enforce_from_day_start_ms,
            86_400_000,
        );
        assert!(
            retail_state::has_policy_for_definition(stx.world(), &policy.asset_definition_id)
                .expect("exact activation index")
        );
        assert!(instruction.execute(&ALICE_ID, &mut stx).is_err());
        stx.world.smart_contract_state.insert(
            retail_state::policy_key(&policy.asset_definition_id, policy.physical_dataspace),
            vec![0xFF],
        );
        assert!(
            retail_state::has_policy_for_definition(stx.world(), &policy.asset_definition_id)
                .is_err()
        );
    }

    #[test]
    fn issuer_signed_binding_cannot_be_replaced_or_submitted_by_another_account() {
        let (state, definition, policy, issuer) = fixture();
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut stx = block.transaction();
        set_physical_lane(&mut stx);
        ActivateRetailDailyLimitV1 {
            definition,
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("owner activation");
        let body = RetailIdentityAttestationBodyV1 {
            domain: RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1.to_owned(),
            asset_definition_id: policy.asset_definition_id.clone(),
            physical_dataspace: policy.physical_dataspace,
            policy_revision: policy.revision,
            account_id: BOB_ID.clone(),
            identity: RetailIdentityCommitmentV1 { digest: [0xA1; 32] },
            uniqueness_evidence_digest: [0xB1; 32],
        };
        let mut reserve_body = body.clone();
        reserve_body.account_id = policy.reserve_account.clone();
        assert!(
            BindRetailIdentityV1 {
                attestation: iroha_data_model::asset::RetailIdentityAttestationV1 {
                    signature: SignatureOf::try_new(issuer.private_key(), &reserve_body)
                        .expect("test-only reserve signature"),
                    body: reserve_body,
                },
            }
            .execute(&ALICE_ID, &mut stx)
            .is_err()
        );
        let attestation = iroha_data_model::asset::RetailIdentityAttestationV1 {
            signature: SignatureOf::try_new(issuer.private_key(), &body)
                .expect("test-only signed binding"),
            body,
        };
        let instruction = BindRetailIdentityV1 { attestation };
        assert!(instruction.clone().execute(&BOB_ID, &mut stx).is_err());
        instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect("issuer binding");
        assert!(instruction.execute(&ALICE_ID, &mut stx).is_err());
    }

    #[test]
    fn exact_monetary_purposes_fund_retail_and_reject_generic_reserve_paths() {
        let (state, definition, policy, issuer) = fixture();
        let reserve_account = policy.reserve_account.clone();
        let reserve = AssetId::with_scope(
            policy.asset_definition_id.clone(),
            reserve_account.clone(),
            AssetBalanceScope::Dataspace(policy.physical_dataspace),
        );
        let retail = AssetId::with_scope(
            policy.asset_definition_id.clone(),
            BOB_ID.clone(),
            AssetBalanceScope::Dataspace(policy.physical_dataspace),
        );
        {
            let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut stx = block.transaction();
            set_physical_lane(&mut stx);
            ActivateRetailDailyLimitV1 {
                definition,
                policy: policy.clone(),
            }
            .execute(&ALICE_ID, &mut stx)
            .expect("fresh owner activation");
            let body = RetailIdentityAttestationBodyV1 {
                domain: RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1.to_owned(),
                asset_definition_id: policy.asset_definition_id.clone(),
                physical_dataspace: policy.physical_dataspace,
                policy_revision: policy.revision,
                account_id: BOB_ID.clone(),
                identity: RetailIdentityCommitmentV1 { digest: [0xA1; 32] },
                uniqueness_evidence_digest: [0xB1; 32],
            };
            BindRetailIdentityV1 {
                attestation: iroha_data_model::asset::RetailIdentityAttestationV1 {
                    signature: SignatureOf::try_new(issuer.private_key(), &body)
                        .expect("test-only signed binding"),
                    body,
                },
            }
            .execute(&ALICE_ID, &mut stx)
            .expect("retail binding");
            stx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("persist activation for next UTC day");
        }
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 86_400_000, 0));
        let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
        set_physical_lane(&mut stx);
        let movement = |purpose, retail_account, amount: u32, digest| RetailMonetaryMovementV1 {
            asset_definition_id: policy.asset_definition_id.clone(),
            purpose,
            retail_account,
            amount: Quantity::from(amount),
            operation_digest: [digest; 32],
        };
        assert!(
            movement(RetailMonetaryPurposeV1::MintToReserve, None, 20, 0x11)
                .execute(&reserve_account, &mut stx)
                .is_err()
        );
        movement(RetailMonetaryPurposeV1::MintToReserve, None, 20, 0x11)
            .execute(&ALICE_ID, &mut stx)
            .expect("issuer mints only into reserve");
        assert!(
            Mint::asset_quantity(1_u32, reserve.clone())
                .execute(&ALICE_ID, &mut stx)
                .is_err()
        );
        assert!(
            Transfer::asset_quantity(reserve.clone(), 1_u32, BOB_ID.clone())
                .execute(&reserve_account, &mut stx)
                .is_err()
        );
        assert!(
            movement(
                RetailMonetaryPurposeV1::CreditRetail,
                Some(BOB_ID.clone()),
                10,
                0x12,
            )
            .execute(&BOB_ID, &mut stx)
            .is_err()
        );
        movement(
            RetailMonetaryPurposeV1::CreditRetail,
            Some(BOB_ID.clone()),
            10,
            0x12,
        )
        .execute(&reserve_account, &mut stx)
        .expect("reserve credits bound retail destination");
        assert!(
            movement(
                RetailMonetaryPurposeV1::CreditRetail,
                Some(BOB_ID.clone()),
                10,
                0x12,
            )
            .execute(&reserve_account, &mut stx)
            .is_err()
        );
        assert!(
            movement(
                RetailMonetaryPurposeV1::CreditRetail,
                Some(ALICE_ID.clone()),
                1,
                0x13,
            )
            .execute(&reserve_account, &mut stx)
            .is_err()
        );
        assert!(
            Transfer::asset_quantity(retail.clone(), 1_u32, reserve_account.clone())
                .execute(&BOB_ID, &mut stx)
                .is_err()
        );
        movement(
            RetailMonetaryPurposeV1::DefundRetail,
            Some(BOB_ID.clone()),
            1,
            0x14,
        )
        .execute(&BOB_ID, &mut stx)
        .expect("bound retail defund debits its identity bucket");
        let usage_key = RetailDailyUsageKeyV1 {
            asset_definition_id: policy.asset_definition_id.clone(),
            physical_dataspace: policy.physical_dataspace,
            identity: RetailIdentityCommitmentV1 { digest: [0xA1; 32] },
            utc_day_start_ms: 86_400_000,
        };
        assert_eq!(
            retail_state::usage_for_exact(stx.world(), &usage_key).expect("canonical DAY usage"),
            Some(Quantity::one())
        );
        assert!(
            movement(
                RetailMonetaryPurposeV1::DefundRetail,
                Some(BOB_ID.clone()),
                5,
                0x17,
            )
            .execute(&BOB_ID, &mut stx)
            .is_err()
        );
        assert!(
            Burn::asset_quantity(1_u32, reserve.clone())
                .execute(&ALICE_ID, &mut stx)
                .is_err()
        );
        movement(RetailMonetaryPurposeV1::BurnReserve, None, 1, 0x15)
            .execute(&ALICE_ID, &mut stx)
            .expect("issuer retires exact reserve supply");
        assert_eq!(
            stx.world
                .assets
                .get(&retail)
                .map(|balance| balance.as_ref().clone()),
            Some(Quantity::from(9_u32))
        );
        assert_eq!(
            stx.world
                .assets
                .get(&reserve)
                .map(|balance| balance.as_ref().clone()),
            Some(Quantity::from(10_u32))
        );
    }
}
