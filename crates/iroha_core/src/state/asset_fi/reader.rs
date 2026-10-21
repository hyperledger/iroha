//! Exact revision of an owner-approved FI link, visible only to its active controller.

use super::*;
use crate::{
    executor::ContractRuntimeExecutionContext,
    smartcontracts::isi::query::{QueryExecutionBudget, QueryExecutionStats},
};
use iroha_data_model::query::error::QueryExecutionFail;

/// Preserve deterministic policy/query refusal separately from local resource deferral.
#[derive(Debug)]
pub(crate) enum AssetFiLinkRevisionError {
    Execution(InstructionExecutionError),
    Query(QueryExecutionFail),
    Local(crate::execution_attempt::ExecutionDeferred),
}

impl From<InstructionExecutionError> for AssetFiLinkRevisionError {
    fn from(value: InstructionExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<QueryExecutionFail> for AssetFiLinkRevisionError {
    fn from(value: QueryExecutionFail) -> Self {
        Self::Query(value)
    }
}

fn metered_read<T>(
    world: &impl WorldReadOnly,
    key: &StatePath,
    budget: QueryExecutionBudget,
    stats: &mut QueryExecutionStats,
) -> Result<T, AssetFiLinkRevisionError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    // Charge the lookup, then its exact retained bytes before any canonical decode.
    stats.record_item(key, Some(budget))?;
    let bytes = world
        .smart_contract_state()
        .get(key)
        .ok_or_else(|| reject("current owner-approved FI relationship is unavailable"))?;
    let length = u64::try_from(bytes.len()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    stats.record_preflighted_item(length, Some(budget))?;
    let allocation =
        usize::try_from(budget.remaining_bytes(stats.processed_items(), stats.processed_bytes())?)
            .map_err(|_| QueryExecutionFail::CapacityLimit)?;
    let elements = bytes
        .len()
        .checked_mul(8)
        .ok_or(QueryExecutionFail::CapacityLimit)?;
    let limits = norito::DecodeLimits::new(elements, bytes.len(), elements, allocation, 64);
    norito::decode_canonical_for_admission(bytes, limits).map_err(|error| {
        match error.into_local_refusal() {
            Ok(original) => AssetFiLinkRevisionError::Local(original.into()),
            Err(error) if error.error().is_decode_resource_limit() => {
                AssetFiLinkRevisionError::Query(QueryExecutionFail::GasBudgetExceeded)
            }
            Err(_) => {
                AssetFiLinkRevisionError::Execution(reject("invalid canonical FI relationship"))
            }
        }
    })
}

/// Return a CAS hint, never a transfer capability or a participant bank reference.
///
/// Only the exact currently installed frame named by the wallet owner's enabled
/// link may read it. FI eligibility and attestation remain current and revision-bound.
pub(crate) fn link_revision_for_contract(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    context: &ContractRuntimeExecutionContext,
    definition: &AssetDefinitionId,
    account: &AccountId,
    expected_fi: &AccountId,
    budget: QueryExecutionBudget,
) -> Result<(u64, QueryExecutionStats), AssetFiLinkRevisionError> {
    let mut stats = QueryExecutionStats::default();
    stats.record_item(&context.contract_address, Some(budget))?;
    if !crate::executor::valid_contract_runtime_subject(world, authority, Some(context)) {
        return Err(reject("FI revision read requires its exact active contract runtime").into());
    }
    stats.record_item(definition, Some(budget))?;
    let asset = world
        .asset_definition(definition)
        .map_err(InstructionExecutionError::from)?;
    if asset.balance_scope_policy() != iroha_data_model::asset::AssetBalancePolicy::Global {
        return Err(reject("FI revision read requires a Global asset").into());
    }
    stats.record_item(account, Some(budget))?;
    world
        .account(account)
        .map_err(InstructionExecutionError::from)?;
    let link: AssetFiLinkV1 =
        metered_read(world, &link_key(definition, account), budget, &mut stats)?;
    validate_link_shape(&link)?;
    if link.asset_definition_id != *definition
        || link.account_id != *account
        || !link.enabled
        || link.controller.as_ref() != Some(&context.contract_address)
        || link.fi_account_id != *expected_fi
    {
        return Err(
            reject("FI revision read requires the exact current owner's controller grant").into(),
        );
    }
    stats.record_item(&link.fi_account_id, Some(budget))?;
    world
        .account(&link.fi_account_id)
        .map_err(InstructionExecutionError::from)?;
    let fi: AssetFiV1 = metered_read(
        world,
        &fi_key(definition, &link.fi_account_id),
        budget,
        &mut stats,
    )?;
    if fi.asset_definition_id != *definition
        || fi.fi_account_id != link.fi_account_id
        || !fi.enabled
        || fi.revision == 0
        || fi.revision != link.fi_revision
    {
        return Err(reject("linked FI eligibility was revoked or revised").into());
    }
    let attestation: AssetFiLinkAttestationV1 = metered_read(
        world,
        &attestation_key(
            definition,
            account,
            &link.fi_account_id,
            &link.reference_digest,
        ),
        budget,
        &mut stats,
    )?;
    if attestation.asset_definition_id != *definition
        || attestation.account_id != *account
        || attestation.fi_account_id != link.fi_account_id
        || attestation.reference_digest != link.reference_digest
        || !attestation.enabled
        || attestation.revision == 0
        || attestation.revision != link.attestation_revision
    {
        return Err(reject("linked FI reference approval was revoked or revised").into());
    }
    stats.record_response(&link.revision, Some(budget))?;
    Ok((link.revision, stats))
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
        asset::{AssetBalancePolicy, AssetDefinition},
        prelude::{Account, BlockHeader, Domain},
        smart_contract::ContractAddress,
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use std::num::NonZeroU64;

    // Native read fixture only. Direct retained-row setup exercises readers and
    // tampering refusals; it is not an owner-signature/admission qualification.
    pub(crate) struct Fixture {
        pub(crate) owner: AccountId,
        pub(crate) wallet: AccountId,
        pub(crate) bank: AccountId,
        pub(crate) other: AccountId,
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
    pub(crate) fn ample_budget() -> QueryExecutionBudget {
        QueryExecutionBudget::from_weighted_limit(10_000_000, 7, 3)
    }
    impl Fixture {
        pub(crate) fn new() -> (Self, State) {
            let owner = account(31);
            let wallet = account(32);
            let bank = account(33);
            let other = account(34);
            let domain_id = DomainId::try_new("revision", "universal").unwrap();
            let definition =
                AssetDefinitionId::derive_from_components(domain_id.clone(), "ds".parse().unwrap());
            let domain = Domain::new(domain_id).build(&owner);
            let asset = AssetDefinition::numeric(
                definition.clone(),
                "DS",
                AssetBalancePolicy::Global,
                None,
            )
            .build(&owner);
            let world = World::with(
                [domain],
                [&owner, &wallet, &bank, &other]
                    .into_iter()
                    .map(|id| Account::new(id.clone()).build(&owner)),
                [asset],
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
                ContractAddress::derive(state.network_id_ref(), &owner, 17, DataSpaceId::UNIVERSAL)
                    .unwrap();
            let context = ContractRuntimeExecutionContext {
                contract_subject: address.subject_id(),
                contract_address: address,
                contract_alias: None,
                entrypoint: "revision".into(),
            };
            (
                Self {
                    owner,
                    wallet,
                    bank,
                    other,
                    definition,
                    context,
                },
                state,
            )
        }
        pub(crate) fn fi(&self) -> AssetFiV1 {
            AssetFiV1 {
                asset_definition_id: self.definition.clone(),
                fi_account_id: self.bank.clone(),
                revision: 7,
                enabled: true,
            }
        }
        pub(crate) fn attestation(&self) -> AssetFiLinkAttestationV1 {
            AssetFiLinkAttestationV1 {
                asset_definition_id: self.definition.clone(),
                account_id: self.wallet.clone(),
                fi_account_id: self.bank.clone(),
                reference_digest: [9; 32],
                revision: 11,
                enabled: true,
            }
        }
        pub(crate) fn link(&self) -> AssetFiLinkV1 {
            AssetFiLinkV1 {
                asset_definition_id: self.definition.clone(),
                account_id: self.wallet.clone(),
                fi_account_id: self.bank.clone(),
                reference_digest: [9; 32],
                fi_revision: 7,
                attestation_revision: 11,
                revision: u64::MAX,
                enabled: true,
                controller: Some(self.context.contract_address.clone()),
                waterfall: true,
                reverse_waterfall: false,
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
        pub(crate) fn install(&self, tx: &mut StateTransaction<'_, '_>) {
            tx.world.bind_active_contract_subject_for_testing(
                self.context.contract_address.clone(),
                Hash::new(b"reader-fixture"),
            );
            Self::put(tx, fi_key(&self.definition, &self.bank), &self.fi());
            Self::put(
                tx,
                attestation_key(&self.definition, &self.wallet, &self.bank, &[9; 32]),
                &self.attestation(),
            );
            Self::put(tx, link_key(&self.definition, &self.wallet), &self.link());
        }
        pub(crate) fn read(
            &self,
            world: &impl WorldReadOnly,
        ) -> Result<(u64, QueryExecutionStats), AssetFiLinkRevisionError> {
            link_revision_for_contract(
                world,
                &self.context.contract_subject,
                &self.context,
                &self.definition,
                &self.wallet,
                &self.bank,
                ample_budget(),
            )
        }
    }

    #[test]
    fn fi_revision_returns_current_exact_owner_grant_and_full_unsigned_revision() {
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
        let (revision, stats) = f.read(tx.world()).unwrap();
        assert_eq!(revision, u64::MAX);
        assert_eq!(stats.processed_items(), 10);
        assert!(stats.processed_bytes() > 0);
        assert_eq!(
            before,
            tx.world
                .smart_contract_state
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        );
        let mut current = f.link();
        current.revision = 17;
        Fixture::put(&mut tx, link_key(&f.definition, &f.wallet), &current);
        assert_eq!(
            f.read(tx.world()).unwrap().0,
            17,
            "never reuse the creation-time revision"
        );
        // Equality checks do not grant destination selection or disclose the native FI.
        assert!(
            link_revision_for_contract(
                tx.world(),
                &f.context.contract_subject,
                &f.context,
                &f.definition,
                &f.wallet,
                &f.other,
                ample_budget()
            )
            .is_err()
        );
    }

    #[test]
    fn fi_revision_refuses_disabled_foreign_stale_or_malformed_relationships() {
        for defect in 0..18 {
            let (f, state) = Fixture::new();
            let mut block = state.block(header());
            let mut tx = block.transaction();
            f.install(&mut tx);
            let mut link = f.link();
            let mut bank = f.fi();
            let mut attestation = f.attestation();
            match defect {
                0 => link.enabled = false,
                1 => link.controller = None,
                2 => {
                    link.controller = Some(
                        ContractAddress::derive(
                            state.network_id_ref(),
                            &f.owner,
                            18,
                            DataSpaceId::UNIVERSAL,
                        )
                        .unwrap(),
                    )
                }
                3 => link.revision = 0,
                4 => link.account_id = f.other.clone(),
                5 => link.fi_revision = 8,
                6 => link.attestation_revision = 12,
                7 => bank.enabled = false,
                8 => bank.revision = 8,
                9 => bank.fi_account_id = f.other.clone(),
                10 => attestation.enabled = false,
                11 => attestation.revision = 12,
                12 => attestation.reference_digest = [8; 32],
                13 => attestation.account_id = f.other.clone(),
                14 => attestation.fi_account_id = f.other.clone(),
                15 => link.reference_digest = [0; 32],
                16 => bank.revision = 0,
                17 => attestation.revision = 0,
                _ => unreachable!(),
            }
            Fixture::put(&mut tx, link_key(&f.definition, &f.wallet), &link);
            Fixture::put(&mut tx, fi_key(&f.definition, &f.bank), &bank);
            Fixture::put(
                &mut tx,
                attestation_key(&f.definition, &f.wallet, &f.bank, &[9; 32]),
                &attestation,
            );
            assert!(f.read(tx.world()).is_err(), "relationship defect {defect}");
        }
    }

    #[test]
    fn fi_revision_requires_installed_exact_subject_not_human_authority_fallback() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        assert!(
            link_revision_for_contract(
                tx.world(),
                &f.owner,
                &f.context,
                &f.definition,
                &f.wallet,
                &f.bank,
                ample_budget()
            )
            .is_err()
        );
        let mut forged = f.context.clone();
        forged.contract_subject = f.owner.clone();
        assert!(
            link_revision_for_contract(
                tx.world(),
                &f.owner,
                &forged,
                &f.definition,
                &f.wallet,
                &f.bank,
                ample_budget()
            )
            .is_err()
        );
        tx.world
            .contract_instances
            .remove(f.context.contract_address.clone());
        assert!(f.read(tx.world()).is_err());
    }

    #[test]
    fn fi_revision_budget_and_exact_canonical_decoding_fail_before_unbounded_parse() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        let key = link_key(&f.definition, &f.wallet);
        tx.world
            .smart_contract_state
            .insert(key.clone(), vec![0xff; 32 * 1024]);
        let mut stats = QueryExecutionStats::default();
        let error = metered_read::<AssetFiLinkV1>(
            tx.world(),
            &key,
            QueryExecutionBudget::from_weighted_limit(512, 7, 3),
            &mut stats,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AssetFiLinkRevisionError::Query(QueryExecutionFail::GasBudgetExceeded)
        ));
        assert!(
            stats.processed_bytes() < 32 * 1024,
            "oversized source refused before decode"
        );
        Fixture::put(&mut tx, key.clone(), &f.link());
        let mut bytes = tx.world.smart_contract_state.get(&key).unwrap().clone();
        bytes.push(0);
        tx.world.smart_contract_state.insert(key, bytes);
        assert!(
            f.read(tx.world()).is_err(),
            "trailing bytes cannot enter canonical FI state"
        );
        assert!(
            link_revision_for_contract(
                tx.world(),
                &f.context.contract_subject,
                &f.context,
                &f.definition,
                &f.wallet,
                &f.bank,
                QueryExecutionBudget::from_weighted_limit(0, 7, 3)
            )
            .is_err()
        );
    }
    #[test]
    fn fi_revision_requires_every_retained_row_and_exact_asset_keys() {
        for defect in 0..6 {
            let (f, state) = Fixture::new();
            let mut block = state.block(header());
            let mut tx = block.transaction();
            f.install(&mut tx);
            let keys = [
                link_key(&f.definition, &f.wallet),
                fi_key(&f.definition, &f.bank),
                attestation_key(&f.definition, &f.wallet, &f.bank, &[9; 32]),
            ];
            if defect < 3 {
                tx.world.smart_contract_state.remove(keys[defect].clone());
            } else {
                let other = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("revision", "universal").unwrap(),
                    "other".parse().unwrap(),
                );
                match defect {
                    3 => {
                        let mut value = f.link();
                        value.asset_definition_id = other;
                        Fixture::put(&mut tx, keys[0].clone(), &value);
                    }
                    4 => {
                        let mut value = f.fi();
                        value.asset_definition_id = other;
                        Fixture::put(&mut tx, keys[1].clone(), &value);
                    }
                    5 => {
                        let mut value = f.attestation();
                        value.asset_definition_id = other;
                        Fixture::put(&mut tx, keys[2].clone(), &value);
                    }
                    _ => unreachable!(),
                }
            }
            assert!(
                f.read(tx.world()).is_err(),
                "missing/cross-asset row {defect}"
            );
        }
    }
}
