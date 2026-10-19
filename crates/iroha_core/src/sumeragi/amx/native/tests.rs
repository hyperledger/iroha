//! Paid native participants over independent signed roots, genuine record archives and replay.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::Account,
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    isi::{
        Grant, InstructionBox, Mint, Register, Transfer, Unregister,
        sumeragi_amx::{BeginAmxV1, RegisterAmxDataspaceV1, RelayAmxPreparedV1},
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    sumeragi_amx::{AmxRecordKind, AmxTransactionV1, AmxTransferLegV1, AmxVoteV1},
    sumeragi_finality::authenticated_genesis,
};
use iroha_model_base::{chain::ChainId, domain::DomainId};
use iroha_primitives::numeric::{Numeric, Quantity};

const FIRST: DataSpaceId = DataSpaceId::new((1_u64 << 40) + 117);
const SECOND: DataSpaceId = DataSpaceId::new((1_u64 << 40) + 118);

fn payer() -> KeyPair {
    KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519)
}
fn receiver() -> KeyPair {
    KeyPair::from_seed(vec![0x52; 32], Algorithm::Ed25519)
}
fn account(key: &KeyPair) -> AccountId {
    AccountId::new(key.public_key().clone())
}
fn principal() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("amx", "private-amx").unwrap(),
        "principal".parse().unwrap(),
    )
}
fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}
fn global_config() -> TestChainConfig {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.genesis_instructions.push(
        Grant::account_permission(
            iroha_executor_data_model::permission::parameter::CanSetParameters,
            account(&config.genesis_key),
        )
        .into(),
    );
    config
}

fn private_config(global: &CertifiedTestChain, id: DataSpaceId) -> TestChainConfig {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.chain_id = ChainId::from("native-amx-private-root");
    config.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: global.network_id(),
        dataspace_id: id,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.lane_catalog = LaneCatalog::new(
        1_u32.try_into().unwrap(),
        vec![LaneConfig {
            dataspace_id: id,
            alias: "private-amx".into(),
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id,
        alias: "private-amx".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = id;
    nexus.fees.fee_asset_id = fee_asset().clone();
    nexus.fees.fee_sink_account_id = account(&config.genesis_key).clone();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::block::consensus::RootFeePolicy {
                fee_asset_id: fee_asset(),
                base_fee: 1_u32.into(),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: 1_u32.into(),
                per_gas_unit_fee: 1_u32.into(),
                ..iroha_config::parameters::defaults::nexus::fees::genesis_policy()
            }
            .into_custom_parameter()
            .unwrap(),
        ));
    let gas = iroha_config::parameters::actual::Gas {
        tech_account_id: account(&config.genesis_key).to_string(),
        accepted_assets: vec![fee_asset().canonical_address()],
        units_per_gas: vec![iroha_config::parameters::actual::GasRate {
            asset: fee_asset().canonical_address(),
            units_per_gas: 1,
            twap_local_per_xor: Numeric::one(),
            liquidity: iroha_config::parameters::actual::GasLiquidity::Tier2,
            volatility: iroha_config::parameters::actual::GasVolatility::Stable,
        }],
    };
    config
        .genesis_parameters
        .extend(crate::pipeline_gas_policy::parameters_for_testing(gas));
    let domain = DomainId::try_new("amx", "private-amx").unwrap();
    config.genesis_instructions = vec![
        Register::account(Account::new(account(&payer()))).into(),
        Register::account(Account::new(account(&receiver()))).into(),
        Register::domain(iroha_data_model::domain::Domain::new(domain.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "AMX fee",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain.clone()),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            principal(),
            "AMX principal",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        ))
        .into(),
        Mint::asset_quantity(
            1_000_000_u32,
            AssetId::with_scope(
                fee_asset(),
                account(&payer()),
                AssetBalanceScope::Dataspace(id),
            ),
        )
        .into(),
        Mint::asset_quantity(
            1_000_000_u32,
            AssetId::with_scope(
                fee_asset(),
                account(&receiver()),
                AssetBalanceScope::Dataspace(id),
            ),
        )
        .into(),
        Mint::asset_quantity(
            1_000_u32,
            AssetId::with_scope(
                principal(),
                account(&payer()),
                AssetBalanceScope::Dataspace(id),
            ),
        )
        .into(),
        RegisterAmxParticipantV1 {
            dataspace: id,
            global_chain_id: global_config().chain_id,
            global_genesis: global.committed(1).block().encode_wire().unwrap(),
            global_successor: global.committed(2).block().encode_wire().unwrap(),
        }
        .into(),
    ];
    // Every ordinary private fixture transaction, including clock work and negative controls,
    // pays the real signed private fee policy from its own restricted balance partition.
    for key in [
        config.genesis_key.clone(),
        KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519),
    ] {
        config.genesis_instructions.push(
            Mint::asset_quantity(
                1_000_000_u32,
                AssetId::with_scope(fee_asset(), account(&key), AssetBalanceScope::Dataspace(id)),
            )
            .into(),
        );
    }
    config
}

struct Roots {
    global: CertifiedTestChain,
    participants: [CertifiedTestChain; 2],
}
impl Roots {
    fn new() -> Self {
        Self::new_with_optional_time_source(None)
    }

    fn new_with_time_source(time_source: iroha_primitives::time::TimeSource) -> Self {
        Self::new_with_optional_time_source(Some(time_source))
    }

    fn new_with_optional_time_source(
        time_source: Option<iroha_primitives::time::TimeSource>,
    ) -> Self {
        let start = |config| {
            let prepared = CertifiedTestChain::prepare(config).unwrap();
            if let Some(source) = &time_source {
                CertifiedTestChain::from_prepared_with_time_source(prepared, source.clone())
            } else {
                CertifiedTestChain::from_prepared(prepared)
            }
            .unwrap()
        };
        let mut global = start(global_config());
        let first = global.sign(
            &global_config().genesis_key,
            [iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                "authenticate native AMX global genesis".into(),
            )
            .into()],
            1_499,
        );
        assert_eq!(global.commit_at(1_500, vec![first]), vec![true]);
        let participants = [FIRST, SECOND].map(|id| start(private_config(&global, id)));
        assert_ne!(participants[0].network_id(), participants[1].network_id());
        assert!(
            !participants[0]
                .state()
                .ivm_execution_budget()
                .same_pool(&participants[1].state().ivm_execution_budget())
        );
        assert_ne!(
            participants[0].kura().store_root(),
            participants[1].kura().store_root()
        );
        let registrations = [FIRST, SECOND]
            .into_iter()
            .zip(&participants)
            .map(|(id, chain)| {
                RegisterAmxDataspaceV1 {
                    dataspace: id,
                    instance: chain.instance().0,
                    anchor: norito::encode_canonical(
                        &authenticated_genesis(chain.genesis())
                            .map(|genesis| genesis.into_parts().0)
                            .unwrap(),
                    )
                    .unwrap(),
                }
                .into()
            })
            .collect::<Vec<InstructionBox>>();
        let signed_payload = global.sign(&global_config().genesis_key, registrations, 1_999);
        assert_eq!(global.commit_at(2_000, vec![signed_payload]), vec![true]);
        Self {
            global,
            participants,
        }
    }
    fn transaction(&self, amount: u32, nonce: u8) -> AmxTransactionV1 {
        AmxTransactionV1 {
            legs: [FIRST, SECOND]
                .into_iter()
                .map(|id| AmxLegV1 {
                    dataspace: id,
                    payload: norito::encode_canonical(&AmxTransferLegV1 {
                        source: AssetId::with_scope(
                            principal(),
                            account(&payer()),
                            AssetBalanceScope::Dataspace(id),
                        ),
                        destination: account(&receiver()),
                        amount: amount.into(),
                    })
                    .unwrap(),
                })
                .collect(),
            deadline: self.global.height() + 20,
            // The original signed-genesis cadence bounds this exact intent; later handoffs
            // authenticate its historical decision rather than extending the deadline.
            expires_at_ms: self
                .global
                .committed(self.global.height())
                .block_time_ms()
                .checked_add(
                    iroha_data_model::sumeragi_amx::amx_max_time_window_ms(
                        self.global
                            .state()
                            .view()
                            .world()
                            .parameters()
                            .sumeragi()
                            .block_cadence_ms()
                            .get(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            nonce: [nonce; 32],
        }
    }
    fn approval(
        &self,
        index: usize,
        transaction: &AmxTransactionV1,
    ) -> iroha_data_model::sumeragi_amx::AmxDebitApprovalV1 {
        let dataspace = [FIRST, SECOND][index];
        let transfer: AmxTransferLegV1 =
            norito::decode_canonical(&transaction.leg(dataspace).unwrap().payload).unwrap();
        iroha_data_model::sumeragi_amx::AmxDebitApprovalV1 {
            global_network: self.global.network_id(),
            participant_network: self.participants[index].network_id(),
            participant_instance: self.participants[index].instance().0,
            dataspace,
            transaction_id: transaction.id().unwrap(),
            debited_asset: transfer.source,
        }
    }
    // Real owner-signed work precedes the final Begin. A carrier signature alone is never consent.
    fn approve(
        &mut self,
        index: usize,
        transaction: &AmxTransactionV1,
        relay: AccountId,
        timestamp_ms: u64,
    ) {
        let approval = self.approval(index, transaction);
        assert_eq!(approval.debited_asset.account(), &account(&payer()));
        let chain = &mut self.participants[index];
        let timestamp_ms = timestamp_ms.max(chain.committed(chain.height()).block_time_ms() + 1);
        let signed = chain.sign(
            &payer(),
            [iroha_data_model::isi::Grant::account_permission(
                approval.permission().unwrap(),
                relay,
            )
            .into()],
            timestamp_ms - 1,
        );
        let outcomes = chain.commit_at(timestamp_ms, vec![signed]);
        assert_eq!(
            outcomes,
            vec![true],
            "actual debit owner grants the exact native AMX intent: {:?}",
            chain
                .committed(chain.height())
                .block()
                .network_output_at(0)
                .map(|(_, output)| &output.result)
        );
    }
    fn approve_all(&mut self, transaction: &AmxTransactionV1) {
        for index in 0..2 {
            self.approve(index, transaction, account(&payer()), 2_500);
        }
    }
    fn begin(
        &mut self,
        transaction: &AmxTransactionV1,
    ) -> iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1 {
        self.approve_all(transaction);
        let signed_payload = self.global.sign(
            &global_config().genesis_key,
            [BeginAmxV1 {
                transaction: transaction.clone(),
            }
            .into()],
            2_999,
        );
        assert_eq!(
            self.global.commit_at(3_000, vec![signed_payload]),
            vec![true]
        );
        super::super::amx_record_proof(
            &self.global.state().view(),
            self.global.height(),
            AmxRecordKind::Begin,
            transaction.id().unwrap(),
        )
        .complete()
        .unwrap()
        .unwrap()
    }
    fn prepare(
        &mut self,
        index: usize,
        transaction: &AmxTransactionV1,
        begin: &iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1,
    ) -> iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1 {
        self.prepare_at(index, transaction, begin, 4_000)
    }
    fn prepare_at(
        &mut self,
        index: usize,
        transaction: &AmxTransactionV1,
        begin: &iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1,
        timestamp_ms: u64,
    ) -> iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1 {
        let id = [FIRST, SECOND][index];
        let chain = &mut self.participants[index];
        let signed_payload = chain.sign(
            &payer(),
            [begin
                .try_copy(&self.global.state().ivm_execution_budget())
                .unwrap()
                .into_prepare(id, transaction)
                .complete(&self.global.state().ivm_execution_budget())
                .unwrap()],
            timestamp_ms.checked_sub(1).unwrap(),
        );
        assert_eq!(
            chain.commit_at(timestamp_ms, vec![signed_payload]),
            vec![true]
        );
        let proof = super::super::amx_record_proof(
            &chain.state().view(),
            chain.height(),
            AmxRecordKind::Prepared,
            transaction.id().unwrap(),
        )
        .complete()
        .unwrap()
        .unwrap();
        assert!(
            !proof.canonical().block.commit_qc.is_empty(),
            "original signed certificate"
        );
        proof
    }
    fn decide(
        &mut self,
        proofs: impl IntoIterator<Item = iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1>,
        tx: [u8; 32],
    ) -> iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1 {
        let signed_payload = self.global.sign(
            &global_config().genesis_key,
            proofs.into_iter().map(|proof| {
                let AmxRecordV1::Prepared(record) = &proof.canonical().record else {
                    panic!("original participant Prepared proof");
                };
                let index = [FIRST, SECOND]
                    .iter()
                    .position(|id| *id == record.participant)
                    .unwrap();
                proof
                    .into_relay()
                    .complete(&self.participants[index].state().ivm_execution_budget())
                    .unwrap()
            }),
            4_999,
        );
        assert_eq!(
            self.global.commit_at(5_000, vec![signed_payload]),
            vec![true]
        );
        super::super::amx_record_proof(
            &self.global.state().view(),
            self.global.height(),
            AmxRecordKind::Decision,
            tx,
        )
        .complete()
        .unwrap()
        .unwrap()
    }
}

fn balance(
    chain: &CertifiedTestChain,
    id: DataSpaceId,
    definition: AssetDefinitionId,
    owner: AccountId,
) -> Quantity {
    chain
        .state()
        .view()
        .world()
        .assets()
        .get(&AssetId::with_scope(
            definition,
            owner,
            AssetBalanceScope::Dataspace(id),
        ))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}
fn native(chain: &CertifiedTestChain) -> NativeAmxParticipantStateV1 {
    chain
        .state()
        .view()
        .world()
        .sumeragi_amx_participant()
        .canonical()
        .unwrap()
        .clone()
}

#[inline(never)]
fn check_paid_effects_at_original_pool_capacity(chain: &CertifiedTestChain) {
    // The actual signed Prepare left this authenticated escrow in its original State pool.
    let view = chain.state().view();
    let owner = view.world().sumeragi_amx_participant();
    let budget = chain.state().ivm_execution_budget();
    assert!(owner.is_authenticated());
    assert!(owner.belongs_to(&budget));
    let original = owner.canonical().unwrap();
    assert_eq!(original.escrows.len(), 1);
    let record = &original.escrows[0];
    assert_eq!(record.leg.amount, Quantity::from(100_u32));
    let pointer = std::ptr::from_ref(&record.leg);
    let frame = norito::encode_canonical(&record.leg).unwrap();
    let expected: [u8; 32] =
        iroha_crypto::Hash::new_from_chunks(&[b"iroha:native-amx-transfer:v1", &[0], &frame])
            .into();
    let reader = owner.clone();
    assert!(std::ptr::eq(reader.canonical().unwrap(), original));
    let retained = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    budget.set_limit_bytes(retained);
    let actual = iroha_data_model::sumeragi_amx::native_transfer_effects_hash(&record.leg);
    budget.set_limit_bytes(limit);
    assert_eq!(actual.unwrap(), expected);
    assert_eq!(expected, record.effects_hash);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        std::ptr::from_ref(&reader.canonical().unwrap().escrows[0].leg),
        pointer
    );
    drop(reader);
    assert_eq!(budget.reserved_bytes(), retained);
}

#[test]
fn native_amx_paid_commit_survives_certified_restart_and_rejects_bypass() {
    let mut roots = Roots::new();
    let transaction = roots.transaction(100, 1);
    let begin = roots.begin(&transaction);
    // HC95: a valid foreign Begin never authorizes a different signed debit source.
    let thief = roots.participants[0].sign(
        &receiver(),
        [PrepareAmxV1 {
            dataspace: FIRST,
            transaction: transaction.clone(),
            begin: begin.canonical().clone(),
        }
        .into()],
        3_500,
    );
    assert_eq!(
        roots.participants[0].commit_at(3_600, vec![thief]),
        vec![false]
    );
    assert_eq!(
        balance(
            &roots.participants[0],
            FIRST,
            principal(),
            account(&payer())
        ),
        1_000_u32.into()
    );
    assert!(native(&roots.participants[0]).escrows.is_empty());
    let first = roots.prepare(0, &transaction, &begin);
    let second = roots.prepare(1, &transaction, &begin);
    // The original owner grants are real committed work. Capture each actual Prepare
    // height and proof now, before relay consumes its admitted source.
    let prepared_heights = roots
        .participants
        .each_ref()
        .map(CertifiedTestChain::height);
    let prepared_proofs =
        [&first, &second].map(|proof| norito::encode_canonical(proof.canonical()).unwrap());
    for (id, chain) in [FIRST, SECOND].into_iter().zip(&roots.participants) {
        let native = native(chain);
        assert_eq!(
            balance(chain, id, principal(), account(&payer())),
            900_u32.into()
        );
        assert_eq!(
            balance(chain, id, principal(), native.custody),
            100_u32.into()
        );
        assert_eq!(
            balance(chain, id, principal(), account(&receiver())),
            Quantity::zero()
        );
        assert!(
            balance(chain, id, fee_asset(), account(&payer())) < 1_000_000_u32.into(),
            "actual positive private fee debit"
        );
        check_paid_effects_at_original_pool_capacity(chain);
    }
    let custody = native(&roots.participants[0]).custody;
    let bypass = roots.participants[0].sign(
        &payer(),
        [Transfer::asset_quantity(
            AssetId::with_scope(
                principal(),
                custody.clone(),
                AssetBalanceScope::Dataspace(FIRST),
            ),
            100_u32,
            account(&receiver()),
        )
        .into()],
        4_199,
    );
    assert_eq!(
        roots.participants[0].commit_at(4_200, vec![bypass]),
        vec![false]
    );
    let remove = roots.participants[0].sign(
        &global_config().genesis_key,
        [Unregister::account(custody).into()],
        4_299,
    );
    assert_eq!(
        roots.participants[0].commit_at(4_300, vec![remove]),
        vec![false]
    );
    for instruction in [
        Unregister::account(account(&receiver())).into(),
        Unregister::asset_definition(principal()).into(),
        Unregister::domain(DomainId::try_new("amx", "private-amx").unwrap()).into(),
    ] {
        let signed_payload =
            roots.participants[0].sign(&global_config().genesis_key, [instruction], 4_399);
        assert_eq!(
            roots.participants[0].commit_at(4_400, vec![signed_payload]),
            vec![false],
            "original pending parties and monetary definitions cannot be retired"
        );
    }
    let decision = roots.decide([first, second], transaction.id().unwrap());
    assert!(
        matches!(decision.canonical().record,AmxRecordV1::Decision(value) if value.outcome==AmxOutcomeV1::Commit)
    );
    // Deliberately malformed ordinary DTO fixture, separately owned from the immutable
    // funded source. It grants no funding/authority and must be rejected by the real host.
    let mut forged = decision.canonical().clone();
    if let AmxRecordV1::Decision(value) = &mut forged.record {
        value.outcome = AmxOutcomeV1::Abort;
    }
    let counterfeit = roots.participants[0].sign(
        &payer(),
        [SettleAmxV1 {
            dataspace: FIRST,
            decision: forged,
        }
        .into()],
        5_099,
    );
    assert_eq!(
        roots.participants[0].commit_at(5_100, vec![counterfeit]),
        vec![false]
    );
    assert!(native(&roots.participants[0]).escrows[0].settled.is_none());
    for (id, chain) in [FIRST, SECOND].into_iter().zip(&mut roots.participants) {
        let signed_payload = chain.sign(
            &payer(),
            [decision
                .try_copy(&roots.global.state().ivm_execution_budget())
                .unwrap()
                .into_settle(id)
                .complete(&roots.global.state().ivm_execution_budget())
                .unwrap()],
            5_999,
        );
        assert_eq!(chain.commit_at(6_000, vec![signed_payload]), vec![true]);
        let native = native(chain);
        assert_eq!(native.escrows[0].settled, Some(AmxOutcomeV1::Commit));
        assert_eq!(
            balance(chain, id, principal(), native.custody),
            Quantity::zero()
        );
        assert_eq!(
            balance(chain, id, principal(), account(&receiver())),
            100_u32.into()
        );
        let repeated = chain.sign(
            &payer(),
            [decision
                .try_copy(&roots.global.state().ivm_execution_budget())
                .unwrap()
                .into_settle(id)
                .complete(&roots.global.state().ivm_execution_budget())
                .unwrap()],
            6_099,
        );
        assert_eq!(chain.commit_at(6_100, vec![repeated]), vec![false]);
    }
    for (index, (id, source)) in [FIRST, SECOND]
        .into_iter()
        .zip(&roots.participants)
        .enumerate()
    {
        let mut restored = CertifiedTestChain::start(private_config(&roots.global, id)).unwrap();
        restored.replay_from(source).unwrap();
        assert_eq!(native(&restored), native(source));
        assert_eq!(
            balance(&restored, id, principal(), account(&payer())),
            900_u32.into()
        );
        assert_eq!(
            balance(&restored, id, principal(), account(&receiver())),
            100_u32.into()
        );
        assert_eq!(
            balance(&restored, id, fee_asset(), account(&payer())),
            balance(source, id, fee_asset(), account(&payer()))
        );
        let proof = super::super::amx_record_proof(
            &restored.state().view(),
            prepared_heights[index],
            AmxRecordKind::Prepared,
            transaction.id().unwrap(),
        )
        .complete()
        .unwrap()
        .expect("each original Prepare archive survives all subsequent work and replay");
        assert_eq!(
            norito::encode_canonical(proof.canonical()).unwrap(),
            prepared_proofs[index],
            "restoration retains the exact original Prepare certificate, result and witness"
        );
        assert!(
            super::super::amx_record_proof(
                &restored.state().view(),
                prepared_heights[index] - 1,
                AmxRecordKind::Prepared,
                transaction.id().unwrap(),
            )
            .complete()
            .unwrap()
            .is_none(),
            "the preceding owner grant or rejected debit cannot stand in for Prepare"
        );
    }
}

#[test]
fn native_amx_certified_abort_returns_yes_escrow_and_held_decision_never_debits() {
    let mut roots = Roots::new();
    let mut transaction = roots.transaction(100, 2);
    let second: AmxTransferLegV1 = norito::decode_canonical(&transaction.legs[1].payload).unwrap();
    transaction.legs[1].payload = norito::encode_canonical(&AmxTransferLegV1 {
        amount: 2_000_u32.into(),
        ..second
    })
    .unwrap();
    let begin = roots.begin(&transaction);
    let first = roots.prepare(0, &transaction, &begin);
    let second = roots.prepare(1, &transaction, &begin);
    assert!(
        matches!(second.canonical().record,AmxRecordV1::Prepared(value) if value.vote==AmxVoteV1::No)
    );
    assert!(native(&roots.participants[1]).escrows.is_empty());
    let decision = roots.decide([first, second], transaction.id().unwrap());
    assert!(
        matches!(decision.canonical().record,AmxRecordV1::Decision(value) if value.outcome==AmxOutcomeV1::Abort)
    );
    let budget = roots.global.state().ivm_execution_budget();
    let settle = decision
        .try_copy(&budget)
        .unwrap()
        .into_settle(FIRST)
        .complete(&budget)
        .unwrap();
    assert!(settle.amx_proof_admitted_to(&budget));
    let signed_payload = roots.participants[0].sign(&payer(), [settle], 5_999);
    assert_eq!(
        roots.participants[0].commit_at(6_000, vec![signed_payload]),
        vec![true]
    );
    assert_eq!(
        balance(
            &roots.participants[0],
            FIRST,
            principal(),
            account(&payer())
        ),
        1_000_u32.into()
    );
    assert_eq!(
        native(&roots.participants[0]).escrows[0].settled,
        Some(AmxOutcomeV1::Abort)
    );
    // A separately authenticated root holds the decision before its first Prepare.
    let mut fresh = CertifiedTestChain::start(private_config(&roots.global, FIRST)).unwrap();
    let signed_payload = fresh.sign(
        &payer(),
        [decision
            .into_settle(FIRST)
            .complete(&roots.global.state().ivm_execution_budget())
            .unwrap()],
        6_999,
    );
    assert_eq!(fresh.commit_at(7_000, vec![signed_payload]), vec![true]);
    // This fresh root has not received the original participants' owner-signed approvals.
    let transfer: AmxTransferLegV1 =
        norito::decode_canonical(&transaction.leg(FIRST).unwrap().payload).unwrap();
    let approval = iroha_data_model::sumeragi_amx::AmxDebitApprovalV1 {
        global_network: roots.global.network_id(),
        participant_network: fresh.network_id(),
        participant_instance: fresh.instance().0,
        dataspace: FIRST,
        transaction_id: transaction.id().unwrap(),
        debited_asset: transfer.source,
    };
    assert_eq!(approval.debited_asset.account(), &account(&payer()));
    let signed_approval = fresh.sign(
        &payer(),
        [Grant::account_permission(approval.permission().unwrap(), account(&payer())).into()],
        7_499,
    );
    assert_eq!(
        fresh.commit_at(7_500, vec![signed_approval]),
        vec![true],
        "fresh-root debit owner grants the exact native AMX intent: {:?}",
        fresh
            .committed(fresh.height())
            .block()
            .network_output_at(0)
            .map(|(_, output)| &output.result)
    );
    let prepare = begin
        .into_prepare(FIRST, &transaction)
        .complete(&budget)
        .unwrap();
    assert!(prepare.amx_proof_admitted_to(&budget));
    let signed_payload = fresh.sign(&payer(), [prepare], 7_999);
    assert_eq!(
        fresh.commit_at(8_000, vec![signed_payload]),
        vec![true],
        "approved Prepare must observe the held Abort without debiting: {:?}",
        fresh
            .committed(fresh.height())
            .block()
            .network_output_at(0)
            .map(|(_, output)| &output.result)
    );
    assert!(native(&fresh).escrows.is_empty());
    assert_eq!(
        native(&fresh)
            .participant
            .entry(&transaction.id().unwrap())
            .unwrap()
            .vote,
        AmxVoteV1::No
    );
    assert_eq!(
        balance(&fresh, FIRST, principal(), account(&payer())),
        1_000_u32.into()
    );
}

#[test]
fn native_amx_original_graph_refusal_preserves_committed_owner_and_exact_retry_capacity() {
    let roots = Roots::new();
    let source = native(&roots.participants[0]);
    let budget = roots.participants[0].state().ivm_execution_budget();
    let limit = budget.limit_bytes();
    let retained = budget.reserved_bytes();
    let owner = RetainedNativeAmx::admit(&source, &budget).unwrap();
    let copied = &owner.canonical().unwrap().participant.global.current;
    assert_eq!(copied, &source.participant.global.current);
    assert_eq!(
        copied.generation().generation_id().unwrap(),
        copied.authorization.authority_id,
        "the retained sole BLS roster preserves its exact authorized generation"
    );
    assert!(
        !owner.is_authenticated(),
        "admitting an exact graph does not authenticate its history"
    );
    assert_eq!(
        norito::encode_canonical(&owner).unwrap(),
        norito::encode_canonical(&Some(source.clone())).unwrap(),
        "borrowed funded graph keeps the owned Option wire"
    );
    assert_eq!(
        norito::encode_canonical(&RetainedNativeAmx::default()).unwrap(),
        norito::encode_canonical(&None::<NativeAmxParticipantStateV1>).unwrap()
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), retained);
    budget.set_limit_bytes(retained);
    assert!(matches!(
        Candidate::copy(&source, &budget, 1, 0, None, None),
        Err(GraphError::Admission(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(native(&roots.participants[0]), source);
    for mutation in 0..6 {
        let mut malformed = source.clone();
        let current = &mut malformed.participant.global.current;
        match mutation {
            0 => current.authorization.authority_generation += 1,
            1 => current.authorization.authority_id[0] ^= 1,
            2 => current.committee.swap(0, 1),
            3 => current.committee[0].proof_of_possession[0] ^= 1,
            4 => current.network_id = roots.participants[0].network_id(),
            5 => current.leader_seed = [0; 32],
            _ => unreachable!(),
        }
        assert!(matches!(
            RetainedNativeAmx::admit(&malformed, &budget),
            Err(GraphError::Invalid(_))
        ));
        assert_eq!(
            budget.reserved_bytes(),
            retained,
            "malformed epoch mutation {mutation} is rejected before the occupied pool is charged"
        );
        assert_eq!(native(&roots.participants[0]), source);
    }
    budget.set_limit_bytes(limit);
    let candidate = Candidate::copy(&source, &budget, 1, 0, None, None).unwrap();
    assert!(budget.reserved_bytes() > retained);
    assert_eq!(
        candidate.value.as_ref().unwrap().participant.global.current,
        source.participant.global.current
    );
    drop(candidate);
    assert_eq!(budget.reserved_bytes(), retained);
}

#[test]
fn native_amx_decision_context_archive_keeps_original_pool_custody_through_copy_and_refusal() {
    use iroha_data_model::sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochContextV1,
        ValidatorEpochDecisionV1,
    };

    // Synthetic successor bodies exercise graph admission only. Admission must
    // never authenticate these bodies; signed sequential handoffs are tested by
    // the participant protocol and the native handoff execution controls.
    fn successor(previous: &ValidatorEpochContextV1) -> ValidatorEpochContextV1 {
        let mut next = previous.clone();
        next.authorization.epoch += 1;
        next.authorization.first_height = previous.authorization.last_height + 1;
        next.authorization.last_height = next.authorization.first_height + 9;
        next.authorization.previous_authorization_id =
            previous.authorization.authorization_id().unwrap();
        next.authorization.decision = ValidatorEpochDecisionV1::Retain;
        next.authorization.beacon =
            BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                session_id: [0x41; 32],
                transcript_hash: [0x51; 32],
            });
        next.leader_seed = [0x32; 32];
        next.validate_successor(previous).unwrap();
        next
    }

    let mut roots = Roots::new();
    let transaction = roots.transaction(25, 0xE4);
    let begin = roots.begin(&transaction);
    roots.prepare(0, &transaction, &begin);
    let mut source = native(&roots.participants[0]);
    let original = source.clone();
    let mut first = source.participant.global.current.clone();
    first.authorization.last_height = 10;
    first.validate().unwrap();
    let second = successor(&first);
    let third = successor(&second);
    source.participant.global.current = second;
    source.participant.global.previous = Some(first.clone());
    source.validate().unwrap();
    assert!(source.participant.needs_decision_context(&first));

    let budget = roots.participants[0].state().ivm_execution_budget();
    let limit = budget.limit_bytes();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    assert!(matches!(
        Candidate::copy(&source, &budget, 0, 0, None, Some(&third)),
        Err(GraphError::Admission(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(native(&roots.participants[0]), original);
    budget.set_limit_bytes(limit);

    let owner = Candidate::copy(&source, &budget, 0, 0, None, Some(&third))
        .unwrap()
        .finish()
        .unwrap();
    assert!(!owner.is_authenticated());
    assert!(owner.belongs_to(&budget));
    let archived = owner.canonical().unwrap();
    assert_eq!(archived.participant.decision_contexts, vec![first]);
    assert_eq!(archived.participant.global.current, third);
    let with_archive_bytes = budget.reserved_bytes();
    let mut missing = archived.clone();
    missing.participant.decision_contexts.clear();
    assert!(matches!(
        RetainedNativeAmx::admit(&missing, &budget),
        Err(GraphError::Invalid(_))
    ));
    assert_eq!(budget.reserved_bytes(), with_archive_bytes);
    let copy = RetainedNativeAmx::admit(archived, &budget).unwrap();
    assert!(!copy.is_authenticated());
    assert!(copy.belongs_to(&budget));
    assert_eq!(copy.canonical(), Some(archived));
    assert_eq!(
        norito::encode_canonical(&copy).unwrap(),
        norito::encode_canonical(&owner).unwrap()
    );
    drop(copy);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(native(&roots.participants[0]), original);
}

#[test]
fn native_amx_enrolled_receiver_records_certified_no_without_monetary_or_maintenance_effects() {
    use iroha_data_model::validation_fee::RetailFeeAccountStateV1;
    let (local_clock, time_source) =
        iroha_primitives::time::TimeSource::new_mock(std::time::Duration::from_millis(3_000));
    let mut roots = Roots::new_with_time_source(time_source);
    let transaction = roots.transaction(100, 0x77);
    let begin = roots.begin(&transaction);
    let enrolled = account(&receiver());
    let enrollment_ms = 1_793_451_600_000;
    let clock = roots.participants[0].sign(
        &payer(),
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "advance the original private root into the retail calendar".into(),
        )
        .into()],
        enrollment_ms - 1,
    );
    local_clock.set(std::time::Duration::from_millis(enrollment_ms));
    assert_eq!(
        roots.participants[0].commit_at(enrollment_ms, vec![clock]),
        vec![true]
    );
    let record = RetailFeeAccountStateV1::enroll(enrolled.clone(), enrollment_ms, 0).unwrap();
    let bytes = norito::to_bytes(&record).unwrap();
    let key: iroha_model_base::state_path::StatePath = format!(
        "retail_fee_v1/{}",
        hex::encode(iroha_crypto::Hash::new(enrolled.to_string().as_bytes()).as_ref())
    )
    .parse()
    .unwrap();
    let chain = &roots.participants[0];
    {
        // Controlled negative business-state fixture only: the enrollment cannot authorize
        // any movement. The real signed Prepare and its actual record archive still run below.
        let budget = chain.state().ivm_execution_budget();
        let mut world = chain.state().world.try_block(&budget).unwrap();
        world
            .smart_contract_state
            .insert(key.clone(), bytes.clone());
        world.commit();
    }
    let fee_before = balance(chain, FIRST, fee_asset(), account(&payer()));
    local_clock.set(std::time::Duration::from_millis(enrollment_ms + 1_000));
    let proof = roots.prepare_at(0, &transaction, &begin, enrollment_ms + 1_000);
    let AmxRecordV1::Prepared(prepared) = &proof.canonical().record else {
        panic!("actual certified Prepared")
    };
    assert_eq!(prepared.vote, AmxVoteV1::No);
    let chain = &roots.participants[0];
    assert!(native(chain).escrows.is_empty());
    assert!(balance(chain, FIRST, fee_asset(), account(&payer())) < fee_before);
    assert_eq!(
        balance(chain, FIRST, principal(), account(&payer())),
        1_000_u32.into()
    );
    assert_eq!(
        balance(chain, FIRST, principal(), enrolled),
        Quantity::zero()
    );
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .smart_contract_state()
            .get(&key),
        Some(&bytes)
    );
}

#[test]
fn native_amx_global_source_requires_signed_parent_real_h2_and_exact_instance() {
    use crate::sumeragi::commitment::CertifiedResultV1;
    use iroha_data_model::block::CommitCertificate;
    let config = global_config();
    let chain_id = config.chain_id.clone();
    let key = config.genesis_key.clone();
    let mut global = CertifiedTestChain::start(config).unwrap();
    let transaction = global.sign(
        &key,
        [iroha_data_model::isi::Log::new(iroha_logger::Level::INFO, "real H2".into()).into()],
        1_499,
    );
    assert_eq!(global.commit_at(1_500, vec![transaction]), vec![true]);
    let genesis = global.committed(1).block().as_ref().clone();
    let successor = global.committed(2).block().as_ref().clone();
    let genesis_wire = genesis.encode_wire().unwrap();
    let successor_wire = successor.encode_wire().unwrap();
    let budget = global.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let authenticated_global_source = |chain: &ChainId,
                                       parent,
                                       genesis: &[u8],
                                       successor: &[u8]| {
        let before = budget.reserved_bytes();
        let result = super::authenticated_global_source(chain, parent, genesis, successor, &budget);
        assert_eq!(
            budget.reserved_bytes(),
            before
                + result
                    .as_ref()
                    .ok()
                    .and_then(|owner| owner.allocation_bytes())
                    .unwrap_or(0),
            "completed scratch retires while the returned context retains its exact original graph charge"
        );
        result
    };
    let authenticated = authenticated_global_source(
        &chain_id,
        global.network_id(),
        &genesis_wire,
        &successor_wire,
    )
    .unwrap();
    assert_eq!(authenticated.canonical().instance, global.instance().0);
    assert_eq!(
        authenticated.canonical().current,
        authenticated_genesis(global.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap()
    );
    // A separate test oracle preserves the original canonical equality while the
    // returned funded owner retires before subsequent scratch/refusal controls.
    let expected = authenticated.canonical().clone();
    drop(authenticated);
    let before = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    budget.set_limit_bytes(before);
    let expected_slot_refusal =
        match budget.try_reserve(iroha_data_model::block::SharedSignedBlock::allocation_layout()) {
            Ok(_) => panic!("the occupied original pool must refuse the original block control"),
            Err(original) => original,
        };
    let refused_slot = authenticated_global_source(
        &chain_id,
        global.network_id(),
        &genesis_wire,
        &successor_wire,
    )
    .unwrap_err();
    assert!(
        matches!(&refused_slot, crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
        if reason.allocation_refusal() == Some(&expected_slot_refusal)),
        "the exact source block control must retain its original pool refusal: {refused_slot:?}"
    );
    assert_eq!(budget.reserved_bytes(), before);
    budget.set_limit_bytes(original_limit);
    let prefix_bytes =
        std::alloc::Layout::new::<crate::sumeragi::certified_chain::CertifiedPrefix>().size();
    let shared_bytes = iroha_data_model::block::SharedSignedBlock::allocation_layout().size();
    let frame_bytes =
        std::alloc::Layout::new::<crate::sumeragi::certified_chain::CommittedBlock>().size();
    let result_bytes = std::alloc::Layout::new::<CertifiedResultV1>().size();
    for (prior_slots, requested_slot_bytes) in [
        (shared_bytes, prefix_bytes),
        (shared_bytes + prefix_bytes, frame_bytes),
        (shared_bytes + prefix_bytes + frame_bytes, result_bytes),
    ] {
        budget.set_limit_bytes(before + prior_slots);
        let refused_frame = authenticated_global_source(
            &chain_id,
            global.network_id(),
            &genesis_wire,
            &successor_wire,
        )
        .unwrap_err();
        let release = match &refused_frame {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                match reason.allocation_refusal() {
                    Some(iroha_allocation::AllocationRefusal::Capacity {
                        requested_bytes,
                        reserved_bytes,
                        limit_bytes,
                        release,
                    }) => {
                        assert_eq!(*requested_bytes, requested_slot_bytes);
                        assert_eq!(*reserved_bytes, before + prior_slots);
                        assert_eq!(*limit_bytes, before + prior_slots);
                        release.clone()
                    }
                    refusal => {
                        panic!(
                            "the prepaid slots must preserve the next exact refusal: {refusal:?}"
                        )
                    }
                }
            }
            rejected => panic!("each physical slot refusal must remain local: {rejected:?}"),
        };
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            registration.poll_wait(&release, &mut context).is_ready(),
            "dropping the failed original slots must wake their exact original result/frame refusal"
        );
        registration.cancel();
        assert_eq!(budget.reserved_bytes(), before);
        budget.set_limit_bytes(original_limit);
    }
    let refused = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
        || {
            authenticated_global_source(
                &chain_id,
                global.network_id(),
                &genesis_wire,
                &successor_wire,
            )
        },
    )
    .unwrap_err();
    assert!(
        matches!(
            refused,
            crate::execution_attempt::ExecutionAttemptError::Deferred(_)
        ),
        "original source decoder refusal must remain local: {refused:?}"
    );
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(
        authenticated_global_source(
            &chain_id,
            global.network_id(),
            &genesis_wire,
            &successor_wire
        )
        .unwrap()
        .canonical(),
        &expected
    );
    let private = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    assert!(
        authenticated_global_source(
            &chain_id,
            private.network_id(),
            &private.committed(1).block().encode_wire().unwrap(),
            &successor_wire
        )
        .is_err(),
        "a signed private genesis is never Global parent authority"
    );
    assert!(
        authenticated_global_source(
            &ChainId::from("foreign-global-instance"),
            global.network_id(),
            &genesis_wire,
            &successor_wire
        )
        .is_err()
    );
    assert!(
        authenticated_global_source(&chain_id, global.network_id(), &genesis_wire, &genesis_wire)
            .is_err()
    );
    assert!(
        authenticated_global_source(
            &chain_id,
            roots_foreign_network(),
            &genesis_wire,
            &successor_wire
        )
        .is_err()
    );
    let certificate = genesis.commit_certificate().unwrap();
    let (original_x, mut result) = iroha_data_model::sumeragi_finality::CertifiedResultV1::decode(
        certificate.result_preimage(),
        global.root_scope().into(),
    )
    .unwrap()
    .into_parts();
    result.execution.world_state_root =
        iroha_crypto::Hash::new(b"unsigned AMX genesis R substitution");
    let changed =
        genesis
            .clone()
            .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                Vec::new(),
                Vec::new(),
                iroha_data_model::sumeragi_finality::CertifiedResultV1::from_parts_unvalidated(
                    original_x, result,
                )
                .preimage()
                .unwrap(),
                Vec::new(),
            )));
    assert_eq!(
        changed.hash(),
        genesis.hash(),
        "genesis signatures do not authenticate R"
    );
    assert!(
        authenticated_global_source(
            &chain_id,
            global.network_id(),
            &changed.encode_wire().unwrap(),
            &successor_wire
        )
        .is_err()
    );
    let certificate = successor.commit_certificate().unwrap();
    let mut qc: iroha_sumeragi::message::Qc =
        norito::decode_canonical(certificate.commit_qc()).unwrap();
    qc.agg_sig.0[0] ^= 1;
    let changed =
        successor
            .clone()
            .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                norito::encode_canonical(&qc).unwrap(),
                certificate.result_preimage().to_vec(),
                certificate.availability().to_vec(),
            )));
    assert!(
        authenticated_global_source(
            &chain_id,
            global.network_id(),
            &genesis_wire,
            &changed.encode_wire().unwrap()
        )
        .is_err()
    );
}

fn roots_foreign_network() -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"foreign AMX parent"),
    ))
}

#[test]
fn native_amx_edited_snapshot_admission_cannot_settle_without_original_replay() {
    let mut roots = Roots::new();
    let transaction = roots.transaction(100, 0x76);
    let begin = roots.begin(&transaction);
    let first = roots.prepare(0, &transaction, &begin);
    let second = roots.prepare(1, &transaction, &begin);
    let decision = roots.decide([first, second], transaction.id().unwrap());
    let chain = &mut roots.participants[0];
    let source = native(chain);
    let decoded: NativeAmxParticipantStateV1 =
        norito::json::from_str(&norito::json::to_json(&source).unwrap()).unwrap();
    let budget = chain.state().ivm_execution_budget();
    let restored = RetainedNativeAmx::admit(&decoded, &budget).unwrap();
    assert!(
        !restored.is_authenticated(),
        "allocation admission is never execution authority"
    );
    let mut edited = decoded.clone();
    edited.participant.global.instance = [0x91; 32];
    let edited = RetainedNativeAmx::admit(&edited, &budget).unwrap();
    assert!(
        !edited.is_authenticated(),
        "edited decoded authority cannot acquire provenance"
    );
    {
        let mut world = chain.state().world.try_block(&budget).unwrap();
        *world.sumeragi_amx_participant.get_mut() = restored;
        world.commit();
    }
    let signed_payload = chain.sign(
        &payer(),
        [decision
            .into_settle(FIRST)
            .complete(&roots.global.state().ivm_execution_budget())
            .unwrap()],
        5_999,
    );
    assert_eq!(chain.commit_at(6_000, vec![signed_payload]), vec![false]);
    assert_eq!(native(chain).escrows[0].settled, None);
    assert_eq!(
        balance(chain, FIRST, principal(), account(&receiver())),
        Quantity::zero()
    );
    assert_eq!(
        balance(chain, FIRST, principal(), source.custody),
        100_u32.into()
    );
}

#[test]
fn native_amx_new_state_cannot_inherit_live_authority_without_certified_replay() {
    let mut roots = Roots::new();
    let transaction = roots.transaction(100, 0x77);
    let begin = roots.begin(&transaction);
    let first = roots.prepare(0, &transaction, &begin);
    let second = roots.prepare(1, &transaction, &begin);
    let decision = roots.decide([first, second], transaction.id().unwrap());
    let chain = &mut roots.participants[0];
    let source = chain.state().world.sumeragi_amx_participant.view().clone();
    assert!(source.is_authenticated());
    let budget = chain.state().ivm_execution_budget();
    // The constructor must strip execution authority even when every retained
    // graph and the new World use the exact original physical allocation pool.
    let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
    {
        let mut block = world.try_block(&budget).unwrap();
        *block.sumeragi_amx_participant.get_mut() = source.clone();
        block.commit();
    }
    let constructed =
        crate::state::State::try_new_with_chain_and_network_id_with_default_telemetry(
            budget.clone(),
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
            private_config(&roots.global, FIRST).chain_id,
            chain.network_id(),
        )
        .unwrap();
    let admitted = constructed.world.sumeragi_amx_participant.view().clone();
    assert_eq!(admitted.canonical(), source.canonical());
    assert!(admitted.belongs_to(&budget));
    assert!(
        !admitted.is_authenticated(),
        "a new State never inherits a different State's certified execution capability"
    );
    assert!(
        source.is_authenticated(),
        "the original owner remains usable"
    );
    // Use the original signed private root and the same physical pool. This actual settlement
    // must fail specifically because construction stripped provenance, not a root/pool mismatch.
    {
        let mut block = chain.state().world.try_block(&budget).unwrap();
        *block.sumeragi_amx_participant.get_mut() = admitted;
        block.commit();
    }
    let signed_payload = chain.sign(
        &payer(),
        [decision
            .into_settle(FIRST)
            .complete(&roots.global.state().ivm_execution_budget())
            .unwrap()],
        5_999,
    );
    assert_eq!(chain.commit_at(6_000, vec![signed_payload]), vec![false]);
    assert_eq!(native(chain).escrows[0].settled, None);
    assert_eq!(
        balance(chain, FIRST, principal(), account(&receiver())),
        Quantity::zero()
    );
    assert_eq!(
        balance(chain, FIRST, principal(), native(chain).custody),
        100_u32.into()
    );
}

#[test]
fn native_amx_global_handoff_requires_real_boundary_and_preserves_original_sources() {
    use iroha_data_model::sumeragi_amx::{AmxCertifiedBlockV1, AmxHandoffProofV1};
    let mut global = CertifiedTestChain::npos_boundary_fixture();
    let mut participant = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    let original = native(&participant);
    assert_eq!(original.participant.global.epoch(), 0);
    let early = AmxHandoffProofV1 {
        block: AmxCertifiedBlockV1::from_certificate(
            global.committed(9).block().commit_certificate().unwrap(),
        ),
    };
    let signed_payload = participant.sign(
        &payer(),
        [RelayGlobalAmxHandoffV1 {
            dataspace: FIRST,
            proof: early,
        }
        .into()],
        1_999,
    );
    assert_eq!(
        participant.commit_at(2_000, vec![signed_payload]),
        vec![false]
    );
    assert_eq!(native(&participant), original);
    global.commit(Vec::new());
    assert_eq!(global.height(), 10);
    let boundary = AmxHandoffProofV1 {
        block: AmxCertifiedBlockV1::from_certificate(
            global.committed(10).block().commit_certificate().unwrap(),
        ),
    };
    let mut corrupt = boundary.clone();
    corrupt.block.commit_qc[0] ^= 1;
    let signed_payload = participant.sign(
        &payer(),
        [RelayGlobalAmxHandoffV1 {
            dataspace: FIRST,
            proof: corrupt,
        }
        .into()],
        2_099,
    );
    assert_eq!(
        participant.commit_at(2_100, vec![signed_payload]),
        vec![false]
    );
    assert_eq!(native(&participant), original);
    let signed_payload = participant.sign(
        &payer(),
        [RelayGlobalAmxHandoffV1 {
            dataspace: FIRST,
            proof: boundary.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(
        participant.commit_at(3_000, vec![signed_payload]),
        vec![true]
    );
    let next = native(&participant);
    assert_eq!(next.participant.global.epoch(), 1);
    assert_eq!(
        next.participant.global.previous,
        Some(original.participant.global.current.clone())
    );
    for context in [
        &next.participant.global.current,
        next.participant.global.previous.as_ref().unwrap(),
    ] {
        context.validate().unwrap();
        assert_eq!(
            context.generation().generation_id().unwrap(),
            context.authorization.authority_id,
            "both prepaid handoff contexts retain their complete original BLS generation"
        );
    }
    assert_eq!(next.global_genesis, original.global_genesis);
    assert_eq!(next.global_successor, original.global_successor);
    assert_eq!(next.global_chain_label, original.global_chain_label);
    let signed_payload = participant.sign(
        &payer(),
        [RelayGlobalAmxHandoffV1 {
            dataspace: FIRST,
            proof: boundary,
        }
        .into()],
        3_099,
    );
    assert_eq!(
        participant.commit_at(3_100, vec![signed_payload]),
        vec![true]
    );
    assert_eq!(
        native(&participant),
        next,
        "a valid old-epoch handoff is stale"
    );
    let mut restored = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    restored.replay_from(&participant).unwrap();
    assert_eq!(native(&restored), next);
}

#[test]
fn native_amx_caught_completed_failure_cannot_publish_partial_world_effects() {
    use iroha_data_model::{ValidationFail, block::BlockHeader, isi::SetKeyValue};
    let chain = CertifiedTestChain::start(global_config()).unwrap();
    let signer = global_config().genesis_key;
    let key = "caught_native_amx_effect".parse().unwrap();
    let write: InstructionBox = SetKeyValue::account(
        account(&signer),
        key,
        iroha_primitives::json::Json::new(true),
    )
    .into();
    let signed_payload = chain.sign(&signer, [write.clone()], 1_499);
    let mut block = chain.state().block(BlockHeader::new(
        core::num::NonZeroU64::new(2).unwrap(),
        Some(chain.genesis().hash()),
        None,
        1_500,
        0,
    ));
    let fragments = block.committed_fragment_count();
    let mut attempt = block.transaction();
    attempt.current_entrypoint_index = Some(0);
    attempt.current_tx_hash = Some(signed_payload.hash());
    attempt.tx_call_hash = Some(iroha_crypto::Hash::from(
        signed_payload.hash_as_entrypoint(),
    ));
    attempt.current_lane_id = Some(iroha_model_base::topology::LaneId::SINGLE);
    attempt.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    attempt.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    attempt
        .begin_execution_effect_budget(&signed_payload)
        .unwrap();
    attempt
        .admit_authored_execution_effects(std::slice::from_ref(&write))
        .unwrap();
    write.execute(&account(&signer), &mut attempt).unwrap();
    // Exercise the local failure-owner contract after a real staged effect. This unit control
    // never claims that a fabricated error or manually bound source authorizes monetary work.
    let error = invalid("completed native AMX monetary policy rejection");
    attempt.reject_native_amx_effects(error.clone());
    assert_eq!(
        attempt.finish_execution_effect_budget(),
        Err(ValidationFail::InstructionFailed(error))
    );
    assert!(!attempt.execution_effects_allow_apply());
    attempt.apply();
    assert_eq!(block.committed_fragment_count(), fragments);
    assert!(
        block
            .world
            .account(&account(&signer))
            .unwrap()
            .metadata()
            .get("caught_native_amx_effect")
            .is_none()
    );
}

// The original signed-root AMX fixture retains the exact shared State graph.
struct NativeCheckedJsonSink {
    output: String,
    limit: usize,
    depth: usize,
    depth_ceiling: Option<usize>,
}
impl NativeCheckedJsonSink {
    fn new(limit: usize) -> Self {
        Self {
            output: String::new(),
            limit,
            depth: 5,
            depth_ceiling: None,
        }
    }
}
impl norito::json::JsonWriteSink for NativeCheckedJsonSink {
    fn push(&mut self, value: char) -> Result<(), norito::json::BoundedJsonError> {
        <Self as norito::json::JsonWriteSink>::push_str(self, value.encode_utf8(&mut [0; 4]))
    }
    fn push_str(&mut self, value: &str) -> Result<(), norito::json::BoundedJsonError> {
        if self
            .output
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(norito::json::BoundedJsonError::BodyTooLarge);
        }
        self.output.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), norito::json::BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(norito::json::BoundedJsonError::Unsupported)?;
        if self.depth_ceiling.is_some_and(|ceiling| next > ceiling) {
            return Err(norito::json::BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        assert!(
            self.depth > 5,
            "native AMX writer cannot release caller depth"
        );
        self.depth -= 1;
    }
}
#[test]
fn original_empty_native_amx_checked_refusal_preserves_inherited_depth() {
    use norito::json::{BoundedJsonError, JsonSerialize as _};
    let owner = RetainedNativeAmx::default();
    let mut sink = NativeCheckedJsonSink::new(0);
    assert_eq!(
        owner.json_serialize_to(&mut sink),
        Err(BoundedJsonError::BodyTooLarge)
    );
    assert_eq!(
        sink.depth, 5,
        "empty native AMX refusal preserves original caller depth"
    );
    assert!(owner.canonical().is_none());
    assert!(!owner.is_authenticated());
    assert!(sink.output.is_empty());
    let mut sink = NativeCheckedJsonSink::new(usize::MAX);
    assert_eq!(owner.json_serialize_to(&mut sink), Ok(()));
    assert_eq!(sink.depth, 5);
    assert_eq!(sink.output, "{\"value\":null}");
}
#[test]
fn original_authenticated_native_amx_checked_refusals_keep_graph_pool_and_depth() {
    use norito::json::{BoundedJsonError, JsonSerialize as _};
    let roots = Roots::new();
    let view = roots.participants[0].state().view();
    let original = view.world().sumeragi_amx_participant();
    let owner = original.clone();
    let pointer = std::ptr::from_ref(owner.canonical().unwrap());
    assert_eq!(pointer, std::ptr::from_ref(original.canonical().unwrap()));
    assert!(owner.is_authenticated());
    let budget = roots.participants[0].state().ivm_execution_budget();
    let retained_bytes = budget.reserved_bytes();
    assert!(owner.belongs_to(&budget));
    let ordinary = norito::json::to_json(&owner).unwrap();
    for limit in [0, 1, 7, ordinary.len() - 1] {
        let mut sink = NativeCheckedJsonSink::new(limit);
        assert_eq!(
            owner.json_serialize_to(&mut sink),
            Err(BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(
            sink.depth, 5,
            "native AMX returned error restores caller depth"
        );
        assert!(ordinary.starts_with(&sink.output));
        assert_eq!(std::ptr::from_ref(owner.canonical().unwrap()), pointer);
        assert!(owner.belongs_to(&budget));
        assert!(owner.is_authenticated());
        assert_eq!(budget.reserved_bytes(), retained_bytes);
    }
    let mut sink = NativeCheckedJsonSink::new(usize::MAX);
    sink.depth_ceiling = Some(6);
    assert_eq!(
        owner.json_serialize_to(&mut sink),
        Err(BoundedJsonError::Unsupported)
    );
    assert_eq!(sink.depth, 5);
    assert_eq!(sink.output, "{\"value\":");
    assert_eq!(std::ptr::from_ref(owner.canonical().unwrap()), pointer);
    assert_eq!(budget.reserved_bytes(), retained_bytes);
    let mut sink = NativeCheckedJsonSink::new(ordinary.len());
    assert_eq!(owner.json_serialize_to(&mut sink), Ok(()));
    assert_eq!(sink.output, ordinary);
    assert_eq!(sink.depth, 5);
    assert_eq!(std::ptr::from_ref(owner.canonical().unwrap()), pointer);
    assert_eq!(budget.reserved_bytes(), retained_bytes);
}
#[test]
fn original_authenticated_native_amx_mv_cell_refusal_keeps_original_cut_graph_and_pool() {
    use norito::json::{BoundedJsonError, JsonSerialize as _};
    let roots = Roots::new();
    let view = roots.participants[0].state().view();
    let slot = &view.world().sumeragi_amx_participant;
    let original = view.world().sumeragi_amx_participant();
    let pointer = std::ptr::from_ref(original.canonical().unwrap());
    let budget = roots.participants[0].state().ivm_execution_budget();
    let retained_bytes = budget.reserved_bytes();
    let ordinary = norito::json::to_json(slot.get()).unwrap();
    let original_leaf = "\"global_genesis\":";
    let original_leaf_start = ordinary
        .find(original_leaf)
        .expect("native AMX retains the original global-genesis source leaf")
        + original_leaf.len();
    for limit in [
        original_leaf_start,
        original_leaf_start + 1,
        ordinary.len() - 1,
    ] {
        let mut sink = NativeCheckedJsonSink::new(limit);
        assert_eq!(
            slot.json_serialize_to(&mut sink),
            Err(BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(
            sink.depth, 5,
            "an original native AMX MV leaf cannot strand caller depth"
        );
        assert!(ordinary.starts_with(&sink.output));
        assert_eq!(std::ptr::from_ref(original.canonical().unwrap()), pointer);
        assert!(original.belongs_to(&budget));
        assert!(original.is_authenticated());
        assert_eq!(budget.reserved_bytes(), retained_bytes);
    }
    let mut sink = NativeCheckedJsonSink::new(ordinary.len());
    assert_eq!(slot.json_serialize_to(&mut sink), Ok(()));
    assert_eq!(sink.output, ordinary);
    assert_eq!(sink.depth, 5);
    assert_eq!(std::ptr::from_ref(original.canonical().unwrap()), pointer);
    assert_eq!(budget.reserved_bytes(), retained_bytes);
}

#[path = "tests/paid_borrowed_custody.rs"]
mod paid_borrowed_custody;

#[test]
fn native_leg_decode_refuses_occupied_original_pool_before_any_copy_and_retries_exact_source() {
    let first = payer();
    let second = receiver();
    let transfer = AmxTransferLegV1 {
        source: AssetId::with_scope(
            principal(),
            account(&first),
            AssetBalanceScope::Dataspace(FIRST),
        ),
        destination: account(&second),
        amount: Quantity::from(17_u32),
    };
    let bytes = norito::encode_canonical(&transfer).unwrap();
    let source = (bytes.as_ptr(), bytes.len());
    let first_layout = first.public_key().retained_allocation_layout();
    let controls = norito::core::PreparedDecodeWorkspace::allocation_layouts();
    let control_bytes = controls.iter().map(std::alloc::Layout::size).sum::<usize>();
    let destination_layout = second.public_key().retained_allocation_layout();
    let amount_layout = transfer.amount.admission_clone_layout().unwrap();
    let exact_retained = first_layout.size() + destination_layout.size() + amount_layout.size();
    let budget = AllocationBudget::new(control_bytes);
    let blocker = iroha_allocation::ChargedBuffer::<u8>::new(control_bytes, &budget).unwrap();
    let expected = budget.try_reserve_layouts(controls).unwrap_err();
    assert!(matches!(
        expected,
        iroha_allocation::AllocationRefusal::Capacity { .. }
    ));
    let mut result = None;
    let allocations = crate::test_allocations::allocations_during(|| {
        result = Some(decode_leg(&bytes, &budget));
    });
    let result = result.expect("actual production decoder was called once");
    let refusal =
        result.expect_err("occupied original pool must refuse before copying a canonical leg");
    assert_eq!(refusal.to_string(), expected.to_string());
    let AmxLegDecodeErrorV1::Allocation(iroha_allocation::ChargedBufferError::Admission(actual)) =
        refusal
    else {
        panic!("original pool refusal was erased");
    };
    assert_eq!(actual, expected, "includes the original release generation");
    assert_eq!(
        allocations, 0,
        "no key, alignment, quantity or graph copy may precede original pool refusal"
    );
    assert_eq!(budget.reserved_bytes(), control_bytes);
    assert_eq!((bytes.as_ptr(), bytes.len()), source);
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(exact_retained + control_bytes);
    let retry = decode_leg(&bytes, &budget).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        budget.reserved_bytes(),
        exact_retained,
        "both real compact keys and native digits stay physically funded"
    );
    assert_eq!((bytes.as_ptr(), bytes.len()), source);
    budget.set_limit_bytes(0);
    drop(retry);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_leg_destination_and_scope_invariants_defer_without_protocol_rejection() {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
    use iroha_data_model::block::BlockHeader;
    use std::num::NonZeroU64;
    for cause in [
        AmxLegDecodeErrorV1::Invariant("populated native AMX leg destination"),
        AmxLegDecodeErrorV1::Scope(norito::core::PreparedDecodeScopeError::ForeignPool),
        AmxLegDecodeErrorV1::Scope(norito::core::PreparedDecodeScopeError::AttemptExhausted),
    ] {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state
            .try_block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0))
            .unwrap();
        let mut attempt = block.try_transaction().unwrap();
        assert!(!attempt.is_execution_deferred());
        let diagnostic = leg_decode_error(cause, &mut attempt);
        assert!(
            matches!(diagnostic, Error::InvariantViolation(_)),
            "model API carrier remains unchanged"
        );
        assert_eq!(
            attempt.borrow_execution_deferral().unwrap().reason(),
            ivm::error::ExecutionDeferral::LocalInvariantViolation
        );
        drop(attempt);
        drop(block);
        assert_eq!(
            state.view().height(),
            0,
            "local bookkeeping failure grants no execution output"
        );
    }
}

pub(super) fn with_paid_prepare_retry_fixture(
    test: impl FnOnce(&CertifiedTestChain, InstructionBox, KeyPair),
) {
    paid_borrowed_custody::with_paid_prepare_retry_fixture(test);
}

pub(super) fn with_paid_multisig_prepare_retry_fixture(
    test: impl FnOnce(&CertifiedTestChain, InstructionBox, KeyPair),
) {
    paid_borrowed_custody::with_paid_multisig_prepare_retry_fixture(test);
}

pub(super) fn with_paid_prepare_pruning_fixture(
    test: impl FnOnce(&CertifiedTestChain, [InstructionBox; 3], KeyPair, [[u8; 32]; 2]),
) {
    paid_borrowed_custody::with_paid_prepare_pruning_fixture(test);
}

mod returned_context;

mod multisig_semantic;

mod fixture_clock;

pub(super) fn with_paid_global_begin_fixture(
    test: impl FnOnce(&CertifiedTestChain, iroha_data_model::transaction::SignedTransaction),
) {
    paid_borrowed_custody::with_paid_global_begin_fixture(test);
}
