//! Actual native handoff execution by independent relayers, followed by fresh recovery.
//! DKG ceremonies are explicit proved component prestate, not a live-network claim.

use super::*;
use iroha_core::{
    query::native_receipts::amx_relays,
    state::{World, WorldReadOnly},
    sumeragi::{
        finality::build_proof,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::Account,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId},
    isi::{
        Grant, Mint, Register,
        sumeragi_amx::{RegisterAmxDataspaceV1, RegisterAmxParticipantV1, RelayGlobalAmxHandoffV1},
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    sumeragi_amx::NativeAmxParticipantStateV1,
    sumeragi_finality::{FinalityValidator, authenticated_genesis},
};
use iroha_model_base::{chain::ChainId, domain::DomainId, topology::DataSpaceId};
use iroha_primitives::numeric::Quantity;
use std::collections::BTreeMap;

const FIRST: DataSpaceId = DataSpaceId::new((1_u64 << 40) + 117);

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
    nexus.fees.fee_asset_id = fee_asset().canonical_address();
    nexus.fees.fee_sink_account_id = account(&config.genesis_key).to_string();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::block::consensus::PrivateRootFeePolicy {
                asset_definition_id: fee_asset(),
                base_fee: 1_u32.into(),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: 1_u32.into(),
                per_gas_unit_fee: 1_u32.into(),
            }
            .into_custom_parameter()
            .unwrap(),
        ));
    for (name, value) in [
        (
            "ivm_gas_tech_account_id",
            norito::json!(account(&config.genesis_key).to_string()),
        ),
        (
            "ivm_gas_accepted_assets",
            norito::json::Value::Array(vec![norito::json::Value::String(
                fee_asset().canonical_address(),
            )]),
        ),
        (
            "ivm_gas_units_per_gas",
            norito::json::Value::Array(vec![norito::json!({
                "asset": (fee_asset().canonical_address()), "units_per_gas": 1,
                "twap_local_per_xor": "1", "liquidity_profile": "tier2", "volatility_class": "stable",
            })]),
        ),
    ] {
        config
            .genesis_parameters
            .push(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    name.parse().unwrap(),
                    iroha_primitives::json::Json::new(value),
                ),
            ));
    }
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

struct NativeSource(BTreeMap<u64, SumeragiFinalityProof>);
impl Source for NativeSource {
    fn locate(&self, _: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>> {
        panic!("independent handoff effect recovery cannot use status as authority");
    }
    fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>> {
        Box::pin(async move {
            self.0
                .get(&height.get())
                .cloned()
                .ok_or_else(|| eyre!("no successor"))
        })
    }
    fn applied_height(&self) -> WorkflowFuture<'_, Result<u64>> {
        Box::pin(async { Ok(self.0.keys().next_back().copied().unwrap_or(0)) })
    }
}
struct NoEffects;
impl WorkflowLedger for NoEffects {
    fn dispatch<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        panic!("original certified handoff recovery must not submit another carrier");
    }
    fn committed_outcome<'a>(
        &'a self,
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        panic!("original certified handoff recovery must not trust a delegate outcome");
    }
}

#[inline(never)]
fn roots() -> (CertifiedTestChain, CertifiedTestChain) {
    let mut global = CertifiedTestChain::npos_amx_boundary_fixture();
    let target = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    let registration = RegisterAmxDataspaceV1 {
        dataspace: FIRST,
        instance: target.instance().0,
        anchor: norito::encode_canonical(
            &authenticated_genesis(target.genesis())
                .unwrap()
                .into_parts()
                .0,
        )
        .unwrap(),
    };
    let signed = global.sign(&global_config().genesis_key, [registration.into()], 1_999);
    assert_eq!(global.commit(vec![signed]), vec![true]);
    (global, target)
}

fn boundary_instruction(source: &CertifiedTestChain, height: u64) -> InstructionBox {
    let view = source.state().view();
    let mut discovery = amx_relays(&view, height).unwrap();
    let intent = discovery.complete_next().unwrap().unwrap();
    assert!(discovery.complete_next().unwrap().is_none());
    // Exercise the actual durable plan with Core's authenticated, opaque descriptor.
    // Identity remains the complete original ten-field tuple, never proof authority.
    let descriptor = intent.descriptor();
    let instruction = instruction_digest(intent.instruction()).unwrap();
    let original = norito::encode_canonical(&(
        descriptor.source_network(),
        descriptor.source_scope(),
        descriptor.source_height(),
        descriptor.source_carrier(),
        descriptor.source(),
        descriptor.target_network(),
        descriptor.target_scope(),
        descriptor.target_instance(),
        descriptor.ready_at_ms(),
        instruction,
    ))
    .unwrap();
    let digest = crate::amx_relay::domain_digest(crate::amx_relay::ID_DOMAIN, &[&original]);
    let planned = crate::amx_relay::plan(descriptor, instruction).unwrap();
    assert_eq!(planned.kind, crate::amx_relay::WorkflowKindV1::AmxRelay);
    assert_eq!(planned.instance, hex::encode(digest));
    assert_eq!(planned.driver, crate::amx_relay::driver_identity());
    assert_eq!(planned.request_context_digest, digest);
    assert_eq!(
        planned.steps,
        vec![
            crate::amx_relay::StepDescriptorV1::transaction("relay", digest)
                .with_max_transaction_identities(crate::amx_relay::MAX_CARRIER_IDENTITIES)
        ]
    );
    for flags in [0, norito::core::default_encode_flags()] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            crate::amx_relay::plan(descriptor, instruction).unwrap(),
            planned
        );
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
    let changed =
        crate::amx_relay::plan(descriptor, Hash::new(b"changed relay instruction")).unwrap();
    assert_ne!(changed.instance, planned.instance);
    assert_ne!(
        changed.request_context_digest,
        planned.request_context_digest
    );
    assert_ne!(
        changed.steps[0].intent_digest,
        planned.steps[0].intent_digest
    );
    intent.into_parts().1
}

fn recovery_ledger(target: &CertifiedTestChain, max_reads: usize) -> RelayLedger {
    let view = target.state().view();
    let proofs = (1..=target.height())
        .map(|height| (height, build_proof(&view, height).unwrap()))
        .collect();
    RelayLedger {
        source: Arc::new(NativeSource(proofs)),
        dispatch: Arc::new(NoEffects),
        verifier: Mutex::new(
            SumeragiFinalityVerifier::new(
                target.genesis(),
                "native-amx-private-root",
                target
                    .validators()
                    .iter()
                    .map(|(peer, pop)| FinalityValidator {
                        public_key: peer.public_key().clone(),
                        proof_of_possession: pop.clone(),
                    })
                    .collect(),
            )
            .unwrap(),
        ),
        network: target.network_id(),
        authority: account(&receiver()),
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        instruction: Mutex::new(None),
        approval: Mutex::new(None),
        handoff_scan: Mutex::new(HandoffScan::default()),
        max_reads,
        reads: AtomicUsize::new(max_reads),
    }
}

// Observe the actual native State through its existing canonical snapshot contract;
// this decoded test value never becomes runtime authority or bypasses retained custody.
fn participant_epoch(chain: &CertifiedTestChain) -> u64 {
    let view = chain.state().view();
    let wire = norito::encode_canonical(view.world().sumeragi_amx_participant()).unwrap();
    norito::decode_canonical::<Option<NativeAmxParticipantStateV1>>(&wire)
        .unwrap()
        .unwrap()
        .participant
        .global
        .epoch()
}

#[tokio::test]
async fn fresh_relayer_recovers_independent_native_handoffs_after_two_epochs_and_restart() {
    let (mut global, mut target) = roots();
    assert_eq!(global.height(), 10);
    let original_beacon = global
        .state()
        .view()
        .world()
        .consensus_schedule()
        .ready(11)
        .unwrap()
        .epoch
        .authorization
        .beacon;
    assert!(matches!(
        original_beacon,
        iroha_data_model::sumeragi::epoch::BeaconEpochBindingV1::Installed(_)
    ));
    let first = boundary_instruction(&global, 10);
    let signed = target.sign(&payer(), [first.clone()], 2_999);
    assert_eq!(target.commit_at(3_000, vec![signed]), vec![true]);
    global.advance_to_npos_pre_boundary_fixture();
    assert_eq!(global.height(), 19);
    global.commit(Vec::new());
    assert_eq!(global.height(), 20);
    assert_eq!(
        global
            .state()
            .view()
            .world()
            .consensus_schedule()
            .ready(21)
            .unwrap()
            .epoch
            .authorization
            .beacon,
        original_beacon,
        "retained epochs preserve the original installed DKG session and transcript"
    );
    let second = boundary_instruction(&global, 20);
    let signed = target.sign(&receiver(), [second.clone()], 3_999);
    assert_eq!(target.commit_at(4_000, vec![signed]), vec![true]);
    assert_eq!(participant_epoch(&target), 2);
    // Genuine pre-fix wedge: neither tracked epoch can authenticate the first boundary now.
    let retry = target.sign(&payer(), [first.clone()], 4_999);
    assert_eq!(target.commit_at(5_000, vec![retry]), vec![false]);
    let mut corrupted = first
        .as_any()
        .downcast_ref::<RelayGlobalAmxHandoffV1>()
        .unwrap()
        .clone();
    corrupted.proof.block.result_preimage.push(0);
    let corrupted: InstructionBox = corrupted.into();
    let invalid = target.sign(&payer(), [corrupted.clone()], 5_999);
    assert_eq!(target.commit_at(6_000, vec![invalid]), vec![false]);
    let mut restored = CertifiedTestChain::start(private_config(&global, FIRST)).unwrap();
    restored.replay_from(&target).unwrap();
    assert_eq!(participant_epoch(&restored), 2);

    // A fresh owner has no local successful carrier/journal. It independently verifies
    // the exact earlier successful effects and never dispatches the rejected old proof.
    let ledger = recovery_ledger(&restored, 2);
    ledger
        .begin_observation(instruction_digest(&first).unwrap(), None)
        .unwrap();
    assert!(
        ledger.recover_handoff(&first).await.unwrap(),
        "fresh relayer must recover the original independent successful handoff after its source epoch is no longer tracked"
    );
    // Discard all recovery cursors and verifier caches as on process restart.
    let restarted = recovery_ledger(&restored, 2);
    restarted
        .begin_observation(instruction_digest(&first).unwrap(), None)
        .unwrap();
    assert!(restarted.recover_handoff(&first).await.unwrap());
    restarted
        .begin_observation(instruction_digest(&second).unwrap(), None)
        .unwrap();
    assert!(
        restarted.recover_handoff(&second).await.unwrap(),
        "later route authority work must progress after authenticated recovery"
    );
    restarted
        .begin_observation(instruction_digest(&corrupted).unwrap(), None)
        .unwrap();
    assert!(
        restarted.recover_handoff(&corrupted).await.is_err(),
        "bounded unfinished scan is never effect absence or completion"
    );
    let mut completed = false;
    for _ in 0..restored.height() {
        restarted
            .begin_observation(instruction_digest(&corrupted).unwrap(), None)
            .unwrap();
        match restarted.recover_handoff(&corrupted).await {
            Ok(found) => {
                assert!(
                    !found,
                    "included but rejected handoff never grants delivery"
                );
                completed = true;
                break;
            }
            Err(error) => assert!(
                error.to_string().contains("proof-read budget exhausted"),
                "unexpected recovery refusal: {error}"
            ),
        }
    }
    assert!(
        completed,
        "bounded scan must retain progress across observations"
    );
    restarted
        .begin_observation(instruction_digest(&first).unwrap(), None)
        .unwrap();
    assert!(restarted.recover_handoff(&first).await.unwrap());
    // A retained match is only a locator: replacing its proof by a foreign root refuses.
    let mut foreign =
        iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::start(
            "foreign-native-handoff",
        );
    let body = foreign.block_with_submitted_work(foreign.next_header());
    let bad = foreign.certify(body);
    assert_eq!(bad.height(), 2);
    let mut substituted = recovery_ledger(&restored, 8);
    substituted
        .begin_observation(instruction_digest(&first).unwrap(), None)
        .unwrap();
    assert!(substituted.recover_handoff(&first).await.unwrap());
    substituted.source = Arc::new(NativeSource([(2, bad)].into()));
    substituted
        .begin_observation(instruction_digest(&first).unwrap(), None)
        .unwrap();
    assert!(
        substituted.recover_handoff(&first).await.is_err(),
        "cached successful height cannot replace original destination authentication"
    );
    assert_eq!(global.height(), 20);
    assert_eq!(
        restored.height(),
        5,
        "recovery requires no unrelated successor block"
    );
}
