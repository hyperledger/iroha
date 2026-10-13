//! Public-boundary tests of the SCCP v1 core (`specs/sccp.md` §4): leaf allocation is dense with
//! the 512-leaf cap, every SCCP instruction routes to the universal dataspace, and a network
//! without SCCP behaves exactly as before.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    queue::evaluate_policy_plan_with_nexus_and_world_at,
    smartcontracts::isi::sccp::{self, admission, fees, hook, leaves, params, store},
    state::{State, StateReadOnly, World},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::{BlockHeader, consensus::SumeragiRootScope},
    bridge::SccpNetworkV1,
    isi::{
        InstructionBox,
        sccp::{
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage,
            ReportSccpLightClientEquivocationV1, SettleSccpV1, SubmitSccpInboundMessageV1,
            SubmitSccpOutboundVoidV1,
        },
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    sccp::{
        control::SccpLeafRefV1,
        inbound::SccpSourceProofBytesV1,
        light_client::{SccpLcAdvanceBytesV1, SccpLcEvidenceBytesV1},
        params::SccpParametersV1,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::numeric::Numeric;
use std::num::{NonZeroU32, NonZeroU64};

const PRIVATE_DATASPACE: DataSpaceId = DataSpaceId::new(10);
const PRIVATE_LANE: LaneId = LaneId::new(1);

fn blank_state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn header(height: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("nonzero height"),
        None,
        None,
        height * 4_000,
        0,
    )
}

fn key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic seed")
}

fn network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        [0x7a; 32],
    )))
}

#[test]
fn leaves_are_dense_per_block_and_capped_at_512() {
    let state = blank_state();
    let mut block = state.try_block(header(5)).expect("open block");
    let mut transaction = block.try_transaction().expect("open transaction");
    let control = SccpLeafRefV1::control(SccpNetworkV1::TonMainnet, 1, 1);
    assert_eq!(leaves::allocate_leaf(&mut transaction, control), Ok(0));
    for index in 1..leaves::MAX_LEAVES_PER_BLOCK {
        let mut id = [0_u8; 32];
        id[..4].copy_from_slice(&index.to_be_bytes());
        assert_eq!(
            leaves::allocate_leaf(&mut transaction, SccpLeafRefV1::transfer(id)),
            Ok(index)
        );
    }
    assert!(
        leaves::allocate_leaf(&mut transaction, SccpLeafRefV1::transfer([0xff; 32])).is_err(),
        "the 513th leaf of a block is refused"
    );
    let recorded = leaves::leaves_at(&*transaction.world, 5);
    assert_eq!(recorded.len(), 512);
    assert_eq!(
        recorded[0], control,
        "index 0 holds the first allocated leaf"
    );
    assert!(leaves::leaves_at(&*transaction.world, 4).is_empty());
    assert_eq!(leaves::leaf_count_at(&*transaction.world, 5), 512);
}

fn signed(instructions: Vec<InstructionBox>) -> SignedTransaction {
    let signer = key_pair(0x41);
    TransactionBuilder::new(
        network_id(),
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(signer.private_key())
}

#[test]
fn every_sccp_instruction_routes_to_the_universal_dataspace() {
    let state = blank_state();
    // The two-lane Nexus configuration is evaluated directly: the blank test Kura pins the
    // default lane catalog as the immutable configured baseline, so State keeps its own.
    let mut nexus = state.nexus_snapshot();
    let lanes = LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane bound"),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: PRIVATE_LANE,
                dataspace_id: PRIVATE_DATASPACE,
                alias: "private".to_owned(),
                ..LaneConfig::default()
            },
        ],
    )
    .expect("valid lane catalog");
    nexus.lane_catalog = lanes.clone();
    nexus.lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&lanes);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: PRIVATE_DATASPACE,
            alias: "private".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("valid dataspace catalog");
    nexus.routing_policy.default_lane = PRIVATE_LANE;
    nexus.routing_policy.default_dataspace = PRIVATE_DATASPACE;
    let view = state.view();
    let route = |instructions: Vec<InstructionBox>| {
        evaluate_policy_plan_with_nexus_and_world_at(
            &nexus,
            signed(instructions).payload(),
            view.world(),
            0,
        )
        .expect("routing resolves")
        .coordinator_route()
    };
    let ordinary = route(vec![
        iroha_data_model::isi::Log::new(iroha_data_model::Level::INFO, "ordinary".to_owned())
            .into(),
    ]);
    assert_eq!(
        ordinary.dataspace_id, PRIVATE_DATASPACE,
        "the fixture routes ordinary work away from the universal dataspace"
    );
    let samples: Vec<InstructionBox> = vec![
        SettleSccpV1::inbound([1; 32]).into(),
        RecordSccpMessage {
            network: SccpNetworkV1::EthereumMainnet,
            expected_revision: 1,
            amount: Numeric::new(1_000_000_000_u64, 9),
            recipient: vec![0x22; 20],
        }
        .into(),
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        }
        .into(),
        SubmitSccpInboundMessageV1 {
            network: SccpNetworkV1::TonMainnet,
            revision: 1,
            payload: vec![1],
            proof: SccpSourceProofBytesV1::new(vec![1]).unwrap(),
        }
        .into(),
        SubmitSccpOutboundVoidV1 {
            network: SccpNetworkV1::BscMainnet,
            revision: 1,
            proof: SccpSourceProofBytesV1::new(vec![2]).unwrap(),
        }
        .into(),
        AdvanceSccpLightClientV1 {
            network: SccpNetworkV1::EthereumMainnet,
            expected_state_hash: Some([8; 32]),
            advance: SccpLcAdvanceBytesV1::new(vec![1; 64]).unwrap(),
        }
        .into(),
        ReportSccpLightClientEquivocationV1 {
            network: SccpNetworkV1::BscMainnet,
            a: SccpLcEvidenceBytesV1::new(vec![1, 2]).unwrap(),
            b: SccpLcEvidenceBytesV1::new(vec![3, 4]).unwrap(),
        }
        .into(),
    ];
    for instruction in samples {
        assert!(sccp::is_sccp_instruction(&*instruction));
        assert_eq!(
            route(vec![instruction]).dataspace_id,
            DataSpaceId::UNIVERSAL
        );
    }
}

#[test]
fn a_network_without_sccp_is_unchanged() {
    let state = blank_state();
    let view = state.view();
    let world = view.world();
    assert_eq!(params::parameters(world), None);
    assert!(!params::exists(world));
    assert!(store::routes::is_empty(world));
    assert!(store::committee_generations::is_empty(world));
    assert_eq!(*store::committee_current::get(world), 0);
    let committed_time_ms = view
        .native_execution_tip()
        .map(|tip| tip.creation_time_ms());
    assert_eq!(
        committed_time_ms, None,
        "the blank chain has no committed time"
    );
    let transaction = signed(vec![
        iroha_data_model::isi::Log::new(iroha_data_model::Level::INFO, "ordinary".to_owned())
            .into(),
    ]);
    assert_eq!(admission::classify(world, &view, 2, &transaction), Ok(None));
    assert!(!admission::allows_unregistered_authority(
        transaction.instructions()
    ));
    assert!(admission::block_exempt_cap_ok(world, &[]));
    assert!(!fees::exempt_on_success(
        world,
        transaction.payload(),
        committed_time_ms
    ));
    let log = InstructionBox::from(iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "ordinary".to_owned(),
    ));
    assert!(!sccp::is_sccp_instruction(&*log));
    drop(view);
    // Exercise the actual lifecycle owner before and after a heartbeat interval:
    // elapsed time cannot create a generation on a network without SCCP.
    let initial_time = header(2).creation_time_ms;
    let after_heartbeat = initial_time + SccpParametersV1::taira_default().committee_heartbeat_ms;
    for timestamp_ms in [initial_time, after_heartbeat, u64::MAX] {
        let candidate = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, timestamp_ms, 0);
        let mut block = state.try_block(candidate).expect("open block");
        hook::begin_block(&mut block).expect("inactive block start without SCCP");
        let finality =
            hook::finalize_block(&mut block, &candidate, None, SumeragiRootScope::Global)
                .expect("inactive without SCCP");
        assert!(!finality.is_active());
        assert!(!finality.is_rotation());
        assert_eq!(finality.height(), 2);
        assert!(store::block_commitments::is_empty(&block.world));
        assert!(store::committee_generations::is_empty(&block.world));
        assert_eq!(*store::committee_current::get(&block.world), 0);
        assert_eq!(*store::liability_clock::get(&block.world), 0);
    }
}
