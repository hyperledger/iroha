//! Deterministic fixtures shared by the SCCP core unit tests (`specs/sccp.md` §4).
//!
//! Owner: ws20. Later SCCP workstreams may extend these fixtures for their own tests.

use super::{
    anchors::SccpAnchorV1,
    generation::{SccpCommitteeGenerationV1, SccpGenerationCauseV1},
};
#[cfg(test)]
use crate::state::sccp_generation_custody::GenerationFixtureStorage as _;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldBlock},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    bridge::SccpNetworkV1,
    isi::{
        InstructionBox,
        sccp::{
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage,
            ReportSccpLightClientEquivocationV1, SettleSccpV1, SubmitSccpInboundMessageV1,
            SubmitSccpOutboundVoidV1,
        },
    },
    sccp::{
        commitment::{SccpBlockCommitmentV1, SccpHistoryStateV1},
        control::{SccpControlRecordV1, SccpLeafRefV1},
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        escrow::sccp_xor_route_escrow_account_id_v1,
        governance::{
            SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
            SccpSetParametersActionV1,
        },
        inbound::{
            SccpInboundRecordV1, SccpInboundStatusV1, SccpPendingReasonV1, SccpSourceLocatorV1,
            SccpSourceProofBytesV1,
        },
        light_client::{
            SccpLcAdvanceBytesV1, SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1,
            SccpLcCheckpointV1, SccpLcConsensusSetV1, SccpLcEvidenceBytesV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLcProfileActivationV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
        native::SccpCommitteePinV1,
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        params::SccpParametersV1,
        registry::{SccpRouteRevisionV1, SccpRouteV1},
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_primitives::numeric::Numeric;
use std::num::NonZeroU64;

/// Return a blank test [`State`].
pub(crate) fn blank_state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

/// Return a header at `height` with creation time `height × 4 s`.
pub(crate) fn header(height: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("nonzero fixture height"),
        None,
        None,
        height.saturating_mul(4_000),
        0,
    )
}

fn ed25519(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic seed")
}

/// Return a deterministic account.
pub(crate) fn authority(seed: u8) -> AccountId {
    AccountId::new(ed25519(seed).public_key().clone())
}

fn network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        [seed; 32],
    )))
}

fn word(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn address(seed: u8) -> [u8; 20] {
    [seed; 20]
}

/// Populated values of the seven SCCP v1 instructions.
pub(crate) struct SampleInstructions;

impl SampleInstructions {
    /// Return `InitializeSccpV1`.
    pub(crate) fn initialize() -> InitializeSccpV1 {
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        }
    }

    /// Return an outbound record request.
    pub(crate) fn record() -> RecordSccpMessage {
        RecordSccpMessage {
            network: SccpNetworkV1::EthereumMainnet,
            expected_revision: 1,
            amount: Numeric::new(1_500_000_000_u64, 9),
            recipient: vec![0x22; 20],
        }
    }

    /// Return an inbound proof submission.
    pub(crate) fn inbound() -> SubmitSccpInboundMessageV1 {
        SubmitSccpInboundMessageV1 {
            network: SccpNetworkV1::TonMainnet,
            revision: 2,
            payload: vec![2, 1, 0, 0, 0, 4],
            proof: SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54, 0x30, 0x01])
                .expect("bounded proof"),
        }
    }

    /// Return a settlement retry.
    pub(crate) fn settle() -> SettleSccpV1 {
        SettleSccpV1::inbound(word(6))
    }

    /// Return a void proof submission.
    pub(crate) fn void() -> SubmitSccpOutboundVoidV1 {
        SubmitSccpOutboundVoidV1 {
            network: SccpNetworkV1::BscMainnet,
            revision: 1,
            proof: SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54, 0x30, 0x02])
                .expect("bounded proof"),
        }
    }

    /// Return a light-client advance.
    pub(crate) fn advance() -> AdvanceSccpLightClientV1 {
        AdvanceSccpLightClientV1 {
            network: SccpNetworkV1::EthereumMainnet,
            expected_state_hash: Some(word(8)),
            advance: SccpLcAdvanceBytesV1::new(vec![1; 64]).expect("bounded advance"),
        }
    }

    /// Return a decodable ETH/BSC keeper shape with no proof of source finality.
    ///
    /// Fee/admission tests use it to distinguish eligibility from successful verification.
    pub(crate) fn keeper_advance(network: SccpNetworkV1) -> AdvanceSccpLightClientV1 {
        use iroha_sccp::light_client::{
            bsc::BscLcAdvanceV1, ethereum::EthereumLcAdvanceV1, proof::SccpLcAdvanceV1,
        };
        let advance = match network {
            SccpNetworkV1::EthereumMainnet => SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
                updates: Vec::new(),
            }),
            SccpNetworkV1::BscMainnet => SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 { steps: Vec::new() }),
            _ => panic!("keeper fixture supports only ETH and BSC"),
        };
        AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: None,
            advance: advance.to_bytes().expect("bounded keeper shape"),
        }
    }

    /// Return a light-client equivocation report.
    pub(crate) fn equivocation() -> ReportSccpLightClientEquivocationV1 {
        ReportSccpLightClientEquivocationV1 {
            network: SccpNetworkV1::BscMainnet,
            a: SccpLcEvidenceBytesV1::new(vec![1, 2]).expect("bounded evidence"),
            b: SccpLcEvidenceBytesV1::new(vec![3, 4]).expect("bounded evidence"),
        }
    }

    /// Return every instruction boxed, in the canonical v1 order.
    pub(crate) fn all() -> Vec<InstructionBox> {
        vec![
            Self::initialize().into(),
            Self::record().into(),
            Self::inbound().into(),
            Self::settle().into(),
            Self::void().into(),
            Self::advance().into(),
            Self::equivocation().into(),
        ]
    }
}

/// Return an ordinary signed transaction that claims no SCCP exemption.
pub(crate) fn sample_signed_transaction() -> SignedTransaction {
    let key_pair = ed25519(0x41);
    TransactionBuilder::new(
        network_id(9),
        AccountId::new(key_pair.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "ordinary".to_owned(),
    )])
    .sign(key_pair.private_key())
}

/// Return a four-member native BLS committee generation with captured time bounds.
pub(crate) fn sample_generation(generation: u64, start_height: u64) -> SccpCommitteeGenerationV1 {
    let mut keys = (1..=4)
        .map(|seed| {
            let pair =
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).expect("BLS fixture");
            pair.public_key()
                .try_to_bytes()
                .expect("public bytes")
                .1
                .try_into()
                .expect("48-byte key")
        })
        .collect::<Vec<[u8; 48]>>();
    keys.sort();
    let params = SccpParametersV1::taira_default();
    let start_timestamp_ms = start_height.saturating_mul(4_000);
    SccpCommitteeGenerationV1 {
        generation,
        committee_root: iroha_data_model::sumeragi_finality::certified_result::committee_root(
            &keys,
        )
        .expect("root"),
        keys,
        members: vec![None; 4],
        cause: if generation == 1 {
            SccpGenerationCauseV1::Genesis
        } else {
            SccpGenerationCauseV1::Heartbeat
        },
        start_height,
        start_timestamp_ms,
        start_lc: start_timestamp_ms,
        validity_ms: params.committee_validity_ms,
        deadline_ms: start_timestamp_ms.saturating_add(params.committee_validity_ms),
        grace_ms: params.forgery_evidence_grace_ms,
        progress_cap_ms: params.destination_progress_cap_ms,
        liable_until_lc: start_timestamp_ms
            .saturating_add(params.committee_validity_ms)
            .saturating_add(params.forgery_evidence_grace_ms),
        dest_cleared_lc: None,
        end: None,
    }
}

/// Project a test generation's exact pin; this adds no registration or member authority.
pub(crate) fn sample_pin(generation: &SccpCommitteeGenerationV1) -> SccpCommitteePinV1 {
    SccpCommitteePinV1 {
        generation: generation.generation,
        committee_root: generation.committee_root,
        start_height: generation.start_height,
        until_ms: generation.deadline_ms,
    }
}

/// Return an exact-width original consensus anchor for storage tests.
pub(crate) fn sample_anchor(seed: u8) -> SccpAnchorV1 {
    SccpAnchorV1 {
        core_hash: word(seed),
        result: word(seed.wrapping_add(1)),
    }
}

/// Return an empty route of `network` with one staged revision `1`.
pub(crate) fn sample_route(network: SccpNetworkV1) -> SccpRouteV1 {
    let escrow = sccp_xor_route_escrow_account_id_v1(&network_id(7), network)
        .expect("an external network has a route");
    let mut route = SccpRouteV1::empty(network, escrow).expect("an external network has a route");
    let deployment = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
        address: address(0x33),
        runtime_code_hash: word(0x34),
    });
    route.revisions.insert(
        1,
        SccpRouteRevisionV1::staged(
            1,
            deployment,
            sample_pin(&sample_generation(1, 1)),
            1_000_000_000_000,
            1,
        ),
    );
    route
}

/// Return a statically valid SCCP governance proposal under `network_id`.
pub(crate) fn sample_proposal(network_id: NetworkId) -> SccpGovernanceProposalV1 {
    SccpGovernanceProposalV1 {
        network_id,
        base_revisions: vec![(SccpGovernanceSubjectV1::Parameters, 0).into()],
        actions: vec![SccpGovernanceActionV1::SetParameters(
            SccpSetParametersActionV1 {
                next: SccpParametersV1::taira_default(),
            },
        )],
    }
}

/// Populate every SCCP world map and cell of `block` with `seed`-distinct values, so a
/// snapshot or projection test exercises the complete SCCP field inventory.
pub(crate) fn populate_every_sccp_map(block: &mut WorldBlock<'_>, seed: u8) {
    let network = SccpNetworkV1::EthereumMainnet;
    let height = u64::from(seed) + 10;
    *block.sccp_parameters.get_mut() = Some(SccpParametersV1::taira_default());
    *block.sccp_reset_nonce.get_mut() = Some(word(seed | 1));
    block
        .sccp_committee_generations
        .insert(u64::from(seed), sample_generation(u64::from(seed), height));
    *block.sccp_committee_current.get_mut() = u64::from(seed);
    *block.sccp_liability_clock.get_mut() = height * 4_000;
    *block.sccp_degraded_run.get_mut() = u32::from(seed);
    *block.sccp_anchor_open.get_mut() = vec![sample_anchor(seed)];
    block.sccp_anchor_chunks.insert(u64::from(seed), word(seed));
    block
        .sccp_block_leaves
        .insert((height, 0), SccpLeafRefV1::transfer(word(seed)));
    block.sccp_block_commitments.insert(
        height,
        SccpBlockCommitmentV1 {
            root: word(seed),
            message_count: 1,
            history_index: u64::from(seed),
        },
    );
    *block.sccp_history.get_mut() = SccpHistoryStateV1 {
        size: 1,
        peaks: vec![word(seed)],
    };
    block
        .sccp_history_leaves
        .insert(u64::from(seed), (height, word(seed)));
    block.sccp_outbound_messages.insert(
        word(seed),
        SccpOutboundMessageRecordV1 {
            network,
            revision: 1,
            nonce: u64::from(seed),
            height,
            commitment_index: 0,
            deadline_ms: height * 4_000 + 604_800_000,
            sender: authority(seed),
            amount: 1_000_000_000,
            payload: vec![seed; 8],
            leaf: word(seed),
            status: SccpOutboundStatusV1::Recorded,
        },
    );
    block
        .sccp_outbound_by_nonce
        .insert((network, 1, u64::from(seed)), word(seed));
    block.sccp_control_messages.insert(
        (network, 1, u64::from(seed)),
        SccpControlRecordV1 {
            track: 1,
            parliament_paused: seed % 2 == 0,
            fast_pause_until_ms: 0,
            height,
            commitment_index: 1,
            leaf: word(seed),
            certificate_id: word(seed),
            effect_hash: [0x45; 32],
        },
    );
    block.sccp_routes.insert(network, sample_route(network));
    block
        .sccp_destination_words
        .insert(word(seed), (network, 1));
    block
        .sccp_governance_revisions
        .insert(SccpGovernanceSubjectV1::Route(network), u64::from(seed));
    block.sccp_inbound_messages.insert(
        word(seed),
        SccpInboundRecordV1 {
            network,
            revision: 1,
            payload: vec![seed; 8],
            source_locator: SccpSourceLocatorV1 {
                source_height: height,
                block_hash: word(seed),
                index_in_block: 0,
            },
            proven_at_height: height,
            fee_due: 0,
            status: SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled),
        },
    );
    block
        .sccp_pending_counts
        .insert((network, 1), (u64::from(seed), 0));
    block.sccp_light_clients.insert(
        network,
        SccpLightClientV1 {
            params: SccpLightClientParamsV1::defaults_for(network).expect("external network"),
            head: SccpLcHeadV1 {
                latest_set_id: u64::from(seed),
                latest_finalized: SccpLcPointV1 {
                    source_height: height,
                    block_hash: word(seed),
                    source_time_ms: height * 12_000,
                },
                last_progress_taira_ms: height * 4_000,
            },
            frozen: None,
            state_hash: word(seed),
        },
    );
    block.sccp_light_client_sets.insert(
        (network, u64::from(seed)),
        SccpLcConsensusSetV1 {
            set_id: u64::from(seed),
            valid_from_source_height: height,
            superseded_at_source_ms: None,
            set_bytes: vec![seed; 16],
        },
    );
    block.sccp_light_client_checkpoints.insert(
        (network, height),
        SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: height,
                block_hash: word(seed),
                state_root: Some(word(seed)),
                receipts_or_tx_root: word(seed),
                source_time_ms: height * 12_000,
            },
            recorded_at_taira_ms: height * 4_000,
            origin: SccpLcCheckpointOriginV1::Advance,
        },
    );
    block
        .sccp_light_client_stride_index
        .insert((network, height / 8_192), height);
    block.sccp_light_client_profiles.insert(
        (network, u32::from(seed) + 1),
        SccpLcProfileActivationV1 {
            profile_hash: word(seed),
            activation_height: height + 1,
            proposal_id: word(seed),
        },
    );
}

/// EVM contract address of the outbound fixture's Ethereum revision 1.
pub(crate) const OUTBOUND_FIXTURE_CONTRACT: [u8; 20] = [0xc0; 20];

/// Install live SCCP for an outbound record (§4.4): Taira default parameters, the route
/// escrows, a live committee generation 1 from height 1, and Ethereum revision 1 in
/// `Bidirectional` with `max_wrapped_supply`.
pub(crate) fn install_outbound_route(
    state_transaction: &mut crate::state::StateTransaction<'_, '_>,
    max_wrapped_supply: u128,
) {
    use super::{escrow, store};
    use iroha_data_model::sccp::registry::SccpRouteActivationV1;

    store::parameters::set(state_transaction, Some(SccpParametersV1::taira_default()));
    escrow::create_route_escrows(state_transaction).expect("route escrows");
    store::committee_generations::insert(state_transaction, 1, sample_generation(1, 1))
        .expect("generation");
    store::committee_current::set(state_transaction, 1);
    let mut route = store::routes::get(&*state_transaction.world, &SccpNetworkV1::EthereumMainnet)
        .cloned()
        .expect("route");
    let mut revision = SccpRouteRevisionV1::staged(
        1,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: OUTBOUND_FIXTURE_CONTRACT,
            runtime_code_hash: word(0x34),
        }),
        sample_pin(
            store::committee_generations::get(&*state_transaction.world, &1).expect("generation"),
        ),
        max_wrapped_supply,
        1,
    );
    revision.activation = SccpRouteActivationV1::Bidirectional;
    route.revisions.insert(1, revision);
    store::routes::insert(state_transaction, SccpNetworkV1::EthereumMainnet, route).expect("route");
}

/// Set `holder`'s XOR balance to `units` Taira units.
pub(crate) fn set_xor_balance(
    state_transaction: &mut crate::state::StateTransaction<'_, '_>,
    holder: &AccountId,
    units: u128,
) {
    use iroha_data_model::{
        IntoKeyValue,
        asset::{Asset, AssetId},
        sccp::escrow::sccp_taira_xor_asset_definition_id,
    };

    let asset = AssetId::of(sccp_taira_xor_asset_definition_id(), holder.clone());
    let quantity = super::escrow::xor_quantity(units).expect("XOR quantity");
    let (_, value) = Asset::new(asset.clone(), quantity).into_key_value();
    state_transaction.world.assets.insert(asset, value);
}

/// Return the fixture's record of `amount_xor` whole XOR to `recipient` on Ethereum revision 1.
pub(crate) fn outbound_record(amount_xor: u32, recipient: [u8; 20]) -> RecordSccpMessage {
    RecordSccpMessage {
        network: SccpNetworkV1::EthereumMainnet,
        expected_revision: 1,
        amount: Numeric::new(amount_xor, 0),
        recipient: recipient.to_vec(),
    }
}

/// Return the sender of the Ethereum revision 1 outbound record with `nonce`, if recorded.
pub(crate) fn outbound_sender(
    world: &(impl crate::state::WorldReadOnly + ?Sized),
    nonce: u64,
) -> Option<AccountId> {
    use super::store;

    let message_id =
        store::outbound_by_nonce::get(world, &(SccpNetworkV1::EthereumMainnet, 1, nonce))?;
    store::outbound_messages::get(world, message_id).map(|record| record.sender.clone())
}

/// One XOR in Taira units (`specs/sccp.md` §0).
pub(crate) const ONE_XOR: u128 = 1_000_000_000;

/// Return a state in which `holder` owns the Taira XOR definition and holds `balance` Taira
/// units of XOR.
pub(crate) fn funded_xor_state(holder: &AccountId, balance: u128) -> State {
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetId},
        sccp::escrow::sccp_taira_xor_asset_definition_id,
    };
    let xor = sccp_taira_xor_asset_definition_id();
    let definition = AssetDefinition::numeric(
        xor.clone(),
        "XOR".to_owned(),
        AssetBalancePolicy::Global,
        None,
    )
    .build(holder);
    let world = World::with_assets(
        [],
        [Account::new(holder.clone()).build(holder)],
        [definition],
        [Asset::new(
            AssetId::of(xor, holder.clone()),
            super::escrow::xor_quantity(balance).expect("quantity"),
        )],
        [],
    );
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

/// Initialize SCCP (Taira default parameters, the three route escrows, live committee generation
/// 1) unless it already exists, and add revision `revision` of `network` with `activation` and
/// the cap `max_wrapped_supply`.
pub(crate) fn install_value_route(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    activation: iroha_data_model::sccp::registry::SccpRouteActivationV1,
    max_wrapped_supply: u128,
) {
    use super::{escrow, store};
    if store::parameters::get(&*stx.world).is_none() {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        escrow::create_route_escrows(stx).expect("escrows");
        store::committee_generations::insert(stx, 1, sample_generation(1, 1)).expect("generation");
        store::committee_current::set(stx, 1);
    }
    let mut route = store::routes::get(&*stx.world, &network)
        .cloned()
        .expect("route");
    let mut record = SccpRouteRevisionV1::staged(
        revision,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: address(0xc0),
            runtime_code_hash: word(0x34),
        }),
        sample_pin(
            store::committee_generations::get(
                &*stx.world,
                store::committee_current::get(&*stx.world),
            )
            .expect("current generation"),
        ),
        max_wrapped_supply,
        1,
    );
    record.activation = activation;
    route.revisions.insert(revision, record);
    store::routes::insert(stx, network, route).expect("route");
}

/// Return the XOR balance of `account` in Taira units.
pub(crate) fn xor_balance(
    world: &(impl crate::state::WorldReadOnly + ?Sized),
    account: &AccountId,
) -> u128 {
    use iroha_data_model::{asset::AssetId, sccp::escrow::sccp_taira_xor_asset_definition_id};
    use mv::storage::StorageReadOnly;
    world
        .assets()
        .get(&AssetId::of(
            sccp_taira_xor_asset_definition_id(),
            account.clone(),
        ))
        .filter(|quantity| !quantity.as_ref().is_zero())
        .map_or(0, |quantity| {
            iroha_sccp::v1::amount::taira_units(quantity.as_ref().as_numeric())
                .expect("a canonical XOR balance")
        })
}

/// Assert the escrow invariants of every route (`specs/sccp.md` §4.15):
/// `balance(escrow(route)) = Σ_r liability(r) + stranded(route)` and
/// `liability(r) ≤ max_wrapped_supply(r)`; `context` names the failing step.
pub(crate) fn assert_escrow_invariant(
    world: &(impl crate::state::WorldReadOnly + ?Sized),
    context: &str,
) {
    for (network, route) in super::store::routes::iter(world) {
        let liability: u128 = route
            .revisions
            .values()
            .map(|revision| {
                assert!(
                    revision.liability <= revision.max_wrapped_supply,
                    "{context}: {network:?} revision {} liability {} exceeds its cap {}",
                    revision.revision,
                    revision.liability,
                    revision.max_wrapped_supply
                );
                revision.liability
            })
            .sum();
        assert_eq!(
            xor_balance(world, &route.escrow),
            liability + route.stranded,
            "{context}: {network:?} escrow balance != Σ liability {liability} + stranded {}",
            route.stranded
        );
    }
}
