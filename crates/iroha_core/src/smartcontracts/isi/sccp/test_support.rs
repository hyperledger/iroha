//! Deterministic fixtures shared by the SCCP core unit tests (`specs/sccp.md` §4).
//!
//! Owner: ws20. Later SCCP workstreams may extend these fixtures for their own tests.

use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldBlock},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    bridge::SccpNetworkV1,
    isi::{
        InstructionBox,
        sccp::{
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage,
            ReportSccpLightClientEquivocationV1, SetSccpBridgeKeyV1, SettleSccpV1,
            SubmitSccpAttestationFaultV1, SubmitSccpAttestationsV1, SubmitSccpInboundMessageV1,
            SubmitSccpOutboundVoidV1,
        },
    },
    sccp::{
        attestation::{
            SccpAttestationSignatureV1, SccpAttestationStatementV1, SccpAttestationStatusV1,
            SccpAttestationSubjectV1, SccpBlockCommitmentV1, SccpHistoryStateV1,
        },
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
        keys::{
            SccpAttestationFaultRecordV1, SccpBridgeKeyBindingV1, SccpBridgeKeyStateV1,
            SccpBridgeKeyV1,
        },
        keys_index::SccpPruneCursorV1,
        light_client::{
            SccpLcAdvanceBytesV1, SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1,
            SccpLcCheckpointV1, SccpLcConsensusSetV1, SccpLcEvidenceBytesV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLcProfileActivationV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        params::SccpParametersV1,
        registry::{SccpRouteRevisionV1, SccpRouteV1},
        roster::{SccpBridgeRosterV1, SccpRosterMemberV1},
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_model_base::peer::PeerId;
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

/// Return a deterministic peer.
pub(crate) fn peer(seed: u8) -> PeerId {
    PeerId::new(ed25519(seed.wrapping_add(0x80)).public_key().clone())
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

/// Populated values of the ten SCCP v1 instructions.
pub(crate) struct SampleInstructions;

impl SampleInstructions {
    /// Return `InitializeSccpV1`.
    pub(crate) fn initialize() -> InitializeSccpV1 {
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        }
    }

    /// Return a signed `SetSccpBridgeKeyV1` registration.
    pub(crate) fn set_bridge_key() -> SetSccpBridgeKeyV1 {
        let peer_keys = ed25519(0x31);
        let peer = PeerId::new(peer_keys.public_key().clone());
        let public_key = Some([2; 33]);
        let binding = SccpBridgeKeyBindingV1::new(network_id(7), peer.clone(), public_key, 3, 0);
        SetSccpBridgeKeyV1 {
            peer,
            public_key,
            activation_epoch: 3,
            binding_nonce: 0,
            peer_signature: SignatureOf::new(peer_keys.private_key(), &binding),
            key_pop: Some([0x1b; 65]),
        }
    }

    /// Return an attestation batch.
    pub(crate) fn attestations() -> SubmitSccpAttestationsV1 {
        SubmitSccpAttestationsV1 {
            entries: vec![SccpAttestationSignatureV1 {
                height: 9,
                signer_index: 0,
                signature: [0x1c; 65],
            }],
        }
    }

    /// Return fault evidence.
    pub(crate) fn fault() -> SubmitSccpAttestationFaultV1 {
        SubmitSccpAttestationFaultV1 {
            statement: SccpAttestationStatementV1 {
                height: 9,
                epoch: 1,
                timestamp_ms: 36_000,
                block_hash: word(1),
                sccp_root: word(2),
                message_count: 1,
                history_root: word(3),
                history_size: 1,
                roster_digest: word(4),
                next_roster_digest: [0; 32],
            },
            signature: [0x1b; 65],
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
            Self::set_bridge_key().into(),
            Self::attestations().into(),
            Self::fault().into(),
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

/// Return a bridge-key state with one active key.
pub(crate) fn sample_bridge_key_state(seed: u8) -> SccpBridgeKeyStateV1 {
    let mut public_key = [seed; 33];
    public_key[0] = 0x02;
    SccpBridgeKeyStateV1 {
        active: Some(SccpBridgeKeyV1 {
            public_key,
            address: address(seed),
            activation_epoch: 0,
            registered_at_height: 1,
            faulted: false,
        }),
        pending: None,
        pending_revocation_epoch: None,
        retired: Vec::new(),
        next_binding_nonce: 1,
        last_exempt_binding_epoch: Some(0),
        barred: None,
    }
}

/// Return a four-member, non-inert roster generation.
pub(crate) fn sample_roster(generation: u64, activation_height: u64) -> SccpBridgeRosterV1 {
    SccpBridgeRosterV1 {
        generation,
        valid_from_ms: activation_height.saturating_mul(4_000),
        valid_until_ms: activation_height.saturating_mul(4_000) + 1_209_600_000,
        activation_height,
        handoff_height: None,
        members: (1..=4)
            .map(|seed| SccpRosterMemberV1 {
                address: address(seed),
                peer: Some(peer(seed)),
            })
            .collect(),
        threshold: 3,
        digest: word(u8::try_from(generation % 200).unwrap_or(0) + 1),
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
        SccpRouteRevisionV1::staged(1, deployment, 1_000_000_000_000, 1, word(0x35), 2),
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
        .sccp_bridge_keys
        .insert(peer(seed), sample_bridge_key_state(seed));
    block
        .sccp_bridge_key_owners
        .insert(address(seed), peer(seed));
    block
        .sccp_rosters
        .insert(u64::from(seed), sample_roster(u64::from(seed), height));
    *block.sccp_roster_current.get_mut() = u64::from(seed);
    *block.sccp_heartbeat_marker.get_mut() = Some(u64::from(seed));
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
    block.sccp_attestation_subjects.insert(
        height,
        SccpAttestationSubjectV1 {
            height,
            epoch: 1,
            timestamp_ms: height * 4_000,
            sccp_root: word(seed),
            message_count: 1,
            history_root: word(seed),
            history_size: 1,
            generation: u64::from(seed),
            roster_digest: word(seed),
            next_roster_digest: [0; 32],
        },
    );
    block.sccp_attestation_status.insert(
        height,
        SccpAttestationStatusV1 {
            signer_bitmap: 0b111,
            attested_at_height: Some(height + 1),
        },
    );
    block
        .sccp_attestation_signatures
        .insert((height, 0), [seed; 65]);
    block.sccp_attestation_faults.insert(
        (address(seed), height),
        SccpAttestationFaultRecordV1 {
            peer: peer(seed),
            statement_hash: word(seed),
            reported_at_height: height + 2,
        },
    );
    block.sccp_member_last_signed.insert(address(seed), height);
    block.sccp_handoff_stalled.insert(height, u64::from(seed));
    *block.sccp_prune_cursor.get_mut() = SccpPruneCursorV1 {
        signatures_height: height,
        rotation_height: u64::from(seed),
    };
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
            paused: seed % 2 == 0,
            height,
            commitment_index: 1,
            leaf: word(seed),
            proposal_id: word(seed),
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
/// escrows, a live roster generation 1 from height 1, and Ethereum revision 1 in
/// `Bidirectional` with `max_wrapped_supply`.
pub(crate) fn install_outbound_route(
    state_transaction: &mut crate::state::StateTransaction<'_, '_>,
    max_wrapped_supply: u128,
) {
    use super::{escrow, store};
    use iroha_data_model::sccp::registry::SccpRouteActivationV1;

    store::parameters::set(state_transaction, Some(SccpParametersV1::taira_default()));
    escrow::create_route_escrows(state_transaction).expect("route escrows");
    store::rosters::insert(state_transaction, 1, sample_roster(1, 1)).expect("roster");
    store::roster_current::set(state_transaction, 1);
    let mut route = store::routes::get(&*state_transaction.world, &SccpNetworkV1::EthereumMainnet)
        .cloned()
        .expect("route");
    let mut revision = SccpRouteRevisionV1::staged(
        1,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: OUTBOUND_FIXTURE_CONTRACT,
            runtime_code_hash: word(0x34),
        }),
        max_wrapped_supply,
        1,
        word(0x35),
        2,
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

/// Initialize SCCP (Taira default parameters, the three route escrows, live roster generation
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
        store::rosters::insert(stx, 1, sample_roster(1, 1)).expect("roster");
        store::roster_current::set(stx, 1);
    }
    let mut route = store::routes::get(&*stx.world, &network)
        .cloned()
        .expect("route");
    let tag = word(u8::try_from(revision).unwrap_or(0x7f) ^ iroha_sccp::v1::network::tag(network));
    let mut record = SccpRouteRevisionV1::staged(
        revision,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: address(0xc0),
            runtime_code_hash: word(0x34),
        }),
        max_wrapped_supply,
        1,
        tag,
        2,
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
