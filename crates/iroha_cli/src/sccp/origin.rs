//! Authenticate native routes and deployment pins from a selected signed genesis and complete certified World cut.

use crate::RunContext;
use eyre::{Result, ensure, eyre};
use iroha::{
    blocking::Client,
    crypto::{Hash, HashOf, PublicKey},
    data_model::{
        block::{BlockHeader, consensus::SumeragiRootScope},
        bridge::SccpNetworkV1,
        id::NetworkId,
        sccp::{
            deployment::SccpCommitteePinV1,
            generation::{SccpAnchorV1, SccpCommitteeGenerationV1},
            native::SccpAnchorWitnessV1,
            params::{SCCP_PIN_MARGIN_MS_V1, SccpParametersV1},
            registry::SccpRouteV1,
        },
        sumeragi_finality::{
            FinalityValidator, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, SumeragiFinalityProof,
            SumeragiFinalityVerifier, VerifiedSumeragiBlock, VerifiedWorldStateSnapshotV1,
            WorldStateSnapshotV1,
        },
    },
};
use iroha_sccp::{
    api::{SccpCapabilitiesV1, SccpGenerationV1},
    v1::committee::committee_root,
};
use std::{
    io::Read as _,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

/// Independently selected origin and one bounded complete native snapshot.
#[derive(clap::Args, Debug)]
pub(super) struct OriginArgs {
    /// Canonical signed genesis retained independently of Torii discovery.
    #[arg(long)]
    pub signed_genesis: PathBuf,
    /// Original manifest checked against the signed genesis semantics.
    #[arg(long)]
    pub genesis_manifest: PathBuf,
    /// Independently retained genesis verification key.
    #[arg(long)]
    pub genesis_public_key: PublicKey,
    /// Independently retained canonical genesis hash.
    #[arg(long)]
    pub genesis_hash: Hash,
    /// Explicit applied height of the complete snapshot (at least 2).
    /// Resume transaction confirmation with a selected cut at or after its committed height.
    #[arg(long, value_parser=clap::value_parser!(u64).range(2..))]
    pub at_height: u64,
    /// Complete canonical `WorldStateSnapshotV1` frame exported at that native cut.
    #[arg(long)]
    pub world_snapshot: PathBuf,
    /// Native registry schema hash independently selected with the release that produced the snapshot.
    #[arg(long)]
    pub world_schema_hash: Hash,
}

/// Only this module can create deployment inputs after original authority checks.
#[derive(Debug)]
pub(super) struct AuthenticatedPin {
    pub network: [u8; 32],
    pub instance: [u8; 32],
    pub pin: SccpCommitteePinV1,
    pub keys: Vec<[u8; 48]>,
}

fn bounded_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "{} exceeds its finite input bound",
        path.display()
    );
    Ok(bytes)
}

/// The API record adds `liable`; the native canonical World value contains only Model fields.
fn native_record(view: SccpGenerationV1) -> SccpCommitteeGenerationV1 {
    SccpCommitteeGenerationV1 {
        generation: view.generation,
        committee_root: view.committee_root,
        keys: view.keys,
        members: view.members,
        cause: view.cause,
        start_height: view.start_height,
        start_timestamp_ms: view.start_timestamp_ms,
        start_lc: view.start_lc,
        validity_ms: view.validity_ms,
        deadline_ms: view.deadline_ms,
        grace_ms: view.grace_ms,
        progress_cap_ms: view.progress_cap_ms,
        liable_until_lc: view.liable_until_lc,
        dest_cleared_lc: view.dest_cleared_lc,
        end: view.end,
    }
}
fn authenticate_record(
    world: &VerifiedWorldStateSnapshotV1,
    requested: u64,
    view: SccpGenerationV1,
    required_until: u64,
) -> Result<SccpCommitteeGenerationV1> {
    let record = native_record(view);
    ensure!(
        record.generation == requested && record.is_well_formed(),
        "committee candidate has invalid generation or shape"
    );
    world.verify_table_value("world.sccp_committee_generations", &requested, &record)?;
    ensure!(
        committee_root(&record.keys) == Some(record.committee_root),
        "authenticated committee keys have a different root"
    );
    ensure!(
        record.members.iter().all(Option::is_some),
        "committee contains an unresolved staking binding"
    );
    ensure!(
        record.deadline_ms >= required_until,
        "committee {requested} expires before the deployment pin horizon"
    );
    Ok(record)
}

fn authenticated_world(
    wire: &[u8],
    schema_hash: Hash,
    tip: &VerifiedSumeragiBlock,
) -> Result<(VerifiedWorldStateSnapshotV1, usize)> {
    let snapshot = WorldStateSnapshotV1::decode_bounded_canonical(wire)?;
    ensure!(
        snapshot.schema_hash == schema_hash,
        "snapshot uses a different independently selected native registry schema"
    );
    Ok((snapshot.authenticate(tip)?, snapshot.entries.len()))
}

fn selected_network(hash: HashOf<BlockHeader>, configured: NetworkId) -> Result<NetworkId> {
    let network = NetworkId::from_genesis_hash(hash);
    ensure!(
        network == configured,
        "selected genesis differs from the configured network"
    );
    Ok(network)
}
fn selected_interval(selected: Option<u64>, current: u64, element_count: usize) -> Result<u64> {
    let selected = selected.unwrap_or(current);
    ensure!(
        selected > 0 && selected <= current,
        "requested generation is outside retained native history"
    );
    ensure!(
        current - selected < element_count as u64,
        "claimed generation interval cannot fit the complete snapshot"
    );
    Ok(selected)
}

/// Original native authority and a complete certified World cut selected independently of discovery.
pub(super) struct AuthenticatedOrigin {
    pub network: [u8; 32],
    pub instance: [u8; 32],
    world: VerifiedWorldStateSnapshotV1,
    element_count: usize,
    verifier: SumeragiFinalityVerifier,
}

impl AuthenticatedOrigin {
    /// Reopen only an original retained Global decision at or before the selected cut.
    /// A later transaction requires a new independently selected cut when resuming.
    pub fn verify_retained_block(
        &self,
        proof: &SumeragiFinalityProof,
    ) -> Result<VerifiedSumeragiBlock> {
        ensure!(
            proof.height() <= self.height(),
            "transaction is newer than the selected original cut; resume with a cut at or after its height"
        );
        let block = self.verifier.verify_retained_decision(proof)?;
        let network = self.verifier.initial_epoch().network_id;
        ensure!(
            *network.as_bytes() == self.network && self.verifier.instance().0 == self.instance,
            "retained verifier differs from the original native identity"
        );
        block.verify_global_scope(network, self.verifier.chain_id())?;
        Ok(block)
    }

    /// Public original cut identity retained with a journal's authenticated receipt.
    pub fn receipt_cut(&self) -> norito::json::Value {
        norito::json!({
            "network_id": (self.network),
            "consensus_instance": (self.instance),
            "chain_id": (self.verifier.chain_id()),
            "height": (self.height()),
            "context_id": (self.world.context_id()),
            "world_root": (self.world.world_root()),
            "schema_hash": (self.world.schema_hash()),
        })
    }

    /// Authenticate an exact message record and derive finality from its stored lifecycle.
    pub fn verify_message(
        &self,
        message_id: &[u8; 32],
        status: &iroha_sccp::api::SccpMessageStatusV1,
    ) -> Result<bool> {
        use iroha_data_model::sccp::outbound::SccpOutboundStatusV1 as Stored;
        use iroha_sccp::api::{
            SccpMessageStatusV1 as Message, SccpOutboundStateV1 as State, SccpRecordedStateV1,
        };
        match status {
            Message::Unknown => Ok(false),
            Message::Inbound(view) => {
                ensure!(
                    &view.message_id == message_id,
                    "inbound message identity differs"
                );
                self.world.verify_table_value(
                    "world.sccp_inbound_messages",
                    message_id,
                    &view.record,
                )?;
                Ok(!view.record.status.is_pending())
            }
            Message::Outbound(view) => {
                ensure!(
                    &view.message_id == message_id,
                    "outbound message identity differs"
                );
                self.world.verify_table_value(
                    "world.sccp_outbound_messages",
                    message_id,
                    &view.record,
                )?;
                let expected = match view.record.status {
                    Stored::Recorded => State::Recorded(SccpRecordedStateV1 {
                        deadline_ms: view.record.deadline_ms,
                        provable: view.record.height != 0 && view.record.height <= self.height(),
                    }),
                    Stored::Voided(value) => State::Voided(value),
                    Stored::Refunded(value) => State::Refunded(value),
                    Stored::Stranded(value) => State::Stranded(value),
                };
                ensure!(
                    view.state == expected,
                    "outbound status projection differs from the authenticated record"
                );
                Ok(matches!(
                    view.record.status,
                    Stored::Refunded(_) | Stored::Stranded(_)
                ))
            }
        }
    }

    /// The original native cut chosen by the caller, never a discovery response's tip.
    pub fn height(&self) -> u64 {
        self.world.height()
    }

    /// Verify a retained generation candidate without imposing a deployment pin horizon.
    pub fn verify_generation(
        &self,
        requested: u64,
        view: SccpGenerationV1,
    ) -> Result<SccpCommitteeGenerationV1> {
        let record = native_record(view);
        ensure!(
            record.generation == requested && record.is_well_formed(),
            "committee candidate has invalid generation or shape"
        );
        self.world
            .verify_table_value("world.sccp_committee_generations", &requested, &record)?;
        ensure!(
            committee_root(&record.keys) == Some(record.committee_root),
            "authenticated committee keys have a different root"
        );
        Ok(record)
    }

    /// Bind a completed anchor path to the exact original retained chunk root.
    pub fn verify_anchor_witness(&self, height: u64, witness: &SccpAnchorWitnessV1) -> Result<()> {
        use iroha_sccp::v1::evidence::{anchor_chunk_position, anchor_leaf, anchor_path_root};
        let (chunk, position) =
            anchor_chunk_position(height).ok_or_else(|| eyre!("anchor height must be positive"))?;
        let leaf = anchor_leaf(height, &witness.core_hash, &witness.result);
        let root = anchor_path_root(&leaf, position, &witness.path)
            .ok_or_else(|| eyre!("anchor path has an invalid position"))?;
        self.world
            .verify_table_value("world.sccp_anchor_chunks", &chunk, &root)?;
        Ok(())
    }

    pub fn verify_route(&self, network: SccpNetworkV1, route: &SccpRouteV1) -> Result<()> {
        ensure!(
            route.network == network,
            "route names another requested network"
        );
        self.world
            .verify_table_value("world.sccp_routes", &network, route)?;
        Ok(())
    }

    pub fn verify_pin_generation(
        &self,
        view: SccpGenerationV1,
        pin: &SccpCommitteePinV1,
    ) -> Result<Vec<[u8; 48]>> {
        let record = authenticate_record(&self.world, pin.generation, view, pin.until_ms)?;
        ensure!(
            record.committee_root == pin.committee_root && record.start_height == pin.start_height,
            "deployment pin differs from its authenticated generation"
        );
        Ok(record.keys)
    }

    pub fn verify_capabilities(&self, capabilities: &SccpCapabilitiesV1) -> Result<()> {
        ensure!(
            capabilities.network_id == self.network
                && capabilities.consensus_instance == self.instance,
            "SCCP discovery differs from the selected original native root"
        );
        Ok(())
    }

    /// Read parameters only when their exact cell belongs to the selected original cut.
    pub fn parameters(&self, capabilities: &SccpCapabilitiesV1) -> Result<SccpParametersV1> {
        self.verify_capabilities(capabilities)?;
        self.world
            .verify_cell_value("world.sccp_parameters", &capabilities.parameters)?;
        capabilities
            .parameters
            .ok_or_else(|| eyre!("SCCP parameters are absent"))
    }

    /// Read the permanent forgery floor only from its exact original committed cell.
    pub fn forgery_max(&self, capabilities: &SccpCapabilitiesV1) -> Result<Option<u64>> {
        self.verify_capabilities(capabilities)?;
        self.world.verify_cell_value(
            "world.sccp_forgery_max_generation",
            &capabilities.forgery_max_generation,
        )?;
        Ok(capabilities.forgery_max_generation)
    }

    pub fn current_generation(&self, capabilities: &SccpCapabilitiesV1) -> Result<u64> {
        self.verify_capabilities(capabilities)?;
        let current = capabilities
            .current_generation
            .as_ref()
            .ok_or_else(|| eyre!("SCCP is not initialized"))?;
        self.world
            .verify_cell_value("world.sccp_committee_current", &current.generation)?;
        Ok(current.generation)
    }
}

pub(super) fn authenticate_origin<C: RunContext>(
    context: &C,
    client: &Client,
    args: &OriginArgs,
) -> Result<AuthenticatedOrigin> {
    authenticate_origin_with_anchor(context, client, args, None).map(|(origin, _)| origin)
}

/// Retain at most one original certified anchor while performing the same contiguous walk.
pub(super) fn authenticate_origin_with_anchor<C: RunContext>(
    context: &C,
    client: &Client,
    args: &OriginArgs,
    anchor_height: Option<u64>,
) -> Result<(AuthenticatedOrigin, Option<SccpAnchorV1>)> {
    ensure!(
        args.at_height >= 2,
        "native authority needs a certified successor"
    );
    let hash = HashOf::<BlockHeader>::from_untyped_unchecked(args.genesis_hash);
    let network = selected_network(hash, context.config().network_id)?;
    let wire = bounded_read(&args.signed_genesis, 32 * 1024 * 1024)?;
    let manifest_bytes = bounded_read(&args.genesis_manifest, 16 * 1024 * 1024)?;
    let manifest: iroha_genesis::RawGenesisTransaction = norito::json::from_slice(&manifest_bytes)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &wire,
        &manifest,
        &args.genesis_public_key,
        hash,
    )?;
    let mut validators: Vec<_> = genesis
        .validator_pops()
        .iter()
        .map(|(key, pop)| FinalityValidator {
            public_key: key.clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    validators.sort_by(|left, right| {
        left.public_key
            .to_bytes()
            .1
            .cmp(right.public_key.to_bytes().1)
    });
    let mut verifier =
        SumeragiFinalityVerifier::new(genesis.block(), manifest.chain_id().as_ref(), validators)?;
    ensure!(
        verifier.root_scope() == SumeragiRootScope::Global,
        "SCCP requires the original Global root"
    );
    // The caller selects the height. The endpoint cannot extend this work by advertising a new tip.
    let mut tip = None;
    let mut anchor = None;
    for height in 1..=args.at_height {
        let proof = client.client().get_sumeragi_finality_proof(
            NonZeroU64::new(height).expect("positive range"),
            verifier.root_scope(),
        )?;
        let authenticated = verifier.verify(&proof)?;
        if anchor_height == Some(height) {
            anchor = Some(SccpAnchorV1 {
                core_hash: authenticated.core_hash().0,
                result: authenticated.result().0,
            });
        }
        tip = Some(authenticated);
    }
    let tip = tip.ok_or_else(|| eyre!("no certified successor"))?;
    tip.verify_global_scope(network, verifier.chain_id())?;
    let snapshot_wire = bounded_read(&args.world_snapshot, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1)?;
    let (world, element_count) = authenticated_world(&snapshot_wire, args.world_schema_hash, &tip)?;
    Ok((
        AuthenticatedOrigin {
            network: *network.as_bytes(),
            instance: verifier.instance().0,
            world,
            element_count,
            verifier,
        },
        anchor,
    ))
}

pub(super) fn authenticate<C: RunContext>(
    context: &C,
    client: &Client,
    args: &OriginArgs,
    selected: Option<u64>,
) -> Result<AuthenticatedPin> {
    let original = authenticate_origin(context, client, args)?;
    let capabilities = client.sccp().capabilities()?;
    original.verify_capabilities(&capabilities)?;
    let world = &original.world;
    let element_count = original.element_count;
    // DTO values are candidates; these exact cell/table preimages must match the authenticated World.
    let current = capabilities
        .current_generation
        .ok_or_else(|| eyre!("SCCP is not initialized"))?;
    world.verify_cell_value("world.sccp_committee_current", &current.generation)?;
    world.verify_cell_value("world.sccp_parameters", &capabilities.parameters)?;
    let parameters: SccpParametersV1 = capabilities
        .parameters
        .ok_or_else(|| eyre!("SCCP parameters are absent"))?;
    let required_until = world
        .block_time_ms()
        .checked_add(parameters.committee_heartbeat_ms)
        .and_then(|time| time.checked_add(SCCP_PIN_MARGIN_MS_V1))
        .ok_or_else(|| eyre!("deployment pin horizon overflows"))?;
    let selected = selected_interval(selected, current.generation, element_count)?;
    let mut pinned = None;
    for generation in selected..=current.generation {
        let record = authenticate_record(
            world,
            generation,
            client.sccp().committee(generation)?,
            required_until,
        )?;
        if generation == current.generation {
            ensure!(
                record.committee_root == current.committee_root
                    && record.start_height == current.start_height
                    && record.deadline_ms == current.deadline_ms,
                "current committee summary differs from its certified record"
            );
        }
        if generation == selected {
            pinned = Some(record);
        }
    }
    let record = pinned.ok_or_else(|| eyre!("selected committee missing"))?;
    let pin = SccpCommitteePinV1 {
        generation: record.generation,
        committee_root: record.committee_root,
        start_height: record.start_height,
        until_ms: record.deadline_ms,
    };
    ensure!(
        pin.is_well_formed(),
        "authenticated deployment pin is malformed"
    );
    Ok(AuthenticatedPin {
        network: original.network,
        instance: original.instance,
        pin,
        keys: record.keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::{
        account::AccountId,
        sccp::{
            generation::{SccpGenerationCauseV1, SccpGenerationMemberV1},
            params::SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1,
        },
        sumeragi_finality::{
            WorldStateElementKindV1, WorldStateSnapshotEntryV1, world_state_value_hash_v1,
        },
        testing::native_finality::NativeFinalityFixture,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::topology::LaneId;

    fn record() -> SccpGenerationV1 {
        let mut keys: Vec<[u8; 48]> = (1..=4)
            .map(|seed| {
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .unwrap()
                    .public_key()
                    .to_bytes()
                    .1
                    .try_into()
                    .unwrap()
            })
            .collect();
        keys.sort_unstable();
        let members = (1..=4)
            .map(|seed| {
                Some(SccpGenerationMemberV1 {
                    lane_id: LaneId::SINGLE,
                    validator: AccountId::new(
                        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                            .unwrap()
                            .public_key()
                            .clone(),
                    ),
                    activation_height: 1,
                })
            })
            .collect();
        let grace_ms = SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1;
        SccpGenerationV1 {
            generation: 1,
            committee_root: committee_root(&keys).unwrap(),
            keys,
            members,
            cause: SccpGenerationCauseV1::Genesis,
            start_height: 1,
            start_timestamp_ms: 1000,
            start_lc: 1000,
            validity_ms: 100,
            deadline_ms: 1100,
            grace_ms,
            progress_cap_ms: 30,
            liable_until_lc: 1100 + grace_ms,
            dest_cleared_lc: None,
            end: None,
            liable: true,
        }
    }
    // Portable verification control: real native quorum, synthetic complete World outputs.
    // This fixture executes no World and does not qualify route launch or deployment readiness.
    fn certified(
        record: &SccpGenerationV1,
    ) -> (
        WorldStateSnapshotV1,
        VerifiedSumeragiBlock,
        SumeragiFinalityVerifier,
    ) {
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"independently selected synthetic registry schema"),
            entries: vec![
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_committee_current".into(),
                    kind: WorldStateElementKindV1::Cell,
                    key_hash: None,
                    value_hash: world_state_value_hash_v1(&record.generation).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_committee_generations".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&record.generation).unwrap()),
                    value_hash: world_state_value_hash_v1(&native_record(record.clone())).unwrap(),
                },
            ],
        };
        let mut native = NativeFinalityFixture::new();
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = native.verifier().verify_retained_decision(&proof).unwrap();
        (snapshot, tip, native.verifier())
    }

    #[test]
    fn evidence_generation_preserves_original_unslashable_members_and_rejects_substitution() {
        let mut row = record();
        row.members[0] = None;
        let (snapshot, tip, verifier) = certified(&row);
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 2,
            verifier,
        };
        assert_eq!(original.height(), tip.height());
        assert!(original.verify_generation(1, row.clone()).unwrap().members[0].is_none());
        assert!(original.verify_generation(2, row.clone()).is_err());
        let mut changed = row.clone();
        changed.end = Some(iroha::data_model::sccp::generation::SccpGenerationEndV1 {
            end_height: 2,
            end_timestamp_ms: 1001,
            next_committee_root: row.committee_root,
            successor_validity_ms: row.validity_ms,
        });
        assert!(original.verify_generation(1, changed).is_err());
        let mut changed = row;
        changed.keys[0][0] ^= 1;
        assert!(original.verify_generation(1, changed).is_err());
    }

    #[test]
    fn evidence_anchor_requires_the_original_completed_chunk_preimage() {
        use iroha_sccp::v1::evidence::{anchor_leaf, anchor_path_root};
        let witness = SccpAnchorWitnessV1 {
            core_hash: [3; 32],
            result: [4; 32],
            path: [[5; 32]; 12],
        };
        let root = anchor_path_root(
            &anchor_leaf(1, &witness.core_hash, &witness.result),
            0,
            &witness.path,
        )
        .unwrap();
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"original anchor schema"),
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: "world.sccp_anchor_chunks".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&0_u64).unwrap()),
                value_hash: world_state_value_hash_v1(&root).unwrap(),
            }],
        };
        let mut native = NativeFinalityFixture::new();
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = native.verifier().verify_retained_decision(&proof).unwrap();
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 1,
            verifier: native.verifier(),
        };
        original.verify_anchor_witness(1, &witness).unwrap();
        assert!(original.verify_anchor_witness(0, &witness).is_err());
        assert!(original.verify_anchor_witness(2, &witness).is_err());
        assert!(original.verify_anchor_witness(4097, &witness).is_err());
        for field in 0..3 {
            let mut changed = witness;
            match field {
                0 => changed.core_hash[0] ^= 1,
                1 => changed.result[0] ^= 1,
                _ => changed.path[0][0] ^= 1,
            }
            assert!(original.verify_anchor_witness(1, &changed).is_err());
        }
    }
    #[test]
    fn catch_up_generation_requires_original_identity_and_committed_cell() {
        use iroha_sccp::api::{SccpCurrentGenerationV1, SccpFinalityConstantsV1, SccpReadLimitsV1};
        let row = record();
        let (snapshot, tip, verifier) = certified(&row);
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 2,
            verifier,
        };
        let capabilities = SccpCapabilitiesV1 {
            network_id: original.network,
            consensus_instance: original.instance,
            finality: SccpFinalityConstantsV1::current(),
            current_generation: Some(SccpCurrentGenerationV1 {
                generation: 1,
                committee_root: row.committee_root,
                start_height: 1,
                deadline_ms: 1100,
            }),
            coalition_slashable_floor: None,
            liability_clock: 1000,
            forgery_max_generation: None,
            pause_panel_ids: None,
            parliament_binding_ballot_available: false,
            reconciliation_available: false,
            parameters: None,
            committed_height: 2,
            light_client_profiles: vec![],
            chain_id: "discovery only".into(),
            profiles: vec![],
            profiles_policy_hash: [0; 32],
            limits: SccpReadLimitsV1::v1(),
            path_templates: vec![],
        };
        assert_eq!(original.current_generation(&capabilities).unwrap(), 1);
        for case in 0..4 {
            let mut changed = capabilities.clone();
            match case {
                0 => changed.network_id[0] ^= 1,
                1 => changed.consensus_instance[0] ^= 1,
                2 => changed.current_generation.as_mut().unwrap().generation += 1,
                _ => changed.current_generation = None,
            }
            assert!(
                original.current_generation(&changed).is_err(),
                "case {case}"
            );
        }

        let mut view = capabilities;
        view.parameters = Some(SccpParametersV1::taira_default());
        view.forgery_max_generation = Some(7);
        let (mut snapshot, _, _) = certified(&row);
        for (field, value_hash) in [
            (
                "world.sccp_forgery_max_generation",
                world_state_value_hash_v1(&view.forgery_max_generation).unwrap(),
            ),
            (
                "world.sccp_parameters",
                world_state_value_hash_v1(&view.parameters).unwrap(),
            ),
        ] {
            snapshot.entries.push(WorldStateSnapshotEntryV1 {
                field_id: field.into(),
                kind: WorldStateElementKindV1::Cell,
                key_hash: None,
                value_hash,
            });
        }
        let mut native = NativeFinalityFixture::new();
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = native.verifier().verify_retained_decision(&proof).unwrap();
        let exact = AuthenticatedOrigin {
            network: original.network,
            instance: original.instance,
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: snapshot.entries.len(),
            verifier: native.verifier(),
        };
        assert_eq!(
            exact.parameters(&view).unwrap(),
            SccpParametersV1::taira_default()
        );
        assert_eq!(exact.forgery_max(&view).unwrap(), Some(7));
        let mut substituted = view.clone();
        substituted.parameters.as_mut().unwrap().enabled = false;
        assert!(exact.parameters(&substituted).is_err());
        substituted.parameters = None;
        assert!(exact.parameters(&substituted).is_err());
        for floor in [None, Some(6), Some(8)] {
            substituted = view.clone();
            substituted.forgery_max_generation = floor;
            assert!(exact.forgery_max(&substituted).is_err());
        }
    }

    #[test]
    fn destination_route_binds_complete_record_to_original_world() {
        use iroha::data_model::sccp::{
            deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
            registry::SccpRouteRevisionV1,
        };
        let generation = record();
        let network = SccpNetworkV1::EthereumMainnet;
        let account = generation.members[0].as_ref().unwrap().validator.clone();
        let mut route = SccpRouteV1::empty(network, account).unwrap();
        route.revisions.insert(
            1,
            SccpRouteRevisionV1::staged(
                1,
                SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                    address: [3; 20],
                    runtime_code_hash: [4; 32],
                }),
                SccpCommitteePinV1 {
                    generation: 1,
                    committee_root: generation.committee_root,
                    start_height: 1,
                    until_ms: 1100,
                },
                1000,
                2,
            ),
        );
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"original route schema"),
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: "world.sccp_routes".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&network).unwrap()),
                value_hash: world_state_value_hash_v1(&route).unwrap(),
            }],
        };
        let mut native = NativeFinalityFixture::new();
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = native.verifier().verify_retained_decision(&proof).unwrap();
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 1,
            verifier: native.verifier(),
        };
        original.verify_route(network, &route).unwrap();
        assert!(
            original
                .verify_route(SccpNetworkV1::BscMainnet, &route)
                .is_err()
        );
        for case in 0..8 {
            let mut changed = route.clone();
            let revision = changed.revisions.get_mut(&1).unwrap();
            match case {
                0 => revision.initial_committee.committee_root[0] ^= 1,
                1 => revision.initial_committee.until_ms += 1,
                2 => revision.initial_committee.generation += 1,
                3 => revision.max_wrapped_supply += 1,
                4 => revision.destination_word[0] ^= 1,
                5 => revision.revision += 1,
                6 => {
                    let SccpDeploymentV1::Evm(deployment) = &mut revision.deployment else {
                        unreachable!()
                    };
                    deployment.runtime_code_hash[0] ^= 1;
                }
                _ => {
                    let SccpDeploymentV1::Evm(deployment) = &mut revision.deployment else {
                        unreachable!()
                    };
                    deployment.address[0] ^= 1;
                }
            }
            assert!(
                original.verify_route(network, &changed).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn selected_network_and_finite_generation_interval_are_independent_of_discovery() {
        let hash = HashOf::from_untyped_unchecked(Hash::new(b"original genesis"));
        let network = NetworkId::from_genesis_hash(hash);
        assert_eq!(selected_network(hash, network).unwrap(), network);
        let other = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"another genesis",
        )));
        assert!(selected_network(hash, other).is_err());
        assert_eq!(selected_interval(None, 7, 1).unwrap(), 7);
        assert_eq!(selected_interval(Some(4), 7, 4).unwrap(), 4);
        assert!(selected_interval(Some(4), 7, 3).is_err());
        assert!(selected_interval(Some(0), 7, 8).is_err());
        assert!(selected_interval(Some(8), 7, 8).is_err());
        assert!(selected_interval(None, 0, 1).is_err());
        assert!(selected_interval(Some(1), u64::MAX, 100).is_err());
    }
    #[test]
    fn registered_deployment_pin_requires_exact_authenticated_generation() {
        let row = record();
        let (snapshot, tip, verifier) = certified(&row);
        let wire = norito::encode_canonical(&snapshot).unwrap();
        let (world, element_count) =
            authenticated_world(&wire, snapshot.schema_hash, &tip).unwrap();
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world,
            element_count,
            verifier,
        };
        let pin = SccpCommitteePinV1 {
            generation: row.generation,
            committee_root: row.committee_root,
            start_height: row.start_height,
            until_ms: row.deadline_ms,
        };
        assert_eq!(
            original.verify_pin_generation(row.clone(), &pin).unwrap(),
            row.keys
        );
        let mut wrong = pin;
        wrong.start_height += 1;
        assert!(original.verify_pin_generation(row.clone(), &wrong).is_err());
        wrong = pin;
        wrong.committee_root[0] ^= 1;
        assert!(original.verify_pin_generation(row.clone(), &wrong).is_err());
        wrong = pin;
        wrong.until_ms += 1;
        assert!(original.verify_pin_generation(row, &wrong).is_err());
    }

    #[test]
    fn deployment_pin_authenticates_exact_native_world_record_and_selected_schema() {
        let row = record();
        let (snapshot, tip, _) = certified(&row);
        let wire = norito::encode_canonical(&snapshot).unwrap();
        let (world, count) = authenticated_world(&wire, snapshot.schema_hash, &tip).unwrap();
        assert_eq!(count, 2);
        world
            .verify_cell_value("world.sccp_committee_current", &1_u64)
            .unwrap();
        assert_eq!(
            authenticate_record(&world, 1, row.clone(), 1100).unwrap(),
            native_record(row.clone())
        );
        assert!(authenticate_record(&world, 1, row.clone(), 1101).is_err());
        assert!(authenticate_record(&world, 2, row.clone(), 1100).is_err());
        assert!(
            world
                .verify_cell_value("world.sccp_committee_current", &2_u64)
                .is_err()
        );
        let mut wrong_root = row.clone();
        wrong_root.committee_root[0] ^= 1;
        assert!(authenticate_record(&world, 1, wrong_root, 1100).is_err());
        let mut changed_grace = row.clone();
        changed_grace.grace_ms += 1;
        changed_grace.liable_until_lc += 1;
        // Genesis binds its creation and liability clocks together. Keep both
        // altered records structurally valid and within the pin horizon so only
        // their mismatch with the certified World rejects the substitutions.
        let mut changed_clocks = row.clone();
        changed_clocks.start_timestamp_ms += 1;
        changed_clocks.start_lc += 1;
        changed_clocks.deadline_ms += 1;
        changed_clocks.liable_until_lc += 1;
        for changed in [changed_grace, changed_clocks] {
            assert!(native_record(changed.clone()).is_well_formed());
            assert!(changed.deadline_ms >= 1100);
            assert!(authenticate_record(&world, 1, changed, 1100).is_err());
        }
        let mut discovery_only = row;
        discovery_only.liable = false;
        assert!(
            authenticate_record(&world, 1, discovery_only, 1100).is_ok(),
            "discovery liability does not select committee authority"
        );
        assert!(authenticated_world(&wire, Hash::new(b"substituted schema"), &tip).is_err());
        let mut omitted = snapshot.clone();
        omitted.entries.pop();
        assert!(
            authenticated_world(
                &norito::encode_canonical(&omitted).unwrap(),
                snapshot.schema_hash,
                &tip
            )
            .is_err()
        );
        let mut suffix = wire;
        suffix.push(0);
        assert!(authenticated_world(&suffix, snapshot.schema_hash, &tip).is_err());
    }
    #[test]
    fn certified_unresolved_member_is_refused_as_a_deployment_pin() {
        let mut row = record();
        row.members[0] = None;
        assert!(native_record(row.clone()).is_well_formed());
        let (snapshot, tip, _) = certified(&row);
        let (world, _) = authenticated_world(
            &norito::encode_canonical(&snapshot).unwrap(),
            snapshot.schema_hash,
            &tip,
        )
        .unwrap();
        assert!(authenticate_record(&world, 1, row, 1000).is_err());
    }
    #[test]
    fn original_file_read_refuses_empty_and_over_limit_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("original");
        std::fs::write(&path, []).unwrap();
        assert!(bounded_read(&path, 4).is_err());
        std::fs::write(&path, [1, 2, 3, 4]).unwrap();
        assert_eq!(bounded_read(&path, 4).unwrap(), [1, 2, 3, 4]);
        std::fs::write(&path, [1, 2, 3, 4, 5]).unwrap();
        assert!(bounded_read(&path, 4).is_err());
    }
}

#[path = "origin_record.rs"]
mod record;

impl AuthenticatedOrigin {
    /// Resolve profiles only after proving their newest selection against this complete cut.
    /// An omitted higher activation, unknown catalog version, substituted activation, or
    /// discovery from another committed height refuses local claim verification.
    pub fn light_client_profiles(
        &self,
        client: &Client,
    ) -> Result<iroha_sccp::light_client::profile::SccpChainProfilesV1> {
        let capabilities = client.sccp().capabilities()?;
        self.verify_capabilities(&capabilities)?;
        authenticate_light_client_profiles(
            &self.world,
            capabilities.committed_height,
            &capabilities.light_client_profiles,
            capabilities.profiles_policy_hash,
        )
    }
}

fn authenticate_light_client_profiles(
    world: &VerifiedWorldStateSnapshotV1,
    committed_height: u64,
    selected_profiles: &[iroha_sccp::api::SccpLcProfileStatusV1],
    policy_hash: [u8; 32],
) -> Result<iroha_sccp::light_client::profile::SccpChainProfilesV1> {
    use iroha::data_model::sccp::light_client::SccpLcProfileActivationV1;
    use iroha_sccp::light_client::profile::GENESIS_PROFILE_VERSION;
    ensure!(
        committed_height == world.height(),
        "profile discovery is not at the selected original cut"
    );
    let profiles = super::light_client::resolve_profiles(selected_profiles, policy_hash)?;
    let height = world
        .height()
        .checked_add(1)
        .ok_or_else(|| eyre!("next profile height overflows"))?;
    let mut domain = Vec::new();
    for selected in selected_profiles {
        if selected.version == GENESIS_PROFILE_VERSION {
            ensure!(
                selected.activation_height.is_none() && selected.proposal_id.is_none(),
                "genesis profile carries an invented activation"
            );
        } else {
            let activation = SccpLcProfileActivationV1 {
                profile_hash: selected.profile_hash,
                activation_height: selected
                    .activation_height
                    .ok_or_else(|| eyre!("profile activation height is absent"))?,
                proposal_id: selected
                    .proposal_id
                    .ok_or_else(|| eyre!("profile activation proposal is absent"))?,
            };
            ensure!(
                activation.activation_height <= height,
                "profile is not active at the original next height"
            );
            world.verify_table_value(
                "world.sccp_light_client_profiles",
                &(selected.network, selected.version),
                &activation,
            )?;
        }
        // resolve_profiles bounded this version by the finite locally compiled catalog.
        domain.extend(
            ((GENESIS_PROFILE_VERSION + 1)..=selected.version)
                .map(|version| (selected.network, version)),
        );
    }
    world.verify_table_keys_within("world.sccp_light_client_profiles", &domain)?;
    Ok(profiles)
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use iroha::data_model::sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, test_fixtures::NativeFinalityFixture,
        world_state_value_hash_v1,
    };
    use iroha_sccp::light_client::profile::{
        GENESIS_PROFILES, SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1,
    };

    #[test]
    fn profile_selection_requires_the_complete_original_cut_and_rejects_hidden_activation() {
        let catalog = SccpLcProfileCatalogV1::compiled();
        let active = catalog.genesis();
        let rows: Vec<_> = SCCP_LC_PROFILE_NETWORKS_V1
            .into_iter()
            .map(|network| {
                let profile = active.get(network).unwrap();
                iroha_sccp::api::SccpLcProfileStatusV1 {
                    network,
                    version: profile.version,
                    profile_hash: profile.profile_hash,
                    activation_height: None,
                    proposal_id: None,
                    supported_until_ms: None,
                }
            })
            .collect();
        let authenticate = |entries| {
            let snapshot = WorldStateSnapshotV1 {
                schema_hash: Hash::new(b"profile domain fixture"),
                entries,
            };
            let mut native = NativeFinalityFixture::new();
            let block = native.block_with_submitted_work(native.next_header());
            let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
            let tip = native.verifier().verify_retained_decision(&proof).unwrap();
            snapshot.authenticate(&tip).unwrap()
        };
        let world = authenticate(vec![]);
        assert_eq!(
            authenticate_light_client_profiles(&world, world.height(), &rows, active.policy_hash())
                .unwrap(),
            GENESIS_PROFILES
        );
        assert!(
            authenticate_light_client_profiles(
                &world,
                world.height() + 1,
                &rows,
                active.policy_hash()
            )
            .is_err()
        );
        let mut invented = rows.clone();
        invented[0].activation_height = Some(world.height());
        assert!(
            authenticate_light_client_profiles(
                &world,
                world.height(),
                &invented,
                active.policy_hash()
            )
            .is_err()
        );
        let hidden = authenticate(vec![WorldStateSnapshotEntryV1 {
            field_id: "world.sccp_light_client_profiles".into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(
                world_state_value_hash_v1(&(SccpNetworkV1::EthereumMainnet, 2_u32)).unwrap(),
            ),
            value_hash: Hash::new(b"hidden newer activation"),
        }]);
        assert!(
            authenticate_light_client_profiles(
                &hidden,
                hidden.height(),
                &rows,
                active.policy_hash()
            )
            .is_err()
        );
    }
}

/// Build a portable test cut from an actually verified native fixture prefix.
#[cfg(test)]
pub(super) fn test_cut(
    native: &iroha_data_model::testing::native_finality::NativeFinalityFixture,
    snapshot: &WorldStateSnapshotV1,
    proof: &SumeragiFinalityProof,
) -> AuthenticatedOrigin {
    let verifier = native.verifier();
    let tip = verifier.verify_retained_decision(proof).unwrap();
    AuthenticatedOrigin {
        network: *native.network_id().as_bytes(),
        instance: verifier.instance().0,
        world: snapshot.authenticate(&tip).unwrap(),
        element_count: snapshot.entries.len(),
        verifier,
    }
}

#[cfg(test)]
mod message_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        sccp::{
            inbound::{
                SccpInboundRecordV1, SccpInboundSettledV1, SccpInboundStatusV1,
                SccpPendingReasonV1, SccpSourceLocatorV1,
            },
            outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1, SccpStatusHeightV1},
        },
        sumeragi_finality::{
            WorldStateElementKindV1, WorldStateSnapshotEntryV1, world_state_value_hash_v1,
        },
        testing::native_finality::NativeFinalityFixture,
    };
    use iroha_sccp::api::{
        SccpInboundMessageViewV1, SccpMessageStatusV1, SccpOutboundMessageViewV1,
        SccpOutboundStateV1, SccpRecordedStateV1,
    };

    // A genuine native quorum certifies explicit synthetic World values; this does not
    // execute an escrow transition or qualify a route for monetary operation.
    fn original(id: [u8; 32], field: &str, value_hash: Hash) -> AuthenticatedOrigin {
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"original SCCP message schema"),
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: field.into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&id).unwrap()),
                value_hash,
            }],
        };
        let mut native = NativeFinalityFixture::start("sccp-message-fixture");
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        test_cut(&native, &snapshot, &proof)
    }

    #[test]
    fn outbound_finality_uses_the_exact_original_record_and_status_projection() {
        let id = [0x81; 32];
        let key = KeyPair::from_seed(vec![32; 32], Algorithm::Ed25519);
        let record = SccpOutboundMessageRecordV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            nonce: 2,
            height: 2,
            commitment_index: 0,
            deadline_ms: 10_000,
            sender: AccountId::new(key.public_key().clone()),
            amount: 300,
            payload: vec![7; 40],
            leaf: [8; 32],
            status: SccpOutboundStatusV1::Recorded,
        };
        let root = original(
            id,
            "world.sccp_outbound_messages",
            world_state_value_hash_v1(&record).unwrap(),
        );
        let mut view = SccpOutboundMessageViewV1 {
            message_id: id,
            record: record.clone(),
            state: SccpOutboundStateV1::Recorded(SccpRecordedStateV1 {
                deadline_ms: record.deadline_ms,
                provable: true,
            }),
        };
        assert!(
            !root
                .verify_message(&id, &SccpMessageStatusV1::Outbound(view.clone()))
                .unwrap()
        );
        view.state = SccpOutboundStateV1::Refunded(SccpStatusHeightV1 { height: 2 });
        assert!(
            root.verify_message(&id, &SccpMessageStatusV1::Outbound(view.clone()))
                .is_err(),
            "an endpoint cannot project a recorded message as terminal"
        );
        for status in [
            SccpOutboundStatusV1::Refunded(SccpStatusHeightV1 { height: 2 }),
            SccpOutboundStatusV1::Stranded(SccpStatusHeightV1 { height: 2 }),
        ] {
            view.record.status = status;
            view.state = match status {
                SccpOutboundStatusV1::Refunded(v) => SccpOutboundStateV1::Refunded(v),
                SccpOutboundStatusV1::Stranded(v) => SccpOutboundStateV1::Stranded(v),
                _ => unreachable!(),
            };
            assert!(
                root.verify_message(&id, &SccpMessageStatusV1::Outbound(view.clone()))
                    .is_err(),
                "substituting the record cannot forge a final cut"
            );
            let final_root = original(
                id,
                "world.sccp_outbound_messages",
                world_state_value_hash_v1(&view.record).unwrap(),
            );
            assert!(
                final_root
                    .verify_message(&id, &SccpMessageStatusV1::Outbound(view.clone()))
                    .unwrap()
            );
            let mut altered = view.clone();
            altered.record.amount += 1;
            assert!(
                final_root
                    .verify_message(&id, &SccpMessageStatusV1::Outbound(altered))
                    .is_err()
            );
            assert!(
                final_root
                    .verify_message(&[0x82; 32], &SccpMessageStatusV1::Outbound(view.clone()))
                    .is_err()
            );
        }
        assert!(
            !root
                .verify_message(&id, &SccpMessageStatusV1::Unknown)
                .unwrap()
        );
    }

    #[test]
    fn inbound_finality_requires_the_exact_original_message_row() {
        let id = [0x83; 32];
        let mut view = SccpInboundMessageViewV1 {
            message_id: id,
            record: SccpInboundRecordV1 {
                network: SccpNetworkV1::TonMainnet,
                revision: 1,
                payload: vec![9; 40],
                source_locator: SccpSourceLocatorV1 {
                    source_height: 10,
                    block_hash: [10; 32],
                    index_in_block: 0,
                },
                proven_at_height: 2,
                fee_due: 0,
                status: SccpInboundStatusV1::pending(SccpPendingReasonV1::Held),
            },
        };
        let pending = original(
            id,
            "world.sccp_inbound_messages",
            world_state_value_hash_v1(&view.record).unwrap(),
        );
        assert!(
            !pending
                .verify_message(&id, &SccpMessageStatusV1::Inbound(view.clone()))
                .unwrap()
        );
        view.record.status = SccpInboundStatusV1::Released(SccpInboundSettledV1 {
            height: 2,
            payout: 300,
        });
        assert!(
            pending
                .verify_message(&id, &SccpMessageStatusV1::Inbound(view.clone()))
                .is_err(),
            "a forged released row cannot authorize completion"
        );
        let released = original(
            id,
            "world.sccp_inbound_messages",
            world_state_value_hash_v1(&view.record).unwrap(),
        );
        assert!(
            released
                .verify_message(&id, &SccpMessageStatusV1::Inbound(view.clone()))
                .unwrap()
        );
        let mut changed = view.clone();
        changed.record.source_locator.block_hash[0] ^= 1;
        assert!(
            released
                .verify_message(&id, &SccpMessageStatusV1::Inbound(changed))
                .is_err()
        );
        view.message_id[0] ^= 1;
        assert!(
            released
                .verify_message(&id, &SccpMessageStatusV1::Inbound(view))
                .is_err()
        );
    }
}
