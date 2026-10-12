//! Authenticate deployment pins from a selected signed genesis and complete certified World cut.

use crate::RunContext;
use eyre::{Result, ensure, eyre};
use iroha::{
    blocking::Client,
    crypto::{Hash, HashOf, PublicKey},
    data_model::{
        block::{BlockHeader, consensus::SumeragiRootScope},
        id::NetworkId,
        sccp::{
            deployment::SccpCommitteePinV1,
            generation::SccpCommitteeGenerationV1,
            params::{SCCP_PIN_MARGIN_MS_V1, SccpParametersV1},
        },
        sumeragi_finality::{
            FinalityValidator, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, SumeragiFinalityVerifier,
            VerifiedSumeragiBlock, VerifiedWorldStateSnapshotV1, WorldStateSnapshotV1,
        },
    },
};
use iroha_sccp::{api::SccpGenerationV1, v1::committee::committee_root};
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
    #[arg(long, value_parser=clap::value_parser!(u64).range(2..))]
    pub at_height: u64,
    /// Complete canonical WorldStateSnapshotV1 frame exported at that native cut.
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

pub(super) fn authenticate<C: RunContext>(
    context: &C,
    client: &Client,
    args: &OriginArgs,
    selected: Option<u64>,
) -> Result<AuthenticatedPin> {
    ensure!(
        args.at_height >= 2,
        "deployment needs a certified successor"
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
    let mut verifier = SumeragiFinalityVerifier::new(
        genesis.block(),
        &manifest.chain_id().to_string(),
        validators,
    )?;
    ensure!(
        verifier.root_scope() == SumeragiRootScope::Global,
        "SCCP deployment requires the original Global root"
    );
    let capabilities = client.sccp().capabilities()?;
    ensure!(
        capabilities.network_id == *network.as_bytes()
            && capabilities.consensus_instance == verifier.instance().0,
        "SCCP discovery differs from the selected original native root"
    );
    // The caller selects the height. The endpoint cannot extend this work by advertising a new tip.
    let mut tip = None;
    for height in 1..=args.at_height {
        let proof = client.client().get_sumeragi_finality_proof(
            NonZeroU64::new(height).expect("positive range"),
            verifier.root_scope(),
        )?;
        tip = Some(verifier.verify(&proof)?);
    }
    let tip = tip.ok_or_else(|| eyre!("no certified successor"))?;
    tip.verify_global_scope(network, verifier.chain_id())?;
    let snapshot_wire = bounded_read(&args.world_snapshot, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1)?;
    let (world, element_count) = authenticated_world(&snapshot_wire, args.world_schema_hash, &tip)?;
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
            &world,
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
        network: *network.as_bytes(),
        instance: verifier.instance().0,
        pin,
        keys: record.keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::{
        account::AccountId,
        sccp::generation::{SccpGenerationCauseV1, SccpGenerationMemberV1},
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
        keys.sort();
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
            grace_ms: 20,
            progress_cap_ms: 30,
            liable_until_lc: 1120,
            dest_cleared_lc: None,
            end: None,
            liable: true,
        }
    }
    // Portable verification control: real native quorum, synthetic complete World outputs.
    // This fixture executes no World and does not qualify route launch or deployment readiness.
    fn certified(record: &SccpGenerationV1) -> (WorldStateSnapshotV1, VerifiedSumeragiBlock) {
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
        (snapshot, tip)
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
    fn deployment_pin_authenticates_exact_native_world_record_and_selected_schema() {
        let row = record();
        let (snapshot, tip) = certified(&row);
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
        let mut changed = row.clone();
        changed.start_lc -= 1;
        changed.liable_until_lc -= 1;
        assert!(native_record(changed.clone()).is_well_formed());
        assert!(authenticate_record(&world, 1, changed, 1100).is_err());
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
        let (snapshot, tip) = certified(&row);
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
