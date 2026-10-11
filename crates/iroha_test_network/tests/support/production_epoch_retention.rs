//! Verify incumbent retention through four independently anchored finality chains.
//! Scheduling advances under certified authorizations without per-epoch key writes.

use super::*;
use iroha_core::release_identity::BuildIdentity;
use iroha_core::sumeragi::native_journal::authenticate_signed_genesis;
use iroha_data_model::NetworkId;
use iroha_data_model::query::{
    block::prelude::FindBlocks, builder::QueryBuilderExt as _, parameters::Pagination,
};
use iroha_data_model::sumeragi::epoch::{
    BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochAuthorizationV1,
    ValidatorEpochDecisionV1, ValidatorGenerationV1,
};
use iroha_model_base::peer::PeerId;
use std::num::NonZeroU64;

pub(super) const EPOCH_LENGTH: u64 = 11;

/// Admit immutable source identity before any generated custody or child exists.
pub(super) fn admit_build_identity(identity: BuildIdentity) -> Result<BuildIdentity> {
    identity.release_source_commit().wrap_err(
        "retained-generation beacon fixture requires an exact compiled Git source commit before setup; use maintained Taira checks, not --stable-local-metadata",
    )?;
    Ok(identity)
}

fn require_retained_successor(
    authority: &ValidatorGenerationV1,
    current: &ValidatorEpochAuthorizationV1,
    next: &ValidatorEpochAuthorizationV1,
    installed: InstalledBeaconEpochBindingV1,
    boundary_height: u64,
) -> Result<()> {
    current.validate_against_generation(authority)?;
    next.validate_against_generation(authority)?;
    next.validate_successor(current)?;
    ensure!(
        current.last_height == boundary_height
            && next.last_height
                == boundary_height
                    .checked_add(EPOCH_LENGTH)
                    .ok_or_else(|| eyre!("retained fixture epoch height overflow"))?
            && next.decision == ValidatorEpochDecisionV1::Retain
            && next.beacon == BeaconEpochBindingV1::Installed(installed),
        "certified boundary changed incumbent authority, installed beacon or signed epoch schedule"
    );
    Ok(())
}

pub(super) async fn verify_boundary_chain(
    prepared: &prepare::Prepared,
    clients: &[iroha::client::Client],
    installed: &beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        clients.len() == 4,
        "epoch retention requires all four validators"
    );
    let genesis_bytes = fs::read(prepared.genesis_directory.join("genesis.signed.nrt"))?;
    let (genesis_identity, _metadata) = iroha_core::release_identity::genesis_identity(
        &genesis_bytes,
        &prepared.genesis_public_key,
    )?;
    let genesis = iroha_genesis::decode_signed_genesis(&genesis_bytes)?;
    let network = prepared.network_id;
    let genesis_hash = genesis.hash();
    ensure!(
        genesis_identity == iroha_crypto::Hash::from(network.into_genesis_hash())
            && genesis_hash == network.into_genesis_hash(),
        "epoch proof chain must bind the independently signed genesis network"
    );
    let (_, genesis_epoch) =
        authenticate_signed_genesis(&genesis_bytes, network, native_finality_limits())
            .map_err(|error| eyre!(error))?;
    let authority = genesis_epoch.generation();
    let initial = ValidatorEpochAuthorizationV1::genesis(&authority, EPOCH_LENGTH)?;
    ensure!(
        genesis_epoch.authorization == initial,
        "signed genesis neutral epoch differs from its signed generation-zero roster"
    );
    let roster = genesis_epoch.committee;
    ensure!(
        roster.len() == 4,
        "genesis proof authority is not four peers"
    );
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    installed.validate(&budget)?;
    let session = beacon::validate_global_threshold_beacon_session_v1(
        &installed.session,
        &beacon::GlobalThresholdBeaconSessionBindingV1 {
            network_id: network,
            session_id: installed.session.session_id,
            roster_hash: beacon::global_threshold_beacon_roster_hash_v1(
                &roster
                    .iter()
                    .map(|seat| seat.validator.clone())
                    .collect::<Vec<_>>(),
            ),
            transcript_hash: installed.session.transcript_hash,
        },
        &budget,
    )?;
    ensure!(
        installed.session.network_id == network
            && installed.session.committee_size == 4
            && installed.session.roster_hash
                == beacon::global_threshold_beacon_roster_hash_v1(
                    &roster
                        .iter()
                        .map(|entry| entry.validator.clone())
                        .collect::<Vec<_>>()
                ),
        "retained beacon session differs from independently selected genesis authority"
    );
    let installed_binding = InstalledBeaconEpochBindingV1 {
        session_id: installed.session.session_id,
        transcript_hash: installed.session.transcript_hash,
    };
    let height = status_height(clients, deadline).await?;
    ensure!(
        height > EPOCH_LENGTH,
        "fixture did not apply a successor epoch"
    );
    let tips = try_join_all(clients.iter().enumerate().map(|(index, client)| {
        let client = client.clone();
        let roster = roster.clone();
        let authority = authority.clone();
        let session = session.clone();
        let path = prepared.directory.join(format!("epoch-retention-proof-peer{index}.json"));
        iroha_test_network::read_on_dedicated_thread(move || {
            let bounded = || -> Result<iroha::client::Client> {
                let remaining = deadline.saturating_duration_since(Instant::now());
                ensure!(!remaining.is_zero(), "epoch proof chain exceeded its original audit deadline");
                let mut builder = client.to_builder();
                builder.torii_request_timeout = iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT.min(remaining);
                Ok(builder.build()?)
            };
            let client = bounded()?;
            ensure!(height <= 256, "retention source exceeds the explicit disposable prefix bound");
            let mut source = client.query(FindBlocks).with_pagination(Pagination::new(NonZeroU64::new(257), 0)).execute_all()?;
            ensure!(source.len() <= 256, "retention query exceeded configured source bound");
            source.retain(|block| block.header().height().get() <= height);
            source.sort_by_key(|block| block.header().height());
            ensure!(source.len() == usize::try_from(height)?, "retention source lacks complete genesis prefix");
            let journal = NativeFinalityJournal { blocks: source.iter().map(|block| NativeFinalityArtifact::from_block(block, native_finality_limits()).map_err(|error| eyre!(error))).collect::<Result<Vec<_>>>()? };
            let cursor = NativeJournalCursor::new(client.chain().clone(), network, iroha_data_model::block::consensus::SumeragiRootScope::Global, native_finality_limits(),
&iroha_allocation::AllocationBudget::new(native_finality_limits().allocated_bytes),
).map_err(|error| eyre!(error))?;
            let proofs = with_verified_native_journal((&journal).into(), client.chain(), &network, native_finality_limits(), cursor.allocation_budget(), |reader| reader.walk(1, height).collect::<std::result::Result<Vec<_>, _>>().map_err(iroha_core::sumeragi::native_journal::NativeJournalError::History)).map_err(|error| eyre!(error))?;
            let first = proofs.first().ok_or_else(|| eyre!("missing actual signed genesis"))?;
            let context = &first.commitment().schedule.current;
            ensure!(first.block_hash() == genesis_hash && context.committee == roster && context.generation() == authority && context.authorization == initial,
                "native proof graph differs from exact independent signed genesis authority and schedule");
            let mut expected = initial;
            for proof in proofs.iter().skip(1) {
                let next_height = proof.height();
                ensure!(proof.block().has_consensus_work(), "native certified chain contains no actual work");
                if (next_height + 1) % EPOCH_LENGTH == 0 {
                    let pulse = proof.commitment().beacon.as_ref().ok_or_else(|| eyre!("required native threshold pulse missing"))?;
                    let parent = &proofs[usize::try_from(next_height - 2)?];
                    let header = proof.header().ok_or_else(|| eyre!("native pulse has no authenticated header"))?;
                    beacon::verify_finalized_global_threshold_beacon_pulse_v1(
                        &session, pulse,
                        iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
                            height: next_height - 1, block_hash: parent.block_hash(),
                        },
                        &iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
                            instance: header.instance.0,
                            epoch: header.epoch.epoch,
                            epoch_context_id: header.epoch.context.0,
                            parent_consensus_hash: header.parent_hash.0,
                            parent_result: header.parent_result.0,
                        },
                    )?;
                }
                let context = &proof.commitment().schedule.current;
                ensure!(context.generation() == authority && context.authorization == expected && context.committee == roster,
                    "certified epoch changed retained generation, original PoPs or authorization");
                if next_height == expected.last_height {
                    let transition = proof.commitment().schedule.boundary.as_ref().ok_or_else(|| eyre!("certified boundary omitted retention"))?;
                    ensure!(transition.next.generation() == authority && transition.next.committee == roster, "retained boundary changed original validators or PoPs");
                    require_retained_successor(&authority, &expected, &transition.next.authorization, installed_binding, next_height)?;
                    expected = transition.next.authorization;
                }
            }
            let tip = proofs.last().ok_or_else(|| eyre!("missing verified native tip"))?.block_hash();
            ensure!(!deadline.saturating_duration_since(Instant::now()).is_zero(), "native epoch proof audit exceeded original deadline");
            private_file(&path, &json::to_vec(&journal)?)?;
            Ok(tip)
        })
    })).await?;
    ensure!(
        tips.len() == 4 && tips.iter().all(|tip| *tip == tips[0]),
        "retained epoch proof tips differ across validators"
    );
    Ok(())
}

#[test]
fn production_epoch_retention_requires_exact_source_identity_before_setup() -> Result<()> {
    use iroha_core::release_identity::BuildIdentityError;
    let development = BuildIdentity::from_compiled_parts(
        "fixture-test",
        Some("local-fast-build"),
        None,
        None,
        None,
        None,
    )?;
    let error =
        admit_build_identity(development).expect_err("development label is not source provenance");
    assert_eq!(
        error.downcast_ref::<BuildIdentityError>(),
        Some(&BuildIdentityError::DevelopmentSource)
    );
    assert!(error.to_string().contains("before setup"));
    // Syntax-only public revision fixture, never selected as executable evidence.
    let exact = BuildIdentity::from_compiled_parts(
        "fixture-test",
        Some("592c6e0e5adcd2ff5e0492d971bfbb179f591b53"),
        None,
        None,
        None,
        None,
    )?;
    assert_eq!(admit_build_identity(exact)?, exact);
    Ok(())
}

fn authorization_fixture() -> Result<(
    ValidatorGenerationV1,
    ValidatorEpochAuthorizationV1,
    ValidatorEpochAuthorizationV1,
    InstalledBeaconEpochBindingV1,
)> {
    let mut validators = (1_u8..=4)
        .map(|seed| {
            let key = KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal);
            PeerId::new(key.public_key().clone())
        })
        .collect::<Vec<_>>();
    validators.sort();
    let authority = ValidatorGenerationV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"retained-generation-test"),
        )),
        generation: 0,
        validators,
    };
    let current = ValidatorEpochAuthorizationV1::genesis(&authority, EPOCH_LENGTH)?;
    let installed = InstalledBeaconEpochBindingV1 {
        session_id: [7; 32],
        transcript_hash: [8; 32],
    };
    let next = ValidatorEpochAuthorizationV1 {
        epoch: 1,
        first_height: EPOCH_LENGTH + 1,
        last_height: 2 * EPOCH_LENGTH,
        beacon: BeaconEpochBindingV1::Installed(installed),
        previous_authorization_id: current.authorization_id()?,
        decision: ValidatorEpochDecisionV1::Retain,
        ..current
    };
    Ok((authority, current, next, installed))
}

#[test]
fn production_epoch_retention_binds_exact_generation_beacon_and_interval() -> Result<()> {
    let (authority, current, next, installed) = authorization_fixture()?;
    require_retained_successor(&authority, &current, &next, installed, EPOCH_LENGTH)?;
    let later = ValidatorEpochAuthorizationV1 {
        epoch: 2,
        first_height: 2 * EPOCH_LENGTH + 1,
        last_height: 3 * EPOCH_LENGTH,
        previous_authorization_id: next.authorization_id()?,
        ..next
    };
    require_retained_successor(&authority, &next, &later, installed, 2 * EPOCH_LENGTH)?;
    assert_eq!(later.authority_generation, 0);
    assert_ne!(later.authorization_id()?, next.authorization_id()?);
    Ok(())
}

#[test]
fn production_epoch_retention_rejects_changed_generation_beacon_parent_and_schedule() -> Result<()>
{
    let (authority, current, valid, installed) = authorization_fixture()?;
    for mutation in 0..9 {
        let mut next = valid;
        match mutation {
            0 => next.authority_generation += 1,
            1 => next.authority_id = [9; 32],
            2 => next.beacon = BeaconEpochBindingV1::Bootstrap,
            3 => {
                next.beacon = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                    session_id: [9; 32],
                    ..installed
                })
            }
            4 => {
                next.beacon = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                    transcript_hash: [9; 32],
                    ..installed
                })
            }
            5 => next.previous_authorization_id = [9; 32],
            6 => next.first_height += 1,
            7 => next.last_height += 1,
            _ => {
                next.decision = ValidatorEpochDecisionV1::RetainAndCancel;
                next.transition_id = [9; 32];
            }
        }
        assert!(
            require_retained_successor(&authority, &current, &next, installed, EPOCH_LENGTH)
                .is_err(),
            "mutation {mutation}"
        );
    }
    assert!(
        require_retained_successor(&authority, &current, &valid, installed, EPOCH_LENGTH + 1)
            .is_err()
    );
    Ok(())
}

fn verify_retained_schedule(
    verified: &iroha_core::sumeragi::certified_chain::CertifiedBlock,
    validators: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
    epoch_length: u64,
) -> Result<()> {
    let schedule = &verified.commitment().schedule;
    ensure!(
        schedule.current.committee == validators
            && schedule.next.params().epoch_length_blocks == epoch_length,
        "native certified committee or signed epoch schedule changed"
    );
    Ok(())
}

fn certified_schedule_fixture() -> Result<iroha_core::sumeragi::certified_chain::CertifiedBlock> {
    use iroha_core::{
        state::World,
        sumeragi::{
            certified_chain::CertifiedChain,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000))
        .map_err(|failure| eyre!(failure.error))?;
    chain.commit_at(20_000, Vec::new());
    let view = chain.state().view();
    let verified = CertifiedChain::new(&view)?.certified(2)?;
    ensure!(
        verified.block().has_consensus_work(),
        "schedule fixture must execute real work"
    );
    Ok(verified)
}

#[test]
fn production_current_boundary_binds_exact_certified_committee_and_schedule() -> Result<()> {
    let verified = certified_schedule_fixture()?;
    let schedule = &verified.commitment().schedule;
    verify_retained_schedule(
        &verified,
        &schedule.current.committee,
        schedule.next.params().epoch_length_blocks,
    )?;
    ensure!(
        verified.height() == 2 && schedule.current.committee.len() == 4,
        "native boundary fixture must certify real four-validator work"
    );
    Ok(())
}

#[test]
fn production_current_boundary_rejects_changed_committee_or_schedule() -> Result<()> {
    let verified = certified_schedule_fixture()?;
    let schedule = &verified.commitment().schedule;
    let epoch = schedule.next.params().epoch_length_blocks;
    let mut other = schedule.current.committee.clone();
    other.swap(0, 1);
    assert!(verify_retained_schedule(&verified, &other, epoch).is_err());
    assert!(verify_retained_schedule(&verified, &schedule.current.committee, epoch + 1).is_err());
    Ok(())
}
