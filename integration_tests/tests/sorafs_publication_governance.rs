//! Actual Parliament revocation after production publication and native storage repair.
//! Run explicitly with `parliament-test-signers`; the corridor signs genuine seven-body evidence.

#[cfg(unix)]
#[path = "sora_parliament_lifecycle_support.rs"]
mod parliament;
#[cfg(unix)]
#[path = "sorafs_network.rs"]
mod sorafs_network;
#[cfg(unix)]
#[path = "sorafs_publication.rs"]
mod sorafs_publication;
#[cfg(unix)]
#[path = "sorafs_publication_authority.rs"]
mod sorafs_publication_authority;
#[cfg(unix)]
#[path = "sorafs_publication_compliance.rs"]
mod sorafs_publication_compliance;
#[cfg(unix)]
#[path = "sorafs_publication_config.rs"]
mod sorafs_publication_config;
#[cfg(unix)]
#[path = "sorafs_publication_http.rs"]
mod sorafs_publication_http;

#[cfg(unix)]
#[test]
// TODO: the revocation is enacted through `enact_publication_proposal`, which
// needs a hidden ballot to open. Re-enable this corridor when that fixture enacts through
// the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4).
#[ignore = "timed-OVN release slot is no longer consensus demand; the hidden ballot is replaced by the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4)"]
fn four_peer_native_publication_repair_and_parliament_revocation() -> eyre::Result<()> {
    sorafs_network::run("sorafs-publication-governance", || async {
        let published =
            sorafs_publication::create_and_publish(publication_parliament_builder).await?;
        sorafs_publication::qualify_storage_lifecycle(&published).await?;
        let proposal = published.authority.revocation_proposal(
            0,
            published.network.network_id(),
            sorafs_publication::now()?,
        )?;
        let (_, height) =
            Box::pin(enact_publication_proposal(&published.network, proposal)).await?;
        published.network.ensure_blocks(height).await?;
        let response = sorafs_publication::retrieve(&published, 0).await?;
        eyre::ensure!(
            !response.status().is_success(),
            "revoked provider served admitted bytes"
        );
        let body = String::from_utf8(sorafs_publication_http::bytes(response, 65536).await?)?;
        eyre::ensure!(
            body.contains("provider_not_admitted"),
            "unrelated failure cannot prove governed revocation: {body}"
        );
        // Durable admission tombstones must continue to deny the same provider after restart.
        sorafs_publication::restart(&published, 0).await?;
        let response = sorafs_publication::retrieve(&published, 0).await?;
        eyre::ensure!(
            !response.status().is_success(),
            "restart resurrected revoked admission"
        );
        let body = String::from_utf8(sorafs_publication_http::bytes(response, 65536).await?)?;
        eyre::ensure!(
            body.contains("provider_not_admitted"),
            "restart did not retain governed revocation: {body}"
        );
        let healthy = sorafs_publication::retrieve(&published, 1).await?;
        eyre::ensure!(
            healthy.status().is_success(),
            "revoking one provider disabled a healthy replica"
        );
        let healthy_bytes =
            sorafs_publication_http::bytes(healthy, published.payload.len()).await?;
        eyre::ensure!(healthy_bytes == published.payload);
        Ok(())
    })
}

/// Prepare the actual seven-body provider governance corridor with independent threshold signers.
/// The caller must provision four validators and provider genesis inputs before network startup.
#[cfg(unix)]
fn publication_parliament_builder(
    builder: iroha_test_network::NetworkBuilder,
) -> iroha_test_network::NetworkBuilder {
    parliament::enactment::builder(builder).with_config_layer(|layer| {
        layer
            .write(
                ["gov", "coordination_council_size"],
                i64::from(parliament::BODY_SEATS),
            )
            .write(["gov", "parliament_invitation_phase_blocks"], 68_i64);
    })
}

/// Execute a provider proposal through genuine citizen sortition, findings, timed OVN and enactment.
/// The return coordinates are observed only after all four peers agree on the enacted attempt.
#[cfg(unix)]
async fn enact_publication_proposal(
    network: &iroha_test_network::Network,
    proposal: iroha_data_model::governance::types::ProposalKind,
) -> eyre::Result<(
    iroha_data_model::governance::types::GovernanceAttemptId,
    u64,
)> {
    use eyre::eyre;
    use iroha_data_model::governance::types::{GovernanceAttemptStatusV1, ProposalKind};
    use parliament::{citizen_accounts, citizen_keys, client_for, exact_block, read_attempt};
    let ProposalKind::SorafsProviderGovernance(provider) = &proposal else {
        return Err(eyre!(
            "publication corridor requires a provider governance proposal"
        ));
    };
    let preliminary = iroha_data_model::isi::governance::ProposeSorafsProviderGovernance {
        action: (*provider.action).clone(),
    };
    let keys = citizen_keys();
    let account = citizen_accounts(&keys).remove(0);
    let proposer = client_for(&network.client(), &account, &keys);
    let enacted = Box::pin(parliament::enactment::enact(
        network,
        proposal,
        vec![preliminary.into()],
        Some(proposer),
    ))
    .await?;
    eyre::ensure!(
        enacted.logical_beacon
            == iroha_data_model::governance::types::BeaconSessionId::for_network_v1(
                &network.network_id()
            ),
        "enacted publication proposal must retain the original network's logical beacon"
    );
    let first = exact_block(&network.client(), enacted.height, network).await?;
    for peer in network.peers() {
        let client = peer.client();
        let block = exact_block(&client, enacted.height, network).await?;
        assert_eq!(block.hash(), first.hash());
        let attempt = read_attempt(&client, enacted.attempt_id).await?;
        assert_eq!(attempt.attempt().status, GovernanceAttemptStatusV1::Enacted);
        assert_eq!(attempt.terminal_height(), Some(enacted.height));
        let (_, verified) =
            parliament::finality::certified_block(network, &client, enacted.height).await?;
        assert_eq!(verified.block().hash(), block.hash());
        assert_eq!(
            verified.canonical_executed_wire()?,
            block.clone().with_commit_certificate(None).encode_wire()?,
            "per-peer enacted execution differs from its authenticated native decision",
        );
    }
    Ok((enacted.attempt_id, enacted.height))
}
