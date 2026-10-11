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
// TODO: the revocation is enacted through `parliament::enact_publication_proposal`, which
// needs a hidden ballot to open. Re-enable this corridor when that fixture enacts through
// the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4).
#[ignore = "timed-OVN release slot is no longer consensus demand; the hidden ballot is replaced by the anonymous ballot (specs/parliament_private_ballot_design.md 12.2 step 4)"]
fn four_peer_native_publication_repair_and_parliament_revocation() -> eyre::Result<()> {
    sorafs_network::run("sorafs-publication-governance", || async {
        let published =
            sorafs_publication::create_and_publish(parliament::publication_parliament_builder)
                .await?;
        sorafs_publication::qualify_storage_lifecycle(&published).await?;
        let proposal = published.authority.revocation_proposal(
            0,
            published.network.network_id(),
            sorafs_publication::now()?,
        )?;
        let (_, height) =
            parliament::enact_publication_proposal(&published.network, proposal).await?;
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
        eyre::ensure!(
            sorafs_publication_http::bytes(healthy, published.payload.len()).await?
                == published.payload
        );
        Ok(())
    })
}
