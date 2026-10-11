//! Current embedded-certificate finality for the real Parliament corridor.
//! Genesis comes from the harness provisioning bundle, never from an HTTP trust claim.

use super::*;
use iroha_data_model::sumeragi_finality::{
    FinalityValidator, SumeragiFinalityProof, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
};
use iroha_sumeragi::availability::recommended_data_availability_layout;

/// Authenticate one exact block through the bounded contiguous native prefix.
/// Each HTTP proof remains untrusted until the existing verifier admits its committee and result.
pub(crate) async fn certified_block(
    network: &iroha_test_network::Network,
    client: &Client,
    height: u64,
) -> Result<(SumeragiFinalityProof, VerifiedSumeragiBlock)> {
    visit_certified_prefix(network, client, height, |_, _| Ok(())).await
}

/// Inspect each independently authenticated decision without retaining a second prefix.
pub(crate) async fn visit_certified_prefix(
    network: &iroha_test_network::Network,
    client: &Client,
    height: u64,
    mut visit: impl FnMut(&SumeragiFinalityProof, &VerifiedSumeragiBlock) -> Result<()> + Send + 'static,
) -> Result<(SumeragiFinalityProof, VerifiedSumeragiBlock)> {
    const MAX_CORRIDOR_HEIGHT: u64 = 4_096;
    if !(1..=MAX_CORRIDOR_HEIGHT).contains(&height) {
        return Err(eyre!(
            "Parliament finality height exceeds the bounded corridor"
        ));
    }
    let provisioned = network.native_genesis_provisioning_bundle()?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        norito::json::from_slice(&provisioned.manifest_json)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &provisioned.signed_wire,
        &manifest,
        &provisioned.public_key,
        provisioned.block_hash,
    )?;
    if iroha_data_model::NetworkId::from_genesis_hash(genesis.expected_hash())
        != network.network_id()
        || genesis.consensus_metadata().sumeragi_context.da_layout
            != recommended_data_availability_layout()
    {
        return Err(eyre!(
            "Parliament signed genesis network or mandatory RS16 layout differs"
        ));
    }
    let validators = genesis
        .validator_pops()
        .iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key: public_key.clone(),
            proof_of_possession: proof_of_possession.clone(),
        })
        .collect::<Vec<_>>();
    if validators.len() != VALIDATOR_COUNT {
        return Err(eyre!(
            "Parliament requires exactly four signed-genesis validators"
        ));
    }
    let expected_members = validators
        .iter()
        .map(|validator| PeerId::new(validator.public_key.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let mut verifier = SumeragiFinalityVerifier::new(
        genesis.block(),
        &network.chain_id().to_string(),
        validators,
    )?;
    let client = client.client().clone();
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    read_on_dedicated_thread(move || {
        let client = client.with_request_deadline(deadline);
        let mut tip = None;
        for next in 1..=height {
            let proof = client.get_sumeragi_finality_proof(NonZeroU64::new(next).unwrap())?;
            let verified = verifier.verify(&proof)?;
            let members = proof
                .committee
                .iter()
                .map(|validator| PeerId::new(validator.public_key.clone()))
                .collect::<std::collections::BTreeSet<_>>();
            if proof.committee.len() != VALIDATOR_COUNT || members != expected_members {
                return Err(eyre!("certified Parliament committee differs from the independent four-validator roster"));
            }
            if next > 1 {
                let certificate = verified.block().commit_certificate().ok_or_else(|| {
                    eyre!("verified Parliament successor lacks its embedded certificate")
                })?;
                let qc: iroha_sumeragi::message::Qc =
                    norito::decode_canonical(certificate.commit_qc())?;
                if qc.signers.count_ones() != 3 {
                    return Err(eyre!("Parliament successor requires exactly three equal validator votes"));
                }
            }
            if Instant::now() >= deadline {
                return Err(eyre!("Parliament contiguous finality verification exceeded its deadline"));
            }
            visit(&proof, &verified)?;
            tip = Some((proof, verified));
        }
        tip.ok_or_else(|| eyre!("Parliament finality prefix is empty"))
    })
    .await
}

/// Bind an observed pulse to the native header and parent admitted from signed genesis.
/// The pulse's claimed anchor and context never select these verification inputs.
pub(crate) async fn certified_pulse_context(
    network: &iroha_test_network::Network,
    client: &Client,
    height: u64,
    pulse: &iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1,
) -> Result<(
    iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1,
    iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
)> {
    use iroha_data_model::consensus::{
        GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1,
    };
    let (_, verified) = certified_block(network, client, height).await?;
    if verified.commitment().beacon.as_ref() != Some(pulse) {
        return Err(eyre!(
            "observed Parliament pulse differs from its certified execution"
        ));
    }
    let certificate = verified
        .block()
        .commit_certificate()
        .ok_or_else(|| eyre!("Parliament pulse lacks a native certificate"))?;
    let header: iroha_sumeragi::message::BlockHeader =
        norito::decode_canonical(certificate.consensus_header())?;
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: height
            .checked_sub(1)
            .filter(|height| *height > 0)
            .ok_or_else(|| eyre!("Parliament pulse has no certified parent"))?,
        block_hash: verified
            .header()
            .prev_block_hash()
            .ok_or_else(|| eyre!("Parliament pulse header has no parent hash"))?,
    };
    let context = GlobalThresholdBeaconPulseContextV1 {
        instance: header.instance.0,
        epoch: header.epoch.epoch,
        epoch_context_id: header.epoch.context.0,
        parent_consensus_hash: header.parent_hash.0,
        parent_result: header.parent_result.0,
    };
    Ok((anchor, context))
}
