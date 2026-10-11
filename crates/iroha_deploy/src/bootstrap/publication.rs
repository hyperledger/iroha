//! Offline release production from independently authenticated genesis and native proof frames.

use std::num::NonZeroU64;

use iroha_crypto::{Hash, KeyPair, PublicKey};
use iroha_data_model::{
    Identifiable as _, NetworkId,
    isi::RegisterBox,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityCheckpoint, SumeragiFinalityProof},
};
use iroha_genesis::RawGenesisTransaction;

use super::{
    BootstrapError, InstalledNetworkProfile, InstalledNetworkProfiles, NetworkRelease,
    ReleaseBuildRegistry, ReleaseFaucet, ReleasePeer, Result, SignedNetworkCheckpoint,
};
use crate::verify::finality::{
    FinalitySource, FinalityVerifier, GenesisAnchor, MAX_ADVANCE_BYTES, MAX_ADVANCE_PROOFS,
};

/// Explicit operator publication policy; consensus coordinates are derived from native evidence.
#[derive(Clone, Debug)]
pub struct NetworkPublicationPolicy {
    /// Independently selected installed network label.
    pub network_name: String,
    /// Strictly advancing official publication serial.
    pub serial: u64,
    /// Explicit reset generation for the selected genesis.
    pub generation: u64,
    /// Inclusive release start in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Exclusive release expiry, at most one day after issue.
    pub expires_at_ms: u64,
    /// Explicit approved canonical HTTPS parent roots.
    pub torii_roots: Vec<String>,
    /// Explicit BLS member-to-endpoint bindings.
    pub peers: Vec<ReleasePeer>,
    /// Optional authenticated finite funding allowance.
    pub faucet: Option<ReleaseFaucet>,
    /// Optional independently selected parent build registry.
    pub build_registry: Option<ReleaseBuildRegistry>,
    /// Independently selected canonical HTTPS artifact publication location.
    pub checkpoint_url: String,
    /// Independently selected release authority; it must match the native signer.
    pub release_public_key: PublicKey,
}

/// Complete canonical public installation artifacts, prepared without filesystem or network writes.
pub struct PreparedNetworkPublication {
    /// Derived signed release metadata, including the candidate's compiled World schema.
    pub release: NetworkRelease,
    /// Canonical independently signed checkpoint artifact to publish at the selected URL.
    pub checkpoint_bytes: Vec<u8>,
    /// Canonical installation authority artifact for the matching native developer bundle.
    pub profile_bytes: Vec<u8>,
}

/// Independent operator trust selections for original genesis and its complete source manifest.
///
/// The manifest digest is authenticated separately, for example by an admitted native public-inputs
/// record. It must not be chosen from the same untrusted manifest being admitted. Some manifest
/// fields, including the address discriminant, are not repeated in signed genesis instructions.
pub struct PinnedPublicationGenesis<'a> {
    /// Original canonical signed-genesis bytes selected independently of proof transport.
    pub signed_genesis: &'a [u8],
    /// Exact complete manifest JSON covered by the independent installation/release input digest.
    pub manifest_json: &'a [u8],
    /// Independently authenticated SHA256 digest of the original manifest JSON bytes.
    pub expected_manifest_sha256: [u8; 32],
    /// Independently authenticated genesis signing authority.
    pub genesis_public_key: &'a PublicKey,
    /// Independently selected genesis-derived network identity.
    pub expected_network: NetworkId,
}

/// Verify a pinned signed-genesis bundle and a contiguous native proof prefix, then sign its release.
///
/// Genesis, its key and exact network identity are operator inputs authenticated independently of
/// proof transport. The entire manifest first matches its independently selected digest, then its
/// semantics match signed instructions before its chain/address profile is used. The schema
/// describes this compiled candidate; preparing artifacts does not qualify a
/// live network, publish an HTTPS endpoint or authenticate a developer installation.
///
/// # Errors
/// Refuses substituted genesis/manifest/key/network, missing or noncontiguous proofs, bounded-work
/// violations, invalid native finality, signer substitution, expired policy or unsafe profile URLs.
pub fn prepare_network_publication(
    genesis: PinnedPublicationGenesis<'_>,
    proofs: &[SumeragiFinalityProof],
    policy: NetworkPublicationPolicy,
    signer: &KeyPair,
    now_ms: u64,
) -> Result<PreparedNetworkPublication> {
    if genesis.manifest_json.len() > iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1 {
        return Err(BootstrapError::Invalid(
            "genesis manifest exceeds native input byte bound",
        ));
    }
    if iroha_crypto::sha256(genesis.manifest_json) != genesis.expected_manifest_sha256 {
        return Err(BootstrapError::Invalid(
            "genesis manifest differs from independently authenticated digest",
        ));
    }
    iroha_genesis::validate_genesis_manifest_json(genesis.manifest_json).map_err(|_| {
        BootstrapError::Invalid("genesis manifest exceeds native JSON admission bounds")
    })?;
    let manifest = RawGenesisTransaction::from_json_slice(genesis.manifest_json)
        .map_err(|_| BootstrapError::Invalid("invalid authenticated genesis manifest"))?;
    let bundle = iroha_genesis::validate_prepared_genesis_bundle(
        genesis.signed_genesis,
        &manifest,
        genesis.genesis_public_key,
        genesis.expected_network.into_genesis_hash(),
    )
    .map_err(|_| {
        BootstrapError::Invalid(
            "signed genesis does not match the pinned manifest, key and network",
        )
    })?;
    if let Some(faucet) = &policy.faucet {
        validate_genesis_faucet(&manifest, faucet)?;
    }
    let anchor = GenesisAnchor {
        network_id: genesis.expected_network,
        chain_id: manifest.chain_id().to_string(),
        genesis: bundle.block().clone(),
        validators: bundle
            .validator_pops()
            .iter()
            .map(|(key, pop)| FinalityValidator {
                public_key: key.clone(),
                proof_of_possession: pop.clone(),
            })
            .collect(),
    };
    let checkpoint = checkpoint_from_proofs(&anchor, proofs)?;
    prepare_checkpoint(
        checkpoint,
        manifest.chain_discriminant(),
        policy,
        signer,
        now_ms,
    )
}

fn validate_genesis_faucet(manifest: &RawGenesisTransaction, faucet: &ReleaseFaucet) -> Result<()> {
    // Faucet amount and spending limits are operator-approved runtime policy.
    // Bind their issuer/currency to authenticated native registration instructions;
    // current balances and each prepared funding transfer remain ledger checks.
    let mut issuer_registered = false;
    let mut asset_registered = false;
    for instruction in manifest.instructions() {
        match instruction.as_any().downcast_ref::<RegisterBox>() {
            Some(RegisterBox::Account(register)) if register.object().id() == &faucet.issuer => {
                issuer_registered = true;
            }
            Some(RegisterBox::AssetDefinition(register))
                if register.object().id() == &faucet.asset_definition_id =>
            {
                asset_registered = true;
            }
            _ => {}
        }
    }
    if !issuer_registered || !asset_registered {
        return Err(BootstrapError::Invalid(
            "selected faucet issuer or currency is absent from authenticated genesis",
        ));
    }
    Ok(())
}

fn checkpoint_from_proofs(
    anchor: &GenesisAnchor,
    proofs: &[SumeragiFinalityProof],
) -> Result<SumeragiFinalityCheckpoint> {
    if !(2..=MAX_ADVANCE_PROOFS + 1).contains(&proofs.len()) {
        return Err(BootstrapError::Invalid(
            "publication requires a bounded genesis-through-successor proof prefix",
        ));
    }
    let mut bytes = 0_usize;
    for (index, proof) in proofs.iter().enumerate() {
        if proof.height() != index as u64 + 1 {
            return Err(BootstrapError::Invalid(
                "publication proof prefix must be contiguous from genesis",
            ));
        }
        bytes = bytes
            .checked_add(proof.block_wire.len())
            .ok_or(BootstrapError::Invalid(
                "publication proof byte bound overflow",
            ))?;
        if bytes > MAX_ADVANCE_BYTES {
            return Err(BootstrapError::Invalid(
                "publication proof prefix exceeds native byte bound",
            ));
        }
    }
    let mut verifier = FinalityVerifier::from_genesis(anchor, &proofs[0])?;
    // Pass each existing next proof by reference. There is no intervening height to fetch,
    // and therefore no second retained copy of untrusted frame/committee allocations.
    // Count and aggregate wire work were admitted above before the first verification.
    for proof in &proofs[1..] {
        verifier.advance(&OfflineProofSource, proof)?;
    }
    Ok(verifier.checkpoint().clone())
}

struct OfflineProofSource;
impl FinalitySource for OfflineProofSource {
    type Error = std::io::Error;
    fn finality_proof(
        &self,
        _: NonZeroU64,
    ) -> std::result::Result<SumeragiFinalityProof, Self::Error> {
        Err(std::io::Error::other(
            "offline publication requires an exact next proof",
        ))
    }
    fn latest_attestation(
        &self,
        _: &iroha_model_base::peer::PeerId,
        _: &[u8; 32],
    ) -> std::result::Result<crate::verify::finality::FinalityAttestation, Self::Error> {
        Err(std::io::Error::other(
            "offline publication does not claim fresh readiness",
        ))
    }
}

fn prepare_checkpoint(
    checkpoint: SumeragiFinalityCheckpoint,
    discriminant: u16,
    policy: NetworkPublicationPolicy,
    signer: &KeyPair,
    now_ms: u64,
) -> Result<PreparedNetworkPublication> {
    if signer.public_key() != &policy.release_public_key {
        return Err(BootstrapError::Invalid(
            "release signer differs from independently selected public key",
        ));
    }
    if now_ms < policy.issued_at_ms || now_ms >= policy.expires_at_ms {
        return Err(BootstrapError::Invalid(
            "publication policy is not currently valid",
        ));
    }
    let profiles = InstalledNetworkProfiles::new(vec![InstalledNetworkProfile::new(
        policy.network_name.clone(),
        policy.release_public_key,
        policy.serial,
        policy.checkpoint_url,
    )?])?;
    let canonical_checkpoint = checkpoint
        .encode_canonical()
        .map_err(|_| BootstrapError::Invalid("cannot encode verified native checkpoint"))?;
    let release = NetworkRelease {
        network_name: policy.network_name,
        serial: policy.serial,
        generation: policy.generation,
        network_id: checkpoint.network_id(),
        chain_id: checkpoint.chain_id().into(),
        account_chain_discriminant: discriminant,
        native_world_schema: iroha_core::state::State::native_world_schema_hash_v1()
            .map_err(|_| BootstrapError::Invalid("cannot derive candidate native World schema"))?,
        issued_at_ms: policy.issued_at_ms,
        expires_at_ms: policy.expires_at_ms,
        torii_roots: policy.torii_roots,
        peers: policy.peers,
        faucet: policy.faucet,
        build_registry: policy.build_registry,
        checkpoint_hash: Hash::new(canonical_checkpoint),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_hash: checkpoint.block_hash().into(),
    };
    let checkpoint_bytes =
        SignedNetworkCheckpoint::sign(release.clone(), &checkpoint, signer.private_key())?
            .encode_canonical()?;
    let profile_bytes = profiles.encode_installation()?;
    Ok(PreparedNetworkPublication {
        release,
        checkpoint_bytes,
        profile_bytes,
    })
}

#[cfg(test)]
mod tests;
