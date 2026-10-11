//! Profile-aware genesis verification entrypoint.
use crate::{
    Outcome, RunArgs,
    genesis::{
        GenesisProfile, ProfileDefaults, parse_vrf_seed_hex, profile_defaults,
        profile_requires_npos, profile_uses_public_xor, resolve_vrf_seed,
    },
    genesis::{PUBLIC_XOR_ALIAS, TAIRA_XOR_ASSET_DEFINITION_ID},
    tui,
};
use clap::Parser;
use color_eyre::eyre::{Result, WrapErr as _, eyre};
use iroha_data_model::{
    asset::{AssetDefinitionAlias, AssetDefinitionId},
    block::consensus::is_valid_committee_size,
    isi::{Register, asset_alias::SetAssetDefinitionAlias},
    parameter::{
        custom::CustomParameterId,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameters},
    },
    prelude::AssetDefinition,
};
use iroha_genesis::RawGenesisTransaction;
use iroha_model_base::domain::DomainId;
use iroha_model_base::peer::PeerId;
use std::{
    collections::{BTreeMap, HashSet},
    io::{BufWriter, Write},
    path::PathBuf,
};

/// Verify a genesis manifest against a known profile (chain id, cadence, VRF seed, PoPs).
#[derive(Debug, Parser, Clone)]
pub struct Args {
    /// Profile to verify against (`iroha3-dev`, `iroha3-taira`, `iroha3-nexus`).
    #[clap(long)]
    profile: GenesisProfile,
    /// Path to the genesis manifest (JSON).
    #[clap(long, value_name = "PATH")]
    genesis: PathBuf,
    /// Optional VRF seed (hex, 32 bytes). Required for NPoS taira/nexus manifests.
    #[clap(long, value_name = "HEX")]
    vrf_seed_hex: Option<String>,
}
#[derive(Debug)]
struct VerificationReport {
    chain_id: String,
    fingerprint: String,
    block_cadence_ms: u64,
    vrf_seed_hex: String,
    peer_count: usize,
}
impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        tui::status("Verifying genesis manifest against profile");
        let manifest =
            RawGenesisTransaction::from_path(&self.genesis).wrap_err("failed to load genesis")?;
        let vrf_seed_override = self
            .vrf_seed_hex
            .as_deref()
            .map(parse_vrf_seed_hex)
            .transpose()
            .wrap_err("invalid --vrf-seed-hex")?;
        let report =
            verify_manifest(&manifest, self.profile, vrf_seed_override).wrap_err_with(|| {
                format!(
                    "profile verification failed for {:?} using {}",
                    self.profile,
                    self.genesis.display()
                )
            })?;
        writeln!(writer, "profile: {:?}", self.profile)?;
        writeln!(writer, "chain_id: {}", report.chain_id)?;
        writeln!(writer, "block_cadence_ms: {}", report.block_cadence_ms)?;
        writeln!(writer, "vrf_seed: {}", report.vrf_seed_hex)?;
        writeln!(writer, "peers_with_pop: {}", report.peer_count)?;
        writeln!(writer, "consensus_fingerprint: {}", report.fingerprint)?;
        writeln!(writer, "kagami_version: {}", env!("CARGO_PKG_VERSION"))?;
        tui::success("Genesis manifest verified");
        Ok(())
    }
}
fn verify_manifest(
    manifest: &RawGenesisTransaction,
    profile: GenesisProfile,
    vrf_seed_override: Option<[u8; 32]>,
) -> Result<VerificationReport> {
    let defaults = profile_defaults(profile);
    ensure_chain_id(manifest, &defaults)?;
    crate::genesis::ensure_genesis_schedule_matches_consensus(manifest)?;
    let normalized = manifest.clone().with_consensus_meta()?;
    let params = normalized.effective_parameters()?;
    let sumeragi: SumeragiParameters = params.sumeragi().clone();
    let mode = enforce_mode(profile, &normalized)?;
    enforce_cadence(&sumeragi, &defaults)?;
    enforce_gas_limit(&params)?;
    let wants_npos = matches!(mode, SumeragiConsensusMode::Npos);
    if !wants_npos && vrf_seed_override.is_some() {
        return Err(eyre!(
            "`--vrf-seed-hex` applies only to NPoS consensus manifests"
        ));
    }
    if wants_npos && profile_uses_public_xor(profile) {
        enforce_public_xor_binding(manifest, profile)?;
    }
    let seed_hex = if wants_npos {
        let npos_params = resolve_npos_params(&params)?;
        let expected_seed = resolve_vrf_seed(profile, manifest.chain_id(), vrf_seed_override)?;
        let seed_hex = hex::encode_upper(expected_seed);
        if npos_params.epoch_seed() != expected_seed {
            return Err(eyre!(
                "VRF seed mismatch: expected {} but manifest carries {}",
                seed_hex,
                hex::encode_upper(npos_params.epoch_seed())
            ));
        }
        seed_hex
    } else {
        "n/a".to_owned()
    };
    let peers_with_pops = collect_topology(manifest)?;
    let unique_peers: HashSet<_> = peers_with_pops.iter().collect();
    if unique_peers.len() != peers_with_pops.len() {
        return Err(eyre!(
            "profile {:?} topology contains duplicate voting peer identities",
            profile
        ));
    }
    if unique_peers.len() < defaults.min_peers {
        return Err(eyre!(
            "profile {:?} requires at least {} topology entries with PoP (saw {})",
            profile,
            defaults.min_peers,
            unique_peers.len()
        ));
    }
    if !is_valid_committee_size(unique_peers.len()) {
        return Err(eyre!(
            "profile {:?} topology must contain an exact revision-4 `3f + 1` committee \
             between 4 and 31 validators (saw {})",
            profile,
            unique_peers.len()
        ));
    }
    let fingerprint = normalized
        .consensus_fingerprint()
        .ok_or_else(|| eyre!("consensus fingerprint missing after normalization"))?
        .to_string();
    if let Some(raw_fp) = manifest.consensus_fingerprint()
        && raw_fp.to_string() != fingerprint
    {
        return Err(eyre!(
            "consensus_fingerprint mismatch: manifest advertises {raw_fp} but recomputation yielded {fingerprint}"
        ));
    }
    Ok(VerificationReport {
        chain_id: manifest.chain_id().as_str().to_owned(),
        fingerprint,
        block_cadence_ms: sumeragi.block_cadence_ms().get(),
        vrf_seed_hex: seed_hex,
        peer_count: unique_peers.len(),
    })
}
fn enforce_public_xor_binding(
    manifest: &RawGenesisTransaction,
    profile: GenesisProfile,
) -> Result<()> {
    let public_xor_alias: AssetDefinitionAlias = PUBLIC_XOR_ALIAS.parse()?;
    let synthetic_stake_asset_id = AssetDefinitionId::derive_from_components(
        DomainId::parse_fully_qualified("nexus.universal")?,
        "xor".parse()?,
    );
    let mut registered_asset_definitions = BTreeMap::new();
    let mut public_xor_binding = None;
    for instruction in manifest.instructions() {
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<Register<AssetDefinition>>()
        {
            registered_asset_definitions.insert(register.object.id.clone(), &register.object);
            continue;
        }
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::register::RegisterBox>()
        {
            if let iroha_data_model::isi::register::RegisterBox::AssetDefinition(register) =
                register
            {
                registered_asset_definitions.insert(register.object.id.clone(), &register.object);
            }
            continue;
        }
        if let Some(bind) = instruction
            .as_any()
            .downcast_ref::<SetAssetDefinitionAlias>()
            && bind.alias.as_ref() == Some(&public_xor_alias)
        {
            if let Some(existing) = &public_xor_binding
                && existing != &bind.asset_definition_id
            {
                return Err(eyre!(
                    "public XOR alias `{PUBLIC_XOR_ALIAS}` is bound to multiple asset definitions"
                ));
            }
            public_xor_binding = Some(bind.asset_definition_id.clone());
        }
    }
    if registered_asset_definitions.contains_key(&synthetic_stake_asset_id) {
        return Err(eyre!(
            "public profile {:?} must not register synthetic `nexus.universal/xor` as the NPoS stake asset",
            profile
        ));
    }
    let Some(public_xor_asset_definition_id) = public_xor_binding else {
        return Err(eyre!(
            "public profile {:?} must bind `{PUBLIC_XOR_ALIAS}` to a canonical XOR asset definition in genesis",
            profile
        ));
    };
    if profile == GenesisProfile::Iroha3Taira
        && public_xor_asset_definition_id.to_string() != TAIRA_XOR_ASSET_DEFINITION_ID
    {
        return Err(eyre!(
            "Taira `{PUBLIC_XOR_ALIAS}` binding must target `{TAIRA_XOR_ASSET_DEFINITION_ID}`, found `{public_xor_asset_definition_id}`"
        ));
    }
    if public_xor_asset_definition_id == synthetic_stake_asset_id {
        return Err(eyre!(
            "public profile {:?} binds `{PUBLIC_XOR_ALIAS}` to synthetic `nexus.universal/xor`; use the real canonical XOR asset definition",
            profile
        ));
    }
    if profile == GenesisProfile::Iroha3Nexus
        && public_xor_asset_definition_id.to_string() == TAIRA_XOR_ASSET_DEFINITION_ID
    {
        return Err(eyre!(
            "Nexus requires its operator-provisioned mainnet XOR definition, not the Taira testnet definition"
        ));
    }
    let parameters = manifest.effective_parameters()?;
    let npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| eyre!("public XOR requires the signed NPoS asset pin"))?;
    if npos.xor_asset_definition_id != public_xor_asset_definition_id {
        return Err(eyre!(
            "public XOR alias differs from the immutable NPoS XOR definition"
        ));
    }
    if !registered_asset_definitions.contains_key(&public_xor_asset_definition_id) {
        return Err(eyre!(
            "public profile {:?} binds `{PUBLIC_XOR_ALIAS}` to `{public_xor_asset_definition_id}` but does not register that asset definition",
            profile
        ));
    }
    let definition = registered_asset_definitions[&public_xor_asset_definition_id];
    if definition.spec != iroha_primitives::numeric::NumericSpec::fractional(9)
        || definition.balance_scope_policy != iroha_data_model::asset::AssetBalancePolicy::Global
    {
        return Err(eyre!(
            "public XOR asset `{public_xor_asset_definition_id}` requires global scope and scale nine"
        ));
    }
    Ok(())
}
fn ensure_chain_id(manifest: &RawGenesisTransaction, defaults: &ProfileDefaults) -> Result<()> {
    if manifest.chain_id() != &defaults.chain_id {
        return Err(eyre!(
            "chain id mismatch: expected `{}`, found `{}`",
            defaults.chain_id,
            manifest.chain_id().as_str()
        ));
    }
    Ok(())
}
fn enforce_mode(
    profile: GenesisProfile,
    manifest: &RawGenesisTransaction,
) -> Result<SumeragiConsensusMode> {
    let mode = manifest.consensus_mode();
    if profile_requires_npos(profile) && mode != SumeragiConsensusMode::Npos {
        return Err(eyre!(
            "profile {:?} targets the public dataspace; expected NPoS but manifest advertises {:?}",
            profile,
            mode
        ));
    }
    Ok(mode)
}
fn enforce_cadence(params: &SumeragiParameters, defaults: &ProfileDefaults) -> Result<()> {
    if params.block_cadence_ms() != defaults.block_cadence_ms {
        return Err(eyre!(
            "block cadence mismatch: expected {}ms, saw {}ms",
            defaults.block_cadence_ms,
            params.block_cadence_ms(),
        ));
    }
    Ok(())
}
fn enforce_gas_limit(params: &iroha_data_model::parameter::Parameters) -> Result<()> {
    let gas_param_id = CustomParameterId::new("ivm_gas_limit_per_block".parse()?);
    let Some(custom) = params.custom().get(&gas_param_id) else {
        return Err(eyre!(
            "`ivm_gas_limit_per_block` parameter missing; profiles pin it to 1_680_000"
        ));
    };
    let Some(limit) = custom.payload().try_into_any::<u64>().ok() else {
        return Err(eyre!(
            "`ivm_gas_limit_per_block` payload must be an integer (JSON u64)"
        ));
    };
    if limit != 1_680_000 {
        return Err(eyre!(
            "`ivm_gas_limit_per_block` mismatch: expected 1_680_000, saw {}",
            limit
        ));
    }
    Ok(())
}
fn resolve_npos_params(
    params: &iroha_data_model::parameter::Parameters,
) -> Result<SumeragiNposParameters> {
    let npos_param_id = SumeragiNposParameters::parameter_id();
    params
        .custom()
        .get(&npos_param_id)
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| eyre!("missing `sumeragi_npos_parameters` in manifest"))
}
fn collect_topology(manifest: &RawGenesisTransaction) -> Result<Vec<PeerId>> {
    let mut peers_with_pop = Vec::new();
    for (tx_idx, tx) in manifest.transactions().iter().enumerate() {
        for entry in tx.topology() {
            let Some(_pop) = entry.pop_bytes().map_err(|err| {
                eyre!(
                    "transaction {tx_idx} has invalid `pop_hex` for peer {}: {err}",
                    entry.peer.public_key()
                )
            })?
            else {
                return Err(eyre!(
                    "transaction {tx_idx} missing `pop_hex` for peer {}",
                    entry.peer.public_key()
                ));
            };
            peers_with_pop.push(entry.peer.clone());
        }
    }
    Ok(peers_with_pop)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{CompleteTestGenesisBuilder as _, profile::derive_vrf_seed_from_chain};
    use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
    use iroha_data_model::{
        asset::{AssetDefinitionAlias, AssetDefinitionId},
        isi::asset_alias::SetAssetDefinitionAlias,
        parameter::system::SumeragiConsensusMode,
        prelude::{AssetDefinition, NumericSpec, PublicKey, Register},
    };
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry, RawGenesisTransaction};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::peer::PeerId;
    use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;
    use tempfile::NamedTempFile;
    fn test_public_xor_asset_definition_id(profile: GenesisProfile) -> AssetDefinitionId {
        match profile {
            GenesisProfile::Iroha3Taira => {
                AssetDefinitionId::parse_address_literal(TAIRA_XOR_ASSET_DEFINITION_ID)
                    .expect("valid Taira XOR id")
            }
            GenesisProfile::Iroha3Nexus => {
                AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc")
                    .expect("valid Nexus XOR fixture id")
            }
            GenesisProfile::Iroha3Dev => unreachable!("dev profile has no public XOR"),
        }
    }
    fn append_public_xor_binding_for_test(
        manifest: RawGenesisTransaction,
        asset_definition_id: AssetDefinitionId,
    ) -> RawGenesisTransaction {
        append_public_xor_binding_with_shape_for_test(
            manifest,
            asset_definition_id,
            NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
        )
    }
    fn append_public_xor_binding_with_shape_for_test(
        manifest: RawGenesisTransaction,
        asset_definition_id: AssetDefinitionId,
        spec: NumericSpec,
        scope: iroha_data_model::asset::AssetBalancePolicy,
    ) -> RawGenesisTransaction {
        let consensus_mode = manifest.consensus_mode();
        let chain_discriminant = manifest.chain_discriminant();
        let alias: AssetDefinitionAlias = PUBLIC_XOR_ALIAS.parse().expect("valid alias");
        let parameters = manifest.effective_parameters().expect("fixture parameters");
        let mut npos = parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()
            .expect("valid fixture NPoS parameters")
            .flatten()
            .expect("fixture NPoS snapshot");
        npos.xor_asset_definition_id = asset_definition_id.clone();
        manifest
            .into_builder()
            .append_parameter(iroha_data_model::parameter::Parameter::Custom(
                npos.into_custom_parameter(),
            ))
            .next_transaction()
            .append_instruction(Register::asset_definition(
                AssetDefinition::new(
                    asset_definition_id.clone(),
                    "xor".to_owned(),
                    spec,
                    scope,
                    None,
                )
                .with_metadata(Metadata::default()),
            ))
            .append_instruction(SetAssetDefinitionAlias::bind(
                asset_definition_id,
                alias,
                None,
            ))
            .build_raw()
            .expect("preserve complete profile fixture authority")
            .with_consensus_mode(consensus_mode)
            .with_chain_discriminant(chain_discriminant)
    }
    fn build_manifest_with_profile(
        profile: GenesisProfile,
        consensus_mode: SumeragiConsensusMode,
        vrf_seed: [u8; 32],
        peers: &[(PublicKey, Vec<u8>)],
    ) -> RawGenesisTransaction {
        let defaults = profile_defaults(profile);
        let builder = complete_builder_for_test_peers(
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from(".")),
            peers,
        );
        let manifest = crate::genesis::generate_default(
            builder,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            consensus_mode,
            Some(&defaults),
            Some(vrf_seed),
        )
        .expect("generate profile manifest");
        let manifest = if profile_uses_public_xor(profile) {
            append_public_xor_binding_for_test(
                manifest,
                test_public_xor_asset_definition_id(profile),
            )
        } else {
            manifest
        };
        manifest
            .clear_topology()
            .into_builder()
            .next_transaction()
            .set_topology_for_test(
                peers
                    .iter()
                    .map(|(pk, pop)| {
                        GenesisTopologyEntry::new(PeerId::new(pk.clone()), pop.clone())
                    })
                    .collect(),
            )
            .build_raw()
            .expect("preserve complete profile fixture authority")
    }
    fn complete_builder_for_test_peers(
        builder: GenesisBuilder,
        peers: &[(PublicKey, Vec<u8>)],
    ) -> GenesisBuilder {
        builder
            .set_topology(
                peers
                    .iter()
                    .map(|(public_key, _)| PeerId::new(public_key.clone()))
                    .collect(),
            )
            .complete_for_test()
    }
    fn generate_peer_pop() -> (PublicKey, Vec<u8>) {
        let kp = KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
            .expect("checked Kagami verify BLS fixture key generation");
        let pop = bls_normal_pop_prove(kp.private_key()).expect("generate PoP");
        (kp.public_key().clone(), pop)
    }
    #[test]
    fn generate_peer_pop_uses_checked_bls_key_generation() {
        let (public_key, pop) = generate_peer_pop();
        assert_eq!(
            public_key
                .try_algorithm()
                .expect("checked Kagami fixture public-key algorithm"),
            Algorithm::BlsNormal,
        );
        assert!(!pop.is_empty());
    }
    #[test]
    fn verify_accepts_dev_profile_manifest() {
        let seed = derive_vrf_seed_from_chain(&ChainId::from("iroha3-dev.local"));
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let manifest = build_manifest_with_profile(
            GenesisProfile::Iroha3Dev,
            SumeragiConsensusMode::Npos,
            seed,
            &peers,
        );
        let report =
            verify_manifest(&manifest, GenesisProfile::Iroha3Dev, None).expect("verify manifest");
        assert_eq!(report.peer_count, 4);
        assert_eq!(report.vrf_seed_hex, hex::encode_upper(seed));
    }
    #[test]
    fn verify_allows_permissioned_dev_profile() {
        let seed = derive_vrf_seed_from_chain(&ChainId::from("iroha3-dev.local"));
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let manifest = build_manifest_with_profile(
            GenesisProfile::Iroha3Dev,
            SumeragiConsensusMode::Permissioned,
            seed,
            &peers,
        );
        let report =
            verify_manifest(&manifest, GenesisProfile::Iroha3Dev, None).expect("verify manifest");
        assert_eq!(report.peer_count, 4);
        assert_eq!(report.vrf_seed_hex, "n/a");
    }
    #[test]
    fn verify_rejects_non_committee_profile_topologies() {
        let seed = derive_vrf_seed_from_chain(&ChainId::from("iroha3-dev.local"));
        let peers = (0..32).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        for count in [1_usize, 2, 3, 5, 32] {
            let manifest = build_manifest_with_profile(
                GenesisProfile::Iroha3Dev,
                SumeragiConsensusMode::Npos,
                seed,
                &peers[..4],
            )
            .into_builder()
            .set_topology(
                peers[..count]
                    .iter()
                    .map(|(key, pop)| {
                        GenesisTopologyEntry::new(PeerId::new(key.clone()), pop.clone())
                    })
                    .collect(),
            )
            .build_raw()
            .expect("preserve the original valid authority while substituting invalid topology");
            let error = verify_manifest(&manifest, GenesisProfile::Iroha3Dev, None)
                .expect_err("non-committee topology must fail profile verification");
            assert!(
                error.to_string().contains("requires at least")
                    || error.to_string().contains("exact revision-4 `3f + 1`"),
                "unexpected error for {count} peers: {error}"
            );
        }
    }
    #[test]
    fn verify_requires_seed_for_taira_profile() {
        let seed = [7u8; 32];
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let manifest = build_manifest_with_profile(
            GenesisProfile::Iroha3Taira,
            SumeragiConsensusMode::Npos,
            seed,
            &peers,
        );
        let err = verify_manifest(&manifest, GenesisProfile::Iroha3Taira, None)
            .expect_err("seed required");
        assert!(
            err.to_string().contains("vrf-seed-hex"),
            "unexpected error: {err}"
        );
        let ok = verify_manifest(&manifest, GenesisProfile::Iroha3Taira, Some(seed));
        assert!(
            ok.is_ok(),
            "explicit seed should satisfy verification: {ok:?}"
        );
    }
    #[test]
    fn verify_accepts_nexus_profile_with_explicit_public_xor_binding() {
        let seed = [8u8; 32];
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let manifest = build_manifest_with_profile(
            GenesisProfile::Iroha3Nexus,
            SumeragiConsensusMode::Npos,
            seed,
            &peers,
        );
        let report = verify_manifest(&manifest, GenesisProfile::Iroha3Nexus, Some(seed))
            .expect("Nexus explicit XOR binding should verify");
        assert_eq!(report.peer_count, 4);
    }
    #[test]
    fn public_xor_verification_rejects_wrong_scope_and_precision() {
        for profile in [GenesisProfile::Iroha3Taira, GenesisProfile::Iroha3Nexus] {
            let seed = [8_u8; 32];
            let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
            let defaults = profile_defaults(profile);
            let builder = complete_builder_for_test_peers(
                GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from(".")),
                &peers,
            );
            let manifest = crate::genesis::generate_default(
                builder,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
                None,
                SumeragiConsensusMode::Npos,
                Some(&defaults),
                Some(seed),
            )
            .unwrap();
            for (spec, scope) in [
                (
                    NumericSpec::fractional(9),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                ),
                (
                    NumericSpec::default(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                ),
                (
                    NumericSpec::fractional(18),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                ),
                (
                    NumericSpec::fractional(9),
                    iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                ),
            ] {
                let candidate = append_public_xor_binding_with_shape_for_test(
                    manifest.clone(),
                    test_public_xor_asset_definition_id(profile),
                    spec,
                    scope,
                );
                let result = enforce_public_xor_binding(&candidate, profile);
                if spec == NumericSpec::fractional(9)
                    && scope == iroha_data_model::asset::AssetBalancePolicy::Global
                {
                    result.unwrap();
                } else {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("requires global scope and scale nine")
                    );
                }
            }
        }
    }
    #[test]
    fn verify_rejects_public_profile_missing_xor_binding() {
        let seed = [9u8; 32];
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let defaults = profile_defaults(GenesisProfile::Iroha3Taira);
        let builder = complete_builder_for_test_peers(
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from(".")),
            &peers,
        );
        let manifest = crate::genesis::generate_default(
            builder,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            Some(&defaults),
            Some(seed),
        )
        .expect("generate profile manifest")
        .into_builder()
        .next_transaction()
        .set_topology_for_test(
            peers
                .iter()
                .map(|(pk, pop)| GenesisTopologyEntry::new(PeerId::new(pk.clone()), pop.clone()))
                .collect(),
        )
        .build_raw()
        .expect("preserve complete Taira profile authority")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_chain_discriminant(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT);
        let err = verify_manifest(&manifest, GenesisProfile::Iroha3Taira, Some(seed))
            .expect_err("missing public XOR binding should fail");
        assert!(
            err.to_string().contains(PUBLIC_XOR_ALIAS),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_rejects_taira_wrong_public_xor_binding() {
        let seed = [10u8; 32];
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let defaults = profile_defaults(GenesisProfile::Iroha3Taira);
        let builder = complete_builder_for_test_peers(
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from(".")),
            &peers,
        );
        let manifest = crate::genesis::generate_default(
            builder,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            Some(&defaults),
            Some(seed),
        )
        .expect("generate profile manifest");
        let wrong_xor = AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc")
            .expect("valid fixture id");
        let manifest = append_public_xor_binding_for_test(manifest, wrong_xor)
            .into_builder()
            .next_transaction()
            .set_topology_for_test(
                peers
                    .iter()
                    .map(|(pk, pop)| {
                        GenesisTopologyEntry::new(PeerId::new(pk.clone()), pop.clone())
                    })
                    .collect(),
            )
            .build_raw()
            .expect("preserve complete Taira profile authority")
            .with_consensus_mode(SumeragiConsensusMode::Npos)
            .with_chain_discriminant(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT);
        let err = verify_manifest(&manifest, GenesisProfile::Iroha3Taira, Some(seed))
            .expect_err("wrong Taira XOR id should fail");
        assert!(
            err.to_string().contains(TAIRA_XOR_ASSET_DEFINITION_ID),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_rejects_public_profile_synthetic_xor_binding() {
        let seed = [11u8; 32];
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let defaults = profile_defaults(GenesisProfile::Iroha3Taira);
        let builder = complete_builder_for_test_peers(
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from(".")),
            &peers,
        );
        let manifest = crate::genesis::generate_default(
            builder,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            Some(&defaults),
            Some(seed),
        )
        .expect("generate profile manifest");
        let synthetic_xor = AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("nexus.universal").expect("valid domain"),
            "xor".parse().expect("valid asset name"),
        );
        let manifest = append_public_xor_binding_for_test(manifest, synthetic_xor)
            .into_builder()
            .next_transaction()
            .set_topology_for_test(
                peers
                    .iter()
                    .map(|(pk, pop)| {
                        GenesisTopologyEntry::new(PeerId::new(pk.clone()), pop.clone())
                    })
                    .collect(),
            )
            .build_raw()
            .expect("preserve complete Taira profile authority")
            .with_consensus_mode(SumeragiConsensusMode::Npos)
            .with_chain_discriminant(crate::genesis::profile::TAIRA_CHAIN_DISCRIMINANT);
        let err = verify_manifest(&manifest, GenesisProfile::Iroha3Taira, Some(seed))
            .expect_err("synthetic public XOR binding should fail");
        let malformed_npos = manifest
            .effective_parameters()
            .unwrap()
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose();
        assert!(
            malformed_npos.is_err(),
            "synthetic currency must fail the typed NPoS parameter decoder"
        );
        assert!(
            matches!(
                err.downcast_ref::<norito::json::Error>(),
                Some(norito::json::Error::InvalidField { field, message })
                    if field == "SumeragiNposParameters"
                        && message == "NPoS must use the network's canonical XOR asset, not synthetic nexus.universal/xor"
            ),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_rejects_public_profile_domain_derived_xor_binding() {
        let seed = [12u8; 32];
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let defaults = profile_defaults(GenesisProfile::Iroha3Nexus);
        let builder = complete_builder_for_test_peers(
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from(".")),
            &peers,
        );
        let manifest = crate::genesis::generate_default(
            builder,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            Some(&defaults),
            Some(seed),
        )
        .expect("generate profile manifest");
        let domain_derived_xor = AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("universal.universal").expect("valid domain"),
            "xor".parse().expect("valid asset name"),
        );
        assert_eq!(
            domain_derived_xor.to_string(),
            TAIRA_XOR_ASSET_DEFINITION_ID
        );
        let manifest = append_public_xor_binding_for_test(manifest, domain_derived_xor)
            .into_builder()
            .next_transaction()
            .set_topology_for_test(
                peers
                    .iter()
                    .map(|(pk, pop)| {
                        GenesisTopologyEntry::new(PeerId::new(pk.clone()), pop.clone())
                    })
                    .collect(),
            )
            .build_raw()
            .expect("preserve complete Nexus profile authority")
            .with_consensus_mode(SumeragiConsensusMode::Npos)
            .with_chain_discriminant(crate::genesis::profile::NEXUS_CHAIN_DISCRIMINANT);
        let err = verify_manifest(&manifest, GenesisProfile::Iroha3Nexus, Some(seed))
            .expect_err("domain-derived public XOR binding should fail");
        assert!(
            err.to_string()
                .contains("Nexus requires its operator-provisioned mainnet XOR definition"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_rejects_missing_pop() {
        let defaults = profile_defaults(GenesisProfile::Iroha3Dev);
        let seed = derive_vrf_seed_from_chain(&defaults.chain_id);
        let builder =
            GenesisBuilder::new_without_executor(defaults.chain_id.clone(), PathBuf::from("."))
                .complete_for_test();
        let manifest = crate::genesis::generate_default(
            builder,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
            None,
            SumeragiConsensusMode::Npos,
            Some(&defaults),
            Some(seed),
        )
        .expect("generate profile manifest")
        .into_builder()
        .next_transaction()
        .set_topology(vec![GenesisTopologyEntry::from(PeerId::new(
            generate_peer_pop().0,
        ))])
        .build_raw()
        .expect("preserve complete development profile authority");
        let err = verify_manifest(&manifest, GenesisProfile::Iroha3Dev, Some(seed))
            .expect_err("missing PoP should fail");
        assert!(
            err.to_string().contains("missing `pop_hex`"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn verify_command_outputs_report_for_dev_profile() {
        let seed = derive_vrf_seed_from_chain(&ChainId::from("iroha3-dev.local"));
        let peers = (0..4).map(|_| generate_peer_pop()).collect::<Vec<_>>();
        let manifest = build_manifest_with_profile(
            GenesisProfile::Iroha3Dev,
            SumeragiConsensusMode::Npos,
            seed,
            &peers,
        );
        let mut file = NamedTempFile::new().expect("create temp file");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize genesis");
        file.write_all(json.as_bytes()).expect("write genesis");
        let args = Args {
            profile: GenesisProfile::Iroha3Dev,
            genesis: file.path().to_path_buf(),
            vrf_seed_hex: None,
        };
        let mut writer = std::io::BufWriter::new(Vec::new());
        args.run(&mut writer)
            .expect("verify command should succeed");
        writer.flush().expect("flush buffer");
        let output =
            String::from_utf8(writer.into_inner().expect("collect output")).expect("utf8 output");
        assert!(
            output.contains("chain_id: iroha3-dev.local"),
            "report should include chain id: {output}"
        );
        assert!(
            output.contains("vrf_seed:"),
            "report should include VRF seed: {output}"
        );
    }
}
