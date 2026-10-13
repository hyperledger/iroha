//! Profile presets for Iroha 3 genesis manifests.
use color_eyre::eyre::{Result, eyre};
use core::num::NonZeroU64;
use iroha_crypto::Hash;
use iroha_data_model::asset::AssetDefinitionId;
use iroha_model_base::chain::ChainId;
/// Canonical I105 discriminant for the public Taira testnet.
pub const TAIRA_CHAIN_DISCRIMINANT: u16 = 369;
/// Canonical I105 discriminant for the public Nexus mainnet.
pub const NEXUS_CHAIN_DISCRIMINANT: u16 = 753;
/// Live public Taira XOR asset definition id.
pub const TAIRA_XOR_ASSET_DEFINITION_ID: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
/// Canonical decimal scale for public Taira XOR quantities.
pub const TAIRA_XOR_SCALE: u32 = 9;
/// Public XOR alias selector used by Nexus/Taira configs.
pub const PUBLIC_XOR_ALIAS: &str = "xor#universal";
/// Public XOR domain registered in public-profile genesis manifests.
pub const PUBLIC_XOR_DOMAIN: &str = "universal.universal";
/// Canonical first-release public Taira chain identity.
pub const PUBLIC_TAIRA_CHAIN_ID: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
/// Canonical first-release public Minamoto/Nexus chain identity.
pub const PUBLIC_NEXUS_CHAIN_ID: &str = "00000000-0000-0000-0000-000000000753";
const RETIRED_PUBLIC_CHAIN_ID_ALIASES: &[&str] = &["iroha3-taira", "iroha3-nexus", "cbdc16"];
/// Profile presets for `kagami genesis`/`kagami verify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // Keep network names explicit.
pub enum GenesisProfile {
    /// Local-only developer network.
    Iroha3Dev,
    /// Public Sora test network.
    Iroha3Taira,
    /// Sora Nexus main network.
    Iroha3Nexus,
}
impl std::str::FromStr for GenesisProfile {
    type Err = String;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "iroha3-dev" => Ok(Self::Iroha3Dev),
            "iroha3-taira" => Ok(Self::Iroha3Taira),
            "iroha3-nexus" => Ok(Self::Iroha3Nexus),
            _ => Err("profile must be iroha3-dev, iroha3-taira or iroha3-nexus".into()),
        }
    }
}

/// Default knobs and validation rules derived from a profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDefaults {
    /// Expected chain identifier.
    pub chain_id: ChainId,
    /// Optional canonical I105 chain discriminant to use when rendering account literals.
    pub chain_discriminant: Option<u16>,
    /// Genesis-selected target block cadence in milliseconds.
    pub block_cadence_ms: NonZeroU64,
    /// Minimum number of unique peers (topology entries) required.
    pub min_peers: usize,
    /// How VRF seeds should be resolved for the profile.
    pub seed_policy: SeedPolicy,
}
/// VRF seed policy for a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedPolicy {
    /// Derive the VRF seed deterministically from the chain id when not provided explicitly.
    DerivedFromChain,
    /// Require an explicit seed to be supplied.
    RequireExplicit,
}
/// Return the defaults and validation rules for the given profile.
#[must_use]
pub fn profile_defaults(profile: GenesisProfile) -> ProfileDefaults {
    match profile {
        GenesisProfile::Iroha3Dev => ProfileDefaults {
            chain_id: ChainId::from("iroha3-dev.local"),
            chain_discriminant: None,
            block_cadence_ms: NonZeroU64::new(100).unwrap(),
            min_peers: 4,
            seed_policy: SeedPolicy::DerivedFromChain,
        },
        GenesisProfile::Iroha3Taira => ProfileDefaults {
            chain_id: ChainId::from(PUBLIC_TAIRA_CHAIN_ID),
            chain_discriminant: Some(TAIRA_CHAIN_DISCRIMINANT),
            block_cadence_ms: NonZeroU64::new(4_000).unwrap(),
            min_peers: 4,
            seed_policy: SeedPolicy::RequireExplicit,
        },
        GenesisProfile::Iroha3Nexus => ProfileDefaults {
            chain_id: ChainId::from(PUBLIC_NEXUS_CHAIN_ID),
            chain_discriminant: Some(NEXUS_CHAIN_DISCRIMINANT),
            block_cadence_ms: NonZeroU64::new(100).unwrap(),
            min_peers: 4,
            seed_policy: SeedPolicy::RequireExplicit,
        },
    }
}
/// Whether the profile targets a public Sora network, which is NPoS-only.
#[must_use]
pub fn profile_requires_npos(profile: GenesisProfile) -> bool {
    matches!(
        profile,
        GenesisProfile::Iroha3Taira | GenesisProfile::Iroha3Nexus
    )
}
/// Whether the profile represents a public network whose XOR must be canonical.
#[must_use]
pub fn profile_uses_public_xor(profile: GenesisProfile) -> bool {
    matches!(
        profile,
        GenesisProfile::Iroha3Taira | GenesisProfile::Iroha3Nexus
    )
}
/// Return the public profile associated with a known public chain id.
#[must_use]
pub fn public_xor_profile_for_chain_id(chain_id: &str) -> Option<GenesisProfile> {
    match chain_id {
        PUBLIC_TAIRA_CHAIN_ID => Some(GenesisProfile::Iroha3Taira),
        PUBLIC_NEXUS_CHAIN_ID => Some(GenesisProfile::Iroha3Nexus),
        _ => None,
    }
}
/// Reject pre-release aliases for public network chain identities.
///
/// # Errors
///
/// Returns an error when `chain_id` is a retired Taira or Nexus alias instead of the canonical
/// first-release UUID.
pub fn reject_retired_public_chain_id(chain_id: &str) -> Result<()> {
    if RETIRED_PUBLIC_CHAIN_ID_ALIASES.contains(&chain_id) {
        return Err(eyre!(
            "retired public chain id alias `{chain_id}` is forbidden; select the canonical first-release network UUID"
        ));
    }
    Ok(())
}
/// Default canonical XOR asset id for public profiles where it is known.
///
/// # Errors
///
/// Returns an error if the built-in literal stops parsing as a canonical asset definition id.
pub fn default_public_xor_asset_definition_id(
    profile: GenesisProfile,
) -> Result<Option<AssetDefinitionId>> {
    match profile {
        GenesisProfile::Iroha3Taira => Ok(Some(
            AssetDefinitionId::parse_address_literal(TAIRA_XOR_ASSET_DEFINITION_ID)
                .map_err(|err| eyre!("built-in Taira XOR asset definition id is invalid: {err}"))?,
        )),
        GenesisProfile::Iroha3Nexus | GenesisProfile::Iroha3Dev => Ok(None),
    }
}
/// Resolve the canonical public XOR id selected for a profile run.
///
/// # Errors
///
/// Returns an error when a supplied literal is not canonical Base58, when a public Nexus `NPoS`
/// manifest omits the id, or when the flag is used for a non-public/non-NPoS manifest.
pub fn resolve_public_xor_asset_definition_id(
    profile: Option<GenesisProfile>,
    configured: Option<&str>,
    wants_npos: bool,
) -> Result<Option<AssetDefinitionId>> {
    let Some(profile) = profile else {
        if configured.is_some() {
            return Err(eyre!(
                "`--xor-asset-definition-id` is only supported with public Iroha3 profiles"
            ));
        }
        return Ok(None);
    };
    if !profile_uses_public_xor(profile) {
        if configured.is_some() {
            return Err(eyre!(
                "`--xor-asset-definition-id` applies only to iroha3-taira/iroha3-nexus profiles"
            ));
        }
        return Ok(None);
    }
    if !wants_npos {
        if configured.is_some() {
            return Err(eyre!(
                "`--xor-asset-definition-id` applies only to NPoS public-profile manifests"
            ));
        }
        return Ok(None);
    }
    if let Some(configured) = configured {
        let parsed = AssetDefinitionId::parse_address_literal(configured).map_err(|err| {
                eyre!(
                    "invalid --xor-asset-definition-id `{configured}`: {err}; expected canonical unprefixed Base58 asset definition id, not an alias such as `{PUBLIC_XOR_ALIAS}`"
                )
            })?;
        if profile == GenesisProfile::Iroha3Taira
            && parsed.to_string() != TAIRA_XOR_ASSET_DEFINITION_ID
        {
            return Err(eyre!(
                "public Taira XOR asset definition id is pinned to `{TAIRA_XOR_ASSET_DEFINITION_ID}`; found `{parsed}`"
            ));
        }
        if profile == GenesisProfile::Iroha3Nexus
            && parsed.to_string() == TAIRA_XOR_ASSET_DEFINITION_ID
        {
            return Err(eyre!(
                "public Nexus requires its operator-provisioned mainnet XOR definition; the Taira testnet asset is not a mainnet substitute"
            ));
        }
        return Ok(Some(parsed));
    }
    if let Some(default) = default_public_xor_asset_definition_id(profile)? {
        return Ok(Some(default));
    }
    Err(eyre!(
        "profile {profile:?} requires `--xor-asset-definition-id <BASE58>` so public XOR is bound to a real canonical asset definition"
    ))
}
/// Return the canonical I105 chain discriminant for well-known network ids.
#[must_use]
pub fn known_chain_discriminant_for_chain_id(chain_id: &str) -> Option<u16> {
    match chain_id {
        PUBLIC_TAIRA_CHAIN_ID => Some(TAIRA_CHAIN_DISCRIMINANT),
        PUBLIC_NEXUS_CHAIN_ID => Some(NEXUS_CHAIN_DISCRIMINANT),
        _ => None,
    }
}
/// Parse a hex-encoded VRF seed into the fixed 32-byte array required by `SumeragiNposParameters`.
///
/// # Errors
///
/// Returns an error when the input is not valid hex or does not represent exactly 32 bytes.
pub fn parse_vrf_seed_hex(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).map_err(|err| eyre!("invalid hex for VRF seed: {err}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| eyre!("VRF seed must be exactly 32 bytes (hex length 64)"))?;
    Ok(seed)
}
/// Derive a deterministic VRF seed from the provided chain identifier.
#[must_use]
pub fn derive_vrf_seed_from_chain(chain_id: &ChainId) -> [u8; 32] {
    let hash = Hash::new(chain_id.as_str());
    *hash.as_ref()
}
/// Resolve the VRF seed to use for the profile according to its policy and an optional override.
///
/// # Errors
///
/// Returns an error when the profile requires an explicit seed and none was provided.
pub fn resolve_vrf_seed(
    profile: GenesisProfile,
    chain_id: &ChainId,
    override_seed: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    match (profile_defaults(profile).seed_policy, override_seed) {
        (_, Some(seed)) => Ok(seed),
        (SeedPolicy::DerivedFromChain, None) => Ok(derive_vrf_seed_from_chain(chain_id)),
        (SeedPolicy::RequireExplicit, None) => Err(eyre!(
            "profile {profile:?} requires `--vrf-seed-hex` to supply a 32-byte VRF seed"
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_parser_accepts_only_canonical_spelling() {
        assert_eq!(
            "iroha3-dev".parse::<GenesisProfile>().unwrap(),
            GenesisProfile::Iroha3Dev
        );
        assert_eq!(
            "iroha3-taira".parse::<GenesisProfile>().unwrap(),
            GenesisProfile::Iroha3Taira
        );
        assert_eq!(
            "iroha3-nexus".parse::<GenesisProfile>().unwrap(),
            GenesisProfile::Iroha3Nexus
        );
        for invalid in ["dev", "taira", "IROHA3-TAIRA", " iroha3-dev"] {
            assert!(invalid.parse::<GenesisProfile>().is_err());
        }
    }
    #[test]
    fn profile_defaults_assign_expected_values() {
        let dev = profile_defaults(GenesisProfile::Iroha3Dev);
        assert_eq!(dev.chain_id, ChainId::from("iroha3-dev.local"));
        assert_eq!(dev.chain_discriminant, None);
        assert_eq!(dev.block_cadence_ms.get(), 100);
        assert_eq!(dev.min_peers, 4);
        let taira = profile_defaults(GenesisProfile::Iroha3Taira);
        assert_eq!(taira.chain_id, ChainId::from(PUBLIC_TAIRA_CHAIN_ID));
        assert_eq!(taira.chain_discriminant, Some(TAIRA_CHAIN_DISCRIMINANT));
        assert_eq!(taira.block_cadence_ms.get(), 4_000);
        assert_eq!(taira.min_peers, 4);
        let nexus = profile_defaults(GenesisProfile::Iroha3Nexus);
        assert_eq!(nexus.chain_id, ChainId::from(PUBLIC_NEXUS_CHAIN_ID));
        assert_eq!(nexus.chain_discriminant, Some(NEXUS_CHAIN_DISCRIMINANT));
        assert_eq!(nexus.block_cadence_ms.get(), 100);
        assert_eq!(nexus.min_peers, 4);
    }
    #[test]
    fn derived_seed_depends_on_chain_id() {
        let a = derive_vrf_seed_from_chain(&ChainId::from("chain-a"));
        let b = derive_vrf_seed_from_chain(&ChainId::from("chain-b"));
        assert_ne!(a, b, "seeds derived from different chains must differ");
    }
    #[test]
    fn require_explicit_seed_errors_without_override() {
        let err = resolve_vrf_seed(
            GenesisProfile::Iroha3Nexus,
            &ChainId::from(PUBLIC_NEXUS_CHAIN_ID),
            None,
        )
        .expect_err("explicit seed should be required for nexus");
        assert!(
            err.to_string().contains("vrf-seed-hex"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn resolve_prefers_override_when_provided() {
        let override_seed = [7u8; 32];
        let resolved = resolve_vrf_seed(
            GenesisProfile::Iroha3Dev,
            &ChainId::from("iroha3-dev.local"),
            Some(override_seed),
        )
        .expect("override should be accepted");
        assert_eq!(resolved, override_seed);
    }
    #[test]
    fn public_profiles_require_npos() {
        assert!(!profile_requires_npos(GenesisProfile::Iroha3Dev));
        assert!(profile_requires_npos(GenesisProfile::Iroha3Taira));
        assert!(profile_requires_npos(GenesisProfile::Iroha3Nexus));
    }
    #[test]
    fn public_xor_profiles_are_classified() {
        assert!(!profile_uses_public_xor(GenesisProfile::Iroha3Dev));
        assert!(profile_uses_public_xor(GenesisProfile::Iroha3Taira));
        assert!(profile_uses_public_xor(GenesisProfile::Iroha3Nexus));
        assert_eq!(
            public_xor_profile_for_chain_id(PUBLIC_TAIRA_CHAIN_ID),
            Some(GenesisProfile::Iroha3Taira)
        );
        assert_eq!(
            public_xor_profile_for_chain_id(PUBLIC_NEXUS_CHAIN_ID),
            Some(GenesisProfile::Iroha3Nexus)
        );
        assert_eq!(public_xor_profile_for_chain_id("iroha3-nexus"), None);
        assert_eq!(public_xor_profile_for_chain_id("cbdc16"), None);
    }
    #[test]
    fn public_xor_resolver_defaults_taira_and_requires_nexus() {
        let taira =
            resolve_public_xor_asset_definition_id(Some(GenesisProfile::Iroha3Taira), None, true)
                .expect("Taira should use built-in live XOR id")
                .expect("Taira should resolve an id");
        assert_eq!(taira.to_string(), TAIRA_XOR_ASSET_DEFINITION_ID);
        let err =
            resolve_public_xor_asset_definition_id(Some(GenesisProfile::Iroha3Nexus), None, true)
                .expect_err("Nexus must require an explicit XOR id");
        assert!(
            err.to_string().contains("--xor-asset-definition-id"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn public_xor_resolver_rejects_alias_literal() {
        let err = resolve_public_xor_asset_definition_id(
            Some(GenesisProfile::Iroha3Taira),
            Some(PUBLIC_XOR_ALIAS),
            true,
        )
        .expect_err("alias selector is not a canonical Base58 id");
        assert!(
            err.to_string()
                .contains("expected canonical unprefixed Base58"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn public_xor_resolver_rejects_a_substituted_taira_asset() {
        let err = resolve_public_xor_asset_definition_id(
            Some(GenesisProfile::Iroha3Taira),
            Some("61CtjvNd9T3THAR65GsMVHr82Bjc"),
            true,
        )
        .expect_err("Taira XOR identity must be pinned before first release");
        assert!(
            err.to_string().contains(TAIRA_XOR_ASSET_DEFINITION_ID),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn public_nexus_rejects_taira_xor_substitution() {
        let error = resolve_public_xor_asset_definition_id(
            Some(GenesisProfile::Iroha3Nexus),
            Some(TAIRA_XOR_ASSET_DEFINITION_ID),
            true,
        )
        .expect_err("testnet cannot stand in for mainnet XOR");
        assert!(error.to_string().contains("Taira"));
    }
    #[test]
    fn known_chain_discriminant_maps_taira_and_nexus() {
        assert_eq!(
            known_chain_discriminant_for_chain_id(PUBLIC_TAIRA_CHAIN_ID),
            Some(TAIRA_CHAIN_DISCRIMINANT)
        );
        assert_eq!(known_chain_discriminant_for_chain_id("iroha3-taira"), None);
        assert_eq!(
            known_chain_discriminant_for_chain_id(PUBLIC_NEXUS_CHAIN_ID),
            Some(NEXUS_CHAIN_DISCRIMINANT)
        );
        assert_eq!(known_chain_discriminant_for_chain_id("iroha3-nexus"), None);
        assert_eq!(known_chain_discriminant_for_chain_id("cbdc16"), None);
        assert_eq!(known_chain_discriminant_for_chain_id("unknown"), None);
    }
    #[test]
    fn retired_public_chain_aliases_are_rejected() {
        for alias in RETIRED_PUBLIC_CHAIN_ID_ALIASES {
            let error = reject_retired_public_chain_id(alias).expect_err("alias must be retired");
            assert!(error.to_string().contains("forbidden"));
        }
        reject_retired_public_chain_id(PUBLIC_TAIRA_CHAIN_ID).expect("canonical Taira id");
        reject_retired_public_chain_id(PUBLIC_NEXUS_CHAIN_ID).expect("canonical Nexus id");
    }
}
