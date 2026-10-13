//! Independently installed release authorities and retrieval locations, with no network defaults.

use std::{collections::BTreeMap, path::Path};

use iroha_crypto::PublicKey;
use norito::{Decode, Encode};
use url::Url;

use super::{BootstrapError, ReleaseTrust, Result, decode};

/// Canonical native bundle filename containing independently installed network profiles.
pub const NETWORK_PROFILES_FILENAME: &str = "network-profiles.nrt";
/// Maximum profiles in one authenticated installation artifact.
pub const MAX_INSTALLED_NETWORK_PROFILES: usize = 32;
/// Maximum canonical installation artifact before decoding or retaining it.
pub const MAX_INSTALLED_PROFILE_BYTES: usize = 128 * 1024;
const MAX_CHECKPOINT_URL_BYTES: usize = 2048;

/// One installed network selection; responses never choose its release key or checkpoint URL.
#[derive(Clone, Debug)]
pub struct InstalledNetworkProfile {
    trust: ReleaseTrust,
    checkpoint_url: Url,
}

impl InstalledNetworkProfile {
    /// Install one independently authenticated release key, serial floor and canonical HTTPS URL.
    /// This constructor grants no trust to an HTTP response or a key included in one.
    ///
    /// # Errors
    /// Invalid network label, authority, rollback floor, credentials, noncanonical URL or bounds.
    pub fn new(
        network_name: String,
        public_key: PublicKey,
        minimum_serial: u64,
        checkpoint_url: &str,
    ) -> Result<Self> {
        let trust = ReleaseTrust::new(network_name, public_key, minimum_serial)?;
        if checkpoint_url.len() > MAX_CHECKPOINT_URL_BYTES {
            return Err(BootstrapError::Invalid(
                "installed checkpoint URL exceeds byte bound",
            ));
        }
        let url = Url::parse(checkpoint_url)
            .map_err(|_| BootstrapError::Invalid("invalid installed checkpoint URL"))?;
        if url.as_str() != checkpoint_url
            || url.scheme() != "https"
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(BootstrapError::Invalid(
                "installed checkpoint URL must be canonical credential-free HTTPS",
            ));
        }
        Ok(Self {
            trust,
            checkpoint_url: url,
        })
    }

    /// Exact installed CLI selection, without an inferred official-network fallback.
    pub fn network_name(&self) -> &str {
        &self.trust.network_name
    }

    /// Independently selected verification authority and rollback floor.
    pub fn release_trust(&self) -> &ReleaseTrust {
        &self.trust
    }

    /// Exact independently installed release authority; endpoints cannot replace this key.
    pub fn release_public_key(&self) -> &PublicKey {
        &self.trust.public_key
    }

    /// Installation's minimum accepted release serial, independent of retained release custody.
    pub const fn minimum_serial(&self) -> u64 {
        self.trust.minimum_serial
    }

    /// Exact approved retrieval location; redirects cannot replace it.
    pub fn checkpoint_url(&self) -> &Url {
        &self.checkpoint_url
    }

    fn record(&self) -> ProfileRecord {
        ProfileRecord {
            network_name: self.trust.network_name.clone(),
            public_key: self.trust.public_key.clone(),
            minimum_serial: self.trust.minimum_serial,
            checkpoint_url: self.checkpoint_url.to_string(),
        }
    }
}

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::InstalledNetworkProfileV1")]
struct ProfileRecord {
    network_name: String,
    public_key: PublicKey,
    minimum_serial: u64,
    checkpoint_url: String,
}

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::InstalledNetworkProfilesV1")]
struct ProfileRecords {
    profiles: Vec<ProfileRecord>,
}

/// Bounded, exactly named profiles supplied by an authenticated native installation.
/// An empty set is valid: no official Taira authority or URL is invented by this library.
#[derive(Clone, Debug)]
pub struct InstalledNetworkProfiles {
    profiles: BTreeMap<String, InstalledNetworkProfile>,
}

impl InstalledNetworkProfiles {
    /// Construct an installation set from independent explicit profile inputs.
    ///
    /// # Errors
    /// More than the finite profile count or a duplicate network selection.
    pub fn new(profiles: Vec<InstalledNetworkProfile>) -> Result<Self> {
        if profiles.len() > MAX_INSTALLED_NETWORK_PROFILES {
            return Err(BootstrapError::Invalid(
                "installed network profile count exceeds bound",
            ));
        }
        let mut selected = BTreeMap::new();
        for profile in profiles {
            if selected
                .insert(profile.network_name().to_owned(), profile)
                .is_some()
            {
                return Err(BootstrapError::Invalid(
                    "duplicate installed network profile",
                ));
            }
        }
        Ok(Self { profiles: selected })
    }

    /// Decode bytes already authenticated by installation custody, never bytes downloaded as a response.
    ///
    /// # Errors
    /// Noncanonical, unsorted, duplicate, oversized or invalid installation profiles.
    pub fn from_installation_bytes(bytes: &[u8]) -> Result<Self> {
        let records: ProfileRecords = decode(bytes, MAX_INSTALLED_PROFILE_BYTES)?;
        if records.profiles.len() > MAX_INSTALLED_NETWORK_PROFILES
            || records
                .profiles
                .windows(2)
                .any(|pair| pair[0].network_name >= pair[1].network_name)
        {
            return Err(BootstrapError::Invalid(
                "installed profiles must be bounded and strictly ordered",
            ));
        }
        Self::new(
            records
                .profiles
                .into_iter()
                .map(|record| {
                    InstalledNetworkProfile::new(
                        record.network_name,
                        record.public_key,
                        record.minimum_serial,
                        &record.checkpoint_url,
                    )
                })
                .collect::<Result<_>>()?,
        )
    }

    /// Load a current-user or operating-system-owned installation through retained no-follow custody.
    /// Foreign-writable files, unsafe ancestry, links and reparse points are refused.
    /// The caller must have independently authenticated the installation that supplied it.
    ///
    /// # Errors
    /// Missing or unsafe filesystem custody, bounded read failure or malformed profiles.
    pub fn load(path: &Path) -> Result<Self> {
        Self::from_installation_bytes(&iroha_fs::read_regular(path, MAX_INSTALLED_PROFILE_BYTES)?)
    }

    /// Encode the sole first-release bundle layout in deterministic selection order.
    ///
    /// # Errors
    /// The canonical record exceeds the same bounded decoder used on installation.
    pub fn encode_installation(&self) -> Result<Vec<u8>> {
        let records = ProfileRecords {
            profiles: self
                .profiles
                .values()
                .map(InstalledNetworkProfile::record)
                .collect(),
        };
        let bytes = norito::encode_canonical(&records)
            .map_err(|_| BootstrapError::Invalid("cannot encode installed network profiles"))?;
        Self::from_installation_bytes(&bytes)?;
        Ok(bytes)
    }

    /// Installed network choices in canonical order, for CLI and desktop selection.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }

    /// Select an exact installed name; unknown networks never fall back to another trust root.
    ///
    /// # Errors
    /// The requested selection is absent from this installation.
    pub fn select(&self, network_name: &str) -> Result<&InstalledNetworkProfile> {
        self.profiles
            .get(network_name)
            .ok_or(BootstrapError::Invalid(
                "selected network has no installed release profile",
            ))
    }
}

#[cfg(test)]
mod tests;
