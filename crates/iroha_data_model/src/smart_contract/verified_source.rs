//! Consensus-owned source inventory and native compilation receipt.
//!
//! A receipt is a state value, never a source-publisher attestation or an accepted instruction
//! argument. Native execution creates it only after compiling this exact inventory and joining
//! the output to the already admitted artifact. Read operations borrow the authenticated value.
//!
//! TODO: Register this sole first-release model with the native source instruction and World
//! storage after the coordinated dependency freeze. No unsigned local-record decoder remains.

use iroha_crypto::Hash;
use iroha_schema::IntoSchema;
use norito::{Decode, Encode};

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId, account::AccountId,
    smart_contract::ContractArtifactId,
};

/// Inclusive number of original source files and imported artifacts in one registration.
pub const MAX_SOURCE_FILES: usize = 512;
/// Inclusive UTF-8 bytes in one original source file.
pub const MAX_SOURCE_FILE_BYTES: usize = 1024 * 1024;
/// Inclusive aggregate source text and imported artifact bytes in one registration.
pub const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
/// Inclusive UTF-8 bytes in one portable source path or locked package identity.
pub const MAX_SOURCE_IDENTITY_BYTES: usize = 4096;
/// Inclusive aggregate original path, package, import and export identity bytes.
///
/// This bounds metadata independently of source text. Native decode and compilation still
/// require actual allocation admission; this protocol byte limit grants no heap capacity.
pub const MAX_SOURCE_METADATA_BYTES: usize = MAX_SOURCE_BYTES;
const INVENTORY_DOMAIN: &[u8] = b"iroha.contract.native-source-inventory.v1\0";

/// Exact original source file; compilation performs no filesystem resolution.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ContractSourceFile {
    /// Portable path relative to this source inventory.
    pub source_name: String,
    /// Original bounded UTF-8 text.
    pub source_text: String,
}

/// Exact compiled contract interface input, owned by its source inventory or locked package.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ContractSourceArtifact {
    /// Canonical relative `.to` path resolved only within this inventory owner.
    pub source_name: String,
    /// Complete immutable compiled artifact, authenticated and admitted by the compiler.
    pub artifact: Vec<u8>,
}

/// Exact immutable locked-package binding, with no endpoint-selected resolution.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ContractSourceImport {
    /// Source-visible package alias.
    pub alias: String,
    /// Exact locked package identity.
    pub package: String,
}

/// Complete original files of one explicitly supplied locked package.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ContractSourcePackage {
    /// Exact locked identity.
    pub identity: String,
    /// Original module entry files, sorted by path.
    pub modules: Vec<ContractSourceFile>,
    /// Original companion files, sorted by path.
    pub sources: Vec<ContractSourceFile>,
    /// Exact imported compiled artifacts, strictly sorted by their owner-relative paths.
    pub artifacts: Vec<ContractSourceArtifact>,
    /// Exact exported names, strictly sorted.
    pub exports: Vec<String>,
    /// Exact import bindings, strictly sorted by alias and package.
    pub imports: Vec<ContractSourceImport>,
}

/// Sole explicit Kotodama source inventory accepted by native registration.
///
/// Every supplied file is authenticated, including an unused companion. The compiler may
/// select its semantic closure, but cannot replace the receipt's original inventory identity.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ContractSourceInventory {
    /// Original root source and its required portable identity.
    pub root: ContractSourceFile,
    /// Original root companions, strictly sorted by path.
    pub sources: Vec<ContractSourceFile>,
    /// Exact root-owned compiled artifacts, strictly sorted by path.
    pub artifacts: Vec<ContractSourceArtifact>,
    /// Exact root import bindings, strictly sorted by alias and package.
    pub imports: Vec<ContractSourceImport>,
    /// Complete locked package inventories, strictly sorted by identity.
    pub packages: Vec<ContractSourcePackage>,
}

/// Native structural rejection before compiler work or state mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceInventoryError {
    /// Empty, unsafe, noncanonical or oversized original identity.
    Identity,
    /// A repeated or unordered original identity makes the inventory ambiguous.
    Order,
    /// Original source count or byte demand exceeds the native protocol bound.
    Capacity,
}
impl std::fmt::Display for SourceInventoryError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Identity => "invalid native contract source identity",
            Self::Order => "native contract source inventory is not strictly canonical",
            Self::Capacity => "native contract source inventory exceeds its protocol bound",
        })
    }
}
impl std::error::Error for SourceInventoryError {}

fn identity(value: &str) -> Result<(), SourceInventoryError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTITY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(SourceInventoryError::Identity);
    }
    Ok(())
}
fn path(value: &str) -> Result<(), SourceInventoryError> {
    identity(value)?;
    if value.contains(['\\', ':'])
        || value
            .split('/')
            .any(|part| part.is_empty() || part.chars().all(|character| character == '.'))
    {
        return Err(SourceInventoryError::Identity);
    }
    Ok(())
}
fn imports(values: &[ContractSourceImport]) -> Result<(), SourceInventoryError> {
    for value in values {
        identity(&value.alias)?;
        identity(&value.package)?;
    }
    if values.windows(2).any(|pair| pair[0].alias >= pair[1].alias) {
        return Err(SourceInventoryError::Order);
    }
    Ok(())
}
fn files(values: &[ContractSourceFile]) -> Result<(), SourceInventoryError> {
    if values
        .windows(2)
        .any(|pair| pair[0].source_name >= pair[1].source_name)
    {
        return Err(SourceInventoryError::Order);
    }
    for file in values {
        path(&file.source_name)?;
    }
    Ok(())
}
fn artifacts(
    values: &[ContractSourceArtifact],
    files: impl Iterator<Item = impl AsRef<str>>,
) -> Result<(), SourceInventoryError> {
    if values
        .windows(2)
        .any(|pair| pair[0].source_name >= pair[1].source_name)
    {
        return Err(SourceInventoryError::Order);
    }
    for artifact in values {
        path(&artifact.source_name)?;
        if !artifact.source_name.ends_with(".to") || artifact.artifact.is_empty() {
            return Err(SourceInventoryError::Identity);
        }
    }
    for file in files {
        if values
            .binary_search_by(|artifact| artifact.source_name.as_str().cmp(file.as_ref()))
            .is_ok()
        {
            return Err(SourceInventoryError::Order);
        }
    }
    Ok(())
}
impl ContractSourceInventory {
    /// Validate the exact complete original inventory without allocating lookup collections.
    /// Compiler semantic/token/AST admission remains a separate native execution obligation.
    ///
    /// # Errors
    /// Rejects ambiguous identities, unsafe original paths and original input overflow.
    pub fn validate(&self) -> Result<(), SourceInventoryError> {
        path(&self.root.source_name)?;
        files(&self.sources)?;
        artifacts(
            &self.artifacts,
            std::iter::once(self.root.source_name.as_str())
                .chain(self.sources.iter().map(|file| file.source_name.as_str())),
        )?;
        imports(&self.imports)?;
        if self.packages.len() > MAX_SOURCE_FILES {
            return Err(SourceInventoryError::Capacity);
        }
        if self
            .sources
            .iter()
            .any(|file| file.source_name == self.root.source_name)
            || self
                .packages
                .windows(2)
                .any(|pair| pair[0].identity >= pair[1].identity)
        {
            return Err(SourceInventoryError::Order);
        }
        for package in &self.packages {
            identity(&package.identity)?;
            if package.modules.is_empty() {
                return Err(SourceInventoryError::Identity);
            }
            files(&package.modules)?;
            files(&package.sources)?;
            artifacts(
                &package.artifacts,
                package
                    .modules
                    .iter()
                    .chain(&package.sources)
                    .map(|file| file.source_name.as_str()),
            )?;
            imports(&package.imports)?;
            for export in &package.exports {
                identity(export)?;
            }
            if package.exports.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SourceInventoryError::Order);
            }
            for module in &package.modules {
                if package
                    .sources
                    .binary_search_by(|source| source.source_name.cmp(&module.source_name))
                    .is_ok()
                {
                    return Err(SourceInventoryError::Order);
                }
            }
        }
        let mut count = 0usize;
        let mut bytes = 0usize;
        for file in self.files() {
            count = count.checked_add(1).ok_or(SourceInventoryError::Capacity)?;
            bytes = bytes
                .checked_add(file.source_text.len())
                .ok_or(SourceInventoryError::Capacity)?;
            if file.source_text.len() > MAX_SOURCE_FILE_BYTES
                || count > MAX_SOURCE_FILES
                || bytes > MAX_SOURCE_BYTES
            {
                return Err(SourceInventoryError::Capacity);
            }
        }
        for artifact in self.artifacts() {
            count = count.checked_add(1).ok_or(SourceInventoryError::Capacity)?;
            bytes = bytes
                .checked_add(artifact.artifact.len())
                .ok_or(SourceInventoryError::Capacity)?;
            if count > MAX_SOURCE_FILES || bytes > MAX_SOURCE_BYTES {
                return Err(SourceInventoryError::Capacity);
            }
        }
        let mut metadata_bytes = 0usize;
        for value in self.identities() {
            metadata_bytes = metadata_bytes
                .checked_add(value.len())
                .ok_or(SourceInventoryError::Capacity)?;
            if metadata_bytes > MAX_SOURCE_METADATA_BYTES {
                return Err(SourceInventoryError::Capacity);
            }
        }
        Ok(())
    }

    /// Borrow every exact original file, including all locked packages.
    pub fn files(&self) -> impl Iterator<Item = &ContractSourceFile> {
        std::iter::once(&self.root).chain(&self.sources).chain(
            self.packages
                .iter()
                .flat_map(|package| package.modules.iter().chain(&package.sources)),
        )
    }

    /// Borrow the complete original compiled artifact inventory, including locked packages.
    pub fn artifacts(&self) -> impl Iterator<Item = &ContractSourceArtifact> {
        self.artifacts
            .iter()
            .chain(self.packages.iter().flat_map(|package| &package.artifacts))
    }

    fn identities(&self) -> impl Iterator<Item = &str> {
        self.files()
            .map(|file| file.source_name.as_str())
            .chain(
                self.artifacts()
                    .map(|artifact| artifact.source_name.as_str()),
            )
            .chain(
                self.imports
                    .iter()
                    .flat_map(|binding| [binding.alias.as_str(), binding.package.as_str()]),
            )
            .chain(self.packages.iter().flat_map(|package| {
                std::iter::once(package.identity.as_str())
                    .chain(package.exports.iter().map(String::as_str))
                    .chain(
                        package
                            .imports
                            .iter()
                            .flat_map(|binding| [binding.alias.as_str(), binding.package.as_str()]),
                    )
            }))
    }

    /// Hash the sole native canonical frame directly into the domain-separated hasher.
    ///
    /// # Errors
    /// Rejects noncanonical original inventory or native frame encoding failure.
    pub fn commitment(&self) -> Result<Hash, std::io::Error> {
        self.validate().map_err(std::io::Error::other)?;
        Hash::new_from_writer(|out| {
            out.write_all(INVENTORY_DOMAIN)?;
            norito::core::write_canonical_to_writer(self, out).map_err(std::io::Error::other)
        })
    }
}

/// Immutable consensus state resulting from successful native compilation.
///
/// This value has no registration instruction accepting a caller-provided receipt. Its
/// authority comes from the finalized World transition that constructs it from actual native
/// compilation, never from the registrar's signature over a compilation assertion.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct NativeCompilationReceipt {
    /// Signed genesis identity of the execution network.
    pub network_id: NetworkId,
    /// Exact dataspace and canonical complete artifact hash.
    pub artifact_id: ContractArtifactId,
    /// Domain-separated commitment to all original source identities and contents.
    pub source_inventory_hash: Hash,
    /// Domain-separated commitment to the exact admitted native manifest and its provenance.
    pub manifest_hash: Hash,
    /// Native artifact verifier's ABI identity.
    pub abi_hash: Hash,
    /// Exact native compiler identity verified from the compiled artifact.
    pub compiler_fingerprint: String,
    /// Registered transaction authority that submitted this exact inventory.
    pub registrar: AccountId,
    /// Exact accepted registration transaction commitment.
    pub registration_transaction: Hash,
    /// Consensus block height of the accepted registration.
    pub registration_height: u64,
}

/// Complete immutable source value borrowed by authenticated contract inspection.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct NativeCompiledSourceRecord {
    /// Native execution result authenticated by World state and finality.
    pub receipt: NativeCompilationReceipt,
    /// Exact original input retained for developer inspection and reproducibility.
    pub inventory: ContractSourceInventory,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> ContractSourceInventory {
        ContractSourceInventory {
            artifacts: Vec::new(),
            root: ContractSourceFile {
                source_name: "main.ko".into(),
                source_text: "seiyaku Source { view fn value() -> int { return 7; } }".into(),
            },
            sources: vec![ContractSourceFile {
                source_name: "unused.ko".into(),
                source_text: "module Unused {}".into(),
            }],
            imports: vec![ContractSourceImport {
                alias: "locked".into(),
                package: "package@exact".into(),
            }],
            packages: vec![ContractSourcePackage {
                artifacts: Vec::new(),
                identity: "package@exact".into(),
                modules: vec![ContractSourceFile {
                    source_name: "lib.ko".into(),
                    source_text: "module Locked {}".into(),
                }],
                sources: Vec::new(),
                exports: Vec::new(),
                imports: Vec::new(),
            }],
        }
    }

    #[test]
    fn commitment_authenticates_original_files_and_locked_inventory() {
        let input = inventory();
        let expected = input.commitment().unwrap();
        assert_eq!(input.clone().commitment().unwrap(), expected);
        for changed in [
            {
                let mut changed = input.clone();
                changed.sources[0].source_text.push(' ');
                changed
            },
            {
                let mut changed = input.clone();
                changed.packages[0].modules[0].source_text.push(' ');
                changed
            },
            {
                let mut changed = input.clone();
                changed.root.source_name = "renamed.ko".into();
                changed
            },
            {
                let mut changed = input.clone();
                changed.imports[0].package = "package@substituted".into();
                changed
            },
        ] {
            assert_ne!(changed.commitment().unwrap(), expected);
        }
    }

    #[test]
    fn exact_wire_rejects_extra_receipt_and_ambiguous_inventory() {
        let input = inventory();
        let bytes = norito::json::to_json(&input).unwrap();
        assert_eq!(
            norito::json::from_slice::<ContractSourceInventory>(bytes.as_bytes()).unwrap(),
            input
        );
        let frame = norito::to_bytes(&input).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<ContractSourceInventory>(&frame).unwrap(),
            input
        );
        let mut value: norito::json::Value = norito::json::from_str(&bytes).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("receipt".into(), norito::json::Value::Null);
        assert!(norito::json::from_value::<ContractSourceInventory>(value).is_err());
        let mut duplicate = input.clone();
        duplicate.sources.push(duplicate.root.clone());
        assert_eq!(duplicate.validate(), Err(SourceInventoryError::Order));
        let mut package_duplicate = input.clone();
        package_duplicate.packages[0].sources = package_duplicate.packages[0].modules.clone();
        assert_eq!(
            package_duplicate.validate(),
            Err(SourceInventoryError::Order)
        );
        for invalid in [
            "/absolute.ko",
            "../parent.ko",
            "parts//empty.ko",
            "parts\\platform.ko",
            "C:platform.ko",
            "parts/.../invalid.ko",
        ] {
            let mut changed = input.clone();
            changed.root.source_name = invalid.into();
            assert_eq!(changed.validate(), Err(SourceInventoryError::Identity));
        }
    }

    #[test]
    fn imported_artifacts_are_owner_bound_canonical_and_counted() {
        let mut input = inventory();
        let empty = input.commitment().unwrap();
        input.artifacts.push(ContractSourceArtifact {
            source_name: "interfaces/pool.to".into(),
            artifact: vec![1, 2, 3],
        });
        let root_owned = input.commitment().unwrap();
        assert_ne!(root_owned, empty);
        input.artifacts[0].artifact[0] = 4;
        assert_ne!(input.commitment().unwrap(), root_owned);
        input.artifacts[0].artifact[0] = 1;
        input.packages[0].artifacts = std::mem::take(&mut input.artifacts);
        assert_ne!(input.commitment().unwrap(), root_owned);
        assert_eq!(input.artifacts().count(), 1);
        let frame = norito::encode_canonical(&input).unwrap();
        assert_eq!(
            norito::decode_canonical::<ContractSourceInventory>(&frame).unwrap(),
            input
        );
        for invalid in ["../pool.to", "pool.ko", "/pool.to", "pool\\other.to"] {
            let mut changed = input.clone();
            changed.packages[0].artifacts[0].source_name = invalid.into();
            assert_eq!(changed.validate(), Err(SourceInventoryError::Identity));
        }
        let mut duplicate = input.clone();
        let same = duplicate.packages[0].artifacts[0].clone();
        duplicate.packages[0].artifacts.push(same);
        assert_eq!(duplicate.validate(), Err(SourceInventoryError::Order));
        input.packages[0].artifacts[0]
            .artifact
            .resize(MAX_SOURCE_BYTES, 0);
        assert_eq!(input.validate(), Err(SourceInventoryError::Capacity));
        input.packages[0].artifacts[0].artifact.clear();
        assert_eq!(input.validate(), Err(SourceInventoryError::Identity));
        let mut count = inventory();
        count.artifacts = (0..MAX_SOURCE_FILES)
            .map(|index| ContractSourceArtifact {
                source_name: format!("{index:04}.to"),
                artifact: vec![1],
            })
            .collect();
        assert_eq!(count.validate(), Err(SourceInventoryError::Capacity));
    }

    #[test]
    fn original_file_limit_refuses_before_commitment() {
        let mut input = inventory();
        input.root.source_text = " ".repeat(MAX_SOURCE_FILE_BYTES);
        input.validate().unwrap();
        input.root.source_text.push(' ');
        assert_eq!(input.validate(), Err(SourceInventoryError::Capacity));
        assert!(input.commitment().is_err());
    }

    #[test]
    fn metadata_is_bounded_even_when_original_source_text_is_small() {
        let mut input = inventory();
        // The source-text corridor alone cannot bound many large locked import identities.
        // These are canonical and individually valid; the aggregate metadata corridor refuses.
        input.imports = (0..2048)
            .map(|index| ContractSourceImport {
                alias: format!("{index:04}{}", "a".repeat(MAX_SOURCE_IDENTITY_BYTES - 4)),
                package: "p".repeat(MAX_SOURCE_IDENTITY_BYTES),
            })
            .collect();
        assert_eq!(input.validate(), Err(SourceInventoryError::Capacity));
        assert!(input.commitment().is_err());
    }

    #[test]
    fn empty_or_excess_locked_packages_cannot_bypass_original_file_count() {
        let mut input = inventory();
        input.packages[0].modules.clear();
        assert_eq!(input.validate(), Err(SourceInventoryError::Identity));
        input.packages = (0..=MAX_SOURCE_FILES)
            .map(|index| ContractSourcePackage {
                artifacts: Vec::new(),
                identity: format!("package{index:04}"),
                modules: Vec::new(),
                sources: Vec::new(),
                exports: Vec::new(),
                imports: Vec::new(),
            })
            .collect();
        assert_eq!(input.validate(), Err(SourceInventoryError::Capacity));
    }
}
