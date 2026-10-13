//! Thin operator surface for canonical shared native developer-network release production.

use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Args, Subcommand};
use color_eyre::eyre::{WrapErr as _, eyre};
use iroha_crypto::{ExposedPrivateKey, KeyPair, PublicKey};
use iroha_data_model::{
    AccountId, AssetDefinitionId, NetworkId, account::address::ChainDiscriminantGuard,
    sumeragi_finality::SumeragiFinalityProof,
};
use iroha_deploy::{
    bootstrap::{
        NetworkPublicationPolicy, PinnedPublicationGenesis, ReleaseBuildRegistry, ReleaseFaucet,
        ReleasePeer, prepare_network_publication,
    },
    verify::finality::{MAX_ADVANCE_BYTES, MAX_ADVANCE_PROOFS},
};
use iroha_genesis::RawGenesisTransaction;
use norito::json::{self, Map, Value};
use zeroize::Zeroizing;

use crate::{Outcome, RunArgs};

/// Offline operator commands for independently signed developer-network releases.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify pinned genesis/proofs and atomically prepare canonical public release artifacts
    Prepare(PrepareArgs),
}

/// Explicit independently authenticated inputs and finite publication policy.
#[derive(Clone, Debug, Args)]
pub struct PrepareArgs {
    /// Exact manifest semantically bound to the independently authenticated signed genesis.
    #[arg(long)]
    genesis_manifest: PathBuf,
    /// Manifest SHA256 authenticated independently, for example by native public-inputs metadata.
    #[arg(long, value_parser = parse_manifest_sha256)]
    expected_genesis_manifest_sha256: [u8; 32],
    /// Original canonical signed genesis, selected independently of peer responses.
    #[arg(long)]
    signed_genesis: PathBuf,
    /// Independently selected public key that must authenticate the complete genesis.
    #[arg(long)]
    genesis_public_key: PublicKey,
    /// Independently selected exact genesis-derived network identity.
    #[arg(long)]
    expected_network_id: NetworkId,
    /// Existing typed finality-proof JSON, repeated in contiguous height order from 1 through N.
    #[arg(long, required = true)]
    proof_json: Vec<PathBuf>,
    /// Exact installed network selection; no official label is inferred.
    #[arg(long)]
    network_name: String,
    /// Official monotonic publication serial and resulting installation rollback floor.
    #[arg(long)]
    serial: u64,
    /// Explicit monotonic reset generation for this signed genesis.
    #[arg(long)]
    generation: u64,
    /// Inclusive release validity start in Unix milliseconds.
    #[arg(long)]
    issued_at_ms: u64,
    /// Exclusive expiry; native policy caps validity at one day.
    #[arg(long)]
    expires_at_ms: u64,
    /// Approved canonical HTTPS parent root; repeat for each selected root.
    #[arg(long, required = true)]
    torii_root: Vec<String>,
    /// Exact BLS public key and approved root as PUBLIC_KEY=HTTPS_ROOT; repeat for every member.
    #[arg(long, required = true)]
    peer: Vec<String>,
    /// Independently selected canonical HTTPS location where checkpoint.nrt will be published.
    #[arg(long)]
    checkpoint_url: String,
    /// Independently selected release public key; must match the native signing file.
    #[arg(long)]
    release_public_key: PublicKey,
    /// Absolute native owner-only canonical release signing-key file (mode 0400 or 0600).
    #[arg(long)]
    release_key_file: PathBuf,
    /// Optional approved testnet faucet root; all allowance fields must be supplied together.
    #[arg(long, requires_all = ["faucet_issuer", "faucet_asset", "faucet_amount", "max_operation_fee", "max_namespace_rent"])]
    faucet_root: Option<String>,
    /// Independently authenticated single-key faucet issuer.
    #[arg(long, requires = "faucet_root")]
    faucet_issuer: Option<String>,
    /// Exact sole currency available for automatic fees and namespace rent.
    #[arg(long, requires = "faucet_root")]
    faucet_asset: Option<String>,
    /// Positive allowance supplied by one testnet faucet claim.
    #[arg(long, requires = "faucet_root")]
    faucet_amount: Option<String>,
    /// Finite maximum aggregate fees for one managed parent operation.
    #[arg(long, requires = "faucet_root")]
    max_operation_fee: Option<String>,
    /// Finite maximum combined dataspace and owner-alias one-year namespace rent.
    #[arg(long, requires = "faucet_root")]
    max_namespace_rent: Option<String>,
    /// Optional approved parent build-registry root; repeat for selected roots.
    #[arg(long)]
    build_registry_root: Vec<String>,
    /// Fresh directory beneath an existing safe owner-held parent; outputs publish together.
    #[arg(long)]
    output_dir: PathBuf,
}

impl<T: Write> RunArgs<T> for Command {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let Self::Prepare(args) = self;
        let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let receipt = args.prepare(now_ms)?;
        writeln!(writer, "{}", json::to_json_bounded(&receipt, 16 * 1024)?)?;
        Ok(())
    }
}

impl PrepareArgs {
    fn prepare(self, now_ms: u64) -> color_eyre::Result<Value> {
        if !(2..=MAX_ADVANCE_PROOFS + 1).contains(&self.proof_json.len()) {
            return Err(eyre!(
                "supply a bounded contiguous genesis-through-successor proof prefix"
            ));
        }
        if !self.release_key_file.is_absolute() {
            return Err(eyre!("release signing-key path must be absolute"));
        }
        let output = crate::atomic_output::resolve_output_file(&self.output_dir)?;
        if output.exists() {
            return Err(eyre!("publication output directory must be fresh"));
        }
        for input in std::iter::once(&self.release_key_file)
            .chain([&self.genesis_manifest, &self.signed_genesis])
            .chain(self.proof_json.iter())
        {
            let input = input
                .canonicalize()
                .wrap_err("resolve retained publication input")?;
            if input == output || input.starts_with(&output) {
                return Err(eyre!(
                    "publication output must not overlap a retained input"
                ));
            }
        }
        let manifest_bytes = iroha_genesis::read_genesis_manifest_bytes(&self.genesis_manifest)?;
        if iroha_crypto::sha256(&manifest_bytes) != self.expected_genesis_manifest_sha256 {
            return Err(eyre!(
                "genesis manifest differs from independently authenticated SHA256 pin"
            ));
        }
        let manifest = RawGenesisTransaction::from_json_slice(&manifest_bytes)?;
        let _profile = ChainDiscriminantGuard::enter(manifest.chain_discriminant());
        let signed_genesis = iroha_genesis::read_signed_genesis_bytes(&self.signed_genesis)?;
        let proofs = read_proofs(&self.proof_json)?;
        let signer = release_signer(&self.release_key_file)?;
        let faucet = self
            .faucet_root
            .map(|torii_root| -> color_eyre::Result<_> {
                Ok(ReleaseFaucet {
                    torii_root,
                    issuer: AccountId::parse_encoded(
                        self.faucet_issuer
                            .as_deref()
                            .ok_or_else(|| eyre!("faucet issuer missing"))?,
                    )?,
                    asset_definition_id: AssetDefinitionId::parse_address_literal(
                        self.faucet_asset
                            .as_deref()
                            .ok_or_else(|| eyre!("faucet asset missing"))?,
                    )?,
                    amount: self
                        .faucet_amount
                        .as_deref()
                        .ok_or_else(|| eyre!("faucet amount missing"))?
                        .parse()?,
                    max_operation_fee: self
                        .max_operation_fee
                        .as_deref()
                        .ok_or_else(|| eyre!("operation fee cap missing"))?
                        .parse()?,
                    max_namespace_rent: self
                        .max_namespace_rent
                        .as_deref()
                        .ok_or_else(|| eyre!("namespace rent cap missing"))?
                        .parse()?,
                })
            })
            .transpose()?;
        let peers = self
            .peer
            .iter()
            .map(|binding| {
                let (key, root) = binding
                    .split_once('=')
                    .ok_or_else(|| eyre!("peer binding must be PUBLIC_KEY=HTTPS_ROOT"))?;
                Ok(ReleasePeer {
                    node_id: iroha_model_base::peer::PeerId::new(key.parse()?),
                    torii_root: root.into(),
                })
            })
            .collect::<color_eyre::Result<Vec<_>>>()?;
        let policy = NetworkPublicationPolicy {
            network_name: self.network_name,
            serial: self.serial,
            generation: self.generation,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            torii_roots: self.torii_root,
            peers,
            faucet,
            build_registry: (!self.build_registry_root.is_empty()).then_some(
                ReleaseBuildRegistry {
                    torii_roots: self.build_registry_root,
                },
            ),
            checkpoint_url: self.checkpoint_url.clone(),
            release_public_key: self.release_public_key,
        };
        let prepared = prepare_network_publication(
            PinnedPublicationGenesis {
                signed_genesis: &signed_genesis,
                manifest_json: &manifest_bytes,
                expected_manifest_sha256: self.expected_genesis_manifest_sha256,
                genesis_public_key: &self.genesis_public_key,
                expected_network: self.expected_network_id,
            },
            &proofs,
            policy,
            &signer,
            now_ms,
        )?;
        let parent = iroha_fs::OwnerDirectory::open(
            output
                .parent()
                .ok_or_else(|| eyre!("publication output has no parent"))?,
        )?;
        parent
            .publish_private_child(
                output
                    .file_name()
                    .ok_or_else(|| eyre!("publication output has no name"))?,
                &[
                    ("checkpoint.nrt", prepared.checkpoint_bytes.as_slice()),
                    ("network-profiles.nrt", prepared.profile_bytes.as_slice()),
                ],
            )
            .wrap_err(
                "atomic publication failed; reconcile the exact destination before retrying",
            )?;
        let mut receipt = Map::new();
        for (name, value) in [
            (
                "schema",
                "iroha.developer.network-publication.v1".to_owned(),
            ),
            ("output_directory", output.display().to_string()),
            ("network_name", prepared.release.network_name),
            ("network_id", prepared.release.network_id.to_string()),
            ("chain_id", prepared.release.chain_id),
            (
                "checkpoint_block_hash",
                prepared.release.checkpoint_block_hash.to_string(),
            ),
            (
                "native_checkpoint_hash",
                prepared.release.checkpoint_hash.to_string(),
            ),
            (
                "checkpoint_artifact_blake3",
                blake3::hash(&prepared.checkpoint_bytes)
                    .to_hex()
                    .to_string(),
            ),
            (
                "profiles_artifact_blake3",
                blake3::hash(&prepared.profile_bytes).to_hex().to_string(),
            ),
            (
                "candidate_native_world_schema",
                prepared.release.native_world_schema.to_string(),
            ),
            (
                "candidate_build_source",
                crate::BUILD_SOURCE_ID.unwrap_or("unavailable").to_owned(),
            ),
            ("candidate_version", env!("CARGO_PKG_VERSION").to_owned()),
            ("release_public_key", signer.public_key().to_string()),
            ("checkpoint_url", self.checkpoint_url),
            (
                "genesis_manifest_sha256",
                hex::encode(self.expected_genesis_manifest_sha256),
            ),
        ] {
            receipt.insert(name.into(), Value::String(value));
        }
        for (name, value) in [
            ("serial", prepared.release.serial),
            ("generation", prepared.release.generation),
            ("checkpoint_height", prepared.release.checkpoint_height),
            (
                "account_chain_discriminant",
                u64::from(prepared.release.account_chain_discriminant),
            ),
            ("issued_at_ms", prepared.release.issued_at_ms),
            ("expires_at_ms", prepared.release.expires_at_ms),
        ] {
            receipt.insert(name.into(), Value::Number(value.into()));
        }
        receipt.insert("live_network_qualified".into(), Value::Bool(false));
        Ok(Value::Object(receipt))
    }
}

fn parse_manifest_sha256(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("manifest SHA256 must be exactly 64 lowercase hexadecimal digits".into());
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(value, &mut digest)
        .map_err(|_| "invalid manifest SHA256 encoding".to_owned())?;
    Ok(digest)
}

fn read_proofs(paths: &[PathBuf]) -> color_eyre::Result<Vec<SumeragiFinalityProof>> {
    // The native canonical allocation policy admits measured source-sized decoder copies.
    // One outer scope retains actual Norito allocation/element charges across every proof;
    // opening a subsequent file cannot reset the budget of the retained prefix.
    let canonical = norito::canonical_decode_limits(MAX_ADVANCE_BYTES);
    let limits = norito::DecodeLimits::new(
        iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
        iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
        MAX_ADVANCE_BYTES,
        canonical.max_total_allocated_bytes(),
        16,
    );
    read_proofs_with_limits(paths, MAX_ADVANCE_BYTES, limits)
}

fn read_proofs_with_limits(
    paths: &[PathBuf],
    raw_limit: usize,
    limits: norito::DecodeLimits,
) -> color_eyre::Result<Vec<SumeragiFinalityProof>> {
    if paths.len() > MAX_ADVANCE_PROOFS + 1 {
        return Err(eyre!("proof JSON prefix exceeds native proof count bound"));
    }
    norito::with_decode_limits_scope(limits, || {
        let prefix_capacity = paths
            .len()
            .checked_mul(std::mem::size_of::<SumeragiFinalityProof>())
            .ok_or_else(|| eyre!("proof prefix capacity overflow"))?;
        norito::core::reserve_decode_allocation(prefix_capacity)?;
        let mut proofs = Vec::new();
        proofs
            .try_reserve_exact(paths.len())
            .wrap_err("reserve bounded proof prefix")?;
        let mut remaining_raw = raw_limit;
        let mut remaining_elements = limits.max_total_elements();
        for path in paths {
            let bytes = iroha_fs::read_regular(path, remaining_raw)?;
            remaining_raw = remaining_raw
                .checked_sub(bytes.len())
                .ok_or_else(|| eyre!("proof JSON prefix exceeds native input bound"))?;
            // The input reader has its separate preallocation byte gate. Retain its actual source
            // allocation charge in the same cumulative decode owner before constructing a value.
            norito::core::reserve_decode_allocation(bytes.len())?;
            let document_limits = norito::DecodeLimits::new(
                limits.max_sequence_elements(),
                limits.max_field_bytes(),
                remaining_elements,
                limits.max_total_allocated_bytes(),
                limits.max_nesting_depth(),
            );
            let profile = json::preflight_slice(
                &bytes,
                // The existing proof type has only bounded key/hash string literals; its
                // potentially large block wire and PoPs are byte arrays, not arbitrary text.
                json::JsonPreflightLimits::new(
                    bytes.len(),
                    remaining_elements.saturating_add(1),
                    4096,
                    4096,
                    bytes.len(),
                    document_limits.max_sequence_elements(),
                    remaining_elements,
                    remaining_elements,
                    remaining_elements,
                    document_limits.max_nesting_depth(),
                ),
            )
            .wrap_err("finality-proof JSON exceeds its lexical resource bounds")?;
            let elements = profile
                .array_entries()
                .checked_add(profile.object_entries())
                .ok_or_else(|| eyre!("proof JSON geometry overflow"))?;
            remaining_elements = remaining_elements
                .checked_sub(elements)
                .ok_or_else(|| eyre!("proof JSON prefix exceeds aggregate element bound"))?;
            let measured = norito::canonical_decode_limits(profile.raw_bytes());
            let typed_limits = norito::DecodeLimits::new(
                measured
                    .max_sequence_elements()
                    .min(limits.max_sequence_elements()),
                measured.max_field_bytes().min(limits.max_field_bytes()),
                measured
                    .max_total_elements()
                    .min(limits.max_total_elements()),
                measured
                    .max_total_allocated_bytes()
                    .min(limits.max_total_allocated_bytes()),
                limits.max_nesting_depth(),
            );
            proofs.push(
                norito::with_decode_limits_scope(typed_limits, || json::from_slice(&bytes))
                    .wrap_err("invalid bounded typed native finality-proof JSON")?,
            );
        }
        Ok(proofs)
    })
}

fn release_signer(path: &Path) -> color_eyre::Result<KeyPair> {
    let bytes = iroha_fs::read_private(path, 4096)
        .map_err(|_| eyre!("invalid release signing-key custody"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| eyre!("invalid release signing-key encoding"))?;
    let canonical = text.strip_suffix('\n').ok_or_else(|| {
        eyre!("release signing-key requires one canonical record with final newline")
    })?;
    if canonical.is_empty() || canonical.chars().any(char::is_whitespace) {
        return Err(eyre!("release signing-key requires one canonical record"));
    }
    let exposed = canonical
        .parse::<ExposedPrivateKey>()
        .map_err(|_| eyre!("invalid release signing-key encoding"))?;
    let encoded = Zeroizing::new(exposed.to_string());
    if encoded.as_str() != canonical {
        return Err(eyre!("noncanonical release signing-key encoding"));
    }
    KeyPair::from_private_key(exposed.0).map_err(|_| eyre!("invalid release signing key"))
}

#[cfg(test)]
mod tests;
