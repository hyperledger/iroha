//! Credential-free export of explicitly selected public deployment expectations.
//!
//! Retaining a network does not require a reset inventory. The operator selects
//! the public genesis and peer pins independently; later deployment preflight
//! checks fresh signed attestations against these expectations.

use super::*;
use iroha_crypto::PublicKey;

/// Export the existing native trust format without resetting or contacting a network.
#[derive(Debug, clap::Args)]
pub(crate) struct ExportProfile {
    /// Independently selected canonical checked NetworkId of the retained network.
    #[arg(long, value_parser = parse_network_id)]
    network_id: NetworkId,
    /// Explicit canonical chain ID selected by the network operator; absent from signed genesis.
    #[arg(long)]
    chain: iroha_model_base::chain::ChainId,
    /// Explicit account address discriminant selected by the network operator.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    chain_discriminant: u16,
    /// Exact public SignedBlockWire genesis file.
    #[arg(long, value_name = "FILE")]
    genesis_signed: PathBuf,
    /// Canonical public genesis key, with an optional final newline.
    #[arg(long, value_name = "FILE")]
    genesis_public_key: PathBuf,
    /// Public JSON array of the existing four deployment peer records.
    #[arg(long, value_name = "FILE")]
    peers: PathBuf,
    /// New profile file under an existing current-owner private directory.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

fn parse_network_id(value: &str) -> std::result::Result<NetworkId, String> {
    let network: NetworkId = value.parse().map_err(|error| format!("{error}"))?;
    if network.to_string() != value {
        return Err("network ID must use its canonical checked spelling".into());
    }
    Ok(network)
}

#[derive(JsonSerialize)]
struct ExportReceipt {
    schema: &'static str,
    network_id: NetworkId,
    profile: String,
    profile_sha256: String,
    signed_genesis_sha256: String,
    genesis_public_key_sha256: String,
    peers_sha256: String,
    target_expectation_only: bool,
    authorization_verified: bool,
    deployment_verified: bool,
}

fn derive_profile(
    network: NetworkId,
    chain: &iroha_model_base::chain::ChainId,
    account_chain_discriminant: u16,
    wire: &[u8],
    key_bytes: &[u8],
    peer_bytes: &[u8],
) -> Result<DeploymentTrustV1> {
    let text = std::str::from_utf8(key_bytes).wrap_err("public genesis key is not UTF-8")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let key: PublicKey = text.parse().wrap_err("public genesis key is invalid")?;
    require(
        key.to_string() == text,
        "public genesis key is not canonical",
    )?;
    let peers: Vec<DeploymentPeerV1> =
        json::from_slice(peer_bytes).wrap_err("invalid public deployment peer array")?;
    let profile = DeploymentTrustV1 {
        chain: chain.clone(),
        account_chain_discriminant,
        genesis_public_key: key,
        genesis_signed_wire_hex: hex::encode(wire),
        peers,
    };
    validate_deployment_trust(&profile, network)?;
    validate_deployment_peer_routes(&profile)?;
    Ok(profile)
}

#[cfg(unix)]
pub(crate) struct PublicInput {
    path: PathBuf,
    file: File,
    snapshot: fs::Metadata,
    pub(crate) bytes: Vec<u8>,
}

#[cfg(unix)]
impl PublicInput {
    pub(crate) fn read(path: &Path) -> Result<Self> {
        use rustix::fs::{Mode, OFlags};
        use std::os::unix::fs::MetadataExt as _;
        let mut file = File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        let snapshot = file.metadata()?;
        require(
            snapshot.is_file() && snapshot.nlink() == 1 && snapshot.len() <= MAX_BYTES as u64,
            "public profile input must be a bounded direct single-link regular file",
        )?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() <= MAX_BYTES,
            "public profile input exceeds bound",
        )?;
        let input = Self {
            path: path.into(),
            file,
            snapshot,
            bytes,
        };
        input.revalidate()?;
        Ok(input)
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        require(
            same_file_snapshot(&self.snapshot, &self.file.metadata()?)
                && same_file_snapshot(&self.snapshot, &fs::symlink_metadata(&self.path)?)
                && self.snapshot.len() == self.bytes.len() as u64,
            "public profile input changed during custody",
        )
    }
}

#[cfg(unix)]
pub(super) fn publish_profile(path: &Path, bytes: &[u8]) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
    require(
        path.is_absolute()
            && path.components().all(|part| {
                matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            }),
        "profile output must be an absolute normal file path",
    )?;
    require(
        bytes.len() <= MAX_BYTES,
        "public profile output exceeds bound",
    )?;
    let name = path
        .file_name()
        .ok_or_else(|| eyre!("profile output has no name"))?;
    let parent_path = path
        .parent()
        .ok_or_else(|| eyre!("profile output has no parent"))?
        .canonicalize()?;
    let parent = File::from(rustix::fs::open(
        &parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    let revalidate = || -> Result<()> {
        let named = fs::symlink_metadata(&parent_path)?;
        let held = parent.metadata()?;
        private_metadata(&named, true)?;
        private_metadata(&held, true)?;
        use std::os::unix::fs::MetadataExt as _;
        require(
            named.dev() == held.dev() && named.ino() == held.ino(),
            "profile output directory changed",
        )
    };
    revalidate()?;
    let temporary = format!(".profile-{}", hex::encode(rand::random::<[u8; 16]>()));
    let mut file = File::from(rustix::fs::openat(
        &parent,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?);
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        private_metadata(&file.metadata()?, false)?;
        revalidate()?;
        rustix::fs::renameat_with(
            &parent,
            temporary.as_str(),
            &parent,
            name,
            RenameFlags::NOREPLACE,
        )?;
        parent.sync_all()?;
        revalidate()?;
        let published = PublicInput::read(&parent_path.join(name))?;
        private_metadata(&published.snapshot, false)?;
        require(
            published.bytes == bytes,
            "published profile differs from selected bytes",
        )
    })();
    match rustix::fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty()) {
        Ok(()) => parent.sync_all()?,
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) if result.is_ok() => return Err(error.into()),
        Err(_) => {}
    }
    result
}

impl ExportProfile {
    #[cfg(unix)]
    pub(crate) fn run_without_client_config(&self, mut output: impl std::io::Write) -> Result<()> {
        let wire = PublicInput::read(&self.genesis_signed)?;
        let key = PublicInput::read(&self.genesis_public_key)?;
        let peers = PublicInput::read(&self.peers)?;
        let profile = derive_profile(
            self.network_id,
            &self.chain,
            self.chain_discriminant,
            &wire.bytes,
            &key.bytes,
            &peers.bytes,
        )?;
        let mut bytes = json::to_vec(&profile)?;
        bytes.push(b'\n');
        let receipt = ExportReceipt {
            schema: "iroha.dataspace.profile-export.v1",
            network_id: self.network_id,
            profile: self.output.to_string_lossy().into_owned(),
            profile_sha256: hex::encode(Sha256::digest(&bytes)),
            signed_genesis_sha256: hex::encode(Sha256::digest(&wire.bytes)),
            genesis_public_key_sha256: hex::encode(Sha256::digest(&key.bytes)),
            peers_sha256: hex::encode(Sha256::digest(&peers.bytes)),
            target_expectation_only: true,
            authorization_verified: false,
            deployment_verified: false,
        };
        let mut receipt = json::to_vec(&receipt)?;
        receipt.push(b'\n');
        wire.revalidate()?;
        key.revalidate()?;
        peers.revalidate()?;
        publish_profile(&self.output, &bytes)?;
        output.write_all(&receipt)?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn run_without_client_config(&self, _: impl std::io::Write) -> Result<()> {
        eyre::bail!("native profile export requires Unix filesystem custody")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use clap::Parser as _;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture() -> (tempfile::TempDir, ExportProfile, DeploymentTrustV1) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let trust = finality::test_trust();
        let args = ExportProfile {
            network_id: finality::test_network_id(),
            chain: trust.chain.clone(),
            chain_discriminant: trust.account_chain_discriminant,
            genesis_signed: directory.path().join("genesis.signed.nrt"),
            genesis_public_key: directory.path().join("genesis.public_key"),
            peers: directory.path().join("peers.json"),
            output: directory.path().join("profile.json"),
        };
        fs::write(
            &args.genesis_signed,
            hex::decode(&trust.genesis_signed_wire_hex).unwrap(),
        )
        .unwrap();
        fs::write(
            &args.genesis_public_key,
            format!("{}\n", trust.genesis_public_key),
        )
        .unwrap();
        fs::write(&args.peers, json::to_vec(&trust.peers).unwrap()).unwrap();
        (directory, args, trust)
    }

    fn arguments(args: &ExportProfile) -> Vec<String> {
        [
            "iroha",
            "--machine",
            "dataspace",
            "export-profile",
            "--network-id",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([
            args.network_id.to_string(),
            "--chain".into(),
            args.chain.to_string(),
            "--chain-discriminant".into(),
            args.chain_discriminant.to_string(),
            "--genesis-signed".into(),
            args.genesis_signed.display().to_string(),
            "--genesis-public-key".into(),
            args.genesis_public_key.display().to_string(),
            "--peers".into(),
            args.peers.display().to_string(),
            "--output".into(),
            args.output.display().to_string(),
        ])
        .collect()
    }

    #[test]
    fn retained_profile_export_uses_native_trust_and_exact_input_hashes() {
        let (_directory, args, trust) = fixture();
        let parsed = crate::Args::try_parse_from(arguments(&args)).unwrap();
        let mut output = Vec::new();
        crate::run_local_dataspace_profile(&parsed, &mut output)
            .unwrap()
            .unwrap();
        let bytes = fs::read(&args.output).unwrap();
        let actual: DeploymentTrustV1 = json::from_slice(&bytes).unwrap();
        assert_eq!(actual, trust);
        validate_deployment_trust(&actual, args.network_id).unwrap();
        let receipt: json::Value = json::from_slice(&output).unwrap();
        assert_eq!(
            receipt["profile_sha256"].as_str(),
            Some(hex::encode(Sha256::digest(&bytes)).as_str())
        );
        for (field, path) in [
            ("signed_genesis_sha256", &args.genesis_signed),
            ("genesis_public_key_sha256", &args.genesis_public_key),
            ("peers_sha256", &args.peers),
        ] {
            assert_eq!(
                receipt[field].as_str(),
                Some(hex::encode(Sha256::digest(fs::read(path).unwrap())).as_str())
            );
        }
        assert_eq!(receipt["target_expectation_only"].as_bool(), Some(true));
        assert_eq!(receipt["authorization_verified"].as_bool(), Some(false));
        assert_eq!(receipt["deployment_verified"].as_bool(), Some(false));
        assert_eq!(
            fs::metadata(&args.output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut second = Vec::new();
        assert!(args.run_without_client_config(&mut second).is_err());
        assert!(second.is_empty());
        assert_eq!(fs::read(&args.output).unwrap(), bytes);
    }

    #[test]
    fn retained_profile_export_rejects_unbound_or_malformed_public_inputs() {
        let (_directory, args, trust) = fixture();
        let wire = fs::read(&args.genesis_signed).unwrap();
        let key = fs::read(&args.genesis_public_key).unwrap();
        let peers = fs::read(&args.peers).unwrap();
        let wrong = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"wrong network"),
        ));
        assert!(
            derive_profile(
                wrong,
                &args.chain,
                args.chain_discriminant,
                &wire,
                &key,
                &peers
            )
            .is_err()
        );
        let wrong_key = KeyPair::try_from_seed(vec![99; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_string();
        assert!(
            derive_profile(
                args.network_id,
                &args.chain,
                args.chain_discriminant,
                &wire,
                wrong_key.as_bytes(),
                &peers
            )
            .is_err()
        );
        assert!(
            derive_profile(
                args.network_id,
                &args.chain,
                args.chain_discriminant,
                &[],
                &key,
                &peers
            )
            .is_err()
        );
        let mut padded_key = key.clone();
        padded_key.push(b' ');
        assert!(
            derive_profile(
                args.network_id,
                &args.chain,
                args.chain_discriminant,
                &wire,
                &padded_key,
                &peers
            )
            .is_err()
        );
        let mut altered_wire = wire.clone();
        altered_wire.push(0);
        assert!(
            derive_profile(
                args.network_id,
                &args.chain,
                args.chain_discriminant,
                &altered_wire,
                &key,
                &peers
            )
            .is_err()
        );
        assert!(
            derive_profile(
                args.network_id,
                &args.chain,
                args.chain_discriminant,
                &wire,
                &key,
                b"{}"
            )
            .is_err()
        );
        for defect in 0..6 {
            let mut changed = trust.peers.clone();
            match defect {
                0 => {
                    changed.pop();
                }
                1 => changed[1] = changed[0].clone(),
                2 => changed[0].node_fingerprint = Hash::new(b"wrong node"),
                3 => changed[0].torii_origin = "https://name:password@example.com/".into(),
                4 => changed[1].torii_origin = changed[0].torii_origin.clone(),
                _ => {
                    let foreign =
                        KeyPair::try_from_seed(vec![99; 32], Algorithm::BlsNormal).unwrap();
                    changed[0].peer_id =
                        iroha_model_base::peer::PeerId::new(foreign.public_key().clone());
                    use norito::codec::Encode as _;
                    changed[0].node_fingerprint = Hash::new(changed[0].peer_id.encode());
                }
            }
            assert!(
                derive_profile(
                    args.network_id,
                    &args.chain,
                    args.chain_discriminant,
                    &wire,
                    &key,
                    &json::to_vec(&changed).unwrap()
                )
                .is_err()
            );
        }
        let mut unknown: json::Value = json::from_slice(&peers).unwrap();
        unknown.as_array_mut().unwrap()[0]
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), norito::json!(true));
        assert!(
            derive_profile(
                args.network_id,
                &args.chain,
                args.chain_discriminant,
                &wire,
                &key,
                &json::to_vec(&unknown).unwrap()
            )
            .is_err()
        );
        assert!(!args.output.exists());
    }

    #[test]
    fn retained_profile_export_rejects_changed_linked_and_unsafe_files() {
        let (directory, args, _trust) = fixture();
        let input = PublicInput::read(&args.peers).unwrap();
        fs::write(&args.peers, b"[]").unwrap();
        assert!(input.revalidate().is_err());
        let link = directory.path().join("linked.json");
        std::os::unix::fs::symlink(&args.peers, &link).unwrap();
        assert!(PublicInput::read(&link).is_err());
        let hardlink = directory.path().join("hardlinked.json");
        fs::hard_link(&args.peers, &hardlink).unwrap();
        assert!(PublicInput::read(&args.peers).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(publish_profile(&args.output, b"{}").is_err());
        assert!(!args.output.exists());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&args.genesis_public_key, &args.output).unwrap();
        let original = fs::read(&args.genesis_public_key).unwrap();
        assert!(publish_profile(&args.output, b"{}").is_err());
        assert_eq!(fs::read(&args.genesis_public_key).unwrap(), original);
        let oversized = directory.path().join("oversized");
        File::create(&oversized)
            .unwrap()
            .set_len((MAX_BYTES + 1) as u64)
            .unwrap();
        assert!(PublicInput::read(&oversized).is_err());
    }

    #[test]
    fn retained_profile_export_dispatch_rejects_credential_and_transaction_globals() {
        let (_directory, args, _trust) = fixture();
        let plain = arguments(&args);
        for globals in [
            vec!["--config", "/must-not-read"],
            vec![
                "--config-fd",
                "999",
                "--config-source-path",
                "/must-not-read",
            ],
            vec!["--operator-private-key-file", "/must-not-read"],
            vec!["--operator-private-key-fd", "998"],
            vec!["--verbose"],
            vec!["--metadata", "/must-not-read"],
            vec!["--stdin-instructions"],
            vec!["--emit-instructions"],
        ] {
            let mut argv = vec!["iroha".to_owned()];
            argv.extend(globals.into_iter().map(str::to_owned));
            argv.extend(plain.iter().skip(1).cloned());
            let parsed = crate::Args::try_parse_from(argv).unwrap();
            let mut output = Vec::new();
            let error = crate::run_local_dataspace_profile(&parsed, &mut output)
                .unwrap()
                .unwrap_err();
            assert!(format!("{error:?}").contains("credential-free local tooling"));
            assert!(output.is_empty());
            assert!(!args.output.exists());
        }
        assert!(parse_network_id(&args.network_id.to_string()).is_ok());
        assert!(parse_network_id("not-a-network").is_err());
    }
}
