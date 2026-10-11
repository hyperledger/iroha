//! Verify archived public attestations with independent genesis, role and original read-window pins.
//!
//! This command performs no network requests or ledger writes. Its configured public identity is
//! joined to the pinned request, while the original software-clock observations remain historical.
//! Run with `--output-format json`, the selected native client configuration, and
//! `ops bridge verify-retained-network --request <public-json> --request-sha256 <approved-digest>`.
//! Request schema `iroha.bridge.retained-network-request.v1` contains the independently selected
//! network, chain, discriminant and route; pinned signed/raw genesis and role manifest; a contiguous
//! native JSON proof prefix; and four pinned original JSON attestations with original challenges
//! and read windows. Every file reference contains an absolute path, SHA-256, bytes and full-nine
//! metadata. Private configurations and signing keys are never request inputs or public outputs.

use crate::{CliOutputFormat, RunContext};
use eyre::{Result, ensure, eyre};
use iroha_crypto::{Hash, PublicKey};
use iroha_data_model::{
    NetworkId,
    sumeragi_finality::{
        FinalityValidator, SumeragiFinalityAttestation, SumeragiFinalityProof,
        SumeragiFinalityVerifier,
    },
};
use iroha_model_base::peer::PeerId;
use norito::{
    derive::{JsonDeserialize, JsonSerialize},
    json,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;
const MAX_PREFIX: usize = 128;

/// Explicit caller pin for one bounded public verification request.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// Owner-controlled public request; no private configuration bytes belong in it.
    #[arg(long)]
    request: PathBuf,
    /// SHA-256 independently approved outside the request transport.
    #[arg(long)]
    request_sha256: String,
}

#[derive(Clone, Debug, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct PublicFile {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    identity: Vec<u64>,
}

impl PublicFile {
    /// Validate the JSON sequence before indexing it or performing any custody I/O.
    fn identity_array(&self) -> Result<[u64; 9]> {
        ensure!(
            self.identity.len() == 9,
            "public input metadata must contain exactly nine integers"
        );
        self.identity
            .as_slice()
            .try_into()
            .map_err(|_| eyre!("public input metadata must contain exactly nine integers"))
    }
}

#[derive(Clone, Debug, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct Peer {
    role: u8,
    peer_id: PeerId,
    node_fingerprint: Hash,
    build_fingerprint: Hash,
    node_config_fingerprint: Hash,
    consensus_config_fingerprint: Hash,
    challenge: String,
    read_start_ns: u64,
    read_finish_ns: u64,
    attestation: PublicFile,
}

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Request {
    schema: String,
    network_id: NetworkId,
    chain_id: String,
    chain_discriminant: u16,
    torii_url: String,
    genesis_public_key: PublicKey,
    signed_genesis: PublicFile,
    genesis_manifest: PublicFile,
    peer_manifest: PublicFile,
    proof_prefix: Vec<PublicFile>,
    peers: Vec<Peer>,
}

fn pin(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value.bytes().any(|b| b != b'0'),
        "public SHA-256 pin must be nonzero lowercase hexadecimal"
    );
    Ok(())
}

fn absolute(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| eyre!("public input path is not UTF-8"))?;
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && !text.contains("//")
            && !text.contains("/./")
            && !text.ends_with("/.")
            && !text.ends_with('/'),
        "public input must have an exact absolute path"
    );
    Ok(())
}

#[cfg(unix)]
fn identity(metadata: &std::fs::Metadata) -> Result<[u64; 9]> {
    use std::os::unix::fs::MetadataExt as _;
    Ok([
        metadata.dev(),
        metadata.ino(),
        u64::from(metadata.mode()),
        u64::from(metadata.uid()),
        u64::from(metadata.gid()),
        metadata.nlink(),
        metadata.len(),
        u64::try_from(metadata.mtime())?
            .checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(metadata.mtime_nsec() as u64))
            .ok_or_else(|| eyre!("public input mtime is invalid"))?,
        u64::try_from(metadata.ctime())?
            .checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(metadata.ctime_nsec() as u64))
            .ok_or_else(|| eyre!("public input ctime is invalid"))?,
    ])
}

struct HeldPublic {
    reference: PublicFile,
    file: File,
    bytes: Vec<u8>,
    #[cfg(unix)]
    parents: Vec<(PathBuf, File, [u64; 9], bool)>,
}

/// Match private ancestor metadata exactly and shared ancestor metadata by stable identity.
#[cfg(unix)]
fn directory_identity_unchanged(before: &[u64; 9], observed: &[u64; 9], private: bool) -> bool {
    if private {
        before == observed
    } else {
        before[..5] == observed[..5]
    }
}

impl HeldPublic {
    #[cfg(unix)]
    fn open(reference: &PublicFile) -> Result<Self> {
        use rustix::fs::{Mode, OFlags};
        use std::os::unix::fs::MetadataExt as _;
        let expected_identity = reference.identity_array()?;
        absolute(&reference.path)?;
        pin(&reference.sha256)?;
        ensure!(
            reference.bytes > 0
                && reference.bytes <= MAX_FILE
                && expected_identity[6] == reference.bytes,
            "public input bound/size differs"
        );
        let owner = rustix::process::geteuid().as_raw();
        let mut parents = Vec::new();
        for path in reference
            .path
            .parent()
            .ok_or_else(|| eyre!("public input parent is absent"))?
            .ancestors()
        {
            let before = std::fs::symlink_metadata(path)?;
            ensure!(
                before.is_dir()
                    && !before.file_type().is_symlink()
                    && (before.uid() == 0 || before.uid() == owner)
                    && before.mode() & 0o022 == 0,
                "public input ancestor custody is unsafe"
            );
            let private = before.uid() == owner && before.mode() & 0o7777 == 0o700;
            let directory = File::from(rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let full = identity(&before)?;
            ensure!(
                directory_identity_unchanged(&full, &identity(&directory.metadata()?)?, private)
                    && directory_identity_unchanged(
                        &full,
                        &identity(&std::fs::symlink_metadata(path)?)?,
                        private,
                    ),
                "public input ancestor changed while opening"
            );
            parents.push((path.to_path_buf(), directory, full, private));
        }
        let before = std::fs::symlink_metadata(&reference.path)?;
        ensure!(
            before.is_file()
                && !before.file_type().is_symlink()
                && before.uid() == owner
                && before.nlink() == 1
                && matches!(before.mode() & 0o7777, 0o600 | 0o644)
                && identity(&before)? == expected_identity,
            "public input identity/ownership/mode differs"
        );
        let mut file = File::from(rustix::fs::open(
            &reference.path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        ensure!(
            identity(&file.metadata()?)? == expected_identity,
            "opened public input differs"
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(reference.bytes + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == reference.bytes
                && hex::encode(Sha256::digest(&bytes)) == reference.sha256,
            "public input bytes differ from independently approved digest"
        );
        let retained = Self {
            reference: reference.clone(),
            file,
            bytes,
            parents,
        };
        retained.check()?;
        Ok(retained)
    }

    #[cfg(not(unix))]
    fn open(_: &PublicFile) -> Result<Self> {
        Err(eyre!(
            "retained network verification requires Unix public-file custody"
        ))
    }

    #[cfg(unix)]
    fn check(&self) -> Result<()> {
        use std::os::unix::fs::FileExt as _;
        let expected_identity = self.reference.identity_array()?;
        ensure!(
            identity(&self.file.metadata()?)? == expected_identity
                && identity(&std::fs::symlink_metadata(&self.reference.path)?)?
                    == expected_identity,
            "retained public input metadata changed"
        );
        let mut offset = 0;
        let mut buffer = [0u8; 65536];
        let mut digest = Sha256::new();
        loop {
            let read = self.file.read_at(&mut buffer, offset)?;
            if read == 0 {
                break;
            }
            offset += read as u64;
            ensure!(
                offset <= self.reference.bytes,
                "retained public input exceeded its bound"
            );
            digest.update(&buffer[..read]);
        }
        ensure!(
            offset == self.reference.bytes
                && hex::encode(digest.finalize()) == self.reference.sha256,
            "retained public input bytes changed"
        );
        for (path, directory, before, private) in &self.parents {
            let opened = identity(&directory.metadata()?)?;
            let named = identity(&std::fs::symlink_metadata(path)?)?;
            ensure!(
                directory_identity_unchanged(before, &opened, *private)
                    && directory_identity_unchanged(before, &named, *private),
                "retained public input ancestor changed"
            );
        }
        ensure!(
            identity(&self.file.metadata()?)? == expected_identity
                && identity(&std::fs::symlink_metadata(&self.reference.path)?)?
                    == expected_identity,
            "retained public input changed while hashing"
        );
        Ok(())
    }

    #[cfg(not(unix))]
    fn check(&self) -> Result<()> {
        Err(eyre!("Unix public-file custody is required"))
    }
}

fn challenge(value: &str) -> Result<[u8; 32]> {
    pin(value)?;
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)?;
    Ok(bytes)
}

fn verify_peer(
    peer: &Peer,
    attestation: &SumeragiFinalityAttestation,
    network: NetworkId,
    verifier: &SumeragiFinalityVerifier,
) -> Result<()> {
    attestation.verify()?;
    let body = &attestation.body;
    ensure!(
        peer.read_start_ns > 0 && peer.read_start_ns <= peer.read_finish_ns,
        "original read window is invalid"
    );
    ensure!(
        body.challenge == challenge(&peer.challenge)?
            && body.node_id == peer.peer_id
            && body.node_fingerprint == peer.node_fingerprint
            && body.build_fingerprint == peer.build_fingerprint
            && body.config_fingerprint == peer.node_config_fingerprint
            && body.status.config_fingerprint == peer.consensus_config_fingerprint
            && body.network_id == network
            && body.genesis_block_hash == *network.as_genesis_hash()
            && body.status.instance == verifier.instance().0
            && !body.status.unanchored
            && !body.status.abstaining
            && peer.read_start_ns / 1_000_000 <= body.observed_at_unix_ms
            && body.observed_at_unix_ms <= peer.read_finish_ns / 1_000_000,
        "archived node, challenge, original window, configuration or network differs"
    );
    verifier.verify_retained_decision(&body.genesis_finality_proof)?;
    verifier.verify_retained_decision(&body.finality_proof)?;
    Ok(())
}

fn verify_manifest_identity(
    manifest: &iroha_genesis::RawGenesisTransaction,
    chain_id: &str,
    chain_discriminant: u16,
) -> Result<()> {
    ensure!(
        manifest.chain_id().to_string() == chain_id
            && manifest.chain_discriminant() == chain_discriminant,
        "raw genesis chain label or discriminant differs from independent request"
    );
    Ok(())
}

#[derive(JsonSerialize)]
struct Report {
    schema: &'static str,
    request_sha256: String,
    historical_observations_only: bool,
    chain_write_performed: bool,
    network_id: NetworkId,
    chain_id: String,
    chain_discriminant: u16,
    torii_url: String,
    verified_roles: Vec<u8>,
    verified_prefix_height: u64,
    finality_signatures: bool,
    genesis_signature: bool,
    manifest_role_peer_join: bool,
    challenge_and_window: bool,
    configured_identity: bool,
}

/// Protocol results use stdout even when ordinary diagnostics use stderr.
fn write_report(context: &mut impl RunContext, report: &Report) -> Result<()> {
    context.println_data(json::to_json(report)?)
}

pub(super) fn run(context: &mut impl RunContext, args: Args) -> Result<()> {
    ensure!(
        context.output_format() == CliOutputFormat::Json,
        "retained network verification requires --output-format json"
    );
    absolute(&args.request)?;
    pin(&args.request_sha256)?;
    #[cfg(unix)]
    let request_ref = PublicFile {
        path: args.request.clone(),
        sha256: args.request_sha256.clone(),
        bytes: std::fs::symlink_metadata(&args.request)?.len(),
        identity: identity(&std::fs::symlink_metadata(&args.request)?)?.to_vec(),
    };
    #[cfg(not(unix))]
    return Err(eyre!(
        "retained network verification requires Unix public-file custody"
    ));
    #[cfg(unix)]
    {
        let request_file = HeldPublic::open(&request_ref)?;
        let request: Request = json::from_slice(&request_file.bytes)?;
        ensure!(
            request.schema == "iroha.bridge.retained-network-request.v1"
                && request.peers.len() == 4
                && !request.proof_prefix.is_empty()
                && request.proof_prefix.len() <= MAX_PREFIX
                && request.chain_discriminant != 0,
            "retained public request schema or verification bounds differ"
        );
        ensure!(
            context.config().network_id == request.network_id
                && context.config().chain.to_string() == request.chain_id
                && context.config().account_chain_discriminant == request.chain_discriminant
                && context
                    .config()
                    .torii_api_url
                    .as_str()
                    .strip_suffix('/')
                    .unwrap_or(context.config().torii_api_url.as_str())
                    == request.torii_url,
            "configured public network, chain, discriminant or route differs from independent request"
        );
        let refs = [
            &request.signed_genesis,
            &request.genesis_manifest,
            &request.peer_manifest,
        ]
        .into_iter()
        .chain(request.proof_prefix.iter())
        .chain(request.peers.iter().map(|peer| &peer.attestation))
        .collect::<Vec<_>>();
        let total = refs
            .iter()
            .try_fold(request_ref.bytes, |total, reference| {
                total
                    .checked_add(reference.bytes)
                    .ok_or_else(|| eyre!("public input total overflow"))
            })?;
        ensure!(
            total <= MAX_TOTAL,
            "retained public inputs exceed the aggregate bound"
        );
        let files = refs
            .iter()
            .map(|reference| HeldPublic::open(reference))
            .collect::<Result<Vec<_>>>()?;
        iroha_genesis::init_instruction_registry();
        let manifest: iroha_genesis::RawGenesisTransaction = json::from_slice(&files[1].bytes)?;
        let genesis = iroha_genesis::validate_prepared_genesis_bundle(
            &files[0].bytes,
            &manifest,
            &request.genesis_public_key,
            request.network_id.into_genesis_hash(),
        )?;
        verify_manifest_identity(&manifest, &request.chain_id, request.chain_discriminant)?;
        let validators = genesis
            .validator_pops()
            .iter()
            .map(|(key, pop)| FinalityValidator {
                public_key: key.clone(),
                proof_of_possession: pop.clone(),
            })
            .collect::<Vec<_>>();
        let selected = request
            .peers
            .iter()
            .map(|peer| peer.peer_id.clone())
            .collect::<BTreeSet<_>>();
        let actual = validators
            .iter()
            .map(|validator| PeerId::new(validator.public_key.clone()))
            .collect::<BTreeSet<_>>();
        ensure!(
            selected.len() == 4
                && selected == actual
                && request
                    .peers
                    .iter()
                    .map(|peer| peer.role)
                    .collect::<Vec<_>>()
                    == [1, 2, 3, 4],
            "four ordered original roles differ from independently signed genesis validators"
        );
        let public_manifest: json::Value = json::from_slice(&files[2].bytes)?;
        let manifest_peers = public_manifest
            .get("validators")
            .and_then(json::Value::as_array)
            .ok_or_else(|| eyre!("public role manifest validators are absent"))?;
        ensure!(
            manifest_peers.len() == 4
                && manifest_peers
                    .iter()
                    .zip(&request.peers)
                    .all(
                        |(row, peer)| row.get("peer_id").and_then(json::Value::as_str)
                            == Some(peer.peer_id.to_string().as_str())
                    ),
            "original role ordering differs from independently pinned public manifest"
        );
        let mut verifier =
            SumeragiFinalityVerifier::new(genesis.block(), &request.chain_id, validators)?;
        for (index, file) in files[3..3 + request.proof_prefix.len()].iter().enumerate() {
            let proof: SumeragiFinalityProof = json::from_slice(&file.bytes)?;
            ensure!(
                proof.height() == index as u64 + 1,
                "retained finality prefix is not contiguous from genesis"
            );
            verifier.verify(&proof)?;
        }
        let peer_start = 3 + request.proof_prefix.len();
        for (peer, file) in request.peers.iter().zip(&files[peer_start..]) {
            let attestation: SumeragiFinalityAttestation = json::from_slice(&file.bytes)?;
            verify_peer(peer, &attestation, request.network_id, &verifier)?;
        }
        request_file.check()?;
        for file in &files {
            file.check()?;
        }
        let report = Report {
            schema: "iroha.bridge.retained-network-verification.v1",
            request_sha256: args.request_sha256,
            historical_observations_only: true,
            chain_write_performed: false,
            network_id: request.network_id,
            chain_id: request.chain_id,
            chain_discriminant: request.chain_discriminant,
            torii_url: request.torii_url,
            verified_roles: vec![1, 2, 3, 4],
            verified_prefix_height: request.proof_prefix.len() as u64,
            finality_signatures: true,
            genesis_signature: true,
            manifest_role_peer_join: true,
            challenge_and_window: true,
            configured_identity: true,
        };
        write_report(context, &report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
    use iroha_data_model::{
        sumeragi::{SumeragiFootprint, SumeragiStatus},
        sumeragi_finality::{
            SumeragiFinalityAttestationBody, test_fixtures::NativeFinalityFixture,
        },
    };
    use norito::codec::Encode as _;

    #[test]
    fn machine_verification_report_uses_stdout_without_diagnostics() {
        let fixture = NativeFinalityFixture::new();
        let report = Report {
            schema: "iroha.bridge.retained-network-verification.v1",
            request_sha256: "01".repeat(32),
            historical_observations_only: true,
            chain_write_performed: false,
            network_id: fixture.network_id(),
            chain_id: fixture.chain_id().to_owned(),
            chain_discriminant: 369,
            torii_url: "https://taira.sora.org".to_owned(),
            verified_roles: vec![1, 2, 3, 4],
            verified_prefix_height: 2,
            finality_signatures: true,
            genesis_signature: true,
            manifest_role_peer_join: true,
            challenge_and_window: true,
            configured_identity: true,
        };
        let mut context = crate::tests::test_context(CliOutputFormat::Json);
        write_report(&mut context, &report).unwrap();
        assert_eq!(
            context.write,
            format!("{}\n", json::to_json(&report).unwrap()).as_bytes()
        );
        assert!(context.err_write.is_empty());
        let parsed: json::Value = json::from_slice(&context.write).unwrap();
        assert_eq!(parsed["historical_observations_only"].as_bool(), Some(true));
        assert_eq!(parsed["chain_write_performed"].as_bool(), Some(false));
    }

    #[cfg(unix)]
    #[test]
    fn directory_opening_preserves_shared_core_and_private_full_metadata() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        for (mode, private) in [(0o755, false), (0o700, true)] {
            let parent = root.path().join(format!("directory-{mode:o}"));
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(mode)).unwrap();
            let before = identity(&std::fs::symlink_metadata(&parent).unwrap()).unwrap();
            std::fs::write(
                parent.join("unrelated-public-child"),
                b"public metadata fixture",
            )
            .unwrap();
            let after = identity(&std::fs::symlink_metadata(&parent).unwrap()).unwrap();
            assert_ne!(before, after);
            assert_eq!(
                directory_identity_unchanged(&before, &after, private),
                !private
            );
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750)).unwrap();
            assert!(!directory_identity_unchanged(
                &before,
                &identity(&std::fs::symlink_metadata(&parent).unwrap()).unwrap(),
                private,
            ));
            std::fs::rename(&parent, root.path().join(format!("displaced-{mode:o}"))).unwrap();
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(!directory_identity_unchanged(
                &before,
                &identity(&std::fs::symlink_metadata(&parent).unwrap()).unwrap(),
                private,
            ));
        }
    }

    #[test]
    fn public_file_identity_json_roundtrip_requires_integer_elements() {
        let reference = PublicFile {
            path: "/public/synthetic-only.json".into(),
            sha256: "11".repeat(32),
            bytes: 14,
            identity: vec![11, 22, 33152, 501, 20, 1, 14, 88, 99],
        };
        let encoded = json::to_json(&reference).unwrap();
        let decoded: PublicFile = json::from_slice(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.path, reference.path);
        assert_eq!(decoded.sha256, reference.sha256);
        assert_eq!(decoded.bytes, reference.bytes);
        assert_eq!(decoded.identity, reference.identity);
        assert_eq!(
            decoded.identity_array().unwrap(),
            [11, 22, 33152, 501, 20, 1, 14, 88, 99]
        );
        for boolean in ["true", "false"] {
            let malformed = format!(
                r#"{{"path":"/public/must-not-open.json","sha256":"{}","bytes":1,"identity":[1,1,1,1,1,1,1,1,{boolean}]}}"#,
                "11".repeat(32)
            );
            assert!(json::from_slice::<PublicFile>(malformed.as_bytes()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn malformed_public_file_identity_refuses_before_any_custody_io() {
        for length in [0, 8, 10] {
            let reference = PublicFile {
                // This cannot be a file. Reaching filesystem custody would report a different
                // error; the exact shape error must win before any metadata/open/read call.
                path: "/dev/null/malformed-metadata-must-not-open.json".into(),
                sha256: "11".repeat(32),
                bytes: 1,
                identity: vec![1; length],
            };
            let encoded = json::to_json(&reference).unwrap();
            let decoded: PublicFile = json::from_slice(encoded.as_bytes()).unwrap();
            assert_eq!(decoded.identity.len(), length);
            let error = HeldPublic::open(&decoded).err().unwrap();
            assert_eq!(
                error.to_string(),
                "public input metadata must contain exactly nine integers"
            );
        }
    }

    fn synthetic_peer() -> (Peer, SumeragiFinalityAttestation, NativeFinalityFixture) {
        let fixture = NativeFinalityFixture::new();
        let signer = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
        let node_id = PeerId::new(signer.public_key().clone());
        let body = SumeragiFinalityAttestationBody {
            challenge: [7; 32],
            observed_at_unix_ms: 1_000_000,
            network_id: fixture.network_id(),
            node_fingerprint: Hash::new(node_id.encode()),
            node_id,
            build_fingerprint: Hash::new(b"synthetic compiled build"),
            config_fingerprint: Hash::new(b"synthetic node config"),
            genesis_block_hash: fixture.genesis().hash(),
            genesis_finality_proof: fixture.genesis_proof().clone(),
            status: SumeragiStatus {
                protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
                config_fingerprint: Hash::new(b"synthetic consensus config"),
                beacon_horizon: None,
                instance: fixture.verifier().instance().0,
                height: 3,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: 2,
                applied_height: 2,
                awaiting: false,
                signer: Some(signer.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: SumeragiFootprint::default(),
            },
            finality_proof: fixture.latest().clone(),
        };
        let peer = Peer {
            role: 1,
            peer_id: body.node_id.clone(),
            node_fingerprint: body.node_fingerprint,
            build_fingerprint: body.build_fingerprint,
            node_config_fingerprint: body.config_fingerprint,
            consensus_config_fingerprint: body.status.config_fingerprint,
            challenge: "07".repeat(32),
            read_start_ns: 999_999_000_000,
            read_finish_ns: 1_000_001_000_000,
            attestation: PublicFile {
                path: "/public/synthetic-only.json".into(),
                sha256: "11".repeat(32),
                bytes: 1,
                identity: vec![1; 9],
            },
        };
        let attestation = SumeragiFinalityAttestation {
            signature: SignatureOf::try_from_hash(signer.private_key(), body.signing_hash())
                .unwrap(),
            body,
        };
        (peer, attestation, fixture)
    }

    #[test]
    fn archived_native_peer_checks_original_challenge_window_and_distinct_fingerprints() {
        let (peer, attestation, fixture) = synthetic_peer();
        verify_peer(
            &peer,
            &attestation,
            fixture.network_id(),
            &fixture.verifier(),
        )
        .unwrap();
        for changed in 0..7 {
            let mut peer = peer.clone();
            match changed {
                0 => peer.challenge = "08".repeat(32),
                1 => peer.read_start_ns = 1_000_002_000_000,
                2 => peer.read_finish_ns = 999_998_000_000,
                3 => peer.node_fingerprint = Hash::new(b"foreign node"),
                4 => peer.build_fingerprint = Hash::new(b"foreign build"),
                5 => peer.node_config_fingerprint = peer.consensus_config_fingerprint,
                _ => peer.consensus_config_fingerprint = peer.node_config_fingerprint,
            }
            assert!(
                verify_peer(
                    &peer,
                    &attestation,
                    fixture.network_id(),
                    &fixture.verifier()
                )
                .is_err()
            );
        }
        let other = NativeFinalityFixture::start("foreign synthetic chain");
        assert!(verify_peer(&peer, &attestation, other.network_id(), &other.verifier()).is_err());
    }

    #[test]
    fn archived_tip_requires_the_authenticated_contiguous_prefix() {
        let (peer, attestation, fixture) = synthetic_peer();
        let validators = iroha_genesis::signed_genesis_validator_pops(fixture.genesis())
            .unwrap()
            .into_iter()
            .map(|(public_key, proof_of_possession)| FinalityValidator {
                public_key,
                proof_of_possession,
            })
            .collect();
        let mut verifier =
            SumeragiFinalityVerifier::new(fixture.genesis(), fixture.chain_id(), validators)
                .unwrap();
        verifier.verify(fixture.genesis_proof()).unwrap();
        assert!(verify_peer(&peer, &attestation, fixture.network_id(), &verifier).is_err());
        verifier.verify(fixture.latest()).unwrap();
        verify_peer(&peer, &attestation, fixture.network_id(), &verifier).unwrap();
    }

    #[test]
    fn genesis_discriminant_must_match_the_independent_request() {
        let fixture = NativeFinalityFixture::new();
        let manifest = iroha_genesis::GenesisBuilder::new_without_executor(
            fixture.chain_id().parse().unwrap(),
            ".",
        )
        .with_sumeragi_context_parameters(
            iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
        )
        .build_raw()
        .unwrap()
        .with_chain_discriminant(369);
        verify_manifest_identity(&manifest, fixture.chain_id(), 369).unwrap();
        assert!(verify_manifest_identity(&manifest, fixture.chain_id(), 753).is_err());
        assert!(verify_manifest_identity(&manifest, "foreign chain", 369).is_err());
        let foreign = manifest.with_chain_discriminant(753);
        assert!(verify_manifest_identity(&foreign, fixture.chain_id(), 369).is_err());
    }

    #[test]
    fn independent_pins_and_paths_reject_ambiguous_inputs() {
        for value in ["", &"0".repeat(64), &"AA".repeat(32), &"01".repeat(31)] {
            assert!(pin(value).is_err());
        }
        pin(&"01".repeat(32)).unwrap();
        for path in [
            "relative",
            "/public/../private",
            "/public/./original",
            "/public//original",
            "/public/original/",
        ] {
            assert!(absolute(Path::new(path)).is_err());
        }
        absolute(Path::new("/public/original.json")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn public_custody_rejects_aliases_writable_files_and_retained_byte_drift() {
        use std::os::unix::fs::PermissionsExt as _;
        // Keep the successful custody fixture under safe ancestry. Shared /tmp is intentionally
        // rejected by production, including the usual Linux mode01777 temporary directory.
        let home =
            PathBuf::from(std::env::var_os("HOME").expect("safe owner home for custody test"))
                .canonicalize()
                .unwrap();
        let root = tempfile::Builder::new()
            .prefix(".iroha-retained-network-test-")
            .tempdir_in(home)
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let physical_root = root.path().canonicalize().unwrap();
        let path = physical_root.join("public.original");
        std::fs::write(&path, b"public fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reference = || PublicFile {
            path: path.clone(),
            sha256: hex::encode(Sha256::digest(b"public fixture")),
            bytes: 14,
            identity: identity(&std::fs::symlink_metadata(&path).unwrap())
                .unwrap()
                .to_vec(),
        };
        let held = HeldPublic::open(&reference()).unwrap();
        held.check().unwrap();
        std::fs::write(&path, b"foreign bytes!").unwrap();
        assert!(held.check().is_err());
        drop(held);
        std::fs::write(&path, b"public fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(HeldPublic::open(&reference()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = physical_root.join("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(HeldPublic::open(&reference()).is_err());
        std::fs::remove_file(&hardlink).unwrap();
        let symlink = physical_root.join("symlink");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        let mut aliased = reference();
        aliased.path = symlink;
        assert!(HeldPublic::open(&aliased).is_err());
        std::fs::set_permissions(&physical_root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(HeldPublic::open(&reference()).is_err());
        std::fs::set_permissions(&physical_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
