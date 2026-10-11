//! Produce the complete current wallet artifact graph using genuine native sources.
//!
//! This offline tool constructs and signs packaging originals. It performs no ledger
//! registration, release admission, installation, wallet opening or financial operation.
//! The deployment owner independently authenticates the selected genesis, source build,
//! public role keys and final output before admitting any of these packaging bytes.

use std::{collections::BTreeMap, io, io::Read, io::Write, path::Path, str::FromStr};

use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1,
    producer_inventory::{
        BlobV1, DirectoryOriginalsV1, OfflineCompilerV1, OriginalSourceV1,
        PROVING_KEY_MAX_BYTES_V1, SourceScopeV1, WalletArtifactDraftV1,
    },
};
use iroha_crypto::{Algorithm, PublicKey};
use iroha_data_model::{
    NetworkId,
    block::decode_framed_signed_block,
    kagemusha::kagemusha_wallet_v1::*,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, authenticated_genesis},
};
use iroha_fs::{FileSnapshot, PrivateDirectory, SealedPrivateFile};
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::keys::{CosetCachePolicy, pk::artifact::ReadConfig};
use iroha_plonk_gadgets::p256::native::{Affine, words_from_be};
use norito::json::{self, JsonDeserialize};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::DecodePrivateKey,
};
use sha2::{Digest as _, Sha256};

const REQUEST_MAX: usize = 65_536;
const GENESIS_MAX: usize = 64 << 20;
const OUTPUT_MAX: u64 = 128 << 30;

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OriginalInput {
    path: String,
    sha256: String,
}

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Request {
    schema: String,
    chain_id: String,
    network_id_hex: String,
    genesis_public_key: String,
    signed_genesis: OriginalInput,
    custody_directory: String,
    scheme_root_public_key_hex: String,
    enrollment_public_key_hex: String,
    artifact_public_key_hex: String,
    output_parent: String,
    output_name: String,
    maximum_total_bytes: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checked<T, E>(value: Result<T, E>, message: &'static str) -> io::Result<T> {
    value.map_err(|_| invalid(message))
}

fn digest(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("digest must contain 64 lowercase hex digits"));
    }
    let value: [u8; 32] = checked(
        checked(hex::decode(value), "digest encoding")?.try_into(),
        "digest extent",
    )?;
    if value == [0; 32] {
        return Err(invalid("zero digest"));
    }
    Ok(value)
}

fn point(value: &str) -> io::Result<KagemushaDevicePublicKeyV1> {
    if value.len() != 130
        || !value.starts_with("04")
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "role key requires an uncompressed lowercase P256 point",
        ));
    }
    checked(
        KagemushaDevicePublicKeyV1::from_sec1_bytes(&checked(
            hex::decode(value),
            "role key encoding",
        )?),
        "invalid role key",
    )
}

struct Original {
    directory: PrivateDirectory,
    file: SealedPrivateFile,
    snapshot: FileSnapshot,
    bytes: Vec<u8>,
}

impl Original {
    fn open(path: &str, maximum: usize, pin: Option<[u8; 32]>) -> io::Result<Self> {
        let path = Path::new(path);
        let directory = PrivateDirectory::open_exact(
            path.parent()
                .ok_or_else(|| invalid("original parent missing"))?,
        )?;
        let mut file = directory.open_retained_read_only(
            path.file_name()
                .ok_or_else(|| invalid("original name missing"))?,
            maximum,
        )?;
        let snapshot = file.snapshot()?;
        let length = usize::try_from(file.len()?).map_err(|_| invalid("original extent"))?;
        if length == 0 || length > maximum {
            return Err(invalid("original extent"));
        }
        let mut bytes = Vec::with_capacity(length);
        (&mut file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() != length || pin.is_some_and(|pin| BlobV1::of(&bytes).sha256 != pin) {
            return Err(invalid("original extent or hash changed"));
        }
        let original = Self {
            directory,
            file,
            snapshot,
            bytes,
        };
        original.recheck()?;
        Ok(original)
    }

    fn recheck(&self) -> io::Result<()> {
        self.directory.revalidate()?;
        self.file.revalidate()?;
        if self.file.snapshot()? != self.snapshot {
            return Err(invalid("retained original changed"));
        }
        Ok(())
    }
}

fn parse_request(bytes: &[u8]) -> io::Result<Request> {
    let request: Request = checked(json::from_slice(bytes), "closed request schema required")?;
    if request.schema != "iroha.kagemusha.wallet-artifact-production.v1"
        || request.chain_id.is_empty()
        || request.chain_id.len() > 256
        || request.maximum_total_bytes == 0
        || request.maximum_total_bytes > OUTPUT_MAX
        || request.output_name.is_empty()
        || request.output_name.len() > 128
        || !request
            .output_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid("unsupported production request or resource limit"));
    }
    digest(&request.network_id_hex)?;
    digest(&request.signed_genesis.sha256)?;
    let keys = [
        point(&request.scheme_root_public_key_hex)?,
        point(&request.enrollment_public_key_hex)?,
        point(&request.artifact_public_key_hex)?,
    ];
    if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
        return Err(invalid(
            "scheme, enrollment and artifact keys must be distinct",
        ));
    }
    Ok(request)
}

fn native_finality(
    chain_id: &str,
    network_id_hex: &str,
    genesis_public_key: &str,
    original: &[u8],
) -> io::Result<SumeragiFinalityVerifier> {
    let genesis = checked(
        decode_framed_signed_block(original),
        "canonical signed genesis required",
    )?;
    let public = checked(
        PublicKey::from_str(genesis_public_key),
        "genesis public key",
    )?;
    if public.algorithm() != Algorithm::Ed25519
        || genesis
            .external_transactions()
            .next()
            .and_then(|t| t.authority().try_signatory())
            != Some(&public)
        || *NetworkId::from_genesis_hash(genesis.hash()).as_bytes() != digest(network_id_hex)?
    {
        return Err(invalid(
            "genesis differs from selected network or authority",
        ));
    }
    // The maintained reader authenticates block/transaction signatures, proposal
    // commitments, the complete signed initial epoch and every validator PoP.
    let epoch = checked(
        authenticated_genesis(&genesis).map(|genesis| genesis.into_parts().0),
        "signed genesis authority rejected",
    )?;
    let roster = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    checked(
        SumeragiFinalityVerifier::new(&genesis, chain_id, roster),
        "genesis verifier rejected",
    )
}

fn scope(key: KagemushaDevicePublicKeyV1) -> io::Result<SourceScopeV1> {
    let key = key.as_sec1_bytes();
    let provider = kagemusha_wallet_provider_contract_v1();
    checked(
        SourceScopeV1::new(
            [
                u128::from_le_bytes(provider[..16].try_into().expect("fixed provider")),
                u128::from_le_bytes(provider[16..].try_into().expect("fixed provider")),
            ],
            Affine {
                x: words_from_be(key[1..33].try_into().expect("validated point")),
                y: words_from_be(key[33..65].try_into().expect("validated point")),
            },
        ),
        "invalid source scope",
    )
}

/// Copy only identities returned by the completed signed catalog. The compiler
/// cache may contain provisional sources and is never the transport directory.
fn copy_closed(
    source: &DirectoryOriginalsV1,
    target: &PrivateDirectory,
    selected: &[BlobV1],
) -> io::Result<()> {
    if selected.is_empty() || !target.entries(1)?.is_empty() {
        return Err(invalid(
            "closed carrier requires selected originals and a fresh directory",
        ));
    }
    let mut identities = BTreeMap::new();
    for blob in selected {
        if blob.bytes == 0
            || blob.bytes > PROVING_KEY_MAX_BYTES_V1 as u64
            || blob.sha256 == [0; 32]
            || identities.insert(blob.sha256, *blob).is_some()
        {
            return Err(invalid("invalid or duplicate closed carrier identity"));
        }
    }
    for blob in selected {
        source.verify_original(*blob)?;
        let name = hex::encode(blob.sha256);
        let mut reader = source
            .open_original(blob.sha256)
            .map_err(io::Error::other)?;
        let mut writer = target.create_retained_private(
            format!("{name}.partial"),
            usize::try_from(blob.bytes).map_err(|_| invalid("original extent"))?,
        )?;
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|length| *length <= blob.bytes)
                .ok_or_else(|| invalid("original grew during carrier export"))?;
            hash.update(&buffer[..count]);
            writer.write_all(&buffer[..count])?;
        }
        let actual: [u8; 32] = hash.finalize().into();
        if total != blob.bytes || actual != blob.sha256 {
            return Err(invalid("original changed during carrier export"));
        }
        source.verify_original(*blob)?;
        writer
            .seal_read_only()?
            .publish_new_name(name)?
            .revalidate()?;
    }
    target.sync()
}

struct CompleteSource<'a> {
    wallet: &'a DirectoryOriginalsV1,
    wallet_blobs: &'a BTreeMap<[u8; 32], BlobV1>,
}
impl OriginalSourceV1 for CompleteSource<'_> {
    fn open(
        &mut self,
        digest: [u8; 32],
    ) -> Result<Box<dyn Read + '_>, iroha_core_zk::kagemusha_wallet_proofs_v1::Error> {
        use iroha_core_zk::kagemusha_wallet_proofs_v1::Error;
        let source = self.wallet;
        let blob = self.wallet_blobs.get(&digest).ok_or(Error::Inventory)?;
        source.verify_original(*blob).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput
            ) {
                Error::Inventory
            } else {
                Error::Unavailable
            }
        })?;
        source.open_original(digest)
    }
}

fn publish(directory: &PrivateDirectory, name: &str, bytes: &[u8]) -> io::Result<()> {
    let staging = format!("{name}.partial");
    let mut writer = directory.create_retained_private(&staging, bytes.len())?;
    writer.write_all(bytes)?;
    writer
        .seal_read_only()?
        .publish_new_name(name)?
        .revalidate()?;
    directory.sync()
}

fn private_key(
    directory: &PrivateDirectory,
    name: &str,
    expected: KagemushaDevicePublicKeyV1,
) -> io::Result<SigningKey> {
    let original = directory.read(name, 4_096)?;
    let key = checked(
        SigningKey::from_pkcs8_der(&original),
        "P256 private custody rejected",
    )?;
    if key.verifying_key().to_encoded_point(false).as_bytes() != expected.as_sec1_bytes() {
        return Err(invalid(
            "private custody differs from independent public role",
        ));
    }
    // Original buffers are zeroized by the retained filesystem owner. SigningKey
    // owns its secret scalar and zeroizes it on drop; it is never formatted/logged.
    directory.revalidate()?;
    Ok(key)
}

fn signature(key: &SigningKey, message: &[u8; 32]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: Signature = key.sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}

fn certificate(
    scheme: &KagemushaWalletSchemeV1,
    root: &SigningKey,
    key: KagemushaDevicePublicKeyV1,
    role: KagemushaWalletSignerRoleV1,
) -> io::Result<KagemushaWalletSignerCertificateV1> {
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: scheme.scheme_id(),
        role,
        key,
        serial: 1,
    };
    checked(
        KagemushaWalletSignerCertificateV1::sign(
            body,
            scheme,
            signature(root, &body.signing_message()),
        ),
        "protocol certificate signing rejected",
    )
}

fn finish(
    request: &Request,
    draft: WalletArtifactDraftV1,
    output: &PrivateDirectory,
    wallet: &DirectoryOriginalsV1,
    native: &SumeragiFinalityVerifier,
    config: ReadConfig,
) -> io::Result<()> {
    let custody = PrivateDirectory::open_exact(&request.custody_directory)?;
    let root = private_key(
        &custody,
        "scheme-root.pkcs8.der",
        point(&request.scheme_root_public_key_hex)?,
    )?;
    let artifact = private_key(
        &custody,
        "artifact.pkcs8.der",
        point(&request.artifact_public_key_hex)?,
    )?;
    let scheme = *draft.scheme();
    let artifact_certificate = certificate(
        &scheme,
        &root,
        point(&request.artifact_public_key_hex)?,
        KagemushaWalletSignerRoleV1::Artifact,
    )?;
    let enrollment_certificate = certificate(
        &scheme,
        &root,
        point(&request.enrollment_public_key_hex)?,
        KagemushaWalletSignerRoleV1::Enrollment,
    )?;
    let certificate_original = checked(
        artifact_certificate.to_canonical_bytes(),
        "artifact certificate encoding",
    )?;
    let body = checked(
        draft.manifest_body(&certificate_original),
        "compiler manifest body rejected",
    )?;
    let manifest = checked(
        KagemushaWalletArtifactManifestV1::sign(
            body,
            &artifact_certificate,
            signature(&artifact, &body.signing_message()),
        ),
        "protocol manifest signing rejected",
    )?;
    let manifest_original = checked(manifest.to_canonical_bytes(), "manifest encoding")?;
    custody.revalidate()?;
    let installation = InstallationV1 {
        scheme_id: scheme.scheme_id(),
        manifest_digest: manifest.manifest_digest(),
    };
    let originals = checked(
        draft.finish(&certificate_original, &manifest_original),
        "complete signed pack rejected",
    )?;
    publish(
        output,
        "scheme.norito",
        &checked(scheme.to_canonical_bytes(), "scheme encoding")?,
    )?;
    publish(
        output,
        "enrollment-certificate.norito",
        &checked(
            enrollment_certificate.to_canonical_bytes(),
            "enrollment certificate encoding",
        )?,
    )?;
    publish(output, "artifact-certificate.norito", &certificate_original)?;
    publish(output, "artifact-manifest.norito", &manifest_original)?;
    let carrier = output.create_child("carrier")?;
    let carrier_wallet_directory = carrier.create_child("wallet-originals")?;
    copy_closed(
        wallet,
        &carrier_wallet_directory,
        originals.wallet_originals(),
    )?;
    let carrier_wallet = DirectoryOriginalsV1::open_existing(
        carrier_wallet_directory.path(),
        PROVING_KEY_MAX_BYTES_V1,
    )?;
    let installed = checked(
        InstalledVerifierPackV1::load(originals.verifier_pack(), installation),
        "generated verifier pack rejected",
    )?;
    let authenticated = checked(
        installed.authenticate_producer_inventory(originals.producer_inventory()),
        "signed producer inventory rejected",
    )?;
    let wallet_blobs = originals
        .wallet_originals()
        .iter()
        .map(|blob| (blob.sha256, *blob))
        .collect();
    let mut combined = CompleteSource {
        wallet: &carrier_wallet,
        wallet_blobs: &wallet_blobs,
    };
    let qualified = authenticated
        .qualify_wallet(&installed, native, &mut combined, config)
        .map_err(io::Error::other)?;
    if qualified.installation() != (installation.scheme_id, installation.manifest_digest) {
        return Err(invalid(
            "qualified graph changed signed installation identity",
        ));
    }
    originals.write_bundle_metadata(carrier.path(), &carrier_wallet)?;
    custody.revalidate()?;
    Ok(())
}

fn run(path: &str) -> io::Result<()> {
    let request_original = Original::open(path, REQUEST_MAX, None)?;
    let request = parse_request(&request_original.bytes)?;
    let genesis = Original::open(
        &request.signed_genesis.path,
        GENESIS_MAX,
        Some(digest(&request.signed_genesis.sha256)?),
    )?;
    let native = native_finality(
        &request.chain_id,
        &request.network_id_hex,
        &request.genesis_public_key,
        &genesis.bytes,
    )?;
    request_original.recheck()?;
    genesis.recheck()?;
    let parent = PrivateDirectory::open_exact(&request.output_parent)?;
    let output = parent.create_child(&request.output_name)?;
    let wallet_directory = output.create_child("compiler-cache")?;
    let mut wallet =
        DirectoryOriginalsV1::open_existing(wallet_directory.path(), PROVING_KEY_MAX_BYTES_V1)?;
    publish(&output, "request.json", &request_original.bytes)?;
    publish(&output, "signed-genesis.norito", &genesis.bytes)?;
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    eprintln!(
        "Compiling the complete native wallet graph; partial originals remain preserved on failure."
    );
    let mut compiler = checked(
        OfflineCompilerV1::new(
            scope(point(&request.scheme_root_public_key_hex)?)?,
            &mut wallet,
            config,
            request.maximum_total_bytes,
        ),
        "wallet compiler configuration",
    )?;
    let draft = compiler
        .wallet_pack(*native.initial_epoch().network_id.as_bytes())
        .map_err(io::Error::other)?;
    drop(compiler);
    request_original.recheck()?;
    genesis.recheck()?;
    publish(
        &output,
        "unsigned-producer-inventory.norito",
        draft.producer_inventory(),
    )?;
    finish(&request, draft, &output, &wallet, &native, config)?;
    request_original.recheck()?;
    genesis.recheck()?;
    output.sync()?;
    println!(
        "Complete signed artifact originals written to {}. Installation, release admission and financial execution remain separate.",
        output.path().display()
    );
    Ok(())
}

fn main() {
    // The compiler inherits owner-only modes for temporary artifact originals.
    #[cfg(unix)]
    let _previous_mask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [help] if help == "--help" => {
            println!(
                "kagemusha_wallet_artifacts --request ABSOLUTE_IMMUTABLE_PUBLIC_JSON\nConstructs native wallet originals and signs protocol certificates/manifest using the selected private recovery role keys. Finality uses direct BLS verification and needs no proof artifacts. No network actions."
            );
            Ok(())
        }
        [flag, path] if flag == "--request" => run(path),
        _ => Err(invalid(
            "usage: kagemusha_wallet_artifacts --request ABSOLUTE_IMMUTABLE_PUBLIC_JSON",
        )),
    };
    if let Err(error) = result {
        eprintln!("Wallet artifact production failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "kagemusha_wallet_artifacts/tests.rs"]
mod tests;
