//! Authenticate a complete native fee accounting window against independent checkpoints.
//! Inputs are canonical Norito artifacts with exact SHA-256 pins. The returned
//! projection contains only finality-authenticated native records; application
//! signatures, provider legal independence and capacity assumptions remain external.
use iroha_data_model::{
    fee_evidence::{FeeEvidenceRecordV1, FeeEvidenceTrustAnchorV1, FeeEvidenceWindowProofV1},
    validation_fee::ValidationFeePolicyRegistryV1,
};
use norito::JsonSerialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::Read,
    path::Path,
    process,
};
const MAX_PROOF_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ANCHOR_BYTES: u64 =
    iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES as u64 + 64 * 1024;
const MAX_CONTRACT_BYTES: u64 = 16 * 1024 * 1024;
#[derive(JsonSerialize)]
struct BlockProjection {
    height: String,
    block_hash: String,
    timestamp_ms: String,
    registry: Option<ValidationFeePolicyRegistryV1>,
    records: Vec<FeeEvidenceRecordV1>,
}
#[derive(JsonSerialize)]
struct Projection {
    version: u16,
    network_id: String,
    blocks: Vec<BlockProjection>,
}
#[derive(JsonSerialize)]
struct Verified {
    schema: String,
    proof_sha256: String,
    trust_anchor_sha256: String,
    network_id: String,
    checks: BTreeMap<String, bool>,
    authenticated_projection: Projection,
}
#[derive(JsonSerialize)]
struct VerifiedContractArtifact {
    sha256: String,
    code_hash_hex: String,
}
#[derive(JsonSerialize)]
struct VerifiedWithContracts {
    schema: String,
    closing_context_id_hex: String,
    registry_snapshot_hash_hex: String,
    proof_sha256: String,
    trust_anchor_sha256: String,
    network_id: String,
    checks: BTreeMap<String, bool>,
    authenticated_projection: Projection,
    verified_contract_artifacts: BTreeMap<String, VerifiedContractArtifact>,
}
fn verify_contract_bytes(bytes: &[u8], expected_code_hash: &[u8; 32]) -> Result<(), String> {
    let verified = ivm::verify_contract_artifact(bytes).map_err(|error| {
        format!("contract artifact is not deployable by this native runtime: {error}")
    })?;
    if verified.code_hash.as_ref() != expected_code_hash {
        return Err(
            "signed contract artifact differs from the finalized governed code hash".into(),
        );
    }
    Ok(())
}
fn read_pinned(path: &str, expected: &str, max: u64) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    if !path.is_absolute()
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("absolute input paths and lowercase SHA-256 pins are required".into());
    }
    let before = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !before.is_file() || before.len() > max {
        return Err("input is not a bounded regular file".into());
    }
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags, open, openat};
        let mut directory = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let components = path.components().skip(1).collect::<Vec<_>>();
        let (last, parents) = components.split_last().ok_or("missing artifact filename")?;
        for component in parents {
            let std::path::Component::Normal(name) = component else {
                return Err("input paths must not contain parent traversal".into());
            };
            directory = openat(
                &directory,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|e| format!("input parent must not be a symbolic link: {e}"))?;
        }
        let std::path::Component::Normal(name) = last else {
            return Err("input must have a regular filename".into());
        };
        File::from(
            openat(
                &directory,
                *name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        )
    };
    #[cfg(not(unix))]
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("input file identity changed during opening".into());
        }
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if !after.is_file()
        || after.len() != opened.len()
        || after.modified().ok() != opened.modified().ok()
    {
        return Err("input file changed during reading".into());
    }
    if bytes.len() as u64 > max || hex::encode(Sha256::digest(&bytes)) != expected {
        return Err("input artifact SHA-256 mismatch".into());
    }
    Ok(bytes)
}
fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if key == "--help" {
            println!(
                "validation_fee_rewards_evidence_verify --proof ABS.nrt --proof-sha256 HEX --trust-anchor ABS.nrt --trust-anchor-sha256 HEX --network-id GENESIS_HASH\nOptional release binding requires all four --pool-artifact ABS.to --pool-sha256 HEX --wrapper-artifact ABS.to --wrapper-sha256 HEX flags. These artifacts must match the finalized closing conversion policy.\nBoth proof artifacts use canonical native Norito. Obtain the opening and closing checkpoints independently; never derive trust inputs from the unverified proof."
            );
            return Ok(());
        }
        if ![
            "--proof",
            "--proof-sha256",
            "--trust-anchor",
            "--trust-anchor-sha256",
            "--network-id",
            "--pool-artifact",
            "--pool-sha256",
            "--wrapper-artifact",
            "--wrapper-sha256",
        ]
        .contains(&key.as_str())
            || options
                .insert(key, arguments.next().ok_or("missing argument value")?)
                .is_some()
        {
            return Err("unknown or duplicate verifier argument".into());
        }
    }
    let value = |name: &str| {
        options
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}"))
    };
    let proof_pin = value("--proof-sha256")?;
    let anchor_pin = value("--trust-anchor-sha256")?;
    let proof_bytes = read_pinned(value("--proof")?, proof_pin, MAX_PROOF_BYTES)?;
    let anchor_bytes = read_pinned(value("--trust-anchor")?, anchor_pin, MAX_ANCHOR_BYTES)?;
    let anchor: FeeEvidenceTrustAnchorV1 = norito::decode_canonical(&anchor_bytes)
        .map_err(|e| format!("noncanonical independent trust anchor: {e}"))?;
    let network = hex::encode(anchor.network_id.as_bytes());
    if value("--network-id")? != network {
        return Err("independent checkpoint network differs from expected network".into());
    }
    let proof: FeeEvidenceWindowProofV1 = norito::decode_canonical(&proof_bytes)
        .map_err(|e| format!("noncanonical native fee proof: {e}"))?;
    proof.verify(&anchor)?;
    let contract_options = [
        "--pool-artifact",
        "--pool-sha256",
        "--wrapper-artifact",
        "--wrapper-sha256",
    ];
    let verify_contracts = contract_options
        .iter()
        .any(|key| options.contains_key(*key));
    let mut closing_context_id_hex = String::new();
    let mut registry_snapshot_hash_hex = String::new();
    let verified_contract_artifacts = if verify_contracts {
        let closing = proof
            .blocks
            .last()
            .ok_or("verified window has no closing block")?;
        let checkpoint = &anchor.opening_checkpoint;
        let mut verifier =
            iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier::from_trusted_checkpoint(
                checkpoint,
                &anchor.network_id,
                checkpoint.chain_id(),
            )
            .map_err(|error| error.to_string())?;
        for (index, block) in proof.blocks.iter().enumerate() {
            let verified = if index == 0 {
                verifier.verify_same_decision(checkpoint.tip(), &block.finality)
            } else {
                verifier.verify(&block.finality)
            }
            .map_err(|error| error.to_string())?;
            closing_context_id_hex = hex::encode(verified.context_id().as_ref());
        }
        registry_snapshot_hash_hex = hex::encode(
            closing
                .registry
                .as_ref()
                .ok_or("closing conversion registry is absent")?
                .snapshot_hash()
                .map_err(|e| e.to_string())?,
        );
        let binding = &closing
            .registry
            .as_ref()
            .ok_or("closing conversion registry is absent")?
            .payout_policies
            .effective_entry_at_height(closing.finality.height())
            .ok_or("closing conversion policy is not finalized")?
            .payout_binding;
        let mut artifacts = BTreeMap::new();
        for (role, path_key, sha_key, expected) in [
            (
                "soraswap_pool",
                "--pool-artifact",
                "--pool-sha256",
                &binding.pool_code_hash,
            ),
            (
                "soraswap_wrapper",
                "--wrapper-artifact",
                "--wrapper-sha256",
                &binding.code_hash,
            ),
        ] {
            let sha256 = value(sha_key)?;
            let bytes = read_pinned(value(path_key)?, sha256, MAX_CONTRACT_BYTES)?;
            verify_contract_bytes(&bytes, expected)?;
            artifacts.insert(
                role.to_owned(),
                VerifiedContractArtifact {
                    sha256: sha256.to_owned(),
                    code_hash_hex: hex::encode(expected),
                },
            );
        }
        Some(artifacts)
    } else {
        None
    };
    let projection = Projection {
        version: 1,
        network_id: network.clone(),
        blocks: proof
            .blocks
            .into_iter()
            .map(|b| BlockProjection {
                height: b.finality.height().to_string(),
                block_hash: hex::encode(b.finality.block_header.hash().as_ref()),
                timestamp_ms: b.header().creation_time().as_millis().to_string(),
                registry: b.registry,
                records: b.evidence.records,
            })
            .collect(),
    };
    let checks = [
        "native_canonical_decoding",
        "network_and_checkpoint",
        "parliament_enactments",
        "receipt_inclusion",
        "conversion_inclusion",
        "original_signed_reference_reports",
        "historical_validator_membership",
        "allocation_inclusion",
        "claim_inclusion",
        "reserved_funding",
        "complete_accounting_window",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), true))
    .collect();
    let result = Verified {
        schema: "iroha.validation_fee_rewards.verified.v1".into(),
        proof_sha256: proof_pin.into(),
        trust_anchor_sha256: anchor_pin.into(),
        network_id: network,
        checks,
        authenticated_projection: projection,
    };
    let output = if let Some(verified_contract_artifacts) = verified_contract_artifacts {
        norito::json::to_json(&VerifiedWithContracts {
            schema: "iroha.validation_fee_rewards.release_verified.v1".into(),
            closing_context_id_hex,
            registry_snapshot_hash_hex,
            proof_sha256: result.proof_sha256,
            trust_anchor_sha256: result.trust_anchor_sha256,
            network_id: result.network_id,
            checks: result.checks,
            authenticated_projection: result.authenticated_projection,
            verified_contract_artifacts,
        })
    } else {
        norito::json::to_json(&result)
    }
    .map_err(|e| e.to_string())?;
    if output.len() > 256 * 1024 * 1024 {
        return Err("authenticated projection exceeds its byte bound".into());
    }
    println!("{output}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("validation fee native proof: {error}");
        process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn release_contract_bytes_must_match_native_full_artifact_hash() {
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source("seiyaku ReleaseContract { view fn value() authorize(anyone) -> int { return 7; } }")
            .unwrap();
        let expected: [u8; 32] = ivm::contract_code_hash(&bytes).into();
        super::verify_contract_bytes(&bytes, &expected).unwrap();
        assert!(super::verify_contract_bytes(&bytes, &[0x42; 32]).is_err());
        assert!(super::verify_contract_bytes(&bytes[..4], &expected).is_err());

        let parsed = ivm::ProgramMetadata::parse(&bytes).unwrap();
        let mut interface = parsed.contract_interface.unwrap();
        let original_section = interface.encode_section();
        let section_end = parsed.header_len + original_section.len();
        assert_eq!(&bytes[parsed.header_len..section_end], &original_section);
        interface.abi_hash[0] ^= 1;
        let changed_section = interface.encode_section();
        assert_eq!(changed_section.len(), original_section.len());
        // Preserve the compiler's debug/literal sections and their absolute
        // offsets. Only the independently checked interface ABI is changed.
        let mut wrong_abi = bytes.clone();
        wrong_abi[parsed.header_len..section_end].copy_from_slice(&changed_section);
        assert!(
            ivm::ProgramMetadata::parse(&wrong_abi).is_ok(),
            "metadata parsing alone cannot authenticate the runtime ABI"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("wrong-abi.to");
        fs::write(&path, &wrong_abi).unwrap();
        let exact_sha = hex::encode(Sha256::digest(&wrong_abi));
        let checked = read_pinned(path.to_str().unwrap(), &exact_sha, 1024 * 1024).unwrap();
        let exact_code_hash: [u8; 32] = ivm::contract_code_hash(&checked).into();
        let error = super::verify_contract_bytes(&checked, &exact_code_hash).unwrap_err();
        assert!(error.contains("abi_hash"), "unexpected error: {error}");
    }
    use super::*;
    #[test]
    fn pinned_input_rejects_changed_bytes_and_symbolic_links() {
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().canonicalize().unwrap();
        let path = directory.join("proof.nrt");
        fs::write(&path, b"canonical artifact").unwrap();
        let pin = hex::encode(Sha256::digest(b"canonical artifact"));
        assert_eq!(
            read_pinned(path.to_str().unwrap(), &pin, 100).unwrap(),
            b"canonical artifact"
        );
        fs::write(&path, b"different artifact").unwrap();
        assert!(read_pinned(path.to_str().unwrap(), &pin, 100).is_err());
        #[cfg(unix)]
        {
            let link = directory.join("link.nrt");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_pinned(link.to_str().unwrap(), &pin, 100).is_err());
            let parent_link = directory.join("linked-directory");
            std::os::unix::fs::symlink(&directory, &parent_link).unwrap();
            assert!(
                read_pinned(parent_link.join("proof.nrt").to_str().unwrap(), &pin, 100).is_err()
            );
        }
    }
}
