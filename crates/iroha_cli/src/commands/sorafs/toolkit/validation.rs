//! Local SoraFS artifact validation, signing and release evidence.
//!
//! Command arguments belong to the canonical CLI; artifact validators, wire types and
//! cryptographic verification remain in their reusable library owners.
mod args;
pub mod final_promotion_receipt;
pub mod release_manifest_receipt;
pub use args::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroha_crypto::sha256;
use norito::json;
use sorafs_manifest::{
    AdvertSignature, FixtureBundlePayloadKindV1, FixtureBundlePayloadV1, GovernanceLogNodeV1,
    GovernanceLogSignatureV1, GovernanceSignatureAlgorithm, HedgingValidationPayloadKindV1,
    ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1, OrderbookValidationPayloadKindV1,
    POP_REFERENCE_PAYLOAD_MAX_BYTES_V1, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1,
    PopValidationPayloadKindV1, ProofStreamTier, ProviderAdvertV1, RepairValidationPayloadKindV1,
    ReplicationOrderSignatureV1, ReplicationOrderV1, SIGNED_REPLICATION_ORDER_VERSION_V1,
    SignatureAlgorithm, SignedReplicationOrderV1, ValidationContextFieldV1, ValidationInputV1,
    ValidationOutcomeV1, decode_order_cancel_v1, decode_order_request_v1,
    decode_provider_advert_v1, decode_settlement_receipt_v1, sign_order_cancel_ed25519_v1,
    sign_order_request_ed25519_v1, sign_settlement_receipt_ed25519_v1,
    validate_fixture_bundle_payloads, validate_governance_dag_block_bytes,
    validate_governance_dag_head_chain_bytes, validate_governance_log_node_bytes,
    validate_hedging_payload_bytes, validate_orderbook_payload_bytes, validate_pdp_challenge_bytes,
    validate_pdp_challenge_proof_bytes, validate_pdp_commitment_bytes,
    validate_pdp_commitment_challenge_bytes, validate_pdp_commitment_challenge_proof_bytes,
    validate_pdp_proof_bytes, validate_pop_payload_bytes, validate_por_challenge_proof_bytes,
    validate_potr_receipt_bytes, validate_provider_admission_envelope_bytes,
    validate_provider_admission_renewal_bytes, validate_provider_admission_revocation_bytes,
    validate_provider_advert_bytes, validate_repair_payload_bytes,
    validate_replication_order_bytes, validate_signed_replication_order_bytes,
};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

fn run_advert(args: AdvertArgs) -> Result<ExitCode, CliError> {
    let input = args.input.ok_or(CliError::Config(
        "advert requires --input <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let now = match args.now {
        Some(now) => now,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = read_cli_bytes_bounded(&input, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1)?;
    let outcome =
        validate_provider_advert_bytes(&bytes, input.display().to_string(), now, generated_at);
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_admission(args: AdmissionArgs) -> Result<ExitCode, CliError> {
    let input = args.input.ok_or(CliError::Config(
        "admission requires --input <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = fs::read(&input)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", input.display())))?;
    let outcome = if let Some(renewal) = args.renewal {
        let renewal_bytes = fs::read(&renewal)
            .map_err(|err| CliError::Io(format!("failed to read {}: {err}", renewal.display())))?;
        validate_provider_admission_renewal_bytes(
            &bytes,
            &renewal_bytes,
            input.display().to_string(),
            renewal.display().to_string(),
            generated_at,
        )
    } else if let Some(revocation) = args.revocation {
        let revocation_bytes = fs::read(&revocation).map_err(|err| {
            CliError::Io(format!("failed to read {}: {err}", revocation.display()))
        })?;
        validate_provider_admission_revocation_bytes(
            &bytes,
            &revocation_bytes,
            input.display().to_string(),
            revocation.display().to_string(),
            generated_at,
        )
    } else {
        validate_provider_admission_envelope_bytes(
            &bytes,
            input.display().to_string(),
            generated_at,
        )
    };
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_order(args: OrderArgs) -> Result<ExitCode, CliError> {
    let input = args.order.ok_or(CliError::Config(
        "order requires --order <path> or --signed-order <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = fs::read(&input)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", input.display())))?;
    let outcome = if args.signed {
        validate_signed_replication_order_bytes(&bytes, input.display().to_string(), generated_at)
    } else {
        validate_replication_order_bytes(&bytes, input.display().to_string(), generated_at)
    };
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_orderbook(args: OrderbookArgs) -> Result<ExitCode, CliError> {
    let input = args.input.ok_or(CliError::Config(
        "orderbook requires --input <path>".to_owned(),
    ))?;
    let kind = args.kind.ok_or(CliError::Config(
        "orderbook requires --kind <payload-kind>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = read_cli_bytes_bounded(&input, ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1)?;
    let outcome =
        validate_orderbook_payload_bytes(kind, &bytes, input.display().to_string(), generated_at);
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_pop(args: PopArgs) -> Result<ExitCode, CliError> {
    let input = args
        .input
        .ok_or(CliError::Config("pop requires --input <path>".to_owned()))?;
    let kind = args.kind.ok_or(CliError::Config(
        "pop requires --kind <payload-kind>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = read_cli_bytes_bounded(&input, POP_REFERENCE_PAYLOAD_MAX_BYTES_V1)?;
    let outcome =
        validate_pop_payload_bytes(kind, &bytes, input.display().to_string(), generated_at);
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_hedging(args: HedgingArgs) -> Result<ExitCode, CliError> {
    let input = args.input.ok_or(CliError::Config(
        "hedging requires --input <path>".to_owned(),
    ))?;
    let kind = args.kind.ok_or(CliError::Config(
        "hedging requires --kind <payload-kind>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = fs::read(&input)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", input.display())))?;
    let outcome =
        validate_hedging_payload_bytes(kind, &bytes, input.display().to_string(), generated_at);
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_pdp(args: PdpArgs) -> Result<ExitCode, CliError> {
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let outcome = match (&args.commitment, &args.challenge, &args.proof) {
        (None, None, None) => {
            return Err(CliError::Config(
                "pdp requires at least one of --commitment, --challenge, or --proof".to_owned(),
            ));
        }
        (Some(_commitment), None, Some(_)) => {
            return Err(CliError::Config(
                "pdp requires --challenge when validating --commitment with --proof".to_owned(),
            ));
        }
        (Some(commitment), Some(challenge), Some(proof)) => {
            let commitment_bytes = read_cli_bytes(commitment)?;
            let challenge_bytes = read_cli_bytes(challenge)?;
            let proof_bytes = read_cli_bytes(proof)?;
            validate_pdp_commitment_challenge_proof_bytes(
                &commitment_bytes,
                &challenge_bytes,
                &proof_bytes,
                commitment.display().to_string(),
                challenge.display().to_string(),
                proof.display().to_string(),
                generated_at,
            )
        }
        (Some(commitment), Some(challenge), None) => {
            let commitment_bytes = read_cli_bytes(commitment)?;
            let challenge_bytes = read_cli_bytes(challenge)?;
            validate_pdp_commitment_challenge_bytes(
                &commitment_bytes,
                &challenge_bytes,
                commitment.display().to_string(),
                challenge.display().to_string(),
                generated_at,
            )
        }
        (None, Some(challenge), Some(proof)) => {
            let challenge_bytes = read_cli_bytes(challenge)?;
            let proof_bytes = read_cli_bytes(proof)?;
            validate_pdp_challenge_proof_bytes(
                &challenge_bytes,
                &proof_bytes,
                challenge.display().to_string(),
                proof.display().to_string(),
                generated_at,
            )
        }
        (Some(commitment), None, None) => {
            let commitment_bytes = read_cli_bytes(commitment)?;
            validate_pdp_commitment_bytes(
                &commitment_bytes,
                commitment.display().to_string(),
                generated_at,
            )
        }
        (None, Some(challenge), None) => {
            let challenge_bytes = read_cli_bytes(challenge)?;
            validate_pdp_challenge_bytes(
                &challenge_bytes,
                challenge.display().to_string(),
                generated_at,
            )
        }
        (None, None, Some(proof)) => {
            let proof_bytes = read_cli_bytes(proof)?;
            validate_pdp_proof_bytes(&proof_bytes, proof.display().to_string(), generated_at)
        }
    };
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn read_cli_bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|err| CliError::Io(format!("failed to read {}: {err}", path.display())))
}
fn read_cli_bytes_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, CliError> {
    let maximum_u64 = u64::try_from(maximum_bytes)
        .map_err(|_| CliError::Internal("CLI byte ceiling exceeds u64".to_owned()))?;
    let mut options = OpenOptions::new();
    options.read(true);
    set_release_no_follow(&mut options);
    let mut file = options
        .open(path)
        .map_err(|err| CliError::Io(format!("failed to open {}: {err}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|err| CliError::Io(format!("failed to inspect {}: {err}", path.display())))?;
    if !metadata.is_file() {
        return Err(CliError::Validation(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum_u64 {
        return Err(CliError::Validation(format!(
            "{} exceeds the {maximum_bytes}-byte input ceiling",
            path.display()
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| CliError::Validation(format!("{} is too large", path.display())))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", path.display())))?;
    if bytes.len() > maximum_bytes {
        return Err(CliError::Validation(format!(
            "{} exceeds the {maximum_bytes}-byte input ceiling",
            path.display()
        )));
    }
    Ok(bytes)
}
fn run_por(args: PorArgs) -> Result<ExitCode, CliError> {
    let challenge = args.challenge.ok_or(CliError::Config(
        "por requires --challenge <path>".to_owned(),
    ))?;
    let proof = args
        .proof
        .ok_or(CliError::Config("por requires --proof <path>".to_owned()))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let challenge_bytes = fs::read(&challenge)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", challenge.display())))?;
    let proof_bytes = fs::read(&proof)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", proof.display())))?;
    let outcome = validate_por_challenge_proof_bytes(
        &challenge_bytes,
        &proof_bytes,
        challenge.display().to_string(),
        proof.display().to_string(),
        generated_at,
    );
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_potr(args: PotrArgs) -> Result<ExitCode, CliError> {
    let receipt = args.receipt.ok_or(CliError::Config(
        "potr requires --receipt <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = fs::read(&receipt)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", receipt.display())))?;
    let outcome = validate_potr_receipt_bytes(
        &bytes,
        receipt.display().to_string(),
        args.profile,
        generated_at,
    );
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_repair(args: RepairArgs) -> Result<ExitCode, CliError> {
    let input = args.input.ok_or(CliError::Config(
        "repair requires --input <path>".to_owned(),
    ))?;
    let kind = args.kind.ok_or(CliError::Config(
        "repair requires --kind <payload-kind>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let bytes = fs::read(&input)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", input.display())))?;
    let outcome =
        validate_repair_payload_bytes(kind, &bytes, input.display().to_string(), generated_at);
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_bundle(args: BundleArgs) -> Result<ExitCode, CliError> {
    let bundle = args.bundle.ok_or(CliError::Config(
        "bundle requires --bundle <directory>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let now = match args.now {
        Some(now) => now,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let payloads = read_bundle_payloads(&bundle)?;
    let borrowed = payloads
        .iter()
        .map(|payload| {
            FixtureBundlePayloadV1::new(
                payload.kind,
                payload.label.clone(),
                payload.bytes.as_slice(),
            )
        })
        .collect::<Vec<_>>();
    let outcome = validate_fixture_bundle_payloads(&borrowed, now, generated_at);
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_governance(args: GovernanceArgs) -> Result<ExitCode, CliError> {
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let modes = usize::from(args.node.is_some())
        + usize::from(args.block.is_some())
        + usize::from(args.head.is_some());
    if modes != 1 {
        return Err(CliError::Config(
            "governance requires exactly one of --node <path>, --block <path>, or --head <path>"
                .to_owned(),
        ));
    }
    let outcome = if let Some(node) = args.node {
        if !args.blocks.is_empty() {
            return Err(CliError::Config(
                "governance --node does not accept additional --block inputs".to_owned(),
            ));
        }
        let bytes = fs::read(&node)
            .map_err(|err| CliError::Io(format!("failed to read {}: {err}", node.display())))?;
        let cid = args.cid.as_deref().ok_or(CliError::Config(
            "governance --node requires --cid <node-cid>".to_owned(),
        ))?;
        let expected_cid = parse_cid_arg_bytes(cid)?;
        validate_governance_log_node_bytes(
            &bytes,
            node.display().to_string(),
            Some(expected_cid.as_slice()),
            generated_at,
        )
    } else if let Some(block) = args.block {
        if !args.blocks.is_empty() {
            return Err(CliError::Config(
                "governance --block validates one block; use --head with repeated --block inputs for chain validation"
                    .to_owned(),
            ));
        }
        let bytes = fs::read(&block)
            .map_err(|err| CliError::Io(format!("failed to read {}: {err}", block.display())))?;
        let expected_cid = args.cid.as_deref().map(parse_cid_arg_bytes).transpose()?;
        validate_governance_dag_block_bytes(
            &bytes,
            block.display().to_string(),
            expected_cid.as_deref(),
            generated_at,
        )
    } else if let Some(head) = args.head {
        if args.blocks.is_empty() {
            return Err(CliError::Config(
                "governance --head requires at least one --block <path>".to_owned(),
            ));
        }
        if args.cid.is_some() {
            return Err(CliError::Config(
                "governance --head does not accept --cid; the signed head carries the expected block CID"
                    .to_owned(),
            ));
        }
        let head_bytes = fs::read(&head)
            .map_err(|err| CliError::Io(format!("failed to read {}: {err}", head.display())))?;
        let mut block_payloads = Vec::with_capacity(args.blocks.len());
        for block in &args.blocks {
            let bytes = fs::read(block).map_err(|err| {
                CliError::Io(format!("failed to read {}: {err}", block.display()))
            })?;
            block_payloads.push((bytes, block.display().to_string()));
        }
        let refs: Vec<(&[u8], String)> = block_payloads
            .iter()
            .map(|(bytes, label)| (bytes.as_slice(), label.clone()))
            .collect();
        validate_governance_dag_head_chain_bytes(
            &head_bytes,
            head.display().to_string(),
            &refs,
            generated_at,
        )
    } else {
        unreachable!("governance mode count checked above")
    };
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
const RELEASE_MANIFEST_MAX_BYTES: u64 = 1024 * 1024;

pub(super) fn run_release_manifest(args: ReleaseManifestArgs) -> Result<ExitCode, CliError> {
    let manifest_path = args.manifest.ok_or(CliError::Config(
        "release-manifest requires --manifest <path>".to_owned(),
    ))?;
    let public_key_path = args.public_key.ok_or(CliError::Config(
        "release-manifest requires --public-key <path>".to_owned(),
    ))?;
    let fingerprint_text = args.public_key_fingerprint.ok_or(CliError::Config(
        "release-manifest requires --public-key-fingerprint <hex>".to_owned(),
    ))?;
    let reviewed_fingerprint = parse_release_fingerprint(&fingerprint_text)?;
    let manifest = read_release_input(
        &manifest_path,
        "release manifest",
        RELEASE_MANIFEST_MAX_BYTES,
        None,
        false,
    )?;
    let public_key_bytes = read_release_input(
        &public_key_path,
        "release manifest public key",
        32,
        Some(32),
        false,
    )?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .expect("exact public key length checked above");
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(CliError::Validation(
            "release manifest public key must not be all zero".to_owned(),
        ));
    }
    let actual_fingerprint = sha256(public_key);
    if actual_fingerprint != reviewed_fingerprint {
        return Err(CliError::Validation(
            "release manifest public key does not match the reviewed fingerprint".to_owned(),
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        CliError::Validation("release manifest public key is not valid Ed25519".to_owned())
    })?;
    if verifying_key.is_weak() {
        return Err(CliError::Validation(
            "release manifest public key must not be weak or small-order".to_owned(),
        ));
    }
    match (
        args.signature,
        args.signing_seed,
        args.signature_out,
        args.development_local_signing,
    ) {
        (Some(signature_path), None, None, false) => {
            let signature_bytes = read_release_input(
                &signature_path,
                "release manifest signature",
                64,
                Some(64),
                false,
            )?;
            let signature_bytes: [u8; 64] = signature_bytes
                .try_into()
                .expect("exact signature length checked above");
            verify_release_signature(&verifying_key, &manifest, &signature_bytes)?;
            println!(
                "release manifest Ed25519 signature verified\npublic_key_fingerprint_sha256={}",
                hex::encode(actual_fingerprint)
            );
            Ok(ExitCode::SUCCESS)
        }
        (None, Some(seed_path), Some(signature_out), true) => {
            let seed_bytes = read_release_input(
                &seed_path,
                "release manifest development signing seed",
                32,
                Some(32),
                true,
            )?;
            let seed: [u8; 32] = seed_bytes
                .try_into()
                .expect("exact signing seed length checked above");
            if seed.iter().all(|byte| *byte == 0) {
                return Err(CliError::Validation(
                    "release manifest development signing seed must not be all zero".to_owned(),
                ));
            }
            let signing_key = SigningKey::from_bytes(&seed);
            if signing_key.verifying_key().to_bytes() != public_key {
                return Err(CliError::Validation(
                    "release manifest public key does not match the development signing seed"
                        .to_owned(),
                ));
            }
            let signature = signing_key.sign(&manifest).to_bytes();
            verify_release_signature(&verifying_key, &manifest, &signature)?;
            write_release_signature(&signature_out, &signature)?;
            println!(
                "release manifest Ed25519 signature created (development-only)\npublic_key_fingerprint_sha256={}",
                hex::encode(actual_fingerprint)
            );
            Ok(ExitCode::SUCCESS)
        }
        (Some(_), _, _, true) => Err(CliError::Config(
            "release-manifest external verification does not accept --development-local-signing"
                .to_owned(),
        )),
        (Some(_), Some(_), _, _) | (Some(_), _, Some(_), _) => Err(CliError::Config(
            "release-manifest accepts either --signature or development signing options, not both"
                .to_owned(),
        )),
        (None, Some(_), Some(_), false) => Err(CliError::Config(
            "release-manifest --signing-seed is development-only and requires --development-local-signing"
                .to_owned(),
        )),
        (None, None, None, false) => Err(CliError::Config(
            "release-manifest requires --signature <path> or the complete development-only signing option set"
                .to_owned(),
        )),
        _ => Err(CliError::Config(
            "release-manifest development signing requires --signing-seed <path>, --signature-out <path>, and --development-local-signing"
                .to_owned(),
        )),
    }
}
pub(super) fn run_sign(args: SignArgs) -> Result<ExitCode, CliError> {
    match args.kind {
        Some(SignKind::Advert) => run_sign_advert(args),
        Some(SignKind::Order) => run_sign_order(args),
        Some(SignKind::Orderbook) => run_sign_orderbook(args),
        Some(SignKind::Governance) => run_sign_governance(args),
        None => Err(CliError::Config(
            "sign requires --kind advert, --kind order, --kind orderbook, or --kind governance"
                .to_owned(),
        )),
    }
}
fn run_sign_advert(args: SignArgs) -> Result<ExitCode, CliError> {
    let input = args.input.clone().ok_or(CliError::Config(
        "sign --kind advert requires --input <path>".to_owned(),
    ))?;
    let output = args.out.clone().ok_or(CliError::Config(
        "sign --kind advert requires --out <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let now = match args.now {
        Some(now) => now,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let seed = read_signing_seed(&args)?;
    let input_bytes = read_cli_bytes_bounded(&input, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1)?;
    let mut advert = match decode_provider_advert_v1(&input_bytes) {
        Ok(advert) => advert,
        Err(_) => {
            let outcome = validate_provider_advert_bytes(
                &input_bytes,
                input.display().to_string(),
                now,
                generated_at,
            );
            if let Some(path) = args.telemetry_out {
                write_json_outcome(&path, &outcome)?;
            }
            print_outcome(&outcome, format)?;
            return Ok(ExitCode::from(2));
        }
    };
    sign_provider_advert(&mut advert, &seed)?;
    let signed_bytes = norito::to_bytes(&advert).map_err(|err| {
        CliError::Internal(format!("failed to encode signed provider advert: {err}"))
    })?;
    let mut outcome = validate_provider_advert_bytes(
        &signed_bytes,
        output.display().to_string(),
        now,
        generated_at,
    );
    outcome
        .telemetry_tags
        .push("sorafs.reference.sign.advert".to_owned());
    outcome
        .context
        .push(ValidationContextFieldV1::new("operation", "sign"));
    outcome.context.push(ValidationContextFieldV1::new(
        "public_key_hex",
        hex::encode(&advert.signature.public_key),
    ));
    outcome.inputs.push(ValidationInputV1::new(
        "signed_provider_advert",
        output.display().to_string(),
    ));
    if outcome.is_ok() {
        fs::write(&output, signed_bytes)
            .map_err(|err| CliError::Io(format!("failed to write {}: {err}", output.display())))?;
    }
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_sign_order(args: SignArgs) -> Result<ExitCode, CliError> {
    let input = args.input.clone().ok_or(CliError::Config(
        "sign --kind order requires --input <path>".to_owned(),
    ))?;
    let output = args.out.clone().ok_or(CliError::Config(
        "sign --kind order requires --out <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let seed = read_signing_seed(&args)?;
    let input_bytes = fs::read(&input)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", input.display())))?;
    let order = match norito::decode_from_bytes::<ReplicationOrderV1>(&input_bytes) {
        Ok(order) => order,
        Err(_) => {
            let outcome = validate_replication_order_bytes(
                &input_bytes,
                input.display().to_string(),
                generated_at,
            );
            if let Some(path) = args.telemetry_out {
                write_json_outcome(&path, &outcome)?;
            }
            print_outcome(&outcome, format)?;
            return Ok(ExitCode::from(2));
        }
    };
    let signed_order = sign_replication_order(order, &seed)?;
    let signed_bytes = norito::to_bytes(&signed_order).map_err(|err| {
        CliError::Internal(format!("failed to encode signed replication order: {err}"))
    })?;
    let mut outcome = validate_signed_replication_order_bytes(
        &signed_bytes,
        output.display().to_string(),
        generated_at,
    );
    outcome
        .telemetry_tags
        .push("sorafs.reference.sign.order".to_owned());
    outcome
        .context
        .push(ValidationContextFieldV1::new("operation", "sign"));
    outcome.context.push(ValidationContextFieldV1::new(
        "public_key_hex",
        hex::encode(&signed_order.signature.public_key),
    ));
    outcome.inputs.push(ValidationInputV1::new(
        "signed_replication_order",
        output.display().to_string(),
    ));
    if outcome.is_ok() {
        fs::write(&output, signed_bytes)
            .map_err(|err| CliError::Io(format!("failed to write {}: {err}", output.display())))?;
    }
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_sign_orderbook(args: SignArgs) -> Result<ExitCode, CliError> {
    let input = args.input.clone().ok_or(CliError::Config(
        "sign --kind orderbook requires --input <path>".to_owned(),
    ))?;
    let output = args.out.clone().ok_or(CliError::Config(
        "sign --kind orderbook requires --out <path>".to_owned(),
    ))?;
    let payload_kind = args.payload_kind.ok_or(CliError::Config(
        "sign --kind orderbook requires --payload-kind order-request, order-cancel, or settlement-receipt".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let seed = read_signing_seed(&args)?;
    let input_bytes = read_cli_bytes_bounded(&input, ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1)?;
    let signed_bytes = match sign_orderbook_payload_bytes(payload_kind, &input_bytes, &seed) {
        Ok(bytes) => bytes,
        Err(SignOrderbookPayloadError::Decode) => {
            let outcome = validate_orderbook_payload_bytes(
                payload_kind,
                &input_bytes,
                input.display().to_string(),
                generated_at,
            );
            if let Some(path) = args.telemetry_out {
                write_json_outcome(&path, &outcome)?;
            }
            print_outcome(&outcome, format)?;
            return Ok(ExitCode::from(2));
        }
        Err(SignOrderbookPayloadError::UnsupportedKind(kind)) => {
            return Err(CliError::Config(format!(
                "sign --kind orderbook does not support payload kind `{}`; expected order-request, order-cancel, or settlement-receipt",
                orderbook_kind_label(kind)
            )));
        }
        Err(SignOrderbookPayloadError::Sign(reason)) => {
            return Err(CliError::Internal(format!(
                "failed to sign orderbook payload: {reason}"
            )));
        }
        Err(SignOrderbookPayloadError::Encode(reason)) => {
            return Err(CliError::Internal(format!(
                "failed to encode signed orderbook payload: {reason}"
            )));
        }
    };
    let mut outcome = validate_orderbook_payload_bytes(
        payload_kind,
        &signed_bytes,
        output.display().to_string(),
        generated_at,
    );
    outcome
        .telemetry_tags
        .push("sorafs.reference.sign.orderbook".to_owned());
    outcome
        .context
        .push(ValidationContextFieldV1::new("operation", "sign"));
    outcome.context.push(ValidationContextFieldV1::new(
        "payload_kind",
        orderbook_kind_label(payload_kind),
    ));
    outcome.context.push(ValidationContextFieldV1::new(
        "public_key_hex",
        hex::encode(orderbook_payload_public_key(payload_kind, &signed_bytes)?),
    ));
    outcome.inputs.push(ValidationInputV1::new(
        signed_orderbook_input_kind(payload_kind),
        output.display().to_string(),
    ));
    if outcome.is_ok() {
        fs::write(&output, signed_bytes)
            .map_err(|err| CliError::Io(format!("failed to write {}: {err}", output.display())))?;
    }
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
fn run_sign_governance(args: SignArgs) -> Result<ExitCode, CliError> {
    let input = args.input.clone().ok_or(CliError::Config(
        "sign --kind governance requires --input <path>".to_owned(),
    ))?;
    let output = args.out.clone().ok_or(CliError::Config(
        "sign --kind governance requires --out <path>".to_owned(),
    ))?;
    let format = args.format.unwrap_or(OutputFormat::Table);
    let generated_at = match args.generated_at {
        Some(generated_at) => generated_at,
        None => unix_time_now()
            .ok_or_else(|| CliError::Internal("system time is before the UNIX epoch".to_owned()))?,
    };
    let seed = read_signing_seed(&args)?;
    let input_bytes = fs::read(&input)
        .map_err(|err| CliError::Io(format!("failed to read {}: {err}", input.display())))?;
    let mut node = match norito::decode_from_bytes::<GovernanceLogNodeV1>(&input_bytes) {
        Ok(node) => node,
        Err(_) => {
            let outcome = validate_governance_log_node_bytes(
                &input_bytes,
                input.display().to_string(),
                None,
                generated_at,
            );
            if let Some(path) = args.telemetry_out {
                write_json_outcome(&path, &outcome)?;
            }
            print_outcome(&outcome, format)?;
            return Ok(ExitCode::from(2));
        }
    };
    sign_governance_log_node(&mut node, &seed)?;
    let signed_bytes = norito::to_bytes(&node).map_err(|err| {
        CliError::Internal(format!(
            "failed to encode signed governance log node: {err}"
        ))
    })?;
    let mut outcome = validate_governance_log_node_bytes(
        &signed_bytes,
        output.display().to_string(),
        None,
        generated_at,
    );
    outcome
        .telemetry_tags
        .push("sorafs.reference.sign.governance".to_owned());
    outcome
        .context
        .push(ValidationContextFieldV1::new("operation", "sign"));
    outcome.context.push(ValidationContextFieldV1::new(
        "public_key_hex",
        hex::encode(&node.publisher_signature.public_key),
    ));
    outcome.inputs.push(ValidationInputV1::new(
        "signed_governance_log_node",
        output.display().to_string(),
    ));
    if outcome.is_ok() {
        fs::write(&output, signed_bytes)
            .map_err(|err| CliError::Io(format!("failed to write {}: {err}", output.display())))?;
    }
    if let Some(path) = args.telemetry_out {
        write_json_outcome(&path, &outcome)?;
    }
    print_outcome(&outcome, format)?;
    if outcome.is_ok() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignKind {
    Advert,
    Order,
    Orderbook,
    Governance,
}

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Json,
    Table,
    Yaml,
}
impl OutputFormat {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            "yaml" => Ok(Self::Yaml),
            other => Err(CliError::Config(format!(
                "unsupported --format `{other}`; expected json, table, or yaml"
            ))),
        }
    }
}
/// Stable artifact validation error and exit-status classification.
#[derive(Debug)]
pub(crate) enum CliError {
    Validation(String),
    Config(String),
    Io(String),
    Internal(String),
}
impl CliError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            CliError::Validation(_) => 2,
            CliError::Config(_) => 4,
            CliError::Io(_) => 3,
            CliError::Internal(_) => 10,
        }
    }
}
impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Validation(message)
            | CliError::Config(message)
            | CliError::Io(message)
            | CliError::Internal(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for CliError {}

fn parse_u64_flag(value: &str, flag: &str) -> Result<u64, CliError> {
    require_canonical_unsigned_decimal(value, flag)?;
    value
        .parse::<u64>()
        .map_err(|err| CliError::Config(format!("{flag} must be an unsigned integer: {err}")))
}
fn require_canonical_unsigned_decimal(value: &str, flag: &str) -> Result<(), CliError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(CliError::Config(format!(
            "{flag} must be a canonical unsigned decimal integer"
        )));
    }
    Ok(())
}
fn parse_cid_arg_bytes(value: &str) -> Result<Vec<u8>, CliError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CliError::Config(
            "governance --cid must not be empty".to_owned(),
        ));
    }
    if let Some(hex_value) = trimmed.strip_prefix("hex:") {
        return hex::decode(hex_value).map_err(|err| {
            CliError::Config(format!("invalid governance --cid hex `{trimmed}`: {err}"))
        });
    }
    if trimmed.len().is_multiple_of(2)
        && trimmed
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return hex::decode(trimmed).map_err(|err| {
            CliError::Config(format!("invalid governance --cid hex `{trimmed}`: {err}"))
        });
    }
    Ok(trimmed.as_bytes().to_vec())
}
fn parse_profile(value: &str) -> Result<ProofStreamTier, CliError> {
    match value {
        "hot" => Ok(ProofStreamTier::Hot),
        "warm" => Ok(ProofStreamTier::Warm),
        "archive" => Ok(ProofStreamTier::Archive),
        other => Err(CliError::Config(format!(
            "unsupported --profile `{other}`; expected hot, warm, or archive"
        ))),
    }
}
fn parse_repair_kind(value: &str) -> Result<RepairValidationPayloadKindV1, CliError> {
    match value {
        "task" => Ok(RepairValidationPayloadKindV1::TaskRecord),
        "evidence" => Ok(RepairValidationPayloadKindV1::Evidence),
        "report" => Ok(RepairValidationPayloadKindV1::Report),
        "slash-proposal" => Ok(RepairValidationPayloadKindV1::SlashProposal),
        "policy" => Ok(RepairValidationPayloadKindV1::EscalationPolicy),
        "approval" => Ok(RepairValidationPayloadKindV1::EscalationApproval),
        "event" => Ok(RepairValidationPayloadKindV1::TaskEvent),
        "audit-event" => Ok(RepairValidationPayloadKindV1::AuditEvent),
        other => Err(CliError::Config(format!(
            "unsupported repair --kind `{other}`; expected task, evidence, report, slash-proposal, policy, approval, event, or audit-event"
        ))),
    }
}
fn parse_pop_kind(value: &str) -> Result<PopValidationPayloadKindV1, CliError> {
    match value {
        "credential" => Ok(PopValidationPayloadKindV1::Credential),
        "commitment-root" => Ok(PopValidationPayloadKindV1::CommitmentRoot),
        "revocation-list" => Ok(PopValidationPayloadKindV1::RevocationList),
        "issued-credential-bundle" => Ok(PopValidationPayloadKindV1::IssuedCredentialBundle),
        "enrollment-request" => Ok(PopValidationPayloadKindV1::EnrollmentRequest),
        "renewal-request" => Ok(PopValidationPayloadKindV1::RenewalRequest),
        "membership-proof" => Ok(PopValidationPayloadKindV1::MembershipProof),
        other => Err(CliError::Config(format!(
            "unsupported pop --kind `{other}`; expected credential, commitment-root, revocation-list, issued-credential-bundle, enrollment-request, renewal-request, or membership-proof"
        ))),
    }
}
fn parse_hedging_kind(value: &str) -> Result<HedgingValidationPayloadKindV1, CliError> {
    match value {
        "price-feed" => Ok(HedgingValidationPayloadKindV1::PriceFeed),
        "reference-price-decision" => Ok(HedgingValidationPayloadKindV1::ReferencePriceDecision),
        "billing-line-item" => Ok(HedgingValidationPayloadKindV1::BillingLineItem),
        "billing-statement" => Ok(HedgingValidationPayloadKindV1::BillingStatement),
        other => Err(CliError::Config(format!(
            "unsupported hedging --kind `{other}`; expected price-feed, reference-price-decision, billing-line-item, or billing-statement"
        ))),
    }
}
fn parse_orderbook_kind(value: &str) -> Result<OrderbookValidationPayloadKindV1, CliError> {
    match value {
        "order-request" => Ok(OrderbookValidationPayloadKindV1::OrderRequest),
        "order-cancel" => Ok(OrderbookValidationPayloadKindV1::OrderCancel),
        "trade-event" => Ok(OrderbookValidationPayloadKindV1::TradeEvent),
        "settlement-channel" => Ok(OrderbookValidationPayloadKindV1::SettlementChannel),
        "settlement-receipt" => Ok(OrderbookValidationPayloadKindV1::SettlementReceipt),
        other => Err(CliError::Config(format!(
            "unsupported orderbook --kind `{other}`; expected order-request, order-cancel, trade-event, settlement-channel, or settlement-receipt"
        ))),
    }
}
fn parse_orderbook_sign_kind(value: &str) -> Result<OrderbookValidationPayloadKindV1, CliError> {
    let kind = parse_orderbook_kind(value)?;
    if matches!(
        kind,
        OrderbookValidationPayloadKindV1::OrderRequest
            | OrderbookValidationPayloadKindV1::OrderCancel
            | OrderbookValidationPayloadKindV1::SettlementReceipt
    ) {
        Ok(kind)
    } else {
        Err(CliError::Config(format!(
            "unsupported sign --kind orderbook --payload-kind `{value}`; expected order-request, order-cancel, or settlement-receipt"
        )))
    }
}
fn parse_sign_kind(value: &str) -> Result<SignKind, CliError> {
    match value {
        "advert" => Ok(SignKind::Advert),
        "order" => Ok(SignKind::Order),
        "orderbook" => Ok(SignKind::Orderbook),
        "governance" => Ok(SignKind::Governance),
        other => Err(CliError::Config(format!(
            "unsupported sign --kind `{other}`; expected advert, order, orderbook, or governance"
        ))),
    }
}
fn read_signing_seed(args: &SignArgs) -> Result<[u8; 32], CliError> {
    match (&args.key_hex, &args.key) {
        (Some(_), Some(_)) => Err(CliError::Config(
            "sign accepts either --key-hex or --key, not both".to_owned(),
        )),
        (Some(key_hex), None) => parse_ed25519_seed_hex(key_hex, "--key-hex"),
        (None, Some(path)) => {
            let contents = fs::read_to_string(path).map_err(|err| {
                CliError::Io(format!(
                    "failed to read signing key {}: {err}",
                    path.display()
                ))
            })?;
            parse_ed25519_seed_hex(&contents, "--key")
        }
        (None, None) => Err(CliError::Config(
            "sign requires --key-hex <32-byte-hex-seed> or --key <path>".to_owned(),
        )),
    }
}
fn parse_ed25519_seed_hex(value: &str, flag: &str) -> Result<[u8; 32], CliError> {
    require_canonical_seed_hex(value, flag)?;
    let bytes = hex::decode(value).map_err(|err| {
        CliError::Config(format!(
            "{flag} must contain a 32-byte Ed25519 seed encoded as hex: {err}"
        ))
    })?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        CliError::Config(format!(
            "{flag} must contain exactly 32 seed bytes, got {}",
            bytes.len()
        ))
    })?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(CliError::Config(format!(
            "{flag} seed material must not be all zero"
        )));
    }
    Ok(seed)
}
fn require_canonical_seed_hex(value: &str, flag: &str) -> Result<(), CliError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || bytes.iter().any(u8::is_ascii_whitespace)
        || value.starts_with("0x")
        || value.starts_with("0X")
        || value.starts_with("ed25519:")
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(CliError::Config(format!(
            "{flag} must contain exactly 32 seed bytes as lowercase hex without prefixes or whitespace"
        )));
    }
    Ok(())
}
fn parse_release_fingerprint(value: &str) -> Result<[u8; 32], CliError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(CliError::Config(
            "--public-key-fingerprint must be exactly 32 bytes of lowercase SHA-256 hex without prefixes or whitespace"
                .to_owned(),
        ));
    }
    let decoded = hex::decode(value).map_err(|_| {
        CliError::Config("--public-key-fingerprint contains invalid hex".to_owned())
    })?;
    Ok(decoded
        .try_into()
        .expect("exact release fingerprint length checked above"))
}
fn verify_release_signature(
    verifying_key: &VerifyingKey,
    manifest: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), CliError> {
    if signature_bytes.iter().all(|byte| *byte == 0) {
        return Err(CliError::Validation(
            "release manifest signature must not be all zero".to_owned(),
        ));
    }
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify_strict(manifest, &signature)
        .map_err(|_| {
            CliError::Validation(
                "release manifest Ed25519 signature verification failed".to_owned(),
            )
        })
}
fn read_release_input(
    path: &Path,
    label: &str,
    maximum_bytes: u64,
    exact_bytes: Option<u64>,
    secret: bool,
) -> Result<Vec<u8>, CliError> {
    let direct_path = release_direct_path(path, label)?;
    let before = fs::symlink_metadata(&direct_path)
        .map_err(|err| CliError::Io(format!("failed to inspect {label}: {err}")))?;
    validate_release_metadata(label, &before, maximum_bytes, secret)?;
    let mut options = OpenOptions::new();
    options.read(true);
    set_release_no_follow(&mut options);
    let mut file = options
        .open(&direct_path)
        .map_err(|err| CliError::Io(format!("failed to open {label}: {err}")))?;
    let opened = file
        .metadata()
        .map_err(|err| CliError::Io(format!("failed to inspect open {label}: {err}")))?;
    validate_release_metadata(label, &opened, maximum_bytes, secret)?;
    if !release_metadata_matches(&before, &opened) {
        return Err(CliError::Validation(format!(
            "{label} changed while being opened"
        )));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_| CliError::Validation(format!("{label} exceeds host size limits")))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| CliError::Io(format!("failed to read {label}: {err}")))?;
    let after = fs::symlink_metadata(&direct_path)
        .map_err(|err| CliError::Io(format!("failed to re-inspect {label}: {err}")))?;
    validate_release_metadata(label, &after, maximum_bytes, secret)?;
    if bytes.len() as u64 != opened.len()
        || !release_metadata_matches(&opened, &after)
        || !release_metadata_matches(&before, &after)
    {
        return Err(CliError::Validation(format!(
            "{label} changed while being read"
        )));
    }
    if let Some(expected) = exact_bytes
        && bytes.len() as u64 != expected
    {
        return Err(CliError::Validation(format!(
            "{label} must contain exactly {expected} raw bytes"
        )));
    }
    Ok(bytes)
}

fn release_direct_path(path: &Path, label: &str) -> Result<PathBuf, CliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CliError::Validation(format!(
            "{label} must use a non-empty direct path without `.` or `..` components"
        )));
    }
    let direct_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| CliError::Io(format!("failed to resolve {label} path: {err}")))?
            .join(path)
    };
    if let Some(parent) = direct_path.parent() {
        for ancestor in parent.ancestors() {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|err| CliError::Io(format!("failed to inspect {label} parent: {err}")))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CliError::Validation(format!(
                    "{label} parent must be a real directory"
                )));
            }
        }
    }
    Ok(direct_path)
}
fn validate_release_metadata(
    label: &str,
    metadata: &fs::Metadata,
    maximum_bytes: u64,
    secret: bool,
) -> Result<(), CliError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::Validation(format!(
            "{label} must be a direct regular file"
        )));
    }
    if metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(CliError::Validation(format!(
            "{label} size is outside the supported range"
        )));
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 {
            return Err(CliError::Validation(format!(
                "{label} must have exactly one hard link"
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if secret {
            if !matches!(mode, 0o400 | 0o600) {
                return Err(CliError::Validation(format!(
                    "{label} permissions must be owner-only 0400 or 0600"
                )));
            }
        } else if mode & 0o022 != 0 {
            return Err(CliError::Validation(format!(
                "{label} must not be group- or world-writable"
            )));
        }
    }
    Ok(())
}
#[cfg(unix)]
fn release_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(not(unix))]
fn release_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn write_release_signature(path: &Path, signature: &[u8; 64]) -> Result<(), CliError> {
    let direct_path = release_direct_path(path, "release manifest signature output")?;
    match fs::symlink_metadata(&direct_path) {
        Ok(_) => {
            return Err(CliError::Validation(
                "release manifest signature output must not already exist".to_owned(),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(CliError::Io(format!(
                "failed to inspect release manifest signature output: {err}"
            )));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    set_release_no_follow(&mut options);
    let mut file = options.open(&direct_path).map_err(|err| {
        CliError::Io(format!(
            "failed to create release manifest signature output: {err}"
        ))
    })?;
    file.write_all(signature).map_err(|err| {
        CliError::Io(format!(
            "failed to write release manifest signature output: {err}"
        ))
    })?;
    file.sync_all().map_err(|err| {
        CliError::Io(format!(
            "failed to sync release manifest signature output: {err}"
        ))
    })?;
    let opened = file.metadata().map_err(|err| {
        CliError::Io(format!(
            "failed to inspect release manifest signature output: {err}"
        ))
    })?;
    let after = fs::symlink_metadata(&direct_path).map_err(|err| {
        CliError::Io(format!(
            "failed to re-inspect release manifest signature output: {err}"
        ))
    })?;
    if !release_metadata_matches(&opened, &after)
        || !after.is_file()
        || after.len() != signature.len() as u64
    {
        return Err(CliError::Validation(
            "release manifest signature output changed while being written".to_owned(),
        ));
    }
    #[cfg(unix)]
    if let Some(parent) = direct_path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|err| {
                CliError::Io(format!(
                    "failed to sync release manifest signature output directory: {err}"
                ))
            })?;
    }
    Ok(())
}
#[cfg(unix)]
fn set_release_no_follow(options: &mut OpenOptions) {
    options.custom_flags(release_no_follow_flag());
}
#[cfg(not(unix))]
fn set_release_no_follow(_options: &mut OpenOptions) {}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn release_no_follow_flag() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android")),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
fn release_no_follow_flag() -> i32 {
    0x100
}
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn release_no_follow_flag() -> i32 {
    0
}
fn sign_provider_advert(advert: &mut ProviderAdvertV1, seed: &[u8; 32]) -> Result<(), CliError> {
    let signing_key = SigningKey::from_bytes(seed);
    advert.signature = AdvertSignature {
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature: vec![0; 64],
    };
    advert.signature_strict = true;
    let payload = advert.signature_payload_bytes().map_err(|err| {
        CliError::Internal(format!(
            "failed to encode provider advert envelope for signing: {err}"
        ))
    })?;
    advert.signature.signature = signing_key.sign(&payload).to_bytes().to_vec();
    Ok(())
}
fn sign_replication_order(
    order: ReplicationOrderV1,
    seed: &[u8; 32],
) -> Result<SignedReplicationOrderV1, CliError> {
    let signing_key = SigningKey::from_bytes(seed);
    let mut signed_order = SignedReplicationOrderV1 {
        version: SIGNED_REPLICATION_ORDER_VERSION_V1,
        order,
        signature: ReplicationOrderSignatureV1 {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: vec![0; 64],
        },
    };
    let payload_bytes = signed_order.signature_payload_bytes().map_err(|err| {
        CliError::Internal(format!(
            "failed to encode replication order payload for signing: {err}"
        ))
    })?;
    let signature = signing_key.sign(&payload_bytes);
    signed_order.signature.signature = signature.to_bytes().to_vec();
    Ok(signed_order)
}
#[derive(Debug)]
enum SignOrderbookPayloadError {
    Decode,
    UnsupportedKind(OrderbookValidationPayloadKindV1),
    Sign(String),
    Encode(String),
}
fn sign_orderbook_payload_bytes(
    kind: OrderbookValidationPayloadKindV1,
    input_bytes: &[u8],
    seed: &[u8; 32],
) -> Result<Vec<u8>, SignOrderbookPayloadError> {
    let signing_key = SigningKey::from_bytes(seed);
    match kind {
        OrderbookValidationPayloadKindV1::OrderRequest => {
            let order = decode_order_request_v1(input_bytes)
                .map_err(|_| SignOrderbookPayloadError::Decode)?;
            let signed = sign_order_request_ed25519_v1(order, &signing_key)
                .map_err(|err| SignOrderbookPayloadError::Sign(err.to_string()))?;
            norito::to_bytes(&signed)
                .map_err(|err| SignOrderbookPayloadError::Encode(err.to_string()))
        }
        OrderbookValidationPayloadKindV1::OrderCancel => {
            let cancel = decode_order_cancel_v1(input_bytes)
                .map_err(|_| SignOrderbookPayloadError::Decode)?;
            let signed = sign_order_cancel_ed25519_v1(cancel, &signing_key)
                .map_err(|err| SignOrderbookPayloadError::Sign(err.to_string()))?;
            norito::to_bytes(&signed)
                .map_err(|err| SignOrderbookPayloadError::Encode(err.to_string()))
        }
        OrderbookValidationPayloadKindV1::SettlementReceipt => {
            let receipt = decode_settlement_receipt_v1(input_bytes)
                .map_err(|_| SignOrderbookPayloadError::Decode)?;
            let signed = sign_settlement_receipt_ed25519_v1(receipt, &signing_key)
                .map_err(|err| SignOrderbookPayloadError::Sign(err.to_string()))?;
            norito::to_bytes(&signed)
                .map_err(|err| SignOrderbookPayloadError::Encode(err.to_string()))
        }
        other => Err(SignOrderbookPayloadError::UnsupportedKind(other)),
    }
}
fn orderbook_payload_public_key(
    kind: OrderbookValidationPayloadKindV1,
    input_bytes: &[u8],
) -> Result<Vec<u8>, CliError> {
    match kind {
        OrderbookValidationPayloadKindV1::OrderRequest => {
            let order = decode_order_request_v1(input_bytes).map_err(|err| {
                CliError::Internal(format!("failed to decode signed orderbook order: {err}"))
            })?;
            Ok(order.signature.public_key)
        }
        OrderbookValidationPayloadKindV1::OrderCancel => {
            let cancel = decode_order_cancel_v1(input_bytes).map_err(|err| {
                CliError::Internal(format!("failed to decode signed orderbook cancel: {err}"))
            })?;
            Ok(cancel.signature.public_key)
        }
        OrderbookValidationPayloadKindV1::SettlementReceipt => {
            let receipt = decode_settlement_receipt_v1(input_bytes).map_err(|err| {
                CliError::Internal(format!(
                    "failed to decode signed orderbook settlement receipt: {err}"
                ))
            })?;
            Ok(receipt.settlement_signature.public_key)
        }
        other => Err(CliError::Config(format!(
            "sign --kind orderbook does not support payload kind `{}`",
            orderbook_kind_label(other)
        ))),
    }
}
fn orderbook_kind_label(kind: OrderbookValidationPayloadKindV1) -> &'static str {
    match kind {
        OrderbookValidationPayloadKindV1::OrderRequest => "order-request",
        OrderbookValidationPayloadKindV1::OrderCancel => "order-cancel",
        OrderbookValidationPayloadKindV1::TradeEvent => "trade-event",
        OrderbookValidationPayloadKindV1::SettlementChannel => "settlement-channel",
        OrderbookValidationPayloadKindV1::SettlementReceipt => "settlement-receipt",
    }
}
fn signed_orderbook_input_kind(kind: OrderbookValidationPayloadKindV1) -> &'static str {
    match kind {
        OrderbookValidationPayloadKindV1::OrderRequest => "signed_orderbook_order_request",
        OrderbookValidationPayloadKindV1::OrderCancel => "signed_orderbook_order_cancel",
        OrderbookValidationPayloadKindV1::SettlementReceipt => {
            "signed_orderbook_settlement_receipt"
        }
        _ => "signed_orderbook_payload",
    }
}
fn sign_governance_log_node(
    node: &mut GovernanceLogNodeV1,
    seed: &[u8; 32],
) -> Result<(), CliError> {
    let signing_key = SigningKey::from_bytes(seed);
    let payload_bytes = node.signature_payload_bytes().map_err(|err| {
        CliError::Internal(format!(
            "failed to encode governance log node payload for signing: {err}"
        ))
    })?;
    let signature = signing_key.sign(&payload_bytes);
    node.publisher_signature = GovernanceLogSignatureV1 {
        algorithm: GovernanceSignatureAlgorithm::Ed25519,
        public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
    };
    Ok(())
}
#[derive(Debug)]
struct OwnedBundlePayload {
    kind: FixtureBundlePayloadKindV1,
    label: String,
    bytes: Vec<u8>,
}
const BUNDLE_PAYLOAD_CANDIDATES: &[(FixtureBundlePayloadKindV1, &[&str])] = &[
    (
        FixtureBundlePayloadKindV1::ProviderAdvert,
        &[
            "provider_admission/advert_v1.to",
            "advert_v1.to",
            "advert.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::ProviderAdmissionEnvelope,
        &[
            "provider_admission/envelope_v1.to",
            "envelope_v1.to",
            "envelope.to",
            "admission.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::ReplicationOrder,
        &["replication_order/order_v1.to", "order_v1.to", "order.to"],
    ),
    (
        FixtureBundlePayloadKindV1::PdpCommitment,
        &[
            "pdp/commitment_v1.to",
            "pdp_commitment_v1.to",
            "commitment_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::PdpChallenge,
        &[
            "pdp/challenge_v1.to",
            "pdp_challenge_v1.to",
            "pdp-challenge.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::PdpProof,
        &["pdp/proof_v1.to", "pdp_proof_v1.to", "pdp-proof.to"],
    ),
    (
        FixtureBundlePayloadKindV1::PorChallenge,
        &["por/challenge_v1.to", "challenge_v1.to", "challenge.to"],
    ),
    (
        FixtureBundlePayloadKindV1::PorProof,
        &["por/proof_v1.to", "proof_v1.to", "proof.to"],
    ),
    (
        FixtureBundlePayloadKindV1::PotrReceipt,
        &["potr/receipt_v1.to", "receipt_v1.to", "potr_receipt_v1.to"],
    ),
    (
        FixtureBundlePayloadKindV1::RepairEvidence,
        &[
            "repair/evidence_v1.to",
            "evidence_v1.to",
            "repair_evidence_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::RepairReport,
        &["repair/report_v1.to", "report_v1.to", "repair_report_v1.to"],
    ),
    (
        FixtureBundlePayloadKindV1::RepairTaskRecord,
        &["repair/task_v1.to", "task_v1.to", "repair_task_v1.to"],
    ),
    (
        FixtureBundlePayloadKindV1::RepairSlashProposal,
        &[
            "repair/slash_proposal_v1.to",
            "slash_proposal_v1.to",
            "repair_slash_proposal_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::RepairTaskEvent,
        &["repair/event_v1.to", "event_v1.to", "repair_event_v1.to"],
    ),
    (
        FixtureBundlePayloadKindV1::OrderbookOrderRequest,
        &[
            "orderbook/order_request_v1.to",
            "order_request_v1.to",
            "orderbook_order_request_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::OrderbookOrderCancel,
        &[
            "orderbook/order_cancel_v1.to",
            "order_cancel_v1.to",
            "orderbook_order_cancel_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::OrderbookTradeEvent,
        &[
            "orderbook/trade_event_v1.to",
            "trade_event_v1.to",
            "orderbook_trade_event_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::OrderbookSettlementChannel,
        &[
            "orderbook/settlement_channel_v1.to",
            "settlement_channel_v1.to",
            "orderbook_settlement_channel_v1.to",
        ],
    ),
    (
        FixtureBundlePayloadKindV1::OrderbookSettlementReceipt,
        &[
            "orderbook/settlement_receipt_v1.to",
            "settlement_receipt_v1.to",
            "orderbook_settlement_receipt_v1.to",
        ],
    ),
];
fn read_bundle_payloads(bundle: &Path) -> Result<Vec<OwnedBundlePayload>, CliError> {
    if !bundle.is_dir() {
        return Err(CliError::Io(format!(
            "bundle path {} is not a directory",
            bundle.display()
        )));
    }
    let mut payloads = Vec::new();
    let mut seen_paths = BTreeSet::new();
    for &(kind, candidates) in BUNDLE_PAYLOAD_CANDIDATES {
        for relative_path in candidates {
            let path = bundle.join(relative_path);
            if !path.is_file() || !seen_paths.insert(path.clone()) {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|err| CliError::Io(format!("failed to read {}: {err}", path.display())))?;
            payloads.push(OwnedBundlePayload {
                kind,
                label: path.display().to_string(),
                bytes,
            });
        }
    }
    Ok(payloads)
}
fn write_json_outcome(path: &PathBuf, outcome: &ValidationOutcomeV1) -> Result<(), CliError> {
    let mut json = json::to_string_pretty(outcome)
        .map_err(|err| CliError::Internal(format!("failed to render outcome JSON: {err}")))?;
    json.push('\n');
    fs::write(path, json)
        .map_err(|err| CliError::Io(format!("failed to write {}: {err}", path.display())))
}
fn print_outcome(outcome: &ValidationOutcomeV1, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => {
            let mut rendered = json::to_string_pretty(outcome).map_err(|err| {
                CliError::Internal(format!("failed to render outcome JSON: {err}"))
            })?;
            rendered.push('\n');
            print!("{rendered}");
        }
        OutputFormat::Table => {
            println!("STATUS\tCODE\tCATEGORY\tMESSAGE");
            println!(
                "{}\t{}\t{}\t{}",
                outcome.status, outcome.code, outcome.category, outcome.message
            );
        }
        OutputFormat::Yaml => {
            print!("{}", render_yaml(outcome));
        }
    }
    io::Write::flush(&mut io::stdout())
        .map_err(|err| CliError::Io(format!("failed to flush stdout: {err}")))
}
fn render_yaml(outcome: &ValidationOutcomeV1) -> String {
    let mut rendered = String::new();
    rendered.push_str(&format!("status: {}\n", yaml_string(&outcome.status)));
    rendered.push_str(&format!("code: {}\n", yaml_string(&outcome.code)));
    rendered.push_str(&format!("category: {}\n", yaml_string(&outcome.category)));
    rendered.push_str(&format!("message: {}\n", yaml_string(&outcome.message)));
    match &outcome.action {
        Some(action) => rendered.push_str(&format!("action: {}\n", yaml_string(action))),
        None => rendered.push_str("action: null\n"),
    }
    match &outcome.docs_url {
        Some(docs_url) => rendered.push_str(&format!("docs_url: {}\n", yaml_string(docs_url))),
        None => rendered.push_str("docs_url: null\n"),
    }
    rendered.push_str("telemetry_tags:\n");
    for tag in &outcome.telemetry_tags {
        rendered.push_str(&format!("  - {}\n", yaml_string(tag)));
    }
    rendered.push_str("context:\n");
    for field in &outcome.context {
        rendered.push_str(&format!("  - key: {}\n", yaml_string(&field.key)));
        rendered.push_str(&format!("    value: {}\n", yaml_string(&field.value)));
    }
    rendered.push_str("inputs:\n");
    for input in &outcome.inputs {
        rendered.push_str(&format!("  - kind: {}\n", yaml_string(&input.kind)));
        rendered.push_str(&format!("    path: {}\n", yaml_string(&input.path)));
    }
    rendered.push_str(&format!("version: {}\n", outcome.version));
    rendered.push_str(&format!("generated_at: {}\n", outcome.generated_at));
    rendered
}
fn yaml_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}
fn unix_time_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

/// Validate a local SoraFS artifact.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Validate advert artifacts.
    Advert(AdvertArgs),
    /// Validate admission artifacts.
    Admission(AdmissionArgs),
    /// Validate order artifacts.
    Order(OrderArgs),
    /// Validate orderbook artifacts.
    Orderbook(OrderbookArgs),
    /// Validate pdp artifacts.
    Pdp(PdpArgs),
    /// Validate pop artifacts.
    Pop(PopArgs),
    /// Validate hedging artifacts.
    Hedging(HedgingArgs),
    /// Validate por artifacts.
    Por(PorArgs),
    /// Validate potr artifacts.
    Potr(PotrArgs),
    /// Validate repair artifacts.
    Repair(RepairArgs),
    /// Validate bundle artifacts.
    Bundle(BundleArgs),
    /// Validate governance artifacts.
    Governance(GovernanceArgs),
}
impl Command {
    pub(super) fn run(self) -> Result<ExitCode, CliError> {
        match self {
            Self::Advert(args) => run_advert(args),
            Self::Admission(args) => run_admission(args),
            Self::Order(args) => run_order(args.normalize()),
            Self::Orderbook(args) => run_orderbook(args),
            Self::Pdp(args) => run_pdp(args),
            Self::Pop(args) => run_pop(args),
            Self::Hedging(args) => run_hedging(args),
            Self::Por(args) => run_por(args),
            Self::Potr(args) => run_potr(args),
            Self::Repair(args) => run_repair(args),
            Self::Bundle(args) => run_bundle(args),
            Self::Governance(args) => run_governance(args.normalize()),
        }
    }
}

#[cfg(test)]
mod tests;
