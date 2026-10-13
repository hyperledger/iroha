//! Bind a retained deployment to canonical immutable artifacts and native instructions.
use super::*;
use iroha::data_model::transaction::Executable;
use std::cmp::Ordering;

pub struct DeploymentReadContext {
    network_id: NetworkId,
    chain_id: String,
    chain_discriminant: u16,
}
impl From<&Config> for DeploymentReadContext {
    fn from(config: &Config) -> Self {
        Self {
            network_id: config.network_id,
            chain_id: config.chain.to_string(),
            chain_discriminant: config.account_chain_discriminant,
        }
    }
}

pub fn validate_plan(record: &PlanRecord, config: &Config) -> DeploymentResult<()> {
    let mut manifest_budget = ManifestEncodingBudget::new()
        .map_err(|error| DeploymentError::InvalidRequest(error.to_string()))?;
    validate_plan_with_manifest_budget(record, config, &mut manifest_budget)
}

/// Authenticate using the prepare operation's original cumulative codec owner.
pub fn validate_plan_with_manifest_budget(
    record: &PlanRecord,
    config: &Config,
    manifest_budget: &mut ManifestEncodingBudget,
) -> DeploymentResult<()> {
    if record.preflight.authority != config.account
        || record.preflight.authority.try_signatory() != Some(config.key_pair.public_key())
    {
        return Err(DeploymentError::InvalidRequest(
            "writing or resuming a deployment requires its exact retained authority and signing key"
                .to_owned(),
        ));
    }
    validate_contents(
        record,
        &DeploymentReadContext::from(config),
        manifest_budget,
    )
    .map_err(|error| DeploymentError::InvalidRequest(error.to_string()))
}

pub fn validate_read_plan(
    record: &PlanRecord,
    reader: &DeploymentReadContext,
) -> DeploymentResult<()> {
    let mut manifest_budget = ManifestEncodingBudget::new()
        .map_err(|error| DeploymentError::InvalidRequest(error.to_string()))?;
    validate_contents(record, reader, &mut manifest_budget)
        .map_err(|error| DeploymentError::InvalidRequest(error.to_string()))
}

fn validate_contents(
    record: &PlanRecord,
    reader: &DeploymentReadContext,
    manifest_budget: &mut ManifestEncodingBudget,
) -> Result<()> {
    let context = &record.preflight;
    if record.version != 1
        || context.network_id != reader.network_id
        || context.chain_id != reader.chain_id
        || context.chain_discriminant != reader.chain_discriminant
    {
        return Err(eyre!(
            "retained deployment belongs to a different version, network, chain, or address discriminant"
        ));
    }
    let signer = context.authority.try_signatory().ok_or_else(|| {
        eyre!("retained native deployment authority must be a single-signatory account")
    })?;
    if record.artifact_hex.is_empty()
        || record.artifact_hex.len() > MAX_DEPLOYMENT_ARTIFACT_BYTES * 2
    {
        return Err(eyre!("retained artifact violates the fixed byte bound"));
    }
    let artifact = hex::decode(&record.artifact_hex)?;
    if hex::encode(&artifact) != record.artifact_hex {
        return Err(eyre!("retained artifact is not canonical hex"));
    }
    let verified = ivm_artifact_admission::verify_contract_artifact(&artifact)?;
    if verified.code_hash != context.code_hash || verified.abi_hash != context.abi_hash {
        return Err(eyre!(
            "retained code or ABI hash differs from the verified artifact"
        ));
    }
    record.requested_fee.validate()?;
    authorization::validate_authorization(
        &context.authorization,
        &context.contract_alias,
        context.dataspace_id,
    )?;
    let expected_address = ContractAddress::derive(
        &context.network_id,
        &context.authority,
        context.deploy_nonce,
        context.dataspace_id,
    )?;
    if context.contract_address != expected_address
        || context.deploy_nonce == u64::MAX
        || context.observed_block_height == 0
        || context
            .previous_contract_address
            .as_ref()
            .is_some_and(|address| address.dataspace_id().ok() != Some(context.dataspace_id))
    {
        return Err(eyre!(
            "retained deployment has inconsistent address, nonce, dataspace, or ledger observation"
        ));
    }
    let observation_hash = Hash::from_str(&context.observed_block_hash)?;
    if observation_hash.to_string() != context.observed_block_hash {
        return Err(eyre!("retained observed block hash is not canonical"));
    }
    let chunks = artifact.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES);
    let count = chunks + 2;
    if record.transactions.len() != count
        || context.fee_quotes.len() != count
        || context.transaction_hashes.len() != count
    {
        return Err(eyre!(
            "retained deployment does not contain the exact complete native sequence"
        ));
    }
    let metadata = deployment_transaction_metadata(&context.contract_address, &[])?;
    for (index, step) in record.transactions.iter().enumerate() {
        let transaction = decode_bound_step(record, &metadata, index, step)?;
        let Executable::Instructions(actual) = transaction.instructions() else {
            return Err(eyre!("deployment plan must contain native instructions"));
        };
        let (name, expected) = match index.cmp(&chunks) {
            Ordering::Less => upload_stage(context, &artifact, index, chunks)?,
            Ordering::Equal => manifest_stage(context, actual, &verified, signer, manifest_budget)?,
            Ordering::Greater => commit_stage(context),
        };
        if step.name != name || actual.as_ref() != expected.as_slice() {
            return Err(eyre!(
                "retained native stage {index} differs from the immutable artifact, upload sequence, or atomic alias compare-and-swap"
            ));
        }
    }
    Ok(())
}

/// Decode retained step `index` and check its authority, network, attribution, fee, and hash.
fn decode_bound_step(
    record: &PlanRecord,
    metadata: &Metadata,
    index: usize,
    step: &TransactionRecord,
) -> Result<SignedTransaction> {
    let context = &record.preflight;
    // Bounds precede Norito decoding; one transaction contains at most one 64 KiB chunk.
    if step.norito_hex.len() > 2 * MAX_DEPLOYMENT_TRANSACTION_BYTES {
        return Err(eyre!(
            "retained native transaction exceeds the fixed byte bound"
        ));
    }
    let signed = decode_transaction(step)?;
    let quote = &context.fee_quotes[index];
    native::validate_quote_route(quote, context.dataspace_id)?;
    if signed.authority() != &context.authority
        || signed.network_id() != Some(&context.network_id)
        || signed.metadata() != metadata
        || signed.payload().fee_payment != quote.intent
        || !record
            .requested_fee
            .has_same_payer_and_gas_bound(&quote.intent)
        || step.hash != context.transaction_hashes[index]
    {
        return Err(eyre!(
            "retained transaction differs from the exact authority, network, attribution, fee, or hash binding"
        ));
    }
    quote
        .validate_for_draft(signed.payload())
        .map_err(|error| eyre!(error))?;
    Ok(signed)
}

/// Expected stage name and instructions for upload chunk `index` of `chunks`.
fn upload_stage(
    context: &DeploymentPreflight,
    artifact: &[u8],
    index: usize,
    chunks: usize,
) -> Result<(String, Vec<InstructionBox>)> {
    let final_chunk = index + 1 == chunks;
    // The retained artifact is bounded by `MAX_DEPLOYMENT_ARTIFACT_BYTES`, so both fit `u32`.
    let chunk_index = u32::try_from(index).wrap_err("contract upload index does not fit u32")?;
    let chunk_count =
        u32::try_from(chunks).wrap_err("contract upload chunk count does not fit u32")?;
    let mut instructions = vec![InstructionBox::from(UploadSmartContractCodeChunk {
        artifact_id: ContractArtifactId::new(context.dataspace_id, context.code_hash),
        total_size: artifact.len() as u64,
        chunk_index,
        chunk_count,
        chunk: artifact[index * SMART_CONTRACT_CODE_CHUNK_BYTES
            ..((index + 1) * SMART_CONTRACT_CODE_CHUNK_BYTES).min(artifact.len())]
            .to_vec(),
    })];
    if final_chunk {
        instructions.push(InstructionBox::from(FinalizeSmartContractCodeUpload {
            artifact_id: ContractArtifactId::new(context.dataspace_id, context.code_hash),
            total_size: artifact.len() as u64,
            chunk_count,
        }));
    }
    let name = if final_chunk {
        "register_bytes_finalize".to_owned()
    } else {
        format!("register_bytes_chunk_{:04}_of_{chunks:04}", index + 1)
    };
    Ok((name, instructions))
}

/// Expected manifest-registration stage, bound to the verified artifact and retained signer.
fn manifest_stage(
    context: &DeploymentPreflight,
    actual: &[InstructionBox],
    verified: &ivm_artifact_admission::VerifiedContractArtifact,
    signer: &iroha_crypto::PublicKey,
    manifest_budget: &mut ManifestEncodingBudget,
) -> Result<(String, Vec<InstructionBox>)> {
    if actual.len() != 1 {
        return Err(eyre!(
            "manifest stage must contain exactly one registration"
        ));
    }
    let registration = actual[0]
        .as_any()
        .downcast_ref::<RegisterSmartContractCode>()
        .ok_or_else(|| eyre!("manifest stage is not native registration"))?;
    if registration.artifact_id != ContractArtifactId::new(context.dataspace_id, context.code_hash)
    {
        return Err(eyre!(
            "retained manifest artifact scope differs from the deployment context"
        ));
    }
    let manifest = &registration.manifest;
    let provenance = manifest
        .provenance
        .as_ref()
        .ok_or_else(|| eyre!("retained manifest has no signed provenance"))?;
    if !manifest.same_signed_content(&verified.manifest) || provenance.signer != *signer {
        return Err(eyre!(
            "retained manifest or signer differs from the verified artifact and retained authority"
        ));
    }
    let verification_frame = manifest_budget.reserve_frame(manifest)?;
    let payload = manifest.signature_payload_bytes(
        manifest_budget.context(),
        verification_frame.remaining_bytes(),
    )?;
    provenance.signature.verify(&provenance.signer, &payload)?;
    drop(payload);
    drop(verification_frame);
    Ok((
        "register_manifest".to_owned(),
        vec![InstructionBox::from(registration.clone())],
    ))
}

/// Expected atomic alias compare-and-swap deployment commit stage.
fn commit_stage(context: &DeploymentPreflight) -> (String, Vec<InstructionBox>) {
    (
        "commit_deployment".to_owned(),
        vec![InstructionBox::from(CommitContractDeployment {
            expected_deploy_nonce: context.deploy_nonce,
            contract_address: context.contract_address.clone(),
            code_hash: context.code_hash,
            contract_alias: context.contract_alias.clone(),
            lease_expiry_ms: None,
            expected_previous_contract_address: context.previous_contract_address.clone(),
        })],
    )
}
