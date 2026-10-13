//! Canonical native upload, manifest, and atomic deployment transaction construction.
use super::*;
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::JsonDeserialize, norito::derive::JsonSerialize,
)]
#[norito(deny_unknown_fields)]
pub struct ContractDeploymentStateSnapshot {
    pub(super) authority: String,
    contract_alias: String,
    pub(super) deploy_nonce: String,
    dataspace_alias: String,
    pub(super) dataspace_id: String,
    pub(super) previous_contract_address: Option<String>,
    pub(super) observed_block_height: String,
    pub(super) observed_block_hash: String,
    ledger_time_ms: String,
    chain_discriminant: String,
}
pub struct ValidatedContractDeploymentState {
    pub(super) snapshot: ContractDeploymentStateSnapshot,
    pub(super) deploy_nonce: u64,
    pub(super) dataspace_id: DataSpaceId,
    pub(super) previous_contract_address:
        Option<iroha::data_model::smart_contract::ContractAddress>,
}
pub fn insert_string_metadata(
    metadata: &mut Metadata,
    key: &str,
    value: impl Into<String>,
) -> Result<()> {
    metadata.insert(Name::from_str(key)?, Json::new(value.into()));
    Ok(())
}
pub fn insert_gov_manifest_approvers(metadata: &mut Metadata, approvers: &[String]) -> Result<()> {
    let mut accounts = Vec::new();
    for (index, raw) in approvers.iter().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(eyre!("--gov-manifest-approver[{index}] must not be blank"));
        }
        accounts.push(trimmed.to_owned());
    }
    if !accounts.is_empty() {
        metadata.insert(
            Name::from_str("gov_manifest_approvers")?,
            Json::new(accounts),
        );
    }
    Ok(())
}
pub fn deployment_transaction_metadata(
    contract_address: &iroha::data_model::smart_contract::ContractAddress,
    gov_manifest_approvers: &[String],
) -> Result<Metadata> {
    let mut metadata = Metadata::default();
    insert_string_metadata(
        &mut metadata,
        "gov_contract_address",
        contract_address.to_string(),
    )?;
    insert_string_metadata(
        &mut metadata,
        "contract_address",
        contract_address.to_string(),
    )?;
    insert_gov_manifest_approvers(&mut metadata, gov_manifest_approvers)?;
    Ok(metadata)
}
pub fn canonical_decimal_u64(raw: &str, field: &str) -> Result<u64> {
    let parsed = raw
        .parse::<u64>()
        .wrap_err_with(|| format!("deployment-state `{field}` is not a u64"))?;
    if parsed.to_string() != raw {
        return Err(eyre!(
            "deployment-state `{field}` is not canonical decimal text"
        ));
    }
    Ok(parsed)
}
pub fn read_contract_deployment_state(
    client: &Client,
    authority: &AccountId,
    contract_alias: &ContractAlias,
    chain_discriminant: u16,
) -> Result<ValidatedContractDeploymentState> {
    let response = client
        .client()
        .post_contract_deployment_state(contract_alias)
        .wrap_err("failed to read authenticated contract deployment state")?;
    let status = response.status();
    let body = response.into_body();
    if status.as_u16() != 200 {
        return Err(eyre!(
            "contract deployment-state request failed with HTTP {}: {}",
            status,
            std::str::from_utf8(&body).unwrap_or("")
        ));
    }
    let snapshot: ContractDeploymentStateSnapshot = norito::json::from_slice(&body)
        .wrap_err("decode closed contract deployment-state response")?;
    if snapshot.authority != authority.to_string()
        || snapshot.contract_alias != contract_alias.to_string()
    {
        return Err(eyre!(
            "contract deployment-state response does not bind the exact authority and alias"
        ));
    }
    let deploy_nonce = canonical_decimal_u64(&snapshot.deploy_nonce, "deploy_nonce")?;
    if deploy_nonce == u64::MAX {
        return Err(eyre!("contract deployment nonce is exhausted"));
    }
    let dataspace_id = DataSpaceId::new(canonical_decimal_u64(
        &snapshot.dataspace_id,
        "dataspace_id",
    )?);
    let expected_dataspace_alias = if contract_alias.dataspace_segment() == "universal" {
        "universal"
    } else {
        contract_alias.dataspace_segment()
    };
    if snapshot.dataspace_alias != expected_dataspace_alias {
        return Err(eyre!(
            "contract deployment-state response names a different dataspace alias"
        ));
    }
    let response_discriminant =
        canonical_decimal_u64(&snapshot.chain_discriminant, "chain_discriminant")?;
    if response_discriminant != u64::from(chain_discriminant) {
        return Err(eyre!(
            "contract deployment-state chain discriminant differs from the configured client"
        ));
    }
    let observed_height =
        canonical_decimal_u64(&snapshot.observed_block_height, "observed_block_height")?;
    if observed_height == 0 {
        return Err(eyre!(
            "contract deployment-state observed block height must be non-zero"
        ));
    }
    canonical_decimal_u64(&snapshot.ledger_time_ms, "ledger_time_ms")?;
    let observed_hash: iroha_crypto::HashOf<iroha::data_model::block::BlockHeader> = snapshot
        .observed_block_hash
        .parse()
        .wrap_err("deployment-state observed block hash is invalid")?;
    if observed_hash.to_string() != snapshot.observed_block_hash {
        return Err(eyre!(
            "deployment-state observed block hash is not canonical"
        ));
    }
    let previous_contract_address = snapshot
        .previous_contract_address
        .as_deref()
        .map(str::parse::<iroha::data_model::smart_contract::ContractAddress>)
        .transpose()
        .wrap_err("deployment-state previous contract address is invalid")?;
    if let Some(previous) = previous_contract_address.as_ref()
        && (previous.to_string()
            != snapshot
                .previous_contract_address
                .as_deref()
                .expect("present parsed previous address has source")
            || previous
                .dataspace_id()
                .map_err(|error| eyre!(error.to_string()))?
                != dataspace_id)
    {
        return Err(eyre!(
            "deployment-state previous contract address is non-canonical or in another dataspace"
        ));
    }
    Ok(ValidatedContractDeploymentState {
        snapshot,
        deploy_nonce,
        dataspace_id,
        previous_contract_address,
    })
}
pub struct NativeUploadTransactionPlan {
    pub(super) chunk_count: u32,
    pub(super) pre_stage: Vec<(String, String, SignedTransaction)>,
    pub(super) finalize: (String, String, SignedTransaction),
}
pub struct TransactionSigningContext<'a> {
    pub(super) network_id: NetworkId,
    pub(super) authority: &'a AccountId,
    pub(super) private_key: &'a PrivateKey,
    pub(super) transaction_ttl: Option<Duration>,
    pub(super) fee_payment: &'a FeePaymentIntent,
    pub(super) metadata: &'a Metadata,
}
impl TransactionSigningContext<'_> {
    pub(super) fn sign(
        &self,
        instructions: impl IntoIterator<Item = InstructionBox>,
    ) -> Result<SignedTransaction> {
        let mut builder = TransactionBuilder::new(
            self.network_id,
            self.authority.clone(),
            self.fee_payment.clone(),
        );
        if let Some(transaction_ttl) = self.transaction_ttl {
            builder.set_ttl(transaction_ttl);
        }
        builder
            .with_metadata(self.metadata.clone())
            .with_instructions(instructions)
            .try_sign(self.private_key)
            .wrap_err("failed to sign instruction transaction")
    }
}
#[cfg(test)]
pub fn native_upload_report(
    plan: &NativeUploadTransactionPlan,
    skip_register_bytes: bool,
) -> norito::json::Value {
    let register_bytes_stage_tx_hashes = if skip_register_bytes {
        Vec::new()
    } else {
        plan.pre_stage
            .iter()
            .map(|(_, _, transaction)| transaction.hash().to_string())
            .collect::<Vec<_>>()
    };
    let register_bytes_tx_hash = (!skip_register_bytes).then(|| plan.finalize.2.hash().to_string());
    norito::json!({
        "register_bytes_tx_strategy": ("native_chunks"),
        "register_bytes_chunk_size": (u64::try_from(SMART_CONTRACT_CODE_CHUNK_BYTES)
            .expect("public contract chunk size fits u64")),
        "register_bytes_chunk_count": (plan.chunk_count),
        "register_bytes_stage_tx_hashes": (register_bytes_stage_tx_hashes),
        "register_bytes_tx_hash": (register_bytes_tx_hash),
    })
}
pub fn deployment_transaction_sequence(
    skip_register_bytes: bool,
    register_plans: Vec<(String, String, SignedTransaction)>,
    register_manifest_tx: SignedTransaction,
    commit_deployment_tx: SignedTransaction,
) -> Vec<(String, String, SignedTransaction)> {
    let mut planned = if skip_register_bytes {
        Vec::new()
    } else {
        register_plans
    };
    planned.push((
        "register_manifest".to_owned(),
        "register-manifest".to_owned(),
        register_manifest_tx,
    ));
    planned.push((
        "commit_deployment".to_owned(),
        "commit-deployment".to_owned(),
        commit_deployment_tx,
    ));
    planned
}
#[allow(clippy::too_many_arguments)]
pub fn build_commit_deployment_transaction(
    signing: &TransactionSigningContext<'_>,
    expected_deploy_nonce: u64,
    contract_address: iroha::data_model::smart_contract::ContractAddress,
    code_hash: Hash,
    contract_alias: ContractAlias,
    expected_previous_contract_address: Option<iroha::data_model::smart_contract::ContractAddress>,
) -> Result<SignedTransaction> {
    signing.sign([InstructionBox::from(CommitContractDeployment {
        expected_deploy_nonce,
        contract_address,
        code_hash,
        contract_alias,
        lease_expiry_ms: None,
        expected_previous_contract_address,
    })])
}
pub fn build_native_upload_transaction_plan(
    signing: &TransactionSigningContext<'_>,
    artifact_id: ContractArtifactId,
    code: &[u8],
) -> Result<NativeUploadTransactionPlan> {
    if code.is_empty() {
        return Err(eyre!("contract artifact must not be empty"));
    }
    let canonical_code_hash = ivm_abi::metadata::contract_code_hash(code);
    if artifact_id.code_hash != canonical_code_hash {
        return Err(eyre!(
            "contract code hash does not match the canonical artifact hash"
        ));
    }
    let total_size = u64::try_from(code.len())
        .wrap_err("contract artifact length does not fit the upload descriptor")?;
    let chunk_count_usize = code.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES);
    let chunk_count = u32::try_from(chunk_count_usize)
        .wrap_err("contract upload chunk count does not fit u32")?;
    let mut pre_stage = Vec::with_capacity(chunk_count_usize.saturating_sub(1));
    for (index, chunk) in code.chunks(SMART_CONTRACT_CODE_CHUNK_BYTES).enumerate() {
        let chunk_index =
            u32::try_from(index).wrap_err("contract upload index does not fit u32")?;
        let upload = UploadSmartContractCodeChunk {
            artifact_id,
            total_size,
            chunk_index,
            chunk_count,
            chunk: chunk.to_vec(),
        };
        let is_final = index + 1 == chunk_count_usize;
        let instructions = if is_final {
            vec![
                InstructionBox::from(upload),
                InstructionBox::from(FinalizeSmartContractCodeUpload {
                    artifact_id,
                    total_size,
                    chunk_count,
                }),
            ]
        } else {
            vec![InstructionBox::from(upload)]
        };
        let tx = signing.sign(instructions)?;
        if is_final {
            return Ok(NativeUploadTransactionPlan {
                chunk_count,
                pre_stage,
                finalize: (
                    "register_bytes_finalize".to_owned(),
                    "register-bytes-finalize".to_owned(),
                    tx,
                ),
            });
        }
        let ordinal = index + 1;
        pre_stage.push((
            format!("register_bytes_chunk_{ordinal:04}_of_{chunk_count_usize:04}"),
            format!("register-bytes-chunk-{ordinal:04}-of-{chunk_count_usize:04}"),
            tx,
        ));
    }
    Err(eyre!("contract upload plan did not contain a final chunk"))
}
pub fn quote_and_resign_transaction(
    client: &Client,
    draft: &SignedTransaction,
    requested_fee_payment: &FeePaymentIntent,
) -> Result<(SignedTransaction, FeeQuoteResponse)> {
    quote_and_resign_transaction_reviewed(client, draft, requested_fee_payment, &mut |_| Ok(()))
}
/// Review an exact fee quote before signing its unchanged payer and gas-bound intent.
pub fn quote_and_resign_transaction_reviewed(
    client: &Client,
    draft: &SignedTransaction,
    requested_fee_payment: &FeePaymentIntent,
    review: &mut dyn FnMut(&FeeQuoteResponse) -> Result<()>,
) -> Result<(SignedTransaction, FeeQuoteResponse)> {
    let mut payload = draft.payload().clone();
    let quote = client
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .wrap_err("failed to quote exact contract-deployment transaction fees")?;
    if !requested_fee_payment.has_same_payer_and_gas_bound(&quote.intent) {
        return Err(eyre!(
            "fee quote changed the selected payer, sponsor revision, or gas bound; refusing to sign"
        ));
    }
    review(&quote)?;
    payload.fee_payment = quote.intent.clone();
    let transaction = client
        .account_client()
        .sign_transaction(payload)
        .wrap_err("failed to sign exact quoted contract-deployment payload")?;
    Ok((transaction, quote))
}

/// Bind fee preflight to the dataspace already selected by native deployment state.
pub fn validate_quote_route(
    quote: &FeeQuoteResponse,
    expected_dataspace: DataSpaceId,
) -> Result<()> {
    if quote.observation.route_dataspace_id != expected_dataspace {
        return Err(eyre!(
            "fee quote route differs from the exact contract dataspace"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
