//! Shared signed Parliament submissions and canonical contract artifacts for real networks.

use std::time::Duration;

use eyre::{Result, eyre};
use integration_tests::manifest::ManifestEncodingBudget;
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, FeeQuoteRequest},
    data_model::{
        governance::types::{ContractAbiHash, ContractCodeHash},
        isi::{
            InstructionBox, Log,
            smart_contract_code::{
                FinalizeSmartContractCodeUpload, RegisterSmartContractCode,
                SMART_CONTRACT_CODE_CHUNK_BYTES, UploadSmartContractCodeChunk,
            },
        },
        prelude::{FeePaymentIntent, SignedTransaction},
    },
};
use iroha_model_base::metadata::Metadata;

pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(300);

const FEE_QUOTE_BACKPRESSURE_ATTEMPTS: usize = 8;
// A single attempt would make the backpressure retry unreachable.
const _: () = assert!(FEE_QUOTE_BACKPRESSURE_ATTEMPTS > 1);
const FEE_QUOTE_BACKPRESSURE_RETRY_AFTER: Duration = Duration::from_secs(1);

// Exact transient admission backpressure of the read path; nothing else is retried.
fn is_query_capacity_backpressure(rendered: &str) -> bool {
    rendered.contains("429 Too Many Requests")
        && rendered.contains("Reached the limit of parallel queries")
}

pub(crate) fn fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), None)
}

// The blocking client is retained only as the test network's account/configuration
// holder. All writes use its current account-owned async signing and finality API.
pub(crate) async fn prepare_parliament_transaction(
    client: &Client,
    instructions: impl IntoIterator<Item = impl Into<InstructionBox>>,
) -> Result<SignedTransaction> {
    let account = client.account_client();
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        instructions.into_iter().map(Into::into).collect::<Vec<_>>(),
        fee(),
        Metadata::default(),
    ))?;
    // The fee quote is a read against the bounded live-query store. Under local load the
    // node answers 429 with a one-second retry hint; honour it a bounded number of times
    // and surface every other failure unchanged.
    let mut quote_attempt = 1_usize;
    let quote = loop {
        let quoted = tokio::time::timeout(
            OPERATION_TIMEOUT,
            account.quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload }),
        )
        .await
        .map_err(|_| eyre!("Parliament fee quote exceeded {OPERATION_TIMEOUT:?}"))?;
        match quoted {
            Ok(quote) => break quote,
            Err(error)
                if quote_attempt < FEE_QUOTE_BACKPRESSURE_ATTEMPTS
                    && is_query_capacity_backpressure(&format!("{error:#}")) =>
            {
                quote_attempt += 1;
                tokio::time::sleep(FEE_QUOTE_BACKPRESSURE_RETRY_AFTER).await;
            }
            Err(error) => return Err(error),
        }
    };
    if !payload
        .fee_payment
        .has_same_payer_and_gas_bound(&quote.intent)
    {
        return Err(eyre!("Parliament fee quote changed payer or gas bound"));
    }
    payload.fee_payment = quote.intent;
    Ok(account.sign_transaction(payload)?)
}

pub(crate) async fn submit_parliament_instructions(
    client: &Client,
    instructions: impl IntoIterator<Item = impl Into<InstructionBox>>,
) -> Result<()> {
    let transaction = prepare_parliament_transaction(client, instructions).await?;
    let applied_hash = tokio::time::timeout(
        OPERATION_TIMEOUT,
        client
            .account_client()
            .submit_transaction_and_wait(&transaction),
    )
    .await
    .map_err(|_| eyre!("Parliament Applied finality exceeded {OPERATION_TIMEOUT:?}"))??;
    if applied_hash != transaction.hash() {
        return Err(eyre!(
            "Parliament Applied response substituted the signed transaction hash"
        ));
    }
    Ok(())
}

// The caller observes the exact certified carrier height after native admission.
pub(crate) async fn admit_parliament_height_carrier(
    client: &Client,
    instructions: [Log; 1],
) -> Result<()> {
    let transaction = prepare_parliament_transaction(client, instructions).await?;
    let admitted_hash = tokio::time::timeout(
        OPERATION_TIMEOUT,
        client.account_client().submit_transaction(&transaction),
    )
    .await
    .map_err(|_| eyre!("Parliament carrier admission exceeded {OPERATION_TIMEOUT:?}"))??;
    if admitted_hash != transaction.hash() {
        return Err(eyre!(
            "Parliament carrier admission substituted the signed hash"
        ));
    }
    Ok(())
}

pub(crate) fn minimal_contract_artifact() -> Vec<u8> {
    minimal_contract_artifact_with_identity("ParliamentLifecycleSmoke", "integration-tests")
}

pub(crate) fn minimal_contract_artifact_with_identity(
    seiyaku_name: &str,
    compiler_fingerprint: &str,
) -> Vec<u8> {
    let metadata = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1_000,
        abi_version: 1,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![ivm::call::EmbeddedCallableV1 {
            entry_pc: 0,
            frame_bytes: 0,
            arguments: ivm::call::CallSchemaV1::empty(),
            results: ivm::call::CallSchemaV1::unit(),
        }],
        seiyaku_name: seiyaku_name.to_owned(),
        compiler_fingerprint: compiler_fingerprint.to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        permissions: Vec::new(),
        events: Vec::new(),
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha::data_model::smart_contract::manifest::EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_types: Vec::new(),
        enum_types: Vec::new(),
        error_messages: Vec::new(),
        states: Vec::new(),
    };
    let mut artifact = metadata.encode();
    artifact.extend_from_slice(&interface.encode_section());
    // Return Unit through the caller-owned result table required by this ABI.
    use ivm::{encoding::wide as enc, instruction::wide};
    for word in [
        enc::encode_store(wide::memory::STORE64, 12, 0, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
    ] {
        artifact.extend_from_slice(&word.to_le_bytes());
    }
    artifact
}

pub(crate) async fn stage_contract_artifact(
    client: &Client,
    artifact: &[u8],
) -> Result<(ContractCodeHash, ContractAbiHash)> {
    let encoding = ManifestEncodingBudget::new()?;
    let verified = ivm::verify_contract_artifact(artifact)
        .map_err(|error| eyre!("verify integration contract artifact: {error}"))?;
    let manifest = verified
        .manifest
        .try_signed(
            encoding.context(),
            encoding.max_frame_bytes(),
            client.client().key_pair(),
        )
        .map_err(|error| eyre!("sign integration contract manifest: {error}"))?;
    let total_size = u64::try_from(artifact.len())?;
    let chunk_count = u32::try_from(artifact.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES))?;
    for (index, chunk) in artifact.chunks(SMART_CONTRACT_CODE_CHUNK_BYTES).enumerate() {
        let chunk_index = u32::try_from(index)?;
        let mut instructions = vec![InstructionBox::from(UploadSmartContractCodeChunk {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                verified.code_hash,
            ),
            total_size,
            chunk_index,
            chunk_count,
            chunk: chunk.to_vec(),
        })];
        if chunk_index + 1 == chunk_count {
            instructions.push(InstructionBox::from(FinalizeSmartContractCodeUpload {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    verified.code_hash,
                ),
                total_size,
                chunk_count,
            }));
        }
        submit_parliament_instructions(&client, instructions).await?;
    }
    submit_parliament_instructions(
        &client,
        [{
            let scoped_manifest = manifest;
            RegisterSmartContractCode {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    scoped_manifest
                        .code_hash
                        .ok_or_else(|| eyre!("verified contract manifest omitted its code hash"))?,
                ),
                manifest: scoped_manifest,
            }
        }],
    )
    .await?;
    let code_hash = *verified.code_hash.as_ref();
    let abi_hash = *verified.abi_hash.as_ref();
    Ok((
        ContractCodeHash::new(code_hash),
        ContractAbiHash::new(abi_hash),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_query_capacity_backpressure_is_retried() {
        assert!(is_query_capacity_backpressure(
            "failed to quote transaction fees; status: 429 Too Many Requests; response body: \
             query_validation_failed: Reached the limit of parallel queries. Either wait"
        ));
        assert!(!is_query_capacity_backpressure(
            "status: 429 Too Many Requests; response body: rate limited"
        ));
        assert!(!is_query_capacity_backpressure(
            "status: 400 Bad Request; Reached the limit of parallel queries"
        ));
    }

    #[test]
    fn parliament_artifacts_bind_identity_and_current_abi_before_submission() {
        let original = minimal_contract_artifact_with_identity("CommitteePulse", "native-tests");
        let verified =
            ivm::verify_contract_artifact(&original).expect("canonical fixture artifact");
        assert_eq!(verified.metadata.abi_version, 1);
        assert_eq!(
            verified.contract_interface.callables,
            [ivm::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm::call::CallSchemaV1::empty(),
                results: ivm::call::CallSchemaV1::unit(),
            }],
        );
        assert_eq!(verified.manifest.code_hash, Some(verified.code_hash));
        assert_eq!(
            verified.abi_hash.as_ref(),
            &ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1)
        );
        assert_eq!(verified.contract_interface.seiyaku_name, "CommitteePulse");
        assert_eq!(
            verified.contract_interface.compiler_fingerprint,
            "native-tests"
        );
        let other = ivm::verify_contract_artifact(&minimal_contract_artifact_with_identity(
            "OtherPulse",
            "native-tests",
        ))
        .expect("distinct canonical artifact");
        assert_ne!(verified.code_hash, other.code_hash);
        let mut truncated = original;
        truncated.pop();
        assert!(ivm::verify_contract_artifact(&truncated).is_err());
        assert!(ivm::verify_contract_artifact(&minimal_contract_artifact()).is_ok());
    }
}
