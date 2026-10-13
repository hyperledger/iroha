//! Verified contract upload used by the Parliament lifecycle and committee-transition corridors.

use super::parliament_submission::submit_parliament_instructions;
use eyre::{Result, eyre};
use integration_tests::manifest::ManifestEncodingBudget;
use iroha::{
    blocking::Client,
    data_model::{
        governance::types::{ContractAbiHash, ContractCodeHash},
        isi::{
            InstructionBox,
            smart_contract_code::{
                FinalizeSmartContractCodeUpload, RegisterSmartContractCode,
                SMART_CONTRACT_CODE_CHUNK_BYTES, UploadSmartContractCodeChunk,
            },
        },
    },
};

pub async fn stage_contract_artifact(
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
        submit_parliament_instructions(client, instructions).await?;
    }
    submit_parliament_instructions(
        client,
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
