//! Borrowed literal admission and exact canonical-payload resource refusals.

use super::{
    AccountId, AssetDefinitionId, AssetId, AxtAnchoredSpendV1, AxtDescriptor,
    ContractArtifactError, DataSpaceId, DecimalValueV1, DecodedOp, DomainId, IntValueV1, Json,
    Name, NftId, ParsedProgramMetadata, ProofBlob, QuantityValueV1, SoracloudHostRequestEnvelopeV1,
    SoracloudHostResponseEnvelopeV1, SyscallPolicy, VMError, validate_descriptor,
    validate_proof_blob,
};
use ivm_abi::metadata::{LiteralDirectory, ValidatedLiteral};

pub fn validate_literal_table(
    artifact: &[u8],
    parsed: &ParsedProgramMetadata,
    decoded: &[DecodedOp],
) -> Result<(), ContractArtifactError> {
    let validate = || -> Result<LiteralDirectory<'_>, VMError> {
        let directory = LiteralDirectory::validate(
            artifact,
            parsed.header_len,
            parsed.literal_section,
            SyscallPolicy::AbiV1,
        )
        .map_err(|error| {
            ivm_abi::error::preserve_execution_deferral(error, VMError::InvalidMetadata)
        })?;
        for value in directory.iter() {
            if let ValidatedLiteral::Pointer {
                type_id, payload, ..
            } = value
            {
                validate_literal_payload(type_id, payload)?;
            }
        }
        Ok(directory)
    };
    let literals = validate()
        .map_err(|error| ContractArtifactError::preparation("literal index validation", error))?;
    for op in decoded {
        let expects_i64 = match ivm_abi::instruction::wide::opcode(op.inst) {
            ivm_abi::instruction::wide::memory::LDLIT => Some(false),
            ivm_abi::instruction::wide::memory::LDI64 => Some(true),
            _ => None,
        };
        if let Some(expects_i64) = expects_i64 {
            let literal = literals
                .get(ivm_abi::instruction::wide::literal_index(op.inst))
                .ok_or_else(|| {
                    ContractArtifactError::invalid(
                        "literal instruction validation failed: invalid metadata",
                    )
                })?;
            if matches!(literal, ValidatedLiteral::I64(_)) != expects_i64 {
                return Err(ContractArtifactError::invalid(
                    "literal instruction validation failed: invalid metadata",
                ));
            }
        }
    }
    Ok(())
}
fn decode_canonical_literal_payload<T>(payload: &[u8]) -> Result<T, VMError>
where
    T: for<'__frame> norito::NoritoDeserialize<'__frame> + norito::NoritoSerialize,
{
    norito::decode_canonical_for_admission(
        payload,
        ivm_abi::codec::canonical_norito_decode_limits(payload.len()),
    )
    .map_err(|error| match error.into_local_refusal() {
        Ok(original) => VMError::DecodeDeferred(original),
        Err(_) => VMError::InvalidMetadata,
    })
}
pub fn validate_literal_payload(
    type_id: ivm_abi::pointer_abi::PointerType,
    payload: &[u8],
) -> Result<(), VMError> {
    use ivm_abi::pointer_abi::PointerType;
    // A literal pointer's nominal type is part of the authenticated artifact
    // contract. Validate every compiler-structured payload at admission rather
    // than deferring malformed frames to whichever syscall first consumes
    // them. Blob and NoritoBytes deliberately remain opaque byte containers.
    //
    // Malformed payloads retain the deterministic metadata failure. Original
    // local decoder refusals survive every wrapper without changing validity.
    match type_id {
        PointerType::AccountId => decode_canonical_literal_payload::<AccountId>(payload).map(drop),
        PointerType::AssetDefinitionId => {
            decode_canonical_literal_payload::<AssetDefinitionId>(payload).map(drop)
        }
        PointerType::Name => decode_canonical_literal_payload::<Name>(payload).map(drop),
        PointerType::Json => decode_canonical_literal_payload::<Json>(payload).map(drop),
        PointerType::NftId => decode_canonical_literal_payload::<NftId>(payload).map(drop),
        PointerType::Blob | PointerType::NoritoBytes => Ok(()),
        PointerType::AssetId => decode_canonical_literal_payload::<AssetId>(payload).map(drop),
        PointerType::DomainId => decode_canonical_literal_payload::<DomainId>(payload).map(drop),
        PointerType::DataSpaceId => {
            decode_canonical_literal_payload::<DataSpaceId>(payload).map(drop)
        }
        PointerType::AxtDescriptor => {
            let descriptor = decode_canonical_literal_payload::<AxtDescriptor>(payload)?;
            validate_descriptor(&descriptor).map_err(|_| VMError::InvalidMetadata)
        }
        PointerType::ProofBlob => {
            let proof = decode_canonical_literal_payload::<ProofBlob>(payload)?;
            validate_proof_blob(&proof).map_err(|_| VMError::InvalidMetadata)
        }
        PointerType::AxtAnchoredSpendV1 => {
            let spend = decode_canonical_literal_payload::<AxtAnchoredSpendV1>(payload)?;
            spend
                .issuer_payload_v1()
                .map(drop)
                .map_err(|_| VMError::InvalidMetadata)
        }
        PointerType::SoracloudRequest => {
            let request =
                decode_canonical_literal_payload::<SoracloudHostRequestEnvelopeV1>(payload)?;
            request.validate().map_err(|_| VMError::InvalidMetadata)
        }
        PointerType::SoracloudResponse => {
            let response =
                decode_canonical_literal_payload::<SoracloudHostResponseEnvelopeV1>(payload)?;
            response.validate().map_err(|_| VMError::InvalidMetadata)
        }
        PointerType::Int => IntValueV1::decode_frame(payload)
            .map(drop)
            .map_err(|_| VMError::InvalidMetadata),
        PointerType::Decimal => DecimalValueV1::decode_frame(payload)
            .map(drop)
            .map_err(|_| VMError::InvalidMetadata),
        PointerType::Quantity => QuantityValueV1::decode_frame(payload)
            .map(drop)
            .map_err(|_| VMError::InvalidMetadata),
    }
    .map_err(|error| ivm_abi::error::preserve_execution_deferral(error, VMError::InvalidMetadata))
}

#[cfg(test)]
mod tests;
