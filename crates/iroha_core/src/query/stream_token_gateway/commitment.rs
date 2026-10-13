//! Exact canonical native gateway instruction and signing-authority commitments.

use super::rows::TransitionError;
use iroha_crypto::Hash;
use iroha_data_model::{account::AccountId, isi::sorafs::MutateSorafsStreamTokenGateway};

const MAX_INSTRUCTION_COMMITMENT_BYTES: usize = 64 * 1024;

/// Bind the complete native action and actual signing authority under one bounded domain.
pub(crate) fn instruction_digest(
    instruction: &MutateSorafsStreamTokenGateway,
    authority: &AccountId,
) -> Result<[u8; 32], TransitionError> {
    const DOMAIN: &[u8] = b"iroha.sorafs.stream-token.gateway-instruction.v1\0";
    let request_len =
        norito::canonical_frame_len(instruction).map_err(|_| TransitionError::Invalid)?;
    let authority_len =
        norito::canonical_frame_len(authority).map_err(|_| TransitionError::Invalid)?;
    let length = request_len
        .checked_add(authority_len)
        .filter(|length| *length <= MAX_INSTRUCTION_COMMITMENT_BYTES)
        .ok_or(TransitionError::Invalid)?;
    let request = norito::encode_canonical(instruction).map_err(|_| TransitionError::Invalid)?;
    let account = norito::encode_canonical(authority).map_err(|_| TransitionError::Invalid)?;
    let mut bytes = Vec::with_capacity(DOMAIN.len() + length);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&request);
    bytes.extend_from_slice(&account);
    Ok(*Hash::new(bytes).as_ref())
}
