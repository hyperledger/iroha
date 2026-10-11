//! Sole signed native pin-outbox transitions and challenge-bound current-row checks.

use super::*;
use crate::execution_attempt::norito_decode_attempt_error;
use iroha_crypto::{Algorithm, Hash, HashOf};
use iroha_data_model::{
    ValidationFail,
    block::consensus::SumeragiRootScope,
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};

// These are local relative source-read limits, not consensus rejection bounds or a chain-age
// ceiling. Recent floors cost only their distance from the original State execution tip.
const MAX_FLOOR_SOURCE_WORK: u64 = 4_096;
const MAX_FLOOR_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// Private one-use evidence retained only by the executor of the original signed External.
/// No decoder, instruction caller, snapshot, or nested execution can construct this owner.
pub(crate) struct PinOutboxOperationOrigin {
    signed_hash: HashOf<SignedTransaction>,
    entry_hash: HashOf<TransactionEntrypoint>,
    entry_index: u64,
    instruction_hash: Hash,
    is_check: bool,
}

/// Capture a sole direct native instruction from its original signed network input.
pub(crate) fn capture_pin_outbox_operation_origin(
    state: &mut StateTransaction<'_, '_>,
    signed: &SignedTransaction,
    instruction: &InstructionBox,
    direct_body: bool,
) -> Result<Option<PinOutboxOperationOrigin>, ValidationFail> {
    state.current_direct_musubi_pin_outbox_origin = None;
    if !direct_body
        || state.genesis_execution_scope.is_some()
        || state._curr_block.height().get() <= 1
        || !(instruction.as_any().is::<AdvanceMusubiPinOutboxV1>()
            || instruction.as_any().is::<CheckMusubiPinOutboxV1>())
    {
        return Ok(None);
    }
    let Executable::Instructions(instructions) = signed.instructions() else {
        return Ok(None);
    };
    if instructions.len() != 1
        || instructions.first() != Some(instruction)
        || signed.network_id() != Some(state.network_id())
        || signed.payload().attachments.is_some()
        || signed.multisig_signatures().is_some()
        || signed
            .authority()
            .try_signatory()
            .and_then(|key| key.try_algorithm().ok())
            != Some(Algorithm::Ed25519)
    {
        return Ok(None);
    }
    // Bound the borrowed signed value before retaining its owned External representation.
    // Both size passes preserve the original inherited decoder/allocation refusal if present;
    // neither creates a fresh budget or an invented allocator release observation.
    let signed_len = norito::canonical_frame_len(signed).map_err(|error| {
        state.attempt_error_to_validation_fail(norito_decode_attempt_error(error, |_| {
            ValidationFail::NotPermitted("invalid Musubi pin-outbox signed frame".into())
        }))
    })?;
    if signed_len > MUSUBI_PIN_OUTBOX_EXTERNAL_MAX_BYTES_V1 {
        return Ok(None);
    }
    let signed_bytes =
        encode_owned_frame(signed, signed_len).map_err(|error| origin_codec_error(state, error))?;
    let owned_signed = norito::decode_canonical::<SignedTransaction>(&signed_bytes)
        .map_err(|error| origin_codec_error(state, error))?;
    let entry = TransactionEntrypoint::External(owned_signed);
    let entry_len = norito::canonical_frame_len(&entry).map_err(|error| {
        state.attempt_error_to_validation_fail(norito_decode_attempt_error(error, |_| {
            ValidationFail::NotPermitted("invalid Musubi pin-outbox External frame".into())
        }))
    })?;
    if entry_len > MUSUBI_PIN_OUTBOX_EXTERNAL_MAX_BYTES_V1
        || signed.payload().validate_fee_payment_intent().is_err()
    {
        return Ok(None);
    }
    let payload_hash =
        HashOf::try_new(signed.payload()).map_err(|error| origin_codec_error(state, error))?;
    // Reuse exactly the borrowed Ed25519 admission relation and original typed payload prehash.
    // The primitive retains only fixed semantic parser/signature errors, never resource failures.
    let Some(signatory) = signed.authority().try_signatory() else {
        return Ok(None);
    };
    if iroha_crypto::verify_signature_borrowed(
        &signed.signature().0,
        signatory,
        payload_hash.as_ref(),
    )
    .is_err()
    {
        return Ok(None);
    }
    let entry_hash = signed
        .try_hash_as_entrypoint()
        .map_err(|error| origin_codec_error(state, error))?;
    let signed_hash = HashOf::from_untyped_unchecked(Hash::from(entry_hash));
    let (instruction_hash, is_check) = if let Some(value) = instruction
        .as_any()
        .downcast_ref::<CheckMusubiPinOutboxV1>(
    ) {
        let len =
            norito::canonical_frame_len(value).map_err(|error| origin_codec_error(state, error))?;
        if len > MUSUBI_PIN_OUTBOX_CHECK_MAX_BYTES_V1 {
            return Ok(None);
        }
        (
            Hash::from(HashOf::try_new(value).map_err(|error| origin_codec_error(state, error))?),
            true,
        )
    } else if let Some(value) = instruction
        .as_any()
        .downcast_ref::<AdvanceMusubiPinOutboxV1>()
    {
        (
            Hash::from(HashOf::try_new(value).map_err(|error| origin_codec_error(state, error))?),
            false,
        )
    } else {
        return Ok(None);
    };
    let Some(entry_index) = state.current_entrypoint_index else {
        return Ok(None);
    };
    if state.current_network_entrypoint_hash != Some(entry_hash)
        || state.tx_call_hash != Some(Hash::from(entry_hash))
        || state.current_tx_hash != Some(signed_hash)
    {
        return Ok(None);
    }
    Ok(Some(PinOutboxOperationOrigin {
        signed_hash,
        entry_hash,
        entry_index,
        instruction_hash,
        is_check,
    }))
}

fn origin_codec_error(
    state: &mut StateTransaction<'_, '_>,
    error: norito::Error,
) -> ValidationFail {
    state.attempt_error_to_validation_fail(norito_decode_attempt_error(error, |_| {
        ValidationFail::NotPermitted("invalid Musubi pin-outbox original encoding".into())
    }))
}

fn encode_owned_frame<T: norito::NoritoSerialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, norito::Error> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::core::encoded_frame_len(value)?;
    if length > maximum {
        return Err(norito::Error::LengthMismatch);
    }
    // The exact destination encoder charges its physical frame once to the inherited
    // cumulative owner. The subsequent owned decode spends the same unchanged scope.
    norito::core::to_bytes_bounded(value, length).map_err(|error| match error {
        norito::core::BoundedEncodeError::Serialization(error) => error,
        norito::core::BoundedEncodeError::AllocationFailed { bytes } => {
            norito::Error::AllocationFailed {
                bytes: bytes as u64,
            }
        }
        norito::core::BoundedEncodeError::FrameTooLarge { .. } => norito::Error::LengthMismatch,
    })
}

fn consume_origin<T: norito::codec::Encode>(
    instruction: &T,
    is_check: bool,
    authority: &AccountId,
    pin_authority: &AccountId,
    network: &iroha_data_model::NetworkId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<HashOf<SignedTransaction>, Error> {
    let origin = state
        .current_direct_musubi_pin_outbox_origin
        .take()
        .ok_or_else(|| invariant("Musubi pin-outbox requires a sole direct signed External"))?;
    let instruction_hash = HashOf::try_new(instruction)
        .map(Hash::from)
        .map_err(|error| {
            state.attempt_error_to_instruction_error(norito_decode_attempt_error(error, |_| {
                invariant("invalid Musubi pin-outbox instruction encoding")
            }))
        })?;
    if authority != pin_authority
        || network != state.network_id()
        || state.current_tx_hash != Some(origin.signed_hash)
        || state.current_network_entrypoint_hash != Some(origin.entry_hash)
        || state.tx_call_hash != Some(Hash::from(origin.entry_hash))
        || state.current_entrypoint_index != Some(origin.entry_index)
        || instruction_hash != origin.instruction_hash
        || is_check != origin.is_check
    {
        return Err(invariant(
            "Musubi pin-outbox original signed operation differs",
        ));
    }
    let scope = match crate::executor::root_scope::execution_root_scope(state) {
        Ok(scope) => scope,
        Err(_) => {
            if let Some(original) = state.execution_deferral() {
                return Err(state.attempt_error_to_instruction_error(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(original),
                ));
            }
            return Err(invariant(
                "Musubi pin-outbox requires the original Global root",
            ));
        }
    };
    if scope != SumeragiRootScope::Global {
        return Err(invariant(
            "Musubi pin-outbox requires the original Global root",
        ));
    }
    Ok(origin.signed_hash)
}

impl Execute for AdvanceMusubiPinOutboxV1 {
    fn execute(
        self,
        authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let signed_hash = consume_origin(
            &self,
            false,
            authority,
            &self.pin_authority,
            &self.network_id,
            state,
        )?;
        self.validate_fields()
            .map_err(|error| invalid_parameter(error.reason()))?;
        match state.world.musubi_pin_outbox_high_waters.get(authority) {
            None if self.expected_revision == 0 => {}
            Some(record)
                if record.network_id == self.network_id
                    && record.pin_authority == *authority
                    && record.session_id == self.session_id
                    && record.revision == self.expected_revision
                    && record.inventory_digest == self.expected_inventory_digest => {}
            _ => {
                return Err(invariant(
                    "Musubi pin-outbox predecessor is stale or substituted",
                ));
            }
        }
        let record = MusubiPinOutboxHighWaterV1 {
            version: MUSUBI_PIN_OUTBOX_HIGH_WATER_VERSION_V1,
            network_id: self.network_id,
            pin_authority: self.pin_authority,
            session_id: self.session_id,
            revision: self
                .expected_revision
                .checked_add(1)
                .ok_or_else(|| invalid_parameter("Musubi pin-outbox revision overflow"))?,
            inventory_digest: self.inventory_digest,
            recorded_at_height: execution_height(state),
            transaction_hash: *signed_hash.as_ref(),
        };
        // The record moves its signed authority. Materialize the table's separate key through
        // the bounded fallible codec, preserving the caller's original allocation scope.
        let key_bytes = encode_owned_frame(authority, MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1)
            .map_err(|error| {
                state.attempt_error_to_instruction_error(norito_decode_attempt_error(error, |_| {
                    invariant("invalid pin authority encoding")
                }))
            })?;
        let key: AccountId = norito::decode_canonical(&key_bytes).map_err(|error| {
            state.attempt_error_to_instruction_error(norito_decode_attempt_error(error, |_| {
                invariant("invalid pin authority encoding")
            }))
        })?;
        state
            .world
            .musubi_pin_outbox_high_waters
            .insert(key, record);
        Ok(())
    }
}

#[cfg(test)]
mod origin_tests;

impl Execute for CheckMusubiPinOutboxV1 {
    fn execute(
        self,
        authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        consume_origin(
            &self,
            true,
            authority,
            &self.pin_authority,
            &self.network_id,
            state,
        )?;
        self.validate_fields()
            .map_err(|error| invalid_parameter(error.reason()))?;
        state.authenticate_musubi_pin_outbox_floor(
            self.floor,
            MAX_FLOOR_SOURCE_WORK,
            MAX_FLOOR_SOURCE_BYTES,
        )?;
        // Lookup is authority-wide. Neither the signed local session nor its inventory can
        // hide an existing row, and Present compares every field, including original advance.
        let current = state.world.musubi_pin_outbox_high_waters.get(authority);
        match (&self.expected, current) {
            (MusubiPinOutboxCheckExpectationV1::Absent, None) => Ok(()),
            (MusubiPinOutboxCheckExpectationV1::Present(expected), Some(current))
                if expected == current =>
            {
                Ok(())
            }
            _ => Err(invariant("Musubi pin-outbox Check current row differs")),
        }
    }
}
