//! One canonical durable-record representation for scalar and tuple map keys.

use super::*;
use crate::metadata::EmbeddedStateType as Embedded;
use ivm_abi::state_value::{
    MAX_STATE_VALUE_NODES, MAX_STATE_VALUE_SCHEMA_BYTES, StateValueAtomV1 as Atom,
    StateValueKindV1 as Kind, StateValueNodeV1 as Node, StateValueSchemaV1,
    decode_canonical_state_value_record_v1, state_value_schema_hash_v1,
};

fn unavailable() -> VMError {
    VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable)
}
fn codec_error(error: norito::Error) -> VMError {
    match error {
        norito::Error::AllocationFailed { .. } => unavailable(),
        _ => VMError::NoritoInvalid,
    }
}
fn visit_key_type(ty: &Embedded, mut visit: impl FnMut(Node)) -> Result<usize, VMError> {
    let mut pending = [ty; MAX_STATE_VALUE_NODES];
    let mut pending_len = 1usize;
    let mut count = 0usize;
    while pending_len != 0 {
        pending_len -= 1;
        let ty = pending[pending_len];
        count += 1;
        if count > MAX_STATE_VALUE_NODES {
            return Err(VMError::NoritoInvalid);
        }
        let kind = match ty {
            Embedded::Tuple(items) => {
                if items.len() < 2 || items.len() > MAX_STATE_VALUE_NODES - count {
                    return Err(VMError::NoritoInvalid);
                }
                let end = pending_len
                    .checked_add(items.len())
                    .ok_or(VMError::NoritoInvalid)?;
                if end > MAX_STATE_VALUE_NODES {
                    return Err(VMError::NoritoInvalid);
                }
                for item in items.iter().rev() {
                    pending[pending_len] = item;
                    pending_len += 1;
                }
                visit(Node::Tuple {
                    arity: items.len() as u16,
                });
                continue;
            }
            Embedded::Bool => Kind::Bool,
            Embedded::Int => Kind::Int,
            Embedded::Decimal => Kind::Decimal,
            Embedded::Quantity => Kind::Quantity,
            Embedded::String => Kind::String,
            Embedded::Bytes => Kind::Bytes,
            Embedded::AccountId => Kind::AccountId,
            Embedded::AssetDefinitionId => Kind::AssetDefinitionId,
            Embedded::AssetId => Kind::AssetId,
            Embedded::DomainId => Kind::DomainId,
            Embedded::NftId => Kind::NftId,
            Embedded::Name => Kind::Name,
            Embedded::DataSpaceId => Kind::DataSpaceId,
            _ => return Err(VMError::NoritoInvalid),
        };
        visit(Node::Leaf(kind));
    }
    Ok(count)
}

/// Reconstruct the exact scalar/tuple durable schema for a declared map key.
/// The bounded walk and all scratch allocation fail before publishing a schema.
/// Runtime callers retain temporary VM-budget custody around this owned value.
pub(crate) fn state_map_key_schema(ty: &Embedded) -> Result<StateValueSchemaV1, VMError> {
    let count = visit_key_type(ty, |_| {})?;
    let mut nodes = Vec::new();
    nodes.try_reserve_exact(count).map_err(|_| unavailable())?;
    visit_key_type(ty, |node| nodes.push(node))?;
    Ok(StateValueSchemaV1 { nodes })
}

/// Validate the exact canonical state record while its decoded graph remains in
/// one bounded scope funded from the executing VM's original allocation pool.
pub(super) fn validate_key_record(vm: &IVM, ty: &Embedded, bytes: &[u8]) -> Result<(), VMError> {
    if bytes.is_empty() || bytes.len() > syscalls::STATE_MAP_MAX_KEY_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let limits = norito::canonical_decode_limits(bytes.len());
    // The schema has no owned names or nested collections. Besides its exact
    // bounded node backing, retain headroom for the canonical schema serializer,
    // schema-hash material and record destruction work until all values die.
    let scratch =
        MAX_STATE_VALUE_NODES * core::mem::size_of::<Node>() + 4 * MAX_STATE_VALUE_SCHEMA_BYTES;
    let mut reservation = vm
        .memory
        .allocation_budget()
        .map(|pool| {
            pool.try_reserve_bytes(
                scratch
                    + limits.max_total_allocated_bytes()
                    + norito::core::DecodeBudgetContext::allocation_layout().size(),
            )
        })
        .transpose()
        .map_err(VMError::AllocationDeferred)?;
    let schema = super::state_map_key_schema(ty)?;
    let schema_bytes = norito::encode_canonical(&schema).map_err(codec_error)?;
    if schema_bytes.len() > MAX_STATE_VALUE_SCHEMA_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let expected_hash = state_value_schema_hash_v1(&schema_bytes);
    let context = match reservation.as_mut() {
        Some(reservation) => norito::core::DecodeBudgetContext::from_reservation(
            limits,
            reservation,
        )
        .map_err(|error| match error {
            iroha_allocation::PrepaidSharedError::Reservation(_) => {
                VMError::ExecutionDeferred(crate::ExecutionDeferral::LocalInvariantViolation)
            }
            iroha_allocation::PrepaidSharedError::Allocator { .. } => unavailable(),
        })?,
        None => norito::core::DecodeBudgetContext::new(limits),
    };
    context.with(|| {
        let record = decode_canonical_state_value_record_v1(bytes).map_err(codec_error)?;
        if record.schema_hash != expected_hash {
            return Err(VMError::NoritoInvalid);
        }
        let mut atoms = record.atoms.iter();
        for node in &schema.nodes {
            let Node::Leaf(kind) = node else {
                continue;
            };
            match (kind, atoms.next()) {
                (Kind::Bool, Some(Atom::Bool(_))) => {}
                (Kind::Bool, _) => return Err(VMError::NoritoInvalid),
                (_, Some(Atom::Pointer(envelope))) => {
                    // Numeric keys retain the exact authenticated-envelope fault
                    // contract used by scalar ingress and persisted-key iteration.
                    // The enclosing reservation owns this bounded decode work.
                    match kind {
                        Kind::Int => crate::numeric_tlv::decode_int_bytes(envelope).map(drop)?,
                        Kind::Decimal => {
                            crate::numeric_tlv::decode_decimal_bytes(envelope).map(drop)?
                        }
                        Kind::Quantity => {
                            crate::numeric_tlv::decode_quantity_bytes(envelope).map(drop)?
                        }
                        _ => crate::state_value_runtime::validate_state_pointer_atom(
                            vm.syscall_policy(),
                            *kind,
                            envelope,
                        )?,
                    }
                }
                _ => return Err(VMError::NoritoInvalid),
            }
        }
        if atoms.next().is_some() {
            return Err(VMError::NoritoInvalid);
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "tests/state_map_key.rs"]
mod tests;
