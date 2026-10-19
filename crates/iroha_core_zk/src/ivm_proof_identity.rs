//! One reserved IVM namespace boundary for generic registry and native STARK AIR.

/// Generic proofs cannot claim the unavailable IVM execution relation.
///
/// Reserve complete colon/slash components named `ivm` and their hyphenated or
/// snake-case stems at every depth. Prefixing a tenant or appending a leaf does
/// not change ownership of that namespace. This is rejection, not alias
/// normalization: portable `OpenVerify` identifiers remain lowercase ASCII and
/// their existing grammar is checked separately. Other component names remain
/// available for generic public-input bindings.
pub(super) fn circuit_id_uses_reserved_ivm_namespace(circuit_id: &str) -> bool {
    circuit_id.trim().split([':', '/']).any(|component| {
        component == "ivm" || component.starts_with("ivm-") || component.starts_with("ivm_")
    })
}

#[cfg(test)]
pub(super) const RESERVED_RELATIONS: &[&str] = &[
    "ivm",
    "ivm-execution-v1",
    "ivm_execution_v1",
    "ivm-replay-binding-v1",
    "ivm_replay_binding_v1",
    "ivm-overlay-bind",
    "tenant:ivm",
    "tenant/ivm",
    "tenant:ivm-execution-v1",
    "tenant/ivm_replay_binding_v1",
    "tenant:ivm-execution-v1:binding",
    "tenant/ivm-overlay-bind/leaf",
    "tenant/ivm_execution_v1:binding",
    "tenant:ivm_replay_binding_v1/leaf",
    "tenant:group/ivm:key",
];

#[cfg(test)]
mod tests;
