// Canonical native/user state namespace predicates, included in the host module.
/// Reject native reserve and escrow scope originals in generic durable artifacts.
/// Native reserve instructions mutate their own state after their ordinary authorization checks;
/// they never obtain mutation authority by supplying a generic durable-state overlay.
pub(crate) fn validate_reserve_durable_state_path(path: &StatePath) -> Result<(), ValidationFail> {
    if iroha_data_model::escrow::scoped::is_native_scope_key(path.as_ref()) {
        return Err(ValidationFail::NotPermitted(
            "native escrow scope cannot be mutated by a contract durable-state artifact".into(),
        ));
    }
    if iroha_data_model::sorafs::reserve::history::is_reserve_state_key(path.as_ref()) {
        return Err(ValidationFail::NotPermitted(
            "native reserve state cannot be mutated by a contract durable-state artifact".into(),
        ));
    }
    Ok(())
}

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    fn contract_state_key_matches_namespace(key: &str, prefix: &str) -> bool {
        if let Some(root) = prefix
            .strip_suffix('/')
            .or_else(|| prefix.strip_suffix('_'))
        {
            return key == root || key.starts_with(prefix);
        }
        key == prefix
            || key
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('_') || suffix.starts_with('/'))
    }
    fn contract_state_namespace_access(key: &str) -> ContractStateNamespaceAccess {
        if OPAQUE_SYSTEM_CONTRACT_STATE_PREFIXES
            .iter()
            .any(|prefix| Self::contract_state_key_matches_namespace(key, prefix))
        {
            ContractStateNamespaceAccess::OpaqueSystem
        } else if READ_ONLY_SYSTEM_CONTRACT_STATE_PREFIXES
            .iter()
            .any(|prefix| Self::contract_state_key_matches_namespace(key, prefix))
        {
            ContractStateNamespaceAccess::ReadOnlySystem
        } else {
            ContractStateNamespaceAccess::User
        }
    }
    fn ensure_contract_state_read_allowed(path: &StatePath) -> Result<(), ivm::VMError> {
        if Self::contract_state_namespace_access(path.as_ref())
            == ContractStateNamespaceAccess::OpaqueSystem
        {
            return Err(ivm::VMError::PermissionDenied);
        }
        Ok(())
    }
    fn ensure_contract_state_write_allowed(path: &StatePath) -> Result<(), ivm::VMError> {
        if Self::contract_state_namespace_access(path.as_ref())
            != ContractStateNamespaceAccess::User
        {
            return Err(ivm::VMError::PermissionDenied);
        }
        Ok(())
    }
}
