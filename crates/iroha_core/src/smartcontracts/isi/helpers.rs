//! Small authorization, signature and error-mapping helpers shared by ISI modules.

use iroha_crypto::{Algorithm, PublicKey, Signature};
use iroha_data_model::{
    IntoKeyValue,
    account::{Account, AccountId},
    isi::error::InstructionExecutionError,
    permission::Permission,
    query::error::QueryExecutionFail,
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::json::Json;
use mv::storage::StorageReadOnly;

use crate::{
    smartcontracts::isi::domain::isi::ensure_controller_policy,
    state::{StateTransaction, WorldReadOnly},
};

/// Whether `authority` holds `permission` directly or through one of its roles in the
/// transaction's world view.
pub(crate) fn transaction_account_has_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission: &str,
) -> bool {
    let required = Permission::new(permission.to_owned(), Json::new(()));
    if state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.iter().any(|candidate| candidate == &required))
    {
        return true;
    }
    state_transaction
        .world
        .account_roles_iter(authority)
        .filter_map(|role_id| state_transaction.world.roles.get(role_id))
        .any(|role| role.permissions().any(|candidate| candidate == &required))
}

/// Whether the registered `account` holds `permission` inherently or through one of its roles.
pub(crate) fn world_account_has_permission(
    world: &impl WorldReadOnly,
    account: &AccountId,
    permission: Permission,
) -> bool {
    world.accounts().get(account).is_some()
        && (world.account_contains_inherent_permission(account, &permission)
            || world
                .account_roles_iter(account)
                .filter_map(|id| world.roles().get(id))
                .any(|role| role.permissions().any(|token| token == &permission)))
}

/// Surface a query failure unchanged and report any other instruction error as a conversion
/// failure.
#[inline]
pub(crate) fn instruction_error_as_query_failure(
    error: InstructionExecutionError,
) -> QueryExecutionFail {
    match error {
        InstructionExecutionError::Query(error) => error,
        error => QueryExecutionFail::Conversion(error.to_string()),
    }
}

/// Verify `signature` over `payload`, rejecting non-canonical Ed25519 and ML-DSA encodings
/// before the cryptographic check.
///
/// # Errors
///
/// Returns the parse or verification error from `iroha_crypto`.
#[inline]
pub(crate) fn verify_signature_for_signer(
    signature: &Signature,
    signer: &PublicKey,
    payload: &[u8],
) -> Result<(), iroha_crypto::Error> {
    match signer.try_algorithm() {
        Ok(Algorithm::Ed25519) => {
            iroha_crypto::ed25519_parse_signature(signature.payload())?;
        }
        Ok(Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(signature.payload())?;
        }
        _ => {}
    }
    signature.verify(signer, payload)
}

/// Register the protocol custody account on first use.
///
/// Returns `true` when the account was created by this call.
///
/// # Errors
///
/// Rejects a custody controller whose signing algorithm or curve is not allowed.
pub(crate) fn ensure_custody_account(
    custody: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<bool, InstructionExecutionError> {
    ensure_controller_policy(
        custody.controller(),
        state_transaction
            .crypto_admission_policy()
            .map_err(|message| {
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                    message.into(),
                )
            })?,
    )?;
    if state_transaction.world.account(custody).is_ok() {
        return Ok(false);
    }
    let account = Account {
        id: custody.clone(),
        metadata: Metadata::default(),
        label: None,
        uaid: None,
        opaque_ids: Vec::new(),
    };
    let (id, value) = account.into_key_value();
    state_transaction.world.accounts.insert(id, value);
    Ok(true)
}
