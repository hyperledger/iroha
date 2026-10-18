//! Current signed read authority for the two certified-native-original endpoints.

use super::*;
use iroha_executor_data_model::permission::query::CanReadCertifiedOriginals;

/// Accept only the exact certified-original capability or the existing genesis root.
///
/// # Errors
/// Returns a permission refusal when the account holds neither accepted capability.
pub fn require_permission(app: &SharedAppState, account: &AccountId) -> Result<(), Error> {
    let certified: Permission = CanReadCertifiedOriginals.into();
    let root: Permission = CanReadAllLedgerData.into();
    let view = app.state.view();
    if !torii_account_has_permission(view.world(), account, &certified)
        && !torii_account_has_permission(view.world(), account, &root)
    {
        return Err(Error::Query(iroha_data_model::ValidationFail::NotPermitted(
            "Certified native originals require CanReadCertifiedOriginals or CanReadAllLedgerData"
                .to_owned(),
        )));
    }
    Ok(())
}

/// Bind the current reader to the exact network, HTTP target, and request body.
///
/// # Errors
/// Returns the original authorization-resource or canonical-request verification error,
/// rejects missing signed authentication, and rejects a reader without either accepted capability.
pub fn authenticate(
    app: &SharedAppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<AccountId, Error> {
    let authentication_owner =
        crate::history_producer::HistoryProducerOwner::authentication_read(app)?;
    let verified = crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts { method, uri, body },
        None,
        authentication_owner.allocation_context(),
    )?
    .ok_or_else(|| Error::AppUnauthorized {
        code: "canonical_authentication_required",
        message:
            "canonical signed account authentication is required for certified native originals"
                .into(),
    })?;
    require_permission(app, &verified.account)?;
    Ok(verified.account)
}
