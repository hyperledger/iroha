//! ISO 20022 profile selection from authenticated requests.
use super::{Error, Iso20022BridgeRuntime};
use axum::http::HeaderMap;
use std::collections::HashMap;
pub fn from_request<'a>(
    runtime: &'a Iso20022BridgeRuntime,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> Result<&'a iroha_core::iso_bridge::profiles::TradfiRailProfile, Error> {
    if headers.contains_key("x-iroha-iso-profile") {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "X-Iroha-Iso-Profile is retired; select the profile with the signed `profile` query parameter"
                    .into(),
            ),
        ));
    }
    let selected = query
        .get("profile")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    runtime.resolve_profile(selected).ok_or_else(|| {
        Error::Query(iroha_data_model::ValidationFail::NotPermitted(format!(
            "unknown ISO 20022 profile `{}`",
            selected.unwrap_or("<default>")
        )))
    })
}
