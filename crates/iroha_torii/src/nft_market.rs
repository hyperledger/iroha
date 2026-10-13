//! Bounded public reads of native one-shot NFT sale offers.
use crate::{Error, SharedAppState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use iroha_core::state::{StateReadOnly, WorldReadOnly};
use iroha_crypto::Hash;
use iroha_data_model::{nft::NftId, nft_market::NftSaleStatusV1};
use mv::storage::StorageReadOnly;

#[derive(Default, Debug, crate::json_macros::JsonDeserialize)]
pub struct NftOfferListParams {
    /// Exclusive exact native offer hash; scans remain bounded even with filters.
    pub cursor: Option<Hash>,
    /// Optional exact NFT filter.
    pub nft_id: Option<NftId>,
}
pub fn capabilities(app: &SharedAppState) -> Response {
    let view = app.state.view();
    crate::utils::JsonBody(norito::json!({
        "version": 1, "network_id": (view.network_id()),
        "protocol_id": (iroha_core::smartcontracts::isi::nft_market::nft_market_profile_id_v1()),
        "qualified": (iroha_core::smartcontracts::isi::nft_market::nft_market_qualified_v1()),
        "native_nft_market": true,
    }))
    .into_response()
}
pub fn get(app: &SharedAppState, id: &str) -> Result<Response, Error> {
    let id: Hash = id
        .parse()
        .map_err(|_| crate::routing::conversion_error("invalid NFT offer hash".into()))?;
    let view = app.state.view();
    let Some(record) = view.world().nft_sale_offers().get(&id) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    Ok(crate::utils::JsonBody(record.clone()).into_response())
}
pub fn list(app: &SharedAppState, params: NftOfferListParams) -> Response {
    let view = app.state.view();
    let mut rows = Vec::new();
    let mut next = None;
    let mut more = false;
    for (scanned, (id, record)) in view
        .world()
        .nft_sale_offers()
        .range((
            params
                .cursor
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
            std::ops::Bound::Unbounded,
        ))
        .take(129)
        .enumerate()
    {
        if scanned == 128 || rows.len() == 32 {
            more = true;
            break;
        }
        next = Some(*id);
        if record.status != NftSaleStatusV1::Open
            || params
                .nft_id
                .as_ref()
                .is_some_and(|nft| nft != &record.offer.nft_id)
        {
            continue;
        }
        rows.push(record.clone());
    }
    crate::utils::JsonBody(norito::json!({
        "version": 1, "network_id": (view.network_id()), "items": rows,
        "next_cursor": (if more { next } else { None }), "has_more": more,
    }))
    .into_response()
}
