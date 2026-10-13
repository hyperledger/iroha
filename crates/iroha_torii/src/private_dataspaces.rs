//! Bounded public membership proofs for owner-private roots registered on a global parent.

use super::*;

fn record_selector(dataspace: &str, height: &str) -> Result<(DataSpaceId, u64), Error> {
    let parse = |value: &str, label: &str| {
        let number = value.parse::<u64>().map_err(|_| {
            routing::conversion_error(format!("{label} must be a canonical nonzero decimal u64"))
        })?;
        if number == 0 || number.to_string() != value {
            return Err(routing::conversion_error(format!(
                "{label} must be a canonical nonzero decimal u64"
            )));
        }
        Ok(number)
    };
    let height = parse(height, "height")?;
    if height < 2 {
        return Err(routing::conversion_error(
            "record proof height must be a non-genesis height".into(),
        ));
    }
    Ok((DataSpaceId::new(parse(dataspace, "dataspace_id")?), height))
}

fn require_global_parent(world: &impl iroha_core::state::WorldReadOnly) -> Result<(), Error> {
    if iroha_core::sumeragi::lanes::routing::committed_root_scope(world)
        != Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "private dataspace registration proofs require an authenticated global parent"
                    .into(),
            ),
        ));
    }
    Ok(())
}

pub async fn record_proof(
    State(app): State<SharedAppState>,
    axum::extract::Path((dataspace, height)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    const ROUTE: &str = "/v1/private-dataspaces/{dataspace_id}/records/{height}/proof";
    let (dataspace, height) = record_selector(&dataspace, &height)?;
    let _api_token_principal =
        validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    require_global_parent(app.state.view().world())?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(
        &headers,
        Some(remote.ip()),
        ROUTE,
        app.authenticated_api_token_principal(&headers),
    );
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let state = app.state.clone();
    let response = routing::run_admitted_blocking(
        admission,
        "private dataspace proof worker failed",
        move || {
            let view = state.view();
            require_global_parent(view.world())?;
            let proof = iroha_core::query::native_receipts::private_dataspace_record_proof(
                &view, height, dataspace,
            )
            .map_err(|error| {
                Error::Query(iroha_data_model::ValidationFail::InternalError(format!(
                    "private dataspace original certified receipt is unavailable: {error}"
                )))
            })?
            .ok_or_else(|| Error::AppNotFound {
                code: "private_dataspace_record_not_written",
                message: "the authenticated carrier contains no write for this private dataspace"
                    .into(),
            })?;
            if matches!(format, crate::utils::ResponseFormat::Norito) {
                Ok(crate::NoritoBody(proof).into_response())
            } else {
                crate::routing::pretty_json_response(&proof)
            }
        },
    )
    .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        ROUTE,
        response,
        true,
    )
    .await
}

#[cfg(all(test, feature = "app_api"))]
mod tests {
    use super::*;

    #[test]
    fn selectors_require_exact_full_width_nonzero_integers() {
        assert_eq!(
            record_selector(&u64::MAX.to_string(), "2").unwrap(),
            (DataSpaceId::new(u64::MAX), 2)
        );
        assert!(record_selector("1", "1").is_err());
        for value in ["0", "01", "+1", " 1", "1/2", "18446744073709551616"] {
            assert!(record_selector(value, "2").is_err());
            assert!(record_selector("1", value).is_err());
        }
    }

    #[test]
    fn parent_proofs_reject_private_and_unbound_roots() {
        let global = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            false,
        );
        require_global_parent(global.state.view().world()).expect("explicit global parent");
        let private = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            true,
        );
        assert!(require_global_parent(private.state.view().world()).is_err());
        let missing = iroha_core::state::World::new();
        assert!(require_global_parent(&missing.view()).is_err());
    }
}
