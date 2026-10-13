//! Current committed registration projection for the independently trusted retail issuer.
//!
//! This read is not an ownership certificate or native enrollment capability. All fields
//! come from one StateView; absent registration-incarnation evidence is never synthesized.

use super::*;
use iroha_data_model::{asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1};
use iroha_primitives::numeric::{MAX_DECIMAL_SCALE, NumericSpec};

#[derive(Debug, PartialEq, Eq, crate::json_macros::JsonSerialize)]
struct RegistrationV1 {
    version: u16,
    network_id: String,
    asset_definition_id: String,
    asset_incarnation_hex: String,
    scale: u32,
    committed_height: u64,
    committed_block_hash_hex: String,
    committed_at_ms: u64,
}
fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "offline_asset_registration_unavailable",
        message: "current committed asset registration is unavailable".to_owned(),
    }
}
fn registration(
    network_id: &iroha_data_model::NetworkId,
    asset: &AssetDefinitionId,
    incarnation: Option<AxtAssetIncarnationV1>,
    specification: NumericSpec,
    committed_height: u64,
    committed_block_hash: &[u8; 32],
    committed_at_ms: u64,
) -> Result<RegistrationV1, Error> {
    let incarnation = incarnation
        .filter(|value| value.validate().is_ok())
        .ok_or_else(unavailable)?;
    let scale = specification
        .scale()
        .filter(|scale| *scale <= MAX_DECIMAL_SCALE)
        .ok_or_else(unavailable)?;
    if committed_height == 0
        || committed_at_ms == 0
        || *committed_block_hash == [0; 32]
        || *network_id.as_bytes() == [0; 32]
    {
        return Err(unavailable());
    }
    Ok(RegistrationV1 {
        version: 1,
        network_id: network_id.to_string(),
        asset_definition_id: asset.to_string(),
        asset_incarnation_hex: hex::encode(incarnation.as_bytes()),
        scale,
        committed_height,
        committed_block_hash_hex: hex::encode(committed_block_hash),
        committed_at_ms,
    })
}

fn canonical_asset(raw: &str) -> Result<AssetDefinitionId, Error> {
    if raw.is_empty() || raw.len() > 128 {
        return Err(conversion_error(
            "asset must be an exact canonical definition address".to_owned(),
        ));
    }
    let asset = AssetDefinitionId::parse_address_literal(raw).map_err(|_| {
        conversion_error("asset must be an exact canonical definition address".to_owned())
    })?;
    if asset.to_string() != raw {
        return Err(conversion_error(
            "asset must be an exact canonical definition address".to_owned(),
        ));
    }
    Ok(asset)
}

pub async fn handler(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    AxPath(asset_raw): AxPath<String>,
) -> Result<AxResponse, Error> {
    let context = "v1/assets/definitions/{asset}/registration";
    let visibility = torii_dataspace_context_from_headers(&app, &headers, &method, &uri, context)?;
    if !limits::is_allowed_by_cidr(&headers, Some(remote.ip()), &app.api_rate_limit_bypass_nets) {
        check_access(&app, &headers, Some(remote.ip()), context).await?;
    }
    // This issuer boundary accepts an immutable address only. Resolving an alias in a
    // separate view would let a repoint race change the registration being projected.
    let asset = canonical_asset(&asset_raw)?;
    let view = app.state.view();
    let world = view.world();
    if !visibility
        .current_visibility()
        .allows_asset_definition(world, &asset)
    {
        return Err(routing::explorer_not_found());
    }
    let definition = world
        .asset_definition(&asset)
        .map_err(|_| routing::explorer_not_found())?;
    let height = u64::try_from(view.height()).map_err(|_| unavailable())?;
    let hash = view.latest_block_hash().ok_or_else(unavailable)?;
    let block = view
        .latest_block()
        .map_err(crate::canonical_history::canonical_attempt_error)?
        .ok_or_else(unavailable)?;
    if block.header().height().get() != height || block.hash() != hash {
        return Err(unavailable());
    }
    let hash_bytes: &[u8; 32] = hash.as_ref();
    let response = registration(
        view.network_id(),
        &asset,
        world.axt_asset_incarnations().get(&asset).copied(),
        definition.spec(),
        height,
        hash_bytes,
        block.header().creation_time_ms,
    )?;
    Ok(crate::utils::JsonBody(response).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::NetworkId;
    fn inputs() -> (NetworkId, AssetDefinitionId, AxtAssetIncarnationV1) {
        (
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"registration-network",
            ))),
            AssetDefinitionId::from_uuid_bytes([
                0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
                0xcd, 0x2f,
            ])
            .unwrap(),
            AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"registration-incarnation").as_ref())
                .unwrap(),
        )
    }
    #[test]
    fn registration_selector_rejects_aliases_and_noncanonical_addresses_without_a_world_read() {
        let (_, asset, _) = inputs();
        assert_eq!(canonical_asset(&asset.to_string()).unwrap(), asset);
        for raw in [
            "DK#bpng",
            "",
            "asset#bpng",
            &format!(" {asset}"),
            &format!("{asset} "),
        ] {
            assert!(canonical_asset(raw).is_err(), "{raw}");
        }
    }
    #[test]
    fn projection_preserves_exact_registration_without_deriving_it_from_asset_id() {
        let (network, asset, incarnation) = inputs();
        let result = registration(
            &network,
            &asset,
            Some(incarnation),
            NumericSpec::fractional(2),
            7,
            &[8; 32],
            9,
        )
        .unwrap();
        assert_eq!(
            result.asset_incarnation_hex,
            hex::encode(incarnation.as_bytes())
        );
        assert_eq!(result.network_id, network.to_string());
        assert_eq!(result.asset_definition_id, asset.to_string());
        assert_eq!(result.scale, 2);
        assert_eq!(result.committed_height, 7);
        let successor =
            AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"re-registration").as_ref()).unwrap();
        assert_ne!(
            result,
            registration(
                &network,
                &asset,
                Some(successor),
                NumericSpec::fractional(2),
                7,
                &[8; 32],
                9
            )
            .unwrap()
        );
    }
    #[test]
    fn registration_requires_a_bounded_canonical_decimal_scale() {
        let (network, asset, incarnation) = inputs();
        let at_maximum = registration(
            &network,
            &asset,
            Some(incarnation),
            NumericSpec::fractional(MAX_DECIMAL_SCALE),
            7,
            &[8; 32],
            9,
        )
        .unwrap();
        assert_eq!(at_maximum.scale, MAX_DECIMAL_SCALE);
        assert_eq!(
            registration(
                &network,
                &asset,
                Some(incarnation),
                NumericSpec::integer(),
                7,
                &[8; 32],
                9
            )
            .unwrap()
            .scale,
            0
        );
        assert!(
            registration(
                &network,
                &asset,
                Some(incarnation),
                NumericSpec::unconstrained(),
                7,
                &[8; 32],
                9
            )
            .is_err()
        );
    }
    #[test]
    fn absent_incarnation_or_committed_identity_never_qualifies() {
        let (network, asset, incarnation) = inputs();
        assert!(
            registration(
                &network,
                &asset,
                None,
                NumericSpec::fractional(2),
                7,
                &[8; 32],
                9
            )
            .is_err()
        );
        assert!(
            registration(
                &network,
                &asset,
                Some(incarnation),
                NumericSpec::fractional(2),
                0,
                &[8; 32],
                9
            )
            .is_err()
        );
        assert!(
            registration(
                &network,
                &asset,
                Some(incarnation),
                NumericSpec::fractional(2),
                7,
                &[0; 32],
                9
            )
            .is_err()
        );
        assert!(
            registration(
                &network,
                &asset,
                Some(incarnation),
                NumericSpec::fractional(2),
                7,
                &[8; 32],
                0
            )
            .is_err()
        );
        assert!(
            registration(
                &network,
                &asset,
                Some(incarnation),
                NumericSpec::unconstrained(),
                7,
                &[8; 32],
                9
            )
            .is_err()
        );
    }
}
