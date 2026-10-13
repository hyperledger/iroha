//! Curated MCP resources backed by Torii's existing in-process routes.
//!
//! Torii remains the sole HTTP and MCP server. Resource reads enter the same
//! in-process router used by MCP tools; this module never creates a listener,
//! sidecar, gateway, or network hop.

use std::{fmt, sync::LazyLock};

use axum::http::{HeaderMap, Method};
use iroha_torii_shared::route_catalog::{
    self, AdmissionPolicy, ApiSurface, AuthenticationPolicy, CatalogValidationError,
    EnabledFeatures, HttpMethod, Listener, RouteCatalog, RouteDescriptor, RouteEffect,
    RouteTransport,
};
use norito::json::{self, Value};

use crate::SharedAppState;

const JSON_MIME_TYPE: &str = "application/json";
const PRIVATE_CACHE_SCOPE: &str = "private";
const RESOURCE_LIST_TTL_MS: u64 = 30_000;

const COMPILED_RESOURCE_FEATURES: &[&str] = &[
    #[cfg(feature = "app_api")]
    "app_api",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceSpec {
    uri: &'static str,
    name: &'static str,
    title: &'static str,
    description: &'static str,
    route_id: &'static str,
    route_path: &'static str,
    request_target: &'static str,
    surface: ApiSurface,
    authentication: AuthenticationPolicy,
    ttl_ms: u64,
}

const RESOURCE_SPECS: &[ResourceSpec] = &[
    ResourceSpec {
        uri: "iroha://node/health",
        name: "iroha-node-health",
        title: "Iroha node health",
        description: "Torii liveness reported by the canonical health route.",
        route_id: "protocol.health",
        route_path: "/health",
        request_target: "/health",
        surface: ApiSurface::Protocol,
        authentication: AuthenticationPolicy::Unauthenticated,
        ttl_ms: 0,
    },
    ResourceSpec {
        uri: "iroha://node/api-version",
        name: "iroha-node-api-version",
        title: "Iroha node API version",
        description: "Torii API and build version information.",
        route_id: "core.api_version",
        route_path: "/v1/api/version",
        request_target: "/v1/api/version",
        surface: ApiSurface::Public,
        authentication: AuthenticationPolicy::ToriiDefault,
        ttl_ms: 300_000,
    },
    ResourceSpec {
        uri: "iroha://chain/head",
        name: "iroha-chain-head",
        title: "Iroha chain head",
        description: "The newest canonical ledger header visible to Torii.",
        route_id: "ledger.headers",
        route_path: "/v1/ledger/headers",
        request_target: "/v1/ledger/headers?limit=1",
        surface: ApiSurface::Public,
        authentication: AuthenticationPolicy::ToriiDefault,
        ttl_ms: 0,
    },
    #[cfg(feature = "app_api")]
    ResourceSpec {
        uri: "iroha://chain/parameters",
        name: "iroha-chain-parameters",
        title: "Iroha chain parameters",
        description: "The effective on-chain application parameters.",
        route_id: "application.parameters_get",
        route_path: "/v1/parameters",
        request_target: "/v1/parameters",
        surface: ApiSurface::Public,
        authentication: AuthenticationPolicy::ToriiDefault,
        ttl_ms: 5_000,
    },
    ResourceSpec {
        uri: "iroha://runtime/abi/hash",
        name: "iroha-runtime-abi-hash",
        title: "Iroha runtime ABI hash",
        description: "The hash of the runtime ABI accepted by this node.",
        route_id: "runtime.abi.hash",
        route_path: "/v1/runtime/abi/hash",
        request_target: "/v1/runtime/abi/hash",
        surface: ApiSurface::Public,
        authentication: AuthenticationPolicy::ToriiDefault,
        ttl_ms: 30_000,
    },
];

static VALIDATED_RESOURCE_REGISTRY: LazyLock<Result<(), ResourceRegistryError>> =
    LazyLock::new(|| {
        validate_registry_against_catalog(
            RESOURCE_SPECS,
            route_catalog::CATALOGED_ROUTES,
            EnabledFeatures::new(COMPILED_RESOURCE_FEATURES),
        )
    });

/// A fail-closed mismatch between the curated resource registry and Torii's
/// authoritative route catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceRegistryError {
    /// The route catalog itself is invalid.
    InvalidCatalog(Vec<CatalogValidationError>),
    /// Two resource entries use the same exact URI.
    DuplicateUri(&'static str),
    /// No catalog descriptor has the required stable route identifier.
    MissingRoute(&'static str),
    /// The catalog route path differs from the reviewed resource path.
    UnexpectedPath {
        /// Stable route identifier.
        route_id: &'static str,
        /// Reviewed exact path.
        expected: &'static str,
        /// Catalog path.
        actual: &'static str,
    },
    /// The internal dispatch target is not the exact route path or a query on it.
    InvalidRequestTarget {
        /// Resource URI.
        uri: &'static str,
        /// Internal Torii request target.
        target: &'static str,
    },
    /// The catalog route is not mounted on Torii's sole listener.
    UnexpectedListener(&'static str),
    /// The catalog route is not a GET operation.
    UnexpectedMethod(&'static str),
    /// The catalog route can perform more than a bounded read.
    UnexpectedEffect(&'static str),
    /// The catalog route is not bounded HTTP.
    UnexpectedTransport(&'static str),
    /// The catalog route requires a non-public principal.
    UnexpectedAdmission(&'static str),
    /// The catalog route moved to a different audience surface.
    UnexpectedSurface(&'static str),
    /// The catalog route's authentication boundary changed.
    UnexpectedAuthentication(&'static str),
    /// The route's feature gate is not enabled in this Torii build.
    DisabledFeature(&'static str),
}

impl fmt::Display for ResourceRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Torii MCP resource registry: {self:?}")
    }
}

impl std::error::Error for ResourceRegistryError {}

/// Typed failures from one resource read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceReadError {
    /// The URI does not exactly match a curated resource.
    UnknownUri(String),
    /// The curated registry no longer matches the mounted Torii route catalog.
    InvalidRegistry(ResourceRegistryError),
    /// The shared MCP dispatch semaphore has no available permit.
    CapacityExhausted,
    /// Torii's in-process router could not dispatch or collect the response.
    DispatchFailed(String),
    /// The target Torii route returned an HTTP error status.
    RouteStatus(u16),
    /// The in-process route response did not have the reviewed shape.
    MalformedRouteResponse(&'static str),
    /// The typed response body could not be safely encoded as JSON text.
    BodyEncodingFailed(String),
}

impl fmt::Display for ResourceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUri(uri) => write!(formatter, "unknown MCP resource URI `{uri}`"),
            Self::InvalidRegistry(error) => fmt::Display::fmt(error, formatter),
            Self::CapacityExhausted => {
                formatter.write_str("MCP resource dispatch capacity is exhausted")
            }
            Self::DispatchFailed(error) => {
                write!(formatter, "MCP resource dispatch failed: {error}")
            }
            Self::RouteStatus(status) => {
                write!(formatter, "MCP resource route returned HTTP {status}")
            }
            Self::MalformedRouteResponse(message) => {
                write!(
                    formatter,
                    "malformed MCP resource route response: {message}"
                )
            }
            Self::BodyEncodingFailed(error) => {
                write!(formatter, "encode MCP resource body: {error}")
            }
        }
    }
}

impl std::error::Error for ResourceReadError {}

impl From<ResourceRegistryError> for ResourceReadError {
    fn from(error: ResourceRegistryError) -> Self {
        Self::InvalidRegistry(error)
    }
}

/// Return the MCP `resources` capability value.
///
/// The exact registry changes only with the Torii binary, so subscriptions and
/// list-changed notifications are intentionally not advertised.
pub fn resources_capability() -> Value {
    norito::json!({ "listChanged": false })
}

/// Return the complete, privately cacheable `resources/list` result.
pub fn resources_list_result() -> Result<Value, ResourceRegistryError> {
    validate_resource_registry()?;
    Ok(resources_list_result_from_specs(RESOURCE_SPECS))
}

/// Read one exact resource through Torii's existing in-process router.
pub async fn read_resource(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    uri: &str,
) -> Result<Value, ResourceReadError> {
    validate_resource_registry()?;
    let spec = RESOURCE_SPECS
        .iter()
        .find(|spec| spec.uri == uri)
        .ok_or_else(|| ResourceReadError::UnknownUri(uri.to_owned()))?;
    let _dispatch_permit = app
        .mcp_dispatch_inflight
        .clone()
        .try_acquire_owned()
        .map_err(|_| ResourceReadError::CapacityExhausted)?;
    let mut response = super::dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        spec.request_target,
        None,
        Vec::new(),
        None,
        Some(JSON_MIME_TYPE.to_owned()),
    )
    .await
    .map_err(ResourceReadError::DispatchFailed)?;

    strip_route_headers(&mut response)?;
    let status = response
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .ok_or(ResourceReadError::MalformedRouteResponse(
            "status must be an unsigned 16-bit integer",
        ))?;
    if !is_success_status(status) {
        return Err(ResourceReadError::RouteStatus(status));
    }
    let body = response
        .get("body")
        .ok_or(ResourceReadError::MalformedRouteResponse(
            "body field is missing",
        ))?;
    let text = json::to_string(body)
        .map_err(|error| ResourceReadError::BodyEncodingFailed(error.to_string()))?;

    Ok(norito::json!({
        "resultType": "complete",
        "contents": [
            {
                "uri": (spec.uri),
                "mimeType": (JSON_MIME_TYPE),
                "text": (text)
            }
        ],
        "ttlMs": (spec.ttl_ms),
        "cacheScope": (PRIVATE_CACHE_SCOPE)
    }))
}

const fn is_success_status(status: u16) -> bool {
    status >= 200 && status < 300
}

fn validate_resource_registry() -> Result<(), ResourceRegistryError> {
    VALIDATED_RESOURCE_REGISTRY.clone()
}

fn resources_list_result_from_specs(specs: &[ResourceSpec]) -> Value {
    let resources = specs
        .iter()
        .map(|spec| {
            norito::json!({
                "uri": (spec.uri),
                "name": (spec.name),
                "title": (spec.title),
                "description": (spec.description),
                "mimeType": (JSON_MIME_TYPE)
            })
        })
        .collect::<Vec<_>>();
    norito::json!({
        "resultType": "complete",
        "resources": (resources),
        "ttlMs": (RESOURCE_LIST_TTL_MS),
        "cacheScope": (PRIVATE_CACHE_SCOPE)
    })
}

fn validate_registry_against_catalog(
    specs: &[ResourceSpec],
    routes: &[RouteDescriptor],
    enabled_features: EnabledFeatures<'_>,
) -> Result<(), ResourceRegistryError> {
    RouteCatalog::new(routes)
        .validate()
        .map_err(ResourceRegistryError::InvalidCatalog)?;

    for (index, spec) in specs.iter().enumerate() {
        if specs[..index]
            .iter()
            .any(|previous| previous.uri == spec.uri)
        {
            return Err(ResourceRegistryError::DuplicateUri(spec.uri));
        }
        let route = routes
            .iter()
            .find(|route| route.stable_route_id() == spec.route_id)
            .ok_or(ResourceRegistryError::MissingRoute(spec.route_id))?;
        if route.path() != spec.route_path {
            return Err(ResourceRegistryError::UnexpectedPath {
                route_id: spec.route_id,
                expected: spec.route_path,
                actual: route.path(),
            });
        }
        if spec.request_target != spec.route_path
            && !spec
                .request_target
                .strip_prefix(spec.route_path)
                .is_some_and(|suffix| suffix.starts_with('?'))
        {
            return Err(ResourceRegistryError::InvalidRequestTarget {
                uri: spec.uri,
                target: spec.request_target,
            });
        }
        if route.listener() != Listener::Torii {
            return Err(ResourceRegistryError::UnexpectedListener(spec.route_id));
        }
        if route.method() != HttpMethod::Get {
            return Err(ResourceRegistryError::UnexpectedMethod(spec.route_id));
        }
        if route.effect() != RouteEffect::ReadOnly {
            return Err(ResourceRegistryError::UnexpectedEffect(spec.route_id));
        }
        if route.transport() != RouteTransport::Http {
            return Err(ResourceRegistryError::UnexpectedTransport(spec.route_id));
        }
        if route.admission() != AdmissionPolicy::Public {
            return Err(ResourceRegistryError::UnexpectedAdmission(spec.route_id));
        }
        if route.surface() != spec.surface {
            return Err(ResourceRegistryError::UnexpectedSurface(spec.route_id));
        }
        if route.authentication() != spec.authentication {
            return Err(ResourceRegistryError::UnexpectedAuthentication(
                spec.route_id,
            ));
        }
        if !route.feature_gate().is_enabled(enabled_features) {
            return Err(ResourceRegistryError::DisabledFeature(spec.route_id));
        }
    }
    Ok(())
}

fn strip_route_headers(response: &mut Value) -> Result<(), ResourceReadError> {
    let headers = response
        .get_mut("headers")
        .and_then(Value::as_object_mut)
        .ok_or(ResourceReadError::MalformedRouteResponse(
            "headers must be an object",
        ))?;
    headers.retain(|name, _| {
        let name = name.to_ascii_lowercase();
        name != "x-iroha-routed-by"
            && !name.starts_with("x-iroha-route-")
            && !name.starts_with("x-iroha-internal-")
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_registry_matches_the_compiled_route_catalog() {
        validate_registry_against_catalog(
            RESOURCE_SPECS,
            route_catalog::CATALOGED_ROUTES,
            EnabledFeatures::new(COMPILED_RESOURCE_FEATURES),
        )
        .expect("curated resource routes must remain exact public Torii reads");
    }

    #[test]
    fn capability_does_not_advertise_unimplemented_change_or_subscription_flows() {
        assert_eq!(
            resources_capability(),
            norito::json!({ "listChanged": false })
        );
    }

    #[test]
    fn resource_reads_accept_only_http_success_statuses() {
        assert!(is_success_status(200));
        assert!(is_success_status(299));
        for status in [0, 199, 300, 304, 399, 400, 500, u16::MAX] {
            assert!(!is_success_status(status), "unexpected success: {status}");
        }
    }

    #[test]
    fn list_result_is_complete_private_and_exact() {
        let result = resources_list_result_from_specs(RESOURCE_SPECS);
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete")
        );
        assert_eq!(
            result.get("ttlMs").and_then(Value::as_u64),
            Some(RESOURCE_LIST_TTL_MS)
        );
        assert_eq!(
            result.get("cacheScope").and_then(Value::as_str),
            Some(PRIVATE_CACHE_SCOPE)
        );
        let resources = result
            .get("resources")
            .and_then(Value::as_array)
            .expect("resource list");
        let uris = resources
            .iter()
            .map(|resource| {
                assert_eq!(
                    resource.get("mimeType").and_then(Value::as_str),
                    Some(JSON_MIME_TYPE)
                );
                resource
                    .get("uri")
                    .and_then(Value::as_str)
                    .expect("resource URI")
            })
            .collect::<Vec<_>>();
        let mut expected = vec![
            "iroha://node/health",
            "iroha://node/api-version",
            "iroha://chain/head",
        ];
        #[cfg(feature = "app_api")]
        expected.push("iroha://chain/parameters");
        expected.push("iroha://runtime/abi/hash");
        assert_eq!(uris, expected);
    }

    #[test]
    fn validation_rejects_path_drift() {
        let mut drifted = RESOURCE_SPECS[0];
        drifted.route_path = "/readyz";
        drifted.request_target = "/readyz";
        assert!(matches!(
            validate_registry_against_catalog(
                &[drifted],
                route_catalog::CATALOGED_ROUTES,
                EnabledFeatures::new(COMPILED_RESOURCE_FEATURES),
            ),
            Err(ResourceRegistryError::UnexpectedPath {
                route_id: "protocol.health",
                expected: "/readyz",
                actual: "/health",
            })
        ));
    }

    #[test]
    fn validation_rejects_non_public_admission() {
        let operator = ResourceSpec {
            uri: "iroha://test/operator-peers",
            name: "test-operator-peers",
            title: "test",
            description: "test",
            route_id: "core.peers",
            route_path: "/v1/peers",
            request_target: "/v1/peers",
            surface: ApiSurface::Operator,
            authentication: AuthenticationPolicy::OperatorSignature,
            ttl_ms: 0,
        };
        assert_eq!(
            validate_registry_against_catalog(
                &[operator],
                route_catalog::CATALOGED_ROUTES,
                EnabledFeatures::new(COMPILED_RESOURCE_FEATURES),
            ),
            Err(ResourceRegistryError::UnexpectedAdmission("core.peers"))
        );
    }

    #[test]
    fn validation_rejects_a_disabled_feature() {
        let parameters = ResourceSpec {
            uri: "iroha://chain/parameters",
            name: "iroha-chain-parameters",
            title: "Iroha chain parameters",
            description: "The effective on-chain application parameters.",
            route_id: "application.parameters_get",
            route_path: "/v1/parameters",
            request_target: "/v1/parameters",
            surface: ApiSurface::Public,
            authentication: AuthenticationPolicy::ToriiDefault,
            ttl_ms: 5_000,
        };
        assert_eq!(
            validate_registry_against_catalog(
                &[parameters],
                route_catalog::CATALOGED_ROUTES,
                EnabledFeatures::none(),
            ),
            Err(ResourceRegistryError::DisabledFeature(
                "application.parameters_get"
            ))
        );
    }
}
